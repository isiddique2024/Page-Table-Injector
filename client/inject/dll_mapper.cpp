#include "dll_mapper.hpp"

#include "utils/logging.h"

void dll_mapper_t::set_iat_hook_params(const char* hook_mod, const char* hook_func,
                                       const wchar_t* main_module) {
  this->hook_module = hook_mod;
  this->hook_function = hook_func;
  this->target_module = main_module;
}

const char* dll_mapper_t::get_method_name(execution_method method) {
  switch (method) {
    case execution_method::IAT_HOOK:
      return "IAT_HOOK";
    case execution_method::SET_WINDOWS_HOOK:
      return "SET_WINDOWS_HOOK";
    case execution_method::THREAD:
      return "THREAD";
    default:
      return "UNKNOWN";
  }
}

void dll_mapper_t::set_execution_method(execution_method method) {
  this->exec_method = method;
  debug_log("SUCCESS", "execution method set to: %s", get_method_name(method));
}

dll_mapper_t::execution_method dll_mapper_t::get_execution_method() const {
  return this->exec_method;
}

auto dll_mapper_t::get_nt_headers(const std::uintptr_t image_base) const -> IMAGE_NT_HEADERS* {
  const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(image_base);
  return reinterpret_cast<IMAGE_NT_HEADERS*>(image_base + dos_header->e_lfanew);
}

auto dll_mapper_t::rva_va(const std::uintptr_t rva, IMAGE_NT_HEADERS* nt_header,
                          void* local_image) const -> void* {
  const auto first_section = IMAGE_FIRST_SECTION(nt_header);

  for (auto section = first_section;
       section < first_section + nt_header->FileHeader.NumberOfSections; section++) {
    if (rva >= section->VirtualAddress &&
        rva < section->VirtualAddress + section->Misc.VirtualSize) {
      return static_cast<unsigned char*>(local_image) + section->PointerToRawData +
             (rva - section->VirtualAddress);
    }
  }

  return nullptr;
}

auto dll_mapper_t::relocate_image(void* remote_image, void* local_image,
                                  IMAGE_NT_HEADERS* nt_header) const -> bool {
  struct reloc_entry {
    std::uint32_t to_rva;
    std::uint32_t size;
    struct {
      std::uint16_t offset : 12;
      std::uint16_t type : 4;
    } item[1];
  };

  const auto delta_offset =
      reinterpret_cast<std::uintptr_t>(remote_image) - nt_header->OptionalHeader.ImageBase;

  if (!delta_offset) {
    return true;
  }

  if (!(nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
    return false;
  }

  auto relocation_entry = static_cast<reloc_entry*>(rva_va(
      nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
      nt_header, local_image));
  const auto relocation_end =
      reinterpret_cast<std::uintptr_t>(relocation_entry) +
      nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

  if (relocation_entry == nullptr) {
    return true;
  }

  while (reinterpret_cast<std::uintptr_t>(relocation_entry) < relocation_end &&
         relocation_entry->size) {
    auto records_count = (relocation_entry->size - 8) >> 1;

    for (auto i = 0ul; i < records_count; i++) {
      std::uint16_t fixed_type = (relocation_entry->item[i].type);
      std::uint16_t shift_delta = (relocation_entry->item[i].offset) % 4096;

      if (fixed_type == IMAGE_REL_BASED_ABSOLUTE) {
        continue;
      }

      if (fixed_type == IMAGE_REL_BASED_HIGHLOW || fixed_type == IMAGE_REL_BASED_DIR64) {
        auto fixed_va = reinterpret_cast<std::uintptr_t>(
            rva_va(relocation_entry->to_rva, nt_header, local_image));

        if (!fixed_va) {
          fixed_va = reinterpret_cast<std::uintptr_t>(local_image);
        }

        *reinterpret_cast<std::uintptr_t*>(fixed_va + shift_delta) += delta_offset;
      }
    }

    relocation_entry = reinterpret_cast<reloc_entry*>(reinterpret_cast<LPBYTE>(relocation_entry) +
                                                      relocation_entry->size);
  }

  return true;
}

auto dll_mapper_t::resolve_function_address(const char* module_name,
                                            const char* function_name) const -> std::uintptr_t {
  const auto handle = LoadLibraryExA(module_name, nullptr, DONT_RESOLVE_DLL_REFERENCES);
  const auto offset = reinterpret_cast<std::uintptr_t>(GetProcAddress(handle, function_name)) -
                      reinterpret_cast<std::uintptr_t>(handle);
  FreeLibrary(handle);
  return offset;
}

bool dll_mapper_t::map_sections(std::uint32_t pid, void* module_base, void* local_image,
                                IMAGE_NT_HEADERS* nt_header) const {
  auto section = IMAGE_FIRST_SECTION(nt_header);
  auto num_sections = nt_header->FileHeader.NumberOfSections;
  debug_log("INFO", "number of sections to map: %u", num_sections);

  // validate number of sections
  if (num_sections == 0 || num_sections > 96) {  // PE format max is 96 sections
    debug_log("ERROR", "invalid number of sections: %u", num_sections);
    return false;
  }

  // calculate total size needed
  std::size_t total_mapping_size = 0;
  for (std::uint16_t i = 0; i < num_sections; i++) {
    if (!section[i].SizeOfRawData) {
      debug_log("INFO", "skipping section %u (%.*s) - no raw data", i + 1, 8, section[i].Name);
      continue;
    }

    // Validate section data
    if (section[i].PointerToRawData > nt_header->OptionalHeader.SizeOfImage) {
      debug_log("ERROR", "section %u has invalid PointerToRawData: 0x%X", i,
                section[i].PointerToRawData);
      return false;
    }

    auto section_end = section[i].VirtualAddress + section[i].SizeOfRawData;
    total_mapping_size = (total_mapping_size > static_cast<std::size_t>(section_end))
                             ? total_mapping_size
                             : static_cast<std::size_t>(section_end);
  }

  if (!total_mapping_size) {
    debug_log("ERROR", "no valid sections to map");
    return false;
  }

  std::size_t buffer_size = total_mapping_size;
  std::vector<std::uint8_t> combined_buffer(buffer_size, 0);

  // copy all sections to buffer
  std::uint16_t mapped_sections = 0;
  for (std::uint16_t i = 0; i < num_sections; i++) {
    if (!section[i].SizeOfRawData) {
      continue;
    }

    debug_log("INFO", "preparing section %u (%.*s) - VA: 0x%X, Size: 0x%X", i + 1, 8,
              section[i].Name, section[i].VirtualAddress, section[i].SizeOfRawData);

    auto source = reinterpret_cast<std::uint8_t*>(local_image) + section[i].PointerToRawData;
    auto dest = combined_buffer.data() + section[i].VirtualAddress;
    std::memcpy(dest, source, section[i].SizeOfRawData);
    mapped_sections++;
  }

  debug_log("INFO", "prepared %u sections in buffer", mapped_sections);

  // write to remote process
  if (!g_driver_manager->write_virtual_memory(pid, reinterpret_cast<std::uintptr_t>(module_base),
                                              combined_buffer.data(), buffer_size)) {
    debug_log("ERROR", "failed to write sections to remote process at 0x%p", module_base);
    return false;
  }

  debug_log("SUCCESS", "successfully mapped %u sections", mapped_sections);
  return true;
}

auto dll_mapper_t::resolve_import(DWORD process_id, DWORD thread_id, void* local_image,
                                  IMAGE_NT_HEADERS* nt_header) const -> bool {
  auto import_description = static_cast<IMAGE_IMPORT_DESCRIPTOR*>(
      rva_va(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
             nt_header, local_image));

  if (!nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress ||
      !nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
    return true;
  }

  while (import_description->Name) {
    LPSTR module_name =
        static_cast<LPSTR>(rva_va(import_description->Name, nt_header, local_image));
    const auto base_image = reinterpret_cast<uintptr_t>(LoadLibraryA(module_name));
    if (!base_image) {
      return false;
    }

    auto import_header_data = static_cast<IMAGE_THUNK_DATA*>(
        rva_va(import_description->FirstThunk, nt_header, local_image));

    while (import_header_data->u1.AddressOfData) {
      if (import_header_data->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        import_header_data->u1.Function =
            base_image +
            resolve_function_address(
                module_name, reinterpret_cast<LPCSTR>(import_header_data->u1.Ordinal & 0xFFFF));
      } else {
        auto ibn = static_cast<IMAGE_IMPORT_BY_NAME*>(
            rva_va(import_header_data->u1.AddressOfData, nt_header, local_image));
        import_header_data->u1.Function =
            base_image + resolve_function_address(module_name, reinterpret_cast<LPCSTR>(ibn->Name));
      }
      import_header_data++;
    }
    import_description++;
  }

  return true;
}

uintptr_t dll_mapper_t::find_iat_entry(uint32_t pid, uintptr_t module_base, const char* dll_name,
                                       const char* function_name) {
  // read DOS header
  IMAGE_DOS_HEADER dos_header = {0};
  g_driver_manager->read_virtual_memory(pid, module_base, &dos_header, sizeof(dos_header));

  if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
    return 0;
  }

  // read NT headers
  IMAGE_NT_HEADERS nt_headers = {0};
  g_driver_manager->read_virtual_memory(pid, module_base + dos_header.e_lfanew, &nt_headers,
                                        sizeof(nt_headers));

  if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
    return 0;
  }

  // get import directory
  IMAGE_DATA_DIRECTORY import_directory =
      nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  if (import_directory.VirtualAddress == 0 || import_directory.Size == 0) {
    return 0;
  }

  // calc max number of import descriptors (to prevent infinite loops)
  const size_t max_descriptors = import_directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

  // process import descriptors using a fixed loop
  uintptr_t import_descriptor_addr = module_base + import_directory.VirtualAddress;

  for (size_t i = 0; i < max_descriptors; i++) {
    IMAGE_IMPORT_DESCRIPTOR import_descriptor = {0};
    g_driver_manager->read_virtual_memory(pid, import_descriptor_addr, &import_descriptor,
                                          sizeof(import_descriptor));

    // check for end of descriptors
    if (import_descriptor.Name == 0) {
      break;
    }

    // read DLL name
    char current_dll_name[256] = {0};
    g_driver_manager->read_virtual_memory(pid, module_base + import_descriptor.Name,
                                          current_dll_name, sizeof(current_dll_name));

    // check if this is the DLL we're looking for
    if (_stricmp(current_dll_name, dll_name) == 0) {
      // setup thunk addresses
      uintptr_t thunk_addr = module_base + import_descriptor.FirstThunk;
      uintptr_t original_thunk_addr = import_descriptor.OriginalFirstThunk
                                          ? module_base + import_descriptor.OriginalFirstThunk
                                          : thunk_addr;

      // process thunks with fixed max to prevent infinite loops
      const size_t max_thunks = 1000;  // arbitrary limit

      for (size_t j = 0; j < max_thunks; j++) {
        // read thunks
        IMAGE_THUNK_DATA thunk = {0}, original_thunk = {0};
        g_driver_manager->read_virtual_memory(pid, thunk_addr, &thunk, sizeof(thunk));

        if (original_thunk_addr != thunk_addr) {
          g_driver_manager->read_virtual_memory(pid, original_thunk_addr, &original_thunk,
                                                sizeof(original_thunk));
        } else {
          original_thunk = thunk;
        }

        // check for end of thunks
        if (thunk.u1.Function == 0) {
          break;
        }

        // check if imported by name (not by ordinal)
        if (!(original_thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
          // read function name
          char current_function_name[256] = {0};
          uintptr_t name_addr = module_base + original_thunk.u1.AddressOfData + sizeof(WORD);
          g_driver_manager->read_virtual_memory(pid, name_addr, current_function_name,
                                                sizeof(current_function_name));

          // check if this is the function we're looking for
          if (strcmp(current_function_name, function_name) == 0) {
            return thunk_addr;
          }
        } else {
          // imported by ordinal
          WORD ordinal = IMAGE_ORDINAL(original_thunk.u1.Ordinal);
        }

        // move to next thunk
        thunk_addr += sizeof(IMAGE_THUNK_DATA);
        original_thunk_addr += sizeof(IMAGE_THUNK_DATA);
      }
    }

    // move to next import descriptor
    import_descriptor_addr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
  }

  return 0;
}

bool dll_mapper_t::execute_via_iat_hook(uint32_t pid, uint32_t tid, uintptr_t main_module_base,
                                        void* alloc_base, DWORD entry_point,
                                        driver_manager_t::alloc_mode alloc_mode) {
  debug_log("INFO", "executing DLL via IAT hook - Module: %s, Function: %s",
            hook_module ? hook_module : "NULL", hook_function ? hook_function : "NULL");

  // validate hook parameters
  if (!hook_module || !hook_function) {
    debug_log("ERROR", "IAT hook parameters not set");
    return false;
  }

  std::uintptr_t iat_entry = find_iat_entry(pid, main_module_base, hook_module, hook_function);
  if (!iat_entry) {
    debug_log("ERROR", "failed to find IAT entry for %s!%s", hook_module, hook_function);
    return false;
  }

  debug_log("INFO", "found IAT entry at 0x%llx", iat_entry);

  const auto remote_shellcode = g_driver_manager->allocate_independent_pages(
      GetCurrentProcessId(), pid, tid, 0x1000, 0, alloc_mode);
  if (!remote_shellcode) {
    debug_log("ERROR", "failed to allocate remote shellcode");
    return false;
  }

  debug_log("INFO", "allocated remote shellcode at 0x%p", remote_shellcode);

  // swap context if using hyperspace
  if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
    if (!g_driver_manager->swap_context_to_hyperspace(tid)) {
      debug_log("ERROR", "failed to swap context to hyperspace for thread %u", tid);
      return false;
    }
    debug_log("INFO", "swapped to hyperspace context");
  }

  void* local_alloc = VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!local_alloc) {
    debug_log("ERROR", "failed to allocate local memory: %lu", GetLastError());
    if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
      g_driver_manager->restore_context(tid);
    }
    return false;
  }

  memcpy(local_alloc, dll_main_shellcode, sizeof(dll_main_shellcode));

  std::uintptr_t shell_data_addr = (std::uintptr_t)remote_shellcode + sizeof(dll_main_shellcode);
  *(std::uintptr_t*)((std::uintptr_t)local_alloc + shell_data_offset) = shell_data_addr;

  auto ctx = (pexecution_context)((std::uintptr_t)local_alloc + sizeof(dll_main_shellcode));
  ctx->state = 0;
  ctx->base_address = (HINSTANCE)alloc_base;
  ctx->target_function = (std::uintptr_t)alloc_base + entry_point;

  // write shellcode with error handling
  if (!g_driver_manager->write_virtual_memory(pid, (std::uintptr_t)remote_shellcode, local_alloc,
                                              total_size)) {
    debug_log("ERROR", "failed to write shellcode to remote process");
    VirtualFree(local_alloc, 0, MEM_RELEASE);
    if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
      g_driver_manager->restore_context(tid);
    }
    return false;
  }

  // read and save original pointer
  void* original_ptr = nullptr;
  if (!g_driver_manager->read_virtual_memory(pid, iat_entry, &original_ptr, sizeof(uintptr_t))) {
    debug_log("ERROR", "failed to read original IAT entry");
    VirtualFree(local_alloc, 0, MEM_RELEASE);
    if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
      g_driver_manager->restore_context(tid);
    }
    return false;
  }

  debug_log("INFO", "original IAT pointer: 0x%p", original_ptr);

  // hook IAT entry
  if (!g_driver_manager->write_virtual_memory(pid, iat_entry, &remote_shellcode,
                                              sizeof(uintptr_t))) {
    debug_log("ERROR", "failed to write hook to IAT entry");
    VirtualFree(local_alloc, 0, MEM_RELEASE);
    if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
      g_driver_manager->restore_context(tid);
    }
    return false;
  }

  debug_log("INFO", "hooked IAT entry, waiting for execution");

  // wait for execution
  execution_context status_check = {0};
  const int max_wait_cycles = 1500;
  int wait_cycles = 0;

  while (status_check.state != 2 && wait_cycles < max_wait_cycles) {
    Sleep(10);
    if (!g_driver_manager->read_virtual_memory(pid, shell_data_addr, &status_check,
                                               sizeof(std::uintptr_t))) {
      debug_log("WARNING", "failed to read status at cycle %d", wait_cycles);
    }
    wait_cycles++;

    if (wait_cycles % 100 == 0) {
      debug_log("INFO", "waiting for execution... cycle %d, state: %d", wait_cycles,
                status_check.state);
    }
  }

  // restore original IAT entry
  if (!g_driver_manager->write_virtual_memory(pid, iat_entry, &original_ptr, sizeof(uintptr_t))) {
    debug_log("ERROR", "failed to restore original IAT entry - process may be unstable!");
  } else {
    debug_log("INFO", "restored original IAT entry");
  }

  // restore context if needed
  if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
    if (!g_driver_manager->restore_context(tid)) {
      debug_log("ERROR", "failed to restore context from hyperspace");
    } else {
      debug_log("INFO", "restored context from hyperspace");
    }
  }

  // clear shellcode
  std::uint8_t zero_shell[sizeof(dll_main_shellcode)] = {0};
  g_driver_manager->write_virtual_memory(pid, (std::uintptr_t)remote_shellcode, zero_shell,
                                         sizeof(zero_shell));

  VirtualFree(local_alloc, 0, MEM_RELEASE);

  bool success = (status_check.state == 2);
  debug_log(success ? "SUCCESS" : "ERROR", "IAT hook execution %s (state: %d, cycles: %d)",
            success ? "completed" : "failed/timed out", status_check.state, wait_cycles);

  return success;
}

bool dll_mapper_t::execute_via_swhk(uint32_t pid, uint32_t tid, void* alloc_base, DWORD entry_point,
                                    driver_manager_t::alloc_mode alloc_mode) {
  debug_log("INFO", "executing DLL via SetWindowsHookEx for TID %u", tid);

  const auto system_lib = reinterpret_cast<HMODULE>(LoadLibraryW(L"ntdll.dll"));
  if (!system_lib) {
    debug_log("ERROR", "failed to load ntdll.dll: %lu", GetLastError());
    return false;
  }

  const auto remote_shellcode = g_driver_manager->allocate_independent_pages(
      GetCurrentProcessId(), pid, tid, 0x1000, 0, alloc_mode);
  if (!remote_shellcode) {
    debug_log("ERROR", "failed to allocate remote shellcode");
    return false;
  }

  debug_log("INFO", "allocated remote shellcode at 0x%p", remote_shellcode);

  if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
    if (!g_driver_manager->swap_context_to_hyperspace(tid)) {
      debug_log("ERROR", "failed to swap context to hyperspace");
      return false;
    }
    debug_log("INFO", "swapped to hyperspace context");
  }

  const auto local_alloc = VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!local_alloc) {
    debug_log("ERROR", "failed to allocate local memory: %lu", GetLastError());
    if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
      g_driver_manager->restore_context(tid);
    }
    return false;
  }

  // setup shellcode and context
  memcpy(local_alloc, dll_main_shellcode, sizeof(dll_main_shellcode));
  const auto context_address = (uintptr_t)remote_shellcode + sizeof(dll_main_shellcode);
  *(uintptr_t*)((uintptr_t)local_alloc + shell_data_offset) = context_address;

  auto ctx = (execution_context*)((uintptr_t)local_alloc + sizeof(dll_main_shellcode));
  ctx->state = 0;
  ctx->base_address = (HINSTANCE)alloc_base;
  ctx->target_function = ((uintptr_t)alloc_base + entry_point);

  // write shellcode with error handling
  if (!g_driver_manager->write_virtual_memory(pid, (std::uintptr_t)remote_shellcode, local_alloc,
                                              total_size)) {
    debug_log("ERROR", "failed to write shellcode to remote process");
    VirtualFree(local_alloc, 0, MEM_RELEASE);
    if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
      g_driver_manager->restore_context(tid);
    }
    return false;
  }

  // install hook
  const auto message_hook =
      SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)remote_shellcode, system_lib, tid);
  if (message_hook == NULL) {
    debug_log("ERROR", "failed to install hook, error: %lu", GetLastError());
    VirtualFree(local_alloc, 0, MEM_RELEASE);
    if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
      g_driver_manager->restore_context(tid);
    }
    return false;
  }

  debug_log("INFO", "installed SetWindowsHookEx hook, waiting for execution");

  execution_context remote_ctx = {};
  const auto start_time = GetTickCount64();
  const auto timeout_ms = 15000;
  int read_failures = 0;

  while (remote_ctx.state != 2) {
    if (GetTickCount64() - start_time > timeout_ms) {
      debug_log("ERROR", "execution timeout after %lu ms", timeout_ms);
      break;
    }

    // trigger hook
    if (!PostThreadMessageA(tid, WM_NULL, 0, 0)) {
      debug_log("WARNING", "failed to post message to thread %u: %lu", tid, GetLastError());
    }

    if (!g_driver_manager->read_virtual_memory(pid, context_address, (PVOID)&remote_ctx,
                                               sizeof(execution_context))) {
      read_failures++;
      debug_log("WARNING", "failed to read context (attempt %d)", read_failures);
      if (read_failures > 10) {
        debug_log("ERROR", "too many read failures, aborting");
        break;
      }
    }

    if (remote_ctx.state != 0) {
      debug_log("DEBUG", "context state changed to: %d", remote_ctx.state);
    }

    Sleep(10);
  }

  // cleanup
  if (!UnhookWindowsHookEx(message_hook)) {
    debug_log("WARNING", "failed to unhook: %lu", GetLastError());
  }

  // clear shellcode
  std::uint8_t cleanup_buffer[sizeof(dll_main_shellcode)] = {0};
  if (!g_driver_manager->write_virtual_memory(pid, (std::uintptr_t)remote_shellcode, cleanup_buffer,
                                              sizeof(cleanup_buffer))) {
    debug_log("WARNING", "failed to clear remote shellcode");
  }

  if (alloc_mode == g_driver_manager->ALLOC_AT_HYPERSPACE) {
    if (!g_driver_manager->restore_context(tid)) {
      debug_log("ERROR", "failed to restore context from hyperspace");
    } else {
      debug_log("INFO", "restored context from hyperspace");
    }
  }

  VirtualFree(local_alloc, 0, MEM_RELEASE);

  bool success = (remote_ctx.state == 2);
  debug_log(success ? "SUCCESS" : "ERROR", "SetWindowsHookEx execution %s (final state: %d)",
            success ? "completed" : "failed", remote_ctx.state);

  return success;
}

bool dll_mapper_t::execute_via_thread(uint32_t pid, uint32_t tid, void* alloc_base,
                                      DWORD entry_point, driver_manager_t::alloc_mode alloc_mode) {
  debug_log("INFO", "executing DLL via thread creation");

  if (!g_driver_manager->execute_dll_via_thread(GetCurrentProcessId(), pid, tid, alloc_base,
                                                entry_point, alloc_mode)) {
    return false;
  }

  return true;
}

auto dll_mapper_t::run(const std::uint32_t pid, const std::uint32_t tid, void* buffer,
                       uintptr_t offsets, driver_manager_t::memory_type memory_type,
                       driver_manager_t::alloc_mode alloc_mode) -> bool {
  std::uintptr_t main_module_base = g_driver_manager->get_module_base(pid, target_module);

  if (!main_module_base) {
    debug_log("ERROR", "failed to get main module base");
    return false;
  }

  debug_log("SUCCESS", "main module base 0x%llx", main_module_base);

  const auto nt_header = get_nt_headers(reinterpret_cast<std::uintptr_t>(buffer));
  if (!nt_header) {
    debug_log("ERROR", "failed to get NT headers");
    return false;
  }

  std::size_t size = nt_header->OptionalHeader.SizeOfImage;

  debug_log("SUCCESS", "DLL size 0x%llx", size);

  auto dll_alloc_base = g_driver_manager->allocate_independent_pages(
      GetCurrentProcessId(), pid, tid, size, memory_type, alloc_mode);
  if (!dll_alloc_base) {
    debug_log("ERROR", "invalid base address");
    return false;
  }

  debug_log("SUCCESS", "allocated memory at: 0x%llx",
            reinterpret_cast<std::uintptr_t>(dll_alloc_base));

  if (!relocate_image(dll_alloc_base, buffer, nt_header)) {
    debug_log("ERROR", "image failed to relocate");
    return false;
  }

  debug_log("SUCCESS", "relocated image");

  if (!resolve_import(pid, tid, buffer, nt_header)) {
    debug_log("ERROR", "failed to resolve imports");
    return false;
  }

  debug_log("SUCCESS", "resolved imports");

  if (!map_sections(pid, dll_alloc_base, buffer, nt_header)) {
    debug_log("ERROR", "failed to map sections");
    return false;
  }

  debug_log("SUCCESS", "resolved mapped sections");

  bool execution_success = false;
  switch (exec_method) {
    case execution_method::THREAD:
      execution_success = execute_via_thread(
          pid, tid, dll_alloc_base, nt_header->OptionalHeader.AddressOfEntryPoint, alloc_mode);
      break;
    case execution_method::SET_WINDOWS_HOOK:
      execution_success = execute_via_swhk(
          pid, tid, dll_alloc_base, nt_header->OptionalHeader.AddressOfEntryPoint, alloc_mode);
      break;
    case execution_method::IAT_HOOK:
      execution_success =
          execute_via_iat_hook(pid, tid, main_module_base, dll_alloc_base,
                               nt_header->OptionalHeader.AddressOfEntryPoint, alloc_mode);
      break;
  }

  if (!execution_success) {
    debug_log("ERROR", "failed to execute DLL using %s method", get_method_name(exec_method));
    return false;
  }

  debug_log("SUCCESS", "DLL injection completed successfully using %s method",
            get_method_name(exec_method));

  return true;
}