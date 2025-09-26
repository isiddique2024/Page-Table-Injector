#include "pe_parser.hpp"
#include "memory_manager.hpp"
#include <iostream>

auto pe_parser_t::validate_dos_header(const void* buffer, std::size_t buffer_size) -> bool {
  if (!buffer || buffer_size < sizeof(IMAGE_DOS_HEADER)) {
    return false;
  }

  const auto dos_header = static_cast<const IMAGE_DOS_HEADER*>(buffer);
  return dos_header->e_magic == IMAGE_DOS_SIGNATURE;
}

auto pe_parser_t::validate_nt_headers(const void* buffer, std::size_t buffer_size) -> bool {
  if (!validate_dos_header(buffer, buffer_size)) {
    return false;
  }

  const auto dos_header = static_cast<const IMAGE_DOS_HEADER*>(buffer);
  if (dos_header->e_lfanew >= buffer_size || dos_header->e_lfanew < 0 ||
      buffer_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) {
    return false;
  }

  const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
      static_cast<const char*>(buffer) + dos_header->e_lfanew);

  return nt_headers->Signature == IMAGE_NT_SIGNATURE;
}

auto pe_parser_t::get_nt_headers(void* buffer) -> PIMAGE_NT_HEADERS64 {
  if (!buffer || !validate_dos_header(buffer, SIZE_MAX)) {
    return nullptr;
  }

  const auto dos_header = static_cast<PIMAGE_DOS_HEADER>(buffer);
  return reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<char*>(buffer) + dos_header->e_lfanew);
}

auto pe_parser_t::get_imports(void* buffer) -> std::vector<import_info_t> {
  std::vector<import_info_t> imports;

  auto nt_headers = get_nt_headers(buffer);
  if (!nt_headers) {
    return imports;
  }

  const auto import_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (!import_dir->VirtualAddress) {
    return imports;
  }

  auto import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(static_cast<char*>(buffer) +
                                                                import_dir->VirtualAddress);

  while (import_desc->Name) {
    import_info_t import_info;
    import_info.module_name =
        reinterpret_cast<char*>(static_cast<char*>(buffer) + import_desc->Name);

    auto thunk =
        reinterpret_cast<PIMAGE_THUNK_DATA64>(static_cast<char*>(buffer) + import_desc->FirstThunk);
    auto orig_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(static_cast<char*>(buffer) +
                                                            import_desc->OriginalFirstThunk);

    while (orig_thunk->u1.Function) {
      import_function_t func_info;

      if (!(orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
        auto import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(static_cast<char*>(buffer) +
                                                                      orig_thunk->u1.AddressOfData);
        func_info.name = import_by_name->Name;
      }

      func_info.address = &thunk->u1.Function;
      import_info.functions.push_back(func_info);

      ++thunk;
      ++orig_thunk;
    }

    imports.push_back(import_info);
    ++import_desc;
  }

  return imports;
}

auto pe_parser_t::get_relocs(void* image_base) -> std::vector<reloc_info_t> {
  std::vector<reloc_info_t> relocs;

  auto nt_headers = get_nt_headers(image_base);
  if (!nt_headers) {
    return relocs;
  }

  auto reloc_va =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
  if (!reloc_va) {
    return relocs;
  }

  auto current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
      reinterpret_cast<std::uint64_t>(image_base) + reloc_va);
  auto reloc_end = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
      reinterpret_cast<std::uint64_t>(current_base_relocation) +
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

  while (current_base_relocation < reloc_end && current_base_relocation->SizeOfBlock) {
    reloc_info_t reloc_info;

    reloc_info.address =
        reinterpret_cast<std::uint64_t>(image_base) + current_base_relocation->VirtualAddress;
    reloc_info.item = reinterpret_cast<std::uint16_t*>(
        reinterpret_cast<std::uint64_t>(current_base_relocation) + sizeof(IMAGE_BASE_RELOCATION));
    reloc_info.count = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                       sizeof(std::uint16_t);

    relocs.push_back(reloc_info);

    current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
        reinterpret_cast<std::uint64_t>(current_base_relocation) +
        current_base_relocation->SizeOfBlock);
  }

  return relocs;
}

auto pe_parser_t::relocate_image_by_delta(void* image_base, std::uint64_t delta) -> bool {
  auto relocs = get_relocs(image_base);

  for (const auto& current_reloc : relocs) {
    for (auto i = 0u; i < current_reloc.count; ++i) {
      auto type = current_reloc.item[i] >> 12;
      auto offset = current_reloc.item[i] & 0xFFF;

      if (type == IMAGE_REL_BASED_DIR64) {
        auto reloc_address = reinterpret_cast<std::uint64_t*>(current_reloc.address + offset);
        *reloc_address += delta;
      }
    }
  }

  return true;
}

auto pe_parser_t::process_imports(void* buffer, import_resolver_t resolver) -> bool {
  if (!buffer || !resolver) {
    return false;
  }

  auto imports = get_imports(buffer);

  for (const auto& import : imports) {
    for (const auto& func : import.functions) {
      auto resolved_addr = resolver(import.module_name, func.name);
      if (!resolved_addr) {
        mapper_log("ERROR", "failed to resolve: %ws::%ws",
                   std::wstring(import.module_name.begin(), import.module_name.end()).c_str(),
                   std::wstring(func.name.begin(), func.name.end()).c_str());
        return false;
      }

      *func.address = resolved_addr;
    }
  }

  return true;
}

auto pe_parser_t::resolve_imports(void* image_base, HANDLE device_handle,
                                  std::uint64_t ntoskrnl_addr) -> bool {
  auto imports = get_imports(image_base);
  for (const auto& current_import : imports) {
    // Use g_utils to get kernel module address
    std::uint64_t module_base = g_utils->get_kernel_module_address(current_import.module_name);
    if (!module_base) {
      mapper_log("ERROR", "dependency %ws wasn't found",
                 std::wstring(current_import.module_name.begin(), current_import.module_name.end())
                     .c_str());
      return false;
    }
    for (const auto& function_data : current_import.functions) {
      // get kernel module export - now passes device_handle and module_base as uint64_t
      std::uint64_t function_address =
          get_module_export(device_handle, module_base, function_data.name);
      if (!function_address) {
        // try with ntoskrnl
        if (module_base != ntoskrnl_addr) {
          function_address = get_module_export(device_handle, ntoskrnl_addr, function_data.name);
        }
        if (!function_address) {
          mapper_log("ERROR", "failed to resolve import %ws ",
                     std::wstring(function_data.name.begin(), function_data.name.end()).c_str());
          return false;
        }
      }
      *function_data.address = function_address;
    }
  }
  return true;
}

auto pe_parser_t::find_section(void* image_base, const std::string& section_name)
    -> PIMAGE_SECTION_HEADER {
  auto nt_headers = get_nt_headers(image_base);
  if (!nt_headers) {
    return nullptr;
  }

  auto section_header = IMAGE_FIRST_SECTION(nt_headers);

  for (auto i = 0u; i < nt_headers->FileHeader.NumberOfSections; ++i) {
    std::string current_section_name(
        reinterpret_cast<char*>(section_header[i].Name),
        strnlen(reinterpret_cast<char*>(section_header[i].Name), IMAGE_SIZEOF_SHORT_NAME));

    if (current_section_name == section_name) {
      return &section_header[i];
    }
  }

  return nullptr;
}

std::uint64_t pe_parser_t::get_module_export(HANDLE device_handle, std::uint64_t module_base,
                                             const std::string& export_name) {
  // Read DOS header first
  IMAGE_DOS_HEADER dos_header;
  if (!g_memory_manager->read_memory(device_handle, module_base, &dos_header, sizeof(dos_header))) {
    return 0;
  }

  if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
    return 0;
  }

  // read NT headers
  IMAGE_NT_HEADERS64 nt_headers;
  if (!g_memory_manager->read_memory(device_handle, module_base + dos_header.e_lfanew, &nt_headers,
                                     sizeof(nt_headers))) {
    return 0;
  }

  if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
    return 0;
  }

  auto export_va =
      nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  if (!export_va) {
    return 0;
  }

  // read export directory
  IMAGE_EXPORT_DIRECTORY export_dir;
  if (!g_memory_manager->read_memory(device_handle, module_base + export_va, &export_dir,
                                     sizeof(export_dir))) {
    return 0;
  }

  // read function addresses array
  auto functions_size = export_dir.NumberOfFunctions * sizeof(DWORD);
  auto functions = std::make_unique<DWORD[]>(export_dir.NumberOfFunctions);
  if (!g_memory_manager->read_memory(device_handle, module_base + export_dir.AddressOfFunctions,
                                     functions.get(), functions_size)) {
    return 0;
  }

  // read names array
  auto names_size = export_dir.NumberOfNames * sizeof(DWORD);
  auto names = std::make_unique<DWORD[]>(export_dir.NumberOfNames);
  if (!g_memory_manager->read_memory(device_handle, module_base + export_dir.AddressOfNames,
                                     names.get(), names_size)) {
    return 0;
  }

  // read ordinals array
  auto ordinals_size = export_dir.NumberOfNames * sizeof(WORD);
  auto ordinals = std::make_unique<WORD[]>(export_dir.NumberOfNames);
  if (!g_memory_manager->read_memory(device_handle, module_base + export_dir.AddressOfNameOrdinals,
                                     ordinals.get(), ordinals_size)) {
    return 0;
  }

  // search for the function
  for (DWORD i = 0; i < export_dir.NumberOfNames; ++i) {
    // read function name
    char name_buffer[256];
    if (!g_memory_manager->read_memory(device_handle, module_base + names[i], name_buffer,
                                       sizeof(name_buffer))) {
      continue;
    }
    name_buffer[255] = '\0';  // ensure null termination

    if (export_name == name_buffer) {
      auto ordinal = ordinals[i];
      if (ordinal < export_dir.NumberOfFunctions) {
        auto function_rva = functions[ordinal];
        if (function_rva) {
          return module_base + function_rva;
        }
      }
    }
  }

  return 0;
}

auto pe_parser_t::is_valid_pe(void* buffer) -> bool {
  if (!buffer) {
    return false;
  }

  // check DOS header
  auto dos_header = static_cast<PIMAGE_DOS_HEADER>(buffer);
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    return false;
  }

  // check NT headers
  auto nt_headers =
      reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<char*>(buffer) + dos_header->e_lfanew);

  if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
    return false;
  }

  // check if it's 64-bit
  if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return false;
  }

  return true;
}

auto pe_parser_t::fix_security_cookie(void* image_base, std::uint64_t kernel_image_base) -> bool {
  auto nt_headers = get_nt_headers(image_base);
  if (!nt_headers) {
    return false;
  }

  auto load_config_directory =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
  if (!load_config_directory) {
    // no load config directory - cookie not defined
    return true;
  }

  auto load_config_struct = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>(
      static_cast<char*>(image_base) + load_config_directory);

  auto stack_cookie = load_config_struct->SecurityCookie;
  if (!stack_cookie) {
    // cookie not defined, this is OK
    return true;
  }

  // calc the stack cookie address in local image
  stack_cookie = stack_cookie - kernel_image_base + reinterpret_cast<std::uintptr_t>(image_base);

  auto cookie_ptr = reinterpret_cast<std::uintptr_t*>(stack_cookie);

  // check if cookie needs fixing (default value is 0x2B992DDFA232)
  if (*cookie_ptr != 0x2B992DDFA232) {
    // cookie already fixed
    return true;
  }

  // generate new cookie value
  auto new_cookie = static_cast<std::uintptr_t>(0x2B992DDFA232) ^
                    g_utils->get_current_process_id() ^ g_utils->get_current_thread_id();

  // ensure cookie is not the default value
  if (new_cookie == 0x2B992DDFA232) {
    new_cookie = 0x2B992DDFA233;
  }

  // set the new cookie
  *cookie_ptr = new_cookie;

  return true;
}