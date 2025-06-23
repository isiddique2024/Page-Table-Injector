#pragma once

namespace utils {
  /**
   * @brief Retrieve the Windows build number of the current system
   * @return Windows build number (e.g., 22000 for Windows 11, 19041 for Windows
   * 10)
   *
   * Uses RtlGetVersion to obtain the current operating system version
   * information. Useful for implementing version-specific code paths and
   * compatibility checks.
   */
  auto get_windows_version() -> unsigned long {
    RTL_OSVERSIONINFOW ver = {0};
    ver.dwOSVersionInfoSize = sizeof(ver);
    globals::rtl_get_version(&ver);
    return ver.dwBuildNumber;
  }

  /**
   * @brief Get the base address of a module loaded in a target process
   * @param pid Process ID of the target process
   * @param module_name Wide string name of the module to find (e.g.,
   * L"ntdll.dll") Pass empty string (L"") to get the main executable base
   * @return Base address of the module, or 0 if not found or on error
   *
   * Walks the target process's PEB and LDR structures using physical memory reads
   * to locate a specific module. Case-insensitive module name comparison.
   * Special behavior: empty module_name returns the first (main) module's base.
   */
  auto get_module_base(uintptr_t pid, LPCWSTR module_name) -> uintptr_t {
    PEPROCESS target_proc;
    uintptr_t base = 0;

    if (!NT_SUCCESS(globals::ps_lookup_process_by_process_id((HANDLE)pid, &target_proc)))
      return 0;

    // validate process is still active and acquire rundown protection
    if (!validation::validate_process_state(target_proc, static_cast<uint32_t>(pid))) {
      globals::obf_dereference_object(target_proc);
      return 0;
    }

    if (!validation::acquire_process_rundown_protection(target_proc, static_cast<uint32_t>(pid))) {
      globals::obf_dereference_object(target_proc);
      return 0;
    }

    // get PEB address
    PPEB peb_address = globals::ps_get_process_peb(target_proc);
    if (!peb_address) {
      validation::release_process_rundown_protection(target_proc);
      globals::obf_dereference_object(target_proc);
      return 0;
    }

    // read PEB using physical memory read
    PEB peb{};
    auto status = physical::read_process_memory(target_proc, reinterpret_cast<ULONG64>(peb_address),
                                                &peb, sizeof(PEB));
    if (!NT_SUCCESS(status) || !peb.Ldr || !peb.Ldr->Initialized) {
      validation::release_process_rundown_protection(target_proc);
      globals::obf_dereference_object(target_proc);
      return 0;
    }

    // check if module_name is empty (L"") - special case to get the main module
    bool get_first_module = (module_name[0] == L'\0');

    // only create Unicode string for comparison if we're not getting the first
    // module
    UNICODE_STRING module_name_unicode{};
    if (!get_first_module) {
      globals::rtl_init_unicode_string(&module_name_unicode, module_name);
    }

    // get LDR_DATA_TABLE_ENTRY for InLoadOrderModuleList
    PEB_LDR_DATA ldr_data{};
    status = physical::read_process_memory(target_proc, reinterpret_cast<ULONG64>(peb.Ldr),
                                           &ldr_data, sizeof(PEB_LDR_DATA));
    if (!NT_SUCCESS(status)) {
      validation::release_process_rundown_protection(target_proc);
      globals::obf_dereference_object(target_proc);
      return 0;
    }

    // get the first entry address
    PLIST_ENTRY current_entry = ldr_data.InLoadOrderModuleList.Flink;
    PLIST_ENTRY first_entry = current_entry;

    do {
      // read the current LDR_DATA_TABLE_ENTRY
      LDR_DATA_TABLE_ENTRY entry{};
      status =
          physical::read_process_memory(target_proc,
                                        reinterpret_cast<ULONG64>(CONTAINING_RECORD(
                                            current_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)),
                                        &entry, sizeof(LDR_DATA_TABLE_ENTRY));

      if (!NT_SUCCESS(status)) {
        log("ERROR", "failed to read LDR_DATA_TABLE_ENTRY, status: 0x%08X", status);
        break;
      }

      // return the first valid entry's base if empty wstring is passed
      if (get_first_module && entry.DllBase) {
        base = reinterpret_cast<uintptr_t>(entry.DllBase);
        break;
      }

      // otherwise, proceed with the module name comparison
      // read the module name
      WCHAR dll_name[256]{};
      if (entry.BaseDllName.Length > 0 && entry.BaseDllName.Buffer) {
        status = physical::read_process_memory(
            target_proc, reinterpret_cast<ULONG64>(entry.BaseDllName.Buffer), dll_name,
            min(entry.BaseDllName.Length, static_cast<USHORT>(sizeof(dll_name) - sizeof(WCHAR))));

        if (NT_SUCCESS(status)) {
          // create a UNICODE_STRING for comparison
          UNICODE_STRING dll_name_unicode{};
          dll_name_unicode.Length = entry.BaseDllName.Length;
          dll_name_unicode.MaximumLength = entry.BaseDllName.MaximumLength;
          dll_name_unicode.Buffer = dll_name;

          // compare and check if this is the module we're looking for
          if (globals::rtl_compare_unicode_string(&dll_name_unicode, &module_name_unicode, TRUE) ==
              0) {
            base = reinterpret_cast<uintptr_t>(entry.DllBase);
            break;
          }
        }
      }

      // read the next entry
      LIST_ENTRY next_entry{};
      status = physical::read_process_memory(target_proc, reinterpret_cast<ULONG64>(current_entry),
                                             &next_entry, sizeof(LIST_ENTRY));
      if (!NT_SUCCESS(status)) {
        log("ERROR", "failed to read next LIST_ENTRY, status: 0x%08X", status);
        break;
      }

      current_entry = next_entry.Flink;
    } while (current_entry != first_entry);

    validation::release_process_rundown_protection(target_proc);
    globals::obf_dereference_object(target_proc);
    return base;
  }
}  // namespace utils