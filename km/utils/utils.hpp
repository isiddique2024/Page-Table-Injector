#pragma once

namespace utils
{
    auto get_windows_version() -> unsigned long
    {
        RTL_OSVERSIONINFOW ver = { 0 };
        ver.dwOSVersionInfoSize = sizeof(ver);
        globals::rtl_get_version(&ver);
        return ver.dwBuildNumber;
    }

    auto get_module_base(uintptr_t pid, LPCWSTR module_name) -> uintptr_t
    {
        PEPROCESS target_proc;
        uintptr_t base = 0;
        if (!NT_SUCCESS(globals::ps_lookup_process_by_process_id((HANDLE)pid, &target_proc)))
            return 0;

        // get PEB address
        PPEB peb_address = globals::ps_get_process_peb(target_proc);
        if (!peb_address) {
            globals::obf_dereference_object(target_proc);
            return 0;
        }

        // read PEB using physical memory read
        PEB peb{};
        physical::read_process_memory(target_proc, reinterpret_cast<ULONG64>(peb_address), &peb, sizeof(PEB));
        if (!peb.Ldr || !peb.Ldr->Initialized) {
            globals::obf_dereference_object(target_proc);
            return 0;
        }

        // check if module_name is empty (L"") - special case to get the main module
        bool get_first_module = (module_name[0] == L'\0');

        // only create Unicode string for comparison if we're not getting the first module
        UNICODE_STRING module_name_unicode{};
        if (!get_first_module) {
            globals::rtl_init_unicode_string(&module_name_unicode, module_name);
        }

        // get LDR_DATA_TABLE_ENTRY for InLoadOrderModuleList
        PEB_LDR_DATA ldr_data{};
        physical::read_process_memory(target_proc, reinterpret_cast<ULONG64>(peb.Ldr), &ldr_data, sizeof(PEB_LDR_DATA));

        // get the first entry address
        PLIST_ENTRY current_entry = ldr_data.InLoadOrderModuleList.Flink;
        PLIST_ENTRY first_entry = current_entry;

        do {
            // read the current LDR_DATA_TABLE_ENTRY
            LDR_DATA_TABLE_ENTRY entry{};
            physical::read_process_memory(target_proc,
                reinterpret_cast<ULONG64>(CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)),
                &entry,
                sizeof(LDR_DATA_TABLE_ENTRY));

            // return the first valid entry's base if empty wstring is passed
            if (get_first_module && entry.DllBase) {
                base = reinterpret_cast<uintptr_t>(entry.DllBase);
                break;
            }

            // otherwise, proceed with the module name comparison
            // read the module name
            WCHAR dll_name[256]{};
            if (entry.BaseDllName.Length > 0 && entry.BaseDllName.Buffer) {
                physical::read_process_memory(target_proc,
                    reinterpret_cast<ULONG64>(entry.BaseDllName.Buffer),
                    dll_name,
                    min(entry.BaseDllName.Length, static_cast<USHORT>(sizeof(dll_name) - sizeof(WCHAR))));
                // create a UNICODE_STRING for comparison
                UNICODE_STRING dll_name_unicode{};
                dll_name_unicode.Length = entry.BaseDllName.Length;
                dll_name_unicode.MaximumLength = entry.BaseDllName.MaximumLength;
                dll_name_unicode.Buffer = dll_name;
                // compare and check if this is the module we're looking for
                if (globals::rtl_compare_unicode_string(&dll_name_unicode, &module_name_unicode, TRUE) == 0) {
                    base = reinterpret_cast<uintptr_t>(entry.DllBase);
                    break;
                }
            }

            // read the next entry
            LIST_ENTRY next_entry{};
            physical::read_process_memory(target_proc, reinterpret_cast<ULONG64>(current_entry), &next_entry, sizeof(LIST_ENTRY));
            current_entry = next_entry.Flink;
        } while (current_entry != first_entry);

        globals::obf_dereference_object(target_proc);
        return base;
    }
}