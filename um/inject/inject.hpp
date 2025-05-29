#include <chrono>
#include <string>
#include <vector>
#include <memory>
#include <array>
#include <algorithm>
#include <thread>
#include <Windows.h>
#include <lmcons.h>

class injector_t {
private:

    const char* hook_module = "user32.dll";
    const char* hook_function = "GetMessageW";
    const wchar_t* target_module = L"";

    [[nodiscard]] __forceinline auto get_nt_headers(const std::uintptr_t image_base) const -> IMAGE_NT_HEADERS* {
        const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(image_base);
        return reinterpret_cast<IMAGE_NT_HEADERS*>(image_base + dos_header->e_lfanew);
    }

    [[nodiscard]] __forceinline auto rva_va(const std::uintptr_t rva, IMAGE_NT_HEADERS* nt_header, void* local_image) const -> void* {
        const auto first_section = IMAGE_FIRST_SECTION(nt_header);

        for (auto section = first_section; section < first_section + nt_header->FileHeader.NumberOfSections; section++) {
            if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
                return static_cast<unsigned char*>(local_image) + section->PointerToRawData + (rva - section->VirtualAddress);
            }
        }

        return nullptr;
    }

    [[nodiscard]] __forceinline auto relocate_image(void* remote_image, void* local_image, IMAGE_NT_HEADERS* nt_header) const -> bool {
        struct reloc_entry {
            std::uint32_t to_rva;
            std::uint32_t size;
            struct {
                std::uint16_t offset : 12;
                std::uint16_t type : 4;
            } item[1];
        };

        const auto delta_offset = reinterpret_cast<std::uintptr_t>(remote_image) - nt_header->OptionalHeader.ImageBase;

        if (!delta_offset) {
            return true;
        }

        if (!(nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
            return false;
        }

        auto relocation_entry = static_cast<reloc_entry*>(rva_va(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_header, local_image));
        const auto relocation_end = reinterpret_cast<std::uintptr_t>(relocation_entry) + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (relocation_entry == nullptr) {
            return true;
        }

        while (reinterpret_cast<std::uintptr_t>(relocation_entry) < relocation_end && relocation_entry->size) {
            auto records_count = (relocation_entry->size - 8) >> 1;

            for (auto i = 0ul; i < records_count; i++) {
                std::uint16_t fixed_type = (relocation_entry->item[i].type);
                std::uint16_t shift_delta = (relocation_entry->item[i].offset) % 4096;

                if (fixed_type == IMAGE_REL_BASED_ABSOLUTE) {
                    continue;
                }

                if (fixed_type == IMAGE_REL_BASED_HIGHLOW || fixed_type == IMAGE_REL_BASED_DIR64) {
                    auto fixed_va = reinterpret_cast<std::uintptr_t>(rva_va(relocation_entry->to_rva, nt_header, local_image));

                    if (!fixed_va) {
                        fixed_va = reinterpret_cast<std::uintptr_t>(local_image);
                    }

                    *reinterpret_cast<std::uintptr_t*>(fixed_va + shift_delta) += delta_offset;
                }
            }

            relocation_entry = reinterpret_cast<reloc_entry*>(reinterpret_cast<LPBYTE>(relocation_entry) + relocation_entry->size);
        }

        return true;
    }

    [[nodiscard]] __forceinline auto resolve_function_address(const char* module_name, const char* function_name) const -> std::uintptr_t {
        const auto handle = shadowcall<HMODULE>("LoadLibraryExA", module_name, nullptr, DONT_RESOLVE_DLL_REFERENCES);
        const auto offset = reinterpret_cast<std::uintptr_t>(shadowcall<FARPROC>("GetProcAddress", handle, function_name)) - reinterpret_cast<std::uintptr_t>(handle);
        shadowcall<BOOL>("FreeLibrary", handle);
        return offset;
    }

    [[nodiscard]] __forceinline bool map_sections(std::uint32_t pid, void* module_base, void* local_image,
        IMAGE_NT_HEADERS* nt_header, bool use_large_pages) const {
        auto section = IMAGE_FIRST_SECTION(nt_header);
        auto num_sections = nt_header->FileHeader.NumberOfSections;
        log("INFO", "number of sections to map: %u", num_sections);
        log("INFO", "using %s pages", use_large_pages ? "large" : "regular");

        // calculate total size needed and find largest section virtual address + size
        std::size_t total_mapping_size = 0;
        for (std::uint16_t i = 0; i < num_sections; i++) {
            if (!section[i].SizeOfRawData) {
                log("INFO", "skipping section %u (%.*s) - no raw data", i + 1, 8, section[i].Name);
                continue;
            }
            auto section_end = section[i].VirtualAddress + section[i].SizeOfRawData;
            total_mapping_size = (total_mapping_size > static_cast<std::size_t>(section_end)) ?
                total_mapping_size : static_cast<std::size_t>(section_end);
        }

        if (!total_mapping_size) {
            log("ERROR", "no valid sections to map");
            return false;
        }

        // calculate final buffer size based on page type
        std::size_t buffer_size;
        if (use_large_pages) {
            //constexpr size_t LARGE_PAGE_SIZE = 0x200000;
            constexpr size_t LARGE_PAGE_MASK = LARGE_PAGE_SIZE - 1;
            buffer_size = (total_mapping_size + LARGE_PAGE_MASK) & ~LARGE_PAGE_MASK;
            log("INFO", "original size: %zu bytes, aligned size: %zu bytes", total_mapping_size, buffer_size);
        }
        else {
            buffer_size = total_mapping_size;
        }

        // create buffer and zero it
        std::vector<std::uint8_t> combined_buffer(buffer_size, 0);

        // copy all sections to their correct positions in the buffer
        std::uint16_t mapped_sections = 0;
        for (std::uint16_t i = 0; i < num_sections; i++) {
            if (!section[i].SizeOfRawData) {
                continue;
            }

            log("INFO", "preparing section %u (%.*s)", i + 1, 8, section[i].Name);
            auto source = reinterpret_cast<std::uint8_t*>(local_image) + section[i].PointerToRawData;
            auto dest = combined_buffer.data() + section[i].VirtualAddress;
            std::memcpy(dest, source, section[i].SizeOfRawData);
            mapped_sections++;
        }

        log("INFO", "prepared %u sections in buffer", mapped_sections);

        // write buffer to target process memory
        if (use_large_pages) {
            // split into 2MB chunks for large pages
            //constexpr size_t LARGE_PAGE_SIZE = 0x200000;
            for (size_t offset = 0; offset < buffer_size; offset += LARGE_PAGE_SIZE) {
                size_t chunk_size = min(LARGE_PAGE_SIZE, buffer_size - offset);
                log("INFO", "writing large page chunk at offset 0x%zx, size: %zu bytes", offset, chunk_size);

                // Write without checking return value
                driver->write_virtual_memory(
                    pid,
                    reinterpret_cast<std::uintptr_t>(module_base) + offset,
                    combined_buffer.data() + offset,
                    chunk_size);
            }
        }
        else {
            // single write for 4KB pages
            log("INFO", "mapping all valid sections at once");
            log("INFO", "destination: 0x%p, size: %zu bytes", module_base, buffer_size);

            driver->write_virtual_memory(
                pid,
                reinterpret_cast<std::uintptr_t>(module_base),
                combined_buffer.data(),
                buffer_size);
        }

        log("INFO", "successfully mapped %u valid sections", mapped_sections);
        return true;
    }

    [[nodiscard]] __forceinline auto resolve_import(DWORD process_id, DWORD thread_id, void* local_image, IMAGE_NT_HEADERS* nt_header) const -> bool {
        auto import_description = static_cast<IMAGE_IMPORT_DESCRIPTOR*>(rva_va(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_header, local_image));

        if (!nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress ||
            !nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
            return true;
        }

        while (import_description->Name) {
            LPSTR module_name = static_cast<LPSTR>(rva_va(import_description->Name, nt_header, local_image));
            const auto base_image = reinterpret_cast<std::uintptr_t>(shadowcall<HMODULE>("LoadLibraryA", module_name));
            if (!base_image) {
                return false;
            }

            auto import_header_data = static_cast<IMAGE_THUNK_DATA*>(rva_va(import_description->FirstThunk, nt_header, local_image));

            while (import_header_data->u1.AddressOfData) {
                if (import_header_data->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    import_header_data->u1.Function = base_image + resolve_function_address(module_name, reinterpret_cast<LPCSTR>(import_header_data->u1.Ordinal & 0xFFFF));
                }
                else {
                    auto ibn = static_cast<IMAGE_IMPORT_BY_NAME*>(rva_va(import_header_data->u1.AddressOfData, nt_header, local_image));
                    import_header_data->u1.Function = base_image + resolve_function_address(module_name, reinterpret_cast<LPCSTR>(ibn->Name));
                }
                import_header_data++;
            }
            import_description++;
        }

        return true;
    }
    uintptr_t find_iat_entry(uint32_t pid, uintptr_t module_base, const char* dll_name, const char* function_name)
    {

        // read DOS header
        IMAGE_DOS_HEADER dos_header = { 0 };
        driver->read_virtual_memory(pid, module_base, &dos_header, sizeof(dos_header));

        if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }

        // read NT headers
        IMAGE_NT_HEADERS nt_headers = { 0 };
        driver->read_virtual_memory(pid, module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers));

        if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }

        // get import directory
        IMAGE_DATA_DIRECTORY import_directory = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (import_directory.VirtualAddress == 0 || import_directory.Size == 0) {
            return 0;
        }

        // calc max number of import descriptors (to prevent infinite loops)
        const size_t max_descriptors = import_directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

        // process import descriptors using a fixed loop
        uintptr_t import_descriptor_addr = module_base + import_directory.VirtualAddress;

        for (size_t i = 0; i < max_descriptors; i++) {
            IMAGE_IMPORT_DESCRIPTOR import_descriptor = { 0 };
            driver->read_virtual_memory(pid, import_descriptor_addr, &import_descriptor, sizeof(import_descriptor));

            // check for end of descriptors
            if (import_descriptor.Name == 0) {
                break;
            }

            // read DLL name
            char current_dll_name[256] = { 0 };
            driver->read_virtual_memory(pid, module_base + import_descriptor.Name, current_dll_name, sizeof(current_dll_name));


            // check if this is the DLL we're looking for
            if (_stricmp(current_dll_name, dll_name) == 0) {

                // setup thunk addresses
                uintptr_t thunk_addr = module_base + import_descriptor.FirstThunk;
                uintptr_t original_thunk_addr = import_descriptor.OriginalFirstThunk ?
                    module_base + import_descriptor.OriginalFirstThunk :
                    thunk_addr;

                // process thunks with fixed max to prevent infinite loops
                const size_t max_thunks = 1000; // Arbitrary limit

                for (size_t j = 0; j < max_thunks; j++) {
                    // read thunks
                    IMAGE_THUNK_DATA thunk = { 0 }, original_thunk = { 0 };
                    driver->read_virtual_memory(pid, thunk_addr, &thunk, sizeof(thunk));

                    if (original_thunk_addr != thunk_addr) {
                        driver->read_virtual_memory(pid, original_thunk_addr, &original_thunk, sizeof(original_thunk));
                    }
                    else {
                        original_thunk = thunk;
                    }

                    // check for end of thunks
                    if (thunk.u1.Function == 0) {
                        break;
                    }

                    // check if imported by name (not by ordinal)
                    if (!(original_thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        // read function name
                        char current_function_name[256] = { 0 };
                        uintptr_t name_addr = module_base + original_thunk.u1.AddressOfData + sizeof(WORD);
                        driver->read_virtual_memory(pid, name_addr, current_function_name, sizeof(current_function_name));


                        // check if this is the function we're looking for
                        if (strcmp(current_function_name, function_name) == 0) {
                            return thunk_addr;
                        }
                    }
                    else {
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

    bool hijack_via_iat_hook(uint32_t pid, void* alloc_base, DWORD entry_point)
    {

        std::uint8_t dll_main_shellcode[92] = {
            // Function prologue - reserve stack space
            0x48, 0x83, 0xEC, 0x38,                                         // sub rsp, 0x38 (reserve 56 bytes on stack)

            // Load address of data structure (will be patched)
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, struct_addr (patched at runtime)

            // Save the structure pointer on stack
            0x48, 0x89, 0x44, 0x24, 0x20,             // mov [rsp+0x20], rax

            // Check if already executed (status != 0)
            0x48, 0x8B, 0x44, 0x24, 0x20,             // mov rax, [rsp+0x20]
            0x83, 0x38, 0x00,                         // cmp dword ptr [rax], 0
            0x75, 0x39,                               // jne exit (skip if already executed)

            // Set status to 1 (executing)
            0x48, 0x8B, 0x44, 0x24, 0x20,             // mov rax, [rsp+0x20]
            0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,       // mov dword ptr [rax], 1

            // Get DLL entry point address from structure
            0x48, 0x8B, 0x44, 0x24, 0x20,             // mov rax, [rsp+0x20]
            0x48, 0x8B, 0x40, 0x08,                   // mov rax, [rax+8] (fn_dll_main)
            0x48, 0x89, 0x44, 0x24, 0x28,             // mov [rsp+0x28], rax

            // Prepare DllMain parameters (follows x64 calling convention)
            0x45, 0x33, 0xC0,                         // xor r8d, r8d (lpReserved = NULL)
            0xBA, 0x01, 0x00, 0x00, 0x00,             // mov edx, 1 (fdwReason = DLL_PROCESS_ATTACH)

            // Load DLL base address from structure (first parameter)
            0x48, 0x8B, 0x44, 0x24, 0x20,             // mov rax, [rsp+0x20]
            0x48, 0x8B, 0x48, 0x10,                   // mov rcx, [rax+0x10] (DLL base)

            // Call the DLL entry point function
            0xFF, 0x54, 0x24, 0x28,                   // call qword ptr [rsp+0x28]

            // Set status to 2 (completed)
            0x48, 0x8B, 0x44, 0x24, 0x20,             // mov rax, [rsp+0x20]
            0xC7, 0x00, 0x02, 0x00, 0x00, 0x00,       // mov dword ptr [rax], 2

            // Function epilogue and return
            0x48, 0x83, 0xC4, 0x38,                   // add rsp, 0x38 (restore stack)
            0xC3,                                     // ret (return to caller)

            // Padding/alignment
            0xCC                                      // int3 (breakpoint, used as padding)
        };

        const unsigned long shell_data_offset = 0x6;

        std::uintptr_t main_module_base = driver->get_module_base(pid, target_module);

        if (main_module_base == 0) {
            return false;
        }

        std::uintptr_t iat_entry = find_iat_entry(pid, main_module_base, hook_module, hook_function);

        if (iat_entry == 0) {
            return false;
        }

        typedef struct _main_struct {
            uint32_t status;             
            std::uintptr_t fn_dll_main;
            HINSTANCE dll_base;    
        } main_struct, * pmain_struct;

        DWORD shell_size = sizeof(dll_main_shellcode) + sizeof(main_struct);

        const auto remote_shellcode = driver->allocate_independent_pages(
            GetCurrentProcessId(),
            pid,
            0x1000,
            0,
            driver->alloc_mode::ALLOC_AT_LOW_ADDRESS
        );

        if (remote_shellcode == NULL) {
            return false;
        }

        void* local_alloc = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!local_alloc) {
            return false;
        }

        memcpy(local_alloc, &dll_main_shellcode, sizeof(dll_main_shellcode));

        std::uintptr_t shell_data_addr = (std::uintptr_t)remote_shellcode + sizeof(dll_main_shellcode);

        *(std::uintptr_t*)((std::uintptr_t)local_alloc + shell_data_offset) = shell_data_addr;

        pmain_struct main_data = (pmain_struct)((std::uintptr_t)local_alloc + sizeof(dll_main_shellcode));
        main_data->status = 0;
        main_data->dll_base = (HINSTANCE)alloc_base;
        main_data->fn_dll_main = (std::uintptr_t)alloc_base + entry_point;

        driver->write_virtual_memory(pid, (std::uintptr_t)remote_shellcode, local_alloc, shell_size);

        void* original_ptr = nullptr;
        driver->read_virtual_memory(pid, iat_entry, &original_ptr, sizeof(uintptr_t));

        driver->write_virtual_memory(pid, iat_entry, &remote_shellcode, sizeof(uintptr_t));

        main_struct status_check = { 0 };

        const int max_wait_cycles = 1500; // 15 seconds at 10ms per cycle
        int wait_cycles = 0;

        while (status_check.status != 2 && wait_cycles < max_wait_cycles) {
            Sleep(10);
            driver->read_virtual_memory(pid, shell_data_addr, &status_check, sizeof(std::uintptr_t));
            wait_cycles++;
        }

        driver->write_virtual_memory(pid, iat_entry, &original_ptr, sizeof(std::uintptr_t));

        std::uint8_t zero_shell[sizeof(dll_main_shellcode)] = { 0 };
        driver->write_virtual_memory(pid, (std::uintptr_t)remote_shellcode, zero_shell, sizeof(zero_shell));

        VirtualFree(local_alloc, 0, MEM_RELEASE);

        return status_check.status == 2; // Return success based on status
    }

public:

    void set_iat_hook_params(const char* hook_mod, const char* hook_func, const wchar_t* main_module) {
        this->hook_module = hook_mod;
        this->hook_function = hook_func;
        this->target_module = main_module;
    }

    [[nodiscard]] __forceinline auto run(const std::uint32_t pid, const std::uint32_t tid, void* buffer, uintptr_t offsets, driver_t::memory_type memory_type, driver_t::alloc_mode alloc_mode) -> bool {
        const auto nt_header = get_nt_headers(reinterpret_cast<std::uintptr_t>(buffer));
        if (!nt_header) {
            log("ERROR", "failed to get NT headers");
            return false;
        }

        std::size_t size = nt_header->OptionalHeader.SizeOfImage;

        log("SUCCESS", "DLL size 0x%llx", size);

        auto dll_alloc_base = driver->allocate_independent_pages(GetCurrentProcessId(), pid, size, memory_type, alloc_mode); 
        if (!dll_alloc_base) {
            log("ERROR", "invalid base address");
            return false;
        }

        log("SUCCESS", "allocated memory at: 0x%llx", reinterpret_cast<std::uintptr_t>(dll_alloc_base));

        if (!relocate_image(dll_alloc_base, buffer, nt_header)) {
            log("ERROR", "image failed to relocate");
            return false;
        }

        log("SUCCESS", "relocated image");

        if (!resolve_import(pid, tid, buffer, nt_header)) {
            log("ERROR", "failed to resolve imports");
            return false;
        }

        log("SUCCESS", "resolved imports");

        if (!map_sections(pid, dll_alloc_base, buffer, nt_header, 0)) {  // memory_type
            log("ERROR", "failed to map sections");
            return false;
        }

        log("SUCCESS", "resolved mapped sections");

        if (!hijack_via_iat_hook(pid, dll_alloc_base, nt_header->OptionalHeader.AddressOfEntryPoint)) {
            log("ERROR", "Failed to hijack via iat hook");
            return false;
        }

        return true;
    }
};

inline std::unique_ptr<injector_t> injector = std::make_unique<injector_t>();