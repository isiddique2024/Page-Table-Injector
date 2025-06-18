#pragma once
namespace mem {

    auto flush_tlb() -> void {
        globals::ke_flush_entire_tb(TRUE, TRUE);
        globals::ke_invalidate_all_caches();
        globals::mi_flush_entire_tb_due_to_attribute_change();
    }

    auto virtual_to_physical(void* virtual_address) -> PHYSICAL_ADDRESS
    {
        PHYSICAL_ADDRESS physical_address{ 0 };
        const uintptr_t va = reinterpret_cast<uintptr_t>(virtual_address);

        PTE_64* const pte = reinterpret_cast<PTE_64*>(globals::mi_get_pte_address(va));
        if (!pte || !pte->Present) {
            return physical_address;
        }

        const uintptr_t pfn = pte->PageFrameNumber;
        physical_address.QuadPart = (pfn << PAGE_SHIFT) | (va & 0xFFF);

        return physical_address;
    }


    auto safe_copy(void* const dst, void* const src, const size_t size) -> bool 
    {
        SIZE_T bytes = 0;
        const auto current_process = globals::io_get_current_process();

        return globals::mm_copy_virtual_memory(
            current_process,
            src,
            current_process,
            dst,
            size,
            KernelMode,
            &bytes
            ) == STATUS_SUCCESS && bytes == size;
    }

    auto probe_user_address(PVOID const addr, const SIZE_T size, const ULONG alignment) -> bool {
        if (size == 0) {
            return TRUE;
        }

        const auto current = reinterpret_cast<ULONG_PTR>(addr);

        if ((current & (alignment - 1)) != 0) {
            return false;
        }

        const auto last = current + size - 1;

        if ((last < current) || (last >= (uintptr_t)globals::mm_user_probe_address)) {
            return false;
        }

        return true;
    }

    auto get_driver_base(LPCSTR const module_name) -> void* {
        void* module_base = nullptr;

        UNICODE_STRING unicode_module_name;
        ANSI_STRING ansi_module_name;

        UNICODE_STRING routine_name;
        globals::rtl_init_unicode_string(&routine_name, L"PsLoadedModuleList");

        const auto module_list = static_cast<PLIST_ENTRY>(globals::mm_get_system_routine_address(&routine_name));
        auto current_entry = module_list->Flink;

        globals::rtl_init_ansi_string(&ansi_module_name, module_name);
        globals::rtl_ansi_string_to_unicode_string(&unicode_module_name, &ansi_module_name, TRUE);

        while (current_entry != module_list) {
            const auto data_table_entry = CONTAINING_RECORD(
                current_entry,
                LDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks
            );

            if (globals::rtl_compare_unicode_string(&data_table_entry->BaseDllName, &unicode_module_name, TRUE) == 0) {
                module_base = data_table_entry->DllBase;
                break;
            }

            current_entry = current_entry->Flink;
        }

        globals::rtl_free_unicode_string(&unicode_module_name);
        return module_base;
    }

    bool hide_physical_memory(uintptr_t page_frame_number, hide_type type) {

        const auto pfn_entry_addr = *reinterpret_cast<uintptr_t*>(globals::mm_pfn_db) +
            0x30 * (page_frame_number);

        switch (type) {
        case hide_type::NONE:
        {
            break;
        }
        case hide_type::PFN_EXISTS_BIT: // returns 0xC0000141, STATUS_INVALID_ADDRESS, The address handle that was given to the transport was invalid.
        {
            const auto PFN_EXISTS_BIT = (globals::build_version >= 22000) ?
                (1ULL << 54) : (1ULL << 50);

            auto* u4_field = reinterpret_cast<uint64_t*>(
                reinterpret_cast<uint8_t*>(pfn_entry_addr) + 0x28
                );

            *u4_field &= ~PFN_EXISTS_BIT;
            break;
        }

        case hide_type::MI_REMOVE_PHYSICAL_MEMORY: // returns 0xC0000141, STATUS_INVALID_ADDRESS, The address handle that was given to the transport was invalid.
        {
            const auto FLAGS = globals::build_version >= 26100 ? 0x62 : 0x32;

            // removes PFN from MmPhysicalMemoryBlock
            NTSTATUS status = globals::mi_remove_physical_memory(page_frame_number, 1, FLAGS);
            if (!NT_SUCCESS(status)) {
                log("ERROR", "failed to remove physical memory on 0x%llx status 0x%X", page_frame_number, status);
                return false;
            }

            // nulls PFN entry for physical page
            globals::memset(reinterpret_cast<void*>(pfn_entry_addr), 0, 0x30);

            break;
        }
        case hide_type::SET_PARITY_ERROR:
        {
            // get pointers to the structures
            auto* e3_field = reinterpret_cast<_MMPFNENTRY3*>(pfn_entry_addr + 0x23);

            // set ParityError, causes MmCopyMemory to return 0xC0000709 (STATUS_HARDWARE_MEMORY_ERROR) on the physical pages
            e3_field->ParityError = 1;

            break;
        }
        case hide_type::SET_LOCK_BIT:
        {
            // get pointers to the structures
            auto* u2 = reinterpret_cast<_MIPFNBLINK*>(pfn_entry_addr + 0x18);

            // set LockBit, causes CPU to yield when MmCopyMemory is called on your dll's physical address, think of this moreso as an anti-debug mechanism.
            // This can be used to see if your allocation is stealthy enough.
            u2->LockBit = 1;

            break;
        }
        case hide_type::HIDE_TRANSLATION: // this doesn't support driver pages yet since I'm using MmGetVirtualForPhysical for that lol, I have to rewrite the driver hiding function 
        {
            PHYSICAL_ADDRESS physical_addr;
            physical_addr.QuadPart = PFN_TO_PAGE(page_frame_number);

            // log the virtual address before nulling MMPFN.PteAddress
            void* virtual_addr_before = globals::mm_get_virtual_for_physical(physical_addr);

            log("INFO", "MmGetVirtualForPhysical before nulling MMPFN.PteAddress: 0x%p for PFN 0x%llx",
                virtual_addr_before, page_frame_number);

            // null MMPFN.PteAddress, this causes MmGetVirtualForPhysical to return the wrong virtual address that's mapped by the PTE
            //
            // here's the pseudocode for MmGetVirtualForPhysical
            // 
            // PVOID __stdcall MmGetVirtualForPhysical(PHYSICAL_ADDRESS PhysicalAddress)
            // {
            //    return (PVOID)((PhysicalAddress.LowPart & 0xFFF)
            //        + ((__int64)(*(_QWORD*)(0x30 * ((unsigned __int64)PhysicalAddress.QuadPart >> 12) - 0x21FFFFFFFFF8LL) << 25) >> 16));
            // }
            // 
            // pay attention specifically to *(_QWORD*)(0x30 * ((unsigned __int64)PhysicalAddress.QuadPart >> 12) - 0x21FFFFFFFFF8LL).
            // this is accessing the MmPfnDatabase for this pfn, specifically the PteAddress field. 
            // ideally you would want to spoof this PteAddress field to look more legitimate by using another pfn entry's PteAddress field, but in this case it will just make MmGetVirtualForPhysical return 0 for this physical address

            // null MMPFN.PteAddress
            auto* pte_address = reinterpret_cast<uint64_t*>(pfn_entry_addr + 0x8);
            *pte_address = 0;

            // log the virtual address after nulling MMPFN.PteAddress
            void* virtual_addr_after = globals::mm_get_virtual_for_physical(physical_addr);
            log("INFO", "MmGetVirtualForPhysical after nulling MMPFN.PteAddress: 0x%p for PFN 0x%llx",
                virtual_addr_after, page_frame_number);

            // verify the unlinking worked
            if (virtual_addr_after == nullptr || virtual_addr_after != virtual_addr_before) {
                log("SUCCESS", "successfully nulled MMPFN.PteAddress, phys to virt translation has failed");
            }
            else {
                log("WARNING", "virtual address unchanged after nulling MMPFN.PteAddress - operation may have failed");
            }

            break;
        }
        }

        return true;
    }
   
    auto allocate_independent_pages(size_t size) -> void*
    {
        void* base_address = globals::mm_allocate_independent_pages_ex(size, -1, 0, 0);
        if (!base_address) {
            log("ERROR", "failed to allocate actual page");
            return 0;
        }

        globals::memset(base_address, 0, size);

        uintptr_t pfn = mem::virtual_to_physical(base_address).QuadPart >> PAGE_SHIFT;
        if (!pfn) {
            globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(base_address), size);
            log("ERROR", "failed to get pfn for page");
            return 0;
        }

        bool hide_status = mem::hide_physical_memory(pfn, static_cast<hide_type>(globals::dll_hide_type));
        if (!hide_status) {
            globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(base_address), size);
            log("ERROR", "failed to hide pfn for page");
            return 0;
        }

        return base_address;
    }

    auto allocate_contiguous_memory(size_t size) -> void*
    {

        PHYSICAL_ADDRESS max_address{};
        max_address.QuadPart = MAXULONG64;

        void* base_address = globals::mm_allocate_contiguous_memory(size, max_address);
        if (!base_address) {
            log("ERROR", "failed to allocate actual page");
            return 0;
        }

        globals::memset(base_address, 0, size);

        uintptr_t pfn = 0;

        PDE_2MB_64* pde = reinterpret_cast<PDE_2MB_64*>(globals::mi_get_pde_address(reinterpret_cast<uintptr_t>(base_address)));
        if (pde->Present && pde->LargePage) {
            pfn = pde->PageFrameNumber;
        }
        else
        {
            pfn = PAGE_TO_PFN(mem::virtual_to_physical(base_address).QuadPart);
        }

        if (!pfn) {
            globals::mm_free_contiguous_memory(base_address);
            log("ERROR", "failed to get pfn for page");
            return 0;
        }

        bool hide_status = mem::hide_physical_memory(pfn, static_cast<hide_type>(globals::dll_hide_type));
        if (!hide_status) {
            globals::mm_free_contiguous_memory(base_address);
            log("ERROR", "failed to hide pfn for page");
            return 0;
        }

        return base_address;
    }

    NTSTATUS write_page_tables(uintptr_t target_dir_base, uintptr_t base_va, size_t page_count, bool use_large_page) {

        const size_t LARGE_PAGE_SIZE = 0x200000;

        PHYSICAL_ADDRESS max_address{};
        max_address.QuadPart = MAXULONG64;

        for (size_t i = 0; i < page_count; ++i) {
            const auto current_va = base_va + i * (use_large_page ? LARGE_PAGE_SIZE : PAGE_SIZE);
            ADDRESS_TRANSLATION_HELPER helper;
            helper.AsUInt64 = current_va;

            auto actual_page = use_large_page ? mem::allocate_contiguous_memory(LARGE_PAGE_SIZE) : mem::allocate_independent_pages(PAGE_SIZE);
            if (!actual_page) {
                log("ERROR", "failed to allocate actual page");
                return STATUS_NO_MEMORY;

            }

            uintptr_t page_frame_number = 0;

            if (use_large_page) {
                PDE_2MB_64* pde_pfn = reinterpret_cast<PDE_2MB_64*>(globals::mi_get_pde_address(reinterpret_cast<uintptr_t>(actual_page)));
                page_frame_number = pde_pfn->PageFrameNumber;
            }
            else {
                page_frame_number = PAGE_TO_PFN(mem::virtual_to_physical(actual_page).QuadPart);
            }

            if (!page_frame_number) {
                log("ERROR", "failed to get pfn from actual page");
                return STATUS_NO_MEMORY;
            }

            uintptr_t pml4_phys = target_dir_base;
            PML4E_64 pml4e = { 0 };

            // read and setup PML4E
            physical::read_physical_address(pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));

            if (!pml4e.Present) {
                auto pdpt = mem::allocate_independent_pages(PAGE_SIZE);
                if (!pdpt) {
                    log("ERROR", "failed to allocate pdpt");
                    return STATUS_NO_MEMORY;
                }

                auto pdpt_pfn = PAGE_TO_PFN(mem::virtual_to_physical(pdpt).QuadPart);
                if (!pdpt_pfn) {
                    log("ERROR", "failed to get pdpt pfn");
                    return STATUS_NO_MEMORY;
                }

                pml4e.Flags = 0;
                pml4e.Present = 1;
                pml4e.Write = 1;
                pml4e.Supervisor = 1;
                pml4e.Accessed = 1;
                pml4e.ExecuteDisable = 0;
                pml4e.PageFrameNumber = pdpt_pfn;

                physical::write_physical_address(pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));

            }

            // read and setup PDPT
            PDPTE_64 pdpte = { 0 };
            physical::read_physical_address(PFN_TO_PAGE(pml4e.PageFrameNumber) + helper.AsIndex.Pdpt * sizeof(PDPTE_64), &pdpte, sizeof(PDPTE_64));

            if (!pdpte.Present) {
                auto pd = mem::allocate_independent_pages(PAGE_SIZE);
                if (!pd) {
                    log("ERROR", "failed to allocate pd");
                    return STATUS_NO_MEMORY;
                }

                auto pd_pfn = PAGE_TO_PFN(mem::virtual_to_physical(pd).QuadPart);
                if (!pd_pfn) {
                    log("ERROR", "failed to get pd pfn");
                    return STATUS_NO_MEMORY;
                }

                pdpte.Flags = 0;
                pdpte.Present = 1;
                pdpte.Write = 1;
                pdpte.Supervisor = 1;
                pdpte.Accessed = 1;
                pdpte.ExecuteDisable = 0;
                pdpte.PageFrameNumber = pd_pfn;

                physical::write_physical_address(PFN_TO_PAGE(pml4e.PageFrameNumber) + helper.AsIndex.Pdpt * sizeof(PDPTE_64), &pdpte, sizeof(PDPTE_64));
            }

            if (use_large_page) {
                // read and setup PD
                PDE_2MB_64 pde = { 0 };
                physical::read_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_2MB_64), &pde, sizeof(PDE_2MB_64));

                if (!pde.Present) {

                    pde.Flags = 0;
                    pde.Present = 1;
                    pde.Write = 1;
                    pde.Supervisor = 1;
                    pde.LargePage = 1;
                    pde.Accessed = 1;
                    pde.ExecuteDisable = 0;
                    pde.PageFrameNumber = page_frame_number;

                    physical::write_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_2MB_64), &pde, sizeof(PDE_2MB_64));
                }
            }
            else {
                // read and setup PD
                PDE_64 pde = { 0 };
                physical::read_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64));

                if (!pde.Present) {
                    auto pt = mem::allocate_independent_pages(PAGE_SIZE);
                    if (!pt) {
                        log("ERROR", "failed to allocate pt");
                        return STATUS_NO_MEMORY;
                    }

                    auto pt_pfn = PAGE_TO_PFN(mem::virtual_to_physical(pt).QuadPart);
                    if (!pt_pfn) {
                        log("ERROR", "failed to get pt pfn");
                        return STATUS_NO_MEMORY;
                    }

                    pde.Flags = 0;
                    pde.Present = 1;
                    pde.Write = 1;
                    pde.Supervisor = 1;
                    pde.Accessed = 1;
                    pde.ExecuteDisable = 0;
                    pde.PageFrameNumber = pt_pfn;

                    physical::write_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64));

                }

                // setup PTE
                PTE_64 pte = { 0 };
                pte.Present = 1;
                pte.Write = 1;
                pte.Supervisor = 1;
                pte.Accessed = 1;
                pte.ExecuteDisable = 0;
                pte.PageFrameNumber = page_frame_number;

                physical::write_physical_address(PFN_TO_PAGE(pde.PageFrameNumber) + helper.AsIndex.Pt * sizeof(PTE_64), &pte, sizeof(PTE_64));
            }

            log("INFO", "page %zd: va: 0x%llx, pfn: 0x%llx", i, current_va, page_frame_number);

        }

        return STATUS_SUCCESS;
    }

    // look for PTEs where pte.PageFrame is null specifically within the .text section. 
    // probably not a good idea due to potential VAD and PTE mismatch and or integrity checks on .text section. 
    // if the process exits there will be a MEMORY_MANAGEMENT BSOD so register a process exit callback and free the pages 
    void* hijack_null_pfn(const uint32_t local_pid, const uint32_t target_pid, const size_t size, const bool use_large_page) {
        const size_t page_mask = PAGE_SIZE - 1;
        const size_t aligned_size = (size + page_mask) & ~page_mask;
        const size_t page_count = aligned_size >> PAGE_SHIFT;

        log("INFO", "searching for space of size 0x%llx (%d pages) within .text section", aligned_size, page_count);

        PEPROCESS target_process;
        if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(target_pid), &target_process) != STATUS_SUCCESS) {
            log("ERROR", "failed to lookup target process");
            return nullptr;
        }

        // get target process directory base
        const auto target_dir_base = physical::get_process_directory_base(target_process);
        if (!target_dir_base) {
            log("ERROR", "failed to lookup target process directory base");
            globals::obf_dereference_object(target_process);
            return nullptr;
        }

        // get target process PEB
        PPEB peb_address = globals::ps_get_process_peb(target_process);
        if (!peb_address) {
            log("ERROR", "failed to get PEB address");
            globals::obf_dereference_object(target_process);
            return nullptr;
        }

        PEB peb;
        physical::read_process_memory(target_process, reinterpret_cast<uintptr_t>(peb_address), &peb, sizeof(PEB));
        log("INFO", "PEB found at 0x%llx", peb_address);

        PEB_LDR_DATA ldr_data;
        physical::read_process_memory(target_process, reinterpret_cast<uintptr_t>(peb.Ldr), &ldr_data, sizeof(PEB_LDR_DATA));

        // get main module 
        LDR_DATA_TABLE_ENTRY main_module;
        physical::read_process_memory(target_process,
            reinterpret_cast<uintptr_t>(CONTAINING_RECORD(ldr_data.InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)),
            &main_module,
            sizeof(LDR_DATA_TABLE_ENTRY));

        uintptr_t module_base = reinterpret_cast<uintptr_t>(main_module.DllBase);

        // read the DOS header
        IMAGE_DOS_HEADER dos_header;
        physical::read_process_memory(target_process, module_base, &dos_header, sizeof(IMAGE_DOS_HEADER));

        if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
            log("ERROR", "invalid DOS header signature");
            globals::obf_dereference_object(target_process);
            return nullptr;
        }

        // read the NT headers
        IMAGE_NT_HEADERS nt_headers;
        physical::read_process_memory(target_process, module_base + dos_header.e_lfanew, &nt_headers, sizeof(IMAGE_NT_HEADERS));

        if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
            log("ERROR", "invalid NT header signature");
            globals::obf_dereference_object(target_process);
            return nullptr;
        }

        // calc the section headers address
        uintptr_t section_header_addr = module_base + dos_header.e_lfanew +
            FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
            nt_headers.FileHeader.SizeOfOptionalHeader;

        // find the .text section
        bool found_text_section = false;
        uintptr_t text_section_start = 0;
        uintptr_t text_section_end = 0;

        for (WORD i = 0; i < nt_headers.FileHeader.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER section_header;
            physical::read_process_memory(
                target_process,
                section_header_addr + (i * sizeof(IMAGE_SECTION_HEADER)),
                &section_header,
                sizeof(IMAGE_SECTION_HEADER)
            );

            // check if this is the .text section
            // the section name might not be null-terminated, so we need to check carefully
            if (globals::memcmp(section_header.Name, ".text", 5) == 0 ||
                globals::memcmp(section_header.Name, "CODE", 4) == 0) {

                text_section_start = module_base + section_header.VirtualAddress;
                text_section_end = text_section_start + section_header.Misc.VirtualSize;
                found_text_section = true;

                log("INFO", "found .text section at 0x%llx - 0x%llx", text_section_start, text_section_end);
                break;
            }
        }

        if (!found_text_section) {
            log("ERROR", "could not find .text section in main module");
            globals::obf_dereference_object(target_process);
            return nullptr;
        }

        // align to page boundaries
        text_section_start &= ~(PAGE_SIZE - 1);  // round down to page boundary
        text_section_end = (text_section_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);  // round up to page boundary

        log("INFO", "scanning .text section range (page-aligned): 0x%llx - 0x%llx", text_section_start, text_section_end);

        uintptr_t base_va = 0;
        uintptr_t pml4_phys = target_dir_base;

        // scan through the .text section looking for empty/null pages
        for (uintptr_t current_va = text_section_start; current_va < text_section_end; current_va += PAGE_SIZE) {
            ADDRESS_TRANSLATION_HELPER helper;
            helper.AsUInt64 = current_va;

            // read PML4E
            PML4E_64 pml4e = { 0 };
            physical::read_physical_address(pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));

            if (!pml4e.Present) continue;

            // read PDPTE
            PDPTE_64 pdpte = { 0 };
            physical::read_physical_address(PFN_TO_PAGE(pml4e.PageFrameNumber) + helper.AsIndex.Pdpt * sizeof(PDPTE_64), &pdpte, sizeof(PDPTE_64));

            if (!pdpte.Present) continue;

            // read PDE
            PDE_64 pde = { 0 };
            physical::read_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64));

            if (!pde.Present) continue;

            // read PTE
            PTE_64 pte = { 0 };
            physical::read_physical_address(PFN_TO_PAGE(pde.PageFrameNumber) + helper.AsIndex.Pt * sizeof(PTE_64), &pte, sizeof(PTE_64));

            if (pte.PageFrameNumber == 0) {
                // found potential page to hijack, check for continuous space
                uintptr_t potential_start = current_va;
                size_t available_size = 0;

                while (available_size < aligned_size && current_va < text_section_end) {
                    helper.AsUInt64 = current_va;

                    // read through page tables again for this VA
                    physical::read_physical_address(pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));
                    if (!pml4e.Present) break;

                    physical::read_physical_address(PFN_TO_PAGE(pml4e.PageFrameNumber) + helper.AsIndex.Pdpt * sizeof(PDPTE_64), &pdpte, sizeof(PDPTE_64));
                    if (!pdpte.Present) break;

                    physical::read_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64));
                    if (!pde.Present) break;

                    physical::read_physical_address(PFN_TO_PAGE(pde.PageFrameNumber) + helper.AsIndex.Pt * sizeof(PTE_64), &pte, sizeof(PTE_64));

                    if (pte.PageFrameNumber == 0) {
                        available_size += PAGE_SIZE;
                        current_va += PAGE_SIZE;
                    }
                    else {
                        break;
                    }
                }

                if (available_size >= aligned_size) {
                    base_va = potential_start;
                    log("SUCCESS", "found suitable empty/null page range within .text section at 0x%llx with size 0x%llx", base_va, available_size);
                    break;
                }
            }
        }

        if (!base_va) {
            log("ERROR", "could not find suitable empty/null page range in .text section");
            globals::obf_dereference_object(target_process);
            return nullptr;
        }

        log("INFO", "selected base address: 0x%llx", base_va);

        auto write_pt_status = mem::write_page_tables(target_dir_base, base_va, page_count, use_large_page);

        if (!NT_SUCCESS(write_pt_status)) {
            log("ERROR", "failed to write page tables");
            globals::obf_dereference_object(target_process);
            return nullptr;
        }

        globals::obf_dereference_object(target_process);

        // flush TLB and caches
        mem::flush_tlb();

        return reinterpret_cast<void*>(base_va);
    }

    // finds space between two legit modules and maps the dll there
    void* allocate_between_modules(const uint32_t local_pid, const uint32_t target_pid, const size_t size, const bool use_large_page) {
        const size_t page_mask = PAGE_SIZE - 1;
        const size_t aligned_size = (size + page_mask) & ~page_mask;
        const size_t page_count = aligned_size >> PAGE_SHIFT;

        log("INFO", "searching for space of size 0x%llx (%d pages)", aligned_size, page_count);

        PEPROCESS target_process;
        if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(target_pid), &target_process) != STATUS_SUCCESS) {
            log("ERROR", "failed to lookup target process");
            return nullptr;
        }

        const auto target_dir_base = physical::get_process_directory_base(target_process);
        if (!target_dir_base) {
            log("ERROR", "failed to lookup target process directory base");
            return nullptr;
        }

        PPEB peb_address = globals::ps_get_process_peb(target_process);
        if (!peb_address) {
            log("ERROR", "failed to get PEB address");
            globals::obf_dereference_object(target_process);
            return nullptr;
        }

        PEB peb;
        physical::read_process_memory(target_process, reinterpret_cast<uintptr_t>(peb_address), &peb, sizeof(PEB));
        log("INFO", "PEB found at 0x%llx", peb_address);

        PEB_LDR_DATA ldr_data;
        physical::read_process_memory(target_process, reinterpret_cast<uintptr_t>(peb.Ldr), &ldr_data, sizeof(PEB_LDR_DATA));

        PLIST_ENTRY current_entry = ldr_data.InMemoryOrderModuleList.Flink;
        PLIST_ENTRY first_entry = current_entry;
        uintptr_t base_va = 0;

        uintptr_t last_module_end = 0;
        int module_count = 0;

        do {
            LDR_DATA_TABLE_ENTRY entry;
            physical::read_process_memory(target_process,
                reinterpret_cast<uintptr_t>(CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)),
                &entry,
                sizeof(LDR_DATA_TABLE_ENTRY));

            if (entry.DllBase && (entry.Flags & 0x00000004)) { // IMAGE_DLL
                uintptr_t current_module_start = reinterpret_cast<uintptr_t>(entry.DllBase);

                log("INFO", "module %d: base: 0x%llx, Size: 0x%llx",
                    module_count++, current_module_start, entry.SizeOfImage);

                if (last_module_end) {
                    uintptr_t gap_start = last_module_end;
                    while (gap_start % 0x10000 != 0) {
                        gap_start += 1;
                    }

                    uintptr_t gap_size = current_module_start - gap_start;

                    log("INFO", "gap found: start: 0x%llx, size: 0x%llx", gap_start, gap_size);

                    if (gap_size >= aligned_size) {
                        base_va = gap_start;
                        log("SUCCESS", "found suitable gap at 0x%llx with size 0x%llx", gap_start, gap_size);
                        break;
                    }
                }

                last_module_end = current_module_start + entry.SizeOfImage;
                log("INFO", "module ends at 0x%llx", last_module_end);
            }

            current_entry = entry.InMemoryOrderLinks.Flink;
        } while (current_entry != first_entry);

        if (!base_va) {
            log("ERROR", "could not find suitable space between modules after checking %d modules", module_count);
            globals::obf_dereference_object(target_process);
            return nullptr;
        }

        log("INFO", "selected base address: 0x%llx", base_va);

        auto write_pt_status = mem::write_page_tables(target_dir_base, base_va, page_count, use_large_page);

        if (!NT_SUCCESS(write_pt_status)) {
            log("ERROR", "failed to write page tables");
            globals::obf_dereference_object(target_process);
            return nullptr;
        }

        globals::obf_dereference_object(target_process);

        // flush TLB and caches
        mem::flush_tlb();

        return reinterpret_cast<void*>(base_va);
    }

    void* allocate_at_non_present_pml4e(const uint32_t local_pid, const uint32_t target_pid, const size_t size, const bool use_large_page, const bool use_high_address) {
        // page size constants
        const size_t STANDARD_PAGE_SIZE = 0x1000;        // 4KB
        const size_t LARGE_PAGE_SIZE = 0x200000;         // 2MB
        const size_t page_size = use_large_page ? LARGE_PAGE_SIZE : STANDARD_PAGE_SIZE;
        const size_t page_mask = page_size - 1;
        const size_t page_shift = use_large_page ? 21 : 12;

        // align the requested size to page boundaries
        const size_t aligned_size = (size + page_mask) & ~page_mask;
        const size_t page_count = aligned_size >> page_shift;

        // get target process
        PEPROCESS target_process;
        if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(target_pid), &target_process) != STATUS_SUCCESS) {
            log("ERROR", "failed to lookup target process");
            return nullptr;
        }

        // get target process directory base
        const auto target_dir_base = physical::get_process_directory_base(target_process);
        if (!target_dir_base) {
            globals::obf_dereference_object(target_process);
            log("ERROR", "failed to lookup target process directory base");
            return nullptr;
        }

        // set the search range based on whether high or low address is requested
        uint32_t start_idx = use_high_address ? 256 : 100;
        uint32_t end_idx = use_high_address ? 511 : 256;
        const char* space_type = use_high_address ? "kernel" : "usermode";

        // count available indices
        uint32_t available_count = 0;
        PML4E_64 pml4e = { 0 };

        for (uint32_t idx = start_idx; idx < end_idx; idx++) {
            physical::read_physical_address(target_dir_base + idx * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));
            if (!pml4e.Present) {
                available_count++;
            }
        }

        if (available_count == 0) {
            globals::obf_dereference_object(target_process);
            log("ERROR", "failed to find any non-present PML4E in %s space", space_type);
            return nullptr;
        }

        // generate random seed using current time and process info
        static bool seeded = false;
        if (!seeded) {
            LARGE_INTEGER time;
            KeQuerySystemTime(&time);
            globals::srand((unsigned int)(time.QuadPart ^ (uintptr_t)target_process ^ target_pid));
            seeded = true;
        }

        // pick a random number between 0 and available_count-1
        uint32_t target_choice = globals::rand() % available_count;

        // find the target_choice-th available index
        uint32_t current_choice = 0;
        uint32_t selected_pml4_index = 0;

        for (uint32_t idx = start_idx; idx < end_idx; idx++) {
            physical::read_physical_address(target_dir_base + idx * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));
            if (!pml4e.Present) {
                if (current_choice == target_choice) {
                    selected_pml4_index = idx;
                    break;
                }
                current_choice++;
            }
        }

        log("INFO", "found %u available PML4E indices, randomly selected index: %u",
            available_count, selected_pml4_index);

        // need to modularize this 
        // additional randomization within the selected PML4E's address space
        // this adds entropy to the lower bits of the address
        uint64_t additional_offset = 0;
        if (use_large_page) {
            // for large pages, we can randomize PDPTE selection (bits 30-38)
            // each PDPTE covers 1GB, so we randomize within available PDPTEs
            additional_offset = (static_cast<uint64_t>(globals::rand() % 512) << 30);
        }
        else {
            // for small pages, randomize at PDE level (bits 21-29) 
            // each PDE covers 2MB, so we randomize within available PDEs
            additional_offset = (static_cast<uint64_t>(globals::rand() % 512) << 21);
        }

        // calc the base virtual address using the selected PML4E index
        uintptr_t base_va;
        if (use_high_address) {
            base_va = 0xFFFF000000000000ULL | page_table::get_pml4e(selected_pml4_index) | additional_offset;
        }
        else {
            base_va = page_table::get_pml4e(selected_pml4_index) | additional_offset;
        }

        log("INFO", "selected base address: 0x%llx", base_va);

        auto write_pt_status = mem::write_page_tables(target_dir_base, base_va, page_count, use_large_page);
        if (!NT_SUCCESS(write_pt_status)) {
            globals::obf_dereference_object(target_process);
            log("ERROR", "failed to write page tables, NTSTATUS: 0x%08X", write_pt_status);
            return nullptr;
        }

        globals::obf_dereference_object(target_process);

        // flush TLB and caches
        mem::flush_tlb();
        return reinterpret_cast<void*>(base_va);
    }


}