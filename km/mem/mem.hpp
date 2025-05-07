#pragma once
namespace mem {

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
        const auto current_process = IoGetCurrentProcess();

        return MmCopyVirtualMemory(
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

        if ((last < current) || (last >= MmUserProbeAddress)) {
            return false;
        }

        return true;
    }

    auto get_driver_base(LPCSTR const module_name) -> void* {
        void* module_base = nullptr;

        UNICODE_STRING unicode_module_name;
        ANSI_STRING ansi_module_name;

        UNICODE_STRING routine_name;
        RtlInitUnicodeString(&routine_name, L"PsLoadedModuleList");

        const auto module_list = static_cast<PLIST_ENTRY>(MmGetSystemRoutineAddress(&routine_name));
        auto current_entry = module_list->Flink;

        RtlInitAnsiString(&ansi_module_name, module_name);
        RtlAnsiStringToUnicodeString(&unicode_module_name, &ansi_module_name, TRUE);

        while (current_entry != module_list) {
            const auto data_table_entry = CONTAINING_RECORD(
                current_entry,
                LDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks
            );

            if (RtlCompareUnicodeString(&data_table_entry->BaseDllName, &unicode_module_name, TRUE) == 0) {
                module_base = data_table_entry->DllBase;
                break;
            }

            current_entry = current_entry->Flink;
        }

        RtlFreeUnicodeString(&unicode_module_name);
        return module_base;
    }

    bool hide_physical_memory(void* current_va, remove_type type) {
        const auto physical_address = mem::virtual_to_physical(current_va); // mem::virtual_to_physical
        if (!physical_address.QuadPart) {
            log("ERROR", "failed to get physical address for VA: %p", current_va);
            return false;
        }

        const auto page_frame_number = physical_address.QuadPart >> PAGE_SHIFT;

        const auto pfn_entry_addr = *reinterpret_cast<uintptr_t*>(globals::mm_pfn_db) +
            0x30 * (page_frame_number);

        // store the original content of the page for verification
        uint64_t original_page_content = 0;
        SIZE_T bytes_read = 0;
        MM_COPY_ADDRESS source;
        source.PhysicalAddress = physical_address;

        const auto original_copy_status = MmCopyMemory(
            &original_page_content,
            source,
            sizeof(original_page_content),
            MM_COPY_MEMORY_PHYSICAL,
            &bytes_read
            );

        if (!NT_SUCCESS(original_copy_status)) {
            log("ERROR", "failed to read original page content: 0x%X", original_copy_status);
            return false;
        }

        switch (type) {
            case remove_type::PFN_EXISTS_BIT: // returns 0xC0000141, STATUS_INVALID_ADDRESS, The address handle that was given to the transport was invalid.
            {
                const auto PFN_EXISTS_BIT = (globals::build_version >= 22000) ?
                    (1ULL << 54) : (1ULL << 50);

                auto* u4_field = reinterpret_cast<uint64_t*>(
                    reinterpret_cast<uint8_t*>(pfn_entry_addr) + 0x28
                    );

                *u4_field &= ~PFN_EXISTS_BIT;
                break;
            }

            case remove_type::MI_REMOVE_PHYSICAL_MEMORY: // returns 0xC0000141, STATUS_INVALID_ADDRESS, The address handle that was given to the transport was invalid.
            {
                const auto FLAGS = globals::build_version >= 26100 ? 0x62 : 0x32;

                NTSTATUS status = globals::mi_remove_physical_memory(page_frame_number, 1, FLAGS);
                if (!NT_SUCCESS(status)) {
                    log("ERROR", "failed to remove physical memory on 0x%llx status 0x%X", page_frame_number, status);
                    return false;
                }

                memset(reinterpret_cast<void*>(pfn_entry_addr), 0, 0x30);

                break;
            }

            case remove_type::MARK_PHYSICAL_MEMORY_AS_BAD:
            {

                // get pointers to the structures
                auto* pfn_flags = reinterpret_cast<_MI_PFN_FLAGS*>(pfn_entry_addr + 0x20);
                auto* e3_field = reinterpret_cast<_MMPFNENTRY3*>(pfn_entry_addr + 0x23);

                // set RemovalRequested
                pfn_flags->RemovalRequested = 1;

                // clear all but high word
                pfn_flags->ReferenceCount = 0;
                pfn_flags->PageLocation = 0;
                pfn_flags->WriteInProgress = 0;
                pfn_flags->Modified = 0;
                pfn_flags->ReadInProgress = 0;
                pfn_flags->CacheAttribute = 0;

                // clear PteFrame
                auto* u4_field = reinterpret_cast<_MI_PFN_FLAGS4*>(pfn_entry_addr + 0x28);
                u4_field->Bits.PteFrame = 0;

                // set ParityError
                e3_field->ParityError = 1;

                break;
            }
        }

        uint64_t test_value = 0;
        bytes_read = 0;
        source.PhysicalAddress = physical_address;

        const auto copy_status = MmCopyMemory(
            &test_value,
            source,
            sizeof(test_value),
            MM_COPY_MEMORY_PHYSICAL,
            &bytes_read
            );

        if (!NT_SUCCESS(copy_status)) {
            if (copy_status == STATUS_INVALID_ADDRESS) {
                log("INFO", "copy failed with STATUS_INVALID_ADDRESS (expected)");
                return true;
            }
            log("INFO", "copy failed with unexpected status: 0x%X", copy_status);
            return true;
        }

        // verify if the copied data matches the original page content
        if (test_value == original_page_content) {
            log("ERROR", "copy succeeded and returned the original page content");
            return false;
        }
        else {
            log("INFO", "copy succeeded but returned different data (expected)");
            log("INFO", "original: 0x%llx, copied: 0x%llx", original_page_content, test_value);
            return true;
        }
    }

    NTSTATUS write_page_tables(uintptr_t target_dir_base, uintptr_t base_va, size_t page_count, bool use_large_page) {

        const size_t LARGE_PAGE_SIZE = 0x200000;

        PHYSICAL_ADDRESS max_address{};
        max_address.QuadPart = MAXULONG64;

        for (size_t i = 0; i < page_count; ++i) {
            const auto current_va = base_va + i * (use_large_page ? LARGE_PAGE_SIZE : PAGE_SIZE);
            ADDRESS_TRANSLATION_HELPER helper;
            helper.AsUInt64 = current_va;

            auto actual_page = (use_large_page ? MmAllocateContiguousMemory(LARGE_PAGE_SIZE, max_address) : globals::mm_allocate_independent_pages_ex(PAGE_SIZE, -1, 0, 0));
            if (!actual_page) {
                log("ERROR", "failed to allocate actual page");
                return STATUS_NO_MEMORY;

            }

            memset(actual_page, 0, use_large_page ? LARGE_PAGE_SIZE : PAGE_SIZE);

            const auto page_frame_number = mem::virtual_to_physical(actual_page).QuadPart >> PAGE_SHIFT;

            uintptr_t pml4_phys = target_dir_base;
            PML4E_64 pml4e = { 0 };

            // read and setup PML4E
            physical::read_physical_address(pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));

            if (!pml4e.Present) {
                auto pdpt = globals::mm_allocate_independent_pages_ex(PAGE_SIZE, -1, 0, 0);
                if (!pdpt) {
                    log("ERROR", "failed to allocate pdpt");
                    return STATUS_NO_MEMORY;
                }

                memset(pdpt, 0, PAGE_SIZE);

                pml4e.Flags = 0;
                pml4e.Present = 1;
                pml4e.Write = 1;
                pml4e.Supervisor = 1;
                pml4e.PageFrameNumber = mem::virtual_to_physical(pdpt).QuadPart >> PAGE_SHIFT;

                physical::write_physical_address(pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));

            }

            // read and setup PDPT
            PDPTE_64 pdpte = { 0 };
            physical::read_physical_address(PFN_TO_PAGE(pml4e.PageFrameNumber) + helper.AsIndex.Pdpt * sizeof(PDPTE_64), &pdpte, sizeof(PDPTE_64));

            if (!pdpte.Present) {
                auto pd = globals::mm_allocate_independent_pages_ex(PAGE_SIZE, -1, 0, 0);
                if (!pd) {
                    log("ERROR", "failed to allocate pd");
                    return STATUS_NO_MEMORY;
                }

                memset(pd, 0, PAGE_SIZE);

                pdpte.Flags = 0;
                pdpte.Present = 1;
                pdpte.Write = 1;
                pdpte.Supervisor = 1;
                pdpte.PageFrameNumber = mem::virtual_to_physical(pd).QuadPart >> PAGE_SHIFT;

                physical::write_physical_address(PFN_TO_PAGE(pml4e.PageFrameNumber) + helper.AsIndex.Pdpt * sizeof(PDPTE_64), &pdpte, sizeof(PDPTE_64));
            }

            if (use_large_page) {
                // read and setup PD
                PDE_64 pde = { 0 };
                physical::read_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64));

                if (!pde.Present) {

                    pde.Flags = 0;
                    pde.Present = 1;
                    pde.Write = 1;
                    pde.Supervisor = 1;
                    pde.LargePage = 1;
                    pde.PageFrameNumber = page_frame_number;

                    physical::write_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64));

                }
            }
            else {
                // read and setup PD
                PDE_64 pde = { 0 };
                physical::read_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64));

                if (!pde.Present) {
                    auto pt = globals::mm_allocate_independent_pages_ex(PAGE_SIZE, -1, 0, 0);
                    if (!pt) {
                        log("ERROR", "failed to allocate pt");
                        return STATUS_NO_MEMORY;
                    }

                    memset(pt, 0, PAGE_SIZE);

                    pde.Flags = 0;
                    pde.Present = 1;
                    pde.Write = 1;
                    pde.Supervisor = 1;
                    pde.PageFrameNumber = mem::virtual_to_physical(pt).QuadPart >> PAGE_SHIFT;

                    physical::write_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64));

                }

                // setup PTE

                PTE_64 pte = { 0 };
                pte.Present = 1;
                pte.Write = 1;
                pte.Dirty = 1; // to be more consistent with how a pte should look when a piece of memory is marked as bad
                pte.Supervisor = 1;
                pte.PageFrameNumber = page_frame_number;

                physical::write_physical_address(PFN_TO_PAGE(pde.PageFrameNumber) + helper.AsIndex.Pt * sizeof(PTE_64), &pte, sizeof(PTE_64));
            }

            mem::hide_physical_memory(actual_page, remove_type::MARK_PHYSICAL_MEMORY_AS_BAD);

            log("INFO", "page %zd: va: 0x%llx, pfn: 0x%llx", i, current_va, page_frame_number);
        }

        return STATUS_SUCCESS;
    }

    // look for pte's where pte.PageFrame is null, hijack and replace with our own page
    void* hijack_null_pfn(const uint32_t local_pid, const uint32_t target_pid, const size_t size, const bool use_large_page) {
        const size_t page_mask = PAGE_SIZE - 1;
        const size_t aligned_size = (size + page_mask) & ~page_mask;
        const size_t page_count = aligned_size >> PAGE_SHIFT;

        log("INFO", "searching for space of size 0x%llx (%d pages)", aligned_size, page_count);

        PEPROCESS target_process;
        if (PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target_pid), &target_process) != STATUS_SUCCESS) {
            log("ERROR", "failed to lookup target process");
            return nullptr;
        }

        physical::init();

        const auto target_dir_base = physical::get_process_directory_base(target_process);

        PPEB peb_address = PsGetProcessPeb(target_process);
        if (!peb_address) {
            log("ERROR", "failed to get PEB address");
            ObfDereferenceObject(target_process);
            return nullptr;
        }

        PEB peb;
        physical::read_process_memory(target_process, reinterpret_cast<ULONG64>(peb_address), &peb, sizeof(PEB));
        log("INFO", "PEB found at 0x%llx", peb_address);

        PEB_LDR_DATA ldr_data;
        physical::read_process_memory(target_process, reinterpret_cast<ULONG64>(peb.Ldr), &ldr_data, sizeof(PEB_LDR_DATA));

        // get main module 
        LDR_DATA_TABLE_ENTRY main_module;
        physical::read_process_memory(target_process,
            reinterpret_cast<ULONG64>(CONTAINING_RECORD(ldr_data.InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)),
            &main_module,
            sizeof(LDR_DATA_TABLE_ENTRY));

        uintptr_t module_start = reinterpret_cast<uintptr_t>(main_module.DllBase);
        uintptr_t module_end = module_start + main_module.SizeOfImage;

        log("INFO", "scanning main module range: 0x%llx - 0x%llx", module_start, module_end);

        uintptr_t base_va = 0;
        uintptr_t pml4_phys = target_dir_base;

        // scan through the main module's range looking for empty/null pages
        for (uintptr_t current_va = module_start; current_va < module_end; current_va += PAGE_SIZE) {
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

            if(pte.PageFrameNumber == 0){
                // found potential page to hijack, check for continuous space
                uintptr_t potential_start = current_va;
                size_t available_size = 0;

                while (available_size < aligned_size && current_va < module_end) {
                    helper.AsUInt64 = current_va;

                    // read through page tables again for this VA
                    physical::read_physical_address(pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));
                    if (!pml4e.Present) break;

                    physical::read_physical_address(PFN_TO_PAGE(pml4e.PageFrameNumber) + helper.AsIndex.Pdpt * sizeof(PDPTE_64), &pdpte, sizeof(PDPTE_64));
                    if (!pdpte.Present) break;

                    physical::read_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64));
                    if (!pde.Present) break;

                    physical::read_physical_address(PFN_TO_PAGE(pde.PageFrameNumber) + helper.AsIndex.Pt * sizeof(PTE_64), &pte, sizeof(PTE_64));

                    if(pte.PageFrameNumber == 0){
                        available_size += PAGE_SIZE;
                        current_va += PAGE_SIZE;
                    }
                    else {
                        break;
                    }
                }

                if (available_size >= aligned_size) {
                    base_va = potential_start;
                    log("SUCCESS", "found suitable empty/null page range at 0x%llx with size 0x%llx", base_va, available_size);
                    break;
                }
            }
        }

        if (!base_va) {
            log("ERROR", "could not find suitable empty/null page range in main module");
            ObfDereferenceObject(target_process);
            return nullptr;
        }

        log("INFO", "selected base address: 0x%llx", base_va);

        auto write_pt_status = mem::write_page_tables(target_dir_base, base_va, page_count, use_large_page);

        if (!NT_SUCCESS(write_pt_status)) {
            log("ERROR", "failed to write page tables");
            ObfDereferenceObject(target_process);
            return nullptr;
        }

        ObfDereferenceObject(target_process);

        // flush TLB and caches
        globals::ke_flush_entire_tb(TRUE, TRUE);
        globals::ke_invalidate_all_caches();
        globals::mi_flush_entire_tb_due_to_attribute_change();

        return reinterpret_cast<void*>(base_va);
    }

    void* allocate_between_modules(const uint32_t local_pid, const uint32_t target_pid, const size_t size, const bool use_large_page) {
        const size_t page_mask = PAGE_SIZE - 1;
        const size_t aligned_size = (size + page_mask) & ~page_mask;
        const size_t page_count = aligned_size >> PAGE_SHIFT;

        log("INFO", "searching for space of size 0x%llx (%d pages)", aligned_size, page_count);

        PEPROCESS target_process;
        if (PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target_pid), &target_process) != STATUS_SUCCESS) {
            log("ERROR", "failed to lookup target process");
            return nullptr;
        }

        physical::init();

        const auto target_dir_base = physical::get_process_directory_base(target_process);

        PPEB peb_address = PsGetProcessPeb(target_process);
        if (!peb_address) {
            log("ERROR", "failed to get PEB address");
            ObfDereferenceObject(target_process);
            return nullptr;
        }

        PEB peb;
        physical::read_process_memory(target_process, reinterpret_cast<ULONG64>(peb_address), &peb, sizeof(PEB));
        log("INFO", "PEB found at 0x%llx", peb_address);

        PEB_LDR_DATA ldr_data;
        physical::read_process_memory(target_process, reinterpret_cast<ULONG64>(peb.Ldr), &ldr_data, sizeof(PEB_LDR_DATA));

        PLIST_ENTRY current_entry = ldr_data.InMemoryOrderModuleList.Flink;
        PLIST_ENTRY first_entry = current_entry;
        uintptr_t base_va = 0;

        uintptr_t last_module_end = 0;
        int module_count = 0;

        do {
            LDR_DATA_TABLE_ENTRY entry;
            physical::read_process_memory(target_process,
                reinterpret_cast<ULONG64>(CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)),
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
            ObfDereferenceObject(target_process);
            return nullptr;
        }

        log("INFO", "selected base address: 0x%llx", base_va);

        auto write_pt_status = mem::write_page_tables(target_dir_base, base_va, page_count, use_large_page);

        if (!NT_SUCCESS(write_pt_status)) {
            log("ERROR", "failed to write page tables");
            ObfDereferenceObject(target_process);
            return nullptr;
        }

        ObfDereferenceObject(target_process);

        // Flush TLB and caches
        globals::ke_flush_entire_tb(TRUE, TRUE);
        globals::ke_invalidate_all_caches();
        globals::mi_flush_entire_tb_due_to_attribute_change();

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
        if (PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target_pid), &target_process) != STATUS_SUCCESS) {
            log("ERROR", "failed to lookup target process");
            return nullptr;
        }

        physical::init();

        const auto target_dir_base = physical::get_process_directory_base(target_process);

        // find a non-present PML4E in the appropriate address space based on use_high_address flag
        uint32_t selected_pml4_index = 0;
        PML4E_64 pml4e = { 0 };

        // Set the search range based on whether high or low address is requested
        uint32_t start_idx = use_high_address ? 256 : 0;
        uint32_t end_idx = use_high_address ? 511 : 256;
        const char* space_type = use_high_address ? "kernel" : "usermode";

        for (uint32_t idx = start_idx; idx < end_idx; idx++) {
            physical::read_physical_address(target_dir_base + idx * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));

            if (!pml4e.Present) {
                selected_pml4_index = idx;
                log("INFO", "found non-present PML4E at index: %u", selected_pml4_index);
                break;
            }
        }

        if (selected_pml4_index == 0 && use_high_address) {
            log("ERROR", "failed to find a non-present PML4E in %s space", space_type);
            ObfDereferenceObject(target_process);
            return nullptr;
        }

        // calc the base virtual address using the selected PML4E index
        uintptr_t base_va;
        if (use_high_address) {
            base_va = 0xFFFF000000000000ULL | (static_cast<uintptr_t>(selected_pml4_index) << 39);
        }
        else {
            base_va = (static_cast<uintptr_t>(selected_pml4_index) << 39);
        }

        log("INFO", "selected base address: 0x%llx", base_va);

        auto write_pt_status = mem::write_page_tables(target_dir_base, base_va, page_count, use_large_page);

        if (!NT_SUCCESS(write_pt_status)) {
            log("ERROR", "failed to write page tables, NTSTATUS: 0x%08X", write_pt_status);
            ObfDereferenceObject(target_process);
            return nullptr;
        }

        ObfDereferenceObject(target_process);

        // flush TLB and caches
        globals::ke_flush_entire_tb(TRUE, TRUE);
        globals::ke_invalidate_all_caches();
        globals::mi_flush_entire_tb_due_to_attribute_change();

        return reinterpret_cast<void*>(base_va);
    }


}