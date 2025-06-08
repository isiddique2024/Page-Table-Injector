#pragma once

namespace hyperspace {

    static ntoskrnl_mapping_info g_ntoskrnl_copy_info = { 0 };
    static pt_hook::hook_info g_pspexit_hook = { 0 };

    __int64 __fastcall PspExitThread(unsigned int a1) {
        // get the original function from our hook info
        typedef __int64(__fastcall* PspExitThread_t)(unsigned int);
        auto original_func = reinterpret_cast<PspExitThread_t>(g_pspexit_hook.original_function);

        auto current_thread = KeGetCurrentThread();

        // check if this thread belongs to our hyperspace context
        PEPROCESS apcstate_process = *reinterpret_cast<PEPROCESS*>(
            reinterpret_cast<uintptr_t>(current_thread) + globals::_kthread_apcstate_pkprocess);

        PEPROCESS kthread_process = *reinterpret_cast<PEPROCESS*>(
            reinterpret_cast<uintptr_t>(current_thread) + globals::_kthread_pkprocess);

        if (apcstate_process != globals::ctx.orig_peproc && kthread_process == globals::ctx.orig_peproc) {
            log("INFO", "PspExitThread called for hyperspace thread, restoring original process");

            // restore the original process before exit
            *reinterpret_cast<PEPROCESS*>(
                reinterpret_cast<uintptr_t>(current_thread) + globals::_kthread_apcstate_pkprocess) = globals::ctx.orig_peproc;

            *reinterpret_cast<PEPROCESS*>(
                reinterpret_cast<uintptr_t>(current_thread) + globals::_kthread_pkprocess) = globals::ctx.orig_peproc;
        }

        // call the original function
        if (original_func) {
            return original_func(a1);
        }
    }

    // init page tracking
    bool initialize_page_tracking() {
        g_ntoskrnl_copy_info.allocated_pages_capacity = 10240; // start with space for 10240 pages
        g_ntoskrnl_copy_info.allocated_pages = reinterpret_cast<uintptr_t*>(
            mem::allocate_independent_pages(
                g_ntoskrnl_copy_info.allocated_pages_capacity * sizeof(uintptr_t)));

        if (!g_ntoskrnl_copy_info.allocated_pages) {
            log("ERROR", "failed to allocate page tracking array");
            return false;
        }

        g_ntoskrnl_copy_info.allocated_pages_count = 0;
        globals::memset(g_ntoskrnl_copy_info.allocated_pages, 0,
            g_ntoskrnl_copy_info.allocated_pages_capacity * sizeof(uintptr_t));

        log("INFO", "initialized page tracking with capacity %zu", g_ntoskrnl_copy_info.allocated_pages_capacity);
        return true;
    }

    // add page to tracking array
    bool add_tracked_page(uintptr_t va) {
        if (g_ntoskrnl_copy_info.allocated_pages_count >= g_ntoskrnl_copy_info.allocated_pages_capacity) {
            log("ERROR", "page tracking array full");
            return false;
        }

        g_ntoskrnl_copy_info.allocated_pages[g_ntoskrnl_copy_info.allocated_pages_count] = va;
        g_ntoskrnl_copy_info.allocated_pages_count++;
        return true;
    }

    // find ntoskrnl base and size
    bool find_ntoskrnl_info(uintptr_t* base, uintptr_t* size) {
        PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(globals::ps_loaded_module_list);
        if (!module_list) {
            log("ERROR", "PsLoadedModuleList not found");
            return false;
        }

        for (PLIST_ENTRY entry = module_list->Flink; entry != module_list; entry = entry->Flink) {
            PKLDR_DATA_TABLE_ENTRY ldr_entry = CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (ldr_entry->BaseDllName.Buffer &&
                globals::_wcsicmp(ldr_entry->BaseDllName.Buffer, L"ntoskrnl.exe") == 0) {

                *base = reinterpret_cast<uintptr_t>(ldr_entry->DllBase);
                *size = ldr_entry->SizeOfImage;

                log("SUCCESS", "found ntoskrnl.exe at 0x%llx, size: 0x%llx", *base, *size);
                return true;
            }
        }

        log("ERROR", "ntoskrnl.exe not found in module list");
        return false;
    }

    // alloc a physical page and track it
    uintptr_t allocate_tracked_physical_page() {
        void* va = mem::allocate_independent_pages(PAGE_SIZE);
        if (!va) {
            log("ERROR", "failed to allocate physical page");
            return 0;
        }

        uintptr_t pa = mem::virtual_to_physical(va).QuadPart;
        if (!pa) {
            log("ERROR", "failed to get physical address");
            return 0;
        }

        // clear the page
        globals::memset(va, 0, PAGE_SIZE);

        // track the allocation
        if (!add_tracked_page(reinterpret_cast<uintptr_t>(va))) {
            log("ERROR", "failed to track allocated page");
            return 0;
        }

        log("INFO", "allocated tracked physical page: PA=0x%llx, VA=0x%llx", pa, reinterpret_cast<uintptr_t>(va));
        return pa;
    }

    // deep copy ntoskrnl pages using 4KB pages
    bool copy_ntoskrnl_pages(uintptr_t src_base, uintptr_t size, uintptr_t dest_pd_pa) {

        log("INFO", "copying ntoskrnl as 4KB pages");

        size_t page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;

        size_t page_pas_size = page_count * sizeof(uintptr_t);
        uintptr_t* page_pas = reinterpret_cast<uintptr_t*>(
            mem::allocate_independent_pages(page_pas_size));

        if (!page_pas) {
            log("ERROR", "failed to allocate page_pas array");
            return false;
        }

        globals::memset(page_pas, 0, page_pas_size);

        for (size_t i = 0; i < page_count; i++) {
            uintptr_t src_va = src_base + (i * PAGE_SIZE);

            // alloc physical page
            uintptr_t dest_pa = allocate_tracked_physical_page();
            if (!dest_pa) {
                log("ERROR", "failed to allocate page %zu", i);
                globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(page_pas), page_pas_size);
                return false;
            }

            page_pas[i] = dest_pa;

            // alloc temporary buffer
            void* temp_buffer = mem::allocate_independent_pages(PAGE_SIZE);
            if (!temp_buffer) {
                log("ERROR", "failed to allocate temp buffer for page %zu", i);
                globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(page_pas), page_pas_size);
                return false;
            }

            globals::memcpy(temp_buffer, reinterpret_cast<void*>(src_va), PAGE_SIZE);
                
            NTSTATUS write_status = physical::write_physical_address(dest_pa, temp_buffer, PAGE_SIZE);

            // free temporary buffer
            globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(temp_buffer), PAGE_SIZE);

            if (!NT_SUCCESS(write_status)) {
                log("ERROR", "failed to write to physical page 0x%llx", dest_pa);
                globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(page_pas), page_pas_size);
                return false;
            }

            if (i % 100 == 0) {
                log("INFO", "copied page %zu from 0x%llx to PA 0x%llx", i, src_va, dest_pa);
            }
        }

        // free the page_pas array
        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(page_pas), page_pas_size);
        log("SUCCESS", "copied all %zu pages", page_count);

        return true;
    }

    // create page tables for ntoskrnl copy in hyperspace
    bool create_ntoskrnl_page_tables(uintptr_t hyperspace_pml4_pa, ntoskrnl_mapping_info* info) {
        // parse virtual address indices
        info->pml4_index = (info->hyperspace_base >> 39) & 0x1FF;
        info->pdpt_index = (info->hyperspace_base >> 30) & 0x1FF;
        info->pd_index = (info->hyperspace_base >> 21) & 0x1FF;

        log("INFO", "creating page tables: PML4[%u] -> PDPT[%u] -> PD[%u]",
            info->pml4_index, info->pdpt_index, info->pd_index);

        // check if PML4E exists
        PML4E_64 pml4e = { 0 };
        uintptr_t pml4e_pa = hyperspace_pml4_pa + info->pml4_index * 8;
        if (!NT_SUCCESS(physical::read_physical_address(pml4e_pa, &pml4e, sizeof(pml4e)))) {
            log("ERROR", "failed to read PML4E");
            return false;
        }

        uintptr_t pdpt_pa;
        if (!pml4e.Present) {
            // alloc new PDPT
            pdpt_pa = allocate_tracked_physical_page();
            if (!pdpt_pa) {
                log("ERROR", "failed to allocate PDPT");
                return false;
            }

            // create PML4E
            pml4e.Present = 1;
            pml4e.Write = 1;
            pml4e.Supervisor = 0;
            pml4e.PageFrameNumber = pdpt_pa >> 12;

            if (!NT_SUCCESS(physical::write_physical_address(pml4e_pa, &pml4e, sizeof(pml4e)))) {
                log("ERROR", "failed to write PML4E");
                return false;
            }

            info->new_pdpt_pa = pdpt_pa;
            log("INFO", "created new PDPT at PA 0x%llx", pdpt_pa);
        }
        else {
            pdpt_pa = pml4e.PageFrameNumber << 12;
            log("INFO", "using existing PDPT at PA 0x%llx", pdpt_pa);
        }

        // check if PDPTE exists
        PDPTE_64 pdpte = { 0 };
        uintptr_t pdpte_pa = pdpt_pa + info->pdpt_index * 8;
        if (!NT_SUCCESS(physical::read_physical_address(pdpte_pa, &pdpte, sizeof(pdpte)))) {
            log("ERROR", "failed to read PDPTE");
            return false;
        }

        uintptr_t pd_pa;
        if (!pdpte.Present) {
            // alloc new PD
            pd_pa = allocate_tracked_physical_page();
            if (!pd_pa) {
                log("ERROR", "failed to allocate PD");
                return false;
            }

            // create PDPTE
            pdpte.Present = 1;
            pdpte.Write = 1;
            pdpte.Supervisor = 0;
            pdpte.PageFrameNumber = pd_pa >> 12;

            if (!NT_SUCCESS(physical::write_physical_address(pdpte_pa, &pdpte, sizeof(pdpte)))) {
                log("ERROR", "failed to write PDPTE");
                return false;
            }

            info->new_pd_pa = pd_pa;
            log("INFO", "created new PD at PA 0x%llx", pd_pa);
        }
        else {
            pd_pa = pdpte.PageFrameNumber << 12;
            log("INFO", "using existing PD at PA 0x%llx", pd_pa);
        }

        return true;
    }

    // map ntoskrnl pages in the new page directory
    bool map_ntoskrnl_pages(ntoskrnl_mapping_info* info) {
        size_t total_pages = (info->original_size + PAGE_SIZE - 1) / PAGE_SIZE;

        log("INFO", "mapping %zu pages starting at PD index %u", total_pages, info->pd_index);

        // get list of allocated physical pages for ntoskrnl copy
        size_t allocated_page_idx = 0;

        for (size_t i = 0; i < total_pages; i++) {
            uint32_t current_pd_idx = info->pd_index + (i / 512); // PD index (each PD covers 512 pages)
            uint32_t pt_idx = i % 512; // PT index within the PD

            if (pt_idx == 0) {
                // need new PT for this PD entry
                uintptr_t pt_pa = allocate_tracked_physical_page();
                if (!pt_pa) {
                    log("ERROR", "failed to allocate PT for PD[%u]", current_pd_idx);
                    return false;
                }

                // create PDE pointing to new PT
                PDE_64 pde = { 0 };
                pde.Present = 1;
                pde.Write = 1;
                pde.Supervisor = 0;
                pde.PageFrameNumber = pt_pa >> 12;

                uintptr_t pde_pa = info->new_pd_pa + current_pd_idx * 8;
                if (!NT_SUCCESS(physical::write_physical_address(pde_pa, &pde, sizeof(pde)))) {
                    log("ERROR", "failed to write PDE[%u]", current_pd_idx);
                    return false;
                }

                log("INFO", "created PT at PA 0x%llx for PD[%u]", pt_pa, current_pd_idx);
            }

            // read the PT physical address from PDE
            PDE_64 pde = { 0 };
            uintptr_t pde_pa = info->new_pd_pa + current_pd_idx * 8;
            if (!NT_SUCCESS(physical::read_physical_address(pde_pa, &pde, sizeof(pde)))) {
                log("ERROR", "failed to read PDE[%u]", current_pd_idx);
                return false;
            }

            uintptr_t pt_pa = pde.PageFrameNumber << 12;

            // create PTE pointing to copied ntoskrnl page
            // use the allocated pages in order (skip the page table pages)
            while (allocated_page_idx < g_ntoskrnl_copy_info.allocated_pages_count) {
                uintptr_t va = g_ntoskrnl_copy_info.allocated_pages[allocated_page_idx];
                uintptr_t pa = mem::virtual_to_physical(reinterpret_cast<void*>(va)).QuadPart;

                // check if this is a page table page (allocated for PT/PD/PDPT)
                bool is_page_table = (pa == info->new_pdpt_pa || pa == info->new_pd_pa);

                // check if it's any of the PT pages we allocated
                for (size_t j = 0; j < total_pages; j += 512) {
                    uint32_t check_pd_idx = info->pd_index + (j / 512);
                    PDE_64 check_pde = { 0 };
                    uintptr_t check_pde_pa = info->new_pd_pa + check_pd_idx * 8;
                    if (NT_SUCCESS(physical::read_physical_address(check_pde_pa, &check_pde, sizeof(check_pde)))) {
                        if (check_pde.Present && (check_pde.PageFrameNumber << 12) == pa) {
                            is_page_table = true;
                            break;
                        }
                    }
                }

                allocated_page_idx++;
                if (!is_page_table) {
                    // this is a data page, use it
                    PTE_64 pte = { 0 };
                    pte.Present = 1;
                    pte.Write = 1;
                    pte.Supervisor = 0;
                    pte.ExecuteDisable = 0; // allow execution
                    pte.PageFrameNumber = pa >> 12;

                    uintptr_t pte_pa = pt_pa + pt_idx * 8;
                    if (!NT_SUCCESS(physical::write_physical_address(pte_pa, &pte, sizeof(pte)))) {
                        log("ERROR", "failed to write PTE[%u][%u]", current_pd_idx, pt_idx);
                        return false;
                    }

                    break;
                }
            }
        }

        log("SUCCESS", "mapped all ntoskrnl pages");
        return true;
    }

    NTSTATUS install_kernel_hooks_in_hyperspace() {
        if (!g_ntoskrnl_copy_info.hyperspace_base) {
            log("ERROR", "ntoskrnl copy not created yet");
            return STATUS_UNSUCCESSFUL;
        }

        // calc offset from ntoskrnl base
        uintptr_t pspexit_offset = globals::psp_exit_thread - g_ntoskrnl_copy_info.original_base;
        log("INFO", "PspExitThread offset from ntoskrnl base: 0x%llx", pspexit_offset);

        // calc corresponding address in hyperspace copy
        uintptr_t hyperspace_pspexit = g_ntoskrnl_copy_info.hyperspace_base + pspexit_offset;
        log("INFO", "PspExitThread address in hyperspace: 0x%llx", hyperspace_pspexit);

        bool hook_result = pt_hook::install_hook_physical(
            globals::ctx.hyperspace_pml4_pa,
            hyperspace_pspexit,
            reinterpret_cast<uintptr_t>(hyperspace::PspExitThread),
            &g_pspexit_hook
        );

        if (!hook_result) {
            log("ERROR", "failed to install PspExitThread hook");
            return STATUS_UNSUCCESSFUL;
        }

        globals::ke_flush_entire_tb(TRUE, TRUE);
        globals::ke_invalidate_all_caches();
        globals::mi_flush_entire_tb_due_to_attribute_change();

        return STATUS_SUCCESS;
    }

    // main function to create deep copy of ntoskrnl in hyperspace
    NTSTATUS create_ntoskrnl_deep_copy_in_hyperspace() {
        if (!globals::ctx.initialized) {
            log("ERROR", "hyperspace context not initialized");
            return STATUS_UNSUCCESSFUL;
        }

        // init page tracking
        if (!initialize_page_tracking()) {
            return STATUS_UNSUCCESSFUL;
        }

        // find ntoskrnl info
        if (!find_ntoskrnl_info(&g_ntoskrnl_copy_info.original_base, &g_ntoskrnl_copy_info.original_size)) {
            return STATUS_UNSUCCESSFUL;
        }

        // use the same virtual address in hyperspace
        g_ntoskrnl_copy_info.hyperspace_base = g_ntoskrnl_copy_info.original_base;

        // create page table structure
        if (!create_ntoskrnl_page_tables(globals::ctx.hyperspace_pml4_pa, &g_ntoskrnl_copy_info)) {
            log("ERROR", "failed to create page tables");
            return STATUS_UNSUCCESSFUL;
        }

        // copy ntoskrnl pages
        if (!copy_ntoskrnl_pages(
            g_ntoskrnl_copy_info.original_base,
            g_ntoskrnl_copy_info.original_size,
            g_ntoskrnl_copy_info.new_pd_pa)) { 
            log("ERROR", "failed to copy ntoskrnl pages");
            return STATUS_UNSUCCESSFUL;
        }

        // map the copied pages
        if (!map_ntoskrnl_pages(&g_ntoskrnl_copy_info)) {
            log("ERROR", "failed to map ntoskrnl pages");
            return STATUS_UNSUCCESSFUL;
        }

        // flush TLB
        globals::ke_flush_entire_tb(TRUE, TRUE);
        globals::ke_invalidate_all_caches();
        globals::mi_flush_entire_tb_due_to_attribute_change();

        log("SUCCESS", "created deep copy of ntoskrnl in hyperspace at 0x%llx",
            g_ntoskrnl_copy_info.hyperspace_base);

        // install kernel hooks in hyperspace ctx
        NTSTATUS install_kernel_hooks_status = install_kernel_hooks_in_hyperspace();
        if (!NT_SUCCESS(install_kernel_hooks_status)) {
            log("WARNING", "failed to install kernel hooks in hyperspace context: 0x%x", install_kernel_hooks_status);
            return STATUS_UNSUCCESSFUL;
        }

        return STATUS_SUCCESS;
    }

    // cleanup function (need to rewrite cause im not taking into account 2mb large pages lol, might just map the ntoskrnl copy on a 4kb page in that case)
    void cleanup_ntoskrnl_deep_copy() {
        // free all allocated pages
        for (size_t i = 0; i < g_ntoskrnl_copy_info.allocated_pages_count; i++) {
            uintptr_t va = g_ntoskrnl_copy_info.allocated_pages[i];
            globals::mm_free_independent_pages(va, PAGE_SIZE);
        }

        // free the tracking array itself
        if (g_ntoskrnl_copy_info.allocated_pages) {
            globals::mm_free_independent_pages(
                reinterpret_cast<uintptr_t>(g_ntoskrnl_copy_info.allocated_pages),
                g_ntoskrnl_copy_info.allocated_pages_capacity * sizeof(uintptr_t));
        }

        globals::memset(&g_ntoskrnl_copy_info, 0, sizeof(g_ntoskrnl_copy_info));

        globals::ke_flush_entire_tb(TRUE, TRUE);
        globals::ke_invalidate_all_caches();
        globals::mi_flush_entire_tb_due_to_attribute_change();

        log("INFO", "cleaned up ntoskrnl deep copy");
    }

    // init all list entries in cloned EPROCESS to be empty
    void initialize_cloned_eprocess_lists(PEPROCESS clone_eproc) {

        // init _EPROCESS.ThreadListHead (0x370)
        PLIST_ENTRY thread_list_head = reinterpret_cast<PLIST_ENTRY>(
            reinterpret_cast<uintptr_t>(clone_eproc) + globals::_eprocess_thread_list_head);
        thread_list_head->Flink = thread_list_head;
        thread_list_head->Blink = thread_list_head;

        // init _KPROCESS.ThreadListHead (0x30)
        PLIST_ENTRY kprocess_thread_list = reinterpret_cast<PLIST_ENTRY>(
            reinterpret_cast<uintptr_t>(clone_eproc) + globals::_kprocess_thread_list_head);
        kprocess_thread_list->Flink = kprocess_thread_list;
        kprocess_thread_list->Blink = kprocess_thread_list;

        // init _EPROCESS.SharedCommitLinks
        PLIST_ENTRY shared_commit_head = reinterpret_cast<PLIST_ENTRY>(
            reinterpret_cast<uintptr_t>(clone_eproc) + globals::_eprocess_shared_commit_links);
        shared_commit_head->Flink = shared_commit_head;
        shared_commit_head->Blink = shared_commit_head;

        // clear _EPROCESS.SharedCommitCharge
        *reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(clone_eproc) + globals::_eprocess_shared_commit_charge) = 0;

        // clear _EPROCESS.RundownProtect
        reinterpret_cast<_EX_RUNDOWN_REF*>(reinterpret_cast<uintptr_t>(clone_eproc) + globals::_eprocess_rundown_protect)->Count = 0;
        reinterpret_cast<_EX_RUNDOWN_REF*>(reinterpret_cast<uintptr_t>(clone_eproc) + globals::_eprocess_rundown_protect)->Ptr = 0;

        // clear AccessLog to prevent MiEmptyPageAccessLog from being called, thus preventing exception
        *reinterpret_cast<void**>(reinterpret_cast<uintptr_t>(clone_eproc) + globals::_eprocess_vm + 0xE8) = nullptr;

        // set VadTrackingDisabled bit on hyperspace process, prevents MiRemoveSharedCommitNode page fault
        unsigned long* flags3_ptr_hyperspace = reinterpret_cast<ULONG*>(reinterpret_cast<uintptr_t>(clone_eproc) + globals::_eprocess_flags3);
        //*flags3_ptr_hyperspace |= 0x1;  // set bit 0 (Minimal), allows for the creation of threads within hyperspace context without triggering thread notify callbacks
        *flags3_ptr_hyperspace |= 0x10; // set bit 4 (VadTrackingDisabled)

        // set VadTrackingDisabled bit on original process, prevents MiRemoveSharedCommitNode page fault
        unsigned long* flags3_ptr_og = reinterpret_cast<ULONG*>(reinterpret_cast<uintptr_t>(globals::ctx.orig_peproc) + globals::_eprocess_flags3);
        *flags3_ptr_og |= 0x10; // set bit 4 (VadTrackingDisabled)


        log("INFO", "initialized list entries in cloned EPROCESS");
    }

    // find the PML4 self-reference entry in the original CR3
    self_reference_entry_info find_pml4_self_reference_entry(uintptr_t cr3_pa) {
        self_reference_entry_info info = { 0, false, {0} };
        uintptr_t cr3_pfn = cr3_pa >> 12;

        log("INFO", "searching for PML4 self-reference entry (CR3 PFN: 0x%llx)", cr3_pfn);

        // check all PML4 entries (0-511)
        for (uint32_t idx = 0; idx < 512; idx++) {
            PML4E_64 pml4e = { 0 };
            if (NT_SUCCESS(physical::read_physical_address(cr3_pa + idx * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64)))) {
                // check if this entry is present and points back to the CR3
                if (pml4e.Present && pml4e.PageFrameNumber == cr3_pfn) {
                    info.index = idx;
                    info.found = true;
                    info.original_entry = pml4e;
                    log("SUCCESS", "found PML4 self-reference entry at index: %u", idx);
                    break;
                }
            }
        }

        if (!info.found) {
            log("WARNING", "PML4 self-reference entry not found in original CR3");
        }

        return info;
    }

    // update the self-reference entry in the cloned PML4 to point to the new CR3
    bool update_cloned_self_reference_entry(uintptr_t cloned_pml4_va, uintptr_t cloned_pml4_pa, self_reference_entry_info self_reference_info) {
        if (!self_reference_info.found) {
            log("INFO", "no self-reference entry to update in cloned PML4");
            return true;
        }

        // calc the address of the self-reference entry in the cloned PML4
        uintptr_t self_reference_entry_va = cloned_pml4_va + (self_reference_info.index * sizeof(PML4E_64));

        // create new self-reference entry pointing to the cloned PML4's physical address
        PML4E_64 new_self_reference_entry = self_reference_info.original_entry;
        new_self_reference_entry.PageFrameNumber = cloned_pml4_pa >> 12;

        // write the updated self-reference entry to the cloned PML4
        globals::memcpy(reinterpret_cast<void*>(self_reference_entry_va), &new_self_reference_entry, sizeof(PML4E_64));

        log("SUCCESS", "updated self-reference entry at index %u to point to cloned PML4 (PFN: 0x%llx)",
            self_reference_info.index, new_self_reference_entry.PageFrameNumber);

        return true;
    }

    // helper function to copy original page tables with self-reference entry tracking
    bool copy_page_tables_with_self_reference_entry(uintptr_t dest_pml4_va, uintptr_t src_pml4_pa, uintptr_t dest_pml4_pa, self_reference_entry_info* self_reference_info) {
        // alloc temporary buffer to read source PML4
        void* temp_buffer = mem::allocate_independent_pages(PAGE_SIZE);
        if (!temp_buffer) {
            log("ERROR", "failed to allocate temp buffer for PML4 copy");
            return false;
        }

        // find self-reference entry in original PML4 before copying
        *self_reference_info = find_pml4_self_reference_entry(src_pml4_pa);

        // read the original PML4 from physical memory
        if (!NT_SUCCESS(physical::read_physical_address(src_pml4_pa, temp_buffer, PAGE_SIZE))) {
            log("ERROR", "failed to read original PML4");
            globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(temp_buffer), PAGE_SIZE);
            return false;
        }

        // copy to our hyperspace PML4 virtual address
        globals::memcpy(reinterpret_cast<void*>(dest_pml4_va), temp_buffer, PAGE_SIZE);

        // update the self-reference entry in the cloned PML4 to point to the new PML4
        if (!update_cloned_self_reference_entry(dest_pml4_va, dest_pml4_pa, *self_reference_info)) {
            log("ERROR", "failed to update self-reference entry in cloned PML4");
            globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(temp_buffer), PAGE_SIZE);
            return false;
        }

        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(temp_buffer), PAGE_SIZE);
        return true;
    }

    // init hyperspace context with full page table clone and proper self-reference entry handling
    NTSTATUS initialize_hyperspace_context(uint32_t target_pid, hyperspace_ctx* ctx) {
        if (!ctx) {
            log("ERROR", "invalid hyperspace context");
            return STATUS_UNSUCCESSFUL;
        }

        // get target process
        PEPROCESS target_process;
        if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(target_pid), &target_process) != STATUS_SUCCESS) {
            log("ERROR", "failed to lookup target process for hyperspace");
            return STATUS_UNSUCCESSFUL;
        }

        ctx->orig_peproc = target_process;

        // get original PML4 physical address
        ctx->orig_pml4_pa = physical::get_process_directory_base(target_process);
        if (!ctx->orig_pml4_pa) {
            log("ERROR", "failed to get target process directory base");
            globals::obf_dereference_object(target_process);
            return STATUS_UNSUCCESSFUL;
        }

        globals::obf_dereference_object(target_process);

        log("INFO", "original PML4 PA: 0x%llx", ctx->orig_pml4_pa);

        // alloc new PML4 for hyperspace
        ctx->hyperspace_pml4_va = reinterpret_cast<uintptr_t>(
            mem::allocate_independent_pages(PAGE_SIZE));
        if (!ctx->hyperspace_pml4_va) {
            log("ERROR", "failed to allocate hyperspace PML4");
            return STATUS_UNSUCCESSFUL;
        }

        // get physical address of our new PML4
        ctx->hyperspace_pml4_pa = mem::virtual_to_physical(
            reinterpret_cast<void*>(ctx->hyperspace_pml4_va)).QuadPart;
        if (!ctx->hyperspace_pml4_pa) {
            log("ERROR", "failed to get physical address of hyperspace PML4");
            return STATUS_UNSUCCESSFUL;
        }

        log("INFO", "hyperspace PML4 VA: 0x%llx, PA: 0x%llx",
            ctx->hyperspace_pml4_va, ctx->hyperspace_pml4_pa);

        // copy original PML4 with proper self-reference entry handling, i'm not sure if this is truly necessary, but I did it anyway
        self_reference_entry_info self_reference_info;
        if (!copy_page_tables_with_self_reference_entry(ctx->hyperspace_pml4_va, ctx->orig_pml4_pa, ctx->hyperspace_pml4_pa, &self_reference_info)) {
            log("ERROR", "failed to copy page tables with self-reference entry");
            return STATUS_UNSUCCESSFUL;
        }

        // store self-reference PML4 entry
        ctx->self_reference_entry_index = self_reference_info.index;
        ctx->has_self_reference_entry = self_reference_info.found;

        log("SUCCESS", "created hyperspace PML4 with %s self-reference entry",
            self_reference_info.found ? "updated" : "no");

        // clone PEPROCESS
        ctx->clone_peproc_page_base = reinterpret_cast<uintptr_t>(
            mem::allocate_independent_pages(PAGE_SIZE));

        if (!ctx->clone_peproc_page_base) {
            log("ERROR", "failed to allocate clone PEPROCESS");
            return STATUS_UNSUCCESSFUL;
        }

        // calc page-aligned addresses
        const auto orig_peproc_page = (reinterpret_cast<uintptr_t>(ctx->orig_peproc) >> 12) << 12;
        const auto clone_peproc_offset = reinterpret_cast<uintptr_t>(ctx->orig_peproc) & 0xFFF;

        // copy EPROCESS page
        globals::memcpy(reinterpret_cast<void*>(ctx->clone_peproc_page_base),
            reinterpret_cast<void*>(orig_peproc_page), PAGE_SIZE);

        // set the adjusted pointer
        ctx->clone_peproc = reinterpret_cast<PEPROCESS>(
            ctx->clone_peproc_page_base + clone_peproc_offset);

        // init necessary _LIST_ENTRYs to prevent bsods
        initialize_cloned_eprocess_lists(ctx->clone_peproc);

        const auto dirbase_ptr = reinterpret_cast<uintptr_t*>(
            reinterpret_cast<uintptr_t>(ctx->clone_peproc) + globals::_kprocess_dirbase);

        // update DirectoryTableBase to new one
        *dirbase_ptr = ctx->hyperspace_pml4_pa;

        ctx->target_pid = target_pid;

        ctx->initialized = true;

        return STATUS_SUCCESS;
    }

    void* allocate_in_hyperspace(uint32_t target_pid, size_t size, bool use_large_page) {
        const size_t page_size = use_large_page ? 0x200000 : PAGE_SIZE;
        const size_t page_mask = page_size - 1;
        const size_t aligned_size = (size + page_mask) & ~page_mask;
        const size_t page_count = aligned_size / page_size;


        PEPROCESS target_process = globals::ctx.clone_peproc;

        // get target process directory base
        const auto target_dir_base = physical::get_process_directory_base(target_process);
        if (!target_dir_base) {
            log("ERROR", "failed to lookup target process directory base");
            return nullptr;
        }

        // find a non-present PML4E in the appropriate address space based on use_high_address flag
        uint32_t selected_pml4_index = 0;
        PML4E_64 pml4e = { 0 };

        // set the search range based on whether high or low address is requested
        uint32_t start_idx = 100;
        uint32_t end_idx = 256;
        const char* space_type = "usermode";

        for (uint32_t idx = start_idx; idx < end_idx; idx++) {
            physical::read_physical_address(target_dir_base + idx * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64));

            if (!pml4e.Present) {
                selected_pml4_index = idx;
                log("INFO", "found non-present PML4E at index: %u", selected_pml4_index);
                break;
            }
        }

        if (selected_pml4_index == 0) {
            log("ERROR", "failed to find a non-present PML4E in %s space", space_type);
            return nullptr;
        }

        uintptr_t base_va = page_table::get_pml4e(selected_pml4_index);

        log("INFO", "selected base address: 0x%llx", base_va);

        auto write_pt_status = mem::write_page_tables(globals::ctx.hyperspace_pml4_pa, base_va, page_count, use_large_page);

        if (!NT_SUCCESS(write_pt_status)) {
            log("ERROR", "failed to write page tables, NTSTATUS: 0x%08X", write_pt_status);
            return nullptr;
        }

        // flush TLB and caches
        globals::ke_flush_entire_tb(TRUE, TRUE);
        globals::ke_invalidate_all_caches();
        globals::mi_flush_entire_tb_due_to_attribute_change();

        log("SUCCESS", "allocated memory in hyperspace at 0x%llx", base_va);
        return reinterpret_cast<void*>(base_va);
    }


    NTSTATUS switch_thread_context_to_hyperspace(uint32_t tid, hyperspace_ctx* ctx) {
        if (!ctx || !ctx->initialized) {
            log("ERROR", "invalid or uninitialized hyperspace context");
            return STATUS_UNSUCCESSFUL;
        }

        PETHREAD target_thread;
        if (globals::ps_lookup_thread_by_thread_id(
            reinterpret_cast<HANDLE>(tid), &target_thread) != STATUS_SUCCESS) {
            log("ERROR", "failed to lookup target thread");
            return STATUS_UNSUCCESSFUL;
        }

        *reinterpret_cast<PEPROCESS*>(
            reinterpret_cast<uintptr_t>(target_thread) + globals::_kthread_apcstate_pkprocess) = ctx->clone_peproc;

        globals::obf_dereference_object(target_thread);

        log("SUCCESS", "thread %d switched to hyperspace", tid);
        return STATUS_SUCCESS;
    }

    // switch thread back to original context
    bool switch_from_hyperspace(uint32_t tid, hyperspace_ctx* ctx) {
        if (!ctx || !ctx->initialized) {
            log("ERROR", "invalid or uninitialized hyperspace context");
            return false;
        }

        PETHREAD target_thread;
        if (globals::ps_lookup_thread_by_thread_id(reinterpret_cast<HANDLE>(tid), &target_thread) != STATUS_SUCCESS) {
            log("ERROR", "failed to lookup target thread");
            return false;
        }

        // resore the thread's _KTHREAD.ApcState.Process to the original PEPROCESS
        const auto apcstate_process_ptr = reinterpret_cast<uintptr_t>(target_thread) + globals::_kthread_apcstate_pkprocess;
        *reinterpret_cast<PEPROCESS*>(apcstate_process_ptr) = ctx->orig_peproc;

        globals::obf_dereference_object(target_thread);

        log("INFO", "thread %d switched back from hyperspace", tid);
        return true;
    }

    // cleanup hyperspace context, used when target process exits
    void cleanup_hyperspace_context(hyperspace_ctx* ctx) {
        if (!ctx || !ctx->initialized) {
            return;
        }

        log("INFO", "cleaning up hyperspace context");

        // free hyperspace PML4 page
        if (ctx->hyperspace_pml4_va) {
            globals::mm_free_independent_pages(ctx->hyperspace_pml4_va, PAGE_SIZE);
            log("INFO", "freed hyperspace PML4 page");
        }

        // free cloned EPROCESS page (causes bsod after a few seconds)
        //if (ctx->clone_peproc_page_base) {
        //    globals::mm_free_independent_pages(ctx->clone_peproc_page_base, PAGE_SIZE);
        //}

        // dereference original process
        if (ctx->orig_peproc) {
            globals::obf_dereference_object(ctx->orig_peproc);
            log("INFO", "dereferenced original EPROCESS");
        }

        // clear the context
        globals::memset(ctx, 0, sizeof(hyperspace_ctx));

        log("SUCCESS", "hyperspace context cleanup completed");
    }

    namespace callbacks {

        static void* g_callback_shellcode_address = nullptr;
        static void* g_process_callback_handle = nullptr;

        void process_notify_callback_impl(
            HANDLE ParentId,
            HANDLE ProcessId,
            BOOLEAN Create
        ) {
            if (!globals::ctx.initialized) {
                return;
            }

            // only handle the target process
            if (HandleToUlong(ProcessId) != globals::ctx.target_pid) {
                return;
            }

            // only handle process termination
            if (Create) {
                log("INFO", "target process %d created", HandleToUlong(ProcessId));
                return;
            }

            log("INFO", "target process %d terminating - cleaning up hyperspace", HandleToUlong(ProcessId));

            // cleanup hyperspace context when target process exits
            cleanup_hyperspace_context(&globals::ctx);

            // clean up ntoskrnl copy in hyperspace ctx (need to rewrite since this bsods, most likely due to calling MmFreeIndependentPages on 2MB contiguous memory, will have to switch to 4kb independent pages for mapping, easier to work with)
            cleanup_ntoskrnl_deep_copy();

            // unregister the process callback to prevent further notifications
            if (g_process_callback_handle) {
                globals::ps_set_create_process_notify_routine_ex(
                    reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(g_callback_shellcode_address),
                    TRUE); 
                g_process_callback_handle = nullptr;
                g_callback_shellcode_address = nullptr;
            }

            log("SUCCESS", "hyperspace cleanup completed for process %d", HandleToUlong(ProcessId));
        }

        PVOID find_legitimate_driver_for_callbacks(PULONG out_size) {
            // common legitimate drivers that typically have proper flags for callbacks
            const wchar_t* legitimate_drivers[] = {
                L"classpnp.sys",   
                L"disk.sys",       
                L"volmgr.sys",     
                L"partmgr.sys"     
            };

            PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(globals::ps_loaded_module_list);
            if (!module_list) {
                log("ERROR", "PsLoadedModuleList not found");
                return nullptr;
            }

            for (PLIST_ENTRY entry = module_list->Flink; entry != module_list; entry = entry->Flink) {
                PKLDR_DATA_TABLE_ENTRY ldr_entry = CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                // check each legitimate driver
                for (const auto& driver_name : legitimate_drivers) {
                    if (ldr_entry->BaseDllName.Buffer &&
                        globals::_wcsicmp(ldr_entry->BaseDllName.Buffer, driver_name) == 0) {

                        // check if the driver has proper flags (bit 0x20 = supports callbacks)
                        if (ldr_entry->Flags & 0x20) {
                            log("INFO", "found legitimate driver for callbacks: %ws", driver_name);
                            if (out_size) {
                                *out_size = ldr_entry->SizeOfImage;
                            }
                            return ldr_entry->DllBase;
                        }
                    }
                }
            }

            // if no specific driver found, search for any driver with proper flags
            for (PLIST_ENTRY entry = module_list->Flink; entry != module_list; entry = entry->Flink) {
                PKLDR_DATA_TABLE_ENTRY ldr_entry = CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                // skip ntoskrnl and hal
                if (ldr_entry->BaseDllName.Buffer &&
                    (globals::_wcsicmp(ldr_entry->BaseDllName.Buffer, L"ntoskrnl.exe") == 0 ||
                        globals::_wcsicmp(ldr_entry->BaseDllName.Buffer, L"hal.dll") == 0)) {
                    continue;
                }

                // check for callback support flag
                if (ldr_entry->Flags & 0x20) {
                    log("INFO", "found driver with callback support: %ws",
                        ldr_entry->BaseDllName.Buffer ? ldr_entry->BaseDllName.Buffer : L"<unknown>");
                    if (out_size) {
                        *out_size = ldr_entry->SizeOfImage;
                    }
                    return ldr_entry->DllBase;
                }
            }

            log("ERROR", "no suitable driver found for callbacks");
            return nullptr;
        }

        // install process notify routine for target process exit cleanup
        NTSTATUS install_process_callback() {
            if (g_callback_shellcode_address) {
                return STATUS_SUCCESS; // already installed
            }

            // find a legitimate driver to host the callback
            ULONG driver_size = 0;
            void* driver_base = find_legitimate_driver_for_callbacks(&driver_size);
            if (!driver_base) {
                log("ERROR", "failed to find legitimate driver for process callback");
                return STATUS_UNSUCCESSFUL;
            }

            // create shellcode that calls callback function
            constexpr size_t CALLBACK_SHELL_SIZE = 12;
            uint8_t shellcode[CALLBACK_SHELL_SIZE] = {
                0x48, 0xB8,                   // mov rax, imm64
                0x00, 0x00, 0x00, 0x00,       // placeholder for lower 32 bits of process_notify_callback_impl
                0x00, 0x00, 0x00, 0x00,       // placeholder for upper 32 bits of process_notify_callback_impl
                0x50,                         // push rax 
                0xC3                          // ret 
            };

            // try and find .data section in the driver
            uint32_t section_size = 0;
            auto section_base = page_table::find_section_base(driver_base, &section_size, ".data", 5);
            if (!section_base) {
                return STATUS_UNSUCCESSFUL;
            }

            // find unused space for callback shellcode
            void* target_address = page_table::find_unused_space(section_base, section_size, CALLBACK_SHELL_SIZE);
            if (!target_address) {
                log("ERROR", "failed to find unused space for process callback shellcode in legitimate driver");
                return STATUS_UNSUCCESSFUL;
            }

            // assign callback function pointer to shellcode
            *reinterpret_cast<uintptr_t*>(&shellcode[2]) = reinterpret_cast<uintptr_t>(process_notify_callback_impl);

            // write shellcode to legitimate driver section
            globals::memcpy(target_address, shellcode, CALLBACK_SHELL_SIZE);

            log("INFO", "process callback shellcode written at addr: 0x%p in legitimate driver", target_address);

            // spoof PTE to make the target address executable
            if (!page_table::spoof_pte_range(reinterpret_cast<uintptr_t>(target_address), CALLBACK_SHELL_SIZE, false)) {
                log("ERROR", "failed to spoof pte range for process callback");
                return STATUS_UNSUCCESSFUL;
            }

            // register the process callback using legit shellcode address
            NTSTATUS status = globals::ps_set_create_process_notify_routine_ex(
                reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(target_address),
                FALSE
            );

            if (NT_SUCCESS(status)) {
                g_callback_shellcode_address = target_address;
                g_process_callback_handle = target_address; // store handle for cleanup
                log("SUCCESS", "registered process callback from legitimate driver section");
            }
            else {
                log("ERROR", "failed to register process callback: 0x%x", status);
            }

            return status;
        }
    }

}