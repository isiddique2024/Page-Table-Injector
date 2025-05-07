#pragma once
namespace detections {
    #define MAX_RESULTS 10000  // max number of entries we can store

    #define STATUS_OK           0
    #define STATUS_PARITY_ERROR_SET 1
    #define STATUS_PFN_EXISTS_NOT_SET 2
    #define STATUS_COPY_FAILED  3
    #define STATUS_SUPERVISOR_ERROR 4

    // struct to hold page table entry information
    typedef struct _page_table_entry_info {
        uintptr_t virtual_address;
        uintptr_t physical_address;
        uint8_t parity_error_flag;  // 1 if parity error was detected in the PFN entry
        uint8_t pfn_exists_flag;  // 1 if PfnExists is not set in the PFN entry
        uint8_t supervisor_flag; // 1 if supervisor bit is set
    } page_table_entry_info, * ppage_table_entry_info;

    // global array to store results
    page_table_entry_info g_results[MAX_RESULTS];
    uint32_t g_result_count = 0;

    // forward decl
    NTSTATUS walk_pdpt(uintptr_t pdpt_base, uint32_t pml4_idx);
    NTSTATUS walk_pd(uintptr_t pd_base, uint32_t pml4_idx, uint32_t pdpt_idx);
    NTSTATUS walk_pt(uintptr_t pt_base, uint32_t pml4_idx, uint32_t pdpt_idx, uint32_t pd_idx);

    // helper function to check if physical memory can be read and if it has parity error
    uint32_t check_physical_memory(uintptr_t physical_address, uint8_t* parity_error_flag, uint8_t* pfn_exists_flag) {
        // check if we can read the physical memory using MmCopyMemory
        uintptr_t test_value = 0;
        size_t bytes_read = 0;
        MM_COPY_ADDRESS source;
        source.PhysicalAddress.QuadPart = physical_address;

        // attempt to copy memory from the physical address
        NTSTATUS copy_status = MmCopyMemory(
            &test_value,
            source,
            sizeof(test_value),
            MM_COPY_MEMORY_PHYSICAL,
            &bytes_read
        );

        if (!NT_SUCCESS(copy_status)) {
            log("INFO", "MmCopyMemory failed for PA: 0x%llx with status: 0x%X", physical_address, copy_status);

            if (copy_status == STATUS_INVALID_ADDRESS) {
                *pfn_exists_flag = 1;
                return STATUS_PFN_EXISTS_NOT_SET;
            }
            else if (copy_status == STATUS_HARDWARE_MEMORY_ERROR) {
                *parity_error_flag = 1;
                return STATUS_PARITY_ERROR_SET;
            }
            else {
                // should probably add a flag if it returns some other NTSTATUS error
                return STATUS_COPY_FAILED;
            }
        }

        return STATUS_OK;
    }

    // helper function to add a result entry for PTE level only
    BOOLEAN add_entry(uintptr_t va, uintptr_t pa, uint8_t parity_error_flag, uint8_t pfn_exists_flag, uint8_t supervisor_flag) {
        // check if we have space
        if (g_result_count >= MAX_RESULTS) {
            log("ERROR", "result buffer full, cannot add more entries");
            return FALSE;
        }

        g_results[g_result_count].virtual_address = va;
        g_results[g_result_count].physical_address = pa;
        g_results[g_result_count].parity_error_flag = parity_error_flag;
        g_results[g_result_count].pfn_exists_flag = pfn_exists_flag;
        g_results[g_result_count].supervisor_flag = supervisor_flag;
        g_result_count++;

        return TRUE;
    }

    // main func to walk entire page table starting from pml4
    NTSTATUS walk_all_page_tables(uintptr_t dir_base) {
        NTSTATUS status = STATUS_SUCCESS;

        // reset the result counter
        g_result_count = 0;

        log("INFO", "starting full page table walk from dir_base 0x%llx", dir_base);
        log("DEBUG", "PML4 level scan started");
        uint32_t pml4_read_count = 0;
        uint32_t pml4_present_count = 0;

        // walk through all 512 PML4 entries
        for (uint32_t pml4_idx = 0; pml4_idx < 512; pml4_idx++) {
            PML4E_64 pml4e = { 0 };

            // try to read the PML4 entry
            if (!NT_SUCCESS(physical::read_physical_address(dir_base + pml4_idx * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64)))) {
                continue;
            }

            pml4_read_count++;

            // skip if not present
            if (!pml4e.Present) {
                continue;
            }

            pml4_present_count++;

            // get physical address from PFN
            uintptr_t pdpt_phys_addr = PFN_TO_PAGE(pml4e.PageFrameNumber);

            // explore the PDPT level for this PML4 entry
            status = walk_pdpt(pdpt_phys_addr, pml4_idx);
            if (!NT_SUCCESS(status)) {
                log("ERROR", "failed to walk PDPT at PML4 index %u, status: 0x%08X", pml4_idx, status);
                return status;
            }
        }

        log("DEBUG", "PML4 level scan: Read %u entries, %u were present", pml4_read_count, pml4_present_count);
        log("INFO", "completed full page table walk, found %u PTE entries", g_result_count);
        return STATUS_SUCCESS;
    }

    // walk whole PDPT level
    NTSTATUS walk_pdpt(uintptr_t pdpt_base, uint32_t pml4_idx) {
        uint32_t pdpt_read_count = 0;
        uint32_t pdpt_present_count = 0;

        for (uint32_t pdpt_idx = 0; pdpt_idx < 512; pdpt_idx++) {
            PDPTE_64 pdpte = { 0 };

            // try to read the PDPT entry
            if (!NT_SUCCESS(physical::read_physical_address(pdpt_base + pdpt_idx * sizeof(PDPTE_64), &pdpte, sizeof(PDPTE_64)))) {
                continue;
            }

            pdpt_read_count++;

            // skip if not present
            if (!pdpte.Present) {
                continue;
            }

            pdpt_present_count++;

            // skip if large page (1GB)
            if (pdpte.LargePage) {
                continue;
            }

            // get physical address from PFN
            uintptr_t pd_phys_addr = PFN_TO_PAGE(pdpte.PageFrameNumber);

            // explore the PD level for this PDPT entry
            NTSTATUS status = walk_pd(pd_phys_addr, pml4_idx, pdpt_idx);
            if (!NT_SUCCESS(status)) {
                log("ERROR", "failed to walk PD at PDPT index %u, status: 0x%08X", pdpt_idx, status);
                return status;
            }
        }

        if (pdpt_read_count > 0) {
            log("DEBUG", "PDPT level scan for PML4 idx %u: Read %u entries, %u were present",
                pml4_idx, pdpt_read_count, pdpt_present_count);
        }

        return STATUS_SUCCESS;
    }

    // walk whole PD level
    NTSTATUS walk_pd(uintptr_t pd_base, uint32_t pml4_idx, uint32_t pdpt_idx) {
        uint32_t pd_read_count = 0;
        uint32_t pd_present_count = 0;

        for (uint32_t pd_idx = 0; pd_idx < 512; pd_idx++) {
            PDE_64 pde = { 0 };

            // try to read the PD entry
            if (!NT_SUCCESS(physical::read_physical_address(pd_base + pd_idx * sizeof(PDE_64), &pde, sizeof(PDE_64)))) {
                continue;
            }

            pd_read_count++;

            // skip if not present
            if (!pde.Present) {
                continue;
            }

            pd_present_count++;

            // skip if large page (2MB)
            if (pde.LargePage) {
                continue;
            }

            // get physical address from PFN
            uintptr_t pt_phys_addr = PFN_TO_PAGE(pde.PageFrameNumber);

            // explore the PT level for this PD entry
            NTSTATUS status = walk_pt(pt_phys_addr, pml4_idx, pdpt_idx, pd_idx);
            if (!NT_SUCCESS(status)) {
                log("ERROR", "Failed to walk PT at PD index %u, status: 0x%08X", pd_idx, status);
                return status;
            }
        }

        if (pd_read_count > 0) {
            log("DEBUG", "PD level scan for PML4 idx %u, PDPT idx %u: Read %u entries, %u were present",
                pml4_idx, pdpt_idx, pd_read_count, pd_present_count);
        }

        return STATUS_SUCCESS;
    }

    // walk whole PT level
    NTSTATUS walk_pt(uintptr_t pt_base, uint32_t pml4_idx, uint32_t pdpt_idx, uint32_t pd_idx) {
        uint32_t pt_read_count = 0;
        uint32_t pt_present_count = 0;
        uint32_t pt_executable_count = 0;
        uint32_t pt_supervisor_count = 0;

        for (uint32_t pt_idx = 0; pt_idx < 512; pt_idx++) {
            PTE_64 pte = { 0 };

            // calculate the virtual address for this PT entry
            uintptr_t va = 0;
            if (pml4_idx >= 256) {
                // kernel space
                va = 0xFFFF000000000000ULL | ((uintptr_t)pml4_idx << 39) |
                    ((uintptr_t)pdpt_idx << 30) | ((uintptr_t)pd_idx << 21) |
                    ((uintptr_t)pt_idx << 12);
            }
            else {
                // user space
                va = ((uintptr_t)pml4_idx << 39) |
                    ((uintptr_t)pdpt_idx << 30) | ((uintptr_t)pd_idx << 21) |
                    ((uintptr_t)pt_idx << 12);
            }

            // try to read the PT entry
            if (!NT_SUCCESS(physical::read_physical_address(pt_base + pt_idx * sizeof(PTE_64), &pte, sizeof(PTE_64)))) {
                continue;
            }

            pt_read_count++;

            // skip if not present
            if (!pte.Present) {
                continue;
            }

            pt_present_count++;

            // skip if ExecuteDisable 
            if (pte.ExecuteDisable) {
                continue;
            }

            pt_executable_count++;

            // skip if not supervisor bit (we only want to check pages with Supervisor=1)
            if (!pte.Supervisor) {
                continue;
            }

            pt_supervisor_count++;

            // get physical address from PFN
            uintptr_t phys_addr = PFN_TO_PAGE(pte.PageFrameNumber);

            // check if in kernel space and Supervisor bit is set
            uint8_t supervisor_flag = 0;
            if (pml4_idx >= 256) {
                supervisor_flag = 1; // kernel space with supervisor might be a problem
            }

            // check if physical memory can be read and if it has parity error
            uint8_t parity_error_flag = 0;
            uint8_t pfn_exists_flag = 0;
            uint32_t status = check_physical_memory(phys_addr, &parity_error_flag, &pfn_exists_flag);

            // only record entries that have actual issues (parity error set, copy failed, or kernel supervisor bit)
            if (status != STATUS_OK || parity_error_flag || pfn_exists_flag || supervisor_flag) {
                if (!add_entry(va, phys_addr, parity_error_flag, pfn_exists_flag, supervisor_flag)) {
                    log("ERROR", "result buffer full at PML4=%u, PDPT=%u, PD=%u, PT=%u",
                        pml4_idx, pdpt_idx, pd_idx, pt_idx);
                    return STATUS_BUFFER_TOO_SMALL;
                }
            }
        }

        if (pt_read_count > 0 && pt_supervisor_count > 0) {
            log("DEBUG", "PT level scan for PML4 idx %u, PDPT idx %u, PD idx %u: read %u entries, %u were present, %u were executable, %u were supervisor",
                pml4_idx, pdpt_idx, pd_idx, pt_read_count, pt_present_count, pt_executable_count, pt_supervisor_count);
        }

        return STATUS_SUCCESS;
    }

    // helper function to process and display results
    void analyze_page_table_results() {
        uint32_t pfn_parity_flag_entries = 0;
        uint32_t pfn_exists_flag_entries = 0;
        uint32_t supervisor_bit_entries = 0;
        uint32_t kernel_entries = 0;
        uint32_t user_entries = 0;

        // ensure we don't divide by zero if no entries were found
        if (g_result_count == 0) {
            log("INFO", "=== page table walk report ===");
            log("INFO", "no entries found to analyze");
            return;
        }

        for (uint32_t i = 0; i < g_result_count; i++) {
            if (g_results[i].virtual_address & 0xFFFF000000000000ULL) {
                kernel_entries++;
            }
            else {
                user_entries++;
            }

            if (g_results[i].parity_error_flag) {
                pfn_parity_flag_entries++;
            }
            if (g_results[i].pfn_exists_flag) {
                pfn_exists_flag_entries++;
            }
            if (g_results[i].supervisor_flag) {
                supervisor_bit_entries++;
            }
        }

        log("INFO", "=== page table walk report ===");
        log("INFO", "total executable supervisor PTE entries: %u", g_result_count);
        log("INFO", "kernel space entries: %u", kernel_entries);
        log("INFO", "user space entries: %u", user_entries);
        log("INFO", "entries with PFN ParityError flag set: %u", pfn_parity_flag_entries);
        log("INFO", "entries with PFN PfnExists flag not set: %u", pfn_exists_flag_entries);
        log("INFO", "kernel entries with Supervisor bit incorrectly set: %u", supervisor_bit_entries);

        // log first few entries with PFN parity error flags for investigation
        if (pfn_parity_flag_entries > 0) {
            log("INFO", "PFN ParityError examples:");
            uint32_t count = 0;
            for (uint32_t j = 0; j < g_result_count; j++) {
                if (g_results[j].parity_error_flag) {
                    log("INFO", "  VA=0x%llx, PA=0x%llx",
                        g_results[j].virtual_address, g_results[j].physical_address);
                    if (++count >= 100) break; // limit to 100 examples
                }
            }
        }

        // log first few entries with PFN exists flags not set for investigation
        if (pfn_exists_flag_entries > 0) {
            log("INFO", "PFN PfnExists examples:");
            uint32_t count = 0;
            for (uint32_t j = 0; j < g_result_count; j++) {
                if (g_results[j].pfn_exists_flag) {
                    log("INFO", "  VA=0x%llx, PA=0x%llx",
                        g_results[j].virtual_address, g_results[j].physical_address);
                    if (++count >= 100) break; // limit to 100 examples
                }
            }
        }

    }

    // main function to execute the full page table walk
    NTSTATUS inspect_process_page_tables(uint32_t process_id) {
        PEPROCESS process;
        auto status = PsLookupProcessByProcessId((HANDLE)process_id, &process);

        if (!NT_SUCCESS(status)) {
            log("ERROR", "failed to lookup process with ID %u, status: 0x%08X", process_id, status);
            return status;
        }

        physical::init();

        const auto dir_base = physical::get_process_directory_base(process);
        log("INFO", "process %u has directory base 0x%llx", process_id, dir_base);

        // validate CR3
        if (!dir_base) {
            log("ERROR", "invalid directory base: 0x%llx", dir_base);
            ObfDereferenceObject(process);
            return STATUS_INVALID_PARAMETER;
        }

        // perform the full page table walk
        status = walk_all_page_tables(dir_base);

        if (NT_SUCCESS(status)) {
            // analysze and report the results
            analyze_page_table_results();
        }
        else {
            log("ERROR", "failed to walk page tables, status: 0x%08X", status);
        }

        ObfDereferenceObject(process);
        return status;
    }
}