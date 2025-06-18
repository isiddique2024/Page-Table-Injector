#pragma once
namespace page_table {

    auto get_page_information(const void* va, const CR3 cr3) -> PAGE_INFORMATION
    {
        ADDRESS_TRANSLATION_HELPER helper;
        UINT32 level;
        PML4E_64* pml4, * pml4e;
        PDPTE_64* pdpt, * pdpte;
        PDE_64* pd, * pde;
        PTE_64* pt, * pte;

        PAGE_INFORMATION info;

        helper.AsUInt64 = reinterpret_cast<uintptr_t>(va);

        PHYSICAL_ADDRESS pa;

        pa.QuadPart = PFN_TO_PAGE(cr3.AddressOfPageDirectory);

        pml4 = reinterpret_cast<PML4E_64*>(globals::mm_get_virtual_for_physical(pa));

        pml4e = &pml4[helper.AsIndex.Pml4];

        info.PML4E = pml4e;

        if (pml4e->Present == FALSE)
        {
            info.PTE = nullptr;
            info.PDE = nullptr;
            info.PDPTE = nullptr;

            goto end;
        }

        pa.QuadPart = PFN_TO_PAGE(pml4e->PageFrameNumber);

        pdpt = reinterpret_cast<PDPTE_64*>(globals::mm_get_virtual_for_physical(pa));

        pdpte = &pdpt[helper.AsIndex.Pdpt];

        info.PDPTE = pdpte;

        if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE))
        {
            info.PTE = nullptr;
            info.PDE = nullptr;

            goto end;
        }

        pa.QuadPart = PFN_TO_PAGE(pdpte->PageFrameNumber);

        pd = reinterpret_cast<PDE_64*>(globals::mm_get_virtual_for_physical(pa));

        pde = &pd[helper.AsIndex.Pd];

        info.PDE = pde;

        if ((pde->Present == FALSE) || (pde->LargePage != FALSE))
        {
            info.PTE = nullptr;

            goto end;
        }

        pa.QuadPart = PFN_TO_PAGE(pde->PageFrameNumber);

        pt = reinterpret_cast<PTE_64*>(globals::mm_get_virtual_for_physical(pa));

        pte = &pt[helper.AsIndex.Pt];

        info.PTE = pte;

        return info;

    end:
        return info;
    }

    auto find_unused_space(void* base, uint32_t section_size, size_t shell_size) -> void* // kinda pointless method to find unused space throughout .data section and picking a random start address out of every usable space it found
    {
        auto* data_section = static_cast<uint8_t*>(base);
        void* free_spaces[MAX_FREE_SPACES];
        uint32_t free_space_count = 0;

        // find all suitable free spaces
        for (uint32_t i = 0; i <= section_size - shell_size; ) {
            bool found_space = true;
            size_t largest_fit = 0;

            // check for free space starting at i
            for (size_t j = 0; j < shell_size; ++j) {
                if (data_section[i + j] != 0x00) {
                    found_space = false;
                    break;
                }
            }

            // if we found free space, determine how large the free block is
            if (found_space) {
                largest_fit = shell_size;

                // determine the largest block that can fit starting from i
                for (size_t j = shell_size; i + j < section_size; ++j) {
                    if (data_section[i + j] != 0x00) {
                        break;  // stop when we encounter a non-zero byte
                    }
                    largest_fit = j + 1;  // adjust largest size that can fit
                }

                // store the adjusted starting address
                if (free_space_count < MAX_FREE_SPACES) {
                    free_spaces[free_space_count++] = &data_section[i];
                    log("INFO", "found free space at: %p, marking range from start address 0x%p to end address 0x%p ( max shell size that can fit: %zu )",
                        &data_section[i], &data_section[i], &data_section[i + largest_fit], largest_fit);
                }
                else {
                    log("WARNING", "too many free spaces found, increase MAX_FREE_SPACES.");
                    break;
                }

                // move i forward by the largest shell size found to avoid overlap
                i += largest_fit;
            }
            else {
                // move to the next address if no space is found at the current location
                ++i;
            }
        }

        // if no free space was found, return nullptr
        if (free_space_count == 0) {
            log("ERROR", "no free space found");
            return nullptr;
        }

        // choose one starting address randomly from above
        LARGE_INTEGER seed;
        KeQuerySystemTime(&seed);
        uint32_t random_index = static_cast<uint32_t>(seed.QuadPart % free_space_count);
        void* chosen_space = free_spaces[random_index];

        log("INFO", "chosen starting address: 0x%p", chosen_space);

        return chosen_space;
    }

    auto find_section_base(void* base, uint32_t* size, const char* section_name, size_t section_name_len) -> void*
    {
        const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            reinterpret_cast<const uint8_t*>(base) + dos_header->e_lfanew);

        const auto* section = IMAGE_FIRST_SECTION(nt_headers);

        for (uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section) {
            if (!globals::strncmp(reinterpret_cast<const char*>(section->Name), section_name, section_name_len)) {
                *size = section->Misc.VirtualSize;
                return reinterpret_cast<uint8_t*>(base) + section->VirtualAddress;
            }
        }

        return nullptr;
    }

    // windows 11 ntoskrnl is mapped on a LargePage
    auto spoof_pte_range(const uintptr_t address, const size_t size, const bool execute_disable) -> bool
    {
        CR3 cr3;
        cr3.Flags = __readcr3();
        log("INFO", "CR3 Value: 0x%llx, Page Directory Base: 0x%llx", cr3.Flags, cr3.AddressOfPageDirectory);

        bool success = false;
        const auto pages = (size + 0xFFF) >> PAGE_SHIFT;
        log("INFO", "number of pages to process: %zu", pages);

        for (size_t i = 0; i < pages; ++i) {
            const auto current_va = address + i * 0x1000;
            log("INFO", "processing VA: 0x%llx", current_va);

            auto page_info = get_page_information(reinterpret_cast<void*>(current_va), cr3);

            auto pte = page_info.PTE;
            if (pte) {
                if (pte->Present) {

                    pte->ExecuteDisable = execute_disable;
                    //pte->Write = true;

                    log("INFO", "modified PTE - Write: %d, ExecuteDisable: %d",
                        pte->Write, pte->ExecuteDisable);

                    success = true;
                }
                else {
                    log("ERROR", "PTE not present for VA: 0x%llx", current_va);
                }
            }
            else {
                log("ERROR", "PTE is null for VA: 0x%llx", current_va);
            }

            auto pde = page_info.PDE;
            if (pde) {
                if (pde->Present && pde->LargePage) {

                    pde->ExecuteDisable = execute_disable;
                    //pde->Write = true;

                    log("INFO", "modified pde - Write: %d, ExecuteDisable: %d",
                        pde->Write, pde->ExecuteDisable);

                    success = true;
                }
                else {
                    log("ERROR", "pde not present for VA: 0x%llx", current_va);
                }
            }
            else {
                log("ERROR", "pde is null for VA: 0x%llx", current_va);
            }
        }

        if (success) {
            log("INFO", "successfully modified PTEs");
        }
        else {
            log("ERROR", "failed to modify any PTEs");
        }

        return success;
    }


    uintptr_t get_pml4e(uint32_t pml4_idx) {
        return static_cast<uintptr_t>(pml4_idx) << 39;
    }

    uintptr_t get_pdpt(uint32_t pdpt_idx) {
        return static_cast<uintptr_t>(pdpt_idx) << 30;
    }

    uintptr_t get_pd(uint32_t pd_idx) {
        return static_cast<uintptr_t>(pd_idx) << 21;
    }

    uintptr_t get_pt(uint32_t pt_idx) {
        return static_cast<uintptr_t>(pt_idx) << 12;
    }

}