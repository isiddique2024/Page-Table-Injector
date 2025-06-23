#pragma once
namespace page_table {

  /**
   * @brief Flush all Translation Lookaside Buffers and processor caches
   *
   * Performs a complete TLB flush and cache invalidation across all processors.
   * This ensures memory mappings and cached data are refreshed after page table
   * modifications.
   */
  auto flush_tlb() -> void {
    globals::ke_flush_entire_tb(TRUE, TRUE);
    globals::ke_invalidate_all_caches();
    globals::mi_flush_entire_tb_due_to_attribute_change();
  }

  /**
   * @brief Intelligently flush caches and TLB for a specific memory address
   *
   * Performs comprehensive cache and Translation Lookaside Buffer (TLB)
   * invalidation for a specific memory address. Uses optimal flushing strategy
   * based on CPU features.
   *
   * @param address Virtual address to flush from caches and TLB
   *
   * @details
   * This function performs the following operations in sequence:
   * 1. **Smart TLB Flushing**:
   *    - If PCID or Global Pages are enabled: Toggles PGE bit to flush global TLB
   * entries
   *    - Otherwise: Reloads CR3 to flush entire TLB (preserves global pages if
   * PGE set)
   * 2. **Cache Invalidation**: Forces all dirty cache lines to memory and
   * invalidates CPU caches
   * 3. **Page-Specific Invalidation**: Removes the specific virtual address from
   * TLB
   *
   * @note This is a heavy operation that flushes ALL processor caches. Use
   * sparingly.
   * @warning Should be called after direct page table modifications to ensure
   * cache coherency
   *
   * @see CR4 control register documentation for PCID and PGE details
   * @see Intel Software Developer Manual Vol 3A, Section 4.10 for TLB management
   */
  void flush_caches(void* address) {
    _mm_mfence();

    CR4 cr4{__readcr4()};

    // save original PGE state
    bool pge_was_enabled = cr4.PageGlobalEnable;

    if (pge_was_enabled) {
      // clear PGE to flush global entries
      cr4.PageGlobalEnable = 0;
      __writecr4(cr4.Flags);

      // restore PGE
      cr4.PageGlobalEnable = 1;
      __writecr4(cr4.Flags);
    }

    // reload CR3 to flush non-global entries
    __writecr3(__readcr3());

    globals::ke_flush_entire_tb(TRUE, TRUE);  //  ( cr3/cr4 rewrite on all cores )
    globals::ke_invalidate_all_caches();      // ( __wbinvd on all cores )
    globals::ke_flush_single_tb(reinterpret_cast<uintptr_t>(address), 0,
                                1);  // ( __invlpg on all cores )

    _mm_mfence();
  }

  /**
   * @brief Convert a virtual address to its corresponding physical address
   * @param virtual_address The virtual address to translate
   * @return PHYSICAL_ADDRESS structure containing the physical address, or 0 if
   * translation fails
   *
   * Uses the Memory Manager's PTE resolution to perform virtual-to-physical
   * address translation. Returns zero physical address if the page is not present
   * or the PTE is invalid.
   */
  auto virtual_to_physical(void* virtual_address) -> PHYSICAL_ADDRESS {
    PHYSICAL_ADDRESS physical_address{0};
    const uintptr_t va = reinterpret_cast<uintptr_t>(virtual_address);

    PTE_64* const pte = reinterpret_cast<PTE_64*>(globals::mi_get_pte_address(va));
    if (!pte || !pte->Present) {
      return physical_address;
    }

    const uintptr_t pfn = pte->PageFrameNumber;
    physical_address.QuadPart = (pfn << PAGE_SHIFT) | (va & 0xFFF);

    return physical_address;
  }
  /**
   * @brief Retrieve page table entry information for a given virtual address
   * @param va Virtual address to analyze
   * @param cr3 CR3 register value containing the page directory base
   * @return PAGE_INFORMATION structure containing pointers to relevant page table
   * entries
   *
   * Walks the page table hierarchy to locate and return pointers to the PML4E,
   * PDPTE, PDE, and PTE entries for a virtual address. Handles large pages and
   * stops traversal early when encountering non-present entries or large page
   * mappings.
   */
  auto get_page_information(const void* va, const CR3 cr3) -> PAGE_INFORMATION {
    ADDRESS_TRANSLATION_HELPER helper;
    UINT32 level;
    PML4E_64 *pml4, *pml4e;
    PDPTE_64 *pdpt, *pdpte;
    PDE_64 *pd, *pde;
    PTE_64 *pt, *pte;

    PAGE_INFORMATION info;

    helper.AsUInt64 = reinterpret_cast<uintptr_t>(va);

    PHYSICAL_ADDRESS pa;

    pa.QuadPart = PFN_TO_PAGE(cr3.AddressOfPageDirectory);

    pml4 = reinterpret_cast<PML4E_64*>(globals::mm_get_virtual_for_physical(pa));

    pml4e = &pml4[helper.AsIndex.Pml4];

    info.PML4E = pml4e;

    if (pml4e->Present == FALSE) {
      info.PTE = nullptr;
      info.PDE = nullptr;
      info.PDPTE = nullptr;

      goto end;
    }

    pa.QuadPart = PFN_TO_PAGE(pml4e->PageFrameNumber);

    pdpt = reinterpret_cast<PDPTE_64*>(globals::mm_get_virtual_for_physical(pa));

    pdpte = &pdpt[helper.AsIndex.Pdpt];

    info.PDPTE = pdpte;

    if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE)) {
      info.PTE = nullptr;
      info.PDE = nullptr;

      goto end;
    }

    pa.QuadPart = PFN_TO_PAGE(pdpte->PageFrameNumber);

    pd = reinterpret_cast<PDE_64*>(globals::mm_get_virtual_for_physical(pa));

    pde = &pd[helper.AsIndex.Pd];

    info.PDE = pde;

    if ((pde->Present == FALSE) || (pde->LargePage != FALSE)) {
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

  /**
   * @brief Find random unused space within a memory section for shellcode
   * placement
   * @param base Base address of the section to scan
   * @param section_size Total size of the section in bytes
   * @param shell_size Required size for the shellcode
   * @return Pointer to a randomly selected free space, or nullptr if none found
   *
   * Scans for contiguous zero-byte regions large enough to hold shellcode and
   * randomly selects one to avoid predictable placement patterns.
   */
  auto find_unused_space(void* base, uint32_t section_size, size_t shell_size)
      -> void*  // kinda pointless method to find unused space throughout .data
                // section and picking a random start address out of every usable
                // space it found
  {
    auto* data_section = static_cast<uint8_t*>(base);
    void* free_spaces[MAX_FREE_SPACES];
    uint32_t free_space_count = 0;

    // find all suitable free spaces
    for (uint32_t i = 0; i <= section_size - shell_size;) {
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
          log("INFO",
              "found free space at: %p, marking range from start address 0x%p to "
              "end address 0x%p ( max shell size that can fit: %zu )",
              &data_section[i], &data_section[i], &data_section[i + largest_fit], largest_fit);
        } else {
          log("WARNING", "too many free spaces found, increase MAX_FREE_SPACES.");
          break;
        }

        // move i forward by the largest shell size found to avoid overlap
        i += largest_fit;
      } else {
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

  /**
   * @brief Locate a specific section within a PE image
   * @param base Base address of the PE image
   * @param size Output parameter for the section's virtual size
   * @param section_name Name of the section to find (e.g., ".text", ".data")
   * @param section_name_len Length of the section name string
   * @return Virtual address of the section, or nullptr if not found
   *
   * Parses PE headers to locate a named section and returns its virtual address
   * and size.
   */
  auto find_section_base(void* base, uint32_t* size, const char* section_name,
                         size_t section_name_len) -> void* {
    const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        reinterpret_cast<const uint8_t*>(base) + dos_header->e_lfanew);

    const auto* section = IMAGE_FIRST_SECTION(nt_headers);

    for (uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section) {
      if (!globals::strncmp(reinterpret_cast<const char*>(section->Name), section_name,
                            section_name_len)) {
        *size = section->Misc.VirtualSize;
        return reinterpret_cast<uint8_t*>(base) + section->VirtualAddress;
      }
    }

    return nullptr;
  }

  /**
   * @brief Modify page table entries to change memory protection attributes
   * @param address Starting virtual address of the memory range
   * @param size Size of the memory range in bytes
   * @param execute_disable Whether to set the Execute Disable (NX) bit
   * @return true if at least one PTE was successfully modified, false otherwise
   *
   * Iterates through pages in the specified range and modifies their PTEs or PDEs
   * to change execution permissions. Handles both regular 4KB pages and 2MB large
   * pages.
   */
  auto spoof_pte_range(const uintptr_t address, const size_t size, const bool execute_disable)
      -> bool {
    CR3 cr3;
    cr3.Flags = __readcr3();
    log("INFO", "CR3 Value: 0x%llx, Page Directory Base: 0x%llx", cr3.Flags,
        cr3.AddressOfPageDirectory);

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
          // pte->Write = true;

          log("INFO", "modified PTE - Write: %d, ExecuteDisable: %d", pte->Write,
              pte->ExecuteDisable);

          success = true;
        } else {
          log("ERROR", "PTE not present for VA: 0x%llx", current_va);
        }
      } else {
        log("ERROR", "PTE is null for VA: 0x%llx", current_va);
      }

      auto pde = page_info.PDE;
      if (pde) {
        if (pde->Present && pde->LargePage) {
          pde->ExecuteDisable = execute_disable;
          // pde->Write = true;

          log("INFO", "modified pde - Write: %d, ExecuteDisable: %d", pde->Write,
              pde->ExecuteDisable);

          success = true;
        } else {
          log("ERROR", "pde not present for VA: 0x%llx", current_va);
        }
      } else {
        log("ERROR", "pde is null for VA: 0x%llx", current_va);
      }
    }

    if (success) {
      log("INFO", "successfully modified PTEs");
    } else {
      log("ERROR", "failed to modify any PTEs");
    }

    return success;
  }

  /**
   * @brief Calculate virtual address component for PML4 entry index
   * @param pml4_idx PML4 table index (0-511)
   * @return Virtual address bits corresponding to the PML4 index (bits 47-39)
   *
   * Helper function to construct virtual addresses by converting page table
   * indices to their corresponding address bit patterns.
   */
  uintptr_t get_pml4e(uint32_t pml4_idx) {
    return static_cast<uintptr_t>(pml4_idx) << 39;
  }

  /**
   * @brief Calculate virtual address component for PDPT entry index
   * @param pdpt_idx PDPT table index (0-511)
   * @return Virtual address bits corresponding to the PDPT index (bits 38-30)
   *
   * Helper function to construct virtual addresses by converting page table
   * indices to their corresponding address bit patterns.
   */
  uintptr_t get_pdpt(uint32_t pdpt_idx) {
    return static_cast<uintptr_t>(pdpt_idx) << 30;
  }

  /**
   * @brief Calculate virtual address component for PD entry index
   * @param pd_idx PD table index (0-511)
   * @return Virtual address bits corresponding to the PD index (bits 29-21)
   *
   * Helper function to construct virtual addresses by converting page table
   * indices to their corresponding address bit patterns.
   */
  uintptr_t get_pd(uint32_t pd_idx) {
    return static_cast<uintptr_t>(pd_idx) << 21;
  }

  /**
   * @brief Calculate virtual address component for PT entry index
   * @param pt_idx PT table index (0-511)
   * @return Virtual address bits corresponding to the PT index (bits 20-12)
   *
   * Helper function to construct virtual addresses by converting page table
   * indices to their corresponding address bit patterns.
   */
  uintptr_t get_pt(uint32_t pt_idx) {
    return static_cast<uintptr_t>(pt_idx) << 12;
  }

}  // namespace page_table