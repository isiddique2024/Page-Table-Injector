#pragma once
// https://github.com/SamuelTulach/DirectPageManipulation

namespace physical {
  extern inline PTE_NEW* main_page_entry;
  extern inline void* main_virtual_address;

  void* physical_to_virtual(const uintptr_t address);

  NTSTATUS init();

  PVOID overwrite_page(const uintptr_t physical_address);

  NTSTATUS read_physical_address(const uintptr_t target_address, void* buffer, const size_t size,
                                 bool bypass_validation = false);

  NTSTATUS write_physical_address(const uintptr_t target_address, const void* buffer,
                                  const size_t size, bool bypass_validation = false);

#define PAGE_OFFSET_SIZE 12
  static constexpr uintptr_t PMASK = 0xFFFFFFFFFFF000;
  uintptr_t translate_linear_address(uintptr_t directory_table_base,
                                     const uintptr_t virtual_address);

  /*uintptr_t translate_linear_address(uintptr_t cr3, uintptr_t va) {
    const uint32_t maxphyaddr = intrin::get_maxphyaddr();
    const uintptr_t phys_mask = ((1ULL << maxphyaddr) - 1) & ~0xFFFULL;

    log("SUCCESS", "VA: 0x%llx, CR3: 0x%llx, MAXPHYADDR: %d bits\n", va, cr3, maxphyaddr);

    cr3 &= phys_mask;

     extract indices
    const uintptr_t pml4_idx = (va >> 39) & 0x1FF;
    const uintptr_t pdpt_idx = (va >> 30) & 0x1FF;
    const uintptr_t pd_idx = (va >> 21) & 0x1FF;
    const uintptr_t pt_idx = (va >> 12) & 0x1FF;
    const uintptr_t offset = va & 0xFFF;

    log("SUCCESS", "INDICES PML4: %llu, PDPT: %llu, PD: %llu, PT: %llu, Offset: 0x%llx", pml4_idx,
        pdpt_idx, pd_idx, pt_idx, offset);

     read PML4E
    PML4E_64 pml4e;
    uintptr_t pml4e_addr = cr3 + 8 * pml4_idx;
    read_physical_address(pml4e_addr, &pml4e, sizeof(pml4e));
    log("SUCCESS", "PML4E Addr: 0x%llx, Value: 0x%llx, Present: %d, PFN: 0x%llx", pml4e_addr, pml4e,
        pml4e.Present, pml4e.PageFrameNumber);
    if (!pml4e.Present) {
      log("ERROR", "PML4E not present\n");
      return 0;
    }

     read PDPTE
    PDPTE_64 pdpte;
    uintptr_t pdpt_base = (pml4e.PageFrameNumber << 12);
    uintptr_t pdpte_addr = pdpt_base + 8 * pdpt_idx;
    read_physical_address(pdpte_addr, &pdpte, sizeof(pdpte));
    log("SUCCESS", "PDPTE Addr: 0x%llx, Value: 0x%llx, Present: %d, LargePage: %d, PFN: 0x%llx\n",
        pdpte_addr, pdpte, pdpte.Present, pdpte.LargePage, pdpte.PageFrameNumber);
    if (!pdpte.Present) {
      log("ERROR", "PDPTE not present");
      return 0;
    }

     check for 1GB page
    if (pdpte.LargePage) {
       for 1GB pages: PDPTE.PFN contains bits 51:30 of physical address
       shift by 12 and mask to align to 1GB boundary
      uintptr_t page_base = pdpte.PageFrameNumber << 12;
      uintptr_t phys_addr = (page_base & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
      log("SUCCESS", "1GB PAGE Base: 0x%llx, Final PA: 0x%llx", page_base & 0x000FFFFFC0000000ULL,
          phys_addr);
      return phys_addr;
    }

     read PDE
    PDE_64 pde;
    uintptr_t pd_base = (pdpte.PageFrameNumber << 12);
    uintptr_t pde_addr = pd_base + 8 * pd_idx;
    read_physical_address(pde_addr, &pde, sizeof(pde));
    log("SUCCESS", "PDE Addr: 0x%llx, Value : 0x%llx, Present: %d, LargePage: %d, PFN: 0x%llx",
        pde_addr, pde, pde.Present, pde.LargePage, pde.PageFrameNumber);
    if (!pde.Present) {
      log("ERROR", "PDE not present");
      return 0;
    }

     check for 2MB page
    if (pde.LargePage) {
       for 2MB pages: PDE.PFN contains bits 51:21 of physical address
       shift by 12 and mask to align to 2MB boundary
      uintptr_t page_base = pde.PageFrameNumber << 12;
      uintptr_t phys_addr = (page_base & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
      log("SUCCESS", "2MB PAGE Base: 0x%llx, Final PA: 0x%llx", page_base & 0x000FFFFFFFE00000ULL,
          phys_addr);
      return phys_addr;
    }

     read PTE for 4KB page
    PTE_64 pte;
    uintptr_t pt_base = (pde.PageFrameNumber << 12);
    uintptr_t pte_addr = pt_base + 8 * pt_idx;
    read_physical_address(pte_addr, &pte, sizeof(pte));
    log("SUCCESS", "PTE Addr: 0x%llx, Value: 0x%llx, Present: %d, PFN: 0x%llx", pte_addr, pte,
        pte.Present, pte.PageFrameNumber);
    if (!pte.Present) {
      log("ERROR", "PTE not present");
      return 0;
    }

     4KB page
    uintptr_t phys_addr = (pte.PageFrameNumber << 12) | offset;
    log("SUCCESS", "4KB PAGE Base: 0x%llx, Final PA: 0x%llx\n", pte.PageFrameNumber << 12,
        phys_addr);
    return phys_addr;
  }*/

  uintptr_t get_process_directory_base(const PEPROCESS input_process);

  uintptr_t get_process_directory_base_user(const PEPROCESS input_process);

  NTSTATUS read_process_memory(const PEPROCESS process, const uintptr_t address, void* buffer,
                               const size_t size);

  NTSTATUS write_process_memory(const PEPROCESS process, const uintptr_t address,
                                const void* buffer, const size_t size);

  NTSTATUS copy_memory(const PEPROCESS source_process, const void* source_address,
                       const PEPROCESS target_process, const void* target_address,
                       const size_t buffer_size);

  auto get_page_frame_number(uintptr_t virtual_address, bool use_large_page) -> uintptr_t;

}  // namespace physical
