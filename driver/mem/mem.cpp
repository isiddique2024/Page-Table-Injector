#pragma once
#include "../def/globals.hpp"
#include "phys.hpp"
#include "page_table.hpp"
#include "validation.hpp"
#include "../utils/raii.hpp"
namespace mem {

  /**
   * @brief Safely copy memory between virtual addresses within the current
   * process
   * @param dst Destination buffer
   * @param src Source buffer
   * @param size Number of bytes to copy
   * @return true if copy succeeded and all bytes were transferred, false
   * otherwise
   *
   * Uses MmCopyVirtualMemory for safe memory transfers.
   */
  bool safe_copy(void* const dst, void* const src, const size_t size) {
    SIZE_T bytes = 0;
    const auto current_process = globals::io_get_current_process();

    return globals::mm_copy_virtual_memory(current_process, src, current_process, dst, size,
                                           KernelMode, &bytes) == STATUS_SUCCESS &&
           bytes == size;
  }

  /**
   * @brief Validate user-mode address alignment and bounds
   * @param addr Address to validate
   * @param size Size of the memory region
   * @param alignment Required alignment (must be power of 2)
   * @return true if address is valid, false if invalid or out of bounds
   *
   * Checks if an address is properly aligned, within user-mode bounds, and
   * doesn't overflow.
   */
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

  /**
   * @brief Locate a loaded driver's base address by module name
   * @param module_name ANSI string name of the module to find
   * @return Base address of the module, or nullptr if not found
   *
   * Searches the PsLoadedModuleList to find a driver by name and returns its base
   * address.
   */
  auto get_driver_base(LPCSTR const module_name) -> void* {
    void* module_base = nullptr;

    UNICODE_STRING unicode_module_name;
    ANSI_STRING ansi_module_name;

    UNICODE_STRING routine_name;
    globals::rtl_init_unicode_string(&routine_name, L"PsLoadedModuleList");

    const auto module_list =
        static_cast<PLIST_ENTRY>(globals::mm_get_system_routine_address(&routine_name));
    auto current_entry = module_list->Flink;

    globals::rtl_init_ansi_string(&ansi_module_name, module_name);
    globals::rtl_ansi_string_to_unicode_string(&unicode_module_name, &ansi_module_name, TRUE);

    while (current_entry != module_list) {
      const auto data_table_entry =
          CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

      if (globals::rtl_compare_unicode_string(&data_table_entry->BaseDllName, &unicode_module_name,
                                              TRUE) == 0) {
        module_base = data_table_entry->DllBase;
        break;
      }

      current_entry = current_entry->Flink;
    }

    globals::rtl_free_unicode_string(&unicode_module_name);
    return module_base;
  }

  /**
   * @brief Apply stealth techniques to hide physical memory pages from detection
   * @param page_frame_number The PFN of the page to hide
   * @param type The hiding technique to apply
   * @return true if hiding succeeded, false otherwise
   *
   * Implements various memory hiding techniques via MmPfnDatabase manipulation
   */
  auto hide_physical_memory(uintptr_t page_frame_number, hide_type type, bool lock_page) -> bool {
    if (page_frame_number < globals::mm_lowest_physical_page ||
        page_frame_number > globals::mm_highest_physical_page) {
      log("ERROR", "invalid PFN range: 0x%llx", page_frame_number);
      return false;
    }

    const auto pfn_entry_addr =
        *reinterpret_cast<uintptr_t*>(globals::mm_pfn_db) + 0x30 * (page_frame_number);

    auto* e1_field = reinterpret_cast<_MMPFNENTRY1*>(pfn_entry_addr + 0x22);
    auto* e3_field = reinterpret_cast<_MMPFNENTRY3*>(pfn_entry_addr + 0x23);
    auto* u2_field = reinterpret_cast<_MIPFNBLINK*>(pfn_entry_addr + 0x18);
    auto* active_field = reinterpret_cast<_MI_ACTIVE_PFN*>(pfn_entry_addr + 0x0);

    if (lock_page) {
      auto lock_result = globals::mi_lock_page_table_page(pfn_entry_addr, 3);
      if (!lock_result) {
        log("ERROR", "failed to lock page table page for PFN: 0x%llx", page_frame_number);
        return 0;
      }
    }

    switch (type) {
      case hide_type::NONE: {
        break;
      }
      case hide_type::PFN_EXISTS_BIT:  // returns 0xC0000141,
                                       // STATUS_INVALID_ADDRESS, The address
                                       // handle that was given to the transport
                                       // was invalid.
      {
        const auto PFN_EXISTS_BIT = (globals::build_version >= 22000) ? (1ULL << 54) : (1ULL << 50);

        auto* u4_field =
            reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(pfn_entry_addr) + 0x28);

        *u4_field &= ~PFN_EXISTS_BIT;
        break;
      }

      case hide_type::MI_REMOVE_PHYSICAL_MEMORY:  // returns 0xC0000141,
                                                  // STATUS_INVALID_ADDRESS, The
                                                  // address handle that was given
                                                  // to the transport was invalid.
      {
        const auto FLAGS = globals::build_version >= 26100 ? 0x62 : 0x32;

        // removes PFN from MmPhysicalMemoryBlock
        NTSTATUS status = globals::mi_remove_physical_memory(page_frame_number, 1, FLAGS);
        if (!NT_SUCCESS(status)) {
          log("ERROR", "failed to remove physical memory on 0x%llx status 0x%X", page_frame_number,
              status);
          return false;
        }

        // nulls PFN entry for physical page
        globals::memset(reinterpret_cast<void*>(pfn_entry_addr), 0, 0x30);

        break;
      }
      case hide_type::SET_PARITY_ERROR: {
        // set ParityError, causes MmCopyMemory to return 0xC0000709
        // (STATUS_HARDWARE_MEMORY_ERROR) on the physical pages
        e3_field->ParityError = 1;

        break;
      }
      case hide_type::SET_LOCK_BIT: {
        // set LockBit, causes CPU to yield when MmCopyMemory is called on your
        // dll's physical address, think of this moreso as an anti-debug
        // mechanism. This can be used to see if your allocation is stealthy
        // enough.
        u2_field->LockBit = 1;

        break;
      }
      case hide_type::HIDE_TRANSLATION:  // this doesn't support driver pages yet
                                         // since I'm using
                                         // MmGetVirtualForPhysical for that lol,
                                         // I have to rewrite the driver hiding
                                         // function
      {
        PHYSICAL_ADDRESS physical_addr;
        physical_addr.QuadPart = PFN_TO_PAGE(page_frame_number);

        // log the virtual address before nulling MMPFN.PteAddress
        void* virtual_addr_before = globals::mm_get_virtual_for_physical(physical_addr);

        log("INFO",
            "MmGetVirtualForPhysical before nulling MMPFN.PteAddress: 0x%p for "
            "PFN "
            "0x%llx",
            virtual_addr_before, page_frame_number);

        // null MMPFN.PteAddress, this causes MmGetVirtualForPhysical to return
        // the wrong virtual address that's mapped by the PTE
        //
        // here's the pseudocode for MmGetVirtualForPhysical
        //
        // PVOID __stdcall MmGetVirtualForPhysical(PHYSICAL_ADDRESS
        // PhysicalAddress)
        // {
        //    return (PVOID)((PhysicalAddress.LowPart & 0xFFF)
        //        + ((__int64)(*(_QWORD*)(0x30 * ((unsigned
        //        __int64)PhysicalAddress.QuadPart >> 12) - 0x21FFFFFFFFF8LL) <<
        //        25)
        //        >> 16));
        // }
        //
        // pay attention specifically to *(_QWORD*)(0x30 * ((unsigned
        // __int64)PhysicalAddress.QuadPart >> 12) - 0x21FFFFFFFFF8LL). this is
        // accessing the MmPfnDatabase for this pfn, specifically the
        // PteAddress/PteLong union field. ideally you would want to spoof this
        // PteAddress/PteLong union field to look more legitimate by using another
        // pfn entry's PteAddress/PteLong union field, but in this case it will
        // just make MmGetVirtualForPhysical return 0 for this physical address

        // null MMPFN.PteAddress
        auto* pte_address = reinterpret_cast<uint64_t*>(pfn_entry_addr + 0x8);
        *pte_address = 0;

        // log the virtual address after nulling MMPFN.PteAddress
        void* virtual_addr_after = globals::mm_get_virtual_for_physical(physical_addr);
        log("INFO",
            "MmGetVirtualForPhysical after nulling MMPFN.PteAddress: 0x%p for "
            "PFN "
            "0x%llx",
            virtual_addr_after, page_frame_number);

        // verify the unlinking worked
        if (virtual_addr_after == nullptr || virtual_addr_after != virtual_addr_before) {
          log("SUCCESS", "successfully nulled MMPFN.PteAddress, phys to virt "
                         "translation has failed");
        } else {
          log("WARNING", "virtual address unchanged after nulling MMPFN.PteAddress "
                         "- operation may have failed");
        }

        break;
      }
    }

    return true;
  }

  /**
   * @brief Allocate independent physical pages with stealth hiding applied
   * @param size Size in bytes to allocate (will be page-aligned)
   * @return Virtual address of allocated memory, or nullptr on failure
   *
   * Allocates non-contiguous physical pages and applies configured hiding
   * techniques. Memory is hidden according to global settings.
   */
  auto allocate_independent_pages(size_t size) -> void* {
    void* base_address = globals::mm_allocate_independent_pages_ex(size, -1, 0, 0);
    if (!base_address) {
      log("ERROR", "failed to allocate independent page");
      return 0;
    }

    globals::memset(base_address, 0, size);

    uintptr_t pfn = page_table::virtual_to_physical(base_address).QuadPart >> PAGE_SHIFT;
    if (!pfn) {
      globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(base_address), size);
      log("ERROR", "failed to get pfn for page");
      return 0;
    }

    bool hide_status =
        mem::hide_physical_memory(pfn, static_cast<hide_type>(globals::dll_hide_type));
    if (!hide_status) {
      globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(base_address), size);
      log("ERROR", "failed to hide pfn for page");
      return 0;
    }

    return base_address;
  }

  /**
   * @brief Allocate secure kernel pages
   * @param size Size in bytes to allocate (will be page-aligned)
   * @return Virtual address of allocated memory, or nullptr on failure
   *
   */
  auto allocate_secure_kernel_pages(size_t size) -> void* {
    size_t page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;

    DWORD output_flag = 0;
    void* base_address = globals::mm_allocate_secure_kernel_pages(
        nullptr,      // Partition parameter (can be nullptr based on the code)
        page_count,   // Number of pages - reuse the function's page_count parameter
        0,            // Slab type (0 is a common default)
        0,            // Unused output parameter
        &output_flag  // Output flag
    );
    if (!base_address) {
      log("ERROR", "failed to allocate secure kernel page");
      return 0;
    }

    globals::memset(base_address, 0, size);

    return base_address;
  }

  /**
   * @brief Allocate contiguous physical memory with stealth hiding applied
   * @param size Size in bytes to allocate (will be page-aligned)
   * @return Virtual address of allocated memory, or nullptr on failure
   *
   * Allocates physically contiguous memory block and applies hiding techniques.
   * Handles both regular and large page allocations.
   */
  auto allocate_contiguous_memory(size_t size) -> void* {
    PHYSICAL_ADDRESS max_address{};
    max_address.QuadPart = ((ULONG64) ~((ULONG64)0));
    void* base_address = globals::mm_allocate_contiguous_memory(size, max_address);
    if (!base_address) {
      log("ERROR", "failed to allocate actual page");
      return 0;
    }
    globals::memset(base_address, 0, size);
    uintptr_t pfn = 0;

    // check if size is 2MB
    if (size == 0x200000) {
      pfn = physical::get_page_frame_number(reinterpret_cast<uintptr_t>(base_address), true);
    } else {
      pfn = physical::get_page_frame_number(reinterpret_cast<uintptr_t>(base_address), false);
    }

    if (!pfn) {
      globals::mm_free_contiguous_memory(base_address);
      log("ERROR", "failed to get pfn for page");
      return 0;
    }

    bool hide_status =
        mem::hide_physical_memory(pfn, static_cast<hide_type>(globals::dll_hide_type));
    if (!hide_status) {
      globals::mm_free_contiguous_memory(base_address);
      log("ERROR", "failed to hide pfn for page");
      return 0;
    }

    return base_address;
  }

  /**
   * @brief Manually construct page table entries for a virtual address range
   * @param target_dir_base Physical address of target process PML4
   * @param base_va Base virtual address to map
   * @param page_count Number of pages to map
   * @param use_large_page Whether to use 2MB large pages instead of 4KB pages
   * @return NTSTATUS indicating success or failure
   *
   * Creates complete page table hierarchy (PML4E->PDPTE->PDE->PTE) for manual
   * memory mapping. Supports both 4KB and 2MB page sizes with proper cache
   * flushing after each page table modification to ensure coherency and locking to prevent paging
   * to disk.
   */
  auto write_page_tables(uintptr_t target_dir_base, uintptr_t base_va, size_t page_count,
                         bool use_large_page) -> NTSTATUS {
    if (!target_dir_base || !page_count)
      return STATUS_INVALID_PARAMETER;

    const size_t PAGE_STEP = use_large_page ? 0x200000 : PAGE_SIZE;

    for (size_t i = 0; i < page_count; ++i) {
      const auto va = base_va + i * PAGE_STEP;
      ADDRESS_TRANSLATION_HELPER h = {.AsUInt64 = va};

      // allocate actual page
      auto page = use_large_page ? mem::allocate_contiguous_memory(0x200000)
                                 : mem::allocate_independent_pages(PAGE_SIZE);
      if (!page)
        return STATUS_INVALID_ADDRESS;

      auto pfn = physical::get_page_frame_number(reinterpret_cast<uintptr_t>(page), use_large_page);

      if (!pfn)
        return STATUS_INVALID_ADDRESS;

      // helper to read/allocate table entry with cache flushing
      auto get_or_create_table = [](uintptr_t table_phys, uint16_t idx, auto& entry) -> uintptr_t {
        auto addr = table_phys + idx * sizeof(entry);
        physical::read_physical_address(addr, &entry, sizeof(entry));

        if (!entry.Present) {
          auto new_table = mem::allocate_independent_pages(PAGE_SIZE);
          if (!new_table)
            return 0;

          entry = {0};
          entry.Flags = 0;
          entry.Present = 1;
          entry.Write = 1;
          entry.Supervisor = 1;
          entry.ExecuteDisable = 0;
          entry.PageFrameNumber = PAGE_TO_PFN(page_table::virtual_to_physical(new_table).QuadPart);

          // write the entry
          if (!NT_SUCCESS(physical::write_physical_address(addr, &entry, sizeof(entry)))) {
            log("ERROR", "failed to write physical address at page table: 0x%llx", addr);
            return 0;
          };

          const auto pfn_entry_addr =
              *reinterpret_cast<uintptr_t*>(globals::mm_pfn_db) + 0x30 * (entry.PageFrameNumber);

          // lock in physical memory
          auto lock_result = globals::mi_lock_page_table_page(pfn_entry_addr, 3);
          if (!lock_result) {
            log("ERROR", "failed to lock page table page for PFN: 0x%llx", entry.PageFrameNumber);
            return 0;
          }

          // flush caches
          page_table::flush_caches(new_table);
          log("INFO", "created and flushed new page table at 0x%llx (entry addr: 0x%llx)",
              reinterpret_cast<uintptr_t>(new_table), addr);
        }

        return PFN_TO_PAGE(entry.PageFrameNumber);
      };

      // walk page table hierarchy and create entries as needed
      log("INFO", "processing VA: 0x%llx (page %zu/%zu)", va, i + 1, page_count);

      // PML4E -> PDPTE
      PML4E_64 pml4e;
      auto pdpt_phys = get_or_create_table(target_dir_base, h.AsIndex.Pml4, pml4e);
      if (!pdpt_phys)
        return STATUS_INVALID_ADDRESS;

      // PDPTE -> PDE
      PDPTE_64 pdpte;
      auto pd_phys = get_or_create_table(pdpt_phys, h.AsIndex.Pdpt, pdpte);
      if (!pd_phys)
        return STATUS_INVALID_ADDRESS;

      if (use_large_page) {
        // create 2MB large page entry
        PDE_2MB_64 pde = {0};
        pde.Flags = 0;
        pde.Present = 1;
        pde.Write = 1;
        pde.Supervisor = 1;
        pde.LargePage = 1;
        pde.ExecuteDisable = 0;
        pde.PageFrameNumber = pfn;

        auto pde_addr = pd_phys + h.AsIndex.Pd * sizeof(pde);
        physical::write_physical_address(pde_addr, &pde, sizeof(pde));

        // flush caches after writing large page PDE
        page_table::flush_caches(page);
        log("INFO", "created 2MB large page PDE at 0x%llx, flushed caches for page 0x%p", pde_addr,
            page);
      } else {
        // PDE -> PTE for 4KB pages
        PDE_64 pde;
        auto pt_phys = get_or_create_table(pd_phys, h.AsIndex.Pd, pde);
        if (!pt_phys)
          return STATUS_INVALID_ADDRESS;

        // create 4KB page entry
        PTE_64 pte = {0};
        pte.Flags = 0;
        pte.Present = 1;
        pte.Write = 1;
        pte.Supervisor = 1;
        pte.ExecuteDisable = 0;
        pte.PageFrameNumber = pfn;

        auto pte_addr = pt_phys + h.AsIndex.Pt * sizeof(pte);
        physical::write_physical_address(pte_addr, &pte, sizeof(pte));

        // flush caches after writing PTE
        page_table::flush_caches(page);
        log("INFO", "created 4KB page PTE at 0x%llx, flushed caches for page 0x%p", pte_addr, page);
      }
    }

    log("SUCCESS", "completed page table creation for %zu pages, performed final TLB flush",
        page_count);

    return STATUS_SUCCESS;
  }
  /**
   * @brief Hijack null/empty PTEs within a process's .text section
   * @param local_pid Current process ID (unused)
   * @param target_pid Target process ID to inject into
   * @param size Size of memory region needed
   * @param use_large_page Whether to use 2MB pages
   * @return Virtual address in target process, or nullptr on failure
   *
   * Scans the target process's main module .text section for PTEs with null page
   * frame numbers and replaces them with hidden physical pages. Dangerous
   * technique that may cause instability.
   */
  auto hijack_null_pfn(const uint32_t local_pid, const uint32_t target_pid, const size_t size,
                       const bool use_large_page) -> void* {
    const size_t page_mask = PAGE_SIZE - 1;
    const size_t aligned_size = (size + page_mask) & ~page_mask;
    const size_t page_count = aligned_size >> PAGE_SHIFT;

    log("INFO", "searching for space of size 0x%llx (%d pages) within .text section", aligned_size,
        page_count);

    PEPROCESS target_process = nullptr;
    if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(target_pid),
                                                 &target_process) != STATUS_SUCCESS) {
      log("ERROR", "failed to lookup target process");
      return nullptr;
    }

    // RAII will handle cleanup
    raii::process_ref process_ref(target_process, "EPROCESS");

    const auto target_dir_base = physical::get_process_directory_base(target_process);
    if (!target_dir_base) {
      log("ERROR", "failed to lookup target process directory base");
      return nullptr;
    }

    PPEB peb_address = globals::ps_get_process_peb(target_process);
    if (!peb_address) {
      log("ERROR", "failed to get PEB address");
      return nullptr;
    }

    PEB peb;
    physical::read_process_memory(target_process, reinterpret_cast<uintptr_t>(peb_address), &peb,
                                  sizeof(PEB));
    log("INFO", "PEB found at 0x%llx", peb_address);

    PEB_LDR_DATA ldr_data;
    physical::read_process_memory(target_process, reinterpret_cast<uintptr_t>(peb.Ldr), &ldr_data,
                                  sizeof(PEB_LDR_DATA));

    LDR_DATA_TABLE_ENTRY main_module;
    physical::read_process_memory(
        target_process,
        reinterpret_cast<uintptr_t>(CONTAINING_RECORD(ldr_data.InMemoryOrderModuleList.Flink,
                                                      LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)),
        &main_module, sizeof(LDR_DATA_TABLE_ENTRY));

    uintptr_t module_base = reinterpret_cast<uintptr_t>(main_module.DllBase);

    IMAGE_DOS_HEADER dos_header;
    physical::read_process_memory(target_process, module_base, &dos_header,
                                  sizeof(IMAGE_DOS_HEADER));

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
      log("ERROR", "invalid DOS header signature");
      return nullptr;
    }

    IMAGE_NT_HEADERS nt_headers;
    physical::read_process_memory(target_process, module_base + dos_header.e_lfanew, &nt_headers,
                                  sizeof(IMAGE_NT_HEADERS));

    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
      log("ERROR", "invalid NT header signature");
      return nullptr;
    }

    uintptr_t section_header_addr = module_base + dos_header.e_lfanew +
                                    FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
                                    nt_headers.FileHeader.SizeOfOptionalHeader;

    bool found_text_section = false;
    uintptr_t text_section_start = 0;
    uintptr_t text_section_end = 0;

    for (WORD i = 0; i < nt_headers.FileHeader.NumberOfSections; i++) {
      IMAGE_SECTION_HEADER section_header;
      physical::read_process_memory(target_process,
                                    section_header_addr + (i * sizeof(IMAGE_SECTION_HEADER)),
                                    &section_header, sizeof(IMAGE_SECTION_HEADER));

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
      return nullptr;
    }

    text_section_start &= ~(PAGE_SIZE - 1);
    text_section_end = (text_section_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    log("INFO", "scanning .text section range (page-aligned): 0x%llx - 0x%llx", text_section_start,
        text_section_end);

    uintptr_t base_va = 0;
    uintptr_t pml4_phys = target_dir_base;

    // Scan for null PTEs (existing logic remains the same)
    for (uintptr_t current_va = text_section_start; current_va < text_section_end;
         current_va += PAGE_SIZE) {
      ADDRESS_TRANSLATION_HELPER helper;
      helper.AsUInt64 = current_va;

      PML4E_64 pml4e = {0};
      physical::read_physical_address(pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e,
                                      sizeof(PML4E_64));

      if (!pml4e.Present)
        continue;

      PDPTE_64 pdpte = {0};
      physical::read_physical_address(PFN_TO_PAGE(pml4e.PageFrameNumber) +
                                          helper.AsIndex.Pdpt * sizeof(PDPTE_64),
                                      &pdpte, sizeof(PDPTE_64));

      if (!pdpte.Present)
        continue;

      PDE_64 pde = {0};
      physical::read_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) +
                                          helper.AsIndex.Pd * sizeof(PDE_64),
                                      &pde, sizeof(PDE_64));

      if (!pde.Present)
        continue;

      PTE_64 pte = {0};
      physical::read_physical_address(PFN_TO_PAGE(pde.PageFrameNumber) +
                                          helper.AsIndex.Pt * sizeof(PTE_64),
                                      &pte, sizeof(PTE_64));

      if (pte.PageFrameNumber == 0) {
        uintptr_t potential_start = current_va;
        size_t available_size = 0;

        while (available_size < aligned_size && current_va < text_section_end) {
          helper.AsUInt64 = current_va;

          physical::read_physical_address(pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64),
                                          &pml4e, sizeof(PML4E_64));
          if (!pml4e.Present)
            break;

          physical::read_physical_address(PFN_TO_PAGE(pml4e.PageFrameNumber) +
                                              helper.AsIndex.Pdpt * sizeof(PDPTE_64),
                                          &pdpte, sizeof(PDPTE_64));
          if (!pdpte.Present)
            break;

          physical::read_physical_address(PFN_TO_PAGE(pdpte.PageFrameNumber) +
                                              helper.AsIndex.Pd * sizeof(PDE_64),
                                          &pde, sizeof(PDE_64));
          if (!pde.Present)
            break;

          physical::read_physical_address(PFN_TO_PAGE(pde.PageFrameNumber) +
                                              helper.AsIndex.Pt * sizeof(PTE_64),
                                          &pte, sizeof(PTE_64));

          if (pte.PageFrameNumber == 0) {
            available_size += PAGE_SIZE;
            current_va += PAGE_SIZE;
          } else {
            break;
          }
        }

        if (available_size >= aligned_size) {
          base_va = potential_start;
          log("SUCCESS",
              "found suitable empty/null page range within .text section at "
              "0x%llx with size 0x%llx",
              base_va, available_size);
          break;
        }
      }
    }

    if (!base_va) {
      log("ERROR", "could not find suitable empty/null page range in .text section");
      return nullptr;
    }

    log("INFO", "selected base address: 0x%llx", base_va);

    auto write_pt_status =
        mem::write_page_tables(target_dir_base, base_va, page_count, use_large_page);

    if (!NT_SUCCESS(write_pt_status)) {
      log("ERROR", "failed to write page tables");
      return nullptr;
    }

    return reinterpret_cast<void*>(base_va);
  }

  /**
   * @brief Find unused virtual address space between loaded modules
   * @param local_pid Current process ID (unused)
   * @param target_pid Target process ID to inject into
   * @param size Size of memory region needed
   * @param use_large_page Whether to use 2MB pages
   * @return Virtual address in target process, or nullptr on failure
   *
   * Enumerates loaded modules and finds gaps in virtual address space large
   * enough for the requested allocation, then maps hidden pages at that location.
   */
  auto allocate_between_modules(const uint32_t local_pid, const uint32_t target_pid,
                                const size_t size, const bool use_large_page) -> void* {
    const size_t page_mask = PAGE_SIZE - 1;
    const size_t aligned_size = (size + page_mask) & ~page_mask;
    const size_t page_count = aligned_size >> PAGE_SHIFT;

    log("INFO", "searching for space of size 0x%llx (%d pages)", aligned_size, page_count);

    PEPROCESS target_process = nullptr;
    if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(target_pid),
                                                 &target_process) != STATUS_SUCCESS) {
      log("ERROR", "failed to lookup target process");
      return nullptr;
    }

    // RAII will handle cleanup
    raii::process_ref process_ref(target_process, "EPROCESS");

    const auto target_dir_base = physical::get_process_directory_base(target_process);
    if (!target_dir_base) {
      log("ERROR", "failed to lookup target process directory base");
      return nullptr;
    }

    PPEB peb_address = globals::ps_get_process_peb(target_process);
    if (!peb_address) {
      log("ERROR", "failed to get PEB address");
      return nullptr;
    }

    PEB peb;
    physical::read_process_memory(target_process, reinterpret_cast<uintptr_t>(peb_address), &peb,
                                  sizeof(PEB));
    log("INFO", "PEB found at 0x%llx", peb_address);

    PEB_LDR_DATA ldr_data;
    physical::read_process_memory(target_process, reinterpret_cast<uintptr_t>(peb.Ldr), &ldr_data,
                                  sizeof(PEB_LDR_DATA));

    PLIST_ENTRY current_entry = ldr_data.InMemoryOrderModuleList.Flink;
    PLIST_ENTRY first_entry = current_entry;
    uintptr_t base_va = 0;

    uintptr_t last_module_end = 0;
    int module_count = 0;

    do {
      LDR_DATA_TABLE_ENTRY entry;
      physical::read_process_memory(target_process,
                                    reinterpret_cast<uintptr_t>(CONTAINING_RECORD(
                                        current_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)),
                                    &entry, sizeof(LDR_DATA_TABLE_ENTRY));

      if (entry.DllBase && (entry.Flags & 0x00000004)) {
        uintptr_t current_module_start = reinterpret_cast<uintptr_t>(entry.DllBase);

        log("INFO", "module %d: base: 0x%llx, Size: 0x%llx", module_count++, current_module_start,
            entry.SizeOfImage);

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
      log("ERROR", "could not find suitable space between modules after checking %d modules",
          module_count);
      return nullptr;
    }

    log("INFO", "selected base address: 0x%llx", base_va);

    auto write_pt_status =
        mem::write_page_tables(target_dir_base, base_va, page_count, use_large_page);

    if (!NT_SUCCESS(write_pt_status)) {
      log("ERROR", "failed to write page tables");
      return nullptr;
    }

    return reinterpret_cast<void*>(base_va);
  }

  /**
   * @brief Allocate memory using unused PML4 entries for maximum stealth
   * @param local_pid Current process ID (unused)
   * @param target_pid Target process ID to inject into
   * @param size Size of memory region needed
   * @param use_large_page Whether to use 2MB pages
   * @param use_high_address Whether to use kernel-space (high) or user-space
   * (low) addresses
   * @return Virtual address in target process, or nullptr on failure
   *
   * Finds non-present PML4 entries and creates entirely new virtual address
   * spaces with base address entropy for maximum stealth.
   */
  auto allocate_at_non_present_pml4e(const uint32_t local_pid, const uint32_t target_pid,
                                     const size_t size, const bool use_large_page,
                                     const bool use_high_address) -> void* {
    const size_t STANDARD_PAGE_SIZE = 0x1000;
    const size_t LARGE_PAGE_SIZE = 0x200000;
    const size_t page_size = use_large_page ? LARGE_PAGE_SIZE : STANDARD_PAGE_SIZE;
    const size_t page_mask = page_size - 1;
    const size_t page_shift = use_large_page ? 21 : 12;

    const size_t aligned_size = (size + page_mask) & ~page_mask;
    const size_t page_count = aligned_size >> page_shift;

    PEPROCESS target_process = nullptr;
    if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(target_pid),
                                                 &target_process) != STATUS_SUCCESS) {
      log("ERROR", "failed to lookup target process");
      return nullptr;
    }

    // RAII will handle cleanup
    raii::process_ref process_ref(target_process, "EPROCESS");

    if (!validation::validate_process_state(target_process, target_pid)) {
      return nullptr;
    }

    if (!validation::acquire_process_rundown_protection(target_process, target_pid)) {
      return nullptr;
    }

    const auto target_dir_base = physical::get_process_directory_base(target_process);
    if (!target_dir_base) {
      log("ERROR", "failed to lookup target process directory base");
      return nullptr;
    }

    if (!validation::is_physical_address_valid(target_dir_base)) {
      validation::release_process_rundown_protection(target_process);
      auto dir_base_pfn = PAGE_TO_PFN(target_dir_base);
      log("ERROR", "directory base PFN 0x%llx outside valid range [0x%llx-0x%llx]", dir_base_pfn,
          globals::mm_lowest_physical_page, globals::mm_highest_physical_page);
      return nullptr;
    }

    uint32_t start_idx, end_idx;
    const char* space_type;
    page_table::get_pml4_search_range(use_high_address, &start_idx, &end_idx, &space_type);

    if (!validation::validate_index_range(start_idx, end_idx, "PML4")) {
      validation::release_process_rundown_protection(target_process);
      return nullptr;
    }

    auto selection = page_table::select_random_available_pml4(
        target_dir_base, start_idx, end_idx, (uintptr_t)target_process ^ target_pid);

    if (!selection.success) {
      validation::release_process_rundown_protection(target_process);
      log("ERROR", "failed to find any non-present PML4E in %s space", space_type);
      return nullptr;
    }

    uintptr_t base_va = page_table::construct_randomized_virtual_address(
        selection.selected_index, use_high_address, use_large_page);

    log("INFO", "selected base address: 0x%llx", base_va);

    auto write_pt_status =
        mem::write_page_tables(target_dir_base, base_va, page_count, use_large_page);
    if (!NT_SUCCESS(write_pt_status)) {
      validation::release_process_rundown_protection(target_process);
      log("ERROR", "failed to write page tables, NTSTATUS: 0x%08X", write_pt_status);
      return nullptr;
    }

    validation::release_process_rundown_protection(target_process);

    return reinterpret_cast<void*>(base_va);
  }

}  // namespace mem