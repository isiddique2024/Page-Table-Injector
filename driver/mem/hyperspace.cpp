#pragma once
#include "../def/globals.hpp"
#include "mem.hpp"
#include "phys.hpp"
#include "page_table.hpp"
#include "validation.hpp"
#include "pt_hook.hpp"
#include "../utils/raii.hpp"
namespace hyperspace {

  extern ntoskrnl_mapping_info g_ntoskrnl_copy_info = {0};
  extern pt_hook::hook_info g_pspexit_hook = {0};

  /**
   * @brief Hook handler for PspExitThread to restore process context on thread
   * exit
   * @param a1 Thread exit parameter
   * @return Result from original PspExitThread function
   *
   * Intercepts thread exits in hyperspace context and restores the original
   * process references before calling the original function to prevent crashes
   * and maintain stability.
   */
  __int64 __fastcall PspExitThread(unsigned int a1) {
    // get the original function from our hook info
    typedef __int64(__fastcall * PspExitThread_t)(unsigned int);
    auto original_func = reinterpret_cast<PspExitThread_t>(g_pspexit_hook.original_function);

    auto current_thread = KeGetCurrentThread();

    // check if this thread belongs to our hyperspace context
    PEPROCESS apcstate_process = *reinterpret_cast<PEPROCESS*>(
        reinterpret_cast<uintptr_t>(current_thread) + globals::_kthread_apcstate_pkprocess);

    PEPROCESS kthread_process = *reinterpret_cast<PEPROCESS*>(
        reinterpret_cast<uintptr_t>(current_thread) + globals::_kthread_pkprocess);

    if (apcstate_process != globals::ctx.orig_peproc &&
        kthread_process == globals::ctx.orig_peproc) {
      log("INFO", "PspExitThread called for hyperspace thread, restoring "
                  "original process");

      // restore the original process before exit
      InterlockedExchangePointer(
          reinterpret_cast<PVOID*>(reinterpret_cast<uintptr_t>(current_thread) +
                                   globals::_kthread_apcstate_pkprocess),
          globals::ctx.orig_peproc);

      InterlockedExchangePointer(
          reinterpret_cast<PVOID*>(reinterpret_cast<uintptr_t>(current_thread) +
                                   globals::_kthread_pkprocess),
          globals::ctx.orig_peproc);
    }

    // call the original function
    if (original_func) {
      return original_func(a1);
    }
  }

  /**
   * @brief Initialize page tracking system for ntoskrnl copy operations
   * @return true if initialization succeeded, false otherwise
   *
   * Allocates memory for tracking physical pages used in ntoskrnl copying.
   * Maintains an array of allocated page addresses for proper cleanup.
   */
  auto initialize_page_tracking() -> bool {
    g_ntoskrnl_copy_info.allocated_pages_capacity = 10240;
    g_ntoskrnl_copy_info.allocated_pages =
        reinterpret_cast<uintptr_t*>(mem::allocate_independent_pages(
            g_ntoskrnl_copy_info.allocated_pages_capacity * sizeof(uintptr_t)));

    if (!g_ntoskrnl_copy_info.allocated_pages) {
      log("ERROR", "failed to allocate page tracking array");
      return false;
    }

    g_ntoskrnl_copy_info.allocated_pages_count = 0;
    globals::memset(g_ntoskrnl_copy_info.allocated_pages, 0,
                    g_ntoskrnl_copy_info.allocated_pages_capacity * sizeof(uintptr_t));

    log("INFO", "initialized page tracking with capacity %zu",
        g_ntoskrnl_copy_info.allocated_pages_capacity);
    return true;
  }

  /**
   * @brief Add a virtual address to the page tracking array
   * @param va Virtual address of the allocated page
   * @return true if page was successfully tracked, false if array is full
   *
   * Records allocated pages for later cleanup. Essential for preventing memory
   * leaks when tearing down the hyperspace context.
   */
  auto add_tracked_page(uintptr_t va) -> bool {
    if (g_ntoskrnl_copy_info.allocated_pages_count >=
        g_ntoskrnl_copy_info.allocated_pages_capacity) {
      log("ERROR", "page tracking array full");
      return false;
    }

    long index = InterlockedIncrement(&g_ntoskrnl_copy_info.allocated_pages_count) - 1;
    if (index >= g_ntoskrnl_copy_info.allocated_pages_capacity) {
      InterlockedDecrement(&g_ntoskrnl_copy_info.allocated_pages_count);
      return false;
    }

    InterlockedExchangePointer(
        reinterpret_cast<void**>(&g_ntoskrnl_copy_info.allocated_pages[index]),
        reinterpret_cast<void*>(va));

    return true;
  }

  /**
   * @brief Locate ntoskrnl.exe in the loaded module list
   * @param base Output parameter for ntoskrnl base address
   * @param size Output parameter for ntoskrnl image size
   * @return true if ntoskrnl was found, false otherwise
   *
   * Searches PsLoadedModuleList to find the kernel image and retrieve its
   * base address and size for copying operations.
   */
  auto find_ntoskrnl_info(uintptr_t* base, uintptr_t* size) -> bool {
    PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(globals::ps_loaded_module_list);
    if (!module_list) {
      log("ERROR", "PsLoadedModuleList not found");
      return false;
    }

    for (PLIST_ENTRY entry = module_list->Flink; entry != module_list; entry = entry->Flink) {
      PKLDR_DATA_TABLE_ENTRY ldr_entry =
          CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

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

  /**
   * @brief Allocate and track a single physical page with hiding applied
   * @return Physical address of allocated page, or 0 on failure
   *
   * Combines page allocation, zeroing, physical address translation, and tracking
   * into a single operation for use in page table construction.
   */
  auto allocate_tracked_physical_page() -> uintptr_t {
    void* va = mem::allocate_independent_pages(PAGE_SIZE);
    if (!va) {
      log("ERROR", "failed to allocate physical page");
      return 0;
    }

    uintptr_t pa = page_table::virtual_to_physical(va).QuadPart;
    if (!pa) {
      log("ERROR", "failed to get physical address");
      return 0;
    }

    // track the allocation
    if (!add_tracked_page(reinterpret_cast<uintptr_t>(va))) {
      log("ERROR", "failed to track allocated page");
      return 0;
    }

    log("INFO", "allocated tracked physical page: PA=0x%llx, VA=0x%llx", pa,
        reinterpret_cast<uintptr_t>(va));
    return pa;
  }

  /**
   * @brief Copy ntoskrnl image to new physical pages using 4KB page granularity
   * @param src_base Source virtual address of ntoskrnl
   * @param size Size of ntoskrnl image in bytes
   * @param dest_pd_pa Physical address of destination page directory
   * @return true if copying succeeded, false otherwise
   *
   * Creates a complete physical copy of the kernel image using individual 4KB
   * pages with proper hiding techniques applied to each page.
   */
  auto copy_ntoskrnl_pages(uintptr_t src_base, uintptr_t size, uintptr_t dest_pd_pa) -> bool {
    log("INFO", "copying ntoskrnl as 4KB pages");

    size_t page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t page_pas_size = page_count * sizeof(uintptr_t);

    // use RAII for page_pas array
    raii::kernel_memory page_pas_mem(page_pas_size);
    if (!page_pas_mem.is_valid()) {
      log("ERROR", "failed to allocate page_pas array");
      return false;
    }

    uintptr_t* page_pas = reinterpret_cast<uintptr_t*>(page_pas_mem.get());

    for (size_t i = 0; i < page_count; i++) {
      uintptr_t src_va = src_base + (i * PAGE_SIZE);

      uintptr_t dest_pa = allocate_tracked_physical_page();
      if (!dest_pa) {
        log("ERROR", "failed to allocate page %zu", i);
        return false;
      }

      page_pas[i] = dest_pa;

      // use RAII for temporary buffer
      raii::kernel_memory temp_buffer(PAGE_SIZE);
      if (!temp_buffer.is_valid()) {
        log("ERROR", "failed to allocate temp buffer for page %zu", i);
        return false;
      }

      globals::memcpy(temp_buffer.get(), reinterpret_cast<void*>(src_va), PAGE_SIZE);

      NTSTATUS write_status =
          physical::write_physical_address(dest_pa, temp_buffer.get(), PAGE_SIZE);

      if (!NT_SUCCESS(write_status)) {
        log("ERROR", "failed to write to physical page 0x%llx", dest_pa);
        return false;
      }

      if (i % 100 == 0) {
        log("INFO", "copied page %zu from 0x%llx to PA 0x%llx", i, src_va, dest_pa);
      }
    }

    log("SUCCESS", "copied all %zu pages", page_count);
    return true;
  }

  /**
   * @brief Create page table hierarchy for ntoskrnl mapping in hyperspace
   * @param hyperspace_pml4_pa Physical address of hyperspace PML4
   * @param info Pointer to mapping information structure
   * @return true if page tables were created successfully, false otherwise
   *
   * Constructs PML4E->PDPTE->PDE hierarchy needed to map the copied ntoskrnl
   * at the same virtual address in hyperspace context.
   */
  auto create_ntoskrnl_page_tables(uintptr_t hyperspace_pml4_pa, ntoskrnl_mapping_info* info)
      -> bool {
    // parse virtual address indices
    info->pml4_index = (info->hyperspace_base >> 39) & 0x1FF;
    info->pdpt_index = (info->hyperspace_base >> 30) & 0x1FF;
    info->pd_index = (info->hyperspace_base >> 21) & 0x1FF;

    log("INFO", "creating page tables: PML4[%u] -> PDPT[%u] -> PD[%u]", info->pml4_index,
        info->pdpt_index, info->pd_index);

    // check if PML4E exists
    PML4E_64 pml4e = {0};
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
      pml4e.PageFrameNumber = PAGE_TO_PFN(pdpt_pa);

      if (!NT_SUCCESS(physical::write_physical_address(pml4e_pa, &pml4e, sizeof(pml4e)))) {
        log("ERROR", "failed to write PML4E");
        return false;
      }

      info->new_pdpt_pa = pdpt_pa;
      log("INFO", "created new PDPT at PA 0x%llx", pdpt_pa);
    } else {
      pdpt_pa = PFN_TO_PAGE(pml4e.PageFrameNumber);
      log("INFO", "using existing PDPT at PA 0x%llx", pdpt_pa);
    }

    // check if PDPTE exists
    PDPTE_64 pdpte = {0};
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
      pdpte.PageFrameNumber = PAGE_TO_PFN(pd_pa);

      if (!NT_SUCCESS(physical::write_physical_address(pdpte_pa, &pdpte, sizeof(pdpte)))) {
        log("ERROR", "failed to write PDPTE");
        return false;
      }

      info->new_pd_pa = pd_pa;
      log("INFO", "created new PD at PA 0x%llx", pd_pa);
    } else {
      pd_pa = PFN_TO_PAGE(pdpte.PageFrameNumber);
      log("INFO", "using existing PD at PA 0x%llx", pd_pa);
    }

    return true;
  }

  /**
   * @brief Map copied ntoskrnl pages into the hyperspace page tables
   * @param info Pointer to mapping information structure
   * @return true if mapping succeeded, false otherwise
   *
   * Creates PTEs pointing to the copied physical pages and constructs
   * complete virtual memory mapping for the ntoskrnl copy.
   */
  auto map_ntoskrnl_pages(ntoskrnl_mapping_info* info) -> bool {
    size_t total_pages = (info->original_size + PAGE_SIZE - 1) / PAGE_SIZE;

    log("INFO", "mapping %zu pages starting at PD index %u", total_pages, info->pd_index);

    // get list of allocated physical pages for ntoskrnl copy
    size_t allocated_page_idx = 0;

    for (size_t i = 0; i < total_pages; i++) {
      uint32_t current_pd_idx = info->pd_index + (i / 512);  // PD index (each PD covers 512 pages)
      uint32_t pt_idx = i % 512;                             // PT index within the PD

      if (pt_idx == 0) {
        // need new PT for this PD entry
        uintptr_t pt_pa = allocate_tracked_physical_page();
        if (!pt_pa) {
          log("ERROR", "failed to allocate PT for PD[%u]", current_pd_idx);
          return false;
        }

        // create PDE pointing to new PT
        PDE_64 pde = {0};
        pde.Present = 1;
        pde.Write = 1;
        pde.Supervisor = 0;
        pde.PageFrameNumber = PAGE_TO_PFN(pt_pa);

        uintptr_t pde_pa = info->new_pd_pa + current_pd_idx * 8;
        if (!NT_SUCCESS(physical::write_physical_address(pde_pa, &pde, sizeof(pde), true))) {
          log("ERROR", "failed to write PDE[%u] for physical address: 0x%llx", current_pd_idx,
              pde_pa);
          return false;
        }

        log("INFO", "created PT at PA 0x%llx for PD[%u]", pt_pa, current_pd_idx);
      }

      // read the PT physical address from PDE
      PDE_64 pde = {0};
      uintptr_t pde_pa = info->new_pd_pa + current_pd_idx * 8;
      if (!NT_SUCCESS(physical::read_physical_address(pde_pa, &pde, sizeof(pde), true))) {
        log("ERROR", "failed to read PDE[%u]", current_pd_idx);
        return false;
      }

      uintptr_t pt_pa = PFN_TO_PAGE(pde.PageFrameNumber);

      // create PTE pointing to copied ntoskrnl page
      // use the allocated pages in order (skip the page table pages)
      while (allocated_page_idx < g_ntoskrnl_copy_info.allocated_pages_count) {
        uintptr_t va = g_ntoskrnl_copy_info.allocated_pages[allocated_page_idx];
        uintptr_t pa = page_table::virtual_to_physical(reinterpret_cast<void*>(va)).QuadPart;

        // check if this is a page table page (allocated for PT/PD/PDPT)
        bool is_page_table = (pa == info->new_pdpt_pa || pa == info->new_pd_pa);

        // check if it's any of the PT pages we allocated
        for (size_t j = 0; j < total_pages; j += 512) {
          uint32_t check_pd_idx = info->pd_index + (j / 512);
          PDE_64 check_pde = {0};
          uintptr_t check_pde_pa = info->new_pd_pa + check_pd_idx * 8;
          if (NT_SUCCESS(physical::read_physical_address(check_pde_pa, &check_pde,
                                                         sizeof(check_pde), true))) {
            if (check_pde.Present && (check_pde.PageFrameNumber << 12) == pa) {
              is_page_table = true;
              break;
            }
          }
        }

        allocated_page_idx++;
        if (!is_page_table) {
          // this is a data page, use it
          PTE_64 pte = {0};
          pte.Present = 1;
          pte.Write = 1;
          pte.Supervisor = 0;
          pte.Global = 1;
          pte.ExecuteDisable = 0;  // allow execution
          pte.PageFrameNumber = PAGE_TO_PFN(pa);

          uintptr_t pte_pa = pt_pa + pt_idx * 8;
          if (!NT_SUCCESS(physical::write_physical_address(pte_pa, &pte, sizeof(pte), true))) {
            log("ERROR", "failed to write PTE[%u][%u]", current_pd_idx, pt_idx);
            return false;
          }

          break;
        }
      }
    }

    // flush caches/TLB
    page_table::flush_caches(reinterpret_cast<void*>(g_ntoskrnl_copy_info.hyperspace_base));
    page_table::flush_tlb();

    log("SUCCESS", "mapped all ntoskrnl pages");

    return true;
  }

  /**
   * @brief Install kernel function hooks within the hyperspace ntoskrnl copy
   * @return NTSTATUS indicating success or failure
   *
   * Applies function hooks to the copied kernel image in hyperspace context,
   * allowing for kernel-level interception without affecting the original kernel.
   */
  auto install_kernel_hooks_in_hyperspace() -> NTSTATUS {
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
        globals::ctx.hyperspace_pml4_pa, hyperspace_pspexit,
        reinterpret_cast<uintptr_t>(hyperspace::PspExitThread), &g_pspexit_hook);

    if (!hook_result) {
      log("ERROR", "failed to install PspExitThread hook");
      return STATUS_UNSUCCESSFUL;
    }

    page_table::flush_caches(reinterpret_cast<void*>(g_ntoskrnl_copy_info.hyperspace_base));
    page_table::flush_tlb();

    return STATUS_SUCCESS;
  }

  /**
   * @brief Create a complete contextualized copy of ntoskrnl in hyperspace
   * @return NTSTATUS indicating success or failure
   *
   * Master function that orchestrates the entire process of copying ntoskrnl
   * into hyperspace with proper page tables, mapping, and hook installation.
   */
  auto create_contextualized_ntoskrnl() -> NTSTATUS {
    if (!globals::ctx.initialized) {
      log("ERROR", "hyperspace context not initialized");
      return STATUS_UNSUCCESSFUL;
    }

    // init page tracking
    if (!initialize_page_tracking()) {
      return STATUS_UNSUCCESSFUL;
    }

    // find ntoskrnl info
    if (!find_ntoskrnl_info(&g_ntoskrnl_copy_info.original_base,
                            &g_ntoskrnl_copy_info.original_size)) {
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
    if (!copy_ntoskrnl_pages(g_ntoskrnl_copy_info.original_base, g_ntoskrnl_copy_info.original_size,
                             g_ntoskrnl_copy_info.new_pd_pa)) {
      log("ERROR", "failed to copy ntoskrnl pages");
      return STATUS_UNSUCCESSFUL;
    }

    // map the copied pages
    if (!map_ntoskrnl_pages(&g_ntoskrnl_copy_info)) {
      log("ERROR", "failed to map ntoskrnl pages");
      return STATUS_UNSUCCESSFUL;
    }

    log("SUCCESS", "created contextualized copy of ntoskrnl in hyperspace at 0x%llx",
        g_ntoskrnl_copy_info.hyperspace_base);

    // install kernel hooks in hyperspace ctx
    NTSTATUS install_kernel_hooks_status = install_kernel_hooks_in_hyperspace();
    if (!NT_SUCCESS(install_kernel_hooks_status)) {
      log("WARNING", "failed to install kernel hooks in hyperspace context: 0x%x",
          install_kernel_hooks_status);
      return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
  }

  /**
   * @brief Clean up and free all resources used by the ntoskrnl copy
   *
   * Releases all tracked pages, page table structures, and associated memory
   * allocated during ntoskrnl copying operations.
   */
  auto cleanup_contextualized_ntoskrnl() -> void {
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

    page_table::flush_tlb();

    log("INFO", "cleaned up ntoskrnl deep copy");
  }

  /**
   * @brief Initialize list entries in cloned EPROCESS to prevent crashes
   * @param clone_eproc Pointer to the cloned EPROCESS structure
   *
   * Sets up empty list heads and clears problematic fields to ensure the
   * cloned process structure doesn't cause system instability.
   */
  auto initialize_cloned_eprocess_lists(PEPROCESS clone_eproc) -> void {
    // init _EPROCESS.ThreadListHead
    PLIST_ENTRY thread_list_head = reinterpret_cast<PLIST_ENTRY>(
        reinterpret_cast<uintptr_t>(clone_eproc) + globals::_eprocess_thread_list_head);
    InitializeListHead(thread_list_head);

    // init _KPROCESS.ThreadListHead
    PLIST_ENTRY kprocess_thread_list = reinterpret_cast<PLIST_ENTRY>(
        reinterpret_cast<uintptr_t>(clone_eproc) + globals::_kprocess_thread_list_head);
    InitializeListHead(kprocess_thread_list);

    // clear _EPROCESS.RundownProtect
    _EX_RUNDOWN_REF* rundown_ref = reinterpret_cast<_EX_RUNDOWN_REF*>(
        reinterpret_cast<uintptr_t>(clone_eproc) + globals::_eprocess_rundown_protect);

    InterlockedExchange64(reinterpret_cast<LONG64*>(&rundown_ref->Count), 0);
    InterlockedExchangePointer(reinterpret_cast<PVOID*>(&rundown_ref->Ptr), nullptr);

    // clear AccessLog to prevent MiEmptyPageAccessLog BSOD
    InterlockedExchangePointer(reinterpret_cast<PVOID*>(reinterpret_cast<uintptr_t>(clone_eproc) +
                                                        globals::_eprocess_vm + 0xE8),
                               nullptr);

    // set VadTrackingDisabled bit on hyperspace process
    ULONG* flags3_ptr_hyperspace = reinterpret_cast<ULONG*>(
        reinterpret_cast<uintptr_t>(clone_eproc) + globals::_eprocess_flags3);
    InterlockedOr(reinterpret_cast<LONG*>(flags3_ptr_hyperspace),
                  0x10);  // set bit 4

    // set VadTrackingDisabled bit on original process
    ULONG* flags3_ptr_og = reinterpret_cast<ULONG*>(
        reinterpret_cast<uintptr_t>(globals::ctx.orig_peproc) + globals::_eprocess_flags3);
    InterlockedOr(reinterpret_cast<LONG*>(flags3_ptr_og), 0x10);  // set bit 4

    _mm_mfence();

    log("INFO", "initialized list entries in cloned EPROCESS");
  }

  /**
   * @brief Locate PML4 self-reference entry in the original page table
   * @param cr3_pa Physical address of the original CR3/PML4
   * @return Structure containing self-reference entry information
   *
   * Finds the PML4 entry that points back to itself, which is used by
   * the system for recursive page table access.
   */
  auto find_pml4_self_reference_entry(uintptr_t cr3_pa) -> self_reference_entry_info {
    self_reference_entry_info info = {0, false, {0}};
    uintptr_t cr3_pfn = PAGE_TO_PFN(cr3_pa);

    log("INFO", "searching for PML4 self-reference entry (CR3 PFN: 0x%llx)", cr3_pfn);

    // check all PML4 entries (0-511)
    for (uint32_t idx = 0; idx < 512; idx++) {
      PML4E_64 pml4e = {0};
      if (NT_SUCCESS(physical::read_physical_address(cr3_pa + idx * sizeof(PML4E_64), &pml4e,
                                                     sizeof(PML4E_64)))) {
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

  /**
   * @brief Update self-reference entry in cloned PML4 to point to new PML4
   * @param cloned_pml4_va Virtual address of cloned PML4
   * @param cloned_pml4_pa Physical address of cloned PML4
   * @param self_reference_info Information about the self-reference entry
   * @return true if update succeeded, false otherwise
   *
   * Modifies the self-reference entry to maintain proper recursive page table
   * access in the hyperspace context.
   */
  auto update_cloned_self_reference_entry(uintptr_t cloned_pml4_va, uintptr_t cloned_pml4_pa,
                                          self_reference_entry_info self_reference_info) -> bool {
    if (!self_reference_info.found) {
      log("INFO", "no self-reference entry to update in cloned PML4");
      return true;
    }

    // calc the address of the self-reference entry in the cloned PML4
    uintptr_t self_reference_entry_va =
        cloned_pml4_va + (self_reference_info.index * sizeof(PML4E_64));

    // create new self-reference entry pointing to the cloned PML4's physical
    // address
    PML4E_64 new_self_reference_entry = self_reference_info.original_entry;
    new_self_reference_entry.PageFrameNumber = PAGE_TO_PFN(cloned_pml4_pa);

    // write the updated self-reference entry to the cloned PML4
    globals::memcpy(reinterpret_cast<void*>(self_reference_entry_va), &new_self_reference_entry,
                    sizeof(PML4E_64));

    log("SUCCESS",
        "updated self-reference entry at index %u to point to cloned PML4 (PFN: "
        "0x%llx)",
        self_reference_info.index, new_self_reference_entry.PageFrameNumber);

    return true;
  }

  /**
   * @brief Copy page tables with proper self-reference entry handling
   * @param dest_pml4_va Virtual address of destination PML4
   * @param src_pml4_pa Physical address of source PML4
   * @param dest_pml4_pa Physical address of destination PML4
   * @param self_reference_info Output parameter for self-reference information
   * @return true if copying succeeded, false otherwise
   *
   * Performs a complete PML4 copy while properly handling and updating
   * the self-reference entry for the new context.
   */
  auto copy_page_tables_with_self_reference_entry(uintptr_t dest_pml4_va, uintptr_t src_pml4_pa,
                                                  uintptr_t dest_pml4_pa,
                                                  self_reference_entry_info* self_reference_info)
      -> bool {
    // use RAII for temporary buffer
    raii::kernel_memory temp_buffer(PAGE_SIZE);
    if (!temp_buffer.is_valid()) {
      log("ERROR", "failed to allocate temp buffer for PML4 copy");
      return false;
    }

    *self_reference_info = find_pml4_self_reference_entry(src_pml4_pa);

    if (!NT_SUCCESS(physical::read_physical_address(src_pml4_pa, temp_buffer.get(), PAGE_SIZE))) {
      log("ERROR", "failed to read original PML4");
      return false;
    }

    globals::memcpy(reinterpret_cast<void*>(dest_pml4_va), temp_buffer.get(), PAGE_SIZE);

    if (!update_cloned_self_reference_entry(dest_pml4_va, dest_pml4_pa, *self_reference_info)) {
      log("ERROR", "failed to update self-reference entry in cloned PML4");
      return false;
    }

    return true;
  }

  /**
   * @brief Initialize complete hyperspace context with cloned page tables
   * @param target_pid Process ID to create hyperspace context for
   * @param ctx Pointer to hyperspace context structure
   * @return NTSTATUS indicating success or failure
   *
   * Master initialization function that creates a complete hyperspace context
   * including cloned PML4, EPROCESS, and all necessary supporting structures.
   */
  auto initialize_hyperspace_context(uint32_t target_pid, hyperspace_ctx* ctx) -> NTSTATUS {
    if (!ctx) {
      log("ERROR", "invalid hyperspace context");
      return STATUS_UNSUCCESSFUL;
    }

    PEPROCESS target_process = nullptr;
    if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(target_pid),
                                                 &target_process) != STATUS_SUCCESS) {
      log("ERROR", "failed to lookup target process for hyperspace");
      return STATUS_UNSUCCESSFUL;
    }

    // use RAII but we need to release ownership since ctx will hold the reference
    raii::process_ref process_ref(target_process, "EPROCESS");

    ctx->orig_peproc = target_process;

    ctx->orig_pml4_pa = physical::get_process_directory_base(target_process);
    if (!ctx->orig_pml4_pa) {
      log("ERROR", "failed to get target process directory base");
      return STATUS_UNSUCCESSFUL;
    }

    // release ownership since ctx now owns the reference
    process_ref.release();

    log("INFO", "original PML4 PA: 0x%llx", ctx->orig_pml4_pa);

    ctx->hyperspace_pml4_va =
        reinterpret_cast<uintptr_t>(mem::allocate_independent_pages(PAGE_SIZE));
    if (!ctx->hyperspace_pml4_va) {
      log("ERROR", "failed to allocate hyperspace PML4");
      globals::obf_dereference_object(target_process);
      return STATUS_UNSUCCESSFUL;
    }

    ctx->hyperspace_pml4_pa =
        page_table::virtual_to_physical(reinterpret_cast<void*>(ctx->hyperspace_pml4_va)).QuadPart;
    if (!ctx->hyperspace_pml4_pa) {
      log("ERROR", "failed to get physical address of hyperspace PML4");
      globals::obf_dereference_object(target_process);
      return STATUS_UNSUCCESSFUL;
    }

    log("INFO", "hyperspace PML4 VA: 0x%llx, PA: 0x%llx", ctx->hyperspace_pml4_va,
        ctx->hyperspace_pml4_pa);

    self_reference_entry_info self_reference_info;
    if (!copy_page_tables_with_self_reference_entry(ctx->hyperspace_pml4_va, ctx->orig_pml4_pa,
                                                    ctx->hyperspace_pml4_pa,
                                                    &self_reference_info)) {
      log("ERROR", "failed to copy page tables with self-reference entry");
      globals::obf_dereference_object(target_process);
      return STATUS_UNSUCCESSFUL;
    }

    ctx->self_reference_entry_index = self_reference_info.index;
    ctx->has_self_reference_entry = self_reference_info.found;

    log("SUCCESS", "created hyperspace PML4 with %s self-reference entry",
        self_reference_info.found ? "updated" : "no");

    ctx->clone_peproc_page_base =
        reinterpret_cast<uintptr_t>(mem::allocate_independent_pages(PAGE_SIZE));

    if (!ctx->clone_peproc_page_base) {
      log("ERROR", "failed to allocate clone PEPROCESS");
      globals::obf_dereference_object(target_process);
      return STATUS_UNSUCCESSFUL;
    }

    const auto orig_peproc_page = (reinterpret_cast<uintptr_t>(ctx->orig_peproc) >> 12) << 12;
    const auto clone_peproc_offset = reinterpret_cast<uintptr_t>(ctx->orig_peproc) & 0xFFF;

    globals::memcpy(reinterpret_cast<void*>(ctx->clone_peproc_page_base),
                    reinterpret_cast<void*>(orig_peproc_page), PAGE_SIZE);

    ctx->clone_peproc =
        reinterpret_cast<PEPROCESS>(ctx->clone_peproc_page_base + clone_peproc_offset);

    initialize_cloned_eprocess_lists(ctx->clone_peproc);

    const auto dirbase_ptr = reinterpret_cast<uintptr_t*>(
        reinterpret_cast<uintptr_t>(ctx->clone_peproc) + globals::_kprocess_dirbase);

    *dirbase_ptr = ctx->hyperspace_pml4_pa;

    ctx->target_pid = target_pid;

    InterlockedExchange(reinterpret_cast<LONG*>(&ctx->initialized), TRUE);

    return STATUS_SUCCESS;
  }

  /**
   * @brief Allocate memory within hyperspace context using unused PML4 entries
   * @param target_pid Target process ID (unused in current implementation)
   * @param size Size of memory to allocate
   * @param mem_type Whether to use 4KB, 2MB or 1GB pages
   * @return Virtual address of allocated memory, or nullptr on failure
   *
   * Allocates memory within the hyperspace context using the same stealth
   * techniques as regular allocation but within the isolated address space.
   */
  auto allocate_in_hyperspace(uint32_t target_pid, size_t size, memory_type mem_type) -> void* {
    const size_t STANDARD_PAGE_SIZE = 0x1000;  // 4KB
    const size_t LARGE_PAGE_SIZE = 0x200000;   // 2MB
    const size_t HUGE_PAGE_SIZE = 0x40000000;  // 1GB

    const size_t page_size = (mem_type == memory_type::HUGE_PAGE)    ? HUGE_PAGE_SIZE
                             : (mem_type == memory_type::LARGE_PAGE) ? LARGE_PAGE_SIZE
                                                                     : STANDARD_PAGE_SIZE;
    const size_t page_mask = page_size - 1;
    const size_t page_shift = (mem_type == memory_type::HUGE_PAGE)    ? 30
                              : (mem_type == memory_type::LARGE_PAGE) ? 21
                                                                      : 12;

    const size_t aligned_size = (size + page_mask) & ~page_mask;
    const size_t page_count = aligned_size >> page_shift;

    PEPROCESS target_process = globals::ctx.clone_peproc;

    // get target process directory base
    const auto target_dir_base = physical::get_process_directory_base(target_process);
    if (!target_dir_base) {
      log("ERROR", "failed to lookup target process directory base");
      return nullptr;
    }

    uint32_t start_idx, end_idx;
    const char* space_type;
    page_table::get_pml4_search_range(false, &start_idx, &end_idx, &space_type);

    // validate index ranges
    if (!validation::validate_index_range(start_idx, end_idx, "PML4")) {
      validation::release_process_rundown_protection(target_process);
      globals::obf_dereference_object(target_process);
      return nullptr;
    }

    // select random available PML4 index
    auto selection = page_table::select_random_available_pml4(
        target_dir_base, start_idx, end_idx, (uintptr_t)target_process ^ target_pid);

    if (!selection.success) {
      validation::release_process_rundown_protection(target_process);
      globals::obf_dereference_object(target_process);
      log("ERROR", "failed to find any non-present PML4E in %s space", space_type);
      return nullptr;
    }

    // construct randomized virtual address
    uintptr_t base_va = page_table::construct_randomized_virtual_address(
        selection.selected_index, memory_space::USER_MODE, mem_type);

    log("INFO", "selected base address: 0x%llx for %s pages", base_va,
        mem_type == memory_type::HUGE_PAGE    ? "1GB"
        : mem_type == memory_type::LARGE_PAGE ? "2MB"
                                              : "4KB");

    auto write_pt_status = mem::write_page_tables(target_dir_base, base_va, page_count, mem_type);
    if (!NT_SUCCESS(write_pt_status)) {
      validation::release_process_rundown_protection(target_process);
      globals::obf_dereference_object(target_process);
      log("ERROR", "failed to write page tables, NTSTATUS: 0x%08X", write_pt_status);
      return nullptr;
    }

    log("SUCCESS", "allocated memory in hyperspace at 0x%llx", base_va);
    return reinterpret_cast<void*>(base_va);
  }

  /**
   * @brief Switch a thread's execution context to hyperspace
   * @param tid Thread ID to switch
   * @param ctx Pointer to hyperspace context
   * @return NTSTATUS indicating success or failure
   *
   * Modifies thread's ApcState.Process to point to the cloned EPROCESS,
   * effectively switching the thread to execute within hyperspace context.
   */
  auto switch_thread_context_to_hyperspace(uint32_t tid, hyperspace_ctx* ctx) -> NTSTATUS {
    if (InterlockedCompareExchange(reinterpret_cast<LONG*>(&ctx->initialized), FALSE, TRUE) !=
        TRUE) {
      log("ERROR", "invalid or uninitialized hyperspace context");
      return STATUS_UNSUCCESSFUL;
    }

    PETHREAD target_thread = nullptr;
    if (globals::ps_lookup_thread_by_thread_id(reinterpret_cast<HANDLE>(tid), &target_thread) !=
        STATUS_SUCCESS) {
      log("ERROR", "failed to lookup target thread");
      return STATUS_UNSUCCESSFUL;
    }

    // use RAII for thread reference
    raii::thread_ref thread_ref(target_thread, "ETHREAD");

    PEPROCESS* apc_process_ptr = reinterpret_cast<PEPROCESS*>(
        reinterpret_cast<uintptr_t>(target_thread) + globals::_kthread_apcstate_pkprocess);

    InterlockedExchangePointer(reinterpret_cast<PVOID*>(apc_process_ptr), ctx->clone_peproc);

    log("SUCCESS", "thread %d switched to hyperspace", tid);
    return STATUS_SUCCESS;
  }

  /**
   * @brief Switch thread back from hyperspace to original context
   * @param tid Thread ID to switch back
   * @param ctx Pointer to hyperspace context
   * @return true if switch succeeded, false otherwise
   *
   * Restores thread's original process context, returning it to normal
   * execution environment.
   */
  auto switch_from_hyperspace(uint32_t tid, hyperspace_ctx* ctx) -> bool {
    if (InterlockedCompareExchange(reinterpret_cast<LONG*>(&ctx->initialized), FALSE, TRUE) !=
        TRUE) {
      log("ERROR", "invalid or uninitialized hyperspace context");
      return false;
    }

    PETHREAD target_thread = nullptr;
    if (globals::ps_lookup_thread_by_thread_id(reinterpret_cast<HANDLE>(tid), &target_thread) !=
        STATUS_SUCCESS) {
      log("ERROR", "failed to lookup target thread");
      return false;
    }

    // use RAII for thread reference
    raii::thread_ref thread_ref(target_thread, "ETHREAD");

    PEPROCESS* apc_process_ptr = reinterpret_cast<PEPROCESS*>(
        reinterpret_cast<uintptr_t>(target_thread) + globals::_kthread_apcstate_pkprocess);

    InterlockedExchangePointer(reinterpret_cast<PVOID*>(apc_process_ptr), ctx->orig_peproc);

    log("INFO", "thread %d switched back from hyperspace", tid);
    return true;
  }

  /**
   * @brief Clean up hyperspace context and free all associated resources
   * @param ctx Pointer to hyperspace context to clean up
   *
   * Comprehensive cleanup function that releases PML4, EPROCESS clone,
   * and all other resources associated with the hyperspace context.
   */
  auto cleanup_hyperspace_context(hyperspace_ctx* ctx) -> void {
    if (InterlockedCompareExchange(reinterpret_cast<LONG*>(&ctx->initialized), FALSE, TRUE) !=
        TRUE) {
      log("ERROR", "invalid or uninitialized hyperspace context");
      return;
    }

    log("INFO", "cleaning up hyperspace context");

    // free hyperspace PML4 page
    if (ctx->hyperspace_pml4_va) {
      globals::mm_free_independent_pages(ctx->hyperspace_pml4_va, PAGE_SIZE);
      log("INFO", "freed hyperspace PML4 page");
    }

    // free cloned EPROCESS page
    // (causes bsod after a few seconds, this might be because the page is
    // automatically free'd once the process exits and another process ends up
    // using the pfn instead)
    if (ctx->clone_peproc_page_base) {
      globals::mm_free_independent_pages(ctx->clone_peproc_page_base, PAGE_SIZE);
    }

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

    extern void* g_callback_shellcode_address = nullptr;
    extern void* g_process_callback_handle = nullptr;

    /**
     * @brief Process notification callback implementation for cleanup on exit
     * @param ParentId Parent process ID
     * @param ProcessId Process ID that created/terminated
     * @param Create TRUE for process creation, FALSE for termination
     *
     * Handles process termination events to trigger automatic cleanup
     * of hyperspace resources when the target process exits.
     */
    auto process_notify_callback_impl(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) -> void {
      if (InterlockedCompareExchange(reinterpret_cast<LONG*>(&globals::ctx.initialized), FALSE,
                                     TRUE) != TRUE) {
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

      log("INFO", "target process %d terminating - cleaning up hyperspace",
          HandleToUlong(ProcessId));

      // cleanup hyperspace context when target process exits
      cleanup_hyperspace_context(&globals::ctx);

      // clean up contextualized ntoskrnl copy in hyperspace ctx
      cleanup_contextualized_ntoskrnl();

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

    /**
     * @brief Find a legitimate driver suitable for hosting callback shellcode
     * @param out_size Output parameter for driver size
     * @return Base address of suitable driver, or nullptr if none found
     *
     * Locates a legitimate system driver with proper flags for hosting
     * callback functions, avoiding detection by security software.
     */
    auto find_legitimate_driver_for_callbacks(PULONG out_size) -> void* {
      // common legitimate drivers that typically have proper flags for callbacks
      const wchar_t* legitimate_drivers[] = {L"classpnp.sys", L"disk.sys", L"volmgr.sys",
                                             L"partmgr.sys"};

      PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(globals::ps_loaded_module_list);
      if (!module_list) {
        log("ERROR", "PsLoadedModuleList not found");
        return nullptr;
      }

      for (PLIST_ENTRY entry = module_list->Flink; entry != module_list; entry = entry->Flink) {
        PKLDR_DATA_TABLE_ENTRY ldr_entry =
            CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

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
        PKLDR_DATA_TABLE_ENTRY ldr_entry =
            CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

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

    /**
     * @brief Install process notification callback for automatic cleanup
     * @return NTSTATUS indicating success or failure
     *
     * Registers a process notification callback using shellcode placed in
     * a legitimate driver to trigger cleanup when the target process exits.
     */
    auto install_process_callback() -> NTSTATUS {
      if (InterlockedCompareExchangePointer(&g_callback_shellcode_address, nullptr, nullptr) !=
          nullptr) {
        return STATUS_SUCCESS;  // already installed
      }

      // find a legitimate driver to host the callback
      ULONG driver_size = 0;
      void* driver_base = find_legitimate_driver_for_callbacks(&driver_size);
      if (!driver_base) {
        log("ERROR", "failed to find legitimate driver for process callback");
        return STATUS_UNSUCCESSFUL;
      }

      // create shellcode that calls callback function
      uint8_t shellcode[12] = {
          0x48, 0xB8,  // mov rax, imm64
          0x00, 0x00, 0x00,
          0x00,  // placeholder for lower 32 bits of process_notify_callback_impl
          0x00, 0x00, 0x00,
          0x00,  // placeholder for upper 32 bits of process_notify_callback_impl
          0x50,  // push rax
          0xC3   // ret
      };

      // try and find .data section in the driver
      uint32_t section_size = 0;
      auto section_base = page_table::find_section_base(driver_base, &section_size, ".data", 5);
      if (!section_base) {
        return STATUS_UNSUCCESSFUL;
      }

      // find unused space for callback shellcode
      void* target_address =
          page_table::find_unused_space(section_base, section_size, globals::SHELL_SIZE);
      if (!target_address) {
        log("ERROR", "failed to find unused space for process callback shellcode "
                     "in legitimate driver");
        return STATUS_UNSUCCESSFUL;
      }

      // assign callback function pointer to shellcode
      *reinterpret_cast<uintptr_t*>(&shellcode[2]) =
          reinterpret_cast<uintptr_t>(process_notify_callback_impl);

      // write shellcode to legitimate driver section
      globals::memcpy(target_address, shellcode, globals::SHELL_SIZE);

      log("INFO", "process callback shellcode written at addr: 0x%p in legitimate driver",
          target_address);

      // spoof PTE to make the target address executable
      if (!page_table::spoof_pte_range(reinterpret_cast<uintptr_t>(target_address),
                                       globals::SHELL_SIZE, false)) {
        log("ERROR", "failed to spoof pte range for process callback");
        return STATUS_UNSUCCESSFUL;
      }

      // register the process callback using legit shellcode address
      NTSTATUS status = globals::ps_set_create_process_notify_routine_ex(
          reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(target_address), FALSE);

      if (NT_SUCCESS(status)) {
        InterlockedExchangePointer(&g_callback_shellcode_address, target_address);
        InterlockedExchangePointer(&g_process_callback_handle, target_address);
        log("SUCCESS", "registered process callback from legitimate driver section");
      } else {
        log("ERROR", "failed to register process callback: 0x%x", status);
      }

      return status;
    }
  }  // namespace callbacks

}  // namespace hyperspace