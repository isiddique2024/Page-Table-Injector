#pragma once
#include "./def/globals.hpp"
namespace init {

  /**
   * @brief Install function hook by placing shellcode in ntoskrnl .data section
   * @param func Pointer to the hook handler function
   * @return NTSTATUS indicating success or failure
   *
   * Creates and deploys shellcode that redirects execution to the specified
   * handler using push/ret technique. Finds unused space in ntoskrnl's .data section,
   * writes shellcode, modifies PTEs for execution permission, and updates the hook
   * address for later restoration.
   */
  auto install_hook(const void* func) -> NTSTATUS {
    globals::hook_pointer = *reinterpret_cast<std::uintptr_t*>(globals::hook_address);

    // far jump pattern
    constexpr size_t FAR_JMP_SIZE = 14;
    uint8_t shellcode[FAR_JMP_SIZE] = {0};

    shellcode[0] = 0xFF;  // opcode for indirect jump
    shellcode[1] = 0x25;  // ModR/M byte for [rip+disp32]

    // displacement (0 means the address is immediately after this instruction)
    *reinterpret_cast<int32_t*>(&shellcode[2]) = 0x00000000;

    // 64-bit absolute address follows immediately after the jump instruction
    *reinterpret_cast<uint64_t*>(&shellcode[6]) = reinterpret_cast<uint64_t>(func);

    uint32_t section_size = 0;
    void* section_base = page_table::find_section_base(reinterpret_cast<void*>(globals::ntos_base),
                                                       &section_size, ".data", 5);

    if (!section_base) {
      log("ERROR", "failed to find .data section in ntoskrnl");
      return STATUS_UNSUCCESSFUL;
    }

    void* target_address = page_table::find_unused_space(section_base, section_size, FAR_JMP_SIZE);

    if (!target_address) {
      log("ERROR", "failed to find unused space in .data section");
      return STATUS_UNSUCCESSFUL;
    }

    // write shellcode to target location
    globals::memcpy(target_address, shellcode, FAR_JMP_SIZE);

    log("INFO", "far jump shellcode written at addr: 0x%p", target_address);
    log("DEBUG", "jump target: 0x%llx", reinterpret_cast<uint64_t>(func));

    // make executable
    if (!page_table::spoof_pte_range(reinterpret_cast<uintptr_t>(target_address), FAR_JMP_SIZE,
                                     false)) {
      log("ERROR", "failed to spoof pte range at target address");
      return STATUS_UNSUCCESSFUL;
    }

    // update hook address
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

    globals::driver_alloc_base = local_offsets.DriverAllocBase;
    globals::driver_size = local_offsets.DriverSize;

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

    globals::mm_allocate_secure_kernel_pages =
        reinterpret_cast<function_types::mm_allocate_secure_kernel_pages_t>(
            local_offsets.MmAllocateSecureKernelPages);

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
    globals::mi_lock_page_table_page = reinterpret_cast<function_types::mi_lock_page_table_page_t>(
        local_offsets.MiLockPageTablePage);

    globals::mi_system_partition = local_offsets.MiSystemPartition;

    globals::mi_allocate_large_zero_pages =
        reinterpret_cast<function_types::mi_allocate_large_zero_pages_t>(
            local_offsets.MiAllocateLargeZeroPages);

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
        reinterpret_cast<function_types::ke_flush_single_tb_t>(local_offsets.KeFlushSingleTb);

    globals::ke_query_system_time_precise =
        reinterpret_cast<function_types::ke_query_system_time_precise_t>(
            local_offsets.KeQuerySystemTimePrecise);

    globals::ke_initialize_apc =
        reinterpret_cast<function_types::ke_initialize_apc_t>(local_offsets.KeInitializeApc);

    globals::ke_insert_queue_apc =
        reinterpret_cast<function_types::ke_insert_queue_apc_t>(local_offsets.KeInsertQueueApc);

    globals::ke_usermode_callback =
        reinterpret_cast<function_types::ke_usermode_callback_t>(local_offsets.KeUsermodeCallback);

    globals::ke_alert_thread =
        reinterpret_cast<function_types::ke_alert_thread_t>(local_offsets.KeAlertThread);

    globals::ke_delay_execution_thread =
        reinterpret_cast<function_types::ke_delay_execution_thread_t>(
            local_offsets.KeDelayExecutionThread);

    globals::ki_kva_shadow = local_offsets.KiKvaShadow;

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

    globals::zw_query_information_process =
        reinterpret_cast<function_types::zw_query_information_process_t>(
            local_offsets.ZwQueryInformationProcess);

    globals::nt_alert_resume_thread = reinterpret_cast<function_types::nt_alert_resume_thread_t>(
        local_offsets.NtAlertResumeThread);

    // assign crt functions
    globals::memcpy = reinterpret_cast<function_types::memcpy_t>(local_offsets.memcpy);
    globals::memset = reinterpret_cast<function_types::memset_t>(local_offsets.memset);
    globals::memcmp = reinterpret_cast<function_types::memcmp_t>(local_offsets.memcmp);
    globals::strncmp = reinterpret_cast<function_types::strncmp_t>(local_offsets.strncmp);
    globals::strlen = reinterpret_cast<function_types::strlen_t>(local_offsets.strlen);
    globals::_wcsicmp = reinterpret_cast<function_types::_wcsicmp_t>(local_offsets._wcsicmp);
    globals::rand = reinterpret_cast<function_types::rand_t>(local_offsets.rand);
    globals::srand = reinterpret_cast<function_types::srand_t>(local_offsets.srand);
    globals::swprintf_s = reinterpret_cast<function_types::swprintf_s_t>(local_offsets.swprintf_s);
    globals::snprintf = reinterpret_cast<function_types::snprintf_t>(local_offsets.snprintf);

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
   * @brief Apply stealth hiding techniques to driver memory page tables using physical operations
   * @param address Base virtual address of driver memory
   * @param size Size of driver memory region in bytes
   * @return NTSTATUS indicating success or failure
   *
   * Walks through all driver pages and hides the lowest level page table structures.
   * For 4KB pages: hides PT pages containing PTEs
   * For 2MB pages: hides PD pages containing PDEs
   * For 1GB pages: hides PDPT pages containing PDPTEs
   */
  auto hide_driver_pages(const uintptr_t address, const uintptr_t size) -> NTSTATUS {
    log("INFO", "starting to hide page table structures at address 0x%llx with size 0x%llx",
        address, size);

    // Get current process CR3 for page table walking
    PEPROCESS current_process = globals::io_get_current_process();
    uintptr_t cr3_pa = physical::get_process_directory_base(current_process);

    if (!cr3_pa) {
      log("ERROR", "failed to get CR3 physical address");
      return STATUS_UNSUCCESSFUL;
    }

    size_t pages_processed = 0;

    for (uintptr_t current_addr = address; current_addr < address + size;) {
      ADDRESS_TRANSLATION_HELPER helper;
      helper.AsUInt64 = current_addr;

      // read PML4E
      PML4E_64 pml4e = {0};
      uintptr_t pml4e_pa = cr3_pa + helper.AsIndex.Pml4 * sizeof(PML4E_64);
      if (!NT_SUCCESS(physical::read_physical_address(pml4e_pa, &pml4e, sizeof(pml4e)))) {
        current_addr += PAGE_SIZE;
        continue;
      }

      if (!pml4e.Present) {
        current_addr += PAGE_SIZE;
        continue;
      }

      // read PDPTE
      PDPTE_64 pdpte = {0};
      uintptr_t pdpt_pa = PFN_TO_PAGE(pml4e.PageFrameNumber);
      uintptr_t pdpte_pa = pdpt_pa + helper.AsIndex.Pdpt * sizeof(PDPTE_64);
      if (!NT_SUCCESS(physical::read_physical_address(pdpte_pa, &pdpte, sizeof(pdpte)))) {
        current_addr += PAGE_SIZE;
        continue;
      }

      if (!pdpte.Present) {
        current_addr += PAGE_SIZE;
        continue;
      }

      // check for 1GB large page
      if (pdpte.LargePage) {
        // hide the PDPT page containing this PDPTE
        uintptr_t pdpt_pfn = PAGE_TO_PFN(pdpt_pa);
        bool hide_result =
            mem::hide_physical_memory(pdpt_pfn, static_cast<hide_type>(globals::driver_hide_type));

        if (hide_result) {
          log("INFO", "hidden PDPT page with PFN 0x%llx for 1GB page at VA 0x%llx", pdpt_pfn,
              current_addr);
        } else {
          log("WARNING", "failed to hide PDPT page with PFN 0x%llx for VA 0x%llx", pdpt_pfn,
              current_addr);
        }

        pages_processed++;

        // skip to next 1GB boundary
        uintptr_t next_gb = (current_addr + 0x40000000) & ~0x3FFFFFFFULL;
        current_addr = (next_gb <= address + size) ? next_gb : address + size;
        continue;
      }

      // read PDE
      PDE_64 pde = {0};
      uintptr_t pd_pa = PFN_TO_PAGE(pdpte.PageFrameNumber);
      uintptr_t pde_pa = pd_pa + helper.AsIndex.Pd * sizeof(PDE_64);
      if (!NT_SUCCESS(physical::read_physical_address(pde_pa, &pde, sizeof(pde)))) {
        current_addr += PAGE_SIZE;
        continue;
      }

      if (!pde.Present) {
        current_addr += PAGE_SIZE;
        continue;
      }

      // check for 2MB large page
      if (pde.LargePage) {
        // hide the PD page containing this PDE
        uintptr_t pd_pfn = PAGE_TO_PFN(pd_pa);
        bool hide_result =
            mem::hide_physical_memory(pd_pfn, static_cast<hide_type>(globals::driver_hide_type));

        if (hide_result) {
          log("INFO", "hidden PD page with PFN 0x%llx for 2MB page at VA 0x%llx", pd_pfn,
              current_addr);
        } else {
          log("WARNING", "failed to hide PD page with PFN 0x%llx for VA 0x%llx", pd_pfn,
              current_addr);
        }

        pages_processed++;

        // skip to next 2MB boundary
        uintptr_t next_2mb = (current_addr + 0x200000) & ~0x1FFFFFULL;
        current_addr = (next_2mb <= address + size) ? next_2mb : address + size;
        continue;
      }

      // hide the PT page containing PTEs
      uintptr_t pt_pfn = pde.PageFrameNumber;
      if (!pt_pfn)
        continue;

      bool hide_result =
          mem::hide_physical_memory(pt_pfn, static_cast<hide_type>(globals::driver_hide_type));

      if (hide_result) {
        log("INFO", "hidden PT page with PFN 0x%llx for 4KB pages at VA 0x%llx", pt_pfn,
            current_addr);
      } else {
        log("WARNING", "failed to hide PT page with PFN 0x%llx for VA 0x%llx", pt_pfn,
            current_addr);
      }

      pages_processed++;

      // move to next page
      current_addr += PAGE_SIZE;
    }

    log("INFO", "completed processing %zu page table structures for driver range 0x%llx-0x%llx",
        pages_processed, address, address + size);

    return STATUS_SUCCESS;
  }
}  // namespace init
