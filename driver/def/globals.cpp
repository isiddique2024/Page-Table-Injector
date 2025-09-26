#pragma once
#include "globals.hpp"

namespace globals {
  // func address to hook in win32k.sys
  extern uintptr_t hook_address = 0;
  extern void* shell_address = 0;
  extern int SHELL_SIZE = 12;
  extern int SHELL_SIZE_FJ = 14;
  extern uintptr_t hook_pointer = 0;
  extern uintptr_t ntos_base = 0;

  extern uint32_t driver_hide_type = 0;
  extern uint32_t dll_hide_type = 0;

  extern uintptr_t driver_alloc_base = 0;
  extern size_t driver_size = 0;
  extern function_types::ke_flush_single_tb_t ke_flush_single_tb = nullptr;
  extern function_types::ke_flush_entire_tb_t ke_flush_entire_tb = nullptr;
  extern function_types::ke_invalidate_all_caches_t ke_invalidate_all_caches = nullptr;
  extern function_types::mm_allocate_independent_pages_ex_t mm_allocate_independent_pages_ex =
      nullptr;
  extern function_types::mm_free_contiguous_memory_t mm_free_contiguous_memory = nullptr;
  extern function_types::mm_set_page_protection_t mm_set_page_protection = nullptr;
  extern function_types::mm_free_independent_pages mm_free_independent_pages = nullptr;

  extern function_types::mi_get_vm_access_logging_partition_t mi_get_vm_access_logging_partition =
      nullptr;
  extern function_types::mi_create_decay_pfn_t mi_create_decay_pfn = nullptr;
  extern function_types::mi_get_ultra_page_t mi_get_ultra_page = nullptr;
  extern function_types::mi_reserve_ptes_t mi_reserve_ptes = nullptr;
  extern function_types::mi_get_pte_address_t mi_get_pte_address = nullptr;
  extern function_types::mi_get_pde_address_t mi_get_pde_address = nullptr;
  extern function_types::mi_remove_physical_memory_t mi_remove_physical_memory = nullptr;
  extern function_types::mi_flush_entire_tb_due_to_attribute_change_t
      mi_flush_entire_tb_due_to_attribute_change = nullptr;
  extern function_types::mi_flush_cache_range_t mi_flush_cache_range = nullptr;
  extern function_types::mi_get_page_table_pfn_buddy_raw_t mi_get_page_table_pfn_buddy_raw =
      nullptr;
  extern function_types::mi_set_page_table_pfn_buddy_t mi_set_page_table_pfn_buddy = nullptr;
  extern function_types::mi_lock_page_table_page_t mi_lock_page_table_page = nullptr;
  extern function_types::mi_allocate_large_zero_pages_t mi_allocate_large_zero_pages = nullptr;

  extern function_types::mm_get_physical_address_t mm_get_physical_address = nullptr;
  extern function_types::mm_allocate_contiguous_memory_t mm_allocate_contiguous_memory = nullptr;
  extern function_types::mm_copy_memory_t mm_copy_memory = nullptr;
  extern function_types::mm_get_virtual_for_physical_t mm_get_virtual_for_physical = nullptr;
  extern function_types::mm_copy_virtual_memory_t mm_copy_virtual_memory = nullptr;
  extern function_types::mm_mark_physical_memory_as_bad_t mm_mark_physical_memory_as_bad = nullptr;
  extern function_types::mm_user_probe_address_t mm_user_probe_address = nullptr;
  extern function_types::mm_get_system_routine_address_t mm_get_system_routine_address = nullptr;
  extern function_types::mm_get_physical_memory_ranges_t mm_get_physical_memory_ranges = nullptr;
  extern function_types::mm_is_address_valid_t mm_is_address_valid = nullptr;
  extern function_types::mm_allocate_secure_kernel_pages_t mm_allocate_secure_kernel_pages =
      nullptr;

  extern uintptr_t mm_highest_physical_page = 0;
  extern uintptr_t mm_lowest_physical_page = 0;

  extern uintptr_t ps_loaded_module_list = 0;
  extern function_types::ps_acquire_process_exit_synchronization_t
      ps_acquire_process_exit_synchronization = nullptr;
  extern function_types::ps_release_process_exit_synchronization_t
      ps_release_process_exit_synchronization = nullptr;
  extern function_types::ps_get_process_exit_status_t ps_get_process_exit_status = nullptr;
  extern function_types::ps_set_create_thread_notify_routine_t ps_set_create_thread_notify_routine =
      nullptr;
  extern function_types::ps_set_create_process_notify_routine_ex_t
      ps_set_create_process_notify_routine_ex = nullptr;
  extern function_types::ps_lookup_process_by_process_id_t ps_lookup_process_by_process_id =
      nullptr;
  extern function_types::ps_lookup_thread_by_thread_id_t ps_lookup_thread_by_thread_id = nullptr;
  extern function_types::ps_get_next_process_thread_t ps_get_next_process_thread = nullptr;
  extern function_types::ps_suspend_thread_t ps_suspend_thread = nullptr;
  extern function_types::ps_suspend_thread_t ps_resume_thread = nullptr;
  extern function_types::ps_query_thread_start_address_t ps_query_thread_start_address = nullptr;
  extern function_types::ps_get_current_thread_id_t ps_get_current_thread_id = nullptr;
  extern function_types::ps_get_process_peb_t ps_get_process_peb = nullptr;
  extern function_types::ps_get_process_image_file_name_t ps_get_process_image_file_name = nullptr;
  extern function_types::io_get_current_process_t io_get_current_process = nullptr;
  extern function_types::obf_dereference_object_t obf_dereference_object = nullptr;

  extern uintptr_t psp_exit_thread = 0;

  extern function_types::ex_allocate_pool2_t ex_allocate_pool2 = nullptr;
  extern function_types::ex_free_pool_with_tag_t ex_free_pool_with_tag = nullptr;
  extern function_types::ex_get_previous_mode_t ex_get_previous_mode = nullptr;

  extern uintptr_t ke_balance_set_manager = 0;
  extern function_types::ke_raise_irql_to_dpc_level_t ke_raise_irql_to_dpc_level = nullptr;
  extern function_types::ke_lower_irql_t ke_lower_irql = nullptr;
  extern function_types::ke_query_system_time_precise_t ke_query_system_time_precise = nullptr;
  extern function_types::ke_initialize_apc_t ke_initialize_apc = nullptr;
  extern function_types::ke_insert_queue_apc_t ke_insert_queue_apc = nullptr;
  extern function_types::ke_usermode_callback_t ke_usermode_callback = nullptr;
  extern function_types::ke_alert_thread_t ke_alert_thread = nullptr;
  extern function_types::ke_delay_execution_thread_t ke_delay_execution_thread = nullptr;
  extern PLIST_ENTRY ki_process_list_head = 0;
  extern uintptr_t ki_page_fault = 0;
  extern uintptr_t ki_kva_shadow = 0;

  extern function_types::rtl_init_ansi_string_t rtl_init_ansi_string = nullptr;
  extern function_types::rtl_init_unicode_string_t rtl_init_unicode_string = nullptr;
  extern function_types::rtl_ansi_string_to_unicode_string_t rtl_ansi_string_to_unicode_string =
      nullptr;
  extern function_types::rtl_compare_unicode_string_t rtl_compare_unicode_string = nullptr;
  extern function_types::rtl_free_unicode_string_t rtl_free_unicode_string = nullptr;
  extern function_types::rtl_get_version_t rtl_get_version = nullptr;
  extern function_types::rtl_create_user_thread_t rtl_create_user_thread = nullptr;

  extern function_types::zw_open_process_t zw_open_process = nullptr;
  extern function_types::zw_close_t zw_close = nullptr;
  extern function_types::zw_wait_for_single_object_t zw_wait_for_single_object = nullptr;
  extern function_types::zw_query_information_process_t zw_query_information_process = nullptr;
  extern function_types::nt_alert_resume_thread_t nt_alert_resume_thread = nullptr;

  extern function_types::dbg_print_t dbg_print = nullptr;

  extern function_types::memcpy_t memcpy = nullptr;
  extern function_types::memset_t memset = nullptr;
  extern function_types::memcmp_t memcmp = nullptr;
  extern function_types::strncmp_t strncmp = nullptr;
  extern function_types::strlen_t strlen = nullptr;
  extern function_types::_wcsicmp_t _wcsicmp = nullptr;
  extern function_types::rand_t rand = nullptr;
  extern function_types::srand_t srand = nullptr;
  extern function_types::swprintf_s_t swprintf_s = nullptr;
  extern function_types::snprintf_t snprintf = nullptr;
  extern LONG some_dword = 0;
  extern uintptr_t mm_pfn_db = 0;
  extern uintptr_t mm_physical_memory_block = 0;
  extern uintptr_t mi_system_partition = 0;
  extern hyperspace_ctx ctx = {0};

  extern uintptr_t active_process_links = 0x0;
  extern uintptr_t _eprocess_thread_list_head = 0x0;
  extern uintptr_t _kprocess_thread_list_head = 0x0;
  extern uintptr_t _eprocess_shared_commit_links = 0x0;
  extern uintptr_t _eprocess_shared_commit_charge = 0x0;
  extern uintptr_t _eprocess_rundown_protect = 0x0;
  extern uintptr_t _eprocess_vm = 0x0;
  extern uintptr_t _eprocess_flags3 = 0x0;

  extern uintptr_t _kprocess_dirbase = 0x28;
  extern uintptr_t _kthread_pkprocess = 0x220;
  extern uintptr_t _kthread_apcstate_pkprocess = 0xB8;

  extern PEPROCESS proc = 0x0;
  extern unsigned long build_version = 0;
  extern bool initialized = false;
}  // namespace globals

#pragma function(memset)
void* memset(void* dest, int value, size_t count) {
  unsigned char* p = (unsigned char*)dest;
  unsigned char val = (unsigned char)value;

  for (size_t i = 0; i < count; i++) {
    p[i] = val;
  }

  return dest;
};