#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <cstdint>
#include <stdlib.h>
#include "ia32.hpp"
#include "def.hpp"

namespace globals {
  // func address to hook in win32k.sys
  extern uintptr_t hook_address;
  extern void* shell_address;
  extern int SHELL_SIZE;
  extern int SHELL_SIZE_FJ;
  extern uintptr_t hook_pointer;
  extern uintptr_t ntos_base;

  extern uint32_t driver_hide_type;
  extern uint32_t dll_hide_type;

  extern uintptr_t driver_alloc_base;
  extern size_t driver_size;
  extern function_types::ke_flush_single_tb_t ke_flush_single_tb;
  extern function_types::ke_flush_entire_tb_t ke_flush_entire_tb;
  extern function_types::ke_invalidate_all_caches_t ke_invalidate_all_caches;
  extern function_types::mm_allocate_independent_pages_ex_t mm_allocate_independent_pages_ex;
  extern function_types::mm_free_contiguous_memory_t mm_free_contiguous_memory;
  extern function_types::mm_set_page_protection_t mm_set_page_protection;
  extern function_types::mm_free_independent_pages mm_free_independent_pages;

  extern function_types::mi_get_vm_access_logging_partition_t mi_get_vm_access_logging_partition;
  extern function_types::mi_create_decay_pfn_t mi_create_decay_pfn;
  extern function_types::mi_get_ultra_page_t mi_get_ultra_page;
  extern function_types::mi_reserve_ptes_t mi_reserve_ptes;
  extern function_types::mi_get_pte_address_t mi_get_pte_address;
  extern function_types::mi_get_pde_address_t mi_get_pde_address;
  extern function_types::mi_remove_physical_memory_t mi_remove_physical_memory;
  extern function_types::mi_flush_entire_tb_due_to_attribute_change_t
      mi_flush_entire_tb_due_to_attribute_change;
  extern function_types::mi_flush_cache_range_t mi_flush_cache_range;
  extern function_types::mi_get_page_table_pfn_buddy_raw_t mi_get_page_table_pfn_buddy_raw;
  extern function_types::mi_set_page_table_pfn_buddy_t mi_set_page_table_pfn_buddy;
  extern function_types::mi_lock_page_table_page_t mi_lock_page_table_page;
  extern function_types::mi_allocate_large_zero_pages_t mi_allocate_large_zero_pages;

  extern function_types::mm_get_physical_address_t mm_get_physical_address;
  extern function_types::mm_allocate_contiguous_memory_t mm_allocate_contiguous_memory;
  extern function_types::mm_copy_memory_t mm_copy_memory;
  extern function_types::mm_get_virtual_for_physical_t mm_get_virtual_for_physical;
  extern function_types::mm_copy_virtual_memory_t mm_copy_virtual_memory;
  extern function_types::mm_mark_physical_memory_as_bad_t mm_mark_physical_memory_as_bad;
  extern function_types::mm_user_probe_address_t mm_user_probe_address;
  extern function_types::mm_get_system_routine_address_t mm_get_system_routine_address;
  extern function_types::mm_get_physical_memory_ranges_t mm_get_physical_memory_ranges;
  extern function_types::mm_is_address_valid_t mm_is_address_valid;
  extern function_types::mm_allocate_secure_kernel_pages_t mm_allocate_secure_kernel_pages;

  extern uintptr_t mm_highest_physical_page;
  extern uintptr_t mm_lowest_physical_page;

  extern uintptr_t ps_loaded_module_list;
  extern function_types::ps_acquire_process_exit_synchronization_t
      ps_acquire_process_exit_synchronization;
  extern function_types::ps_release_process_exit_synchronization_t
      ps_release_process_exit_synchronization;
  extern function_types::ps_get_process_exit_status_t ps_get_process_exit_status;
  extern function_types::ps_set_create_thread_notify_routine_t ps_set_create_thread_notify_routine;
  extern function_types::ps_set_create_process_notify_routine_ex_t
      ps_set_create_process_notify_routine_ex;
  extern function_types::ps_lookup_process_by_process_id_t ps_lookup_process_by_process_id;
  extern function_types::ps_lookup_thread_by_thread_id_t ps_lookup_thread_by_thread_id;
  extern function_types::ps_get_next_process_thread_t ps_get_next_process_thread;
  extern function_types::ps_suspend_thread_t ps_suspend_thread;
  extern function_types::ps_suspend_thread_t ps_resume_thread;
  extern function_types::ps_query_thread_start_address_t ps_query_thread_start_address;
  extern function_types::ps_get_current_thread_id_t ps_get_current_thread_id;
  extern function_types::ps_get_process_peb_t ps_get_process_peb;
  extern function_types::ps_get_process_image_file_name_t ps_get_process_image_file_name;
  extern function_types::io_get_current_process_t io_get_current_process;
  extern function_types::obf_dereference_object_t obf_dereference_object;

  extern uintptr_t psp_exit_thread;

  extern function_types::ex_allocate_pool2_t ex_allocate_pool2;
  extern function_types::ex_free_pool_with_tag_t ex_free_pool_with_tag;
  extern function_types::ex_get_previous_mode_t ex_get_previous_mode;

  extern uintptr_t ke_balance_set_manager;
  extern function_types::ke_raise_irql_to_dpc_level_t ke_raise_irql_to_dpc_level;
  extern function_types::ke_lower_irql_t ke_lower_irql;
  extern function_types::ke_query_system_time_precise_t ke_query_system_time_precise;
  extern function_types::ke_initialize_apc_t ke_initialize_apc;
  extern function_types::ke_insert_queue_apc_t ke_insert_queue_apc;
  extern function_types::ke_usermode_callback_t ke_usermode_callback;
  extern function_types::ke_alert_thread_t ke_alert_thread;
  extern function_types::ke_delay_execution_thread_t ke_delay_execution_thread;
  extern PLIST_ENTRY ki_process_list_head;
  extern uintptr_t ki_page_fault;
  extern uintptr_t ki_kva_shadow;

  extern function_types::rtl_init_ansi_string_t rtl_init_ansi_string;
  extern function_types::rtl_init_unicode_string_t rtl_init_unicode_string;
  extern function_types::rtl_ansi_string_to_unicode_string_t rtl_ansi_string_to_unicode_string;
  extern function_types::rtl_compare_unicode_string_t rtl_compare_unicode_string;
  extern function_types::rtl_free_unicode_string_t rtl_free_unicode_string;
  extern function_types::rtl_get_version_t rtl_get_version;
  extern function_types::rtl_create_user_thread_t rtl_create_user_thread;

  extern function_types::zw_open_process_t zw_open_process;
  extern function_types::zw_close_t zw_close;
  extern function_types::zw_wait_for_single_object_t zw_wait_for_single_object;
  extern function_types::zw_query_information_process_t zw_query_information_process;
  extern function_types::nt_alert_resume_thread_t nt_alert_resume_thread;

  extern function_types::dbg_print_t dbg_print;

  extern function_types::memcpy_t memcpy;
  extern function_types::memset_t memset;
  extern function_types::memcmp_t memcmp;
  extern function_types::strncmp_t strncmp;
  extern function_types::strlen_t strlen;
  extern function_types::_wcsicmp_t _wcsicmp;
  extern function_types::rand_t rand;
  extern function_types::srand_t srand;
  extern function_types::swprintf_s_t swprintf_s;
  extern function_types::snprintf_t snprintf;
  extern LONG some_dword;
  extern uintptr_t mm_pfn_db;
  extern uintptr_t mm_physical_memory_block;
  extern uintptr_t mi_system_partition;
  extern hyperspace_ctx ctx;

  extern uintptr_t active_process_links;
  extern uintptr_t _eprocess_thread_list_head;
  extern uintptr_t _kprocess_thread_list_head;
  extern uintptr_t _eprocess_shared_commit_links;
  extern uintptr_t _eprocess_shared_commit_charge;
  extern uintptr_t _eprocess_rundown_protect;
  extern uintptr_t _eprocess_vm;
  extern uintptr_t _eprocess_flags3;

  extern uintptr_t _kprocess_dirbase;
  extern uintptr_t _kthread_pkprocess;
  extern uintptr_t _kthread_apcstate_pkprocess;

  extern PEPROCESS proc;
  extern unsigned long build_version;
  extern bool initialized;
}  // namespace globals

#pragma function(memset)
extern void* memset(void* dest, int value, size_t count);
