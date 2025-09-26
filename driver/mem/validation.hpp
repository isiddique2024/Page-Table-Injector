#pragma once
#include "../def/globals.hpp"
namespace validation {

  auto virtual_to_physical(void* virtual_address) -> PHYSICAL_ADDRESS;

  auto is_pfn_valid(uintptr_t pfn) -> bool;

  auto is_physical_address_valid(uintptr_t physical_address) -> bool;

  auto is_virtual_address_valid(void* virtual_address) -> bool;

  auto validate_allocated_page(void* virtual_address, const char* page_type) -> NTSTATUS;

  auto validate_page_table_index(uint32_t index, const char* table_type) -> bool;

  auto validate_pfn_with_context(uintptr_t pfn, const char* context) -> bool;

  auto validate_process_state(PEPROCESS process, uint32_t pid) -> bool;

  auto acquire_process_rundown_protection(PEPROCESS process, uint32_t pid) -> bool;

  auto release_process_rundown_protection(PEPROCESS process) -> void;

  auto validate_size_parameters(size_t size, size_t page_count, size_t max_size = 0x40000000000ULL)
      -> bool;

  auto validate_index_range(uint32_t start_idx, uint32_t end_idx, const char* range_type) -> bool;

  auto validate_virtual_address_alignment(uintptr_t va, size_t alignment, const char* context)
      -> bool;

}  // namespace validation