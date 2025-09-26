#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>
#include "memory_manager.hpp"
#include "utils.hpp"

#include "lib/ia_32.h"

#define NtCurrentProcess ((HANDLE)(LONG_PTR)-1)

// status codes
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_INVALID_PARAMETER 0xC000000D
#define STATUS_NO_MEMORY 0xC0000017
#define STATUS_INVALID_ADDRESS 0xC0000141
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// physical address conversion
#define PFN_TO_PAGE(pfn) ((pfn) << 12)
#define PAGE_TO_PFN(physical_address) ((physical_address) >> 12)

// page protection constants
#define PAGE_EXECUTE_READWRITE 0x40

typedef union _PHYSICAL_ADDRESS {
  struct {
    ULONG LowPart;
    LONG HighPart;
  };
  LONGLONG QuadPart;
} PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

class page_table_manager_t {
public:
  page_table_manager_t() = default;
  ~page_table_manager_t() = default;

  // Advanced allocation methods
  auto allocate_within_current_process_context(HANDLE device_handle, std::uint32_t target_pid,
                                               std::size_t size, bool use_large_page,
                                               bool use_high_address = true) -> void*;

  // Page table manipulation
  auto write_page_tables(HANDLE device_handle, std::uint64_t target_dir_base, std::uint64_t base_va,
                         std::size_t page_count, bool use_large_page) -> bool;

  // Physical memory operations
  auto physical_to_virtual(HANDLE device_handle, std::uintptr_t physical_address) -> std::uintptr_t;
  auto virtual_to_physical(HANDLE device_handle, std::uintptr_t virtual_address) -> std::uintptr_t;
  auto read_physical_address(HANDLE device_handle, std::uintptr_t physical_address, void* buffer,
                             std::size_t size) -> bool;
  auto write_physical_address(HANDLE device_handle, std::uintptr_t physical_address, void* buffer,
                              std::size_t size) -> bool;

  // Cache and TLB management'
  auto flush_caches(HANDLE device_handle, void* address) -> bool;

  auto get_pml4e(std::uint32_t pml4_idx) -> std::uint64_t;

  auto get_pdpt(std::uint32_t pdpt_idx) -> std::uint64_t;

  auto get_pd(std::uint32_t pd_idx) -> std::uint64_t;

  auto get_pt(std::uint32_t pt_idx) -> std::uint64_t;
  auto get_pde_address(HANDLE device_handle, std::uint64_t virtual_address) -> std::uint64_t;
  auto get_pte_address(HANDLE device_handle, std::uint64_t virtual_address) -> std::uint64_t;

private:
  // Helper functions
  auto allocate_page_table_page(HANDLE device_handle) -> std::uintptr_t;
  auto get_page_frame_number(HANDLE device_handle, std::uint64_t virtual_address,
                             bool use_large_page) -> std::uint64_t;
  auto setup_page_table_entry(HANDLE device_handle, std::uintptr_t entry_address, std::uint64_t pfn,
                              bool is_present, bool is_writable, bool is_executable) -> bool;

  // Constants
  static constexpr size_t page_size_4kb = 0x1000;
  static constexpr size_t large_page_size = 0x200000;
  static constexpr auto pml4_shift = 39;
  static constexpr auto pdpt_shift = 30;
  static constexpr auto pd_shift = 21;
  static constexpr auto pt_shift = 12;
};

// Global instance
inline std::unique_ptr<page_table_manager_t> g_page_table_manager =
    std::make_unique<page_table_manager_t>();