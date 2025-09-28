#pragma once

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
  bool safe_copy(void* const dst, void* const src, const size_t size);

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
  auto probe_user_address(PVOID const addr, const SIZE_T size, const ULONG alignment) -> bool;

  /**
   * @brief Locate a loaded driver's base address by module name
   * @param module_name ANSI string name of the module to find
   * @return Base address of the module, or nullptr if not found
   *
   * Searches the PsLoadedModuleList to find a driver by name and returns its base
   * address.
   */
  auto get_driver_base(LPCSTR const module_name) -> void*;

  /**
   * @brief Apply stealth techniques to hide physical memory pages from detection
   * @param page_frame_number The PFN of the page to hide
   * @param type The hiding technique to apply
   * @return true if hiding succeeded, false otherwise
   *
   * Implements various memory hiding techniques via MmPfnDatabase manipulation
   */
  auto hide_physical_memory(uintptr_t page_frame_number, hide_type type, bool lock_page = false)
      -> bool;

  /**
   * @brief Allocate independent physical pages with stealth hiding applied
   * @param size Size in bytes to allocate (will be page-aligned)
   * @return Virtual address of allocated memory, or nullptr on failure
   *
   * Allocates non-contiguous physical pages and applies configured hiding
   * techniques. Memory is hidden according to global settings.
   */
  auto allocate_independent_pages(size_t size) -> void*;

  /**
   * @brief Allocate secure kernel pages
   * @param size Size in bytes to allocate (will be page-aligned)
   * @return Virtual address of allocated memory, or nullptr on failure
   *
   */
  auto allocate_secure_kernel_pages(size_t size) -> void*;

  /**
   * @brief Allocate contiguous physical memory with stealth hiding applied
   * @param size Size in bytes to allocate (will be page-aligned)
   * @return Virtual address of allocated memory, or nullptr on failure
   *
   * Allocates physically contiguous memory block and applies hiding techniques.
   * Handles both regular and large page allocations.
   */
  auto allocate_contiguous_memory(size_t size) -> void*;

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
                         memory_type mem_type) -> NTSTATUS;
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
  auto hijack_null_pfn(const uint32_t local_pid, const uint32_t target_pid, const size_t size)
      -> void*;

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
                                const size_t size) -> void*;

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
                                     const size_t size, const memory_type mem_type,
                                     const bool use_high_address) -> void*;

}  // namespace mem