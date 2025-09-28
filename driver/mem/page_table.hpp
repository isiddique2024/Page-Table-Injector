#pragma once
#include <ntifs.h>

namespace page_table {

  /**
   * @brief Flush all Translation Lookaside Buffers and processor caches
   *
   * Performs a complete TLB flush and cache invalidation across all processors.
   * This ensures memory mappings and cached data are refreshed after page table
   * modifications.
   */
  auto flush_tlb() -> void;

  /**
   * @brief Intelligently flush caches and TLB for a specific memory address
   *
   * Performs comprehensive cache and Translation Lookaside Buffer (TLB)
   * invalidation for a specific memory address. Uses optimal flushing strategy
   * based on CPU features.
   *
   * @param address Virtual address to flush from caches and TLB
   *
   * @details
   * This function performs the following operations in sequence:
   * 1. **Smart TLB Flushing**:
   *    - If PCID or Global Pages are enabled: Toggles PGE bit to flush global TLB
   * entries
   *    - Otherwise: Reloads CR3 to flush entire TLB (preserves global pages if
   * PGE set)
   * 2. **Cache Invalidation**: Forces all dirty cache lines to memory and
   * invalidates CPU caches
   * 3. **Page-Specific Invalidation**: Removes the specific virtual address from
   * TLB
   *
   * @note This is a heavy operation that flushes ALL processor caches. Use
   * sparingly.
   * @warning Should be called after direct page table modifications to ensure
   * cache coherency
   *
   * @see CR4 control register documentation for PCID and PGE details
   * @see Intel Software Developer Manual Vol 3A, Section 4.10 for TLB management
   */
  void flush_caches(void* address);

  /**
   * @brief Convert a virtual address to its corresponding physical address
   * @param virtual_address The virtual address to translate
   * @return PHYSICAL_ADDRESS structure containing the physical address, or 0 if
   * translation fails
   *
   * Uses the Memory Manager's PTE resolution to perform virtual-to-physical
   * address translation. Returns zero physical address if the page is not present
   * or the PTE is invalid.
   */
  auto virtual_to_physical(void* virtual_address) -> PHYSICAL_ADDRESS;
  /**
   * @brief Retrieve page table entry information for a given virtual address
   * @param va Virtual address to analyze
   * @param cr3 CR3 register value containing the page directory base
   * @return PAGE_INFORMATION structure containing pointers to relevant page table
   * entries
   *
   * Walks the page table hierarchy to locate and return pointers to the PML4E,
   * PDPTE, PDE, and PTE entries for a virtual address. Handles large pages and
   * stops traversal early when encountering non-present entries or large page
   * mappings.
   */
  auto get_page_information(const void* va, const CR3 cr3) -> PAGE_INFORMATION;

  /**
   * @brief Find random unused space within a memory section for shellcode
   * placement
   * @param base Base address of the section to scan
   * @param section_size Total size of the section in bytes
   * @param shell_size Required size for the shellcode
   * @return Pointer to a randomly selected free space, or nullptr if none found
   *
   * Scans for contiguous zero-byte regions large enough to hold shellcode and
   * randomly selects one to avoid predictable placement patterns.
   */
  auto find_unused_space(void* base, uint32_t section_size, size_t shell_size) -> void*;

  /**
   * @brief Locate a specific section within a PE image
   * @param base Base address of the PE image
   * @param size Output parameter for the section's virtual size
   * @param section_name Name of the section to find (e.g., ".text", ".data")
   * @param section_name_len Length of the section name string
   * @return Virtual address of the section, or nullptr if not found
   *
   * Parses PE headers to locate a named section and returns its virtual address
   * and size.
   */
  auto find_section_base(void* base, uint32_t* size, const char* section_name,
                         size_t section_name_len) -> void*;

  /**
   * @brief Modify page table entries to change memory protection attributes
   * @param address Starting virtual address of the memory range
   * @param size Size of the memory range in bytes
   * @param execute_disable Whether to set the Execute Disable (NX) bit
   * @return true if at least one PTE was successfully modified, false otherwise
   *
   * Iterates through pages in the specified range and modifies their PTEs or PDEs
   * to change execution permissions. Handles both regular 4KB pages and 2MB large
   * pages.
   */
  auto spoof_pte_range(const uintptr_t address, const size_t size, const bool execute_disable)
      -> bool;

  /**
   * @brief Calculate virtual address component for PML4 entry index
   * @param pml4_idx PML4 table index (0-511)
   * @return Virtual address bits corresponding to the PML4 index (bits 47-39)
   *
   * Helper function to construct virtual addresses by converting page table
   * indices to their corresponding address bit patterns.
   */
  uintptr_t get_pml4e(uint32_t pml4_idx);

  /**
   * @brief Calculate virtual address component for PDPT entry index
   * @param pdpt_idx PDPT table index (0-511)
   * @return Virtual address bits corresponding to the PDPT index (bits 38-30)
   *
   * Helper function to construct virtual addresses by converting page table
   * indices to their corresponding address bit patterns.
   */
  uintptr_t get_pdpt(uint32_t pdpt_idx);

  /**
   * @brief Calculate virtual address component for PD entry index
   * @param pd_idx PD table index (0-511)
   * @return Virtual address bits corresponding to the PD index (bits 29-21)
   *
   * Helper function to construct virtual addresses by converting page table
   * indices to their corresponding address bit patterns.
   */
  uintptr_t get_pd(uint32_t pd_idx);

  /**
   * @brief Calculate virtual address component for PT entry index
   * @param pt_idx PT table index (0-511)
   * @return Virtual address bits corresponding to the PT index (bits 20-12)
   *
   * Helper function to construct virtual addresses by converting page table
   * indices to their corresponding address bit patterns.
   */
  uintptr_t get_pt(uint32_t pt_idx);

  /**
   * @brief Structure to hold the result of random PML4 index selection
   */
  struct PML4_SELECTION_RESULT {
    uint32_t selected_index;
    uint32_t available_count;
    bool success;
  };

  /**
   * @brief Find and randomly select an available (non-present) PML4 entry
   * @param dir_base Physical address of the page directory base (CR3)
   * @param start_idx Starting PML4 index to search from
   * @param end_idx Ending PML4 index to search to (exclusive)
   * @param seed_data Additional data to use for random seed generation
   * @return PML4_SELECTION_RESULT containing the selected index and metadata
   *
   * Scans the specified range of PML4 entries to find non-present ones,
   * then randomly selects one for allocation. Uses time and process info
   * for entropy in the random selection.
   */
  auto select_random_available_pml4(uintptr_t dir_base, uint32_t start_idx, uint32_t end_idx,
                                    uintptr_t seed_data = 0) -> PML4_SELECTION_RESULT;

  /**
   * @brief Generate randomized address offset within a PML4E's address space
   * @param use_large_page Whether using 2MB large pages or 4KB pages
   * @return Randomized offset to add entropy to the base address
   *
   * Adds randomization at the appropriate page table level:
   * - Large pages (2MB): Randomizes PDPTE selection (bits 30-38, 1GB regions)
   * - Small pages (4KB): Randomizes PDE selection (bits 21-29, 2MB regions)
   */
  auto generate_address_entropy(bool use_large_page) -> uint64_t;

  /**
   * @brief Helper to determine PML4 search range based on address space preference
   * @param use_high_address Whether to use kernel-space (high) or user-space (low) addresses
   * @param start_idx Output parameter for starting index
   * @param end_idx Output parameter for ending index
   * @param space_type Output parameter for descriptive string
   */
  auto get_pml4_search_range(bool use_high_address, uint32_t* start_idx, uint32_t* end_idx,
                             const char** space_type) -> void;

  /**
   * @brief Construct a complete virtual address with randomization
   * @param selected_pml4_index The selected PML4 table index
   * @param use_high_address Whether this is a kernel-space address
   * @param use_large_page Whether using large pages for entropy calculation
   * @return Complete virtual address with base address and entropy
   */
  auto construct_randomized_virtual_address(uint32_t selected_pml4_index, bool use_high_address,
                                            memory_type mem_type) -> uintptr_t;

}  // namespace page_table