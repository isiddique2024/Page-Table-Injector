#pragma once

namespace detections {

  /**
   * @brief Check if a page table entry frame (MMPFN.u4.PteFrame) has mismatching
   * EPROCESS ownership
   * @param physical_address Physical address of the page frame to check
   * @param no_associated_eprocess_flag Output flag set if EPROCESS mismatch
   * detected
   * @return STATUS_OK if ownership matches, STATUS_MISMATCHING_EPROCESS otherwise
   *
   * Validates that the EPROCESS associated with a page frame number matches the
   * expected target process. Detects usage of pages that don't belong to the
   * process.
   */
  auto check_pte_frame(uintptr_t physical_address, uint8_t* no_associated_eprocess_flag)
      -> uint32_t;

  /**
   * @brief Test physical memory accessibility and check for stealth hiding flags
   * @param physical_address Physical address to test
   * @param parity_error_flag Output flag set if parity error detected
   * @param pfn_exists_flag Output flag set if PfnExists bit is cleared
   * @return Status code indicating type of hiding technique detected
   *
   * Uses MmCopyMemory to test if physical memory is accessible and analyzes
   * the failure modes to detect various memory hiding techniques including
   * parity error injection and PFN existence bit manipulation.
   */
  auto check_mmcopymemory(uintptr_t physical_address, uint8_t* parity_error_flag,
                          uint8_t* pfn_exists_flag) -> uint32_t;

  /**
   * @brief Add a detection result entry to the global results array
   * @param va Virtual address of the suspicious page
   * @param pa Physical address of the suspicious page
   * @param parity_error_flag Flag indicating parity error detection
   * @param pfn_exists_flag Flag indicating PfnExists bit manipulation
   * @param supervisor_flag Flag indicating supervisor bit anomaly
   * @param no_associated_eprocess_flag Flag indicating EPROCESS mismatch
   * @return TRUE if entry was added successfully, FALSE if buffer is full
   *
   * Records suspicious page table entries in the global results array for
   * later analysis and reporting.
   */
  auto add_entry(uintptr_t va, uintptr_t pa, uint8_t parity_error_flag, uint8_t pfn_exists_flag,
                 uint8_t supervisor_flag, uint8_t no_associated_eprocess_flag) -> bool;

  /**
   * @brief Walk all page table entries starting from PML4 level
   * @param dir_base Physical address of the PML4 table (CR3 value)
   * @return NTSTATUS indicating success or failure of the walk operation
   *
   * Master function that performs a complete page table walk across all levels.
   * Iterates through all 512 PML4 entries for both user and kernel space,
   * delegating to lower-level walk functions for detailed analysis.
   */
  auto walk_all_page_tables(uintptr_t dir_base) -> NTSTATUS;

  /**
   * @brief Walk Page Directory Pointer Table entries for a given PML4 entry
   * @param pdpt_base Physical address of the PDPT
   * @param pml4_idx Index of the parent PML4 entry
   * @return NTSTATUS indicating success or failure
   *
   * Iterates through all 512 PDPTE entries, skipping 1GB large pages,
   * and delegates to PD-level walking for standard 4KB page mappings.
   */
  auto walk_pdpt(uintptr_t pdpt_base, uint32_t pml4_idx) -> NTSTATUS;

  /**
   * @brief Walk Page Directory entries for a given PDPTE
   * @param pd_base Physical address of the Page Directory
   * @param pml4_idx Index of the parent PML4 entry
   * @param pdpt_idx Index of the parent PDPTE entry
   * @return NTSTATUS indicating success or failure
   *
   * Iterates through all 512 PDE entries, skipping 2MB large pages,
   * and delegates to PT-level walking for standard 4KB page mappings.
   */
  auto walk_pd(uintptr_t pd_base, uint32_t pml4_idx, uint32_t pdpt_idx) -> NTSTATUS;

  /**
   * @brief Walk Page Table entries and perform detailed security analysis
   * @param pt_base Physical address of the Page Table
   * @param pml4_idx Index of the parent PML4 entry
   * @param pdpt_idx Index of the parent PDPTE entry
   * @param pd_idx Index of the parent PDE entry
   * @return NTSTATUS indicating success or failure
   *
   * Performs the core detection logic by examining individual PTEs for
   * suspicious characteristics including executable supervisor pages,
   * memory hiding techniques, and EPROCESS ownership anomalies.
   */
  auto walk_pt(uintptr_t pt_base, uint32_t pml4_idx, uint32_t pdpt_idx, uint32_t pd_idx)
      -> NTSTATUS;

  /**
   * @brief Analyze and report statistics from the page table walk results
   *
   * Processes the global results array to generate comprehensive statistics
   * about detected anomalies including hiding technique counts, address space
   * distribution, and detailed examples of suspicious entries for investigation.
   */
  auto analyze_page_table_results() -> void;

  /**
   * @brief Main entry point for process page table security inspection
   * @param process_id Process ID to analyze
   * @return NTSTATUS indicating overall success or failure
   *
   * Coordinates the complete page table security analysis for a target process.
   * Looks up the process, obtains its directory base, performs the full walk,
   * and generates a comprehensive security report of potential threats.
   */
  auto inspect_process_page_tables(uint32_t process_id) -> NTSTATUS;
}  // namespace detections