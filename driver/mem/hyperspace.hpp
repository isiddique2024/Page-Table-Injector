#pragma once

namespace hyperspace {

  extern ntoskrnl_mapping_info g_ntoskrnl_copy_info;
  extern pt_hook::hook_info g_pspexit_hook;

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
  __int64 __fastcall PspExitThread(unsigned int a1);

  /**
   * @brief Initialize page tracking system for ntoskrnl copy operations
   * @return true if initialization succeeded, false otherwise
   *
   * Allocates memory for tracking physical pages used in ntoskrnl copying.
   * Maintains an array of allocated page addresses for proper cleanup.
   */
  auto initialize_page_tracking() -> bool;

  /**
   * @brief Add a virtual address to the page tracking array
   * @param va Virtual address of the allocated page
   * @return true if page was successfully tracked, false if array is full
   *
   * Records allocated pages for later cleanup. Essential for preventing memory
   * leaks when tearing down the hyperspace context.
   */
  auto add_tracked_page(uintptr_t va) -> bool;

  /**
   * @brief Locate ntoskrnl.exe in the loaded module list
   * @param base Output parameter for ntoskrnl base address
   * @param size Output parameter for ntoskrnl image size
   * @return true if ntoskrnl was found, false otherwise
   *
   * Searches PsLoadedModuleList to find the kernel image and retrieve its
   * base address and size for copying operations.
   */
  auto find_ntoskrnl_info(uintptr_t* base, uintptr_t* size) -> bool;

  /**
   * @brief Allocate and track a single physical page with hiding applied
   * @return Physical address of allocated page, or 0 on failure
   *
   * Combines page allocation, zeroing, physical address translation, and tracking
   * into a single operation for use in page table construction.
   */
  auto allocate_tracked_physical_page() -> uintptr_t;

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
  auto copy_ntoskrnl_pages(uintptr_t src_base, uintptr_t size, uintptr_t dest_pd_pa) -> bool;

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
      -> bool;

  /**
   * @brief Map copied ntoskrnl pages into the hyperspace page tables
   * @param info Pointer to mapping information structure
   * @return true if mapping succeeded, false otherwise
   *
   * Creates PTEs pointing to the copied physical pages and constructs
   * complete virtual memory mapping for the ntoskrnl copy.
   */
  auto map_ntoskrnl_pages(ntoskrnl_mapping_info* info) -> bool;

  /**
   * @brief Install kernel function hooks within the hyperspace ntoskrnl copy
   * @return NTSTATUS indicating success or failure
   *
   * Applies function hooks to the copied kernel image in hyperspace context,
   * allowing for kernel-level interception without affecting the original kernel.
   */
  auto install_kernel_hooks_in_hyperspace() -> NTSTATUS;

  /**
   * @brief Create a complete contextualized copy of ntoskrnl in hyperspace
   * @return NTSTATUS indicating success or failure
   *
   * Master function that orchestrates the entire process of copying ntoskrnl
   * into hyperspace with proper page tables, mapping, and hook installation.
   */
  auto create_contextualized_ntoskrnl() -> NTSTATUS;

  /**
   * @brief Clean up and free all resources used by the ntoskrnl copy
   *
   * Releases all tracked pages, page table structures, and associated memory
   * allocated during ntoskrnl copying operations.
   */
  auto cleanup_contextualized_ntoskrnl() -> void;

  /**
   * @brief Initialize list entries in cloned EPROCESS to prevent crashes
   * @param clone_eproc Pointer to the cloned EPROCESS structure
   *
   * Sets up empty list heads and clears problematic fields to ensure the
   * cloned process structure doesn't cause system instability.
   */
  auto initialize_cloned_eprocess_lists(PEPROCESS clone_eproc) -> void;

  /**
   * @brief Locate PML4 self-reference entry in the original page table
   * @param cr3_pa Physical address of the original CR3/PML4
   * @return Structure containing self-reference entry information
   *
   * Finds the PML4 entry that points back to itself, which is used by
   * the system for recursive page table access.
   */
  auto find_pml4_self_reference_entry(uintptr_t cr3_pa) -> self_reference_entry_info;

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
                                          self_reference_entry_info self_reference_info) -> bool;

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
      -> bool;

  /**
   * @brief Initialize complete hyperspace context with cloned page tables
   * @param target_pid Process ID to create hyperspace context for
   * @param ctx Pointer to hyperspace context structure
   * @return NTSTATUS indicating success or failure
   *
   * Master initialization function that creates a complete hyperspace context
   * including cloned PML4, EPROCESS, and all necessary supporting structures.
   */
  auto initialize_hyperspace_context(uint32_t target_pid, hyperspace_ctx* ctx) -> NTSTATUS;

  /**
   * @brief Allocate memory within hyperspace context using unused PML4 entries
   * @param target_pid Target process ID (unused in current implementation)
   * @param size Size of memory to allocate
   * @param use_large_page Whether to use 2MB large pages
   * @return Virtual address of allocated memory, or nullptr on failure
   *
   * Allocates memory within the hyperspace context using the same stealth
   * techniques as regular allocation but within the isolated address space.
   */
  auto allocate_in_hyperspace(uint32_t target_pid, size_t size, bool use_large_page) -> void*;

  /**
   * @brief Switch a thread's execution context to hyperspace
   * @param tid Thread ID to switch
   * @param ctx Pointer to hyperspace context
   * @return NTSTATUS indicating success or failure
   *
   * Modifies thread's ApcState.Process to point to the cloned EPROCESS,
   * effectively switching the thread to execute within hyperspace context.
   */
  auto switch_thread_context_to_hyperspace(uint32_t tid, hyperspace_ctx* ctx) -> NTSTATUS;

  /**
   * @brief Switch thread back from hyperspace to original context
   * @param tid Thread ID to switch back
   * @param ctx Pointer to hyperspace context
   * @return true if switch succeeded, false otherwise
   *
   * Restores thread's original process context, returning it to normal
   * execution environment.
   */
  auto switch_from_hyperspace(uint32_t tid, hyperspace_ctx* ctx) -> bool;

  /**
   * @brief Clean up hyperspace context and free all associated resources
   * @param ctx Pointer to hyperspace context to clean up
   *
   * Comprehensive cleanup function that releases PML4, EPROCESS clone,
   * and all other resources associated with the hyperspace context.
   */
  auto cleanup_hyperspace_context(hyperspace_ctx* ctx) -> void;

  namespace callbacks {

    extern void* g_callback_shellcode_address;
    extern void* g_process_callback_handle;

    /**
     * @brief Process notification callback implementation for cleanup on exit
     * @param ParentId Parent process ID
     * @param ProcessId Process ID that created/terminated
     * @param Create TRUE for process creation, FALSE for termination
     *
     * Handles process termination events to trigger automatic cleanup
     * of hyperspace resources when the target process exits.
     */
    auto process_notify_callback_impl(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) -> void;

    /**
     * @brief Find a legitimate driver suitable for hosting callback shellcode
     * @param out_size Output parameter for driver size
     * @return Base address of suitable driver, or nullptr if none found
     *
     * Locates a legitimate system driver with proper flags for hosting
     * callback functions, avoiding detection by security software.
     */
    auto find_legitimate_driver_for_callbacks(PULONG out_size) -> void*;

    /**
     * @brief Install process notification callback for automatic cleanup
     * @return NTSTATUS indicating success or failure
     *
     * Registers a process notification callback using shellcode placed in
     * a legitimate driver to trigger cleanup when the target process exits.
     */
    auto install_process_callback() -> NTSTATUS;
  }  // namespace callbacks

}  // namespace hyperspace