#pragma once

namespace pt_hook {

  struct hook_info {
    uintptr_t target_va;
    uintptr_t target_pa;
    uintptr_t hook_function;
    uintptr_t original_function;
    uint8_t original_bytes[32];
    size_t hook_size;
    bool initialized;
  };

  /**
   * @brief Translate virtual address to physical address using page table walking
   * @param pml4_pa Physical address of the PML4 table (CR3 register value)
   * @param va Virtual address to translate
   * @return Physical address, or 0 if translation fails
   *
   * Manually walks the page table hierarchy (PML4->PDPT->PD->PT) to perform
   * virtual-to-physical address translation. Supports 4KB pages, 2MB large pages,
   * and 1GB huge pages with proper detection at each level.
   */
  auto virt_to_phys_via_pml4(uintptr_t pml4_pa, uintptr_t va) -> uintptr_t;

  /**
   * @brief Calculate the minimum number of bytes needed for hook installation
   * @param target_pa Physical address of the target function
   * @param min_size Minimum required size for the hook (default: 12 bytes)
   * @return Total size in bytes, or 0 if disassembly fails
   *
   * Uses HDE (Hacker Disassembler Engine) to analyze instruction boundaries
   * and ensure the hook doesn't split instructions. Returns the cumulative
   * size of complete instructions that meet the minimum size requirement.
   */
  auto calculate_hook_size(uintptr_t target_pa, size_t min_size = 12) -> size_t;

  /**
   * @brief Create a trampoline function containing original instructions
   * @param target_va Virtual address of the original function
   * @param target_pa Physical address of the original function
   * @param original_bytes Buffer containing the original instruction bytes
   * @param hook_size Number of bytes being hooked
   * @return Virtual address of the trampoline, or 0 on failure
   *
   * Allocates executable memory and creates a trampoline containing the original
   * instructions followed by a jump back to the continuation point. This allows
   * the original function to be called from hook handlers.
   */
  auto create_trampoline(uintptr_t target_va, uintptr_t target_pa, uint8_t* original_bytes,
                         size_t hook_size) -> uintptr_t;

  /**
   * @brief Install a function hook using direct physical memory modification
   * @param pml4_pa Physical address of the target process's PML4 table
   * @param target_va Virtual address of the function to hook
   * @param hook_function Address of the hook handler function
   * @param info Pointer to hook_info structure to store hook metadata
   * @return true if hook installation succeeded, false otherwise
   *
   * Installs a function hook by directly modifying physical memory.
   * Creates a trampoline for calling the original function and
   * overwrites the target with a jump to the hook handler.
   */
  auto install_hook_physical(uintptr_t pml4_pa, uintptr_t target_va, uintptr_t hook_function,
                             hook_info* info) -> bool;

  /**
   * @brief Remove a previously installed hook and restore original function
   * @param info Pointer to hook_info structure containing hook metadata
   * @return true if hook removal succeeded, false otherwise
   *
   * Restores the original function bytes from the saved copy and frees
   * the allocated trampoline memory. Completely reverses the hook installation.
   */
  auto remove_hook_physical(hook_info* info) -> bool;

}  // namespace pt_hook
