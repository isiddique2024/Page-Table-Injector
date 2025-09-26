#pragma once

/**
 * @brief Namespace containing intrinsic functions for low-level CPU operations
 *
 * This namespace provides cross-platform wrappers for CPU intrinsics and inline assembly,
 * supporting both MSVC and GCC/Clang compilers. All functions are intended for kernel-mode
 * or privileged code execution.
 */
namespace intrin {
#if defined(_MSC_VER) && !defined(__clang__)
  #include <intrin.h>
#endif

  /**
   * @brief Read the CR3 control register
   *
   * The CR3 register contains the physical address of the page directory base register (PDBR)
   * for the currently active page table. This is used by the Memory Management Unit (MMU)
   * for virtual-to-physical address translation.
   *
   * @return The current value of the CR3 register as a pointer-sized integer
   */
  uintptr_t readcr3(void);

  /**
   * @brief Get the maximum physical address width supported by the processor
   *
   * Executes CPUID with EAX=80000008h to query processor capabilities.
   * The returned value indicates how many bits are used for physical addressing.
   *
   * @return Number of physical address bits supported (typically 36, 39, 48, or 52)
   */
  uint32_t get_maxphyaddr(void);

  /**
   * @brief Check if the processor supports 1GB pages
   *
   * Queries CPUID function 80000001h to check for PDPE1GB support.
   * 1GB pages allow mapping large contiguous memory regions more efficiently
   * by reducing TLB pressure and page table overhead.
   *
   * @return true if 1GB pages are supported, false otherwise
   */
  bool supports_1gb_pages(void);

  /**
   * @brief Check if 5-level paging (LA57) is supported
   *
   * Queries CPUID function 7 (sub-function 0) to check for Linear Address 57-bit support.
   * LA57 extends virtual address space from 48 bits (256 TiB) to 57 bits (128 PiB)
   * by adding a fifth level to the page table hierarchy.
   *
   * @return true if 5-level paging is supported, false otherwise
   */
  bool supports_la57(void);

  /**
   * @brief Invalidate a single page in the Translation Lookaside Buffer (TLB)
   *
   * The INVLPG instruction invalidates the TLB entry for the specified virtual address.
   * This forces the processor to reload the page table entry on the next access,
   * ensuring coherency after page table modifications.
   *
   * @param m Virtual memory address of the page to invalidate
   * @warning The memory clobber prevents compiler reordering that could cause race conditions
   */
  void invlpg(void* m);

}  // namespace intrin