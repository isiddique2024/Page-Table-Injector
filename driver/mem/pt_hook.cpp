#include "../hde/hde.h"

#pragma warning(push)
#pragma warning(disable : 4706)
#include "../def/globals.hpp"
#include "phys.hpp"
#include "mem.hpp"
namespace pt_hook {

  const uint8_t mov_rax_shellcode[] = {
      0x48, 0xB8,              // mov rax, imm64
      0x00, 0x00, 0x00, 0x00,  // placeholder for lower 32 bits of hook function
      0x00, 0x00, 0x00, 0x00,  // placeholder for upper 32 bits of hook function
      0x50,                    // push rax
      0xC3                     // ret
  };

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
  auto virt_to_phys_via_pml4(uintptr_t pml4_pa, uintptr_t va) -> uintptr_t {
    ADDRESS_TRANSLATION_HELPER addr_helper = {0};
    addr_helper.AsUInt64 = va;

    // read PML4E
    PML4E_64 pml4e = {0};
    if (!NT_SUCCESS(physical::read_physical_address(pml4_pa + addr_helper.AsIndex.Pml4 * 8, &pml4e,
                                                    sizeof(pml4e)))) {
      return 0;
    }
    if (!pml4e.Present)
      return 0;

    // read PDPTE
    PDPTE_64 pdpte = {0};
    uintptr_t pdpt_pa = PFN_TO_PAGE(pml4e.PageFrameNumber);
    if (!NT_SUCCESS(physical::read_physical_address(pdpt_pa + addr_helper.AsIndex.Pdpt * 8, &pdpte,
                                                    sizeof(pdpte)))) {
      return 0;
    }
    if (!pdpte.Present)
      return 0;

    // check for 1GB huge page at PDPT level
    if (pdpte.LargePage) {
      return PFN_TO_PAGE(pdpte.PageFrameNumber) + addr_helper.AsPageOffset.Mapping1Gb;
    }

    // read PDE
    PDE_64 pde = {0};
    uintptr_t pd_pa = PFN_TO_PAGE(pdpte.PageFrameNumber);
    if (!NT_SUCCESS(physical::read_physical_address(pd_pa + addr_helper.AsIndex.Pd * 8, &pde,
                                                    sizeof(pde)))) {
      return 0;
    }
    if (!pde.Present)
      return 0;

    // check for 2MB large page at PD level
    if (pde.LargePage) {
      return PFN_TO_PAGE(pde.PageFrameNumber) + addr_helper.AsPageOffset.Mapping2Mb;
    }

    // read PTE for 4KB page
    PTE_64 pte = {0};
    uintptr_t pt_pa = PFN_TO_PAGE(pde.PageFrameNumber);
    if (!NT_SUCCESS(physical::read_physical_address(pt_pa + addr_helper.AsIndex.Pt * 8, &pte,
                                                    sizeof(pte)))) {
      return 0;
    }
    if (!pte.Present)
      return 0;

    // 4KB page
    return PFN_TO_PAGE(pte.PageFrameNumber) + addr_helper.AsPageOffset.Mapping4Kb;
  }

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
  auto calculate_hook_size(uintptr_t target_pa, size_t min_size = 12) -> size_t {
    uint8_t buffer[64];
    if (!NT_SUCCESS(physical::read_physical_address(target_pa, buffer, sizeof(buffer)))) {
      return 0;
    }

    size_t total_len = 0;
    while (total_len < min_size && total_len < sizeof(buffer)) {
      hde64s hde;
      HdeDisassemble(&buffer[total_len], &hde);
      if (hde.len == 0)
        break;
      total_len += hde.len;
    }

    return total_len;
  }

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
                         size_t hook_size) -> uintptr_t {
    // alloc memory for trampoline
    auto trampoline = reinterpret_cast<uint8_t*>(mem::allocate_independent_pages(0x100));
    if (!trampoline) {
      return 0;
    }

    // copy original instructions
    globals::memcpy(trampoline, original_bytes, hook_size);

    // add jump back to original function after hook
    uintptr_t jmp_back = target_va + hook_size;
    globals::memcpy(&trampoline[hook_size], mov_rax_shellcode, sizeof(mov_rax_shellcode));
    globals::memcpy(&trampoline[hook_size + 2], &jmp_back, sizeof(uintptr_t));

    bool set_page_protection = globals::mm_set_page_protection(
        reinterpret_cast<uintptr_t>(trampoline), 0x100, PAGE_EXECUTE_READWRITE);
    if (!set_page_protection) {
      return 0;
    }

    return reinterpret_cast<uintptr_t>(trampoline);
  }

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
                             pt_hook::hook_info* info) -> bool {
    if (!info)
      return false;

    // get physical address of target
    uintptr_t target_pa = virt_to_phys_via_pml4(pml4_pa, target_va);
    if (!target_pa) {
      log("ERROR", "failed to get physical address for target 0x%llx", target_va);
      return false;
    }

    info->target_va = target_va;
    info->target_pa = target_pa;
    info->hook_function = hook_function;

    // calc hook size
    info->hook_size = calculate_hook_size(target_pa);
    if (!info->hook_size) {
      log("ERROR", "failed to calculate hook size");
      return false;
    }

    log("INFO", "hook size calculated: %zu bytes", info->hook_size);

    // save original bytes
    if (!NT_SUCCESS(
            physical::read_physical_address(target_pa, info->original_bytes, info->hook_size))) {
      log("ERROR", "failed to read original bytes");
      return false;
    }

    // create trampoline
    info->original_function =
        create_trampoline(target_va, target_pa, info->original_bytes, info->hook_size);
    if (!info->original_function) {
      log("ERROR", "failed to create trampoline");
      return false;
    }

    // write hook jump
    uint8_t hook_bytes[12];
    globals::memcpy(hook_bytes, mov_rax_shellcode, sizeof(mov_rax_shellcode));
    globals::memcpy(&hook_bytes[2], &hook_function, sizeof(uintptr_t));

    // apply the hook
    if (!NT_SUCCESS(
            physical::write_physical_address(target_pa, hook_bytes, sizeof(mov_rax_shellcode)))) {
      log("ERROR", "failed to write hook bytes");
      globals::mm_free_independent_pages(info->original_function, 0x100);
      return false;
    }

    // fill remaining bytes with NOPs if needed
    if (info->hook_size > sizeof(mov_rax_shellcode)) {
      uint8_t nops[32];
      globals::memset(nops, 0x90, sizeof(nops));
      size_t nop_count = info->hook_size - sizeof(mov_rax_shellcode);
      if (!NT_SUCCESS(physical::write_physical_address(target_pa + sizeof(mov_rax_shellcode), nops,
                                                       nop_count))) {
        log("WARNING", "failed to write NOP padding");
      }
    }

    info->initialized = true;
    log("SUCCESS", "hook installed at 0x%llx (PA: 0x%llx)", target_va, target_pa);
    return true;
  }

  /**
   * @brief Remove a previously installed hook and restore original function
   * @param info Pointer to hook_info structure containing hook metadata
   * @return true if hook removal succeeded, false otherwise
   *
   * Restores the original function bytes from the saved copy and frees
   * the allocated trampoline memory. Completely reverses the hook installation.
   */
  auto remove_hook_physical(hook_info* info) -> bool {
    if (!info || !info->initialized)
      return false;

    // restore original bytes
    if (!NT_SUCCESS(physical::write_physical_address(info->target_pa, info->original_bytes,
                                                     info->hook_size))) {
      log("ERROR", "failed to restore original bytes");
      return false;
    }

    // free trampoline
    if (info->original_function) {
      globals::mm_free_independent_pages(info->original_function, 0x100);
    }

    info->initialized = false;
    log("SUCCESS", "hook removed from 0x%llx", info->target_va);
    return true;
  }

}  // namespace pt_hook
