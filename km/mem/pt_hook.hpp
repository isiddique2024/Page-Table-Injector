#include "hde/hde.h"

#pragma warning(push)
#pragma warning(disable:4706)

namespace pt_hook
{
    // mov rax shellcode
    static const uint8_t mov_rax_shellcode[] = {
        0x48, 0xB8,                   // mov rax, imm64
        0x00, 0x00, 0x00, 0x00,       // placeholder for lower 32 bits of hook function
        0x00, 0x00, 0x00, 0x00,       // placeholder for upper 32 bits of hook function
        0x50,                         // push rax 
        0xC3                          // ret 
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

    // get physical address from virtual address using page tables
    uintptr_t virt_to_phys_via_pml4(uintptr_t pml4_pa, uintptr_t va) {
        uint32_t pml4_idx = (va >> 39) & 0x1FF;
        uint32_t pdpt_idx = (va >> 30) & 0x1FF;
        uint32_t pd_idx = (va >> 21) & 0x1FF;
        uint32_t pt_idx = (va >> 12) & 0x1FF;
        uint32_t page_offset = va & 0xFFF;

        // read PML4E
        PML4E_64 pml4e = { 0 };
        if (!NT_SUCCESS(physical::read_physical_address(pml4_pa + pml4_idx * 8, &pml4e, sizeof(pml4e)))) {
            return 0;
        }
        if (!pml4e.Present) return 0;

        // read PDPTE
        PDPTE_64 pdpte = { 0 };
        uintptr_t pdpt_pa = pml4e.PageFrameNumber << 12;
        if (!NT_SUCCESS(physical::read_physical_address(pdpt_pa + pdpt_idx * 8, &pdpte, sizeof(pdpte)))) {
            return 0;
        }
        if (!pdpte.Present) return 0;

        // read PDE
        PDE_64 pde = { 0 };
        uintptr_t pd_pa = pdpte.PageFrameNumber << 12;
        if (!NT_SUCCESS(physical::read_physical_address(pd_pa + pd_idx * 8, &pde, sizeof(pde)))) {
            return 0;
        }
        if (!pde.Present) return 0;

        // check if it's a large page
        if (pde.LargePage) {
            // 2MB large page
            return (pde.PageFrameNumber << 12) + (va & 0x1FFFFF);
        }

        // read PTE for 4KB page
        PTE_64 pte = { 0 };
        uintptr_t pt_pa = pde.PageFrameNumber << 12;
        if (!NT_SUCCESS(physical::read_physical_address(pt_pa + pt_idx * 8, &pte, sizeof(pte)))) {
            return 0;
        }
        if (!pte.Present) return 0;

        return (pte.PageFrameNumber << 12) + page_offset;
    }

    // calc the length of instructions we need to overwrite
    //size_t calculate_hook_size(uintptr_t target_pa, size_t min_size = 14) {
    //    uint8_t buffer[64];
    //    if (!NT_SUCCESS(physical::read_physical_address(target_pa, buffer, sizeof(buffer)))) {
    //        return 0;
    //    }

    //    size_t total_len = 0;
    //    while (total_len < min_size && total_len < sizeof(buffer)) {
    //        hde64s hde;
    //        HdeDisassemble(&buffer[total_len], &hde);
    //        if (hde.len == 0) break;
    //        total_len += hde.len;
    //    }

    //    return total_len;
    //}

    //// create trampoline function
    //uintptr_t create_trampoline(uintptr_t target_va, uintptr_t target_pa, uint8_t* original_bytes, size_t hook_size) {
    //    // alloc memory for trampoline
    //    auto trampoline = reinterpret_cast<uint8_t*>(
    //        mem::allocate_independent_pages(0x100));
    //    if (!trampoline) {
    //        return 0;
    //    }

    //    // copy original instructions
    //    globals::memcpy(trampoline, original_bytes, hook_size);

    //    // add jump back to original function after hook
    //    LARGE_INTEGER jmp_back = { .QuadPart = static_cast<int64_t>(target_va + hook_size) };
    //    globals::memcpy(&trampoline[hook_size], jmp_code, sizeof(jmp_code));
    //    globals::memcpy(&trampoline[hook_size + 1], &jmp_back.LowPart, sizeof(uint32_t));
    //    globals::memcpy(&trampoline[hook_size + 9], &jmp_back.HighPart, sizeof(uint32_t));

    //    bool set_page_protection = globals::mm_set_page_protection(reinterpret_cast<uintptr_t>(trampoline), 0x100, PAGE_EXECUTE_READWRITE);
    //    if (!set_page_protection) {
    //        return 0;
    //    }

    //    return reinterpret_cast<uintptr_t>(trampoline);
    //}

      // calc the length of instructions we need to overwrite
    size_t calculate_hook_size(uintptr_t target_pa, size_t min_size = 12) {
        uint8_t buffer[64];
        if (!NT_SUCCESS(physical::read_physical_address(target_pa, buffer, sizeof(buffer)))) {
            return 0;
        }

        size_t total_len = 0;
        while (total_len < min_size && total_len < sizeof(buffer)) {
            hde64s hde;
            HdeDisassemble(&buffer[total_len], &hde);
            if (hde.len == 0) break;
            total_len += hde.len;
        }

        return total_len;
    }

    // create trampoline function
    uintptr_t create_trampoline(uintptr_t target_va, uintptr_t target_pa, uint8_t* original_bytes, size_t hook_size) {
        // alloc memory for trampoline
        auto trampoline = reinterpret_cast<uint8_t*>(
            mem::allocate_independent_pages(0x100));
        if (!trampoline) {
            return 0;
        }

        // copy original instructions
        globals::memcpy(trampoline, original_bytes, hook_size);

        // add jump back to original function after hook
        uintptr_t jmp_back = target_va + hook_size;
        globals::memcpy(&trampoline[hook_size], mov_rax_shellcode, sizeof(mov_rax_shellcode));
        globals::memcpy(&trampoline[hook_size + 2], &jmp_back, sizeof(uintptr_t));

        bool set_page_protection = globals::mm_set_page_protection(reinterpret_cast<uintptr_t>(trampoline), 0x100, PAGE_EXECUTE_READWRITE);
        if (!set_page_protection) {
            return 0;
        }

        return reinterpret_cast<uintptr_t>(trampoline);
    }

    // Install hook using physical memory operations
    bool install_hook_physical(uintptr_t pml4_pa, uintptr_t target_va, uintptr_t hook_function, hook_info* info) {
        if (!info) return false;

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
        if (!NT_SUCCESS(physical::read_physical_address(target_pa, info->original_bytes, info->hook_size))) {
            log("ERROR", "failed to read original bytes");
            return false;
        }

        // create trampoline
        info->original_function = create_trampoline(target_va, target_pa, info->original_bytes, info->hook_size);
        if (!info->original_function) {
            log("ERROR", "failed to create trampoline");
            return false;
        }

        // write hook jump
        uint8_t hook_bytes[12];
        globals::memcpy(hook_bytes, mov_rax_shellcode, sizeof(mov_rax_shellcode));
        globals::memcpy(&hook_bytes[2], &hook_function, sizeof(uintptr_t));

        // apply the hook
        if (!NT_SUCCESS(physical::write_physical_address(target_pa, hook_bytes, sizeof(mov_rax_shellcode)))) {
            log("ERROR", "failed to write hook bytes");
            globals::mm_free_independent_pages(info->original_function, 0x100);
            return false;
        }

        // fill remaining bytes with NOPs if needed
        if (info->hook_size > sizeof(mov_rax_shellcode)) {
            uint8_t nops[32];
            globals::memset(nops, 0x90, sizeof(nops));
            size_t nop_count = info->hook_size - sizeof(mov_rax_shellcode);
            if (!NT_SUCCESS(physical::write_physical_address(target_pa + sizeof(mov_rax_shellcode), nops, nop_count))) {
                log("WARNING", "failed to write NOP padding");
            }
        }


        info->initialized = true;
        log("SUCCESS", "hook installed at 0x%llx (PA: 0x%llx)", target_va, target_pa);
        return true;
    }

    // remove hook
    bool remove_hook_physical(hook_info* info) {
        if (!info || !info->initialized) return false;

        // restore original bytes
        if (!NT_SUCCESS(physical::write_physical_address(info->target_pa, info->original_bytes, info->hook_size))) {
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

}


