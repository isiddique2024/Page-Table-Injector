#pragma once
namespace init
{

    auto install_hook(const void* func) -> NTSTATUS {


        globals::hook_pointer = *reinterpret_cast<std::uintptr_t*>(globals::hook_address);

        uint8_t shellcode[globals::SHELL_SIZE] = {
            0x48, 0xB8,                   // mov rax, imm64
            0x00, 0x00, 0x00, 0x00,       // placeholder for lower 32 bits of request_handler::handle
            0x00, 0x00, 0x00, 0x00,       // placeholder for upper 32 bits of request_handler::handle
            0x50,                         // push rax 
            0xC3                          // ret 
        };

        uint32_t section_size = 0;

        // find section base of .data in ntoskrnl
        void* section_base = pte::find_section_base(reinterpret_cast<void*>(globals::ntos_base), &section_size, ".data", 5); 
        if (!section_base) {
            log("ERROR", "failed to find section in driver");
            return STATUS_UNSUCCESSFUL;
        }

        // last argument is size of shellcode below
        void* target_address = pte::find_unused_space(section_base, section_size, globals::SHELL_SIZE); 
        if (!target_address) {
            log("ERROR", "failed to find unused space in section of driver");
            return STATUS_UNSUCCESSFUL;
        }

        // assign func ptr
        *reinterpret_cast<uintptr_t*>(&shellcode[2]) = reinterpret_cast<uintptr_t>(func);

        memcpy(target_address, shellcode, globals::SHELL_SIZE);

        log("INFO", "shellcode written at addr : 0x%p", target_address);

        // spoof page table entries to make the target address executable
        if (!pte::spoof_pte_range(reinterpret_cast<uintptr_t>(target_address), globals::SHELL_SIZE, false)) {
            log("ERROR", "failed to spoof pte range at target address");
            return STATUS_UNSUCCESSFUL;
        }

        //cache for unloading 
        *reinterpret_cast<std::uintptr_t*>(globals::hook_address) = reinterpret_cast<uintptr_t>(target_address);

        globals::shell_address = target_address;

        log("INFO", "hook installed successfully");

        return STATUS_SUCCESS;
    }


    auto scan_offsets(pdb_offsets& local_offsets) -> NTSTATUS {
        if (globals::initialized) return STATUS_NOT_FOUND;

        globals::ntos_base = reinterpret_cast<uintptr_t>(utils::get_ntos_base());
        if (!globals::ntos_base) {
            log("ERROR", "failed to get ntoskrnl base");
            return STATUS_NOT_FOUND;
        }

        globals::mm_allocate_independent_pages_ex = reinterpret_cast<function_types::mm_allocate_independent_pages_ex_t>(local_offsets.MmAllocateIndependentPages);
        globals::mm_free_independent_pages = reinterpret_cast<function_types::mm_free_independent_pages>(local_offsets.MmFreeIndependentPages);
        globals::mi_reserve_ptes = reinterpret_cast<function_types::mi_reserve_ptes_t>(local_offsets.MiReservePtes);
        globals::mi_get_pte_address = reinterpret_cast<function_types::mi_get_pte_address_t>(local_offsets.MiGetPteAddress);
        globals::mi_remove_physical_memory = reinterpret_cast<function_types::mi_remove_physical_memory_t>(local_offsets.MiRemovePhysicalMemory);
        globals::mi_flush_entire_tb_due_to_attribute_change = reinterpret_cast<function_types::mi_flush_entire_tb_due_to_attribute_change_t>(local_offsets.MiFlushEntireTbDueToAttributeChange);
        globals::mi_flush_cache_range = reinterpret_cast<function_types::mi_flush_cache_range_t>(local_offsets.MiFlushCacheRange);
        globals::active_process_links = local_offsets.ActiveProcessLinks;


        globals::hook_address = scan(
            globals::ntos_base,
            ("48 8B 05 ? ? ? ? 75 07 48 8B 05 ? ? ? ? E8 ? ? ? ?")
        ).resolve_lea();

        if (!globals::hook_address) {
            log("ERROR", "hook pattern not found in ntoskrnl 1");
            globals::hook_address = scan((uintptr_t)utils::get_ntos_base(), ("48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 05 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? C6 05 ? ? ? ? ? E8 ? ? ? ? 48 63 D8")).resolve_lea();
            if (!globals::hook_address) {
                log("ERROR", "hook pattern not found in ntoskrnl 2");
                globals::hook_address = scan(globals::ntos_base, ("48 8B 05 ? ? ? ? 74 49 E8 ? ? ? ? 8B C8")).resolve_mov();
                if (!globals::hook_address) {
                    log("ERROR", "hook pattern not found in ntoskrnl 3");
                    return STATUS_NOT_FOUND;
                }
            }
        }

        globals::mm_pfn_db = scan(globals::ntos_base, ("48 8B 05 ? ? ? ? 48 89 43 18 48 8D 05")).resolve_mov<ULONG_PTR>();
        if (!globals::mm_pfn_db) {
            log("ERROR", "failed to find or resolve MmPfnDatabase");
            return STATUS_NOT_FOUND;
        }

        globals::mi_get_pte_address = scan(globals::ntos_base, ("E8 ? ? ? ? 49 F7 C1 ? ? ? ? B9 ? ? ? ? 4C 8B C0 0F 95 C1")).resolve_call<function_types::mi_get_pte_address_t>();
        if (!globals::mi_get_pte_address) {
            log("ERROR", "failed to find or resolve MiGetPteAddress");
            return STATUS_NOT_FOUND;
        }

        globals::build_version = utils::get_windows_version();

        UNICODE_STRING routine_name;
        RtlInitUnicodeString(&routine_name, L"KeFlushEntireTb");
        globals::ke_flush_entire_tb = (function_types::ke_flush_entire_tb_t)(MmGetSystemRoutineAddress)(&routine_name);
        if (!globals::ke_flush_entire_tb) {
            log("ERROR", "failed to find export KeFlushEntireTb");
            return STATUS_NOT_FOUND;
        }

        RtlInitUnicodeString(&routine_name, L"KeInvalidateAllCaches");
        globals::ke_invalidate_all_caches = (function_types::ke_invalidate_all_caches_t)(MmGetSystemRoutineAddress)(&routine_name);
        if (!globals::ke_invalidate_all_caches) {
            log("ERROR", "failed to find export KeInvalidateAllCaches");
            return STATUS_NOT_FOUND;
        }

        globals::initialized = true;

        return STATUS_SUCCESS;
    }

    auto hide_driver_pages(const uintptr_t address, const uintptr_t size) -> NTSTATUS
    {
        log("INFO", "starting to hide pages at address 0x%llx with size 0x%llx", address, size);

        const auto cr3 = [&] {
            CR3 temp{};
            temp.Flags = __readcr3();
            return temp;
            }();

        LARGE_INTEGER number_of_bytes;
        number_of_bytes.QuadPart = PAGE_SIZE;

        uint64_t last_pml4e_index = ~0ull;
        uint64_t last_pdpte_index = ~0ull;
        uint64_t last_pde_index = ~0ull;

        for (uintptr_t current_addr = address; current_addr < address + size; current_addr += PAGE_SIZE) {
            // calculate current indices
            const uint64_t pml4e_index = (current_addr >> 39) & 0x1FF;
            const uint64_t pdpte_index = (current_addr >> 30) & 0x1FF;
            const uint64_t pde_index = (current_addr >> 21) & 0x1FF;

            const auto page_info = pte::get_page_information(reinterpret_cast<void*>(current_addr), cr3);
            if (!page_info.PTE) {
                log("ERROR", "failed to get PTE for address 0x%llx", current_addr);
                continue;
            }

            // top down to avoid race conditions: PML4E -> PDPTE -> PDE -> PTE
            if (page_info.PML4E && pml4e_index != last_pml4e_index) {
                PHYSICAL_ADDRESS pml4e_physical;
                pml4e_physical.QuadPart = static_cast<LONGLONG>(page_info.PML4E->PageFrameNumber) << PAGE_SHIFT;
                if (pml4e_physical.QuadPart) {
                    NTSTATUS status = MmMarkPhysicalMemoryAsBad(&pml4e_physical, &number_of_bytes);
                    if (!NT_SUCCESS(status)) {
                        log("ERROR", "failed to mark PML4E physical memory at 0x%llx status 0x%X", pml4e_physical.QuadPart, status);
                        continue;
                    }
                    log("INFO", "marked PML4E as bad for address 0x%llx, physical address 0x%llx", current_addr, pml4e_physical.QuadPart);
                    last_pml4e_index = pml4e_index;
                }
            }

            if (page_info.PDPTE && (pml4e_index != last_pml4e_index || pdpte_index != last_pdpte_index)) {
                PHYSICAL_ADDRESS pdpte_physical;
                pdpte_physical.QuadPart = static_cast<LONGLONG>(page_info.PDPTE->PageFrameNumber) << PAGE_SHIFT;
                if (pdpte_physical.QuadPart) {
                    NTSTATUS status = MmMarkPhysicalMemoryAsBad(&pdpte_physical, &number_of_bytes);
                    if (!NT_SUCCESS(status)) {
                        log("ERROR", "failed to mark PDPTE physical memory at 0x%llx status 0x%X", pdpte_physical.QuadPart, status);
                        continue;
                    }
                    log("INFO", "marked PDPTE as bad for address 0x%llx, physical address 0x%llx", current_addr, pdpte_physical.QuadPart);
                    last_pdpte_index = pdpte_index;
                }
            }

            if (page_info.PDE && (pml4e_index != last_pml4e_index || pdpte_index != last_pdpte_index || pde_index != last_pde_index)) {
                PHYSICAL_ADDRESS pde_physical;
                pde_physical.QuadPart = static_cast<LONGLONG>(page_info.PDE->PageFrameNumber) << PAGE_SHIFT;
                if (pde_physical.QuadPart) {
                    NTSTATUS status = MmMarkPhysicalMemoryAsBad(&pde_physical, &number_of_bytes);
                    if (!NT_SUCCESS(status)) {
                        log("ERROR", "failed to mark PDE physical memory at 0x%llx status 0x%X", pde_physical.QuadPart, status);
                        continue;
                    }
                    log("INFO", "marked PDE as bad for address 0x%llx, physical address 0x%llx", current_addr, pde_physical.QuadPart);
                    last_pde_index = pde_index;
                }
            }

            if (page_info.PTE) {
                PHYSICAL_ADDRESS pte_physical;
                pte_physical.QuadPart = static_cast<LONGLONG>(page_info.PTE->PageFrameNumber) << PAGE_SHIFT;
                if (pte_physical.QuadPart) {
                    NTSTATUS status = MmMarkPhysicalMemoryAsBad(&pte_physical, &number_of_bytes);
                    if (!NT_SUCCESS(status)) {
                        log("ERROR", "failed to mark PTE physical memory at 0x%llx status 0x%X", pte_physical.QuadPart, status);
                        continue;
                    }
                    log("INFO", "marked PTE as bad for address 0x%llx, physical address 0x%llx", current_addr, pte_physical.QuadPart);
                }
            }
        }

        log("INFO", "completed marking pages from 0x%llx to 0x%llx", address, address + size);
        return STATUS_SUCCESS;
    }

}
