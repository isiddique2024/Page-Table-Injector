#pragma once

// https://github.com/SamuelTulach/DirectPageManipulation

namespace physical {
    inline PTE_NEW* main_page_entry;
    inline PVOID main_virtual_address;

    void* physical_to_virtual(const uintptr_t address)
    {
        PHYSICAL_ADDRESS physical{};
        physical.QuadPart = address;
        return MmGetVirtualForPhysical(physical);
    }

    NTSTATUS init()
    {
        PHYSICAL_ADDRESS max_address{};
        max_address.QuadPart = MAXULONG64;

        main_virtual_address = MmAllocateContiguousMemory(PAGE_SIZE, max_address);
        if (!main_virtual_address)
            return STATUS_INSUFFICIENT_RESOURCES;

        VIRTUAL_ADDRESS virtual_address{};
        virtual_address.Pointer = main_virtual_address;

        const PTE_CR3 cr3{ __readcr3() };

        auto* pml4 = static_cast<PML4E_NEW*>(physical_to_virtual(PFN_TO_PAGE(cr3.Pml4)));
        auto* pml4e = pml4 + virtual_address.Pml4Index;
        if (!pml4e->Present)
            return STATUS_NOT_FOUND;

        auto* pdpt = static_cast<PDPTE_NEW*>(physical_to_virtual(PFN_TO_PAGE(pml4e->Pdpt)));
        auto* pdpte = pdpt + virtual_address.PdptIndex;
        if (!pdpte->Present)
            return STATUS_NOT_FOUND;

        // sanity check 1GB page
        if (pdpte->PageSize)
            return STATUS_INVALID_PARAMETER;

        auto* pd = static_cast<PDE_NEW*>(physical_to_virtual(PFN_TO_PAGE(pdpte->Pd)));
        auto* pde = pd + virtual_address.PdIndex;
        if (!pde->Present)
            return STATUS_NOT_FOUND;

        // sanity check 2MB page
        if (pde->PageSize)
            return STATUS_INVALID_PARAMETER;

        auto* pt = static_cast<PTE_NEW*>(physical_to_virtual(PFN_TO_PAGE(pde->Pt)));
        auto* pte = pt + virtual_address.PtIndex;
        if (!pte->Present)
            return STATUS_NOT_FOUND;

        main_page_entry = pte;

        return STATUS_SUCCESS;
    }

    PVOID overwrite_page(const ULONG64 physical_address)
    {
        // page boundary checks are done by Read/WriteProcessMemory
        // and page entries are not spread over different pages
        const ULONG page_offset = physical_address % PAGE_SIZE;
        const ULONG64 page_start_physical = physical_address - page_offset;
        main_page_entry->PageFrame = PAGE_TO_PFN(page_start_physical);
        __invlpg(main_virtual_address);
        return reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(main_virtual_address) + page_offset);
    }

    NTSTATUS read_physical_address(const ULONG64 target_address, PVOID buffer, const SIZE_T size)
    {
        const auto virtual_address = overwrite_page(target_address);
        memcpy(buffer, virtual_address, size);
        return STATUS_SUCCESS;
    }

    NTSTATUS write_physical_address(const ULONG64 target_address, const PVOID buffer, const SIZE_T size)
    {
        const auto virtual_address = overwrite_page(target_address);
        memcpy(virtual_address, buffer, size);
        return STATUS_SUCCESS;
    }

#define PAGE_OFFSET_SIZE 12
    static constexpr ULONG64 PMASK = (~0xfull << 8) & 0xfffffffffull;

    ULONG64 translate_linear_address(ULONG64 directory_table_base, const ULONG64 virtual_address)
    {
        directory_table_base &= ~0xf;

        const ULONG64 page_offset = virtual_address & ~(~0ul << PAGE_OFFSET_SIZE);
        const ULONG64 pte = ((virtual_address >> 12) & (0x1ffll));
        const ULONG64 pt = ((virtual_address >> 21) & (0x1ffll));
        const ULONG64 pd = ((virtual_address >> 30) & (0x1ffll));
        const ULONG64 pdp = ((virtual_address >> 39) & (0x1ffll));

        ULONG64 pdpe = 0;
        read_physical_address(directory_table_base + 8 * pdp, &pdpe, sizeof(pdpe));
        if (~pdpe & 1)
            return 0;

        ULONG64 pde = 0;
        read_physical_address((pdpe & PMASK) + 8 * pd, &pde, sizeof(pde));
        if (~pde & 1)
            return 0;

        // 1GB large page, use pde's 12-34 bits
        if (pde & 0x80)
            return (pde & (~0ull << 42 >> 12)) + (virtual_address & ~(~0ull << 30));

        ULONG64 pte_addr = 0;
        read_physical_address((pde & PMASK) + 8 * pt, &pte_addr, sizeof(pte_addr));
        if (~pte_addr & 1)
            return 0;

        // 2MB large page
        if (pte_addr & 0x80)
            return (pte_addr & PMASK) + (virtual_address & ~(~0ull << 21));

        ULONG64 result_address = 0;
        read_physical_address((pte_addr & PMASK) + 8 * pte, &result_address, sizeof(result_address));
        result_address &= PMASK;

        if (!result_address)
            return 0;

        return result_address + page_offset;
    }

    uintptr_t get_process_directory_base(const PEPROCESS input_process)
    {
        const auto* process = reinterpret_cast<const unsigned char*>(input_process);
        const auto dir_base = *reinterpret_cast<const uintptr_t*>(process + 0x28);
        if (!dir_base)
        {
            const auto user_dir_base = *reinterpret_cast<const uintptr_t*>(process + 0x388);
            return user_dir_base;
        }
        return dir_base;
    }

    NTSTATUS read_process_memory(const PEPROCESS process, const ULONG64 address, PVOID buffer, const SIZE_T size)
    {
        if (!address)
            return STATUS_INVALID_PARAMETER;

        const auto process_dir_base = get_process_directory_base(process);
        SIZE_T current_offset = 0;
        SIZE_T total_size = size;

        while (total_size)
        {
            const auto current_physical_address = translate_linear_address(process_dir_base, address + current_offset);
            if (!current_physical_address)
                return STATUS_NOT_FOUND;

            const auto read_size = min(PAGE_SIZE - (current_physical_address & 0xFFF), total_size);
            const auto status = read_physical_address(
                current_physical_address,
                reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(buffer) + current_offset),
                read_size
            );

            if (!NT_SUCCESS(status) || !read_size)
                return status;

            total_size -= read_size;
            current_offset += read_size;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS write_process_memory(const PEPROCESS process, const ULONG64 address, const PVOID buffer, const SIZE_T size)
    {
        if (!address)
            return STATUS_INVALID_PARAMETER;

        const auto process_dir_base = get_process_directory_base(process);
        SIZE_T current_offset = 0;
        SIZE_T total_size = size;

        while (total_size)
        {
            const auto current_physical_address = translate_linear_address(process_dir_base, address + current_offset);
            if (!current_physical_address)
                return STATUS_NOT_FOUND;

            const auto write_size = min(PAGE_SIZE - (current_physical_address & 0xFFF), total_size);
            const auto status = write_physical_address(
                current_physical_address,
                reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(buffer) + current_offset),
                write_size
            );

            if (!NT_SUCCESS(status) || !write_size)
                return status;

            total_size -= write_size;
            current_offset += write_size;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS copy_memory(const PEPROCESS source_process, const PVOID source_address,
        const PEPROCESS target_process, const PVOID target_address, const SIZE_T buffer_size)
    {
        void* temp_buffer = globals::mm_allocate_independent_pages_ex(buffer_size, -1, 0, 0);
        if (!temp_buffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        const auto status = read_process_memory(source_process, reinterpret_cast<uintptr_t>(source_address), temp_buffer, buffer_size);
        if (NT_SUCCESS(status))
        {
            write_process_memory(target_process, reinterpret_cast<uintptr_t>(target_address), temp_buffer, buffer_size);
        }

        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(temp_buffer), buffer_size);
        return status;
    }

    PEPROCESS find_proc(const wchar_t* executable_name, PVOID* main_module_base_address)
    {
        const auto current_process = IoGetCurrentProcess();
        const auto list = reinterpret_cast<PLIST_ENTRY>(
            reinterpret_cast<PCHAR>(current_process) + globals::active_process_links
            );

        auto* current_list = list->Flink;
        while (current_list != reinterpret_cast<PLIST_ENTRY>(
            reinterpret_cast<PCHAR>(current_process) + globals::active_process_links))
        {
            const auto target_process = reinterpret_cast<PEPROCESS>(
                reinterpret_cast<PCHAR>(current_list) - globals::active_process_links
                );

            const auto peb_address = PsGetProcessPeb(target_process);
            if (!peb_address)
            {
                current_list = current_list->Flink;
                continue;
            }

            PEB peb_local{};
            copy_memory(target_process, peb_address, current_process, &peb_local, sizeof(PEB));

            PEB_LDR_DATA loader_data{};
            copy_memory(target_process, peb_local.Ldr, current_process, &loader_data, sizeof(PEB_LDR_DATA));

            auto* current_list_entry = loader_data.InMemoryOrderModuleList.Flink;
            while (true)
            {
                LIST_ENTRY list_entry_local{};
                copy_memory(target_process, current_list_entry, current_process, &list_entry_local, sizeof(LIST_ENTRY));

                if (loader_data.InMemoryOrderModuleList.Flink == list_entry_local.Flink || !list_entry_local.Flink)
                    break;

                const auto entry_address = CONTAINING_RECORD(current_list_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                LDR_DATA_TABLE_ENTRY entry_local{};
                copy_memory(target_process, entry_address, current_process, &entry_local, sizeof(LDR_DATA_TABLE_ENTRY));

                wchar_t module_name[256]{};
                copy_memory(
                    target_process,
                    entry_local.BaseDllName.Buffer,
                    current_process,
                    module_name,
                    min(entry_local.BaseDllName.Length, static_cast<USHORT>(256))
                );

                UNICODE_STRING module_path_str{};
                module_path_str.Buffer = module_name;
                module_path_str.Length = min(entry_local.BaseDllName.Length, static_cast<USHORT>(256));
                module_path_str.MaximumLength = min(entry_local.BaseDllName.MaximumLength, static_cast<USHORT>(256));

                UNICODE_STRING module_name_str{};
                RtlInitUnicodeString(&module_name_str, executable_name);

                if (RtlCompareUnicodeString(&module_path_str, &module_name_str, TRUE) == 0)
                {
                    *main_module_base_address = entry_local.DllBase;
                    return target_process;
                }

                current_list_entry = list_entry_local.Flink;
            }

            current_list = current_list->Flink;
        }
        return nullptr;
    }
}
