//#pragma once
//#include <ntstatus.h>
//
//// Converted to use intel_driver functions
//// Based on https://github.com/SamuelTulach/DirectPageManipulation
//#pragma once
//#define PFN_TO_PAGE(pfn) ( pfn << 12 )
//#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)
//#define PAGE_SIZE 0x1000
//
//#pragma warning(push)
//#pragma warning(disable : 4201) // nonstandard extension used: nameless struct/union
//
//#pragma pack(push, 1)
//typedef union CR3_
//{
//    ULONG64 Value;
//    struct
//    {
//        ULONG64 Ignored1 : 3;
//        ULONG64 WriteThrough : 1;
//        ULONG64 CacheDisable : 1;
//        ULONG64 Ignored2 : 7;
//        ULONG64 Pml4 : 40;
//        ULONG64 Reserved : 12;
//    };
//} PTE_CR3;
//
//typedef union VIRT_ADDR_
//{
//    ULONG64 Value;
//    void* Pointer;
//    struct
//    {
//        ULONG64 Offset : 12;
//        ULONG64 PtIndex : 9;
//        ULONG64 PdIndex : 9;
//        ULONG64 PdptIndex : 9;
//        ULONG64 Pml4Index : 9;
//        ULONG64 Reserved : 16;
//    };
//} VIRTUAL_ADDRESS;
//
//typedef union PML4E_
//{
//    ULONG64 Value;
//    struct
//    {
//        ULONG64 Present : 1;
//        ULONG64 Rw : 1;
//        ULONG64 User : 1;
//        ULONG64 WriteThrough : 1;
//        ULONG64 CacheDisable : 1;
//        ULONG64 Accessed : 1;
//        ULONG64 Ignored1 : 1;
//        ULONG64 Reserved1 : 1;
//        ULONG64 Ignored2 : 4;
//        ULONG64 Pdpt : 40;
//        ULONG64 Ignored3 : 11;
//        ULONG64 Xd : 1;
//    };
//} PML4E_NEW;
//
//typedef union PDPTE_
//{
//    ULONG64 Value;
//    struct
//    {
//        ULONG64 Present : 1;
//        ULONG64 Rw : 1;
//        ULONG64 User : 1;
//        ULONG64 WriteThrough : 1;
//        ULONG64 CacheDisable : 1;
//        ULONG64 Accessed : 1;
//        ULONG64 Dirty : 1;
//        ULONG64 PageSize : 1;
//        ULONG64 Ignored2 : 4;
//        ULONG64 Pd : 40;
//        ULONG64 Ignored3 : 11;
//        ULONG64 Xd : 1;
//    };
//} PDPTE_NEW;
//
//typedef union PDE_
//{
//    ULONG64 Value;
//    struct
//    {
//        ULONG64 Present : 1;
//        ULONG64 Rw : 1;
//        ULONG64 User : 1;
//        ULONG64 WriteThrough : 1;
//        ULONG64 CacheDisable : 1;
//        ULONG64 Accessed : 1;
//        ULONG64 Dirty : 1;
//        ULONG64 PageSize : 1;
//        ULONG64 Ignored2 : 4;
//        ULONG64 Pt : 40;
//        ULONG64 Ignored3 : 11;
//        ULONG64 Xd : 1;
//    };
//} PDE_NEW;
//
//typedef union PTE_
//{
//    ULONG64 Value;
//    VIRTUAL_ADDRESS VirtualAddress;
//    struct
//    {
//        ULONG64 Present : 1;
//        ULONG64 Rw : 1;
//        ULONG64 User : 1;
//        ULONG64 WriteThrough : 1;
//        ULONG64 CacheDisable : 1;
//        ULONG64 Accessed : 1;
//        ULONG64 Dirty : 1;
//        ULONG64 Pat : 1;
//        ULONG64 Global : 1;
//        ULONG64 Ignored1 : 3;
//        ULONG64 PageFrame : 40;
//        ULONG64 Ignored3 : 11;
//        ULONG64 Xd : 1;
//    };
//} PTE_NEW;
//#pragma pack(pop)
//
//#pragma warning(pop)
//
//namespace physical {
//    inline PTE_64* main_page_entry;
//    inline void* main_virtual_address;
//    inline HANDLE driver_handle;
//
//    // Helper function to get PEPROCESS from PID via kernel
//    uintptr_t get_peprocess_from_pid(HANDLE device_handle, DWORD process_id) {
//        static uint64_t kernel_PsLookupProcessByProcessId = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "PsLookupProcessByProcessId");
//        if (!kernel_PsLookupProcessByProcessId) {
//            return 0;
//        }
//
//        uintptr_t process_object = 0;
//        NTSTATUS status = 0;
//
//        if (!intel_driver::CallKernelFunction(device_handle, &status, kernel_PsLookupProcessByProcessId,
//            reinterpret_cast<HANDLE>(static_cast<uintptr_t>(process_id)), &process_object)) {
//            return 0;
//        }
//
//        if (!NT_SUCCESS(status)) {
//            return 0;
//        }
//
//        return process_object;
//    }
//
//    //// Helper to dereference the process object when done
//    //void dereference_process(HANDLE device_handle, uintptr_t process_object) {
//    //    void* test = 0;
//    //    static uint64_t kernel_ObfDereferenceObject = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ObfDereferenceObject");
//    //    if (kernel_ObfDereferenceObject) {
//    //        intel_driver::CallKernelFunction(device_handle, , kernel_ObfDereferenceObject, reinterpret_cast<void*>(process_object));
//    //    }
//    //}
//
//    void* physical_to_virtual(HANDLE device_handle, const uintptr_t address)
//    {
//        PHYSICAL_ADDRESS physical{};
//        physical.QuadPart = address;
//
//        static uint64_t kernel_MmGetVirtualForPhysical = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmGetVirtualForPhysical");
//        if (!kernel_MmGetVirtualForPhysical) {
//            return nullptr;
//        }
//
//        void* virtual_addr = nullptr;
//        if (!intel_driver::CallKernelFunction(device_handle, &virtual_addr, kernel_MmGetVirtualForPhysical, physical)) {
//            return nullptr;
//        }
//
//        return virtual_addr;
//    }
//
//
//    NTSTATUS init(HANDLE device_handle)
//    {
//        driver_handle = device_handle;
//
//        // Allocate main virtual address using AllocIndependentPages
//        uintptr_t allocated_addr = kdmapper::AllocIndependentPages(device_handle, PAGE_SIZE);
//        if (!allocated_addr) {
//            return STATUS_INSUFFICIENT_RESOURCES;
//        }
//
//        main_virtual_address = reinterpret_cast<void*>(allocated_addr);
//
//        VIRTUAL_ADDRESS virtual_address{};
//        virtual_address.Pointer = main_virtual_address;
//
//        // Get CR3 from current process
//        uintptr_t cr3 = GetCurrentProcessCR3(device_handle);
//        if (!cr3) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        PTE_CR3 cr3_struct;
//        cr3_struct.Pml4 = cr3;
//
//        auto pml4_physical = PFN_TO_PAGE(cr3_struct.Pml4);
//        auto* pml4_virtual = static_cast<PML4E_64*>(physical_to_virtual(device_handle, pml4_physical));
//        if (!pml4_virtual) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        PML4E_64 pml4e;
//        if (!intel_driver::ReadMemory(device_handle,
//            reinterpret_cast<uintptr_t>(pml4_virtual) + (virtual_address.Pml4Index * sizeof(PML4E_64)),
//            &pml4e, sizeof(PML4E_64))) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        if (!pml4e.Present) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        auto pdpt_physical = PFN_TO_PAGE(pml4e.PageFrameNumber);
//        auto* pdpt_virtual = static_cast<PDPTE_64*>(physical_to_virtual(device_handle, pdpt_physical));
//        if (!pdpt_virtual) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        PDPTE_64 pdpte;
//        if (!intel_driver::ReadMemory(device_handle,
//            reinterpret_cast<uintptr_t>(pdpt_virtual) + (virtual_address.PdptIndex * sizeof(PDPTE_64)),
//            &pdpte, sizeof(PDPTE_64))) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        if (!pdpte.Present) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        // sanity check 1GB page
//        if (pdpte.LargePage) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_INVALID_PARAMETER;
//        }
//
//        auto pd_physical = PFN_TO_PAGE(pdpte.PageFrameNumber);
//        auto* pd_virtual = static_cast<PDE_64*>(physical_to_virtual(device_handle, pd_physical));
//        if (!pd_virtual) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        PDE_64 pde;
//        if (!intel_driver::ReadMemory(device_handle,
//            reinterpret_cast<uintptr_t>(pd_virtual) + (virtual_address.PdIndex * sizeof(PDE_64)),
//            &pde, sizeof(PDE_64))) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        if (!pde.Present) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        // sanity check 2MB page
//        if (pde.LargePage) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_INVALID_PARAMETER;
//        }
//
//        auto pt_physical = PFN_TO_PAGE(pde.PageFrameNumber);
//        auto* pt_virtual = static_cast<PTE_64*>(physical_to_virtual(device_handle, pt_physical));
//        if (!pt_virtual) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        PTE_64 pte;
//        uintptr_t pte_address = reinterpret_cast<uintptr_t>(pt_virtual) + (virtual_address.PtIndex * sizeof(PTE_64));
//        if (!intel_driver::ReadMemory(device_handle, pte_address, &pte, sizeof(PTE_64))) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        if (!pte.Present) {
//            intel_driver::MmFreeIndependentPages(device_handle, allocated_addr, PAGE_SIZE);
//            return STATUS_NOT_FOUND;
//        }
//
//        // Store the PTE address for later manipulation
//        main_page_entry = reinterpret_cast<PTE_64*>(pte_address);
//
//        return STATUS_SUCCESS;
//    }
//
//    PVOID overwrite_page(HANDLE device_handle, const uintptr_t physical_address)
//    {
//        // page boundary checks are done by Read/WriteProcessMemory
//        // and page entries are not spread over different pages
//        const unsigned long page_offset = physical_address % 0x1000;
//        const uintptr_t page_start_physical = physical_address - page_offset;
//
//        PTE_64 new_pte;
//        if (!intel_driver::ReadMemory(device_handle, reinterpret_cast<uintptr_t>(main_page_entry), &new_pte, sizeof(PTE_64))) {
//            return nullptr;
//        }
//
//        new_pte.PageFrameNumber = PAGE_TO_PFN(page_start_physical);
//
//        if (!intel_driver::WriteMemory(device_handle, reinterpret_cast<uintptr_t>(main_page_entry), &new_pte, sizeof(PTE_64))) {
//            return nullptr;
//        }
//
//        //// Invalidate TLB for this page
//        //static uint64_t kernel_invlpg = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "__invlpg");
//        //if (kernel_invlpg) {
//        //    intel_driver::CallKernelFunction(device_handle, nullptr, kernel_invlpg, main_virtual_address);
//        //}
//
//        return reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(main_virtual_address) + page_offset);
//    }
//
//    NTSTATUS read_physical_address(HANDLE device_handle, const uintptr_t target_address, void* buffer, const size_t size)
//    {
//        const auto virtual_address = overwrite_page(device_handle, target_address);
//        if (!virtual_address) {
//            return STATUS_UNSUCCESSFUL;
//        }
//
//        if (!intel_driver::ReadMemory(device_handle, reinterpret_cast<uintptr_t>(virtual_address), buffer, size)) {
//            return STATUS_UNSUCCESSFUL;
//        }
//
//        return STATUS_SUCCESS;
//    }
//
//    NTSTATUS write_physical_address(HANDLE device_handle, const uintptr_t target_address, const void* buffer, const size_t size)
//    {
//        const auto virtual_address = overwrite_page(device_handle, target_address);
//        if (!virtual_address) {
//            return STATUS_UNSUCCESSFUL;
//        }
//
//        if (!intel_driver::WriteMemory(device_handle, reinterpret_cast<uintptr_t>(virtual_address), const_cast<void*>(buffer), size)) {
//            return STATUS_UNSUCCESSFUL;
//        }
//
//        return STATUS_SUCCESS;
//    }
//
//#define PAGE_OFFSET_SIZE 12
//    static constexpr uintptr_t PMASK = (~0xfull << 8) & 0xFFFFFFFFFFF000;
//
//    uintptr_t translate_linear_address(HANDLE device_handle, uintptr_t directory_table_base, const uintptr_t virtual_address)
//    {
//        directory_table_base &= ~0xf;
//
//        const uintptr_t page_offset = virtual_address & ~(~0ul << PAGE_OFFSET_SIZE);
//        const uintptr_t pte = ((virtual_address >> 12) & (0x1ffll));
//        const uintptr_t pt = ((virtual_address >> 21) & (0x1ffll));
//        const uintptr_t pd = ((virtual_address >> 30) & (0x1ffll));
//        const uintptr_t pdp = ((virtual_address >> 39) & (0x1ffll));
//
//        uintptr_t pdpe = 0;
//        if (!NT_SUCCESS(read_physical_address(device_handle, directory_table_base + 8 * pdp, &pdpe, sizeof(pdpe)))) {
//            return 0;
//        }
//        if (~pdpe & 1)
//            return 0;
//
//        uintptr_t pde = 0;
//        if (!NT_SUCCESS(read_physical_address(device_handle, (pdpe & PMASK) + 8 * pd, &pde, sizeof(pde)))) {
//            return 0;
//        }
//        if (~pde & 1)
//            return 0;
//
//        // 1GB large page, use pde's 12-34 bits
//        if (pde & 0x80)
//            return (pde & (~0ull << 42 >> 12)) + (virtual_address & ~(~0ull << 30));
//
//        uintptr_t pte_addr = 0;
//        if (!NT_SUCCESS(read_physical_address(device_handle, (pde & PMASK) + 8 * pt, &pte_addr, sizeof(pte_addr)))) {
//            return 0;
//        }
//        if (~pte_addr & 1)
//            return 0;
//
//        // 2MB large page
//        if (pte_addr & 0x80)
//            return (pte_addr & PMASK) + (virtual_address & ~(~0ull << 21));
//
//        uintptr_t result_address = 0;
//        if (!NT_SUCCESS(read_physical_address(device_handle, (pte_addr & PMASK) + 8 * pte, &result_address, sizeof(result_address)))) {
//            return 0;
//        }
//        result_address &= PMASK;
//
//        if (!result_address)
//            return 0;
//
//        return result_address + page_offset;
//    }
//
//    uintptr_t get_process_directory_base(HANDLE device_handle, DWORD process_id)
//    {
//        uintptr_t process_object = get_peprocess_from_pid(device_handle, process_id);
//        if (!process_object) {
//            return 0;
//        }
//
//        uintptr_t dir_base = 0;
//        if (!intel_driver::ReadMemory(device_handle, process_object + 0x28, &dir_base, sizeof(uintptr_t))) {
//            //dereference_process(device_handle, process_object);
//            return 0;
//        }
//
//        if (!dir_base) {
//            uintptr_t user_dir_base = 0;
//            if (!intel_driver::ReadMemory(device_handle, process_object + 0x388, &user_dir_base, sizeof(uintptr_t))) {
//                //dereference_process(device_handle, process_object);
//                return 0;
//            }
//            //dereference_process(device_handle, process_object);
//            return user_dir_base;
//        }
//
//        //dereference_process(device_handle, process_object);
//        return dir_base;
//    }
//
//    NTSTATUS read_process_memory(HANDLE device_handle, DWORD process_id, const uintptr_t address, void* buffer, const size_t size)
//    {
//        if (!address)
//            return STATUS_INVALID_PARAMETER;
//
//        const auto process_dir_base = get_process_directory_base(device_handle, process_id);
//        if (!process_dir_base) {
//            return STATUS_NOT_FOUND;
//        }
//
//        size_t current_offset = 0;
//        size_t total_size = size;
//
//        while (total_size)
//        {
//            const auto current_physical_address = translate_linear_address(device_handle, process_dir_base, address + current_offset);
//            if (!current_physical_address)
//                return STATUS_NOT_FOUND;
//
//            const auto read_size = min(PAGE_SIZE - (current_physical_address & 0xFFF), total_size);
//            const auto status = read_physical_address(
//                device_handle,
//                current_physical_address,
//                reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(buffer) + current_offset),
//                read_size
//            );
//
//            if (!NT_SUCCESS(status) || !read_size)
//                return status;
//
//            total_size -= read_size;
//            current_offset += read_size;
//        }
//
//        return STATUS_SUCCESS;
//    }
//
//    NTSTATUS write_process_memory(HANDLE device_handle, DWORD process_id, const uintptr_t address, const void* buffer, const size_t size)
//    {
//        if (!address)
//            return STATUS_INVALID_PARAMETER;
//
//        const auto process_dir_base = get_process_directory_base(device_handle, process_id);
//        if (!process_dir_base) {
//            return STATUS_NOT_FOUND;
//        }
//
//        size_t current_offset = 0;
//        size_t total_size = size;
//
//        while (total_size)
//        {
//            const auto current_physical_address = translate_linear_address(device_handle, process_dir_base, address + current_offset);
//            if (!current_physical_address)
//                return STATUS_NOT_FOUND;
//
//            const auto write_size = min(PAGE_SIZE - (current_physical_address & 0xFFF), total_size);
//            const auto status = write_physical_address(
//                device_handle,
//                current_physical_address,
//                reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(buffer) + current_offset),
//                write_size
//            );
//
//            if (!NT_SUCCESS(status) || !write_size)
//                return status;
//
//            total_size -= write_size;
//            current_offset += write_size;
//        }
//
//        return STATUS_SUCCESS;
//    }
//
//    // Usermode compatible process finder that returns PID
//    DWORD find_process_by_name(const wchar_t* process_name) {
//        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//        if (snapshot == INVALID_HANDLE_VALUE) {
//            return 0;
//        }
//
//        PROCESSENTRY32W entry;
//        entry.dwSize = sizeof(entry);
//
//        if (Process32FirstW(snapshot, &entry)) {
//            do {
//                if (_wcsicmp(entry.szExeFile, process_name) == 0) {
//                    CloseHandle(snapshot);
//                    return entry.th32ProcessID;
//                }
//            } while (Process32NextW(snapshot, &entry));
//        }
//
//        CloseHandle(snapshot);
//        return 0;
//    }
//
//    // Alternative: Find process and get module base
//    struct ProcessInfo {
//        DWORD pid;
//        uintptr_t module_base;
//    };
//
//    ProcessInfo find_process_with_module(HANDLE device_handle, const wchar_t* process_name) {
//        ProcessInfo result = { 0, 0 };
//
//        // First find the PID using standard usermode API
//        result.pid = find_process_by_name(process_name);
//        if (!result.pid) {
//            return result;
//        }
//
//        // Get process object from PID
//        uintptr_t process_object = get_peprocess_from_pid(device_handle, result.pid);
//        if (!process_object) {
//            result.pid = 0;
//            return result;
//        }
//
//        // Get PEB address
//        static uint64_t kernel_PsGetProcessPeb = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "PsGetProcessPeb");
//        if (!kernel_PsGetProcessPeb) {
//            //dereference_process(device_handle, process_object);
//            result.pid = 0;
//            return result;
//        }
//
//        uintptr_t peb_address = 0;
//        if (!intel_driver::CallKernelFunction(device_handle, &peb_address, kernel_PsGetProcessPeb, reinterpret_cast<void*>(process_object))) {
//            //dereference_process(device_handle, process_object);
//            result.pid = 0;
//            return result;
//        }
//
//        // Read PEB to get image base
//        if (peb_address) {
//            // PEB.ImageBaseAddress is at offset +0x10
//            if (!read_process_memory(device_handle, result.pid, peb_address + 0x10, &result.module_base, sizeof(uintptr_t))) {
//                result.module_base = 0;
//            }
//        }
//
//        //dereference_process(device_handle, process_object);
//        return result;
//    }
//}