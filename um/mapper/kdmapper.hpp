#pragma once
#include "../pdb/pdb.hpp"
#include <Windows.h>
#include <iostream>
#include <string>
#include <stdint.h>
#include "portable_executable.hpp"
#include "utils.hpp"
#include "nt.hpp"
#include "intel_driver.hpp"
#include <random>
#include <numeric>
#include "../driver/ia_32.hpp"
#include <ntstatus.h>

#define PAGE_SHIFT 12
#define PFN_TO_PAGE(pfn) ((pfn) << PAGE_SHIFT)
#define PAGE_SIZE 0x1000
#define LARGE_PAGE_SIZE 0x200000

typedef union _PHYSICAL_ADDRESS {
	struct {
		ULONG LowPart;
		LONG HighPart;
	};
	LONGLONG QuadPart;
} PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;

namespace kdmapper
{
	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	__forceinline uint64_t MapDriver(HANDLE iqvw64e_device_handle, BYTE* data, ULONG64 param1 = 0, ULONG64 param2 = 0, bool free = false, bool destroyHeader = true, bool PassAllocationAddressAsFirstParam = false, NTSTATUS* exitCode = nullptr, nt::driver_alloc_mode legit_memory = nt::driver_alloc_mode::ALLOC_IN_SYSTEM_CONTEXT, nt::memory_type driver_mem_type = nt::memory_type::NORMAL_PAGE);
	__forceinline void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
	__forceinline bool FixSecurityCookie(void* local_image, uint64_t kernel_image_base);
	__forceinline bool ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports);
	__forceinline void* AllocContiguousMemory(HANDLE device_handle, size_t size);
	__forceinline uint64_t AllocIndependentPages(HANDLE device_handle, uint32_t size);
	__forceinline int Init(nt::driver_alloc_mode driver_alloc_mode, nt::memory_type driver_mem_type);
}

__forceinline uint64_t kdmapper::AllocIndependentPages(HANDLE device_handle, uint32_t size)
{

	const auto base = intel_driver::MmAllocateIndependentPagesEx(device_handle, size);
	if (!base)
	{
		Log(L"[-] Error allocating independent pages" << std::endl);
		return 0;
	}

	if (!intel_driver::MmSetPageProtection(device_handle, base, size, PAGE_EXECUTE_READWRITE))
	{
		Log(L"[-] Failed to change page protections" << std::endl);
		intel_driver::MmFreeIndependentPages(device_handle, base, size);
		return 0;
	}

	return base;
}

__forceinline void* kdmapper::AllocContiguousMemory(HANDLE device_handle, size_t size)
{
	static uint64_t kernel_MmAllocateContiguousMemory = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmAllocateContiguousMemory");
	if (!kernel_MmAllocateContiguousMemory) {
		Log(L"[-] Failed to find MmAllocateContiguousMemory" << std::endl);
		return 0;
	}

	PHYSICAL_ADDRESS max_address{};
	max_address.QuadPart = MAXULONG64;

	void* virtual_address = 0;
	intel_driver::CallKernelFunction(device_handle, &virtual_address, kernel_MmAllocateContiguousMemory, size, max_address);

	return virtual_address;
}

// page table helper functions
namespace page_table {
	uintptr_t get_pml4e(uint32_t pml4_idx) {
		return static_cast<uintptr_t>(pml4_idx) << 39;
	}

	uintptr_t get_pdpt(uint32_t pdpt_idx) {
		return static_cast<uintptr_t>(pdpt_idx) << 30;
	}

	uintptr_t get_pd(uint32_t pd_idx) {
		return static_cast<uintptr_t>(pd_idx) << 21;
	}

	uintptr_t get_pt(uint32_t pt_idx) {
		return static_cast<uintptr_t>(pt_idx) << 12;
	}
}

// convert physical address to virtual for reading/writing
uintptr_t physical_to_virtual(HANDLE device_handle, uintptr_t physical_address) {
	static uint64_t kernel_MmGetVirtualForPhysical = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmGetVirtualForPhysical");
	if (!kernel_MmGetVirtualForPhysical) {
		Log(L"[-] Failed to find MmGetVirtualForPhysical" << std::endl);
		return 0;
	}

	PHYSICAL_ADDRESS phys_addr;
	phys_addr.QuadPart = physical_address;

	uintptr_t virtual_address = 0;
	intel_driver::CallKernelFunction(device_handle, &virtual_address, kernel_MmGetVirtualForPhysical, phys_addr);

	return virtual_address;
}

bool read_physical_address(HANDLE device_handle, uintptr_t physical_address, void* buffer, size_t size) {
	uintptr_t virtual_address = physical_to_virtual(device_handle, physical_address);
	if (!virtual_address) {
		Log(L"[-] Failed to get virtual address for physical: 0x" << std::hex << physical_address << std::endl);
		return false;
	}

	return intel_driver::ReadMemory(device_handle, virtual_address, buffer, size);
}

// write to physical address
bool write_physical_address(HANDLE device_handle, uintptr_t physical_address, void* buffer, size_t size) {
	uintptr_t virtual_address = physical_to_virtual(device_handle, physical_address);
	if (!virtual_address) {
		Log(L"[-] Failed to get virtual address for physical: 0x" << std::hex << physical_address << std::endl);
		return false;
	}

	return intel_driver::WriteMemory(device_handle, virtual_address, buffer, size);
}

NTSTATUS write_page_tables(HANDLE device_handle, uintptr_t target_dir_base, uintptr_t base_va, size_t page_count, bool use_large_page) {

	for (size_t i = 0; i < page_count; ++i) {
		const auto current_va = base_va + i * (use_large_page ? LARGE_PAGE_SIZE : PAGE_SIZE);
		ADDRESS_TRANSLATION_HELPER helper;
		helper.AsUInt64 = current_va;

		uintptr_t actual_page_va = 0;
		if (use_large_page) {
			// for large pages, we need contiguous memory
			actual_page_va = reinterpret_cast<uintptr_t>(kdmapper::AllocContiguousMemory(device_handle, LARGE_PAGE_SIZE));
		}
		else {
			actual_page_va = reinterpret_cast<uintptr_t>(VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
		}

		if (!actual_page_va) {
			Log(L"[-] Failed to allocate actual page" << std::endl);
			return STATUS_NO_MEMORY;
		}

		// clear the allocated page
		static uint64_t kernel_RtlZeroMemory = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "RtlZeroMemory");
		if (kernel_RtlZeroMemory) {
			intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
				reinterpret_cast<void*>(actual_page_va), use_large_page ? LARGE_PAGE_SIZE : PAGE_SIZE);
		}

		uintptr_t page_frame_number = 0;

		// get page table entry address
		auto pte_va = use_large_page ?
			intel_driver::MiGetPdeAddress(device_handle, actual_page_va) :
			intel_driver::MiGetPteAddress(device_handle, actual_page_va);

		if (!pte_va) {
			Log(L"[-] Failed to get page table entry address" << std::endl);
			return STATUS_UNSUCCESSFUL;
		}

		// both PTE and PDE have PageFrameNumber in the same position, so we can use either
		PTE_64 entry = { 0 };
		if (!intel_driver::ReadMemory(device_handle, pte_va, &entry, use_large_page ? sizeof(PDE_64) : sizeof(PTE_64))) {
			Log(L"[-] Failed to read " << (use_large_page ? L"PDE" : L"PTE") << std::endl);
			return STATUS_UNSUCCESSFUL;
		}

		page_frame_number = entry.PageFrameNumber;
		if (!page_frame_number) {
			Log(L"[-] PFN is null" << std::endl);
			return STATUS_UNSUCCESSFUL;
		}

		uintptr_t pml4_phys = target_dir_base;
		PML4E_64 pml4e = { 0 };

		// read and setup PML4E
		if (!read_physical_address(device_handle, pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64))) {
			Log(L"[-] Failed to read PML4E" << std::endl);
			return STATUS_UNSUCCESSFUL;
		}

		if (!pml4e.Present) {
			auto pdpt_va = kdmapper::AllocIndependentPages(device_handle, PAGE_SIZE);
			if (!pdpt_va) {
				Log(L"[-] Failed to allocate pdpt" << std::endl);
				return STATUS_NO_MEMORY;
			}

			// clear PDPT
			if (kernel_RtlZeroMemory) {
				intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
					reinterpret_cast<void*>(pdpt_va), PAGE_SIZE);
			}

			// get physical address of PDPT
			uintptr_t pdpt_pte_va = intel_driver::MiGetPteAddress(device_handle, pdpt_va);
			if (!pdpt_pte_va) {
				Log(L"[-] Failed to get PTE address for PDPT" << std::endl);
				return STATUS_UNSUCCESSFUL;
			}

			PTE_64 pdpt_pte = { 0 };
			if (!intel_driver::ReadMemory(device_handle, pdpt_pte_va, &pdpt_pte, sizeof(PTE_64))) {
				Log(L"[-] Failed to read PTE for PDPT" << std::endl);
				return STATUS_UNSUCCESSFUL;
			}

			pml4e.Flags = 0;
			pml4e.Present = 1;
			pml4e.Write = 1;
			pml4e.Supervisor = 0;
			pml4e.PageFrameNumber = pdpt_pte.PageFrameNumber;

			if (!write_physical_address(device_handle, pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64))) {
				Log(L"[-] Failed to write PML4E" << std::endl);
				return STATUS_UNSUCCESSFUL;
			}
		}

		// read and setup PDPT
		PDPTE_64 pdpte = { 0 };
		if (!read_physical_address(device_handle, PFN_TO_PAGE(pml4e.PageFrameNumber) + helper.AsIndex.Pdpt * sizeof(PDPTE_64), &pdpte, sizeof(PDPTE_64))) {
			Log(L"[-] Failed to read PDPTE" << std::endl);
			return STATUS_UNSUCCESSFUL;
		}

		if (!pdpte.Present) {
			auto pd_va = kdmapper::AllocIndependentPages(device_handle, PAGE_SIZE);
			if (!pd_va) {
				Log(L"[-] Failed to allocate pd" << std::endl);
				return STATUS_NO_MEMORY;
			}

			// clear PD
			if (kernel_RtlZeroMemory) {
				intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
					reinterpret_cast<void*>(pd_va), PAGE_SIZE);
			}

			// get physical address of PD
			uintptr_t pd_pte_va = intel_driver::MiGetPteAddress(device_handle, pd_va);
			if (!pd_pte_va) {
				Log(L"[-] Failed to get PTE address for PD" << std::endl);
				return STATUS_UNSUCCESSFUL;
			}

			PTE_64 pd_pte = { 0 };
			if (!intel_driver::ReadMemory(device_handle, pd_pte_va, &pd_pte, sizeof(PTE_64))) {
				Log(L"[-] Failed to read PTE for PD" << std::endl);
				return STATUS_UNSUCCESSFUL;
			}

			pdpte.Flags = 0;
			pdpte.Present = 1;
			pdpte.Write = 1;
			pdpte.Supervisor = 0;
			pdpte.PageFrameNumber = pd_pte.PageFrameNumber;

			if (!write_physical_address(device_handle, PFN_TO_PAGE(pml4e.PageFrameNumber) + helper.AsIndex.Pdpt * sizeof(PDPTE_64), &pdpte, sizeof(PDPTE_64))) {
				Log(L"[-] Failed to write PDPTE" << std::endl);
				return STATUS_UNSUCCESSFUL;
			}
		}

		if (use_large_page) {
			// read and setup PD for large page
			PDE_64 pde = { 0 };
			if (!read_physical_address(device_handle, PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64))) {
				Log(L"[-] Failed to read PDE" << std::endl);
				return STATUS_UNSUCCESSFUL;
			}

			if (!pde.Present) {
				pde.Flags = 0;
				pde.Present = 1;
				pde.Write = 1;
				pde.Supervisor = 0;
				pde.LargePage = 1;
				pde.ExecuteDisable = 0;
				pde.PageFrameNumber = page_frame_number;

				if (!write_physical_address(device_handle, PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64))) {
					Log(L"[-] Failed to write PDE" << std::endl);
					return STATUS_UNSUCCESSFUL;
				}
			}
		}
		else {
			// read and setup PD for regular page
			PDE_64 pde = { 0 };
			if (!read_physical_address(device_handle, PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64))) {
				Log(L"[-] Failed to read PDE" << std::endl);
				return STATUS_UNSUCCESSFUL;
			}

			if (!pde.Present) {
				auto pt_va = kdmapper::AllocIndependentPages(device_handle, PAGE_SIZE);
				if (!pt_va) {
					Log(L"ERROR: failed to allocate pt" << std::endl);
					return STATUS_NO_MEMORY;
				}

				// clear PT
				if (kernel_RtlZeroMemory) {
					intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
						reinterpret_cast<void*>(pt_va), PAGE_SIZE);
				}

				// get physical address of PT
				uintptr_t pt_pte_va = intel_driver::MiGetPteAddress(device_handle, pt_va);
				if (!pt_pte_va) {
					Log(L"[-] Failed to get PTE address for PT" << std::endl);
					return STATUS_UNSUCCESSFUL;
				}

				PTE_64 pt_pte = { 0 };
				if (!intel_driver::ReadMemory(device_handle, pt_pte_va, &pt_pte, sizeof(PTE_64))) {
					Log(L"[-] Failed to read PTE for PT" << std::endl);
					return STATUS_UNSUCCESSFUL;
				}

				pde.Flags = 0;
				pde.Present = 1;
				pde.Write = 1;
				pde.Supervisor = 0;
				pde.PageFrameNumber = pt_pte.PageFrameNumber;

				if (!write_physical_address(device_handle, PFN_TO_PAGE(pdpte.PageFrameNumber) + helper.AsIndex.Pd * sizeof(PDE_64), &pde, sizeof(PDE_64))) {
					Log(L"[-] Failed to write PDE" << std::endl);
					return STATUS_UNSUCCESSFUL;
				}
			}

			// setup PTE
			PTE_64 pte = { 0 };
			pte.Present = 1;
			pte.Write = 1;
			pte.Supervisor = 0;
			pte.PageFrameNumber = page_frame_number;

			if (!write_physical_address(device_handle, PFN_TO_PAGE(pde.PageFrameNumber) + helper.AsIndex.Pt * sizeof(PTE_64), &pte, sizeof(PTE_64))) {
				Log(L"[-] Failed to write PTE" << std::endl);
				return STATUS_UNSUCCESSFUL;
			}
		}

		Log(L"[+] page " << i << L": va: 0x" << std::hex << current_va << L", pfn: 0x" << page_frame_number << std::endl);
	}

	return STATUS_SUCCESS;
}

// allocate within current process context within non present pml4 at high address
void* allocate_within_current_process_context(HANDLE device_handle, const uint32_t target_pid, const size_t size, const bool use_large_page, const bool use_high_address = true) {
	// page size constants
	const size_t page_size = use_large_page ? LARGE_PAGE_SIZE : PAGE_SIZE;
	const size_t page_mask = page_size - 1;
	const size_t page_shift = use_large_page ? 21 : 12;

	// align the requested size to page boundaries
	const size_t aligned_size = (size + page_mask) & ~page_mask;
	const size_t page_count = aligned_size >> page_shift;

	static uint64_t kernel_PsGetCurrentProcess = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "PsGetCurrentProcess");

	if (!kernel_PsGetCurrentProcess) {
		Log(L"[!] Failed to find PsGetCurrentProcess" << std::endl);
		return 0;
	}

	// get current process EPROCESS structure
	uintptr_t current_process = 0;
	if (!intel_driver::CallKernelFunction(device_handle, &current_process, kernel_PsGetCurrentProcess)) {
		return 0;
	}

	if (!current_process) {
		return 0;
	}

	// get directory base (CR3)
	uintptr_t target_dir_base = 0;
	if (!intel_driver::ReadMemory(device_handle, current_process + 0x28, &target_dir_base, sizeof(uintptr_t))) {
		Log(L"[-] Failed to read target process directory base" << std::endl);
		return nullptr;
	}

	// find a non-present PML4E in the appropriate address space
	uint32_t selected_pml4_index = 0;
	PML4E_64 pml4e = { 0 };

	// set the search range based on whether high or low address is requested
	uint32_t start_idx = use_high_address ? 256 : 0;
	uint32_t end_idx = use_high_address ? 511 : 256;
	const char* space_type = use_high_address ? "kernel" : "usermode";

	bool found = false;
	for (uint32_t idx = start_idx; idx < end_idx; idx++) {
		if (read_physical_address(device_handle, target_dir_base + idx * sizeof(PML4E_64), &pml4e, sizeof(PML4E_64))) {
			if (!pml4e.Present) {
				selected_pml4_index = idx;
				Log(L"[+] Found non-present PML4E at index: " << selected_pml4_index << std::endl);
				found = true;
				break;
			}
		}
	}

	if (!found) {
		Log(L"[-] Failed to find a non-present PML4E in " << space_type << " space" << std::endl);
		return nullptr;
	}

	// calc the base virtual address using the selected PML4E index
	uintptr_t base_va;
	if (use_high_address) {
		base_va = 0xFFFF000000000000ULL | page_table::get_pml4e(selected_pml4_index);
	}
	else {
		base_va = page_table::get_pml4e(selected_pml4_index);
	}

	Log(L"[+] Selected base address: 0x" << std::hex << base_va << std::endl);

	// write page tables
	auto write_pt_status = write_page_tables(device_handle, target_dir_base, base_va, page_count, use_large_page);

	if (!NT_SUCCESS(write_pt_status)) {
		Log(L"[-] Failed to write page tables, NTSTATUS: 0x" << std::hex << write_pt_status << std::endl);
		return nullptr;
	}

	// flush tb
	__int64 kefet_ret = 0;
	static uint64_t kernel_KeFlushEntireTb = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "KeFlushEntireTb");
	if (kernel_KeFlushEntireTb) {
		intel_driver::CallKernelFunction(device_handle, &kefet_ret, kernel_KeFlushEntireTb, TRUE, TRUE);
	}

	return reinterpret_cast<void*>(base_va);
}

__forceinline uint64_t kdmapper::MapDriver(HANDLE iqvw64e_device_handle, BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, bool PassAllocationAddressAsFirstParam, NTSTATUS* exitCode, nt::driver_alloc_mode driver_alloc_type, nt::memory_type driver_mem_type) {

	Log(L"[+] Starting Driver Map" << std::endl);

	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(data);
	if (!nt_headers) {
		Log(L"[-] Invalid format of PE image" << std::endl);
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Log(L"[-] Image is not 64-bit" << std::endl);
		return 0;
	}

	uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;
	void* local_image_base = nullptr;
	uint64_t alloc_size = image_size;

	bool large_page_support = false;
	if (driver_mem_type == nt::LARGE_PAGE || driver_mem_type == nt::HUGE_PAGE) {
		large_page_support = true;
	}

	auto status = shadowsyscall<NTSTATUS>("NtAllocateVirtualMemory", NtCurrentProcess, &local_image_base, 0, &alloc_size, MEM_RESERVE | MEM_COMMIT, 0x40);

	if (!NT_SUCCESS(status) || !local_image_base) {
		Log(L"[-] Failed to allocate local memory. NTSTATUS: 0x" << std::hex << status << std::endl);
		return 0;
	}

	Log(L"[+] Successfully allocated local memory at: " << local_image_base << L" with size: " << alloc_size << L" bytes" << std::endl);

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	uintptr_t kernel_image_base = 0;
	
	if (driver_alloc_type == nt::driver_alloc_mode::ALLOC_IN_SYSTEM_CONTEXT) {
		kernel_image_base = AllocIndependentPages(iqvw64e_device_handle, image_size);
		if (!kernel_image_base) {
			Log(L"[-] Failed to allocate remote image in kernel" << std::endl);
			alloc_size = 0; 
			shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &local_image_base, &alloc_size, MEM_RELEASE);
			return 0;
		}
	}
	else if (driver_alloc_type == nt::driver_alloc_mode::ALLOC_IN_CURRENT_PROCESS_CONTEXT) {
		kernel_image_base = reinterpret_cast<uintptr_t>(allocate_within_current_process_context(iqvw64e_device_handle, GetCurrentProcessId(), image_size, large_page_support, true));
		if (!kernel_image_base) {
			Log(L"[-] Failed to allocate memory at non-present PML4E" << std::endl);
			return 0;
		}

		Log(L"[+] Allocated memory at: 0x" << std::hex << kernel_image_base << std::endl);
	}
	else if (driver_alloc_type == nt::driver_alloc_mode::ALLOC_IN_NTOSKRNL_DATA_SECTION) {
		const auto ntos_base = utils::GetKernelModuleAddress("ntoskrnl.exe");
		ULONG section_size = 0;
		uintptr_t section_base = intel_driver::FindSectionAtKernel(iqvw64e_device_handle, ".data", ntos_base, &section_size);
		if (!section_base || !section_size) {
			Log(L"[-] Failed to find section in ntoskrnl.exe" << std::endl);
			alloc_size = 0;
			shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &local_image_base, &alloc_size, MEM_RELEASE);
			return 0;
		}

		Log(L"[+] Found usable section with size: " << section_size << std::endl);

		kernel_image_base = reinterpret_cast<uintptr_t>(intel_driver::FindUnusedSpace(iqvw64e_device_handle, section_base, section_size, image_size, 0x1000));
		if (!kernel_image_base) {
			Log(L"[-] Failed to find unused space in section" << std::endl);
			alloc_size = 0;
			shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &local_image_base, &alloc_size, MEM_RELEASE);
			return 0;
		}

		Log(L"[+] Found unused space in section at address: " << reinterpret_cast<void*>(kernel_image_base) << std::endl);

		for (uintptr_t current_addr = kernel_image_base; current_addr < kernel_image_base + image_size; current_addr += PAGE_SIZE) {
			auto pde_address = intel_driver::MiGetPdeAddress(iqvw64e_device_handle, current_addr);

			PDE_64 pde;
			if (!intel_driver::ReadMemory(iqvw64e_device_handle, pde_address, &pde, sizeof(PDE_64))) {
				Log(L"[-] Failed to read PDE at address: " << reinterpret_cast<void*>(pde_address) << std::endl);
				return 0;
			}

			// ntoskrnl is mapped on 2mb pages in newer windows versions it seems
			if (pde.LargePage) {

				pde.ExecuteDisable = 0; // allow Execution
				pde.Write = 1;			// allow Read/Write

				if (!intel_driver::WriteMemory(iqvw64e_device_handle, pde_address, &pde, sizeof(PDE_64))) {
					Log(L"[-] Failed to write PDE at address: " << reinterpret_cast<void*>(pde_address) << std::endl);
					return 0;
				}
			}
			else {

				auto pte_address = intel_driver::MiGetPteAddress(iqvw64e_device_handle, current_addr);

				PTE_64 pte;
				if (!intel_driver::ReadMemory(iqvw64e_device_handle, pte_address, &pte, sizeof(PTE_64))) {
					Log(L"[-] Failed to read PTE at address: " << reinterpret_cast<void*>(pte_address) << std::endl);
					return 0;
				}

				pte.ExecuteDisable = 0; // allow Execution
				pte.Write = 1;			// allow Read/Write

				if (!intel_driver::WriteMemory(iqvw64e_device_handle, pte_address, &pte, sizeof(PTE_64))) {
					Log(L"[-] Failed to write PTE at address: " << reinterpret_cast<void*>(pte_address) << std::endl);
					return 0;
				}
			}
		}

		Log(L"[+] Successfully modified page tables to make pages executable" << std::endl);
	}

	do {
		Log(L"[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl);

		// Copy image headers
		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		Log(L"[+] Image headers copied to local memory" << std::endl);

		// Copy image sections
		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);
		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0) {
				Log(L"[+] Skipping uninitialized section: " << i << std::endl);
				continue;
			}
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
			Log(L"[+] Copied section: " << i << std::endl);
		}

		uint64_t realBase = kernel_image_base;
		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
			Log(L"[+] Skipped 0x" << std::hex << TotalVirtualHeaderSize << L" bytes of PE Header" << std::endl);
		}

		// Resolve relocs and imports
		Log(L"[+] Resolving relocations" << std::endl);
		RelocateImageByDelta(GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		Log(L"[+] Fixing security cookie" << std::endl);
		if (!FixSecurityCookie(local_image_base, kernel_image_base)) {
			Log(L"[-] Failed to fix security cookie" << std::endl);
			return 0;
		}

		Log(L"[+] Resolving imports" << std::endl);
		if (!ResolveImports(iqvw64e_device_handle, GetImports(local_image_base))) {
			Log(L"[-] Failed to resolve imports" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		Log(L"[+] Writing image to kernel memory" << std::endl);

		// Write fixed image
		if (!intel_driver::WriteMemory(iqvw64e_device_handle, realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
			Log(L"[-] Failed to write local image to remote image" << std::endl);
			kernel_image_base = realBase;
			break;
		}
	
		// Call driver entry point
		const uint64_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;
		Log(L"[<] Calling DriverEntry at 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl);

		struct pdb_offsets {
			// driver vars
			uintptr_t DriverAllocBase;
			uintptr_t DriverSize;

			// memory management (Mm)
			uintptr_t MmPfnDatabase;
			uintptr_t MmAllocateIndependentPages;
			uintptr_t MmFreeIndependentPages;
			uintptr_t MmAllocateContiguousMemory;
			uintptr_t MmCopyMemory;
			uintptr_t MmGetVirtualForPhysical;
			uintptr_t MmCopyVirtualMemory;
			uintptr_t MmMarkPhysicalMemoryAsBad;
			uintptr_t MmUserProbeAddress;
			uintptr_t MmGetSystemRoutineAddress;

			// memory info (Mi) functions
			uintptr_t MiCreateDecayPfn;
			uintptr_t MiGetUltraPage;
			uintptr_t MiReservePtes;
			uintptr_t MiGetPteAddress;
			uintptr_t MiGetPdeAddress;
			uintptr_t MiSystemPartition;
			uintptr_t MiInitializePfn;
			uintptr_t MiGetPage;
			uintptr_t MiWaitForFreePage;
			uintptr_t MiRemovePhysicalMemory;
			uintptr_t MiFlushEntireTbDueToAttributeChange;
			uintptr_t MiFlushCacheRange;
			uintptr_t MiPinDriverAddressLog;
			uintptr_t MiGetPageTablePfnBuddyRaw;
			uintptr_t MiSetPageTablePfnBuddy;

			// proc/obj management
			uintptr_t PsLookupProcessByProcessId;
			uintptr_t PsGetProcessPeb;
			uintptr_t PsGetProcessImageFileName;
			uintptr_t IoGetCurrentProcess;
			uintptr_t ObfDereferenceObject;

			// executive functions
			uintptr_t ExAllocatePool2;
			uintptr_t ExFreePoolWithTag;
			uintptr_t ExGetPreviousMode;

			// runtime library
			uintptr_t RtlInitAnsiString;
			uintptr_t RtlInitUnicodeString;
			uintptr_t RtlAnsiStringToUnicodeString;
			uintptr_t RtlCompareUnicodeString;
			uintptr_t RtlFreeUnicodeString;
			uintptr_t RtlGetVersion;

			// debug
			uintptr_t DbgPrint;

			// crt functions
			uintptr_t memcpy;
			uintptr_t memset;
			uintptr_t memcmp;
			uintptr_t strncmp;
			uintptr_t strlen;

			// offsets
			uintptr_t ActiveProcessLinks;
		};

		uintptr_t ntoskrnl_base = utils::GetKernelModuleAddress("ntoskrnl.exe");
		if (!ntoskrnl_base) {
			Log(L"[-] Failed to get ntoskrnl.exe base address" << std::endl);
			return 0;
		}

		std::string kernel = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
		std::string pdbPath = EzPdbDownload(kernel);
		kernel.clear();

		if (pdbPath.empty()) {
			return 0;
		}

		EZPDB pdb;
		if (!EzPdbLoad(pdbPath, &pdb)) {
			return 0;
		}

		pdb_offsets offsets = {
			kernel_image_base,
			alloc_size,
			// memory management (Mm) functions
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmPfnDatabase"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmAllocateIndependentPages"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmFreeIndependentPages"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmAllocateContiguousMemory"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmCopyMemory"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmGetVirtualForPhysical"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmCopyVirtualMemory"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmMarkPhysicalMemoryAsBad"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmUserProbeAddress"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmGetSystemRoutineAddress"),

			// memory info (Mi) functions
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiCreateDecayPfn"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiGetUltraPage"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiReservePtes"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiGetPteAddress"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiGetPdeAddress"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiSystemPartition"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiInitializePfn"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiGetPage"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiWaitForFreePage"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiRemovePhysicalMemory"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiFlushEntireTbDueToAttributeChange"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiFlushCacheRange"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiPinDriverAddressLog"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiGetPageTablePfnBuddyRaw"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiSetPageTablePfnBuddy"),

			// proc/obj management functions
			ntoskrnl_base + EzPdbGetRva(&pdb, "PsLookupProcessByProcessId"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "PsGetProcessPeb"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "PsGetProcessImageFileName"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "PsGetCurrentProcess"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "ObfDereferenceObject"),

			// executive functions
			ntoskrnl_base + EzPdbGetRva(&pdb, "ExAllocatePool2"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "ExFreePoolWithTag"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "ExGetPreviousMode"),

			// runtime library functions
			ntoskrnl_base + EzPdbGetRva(&pdb, "RtlInitAnsiString"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "RtlInitUnicodeString"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "RtlAnsiStringToUnicodeString"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "RtlCompareUnicodeString"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "RtlFreeUnicodeString"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "RtlGetVersion"),

			// debug functions
			ntoskrnl_base + EzPdbGetRva(&pdb, "DbgPrint"),

			// crt functions
			ntoskrnl_base + EzPdbGetRva(&pdb, "memcpy"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "memset"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "memcmp"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "strncmp"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "strlen"),

			// struct offsets
			EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"ActiveProcessLinks")
		};

		// log ntoskrnl base address
		Log(L"[+] ntoskrnl.exe base address: 0x" << std::hex << ntoskrnl_base << std::endl);

		// log memory management functions
		Log(L"[+] === Memory Management Functions ===" << std::endl);
		Log(L"[+] MmPfnDatabase: 0x" << std::hex << offsets.MmPfnDatabase << std::endl);
		Log(L"[+] MmAllocateIndependentPages: 0x" << std::hex << offsets.MmAllocateIndependentPages << std::endl);
		Log(L"[+] MmFreeIndependentPages: 0x" << std::hex << offsets.MmFreeIndependentPages << std::endl);
		Log(L"[+] MmAllocateContiguousMemory: 0x" << std::hex << offsets.MmAllocateContiguousMemory << std::endl);
		Log(L"[+] MmCopyMemory: 0x" << std::hex << offsets.MmCopyMemory << std::endl);
		Log(L"[+] MmGetVirtualForPhysical: 0x" << std::hex << offsets.MmGetVirtualForPhysical << std::endl);
		Log(L"[+] MmCopyVirtualMemory: 0x" << std::hex << offsets.MmCopyVirtualMemory << std::endl);
		Log(L"[+] MmMarkPhysicalMemoryAsBad: 0x" << std::hex << offsets.MmMarkPhysicalMemoryAsBad << std::endl);
		Log(L"[+] MmUserProbeAddress: 0x" << std::hex << offsets.MmUserProbeAddress << std::endl);
		Log(L"[+] MmGetSystemRoutineAddress: 0x" << std::hex << offsets.MmGetSystemRoutineAddress << std::endl);

		// log memory info (Mi) functions
		Log(L"[+] === Memory Info (MI) Functions ===" << std::endl);
		Log(L"[+] MiReservePtes: 0x" << std::hex << offsets.MiReservePtes << std::endl);
		Log(L"[+] MiGetPteAddress: 0x" << std::hex << offsets.MiGetPteAddress << std::endl);
		Log(L"[+] MiSystemPartition: 0x" << std::hex << offsets.MiSystemPartition << std::endl);
		Log(L"[+] MiInitializePfn: 0x" << std::hex << offsets.MiInitializePfn << std::endl);
		Log(L"[+] MiGetPage: 0x" << std::hex << offsets.MiGetPage << std::endl);
		Log(L"[+] MiWaitForFreePage: 0x" << std::hex << offsets.MiWaitForFreePage << std::endl);
		Log(L"[+] MiRemovePhysicalMemory: 0x" << std::hex << offsets.MiRemovePhysicalMemory << std::endl);
		Log(L"[+] MiFlushEntireTbDueToAttributeChange: 0x" << std::hex << offsets.MiFlushEntireTbDueToAttributeChange << std::endl);
		Log(L"[+] MiFlushCacheRange: 0x" << std::hex << offsets.MiFlushCacheRange << std::endl);
		Log(L"[+] MiPinDriverAddressLog: 0x" << std::hex << offsets.MiPinDriverAddressLog << std::endl);
		Log(L"[+] MiGetPageTablePfnBuddyRaw: 0x" << std::hex << offsets.MiGetPageTablePfnBuddyRaw << std::endl);
		Log(L"[+] MiSetPageTablePfnBuddy: 0x" << std::hex << offsets.MiSetPageTablePfnBuddy << std::endl);

		// log proc/obj management functions
		Log(L"[+] === Process/Object Management Functions ===" << std::endl);
		Log(L"[+] PsLookupProcessByProcessId: 0x" << std::hex << offsets.PsLookupProcessByProcessId << std::endl);
		Log(L"[+] PsGetProcessPeb: 0x" << std::hex << offsets.PsGetProcessPeb << std::endl);
		Log(L"[+] PsGetProcessImageFileName: 0x" << std::hex << offsets.PsGetProcessImageFileName << std::endl);
		Log(L"[+] IoGetCurrentProcess: 0x" << std::hex << offsets.IoGetCurrentProcess << std::endl);
		Log(L"[+] ObfDereferenceObject: 0x" << std::hex << offsets.ObfDereferenceObject << std::endl);

		// log executive functions
		Log(L"[+] === Executive Functions ===" << std::endl);
		Log(L"[+] ExAllocatePool2: 0x" << std::hex << offsets.ExAllocatePool2 << std::endl);
		Log(L"[+] ExFreePoolWithTag: 0x" << std::hex << offsets.ExFreePoolWithTag << std::endl);
		Log(L"[+] ExGetPreviousMode: 0x" << std::hex << offsets.ExGetPreviousMode << std::endl);

		// log runtime library functions
		Log(L"[+] === Runtime Library Functions ===" << std::endl);
		Log(L"[+] RtlInitAnsiString: 0x" << std::hex << offsets.RtlInitAnsiString << std::endl);
		Log(L"[+] RtlInitUnicodeString: 0x" << std::hex << offsets.RtlInitUnicodeString << std::endl);
		Log(L"[+] RtlAnsiStringToUnicodeString: 0x" << std::hex << offsets.RtlAnsiStringToUnicodeString << std::endl);
		Log(L"[+] RtlCompareUnicodeString: 0x" << std::hex << offsets.RtlCompareUnicodeString << std::endl);
		Log(L"[+] RtlFreeUnicodeString: 0x" << std::hex << offsets.RtlFreeUnicodeString << std::endl);
		Log(L"[+] RtlGetVersion: 0x" << std::hex << offsets.RtlGetVersion << std::endl);

		// log debug functions
		Log(L"[+] === Debug Functions ===" << std::endl);
		Log(L"[+] DbgPrint: 0x" << std::hex << offsets.DbgPrint << std::endl);

		// log crt Functions
		Log(L"[+] === CRT Functions ===" << std::endl);
		Log(L"[+] memcpy: 0x" << std::hex << offsets.memcpy << std::endl);
		Log(L"[+] memset: 0x" << std::hex << offsets.memset << std::endl);
		Log(L"[+] strncmp: 0x" << std::hex << offsets.strncmp << std::endl);

		// log offsets
		Log(L"[+] === Structure Offsets ===" << std::endl);
		Log(L"[+] ActiveProcessLinks offset: 0x" << std::hex << offsets.ActiveProcessLinks << std::endl);

		EzPdbUnload(pdbPath, &pdb);

		Log(L"[<] Driver Mapped" << std::endl);

		if (!intel_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point, offsets.IoGetCurrentProcess, offsets.MmCopyVirtualMemory, &offsets)) {
			Log(L"[-] Failed to call driver entry" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (exitCode) {
			*exitCode = status;
			Log(L"[+] DriverEntry returned status: 0x" << std::hex << status << std::endl);
		}

		// Free memory
		if (free) {
			Log(L"[+] Freeing kernel memory" << std::endl);
			bool free_status = intel_driver::MmFreeIndependentPages(iqvw64e_device_handle, realBase, image_size);

			if (free_status) {
				Log(L"[+] Memory has been released" << std::endl);
			}
			else {
				Log(L"[-] WARNING: Failed to free memory!" << std::endl);
			}
		}

		alloc_size = 0;
		Log(L"[+] Releasing local memory" << std::endl);
		shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &local_image_base, &alloc_size, MEM_RELEASE);
		return realBase;

	} while (false);

	alloc_size = 0;
	Log(L"[+] Releasing local memory after failure" << std::endl);
	shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &local_image_base, &alloc_size, MEM_RELEASE);

	Log(L"[+] Freeing kernel memory after failure" << std::endl);
	bool free_status = intel_driver::MmFreeIndependentPages(iqvw64e_device_handle, kernel_image_base, image_size);

	if (free_status) {
		Log(L"[+] Memory has been released" << std::endl);
	}
	else {
		Log(L"[-] WARNING: Failed to free memory!" << std::endl);
	}

	return 0;
}

__forceinline void kdmapper::RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

// Fix cookie by @Jerem584
__forceinline bool kdmapper::FixSecurityCookie(void* local_image, uint64_t kernel_image_base)
{
	auto headers = GetNtHeaders(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		Log(L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		Log(L"[+] StackCookie not defined, fix cookie skipped" << std::endl);
		return true; // as I said, it is not an error and we should allow that behavior
	}

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image; //since our local image is already relocated the base returned will be kernel address

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
		Log(L"[-] StackCookie already fixed!? this probably wrong" << std::endl);
		return false;
	}

	Log(L"[+] Fixing stack cookie" << std::endl);

	auto new_cookie = (0x2B992DDFA232) ^ shadowcall<DWORD>("GetCurrentProcessId") ^ shadowcall<DWORD>("GetCurrentThreadId"); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie;
	return true;
}

__forceinline bool kdmapper::ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
#if !defined(DISABLE_OUTPUT)
			//std::cout << ("[-] Dependency ") << current_import.module_name << " wasn't found" << std::endl;
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			uint64_t function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != intel_driver::ntoskrnlAddr) {
					function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, intel_driver::ntoskrnlAddr, current_function_data.name);
					if (!function_address) {
#if !defined(DISABLE_OUTPUT)
						//std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
#endif
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}
	return true;
}

__forceinline int kdmapper::Init(nt::driver_alloc_mode driver_alloc_mode, nt::memory_type driver_mem_type) {

	utils::init_mapper_dependencies();

	void* iqvw64e_device_handle = intel_driver::Load();
	if (iqvw64e_device_handle == (void*)(0x5232)) {
		return NULL;
	}
	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	NTSTATUS exit_code = 0;
	if (!kdmapper::MapDriver(iqvw64e_device_handle, (std::uint8_t*)driver_shell, 0, 0, false, true, false, &exit_code, driver_alloc_mode, driver_mem_type)) {
		intel_driver::Unload(iqvw64e_device_handle);
		return NULL;
	}

	intel_driver::Unload(iqvw64e_device_handle);
	return 1;
}
