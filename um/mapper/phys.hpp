#pragma once

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
			const auto current_va = base_va + i * (use_large_page ? nt::LARGE_PAGE_SIZE : nt::PAGE_SIZE);
			ADDRESS_TRANSLATION_HELPER helper;
			helper.AsUInt64 = current_va;

			uintptr_t actual_page_va = 0;
			if (use_large_page) {
				// for large pages, we need contiguous memory
				actual_page_va = reinterpret_cast<uintptr_t>(kdmapper::AllocContiguousMemory(device_handle, nt::LARGE_PAGE_SIZE));
			}
			else {
				actual_page_va = reinterpret_cast<uintptr_t>(VirtualAlloc(NULL, nt::PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
				//actual_page_va = kdmapper::AllocIndependentPages(device_handle, nt::PAGE_SIZE);
			}

			if (!actual_page_va) {
				Log(L"[-] Failed to allocate actual page" << std::endl);
				return STATUS_NO_MEMORY;
			}

			// clear the allocated page
			static uint64_t kernel_RtlZeroMemory = intel_driver::GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "RtlZeroMemory");
			if (kernel_RtlZeroMemory) {
				intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
					reinterpret_cast<void*>(actual_page_va), use_large_page ? nt::LARGE_PAGE_SIZE : nt::PAGE_SIZE);
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
				auto pdpt_va = kdmapper::AllocIndependentPages(device_handle, nt::PAGE_SIZE);
				if (!pdpt_va) {
					Log(L"[-] Failed to allocate pdpt" << std::endl);
					return STATUS_NO_MEMORY;
				}

				// clear PDPT
				if (kernel_RtlZeroMemory) {
					intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
						reinterpret_cast<void*>(pdpt_va), nt::PAGE_SIZE);
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
				auto pd_va = kdmapper::AllocIndependentPages(device_handle, nt::PAGE_SIZE);
				if (!pd_va) {
					Log(L"[-] Failed to allocate pd" << std::endl);
					return STATUS_NO_MEMORY;
				}

				// clear PD
				if (kernel_RtlZeroMemory) {
					intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
						reinterpret_cast<void*>(pd_va), nt::PAGE_SIZE);
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
					auto pt_va = kdmapper::AllocIndependentPages(device_handle, nt::PAGE_SIZE);
					if (!pt_va) {
						Log(L"ERROR: failed to allocate pt" << std::endl);
						return STATUS_NO_MEMORY;
					}

					// clear PT
					if (kernel_RtlZeroMemory) {
						intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
							reinterpret_cast<void*>(pt_va), nt::PAGE_SIZE);
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
		const size_t page_size = use_large_page ? nt::LARGE_PAGE_SIZE : nt::PAGE_SIZE;
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

}
