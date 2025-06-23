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

  bool flush_caches(HANDLE device_handle, void* address) {
    unsigned char flush_code[] = {
        // Function prologue - maintain stack alignment
        0x48, 0x83, 0xEC, 0x28,  // sub rsp, 0x28 (40 bytes for shadow space)

        // Save the address parameter (RCX) to R8
        0x49, 0x89, 0xC8,  // mov r8, rcx

        // Read CR4
        0x0F, 0x20, 0xE0,  // mov rax, cr4

        // Check if PGE is set (bit 7)
        0xA8, 0x80,  // test al, 0x80
        0x74, 0x0C,  // jz skip_pge_toggle (12 bytes ahead)

        // Clear PGE bit
        0x48, 0x25, 0x7F, 0xFF, 0xFF, 0xFF,  // and rax, 0xFFFFFF7F
        0x0F, 0x22, 0xE0,                    // mov cr4, rax

        // Set PGE bit back
        0x48, 0x0D, 0x80, 0x00, 0x00, 0x00,  // or rax, 0x80
        0x0F, 0x22, 0xE0,                    // mov cr4, rax

        // skip_pge_toggle:
        // Reload CR3
        0x0F, 0x20, 0xD8,  // mov rax, cr3
        0x0F, 0x22, 0xD8,  // mov cr3, rax

        // WBINVD
        0x0F, 0x09,  // wbinvd

        // INVLPG using saved address in R8
        0x41, 0x0F, 0x01, 0x38,  // invlpg [r8]

        // Function epilogue
        0x48, 0x83, 0xC4, 0x28,  // add rsp, 0x28
        0xC3                     // ret
    };

    // alloc executable memory
    auto exec_memory = intel_driver::MmAllocateIndependentPagesEx(device_handle, nt::PAGE_SIZE);
    if (!exec_memory) {
      Log(L"[-] Failed to allocate executable memory" << std::endl);
      return false;
    }

    // set executable permissions
    auto set_page_protection = intel_driver::MmSetPageProtection(
        device_handle, exec_memory, nt::PAGE_SIZE, PAGE_EXECUTE_READWRITE);
    if (!set_page_protection) {
      Log(L"[-] Failed to set page protection" << std::endl);
      intel_driver::MmFreeIndependentPages(device_handle, exec_memory, nt::PAGE_SIZE);
      return false;
    }

    // write within independent pages buffer
    if (!intel_driver::WriteMemory(device_handle, exec_memory, flush_code, sizeof(flush_code))) {
      Log(L"[-] Failed to write flush code" << std::endl);
      intel_driver::MmFreeIndependentPages(device_handle, exec_memory, nt::PAGE_SIZE);
      return false;
    }

    // execute shell
    intel_driver::CallKernelFunction<void>(device_handle, nullptr, exec_memory, address);

    // free shell
    intel_driver::MmFreeIndependentPages(device_handle, exec_memory, nt::PAGE_SIZE);

    // static uint64_t kernel_KeFlushEntireTb = 0;
    // if (!kernel_KeFlushEntireTb) {
    //     kernel_KeFlushEntireTb = intel_driver::GetKernelModuleExport(
    //         device_handle, intel_driver::ntoskrnlAddr, "KeFlushEntireTb");
    // }

    // if (kernel_KeFlushEntireTb) {
    //     __int64 flush_result = 0;
    //     intel_driver::CallKernelFunction(device_handle, &flush_result,
    //         kernel_KeFlushEntireTb, TRUE, TRUE);
    // }

    return true;
  }

  // convert physical address to virtual for reading/writing
  uintptr_t physical_to_virtual(HANDLE device_handle, uintptr_t physical_address) {
    static uint64_t kernel_MmGetVirtualForPhysical = intel_driver::GetKernelModuleExport(
        device_handle, intel_driver::ntoskrnlAddr, "MmGetVirtualForPhysical");
    if (!kernel_MmGetVirtualForPhysical) {
      Log(L"[-] Failed to find MmGetVirtualForPhysical" << std::endl);
      return 0;
    }

    PHYSICAL_ADDRESS phys_addr;
    phys_addr.QuadPart = physical_address;

    uintptr_t virtual_address = 0;
    intel_driver::CallKernelFunction(device_handle, &virtual_address,
                                     kernel_MmGetVirtualForPhysical, phys_addr);

    return virtual_address;
  }

  bool read_physical_address(HANDLE device_handle, uintptr_t physical_address, void* buffer,
                             size_t size) {
    uintptr_t virtual_address = physical_to_virtual(device_handle, physical_address);
    if (!virtual_address) {
      Log(L"[-] Failed to get virtual address for physical: 0x" << std::hex << physical_address
                                                                << std::endl);
      return false;
    }

    return intel_driver::ReadMemory(device_handle, virtual_address, buffer, size);
  }

  // write to physical address
  bool write_physical_address(HANDLE device_handle, uintptr_t physical_address, void* buffer,
                              size_t size) {
    uintptr_t virtual_address = physical_to_virtual(device_handle, physical_address);
    if (!virtual_address) {
      Log(L"[-] Failed to get virtual address for physical: 0x" << std::hex << physical_address
                                                                << std::endl);
      return false;
    }

    return intel_driver::WriteMemory(device_handle, virtual_address, buffer, size);
  }

  NTSTATUS write_page_tables(HANDLE device_handle, uintptr_t target_dir_base, uintptr_t base_va,
                             size_t page_count, bool use_large_page) {
    // Validate parameters
    if (!device_handle || !target_dir_base || !base_va || page_count == 0) {
      Log(L"[-] Invalid parameters to write_page_tables" << std::endl);
      return STATUS_INVALID_PARAMETER;
    }

    if (page_count > (use_large_page ? 0x200000 : 0x1000000)) {
      Log(L"[-] Page count " << page_count << L" exceeds reasonable limits" << std::endl);
      return STATUS_INVALID_PARAMETER;
    }

    // Get kernel function exports
    static uint64_t kernel_RtlZeroMemory = 0;
    static uint64_t kernel_MmIsAddressValid = 0;

    if (!kernel_RtlZeroMemory) {
      kernel_RtlZeroMemory = intel_driver::GetKernelModuleExport(
          device_handle, intel_driver::ntoskrnlAddr, "RtlZeroMemory");
    }
    if (!kernel_MmIsAddressValid) {
      kernel_MmIsAddressValid = intel_driver::GetKernelModuleExport(
          device_handle, intel_driver::ntoskrnlAddr, "MmIsAddressValid");
    }

    for (size_t i = 0; i < page_count; ++i) {
      try {
        const auto current_va =
            base_va + i * (use_large_page ? nt::LARGE_PAGE_SIZE : nt::PAGE_SIZE);
        ADDRESS_TRANSLATION_HELPER helper;
        helper.AsUInt64 = current_va;

        // Validate virtual address alignment
        if (use_large_page && (current_va & (nt::LARGE_PAGE_SIZE - 1)) != 0) {
          Log(L"[-] Unaligned large page VA: 0x" << std::hex << current_va << std::endl);
          return STATUS_INVALID_PARAMETER;
        }

        uintptr_t actual_page_va = 0;

        if (use_large_page) {
          actual_page_va = reinterpret_cast<uintptr_t>(
              VirtualAlloc(NULL, nt::LARGE_PAGE_SIZE, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                           PAGE_READWRITE));
        } else {
          actual_page_va = kdmapper::AllocIndependentPages(device_handle, nt::PAGE_SIZE);
        }

        if (!actual_page_va) {
          Log(L"[-] Failed to allocate " << (use_large_page ? L"2MB aligned large page" : L"page")
                                         << std::endl);
          return STATUS_NO_MEMORY;
        }

        // validate allocated page
        if (kernel_MmIsAddressValid) {
          try {
            BOOLEAN is_valid = FALSE;
            if (intel_driver::CallKernelFunction(device_handle, &is_valid, kernel_MmIsAddressValid,
                                                 reinterpret_cast<PVOID>(actual_page_va))) {
              if (!is_valid) {
                Log(L"[-] Allocated page 0x" << std::hex << actual_page_va << L" is not valid"
                                             << std::endl);
                return STATUS_INVALID_ADDRESS;
              }
            }
          } catch (...) {
            Log(L"[-] Exception validating allocated page address" << std::endl);
          }
        }

        // clear the allocated page
        try {
          if (kernel_RtlZeroMemory) {
            intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
                                                   reinterpret_cast<void*>(actual_page_va),
                                                   use_large_page ? nt::LARGE_PAGE_SIZE
                                                                  : nt::PAGE_SIZE);
          }
        } catch (...) {
          Log(L"[-] Exception clearing allocated page" << std::endl);
        }

        uintptr_t page_frame_number = 0;

        try {
          // get page table entry address
          auto pte_va = use_large_page
                            ? intel_driver::MiGetPdeAddress(device_handle, actual_page_va)
                            : intel_driver::MiGetPteAddress(device_handle, actual_page_va);
          if (!pte_va) {
            Log(L"[-] Failed to get page table entry address for 0x" << std::hex << actual_page_va
                                                                     << std::endl);
            return STATUS_UNSUCCESSFUL;
          }

          if (use_large_page) {
            PDE_2MB_64 entry = {0};
            if (!intel_driver::ReadMemory(device_handle, pte_va, &entry, sizeof(PDE_2MB_64))) {
              Log(L"[-] Failed to read 2MB PDE at 0x" << std::hex << pte_va << std::endl);
              return STATUS_UNSUCCESSFUL;
            }

            page_frame_number = entry.PageFrameNumber;
          } else {
            PTE_64 entry = {0};
            if (!intel_driver::ReadMemory(device_handle, pte_va, &entry, sizeof(PTE_64))) {
              Log(L"[-] Failed to read PTE at 0x" << std::hex << pte_va << std::endl);
              return STATUS_UNSUCCESSFUL;
            }
            page_frame_number = entry.PageFrameNumber;
          }

          if (!page_frame_number) {
            Log(L"[-] PFN is null for allocated page" << std::endl);
            return STATUS_UNSUCCESSFUL;
          }
        } catch (...) {
          Log(L"[-] Exception getting PFN for allocated page" << std::endl);
          return STATUS_UNSUCCESSFUL;
        }

        // validate page table indices
        if (helper.AsIndex.Pml4 >= 512 || helper.AsIndex.Pdpt >= 512 || helper.AsIndex.Pd >= 512 ||
            helper.AsIndex.Pt >= 512) {
          Log(L"[-] Invalid page table indices for VA 0x" << std::hex << current_va << std::endl);
          return STATUS_INVALID_PARAMETER;
        }

        uintptr_t pml4_phys = target_dir_base;
        PML4E_64 pml4e = {0};

        try {
          // read and setup PML4E
          if (!read_physical_address(device_handle,
                                     pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e,
                                     sizeof(PML4E_64))) {
            Log(L"[-] Failed to read PML4E at offset " << helper.AsIndex.Pml4 << std::endl);
            return STATUS_UNSUCCESSFUL;
          }

          if (!pml4e.Present) {
            auto pdpt_va = kdmapper::AllocIndependentPages(device_handle, nt::PAGE_SIZE);
            if (!pdpt_va) {
              Log(L"[-] Failed to allocate PDPT for iteration " << i << std::endl);
              return STATUS_NO_MEMORY;
            }

            // clear PDPT
            if (kernel_RtlZeroMemory) {
              try {
                intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
                                                       reinterpret_cast<void*>(pdpt_va),
                                                       nt::PAGE_SIZE);
              } catch (...) {
                Log(L"[-] Exception clearing PDPT" << std::endl);
              }
            }

            // get physical address of PDPT
            uintptr_t pdpt_pte_va = intel_driver::MiGetPteAddress(device_handle, pdpt_va);
            if (!pdpt_pte_va) {
              Log(L"[-] Failed to get PTE address for PDPT" << std::endl);
              return STATUS_UNSUCCESSFUL;
            }

            PTE_64 pdpt_pte = {0};
            if (!intel_driver::ReadMemory(device_handle, pdpt_pte_va, &pdpt_pte, sizeof(PTE_64))) {
              Log(L"[-] Failed to read PTE for PDPT" << std::endl);
              return STATUS_UNSUCCESSFUL;
            }

            if (!pdpt_pte.PageFrameNumber) {
              Log(L"[-] Invalid PDPT PFN" << std::endl);
              return STATUS_UNSUCCESSFUL;
            }

            pml4e.Flags = 0;
            pml4e.Present = 1;
            pml4e.Write = 1;
            pml4e.Supervisor = 0;
            pml4e.ExecuteDisable = 0;
            pml4e.PageFrameNumber = pdpt_pte.PageFrameNumber;

            if (!write_physical_address(device_handle,
                                        pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64), &pml4e,
                                        sizeof(PML4E_64))) {
              Log(L"[-] Failed to write PML4E" << std::endl);
              return STATUS_UNSUCCESSFUL;
            }
          }
        } catch (...) {
          Log(L"[-] Exception handling PML4E" << std::endl);
          return STATUS_UNSUCCESSFUL;
        }

        try {
          // read and setup PDPT
          PDPTE_64 pdpte = {0};
          if (!read_physical_address(device_handle,
                                     PFN_TO_PAGE(pml4e.PageFrameNumber) +
                                         helper.AsIndex.Pdpt * sizeof(PDPTE_64),
                                     &pdpte, sizeof(PDPTE_64))) {
            Log(L"[-] Failed to read PDPTE" << std::endl);
            return STATUS_UNSUCCESSFUL;
          }

          if (!pdpte.Present) {
            auto pd_va = kdmapper::AllocIndependentPages(device_handle, nt::PAGE_SIZE);
            if (!pd_va) {
              Log(L"[-] Failed to allocate PD for iteration " << i << std::endl);
              return STATUS_NO_MEMORY;
            }

            // clear PD
            if (kernel_RtlZeroMemory) {
              try {
                intel_driver::CallKernelFunction<void>(device_handle, nullptr, kernel_RtlZeroMemory,
                                                       reinterpret_cast<void*>(pd_va),
                                                       nt::PAGE_SIZE);
              } catch (...) {
                Log(L"[-] Exception clearing PD" << std::endl);
              }
            }

            // get physical address of PD
            uintptr_t pd_pte_va = intel_driver::MiGetPteAddress(device_handle, pd_va);
            if (!pd_pte_va) {
              Log(L"[-] Failed to get PTE address for PD" << std::endl);
              return STATUS_UNSUCCESSFUL;
            }

            PTE_64 pd_pte = {0};
            if (!intel_driver::ReadMemory(device_handle, pd_pte_va, &pd_pte, sizeof(PTE_64))) {
              Log(L"[-] Failed to read PTE for PD" << std::endl);
              return STATUS_UNSUCCESSFUL;
            }

            if (!pd_pte.PageFrameNumber) {
              Log(L"[-] Invalid PD PFN" << std::endl);
              return STATUS_UNSUCCESSFUL;
            }

            pdpte.Flags = 0;
            pdpte.Present = 1;
            pdpte.Write = 1;
            pdpte.Supervisor = 0;
            pdpte.ExecuteDisable = 0;
            pdpte.PageFrameNumber = pd_pte.PageFrameNumber;

            if (!write_physical_address(device_handle,
                                        PFN_TO_PAGE(pml4e.PageFrameNumber) +
                                            helper.AsIndex.Pdpt * sizeof(PDPTE_64),
                                        &pdpte, sizeof(PDPTE_64))) {
              Log(L"[-] Failed to write PDPTE" << std::endl);
              return STATUS_UNSUCCESSFUL;
            }
          }

          if (use_large_page) {
            // read and setup 2MB PD for large page
            PDE_2MB_64 pde = {0};
            if (!read_physical_address(device_handle,
                                       PFN_TO_PAGE(pdpte.PageFrameNumber) +
                                           helper.AsIndex.Pd * sizeof(PDE_2MB_64),
                                       &pde, sizeof(PDE_2MB_64))) {
              Log(L"[-] Failed to read large PDE" << std::endl);
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

              if (!write_physical_address(device_handle,
                                          PFN_TO_PAGE(pdpte.PageFrameNumber) +
                                              helper.AsIndex.Pd * sizeof(PDE_2MB_64),
                                          &pde, sizeof(PDE_2MB_64))) {
                Log(L"[-] Failed to write large PDE" << std::endl);
                return STATUS_UNSUCCESSFUL;
              }
            }
          } else {
            // read and setup PD for regular page
            PDE_64 pde = {0};
            if (!read_physical_address(device_handle,
                                       PFN_TO_PAGE(pdpte.PageFrameNumber) +
                                           helper.AsIndex.Pd * sizeof(PDE_64),
                                       &pde, sizeof(PDE_64))) {
              Log(L"[-] Failed to read PDE" << std::endl);
              return STATUS_UNSUCCESSFUL;
            }

            if (!pde.Present) {
              auto pt_va = kdmapper::AllocIndependentPages(device_handle, nt::PAGE_SIZE);
              if (!pt_va) {
                Log(L"[-] Failed to allocate PT for iteration " << i << std::endl);
                return STATUS_NO_MEMORY;
              }

              // clear PT
              if (kernel_RtlZeroMemory) {
                try {
                  intel_driver::CallKernelFunction<void>(
                      device_handle, nullptr, kernel_RtlZeroMemory, reinterpret_cast<void*>(pt_va),
                      nt::PAGE_SIZE);
                } catch (...) {
                  Log(L"[-] Exception clearing PT" << std::endl);
                }
              }

              // get physical address of PT
              uintptr_t pt_pte_va = intel_driver::MiGetPteAddress(device_handle, pt_va);
              if (!pt_pte_va) {
                Log(L"[-] Failed to get PTE address for PT" << std::endl);
                return STATUS_UNSUCCESSFUL;
              }

              PTE_64 pt_pte = {0};
              if (!intel_driver::ReadMemory(device_handle, pt_pte_va, &pt_pte, sizeof(PTE_64))) {
                Log(L"[-] Failed to read PTE for PT" << std::endl);
                return STATUS_UNSUCCESSFUL;
              }

              if (!pt_pte.PageFrameNumber) {
                Log(L"[-] Invalid PT PFN" << std::endl);
                return STATUS_UNSUCCESSFUL;
              }

              pde.Flags = 0;
              pde.Present = 1;
              pde.Write = 1;
              pde.Supervisor = 0;
              pde.ExecuteDisable = 0;
              pde.PageFrameNumber = pt_pte.PageFrameNumber;

              if (!write_physical_address(device_handle,
                                          PFN_TO_PAGE(pdpte.PageFrameNumber) +
                                              helper.AsIndex.Pd * sizeof(PDE_64),
                                          &pde, sizeof(PDE_64))) {
                Log(L"[-] Failed to write PDE" << std::endl);
                return STATUS_UNSUCCESSFUL;
              }
            }

            // setup PTE
            PTE_64 pte = {0};
            pte.Present = 1;
            pte.Write = 1;
            pte.Supervisor = 0;
            pte.ExecuteDisable = 0;
            pte.PageFrameNumber = page_frame_number;

            if (!write_physical_address(device_handle,
                                        PFN_TO_PAGE(pde.PageFrameNumber) +
                                            helper.AsIndex.Pt * sizeof(PTE_64),
                                        &pte, sizeof(PTE_64))) {
              Log(L"[-] Failed to write PTE" << std::endl);
              return STATUS_UNSUCCESSFUL;
            }
          }
        } catch (...) {
          Log(L"[-] Exception handling PDPTE/PDE/PTE for iteration " << i << std::endl);
          return STATUS_UNSUCCESSFUL;
        }

        Log(L"[+] Page " << i << L": VA: 0x" << std::hex << current_va << L", PFN: 0x"
                         << page_frame_number << std::endl);
      } catch (...) {
        Log(L"[-] Exception in page table setup for iteration " << i << std::endl);
        return STATUS_UNSUCCESSFUL;
      }
    }

    if (!page_table::flush_caches(device_handle, reinterpret_cast<void*>(base_va))) {
      return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
  }

  void* allocate_within_current_process_context(HANDLE device_handle, const uint32_t target_pid,
                                                const size_t size, const bool use_large_page,
                                                const bool use_high_address = true) {
    try {
      // Validate input parameters
      if (!device_handle || size == 0) {
        Log(L"[-] Invalid parameters to allocate_within_current_process_context" << std::endl);
        return nullptr;
      }

      if (size > (use_large_page ? 0x40000000000ULL : 0x10000000000ULL)) {
        Log(L"[-] Size " << size << L" exceeds maximum limits" << std::endl);
        return nullptr;
      }

      // Page size constants
      const size_t page_size = use_large_page ? nt::LARGE_PAGE_SIZE : nt::PAGE_SIZE;
      const size_t page_mask = page_size - 1;
      const size_t page_shift = use_large_page ? 21 : 12;

      // Align the requested size to page boundaries
      const size_t aligned_size = (size + page_mask) & ~page_mask;
      const size_t page_count = aligned_size >> page_shift;

      if (page_count == 0 || page_count > (use_large_page ? 0x200000 : 0x1000000)) {
        Log(L"[-] Invalid page count: " << page_count << std::endl);
        return nullptr;
      }

      // Get kernel exports
      static uint64_t kernel_PsGetCurrentProcess = 0;
      static uint64_t kernel_KeFlushEntireTb = 0;

      if (!kernel_PsGetCurrentProcess) {
        kernel_PsGetCurrentProcess = intel_driver::GetKernelModuleExport(
            device_handle, intel_driver::ntoskrnlAddr, "PsGetCurrentProcess");
        if (!kernel_PsGetCurrentProcess) {
          Log(L"[-] Failed to find PsGetCurrentProcess" << std::endl);
          return nullptr;
        }
      }

      if (!kernel_KeFlushEntireTb) {
        kernel_KeFlushEntireTb = intel_driver::GetKernelModuleExport(
            device_handle, intel_driver::ntoskrnlAddr, "KeFlushEntireTb");
      }

      // Get current process EPROCESS structure
      uintptr_t current_process = 0;
      try {
        if (!intel_driver::CallKernelFunction(device_handle, &current_process,
                                              kernel_PsGetCurrentProcess)) {
          Log(L"[-] Failed to call PsGetCurrentProcess" << std::endl);
          return nullptr;
        }
      } catch (...) {
        Log(L"[-] Exception calling PsGetCurrentProcess" << std::endl);
        return nullptr;
      }

      if (!current_process) {
        Log(L"[-] PsGetCurrentProcess returned null" << std::endl);
        return nullptr;
      }

      // Get directory base (CR3)
      uintptr_t target_dir_base = 0;
      try {
        if (!intel_driver::ReadMemory(device_handle, current_process + 0x28, &target_dir_base,
                                      sizeof(uintptr_t))) {
          Log(L"[-] Failed to read target process directory base" << std::endl);
          return nullptr;
        }
      } catch (...) {
        Log(L"[-] Exception reading directory base" << std::endl);
        return nullptr;
      }

      if (!target_dir_base) {
        Log(L"[-] Invalid directory base" << std::endl);
        return nullptr;
      }

      // Initialize random seed (only once per process)
      static bool rand_initialized = false;
      if (!rand_initialized) {
        srand(static_cast<unsigned int>(time(nullptr)) ^ GetCurrentProcessId());
        rand_initialized = true;
      }

      // Find a non-present PML4E in the appropriate address space
      uint32_t selected_pml4_index = 0;
      PML4E_64 pml4e = {0};

      // Set the search range based on whether high or low address is requested
      uint32_t start_idx = use_high_address ? 256 : 100;
      uint32_t end_idx = use_high_address ? 511 : 256;
      const char* space_type = use_high_address ? "kernel" : "usermode";

      // Validate index ranges
      if (start_idx >= 512 || end_idx > 512 || start_idx >= end_idx) {
        Log(L"[-] Invalid PML4 index range: " << start_idx << L"-" << end_idx << std::endl);
        return nullptr;
      }

      // Build a list of available (non-present) PML4 indices
      std::vector<uint32_t> available_indices;
      available_indices.reserve(end_idx - start_idx);

      try {
        for (uint32_t idx = start_idx; idx < end_idx; idx++) {
          if (read_physical_address(device_handle, target_dir_base + idx * sizeof(PML4E_64), &pml4e,
                                    sizeof(PML4E_64))) {
            if (!pml4e.Present) {
              available_indices.push_back(idx);
            }
          }
        }
      } catch (...) {
        Log(L"[-] Exception scanning PML4 entries" << std::endl);
        return nullptr;
      }

      if (available_indices.empty()) {
        Log(L"[-] Failed to find any non-present PML4E in " << space_type << " space" << std::endl);
        return nullptr;
      }

      Log(L"[+] Found " << available_indices.size() << " available PML4 entries in " << space_type
                        << " space" << std::endl);

      // Randomly select one of the available indices
      int random_selection = rand() % available_indices.size();
      selected_pml4_index = available_indices[random_selection];

      Log(L"[+] Randomly selected PML4E at index: "
          << selected_pml4_index << " (selection " << random_selection << " out of "
          << available_indices.size() << " available)" << std::endl);

      // Additional randomization within the selected PML4E's address space
      uint64_t additional_offset = 0;
      if (use_large_page) {
        // For large pages, randomize PDPTE selection (bits 30-38)
        additional_offset = (static_cast<uint64_t>(rand() % 512) << 30);
      } else {
        // For small pages, randomize at PDE level (bits 21-29)
        additional_offset = (static_cast<uint64_t>(rand() % 512) << 21);
      }

      // Calculate the base virtual address using the selected PML4E index
      uintptr_t base_va;
      if (use_high_address) {
        base_va =
            0xFFFF000000000000ULL | page_table::get_pml4e(selected_pml4_index) | additional_offset;
      } else {
        base_va = page_table::get_pml4e(selected_pml4_index) | additional_offset;
      }

      Log(L"[+] Selected base address: 0x" << std::hex << base_va << L" (PML4: "
                                           << selected_pml4_index << L", offset: 0x"
                                           << additional_offset << L")" << std::endl);

      // Write page tables
      NTSTATUS write_pt_status;
      try {
        write_pt_status =
            write_page_tables(device_handle, target_dir_base, base_va, page_count, use_large_page);
      } catch (...) {
        Log(L"[-] Exception during write_page_tables" << std::endl);
        return nullptr;
      }

      if (!NT_SUCCESS(write_pt_status)) {
        Log(L"[-] Failed to write page tables, NTSTATUS: 0x" << std::hex << write_pt_status
                                                             << std::endl);
        return nullptr;
      }

      //// Flush TLB
      // try {
      //     if (kernel_KeFlushEntireTb) {
      //         __int64 flush_result = 0;
      //         intel_driver::CallKernelFunction(device_handle, &flush_result,
      //         kernel_KeFlushEntireTb, TRUE, TRUE);
      //     }
      // }
      // catch (...) {
      //     Log(L"[-] Exception flushing TLB" << std::endl);
      //     // Continue anyway, TLB flush failure is not critical
      // }

      Log(L"[+] Successfully allocated " << page_count << L" pages at base VA: 0x" << std::hex
                                         << base_va << std::endl);
      return reinterpret_cast<void*>(base_va);
    } catch (...) {
      Log(L"[-] Exception in allocate_within_current_process_context" << std::endl);
      return nullptr;
    }
  }
}  // namespace page_table
