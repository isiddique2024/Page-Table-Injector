#include "page_table_manager.hpp"
#include <iostream>
#include <vector>
#include <random>
#include <ctime>

// forward declarations for external NT functions
extern "C" {
NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                 PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                             ULONG FreeType);
}

auto page_table_manager_t::read_physical_address(HANDLE device_handle,
                                                 std::uint64_t physical_address, void* buffer,
                                                 std::size_t size) -> bool {
  if (!device_handle || !physical_address || !buffer || !size) {
    return false;
  }

  // get MmGetVirtualForPhysical export
  static std::uint64_t kernel_MmGetVirtualForPhysical = 0;
  if (!kernel_MmGetVirtualForPhysical) {
    kernel_MmGetVirtualForPhysical = g_utils->get_kernel_module_export(
        device_handle, g_utils->get_kernel_module_address("ntoskrnl.exe"),
        "MmGetVirtualForPhysical");
    if (!kernel_MmGetVirtualForPhysical) {
      return false;
    }
  }

  // convert physical address to PHYSICAL_ADDRESS structure
  PHYSICAL_ADDRESS phys_addr;
  phys_addr.QuadPart = physical_address;

  // call MmGetVirtualForPhysical to get virtual address
  std::uint64_t virtual_address = 0;
  if (!g_memory_manager->call_kernel_function(device_handle, &virtual_address,
                                              kernel_MmGetVirtualForPhysical, phys_addr)) {
    return false;
  }

  if (!virtual_address) {
    return false;
  }

  // use regular ReadMemory with the virtual address
  return g_memory_manager->read_memory(device_handle, virtual_address, buffer, size);
}

auto page_table_manager_t::write_physical_address(HANDLE device_handle,
                                                  std::uint64_t physical_address, void* buffer,
                                                  std::size_t size) -> bool {
  if (!device_handle || !physical_address || !buffer || !size) {
    return false;
  }

  // get MmGetVirtualForPhysical export
  static std::uint64_t kernel_MmGetVirtualForPhysical = 0;
  if (!kernel_MmGetVirtualForPhysical) {
    kernel_MmGetVirtualForPhysical = g_utils->get_kernel_module_export(
        device_handle, g_utils->get_kernel_module_address("ntoskrnl.exe"),
        "MmGetVirtualForPhysical");
    if (!kernel_MmGetVirtualForPhysical) {
      return false;
    }
  }

  // convert physical address to PHYSICAL_ADDRESS structure
  PHYSICAL_ADDRESS phys_addr;
  phys_addr.QuadPart = physical_address;

  // call MmGetVirtualForPhysical to get virtual address
  std::uint64_t virtual_address = 0;
  if (!g_memory_manager->call_kernel_function(device_handle, &virtual_address,
                                              kernel_MmGetVirtualForPhysical, phys_addr)) {
    return false;
  }

  if (!virtual_address) {
    return false;
  }

  // use regular WriteMemory with the virtual address
  return g_memory_manager->write_memory(device_handle, virtual_address, buffer, size);
}

auto page_table_manager_t::get_page_frame_number(HANDLE device_handle,
                                                 std::uint64_t virtual_address, bool use_large_page)
    -> std::uint64_t {
  std::uint64_t physical_address = 0;
  if (!g_memory_manager->get_physical_address(device_handle, virtual_address, &physical_address)) {
    return 0;
  }

  return physical_address >> (use_large_page ? 21 : 12);
}

auto page_table_manager_t::allocate_within_current_process_context(HANDLE device_handle,
                                                                   std::uint32_t target_pid,
                                                                   std::size_t size,
                                                                   bool use_large_page,
                                                                   bool use_high_address) -> void* {
  if (!device_handle || size == 0) {
    return nullptr;
  }

  if (size > (use_large_page ? 0x40000000000ULL : 0x10000000000ULL)) {
    return nullptr;
  }

  // page size constants
  const std::size_t page_size = use_large_page ? 0x200000 : 0x1000;  // 2MB or 4KB
  const std::size_t page_mask = page_size - 1;
  const std::size_t page_shift = use_large_page ? 21 : 12;

  // align the requested size to page boundaries
  const std::size_t aligned_size = (size + page_mask) & ~page_mask;
  const std::size_t page_count = aligned_size >> page_shift;

  if (page_count == 0 || page_count > (use_large_page ? 0x200000 : 0x1000000)) {
    return nullptr;
  }

  // get kernel exports
  static std::uint64_t kernel_PsGetCurrentProcess = 0;
  if (!kernel_PsGetCurrentProcess) {
    kernel_PsGetCurrentProcess = g_utils->get_kernel_module_export(
        device_handle, g_utils->get_kernel_module_address("ntoskrnl.exe"), "PsGetCurrentProcess");
    if (!kernel_PsGetCurrentProcess) {
      return nullptr;
    }
  }

  // get current process EPROCESS structure
  std::uint64_t current_process = 0;
  if (!g_memory_manager->call_kernel_function(device_handle, &current_process,
                                              kernel_PsGetCurrentProcess)) {
    return nullptr;
  }

  if (!current_process) {
    return nullptr;
  }

  // get directory base (CR3)
  std::uint64_t target_dir_base = 0;
  if (!g_memory_manager->read_memory(device_handle, current_process + 0x28, &target_dir_base,
                                     sizeof(std::uint64_t))) {
    return nullptr;
  }

  if (!target_dir_base) {
    return nullptr;
  }

  // find a non-present PML4E in the appropriate address space
  std::uint32_t start_idx = use_high_address ? 256 : 100;
  std::uint32_t end_idx = use_high_address ? 511 : 256;

  // find available PML4 indices
  std::vector<std::uint32_t> available_indices;
  for (std::uint32_t idx = start_idx; idx < end_idx; idx++) {
    PML4E_64 pml4e = {0};
    if (read_physical_address(device_handle, target_dir_base + idx * sizeof(PML4E_64), &pml4e,
                              sizeof(PML4E_64))) {
      if (!pml4e.Present) {
        available_indices.push_back(idx);
      }
    }
  }

  if (available_indices.empty()) {
    return nullptr;
  }

  // randomly select one of the available indices
  srand(static_cast<unsigned int>(time(nullptr)) ^ g_utils->get_current_process_id());
  int random_selection = rand() % available_indices.size();
  std::uint32_t selected_pml4_index = available_indices[random_selection];

  // additional randomization within the selected PML4E's address space
  std::uint64_t additional_offset = 0;
  if (use_large_page) {
    additional_offset = (static_cast<std::uint64_t>(rand() % 512) << 30);
  } else {
    additional_offset = (static_cast<std::uint64_t>(rand() % 512) << 21);
  }

  // calc the base virtual address using the selected PML4E index
  std::uint64_t base_va;
  if (use_high_address) {
    base_va = 0xFFFF000000000000ULL | get_pml4e(selected_pml4_index) | additional_offset;
  } else {
    base_va = get_pml4e(selected_pml4_index) | additional_offset;
  }

  // write page tables
  if (!write_page_tables(device_handle, target_dir_base, base_va, page_count, use_large_page)) {
    return nullptr;
  }

  return reinterpret_cast<void*>(base_va);
}

auto page_table_manager_t::write_page_tables(HANDLE device_handle, std::uint64_t target_dir_base,
                                             std::uint64_t base_va, std::size_t page_count,
                                             bool use_large_page) -> bool {
  if (!device_handle || !target_dir_base || !base_va || page_count == 0) {
    return false;
  }

  if (page_count > (use_large_page ? 0x200000 : 0x1000000)) {
    return false;
  }

  // get kernel function exports
  static std::uint64_t kernel_RtlZeroMemory = 0;
  if (!kernel_RtlZeroMemory) {
    kernel_RtlZeroMemory = g_utils->get_kernel_module_export(
        device_handle, g_utils->get_kernel_module_address("ntoskrnl.exe"), "RtlZeroMemory");
  }

  for (std::size_t i = 0; i < page_count; ++i) {
    const auto current_va = base_va + i * (use_large_page ? 0x200000 : 0x1000);

    // create address translation helper
    ADDRESS_TRANSLATION_HELPER helper;
    helper.AsUInt64 = current_va;

    // validate virtual address alignment
    if (use_large_page && (current_va & (0x200000 - 1)) != 0) {
      return false;
    }

    std::uint64_t actual_page_va = 0;

    if (use_large_page) {
      actual_page_va = reinterpret_cast<std::uint64_t>(
          VirtualAlloc(NULL, 0x200000, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE));
    } else {
      // actual_page_va = g_memory_manager->allocate_independent_pages(device_handle, 0x1000);
      actual_page_va = reinterpret_cast<std::uint64_t>(
          VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    }

    if (!actual_page_va) {
      return false;
    }

    // clear the allocated page
    if (kernel_RtlZeroMemory) {
      g_memory_manager->call_kernel_function<void>(device_handle, nullptr, kernel_RtlZeroMemory,
                                                   reinterpret_cast<void*>(actual_page_va),
                                                   use_large_page ? 0x200000 : 0x1000);
    }

    std::uint64_t page_frame_number =
        get_page_frame_number(device_handle, actual_page_va, use_large_page);
    if (!page_frame_number) {
      return false;
    }

    // validate page table indices
    if (helper.AsIndex.Pml4 >= 512 || helper.AsIndex.Pdpt >= 512 || helper.AsIndex.Pd >= 512 ||
        helper.AsIndex.Pt >= 512) {
      return false;
    }

    std::uint64_t pml4_phys = target_dir_base;
    PML4E_64 pml4e = {0};

    // read and setup PML4E
    if (!read_physical_address(device_handle, pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64),
                               &pml4e, sizeof(PML4E_64))) {
      return false;
    }

    if (!pml4e.Present) {
      auto pdpt_va = g_memory_manager->allocate_independent_pages(device_handle, 0x1000);
      if (!pdpt_va) {
        return false;
      }

      // clear PDPT
      if (kernel_RtlZeroMemory) {
        g_memory_manager->call_kernel_function<void>(device_handle, nullptr, kernel_RtlZeroMemory,
                                                     reinterpret_cast<void*>(pdpt_va), 0x1000);
      }

      // get physical address of PDPT
      std::uint64_t pdpt_pfn = get_page_frame_number(device_handle, pdpt_va, false);
      if (!pdpt_pfn) {
        return false;
      }

      pml4e.Flags = 0;
      pml4e.Present = 1;
      pml4e.Write = 1;
      pml4e.Supervisor = 0;
      pml4e.ExecuteDisable = 0;
      pml4e.Accessed = 1;
      pml4e.PageFrameNumber = pdpt_pfn;

      if (!write_physical_address(device_handle, pml4_phys + helper.AsIndex.Pml4 * sizeof(PML4E_64),
                                  &pml4e, sizeof(PML4E_64))) {
        return false;
      }

      // flush caches after PML4E modification
      flush_caches(device_handle, reinterpret_cast<void*>(current_va));
    }

    // read and setup PDPT
    PDPTE_64 pdpte = {0};
    if (!read_physical_address(device_handle,
                               PFN_TO_PAGE(pml4e.PageFrameNumber) +
                                   helper.AsIndex.Pdpt * sizeof(PDPTE_64),
                               &pdpte, sizeof(PDPTE_64))) {
      return false;
    }

    if (!pdpte.Present) {
      auto pd_va = g_memory_manager->allocate_independent_pages(device_handle, 0x1000);
      if (!pd_va) {
        return false;
      }

      // clear PD
      if (kernel_RtlZeroMemory) {
        g_memory_manager->call_kernel_function<void>(device_handle, nullptr, kernel_RtlZeroMemory,
                                                     reinterpret_cast<void*>(pd_va), 0x1000);
      }

      std::uint64_t pd_pfn = get_page_frame_number(device_handle, pd_va, false);
      if (!pd_pfn) {
        return false;
      }

      pdpte.Flags = 0;
      pdpte.Present = 1;
      pdpte.Write = 1;
      pdpte.Supervisor = 0;
      pdpte.Accessed = 1;
      pdpte.ExecuteDisable = 0;
      pdpte.PageFrameNumber = pd_pfn;

      if (!write_physical_address(device_handle,
                                  PFN_TO_PAGE(pml4e.PageFrameNumber) +
                                      helper.AsIndex.Pdpt * sizeof(PDPTE_64),
                                  &pdpte, sizeof(PDPTE_64))) {
        return false;
      }

      // flush caches after PDPTE modification
      flush_caches(device_handle, reinterpret_cast<void*>(current_va));
    }

    if (use_large_page) {
      // setup 2MB PDE for large page
      PDE_2MB_64 pde = {0};
      if (!read_physical_address(device_handle,
                                 PFN_TO_PAGE(pdpte.PageFrameNumber) +
                                     helper.AsIndex.Pd * sizeof(PDE_2MB_64),
                                 &pde, sizeof(PDE_2MB_64))) {
        return false;
      }

      if (!pde.Present) {
        pde.Flags = 0;
        pde.Present = 1;
        pde.Write = 1;
        pde.Accessed = 1;
        pde.Supervisor = 0;
        pde.LargePage = 1;
        pde.ExecuteDisable = 0;
        pde.Global = 0;
        pde.PageFrameNumber = page_frame_number;

        if (!write_physical_address(device_handle,
                                    PFN_TO_PAGE(pdpte.PageFrameNumber) +
                                        helper.AsIndex.Pd * sizeof(PDE_2MB_64),
                                    &pde, sizeof(PDE_2MB_64))) {
          return false;
        }

        // flush caches after 2MB PDE modification
        flush_caches(device_handle, reinterpret_cast<void*>(current_va));
      }
    } else {
      // setup regular PDE and PTE
      PDE_64 pde = {0};
      if (!read_physical_address(device_handle,
                                 PFN_TO_PAGE(pdpte.PageFrameNumber) +
                                     helper.AsIndex.Pd * sizeof(PDE_64),
                                 &pde, sizeof(PDE_64))) {
        return false;
      }

      if (!pde.Present) {
        auto pt_va = g_memory_manager->allocate_independent_pages(device_handle, 0x1000);
        if (!pt_va) {
          return false;
        }

        // clear PT
        if (kernel_RtlZeroMemory) {
          g_memory_manager->call_kernel_function<void>(device_handle, nullptr, kernel_RtlZeroMemory,
                                                       0x1000);
        }

        std::uint64_t pt_pfn = get_page_frame_number(device_handle, pt_va, false);
        if (!pt_pfn) {
          return false;
        }

        pde.Flags = 0;
        pde.Present = 1;
        pde.Write = 1;
        pde.Supervisor = 0;
        pde.Accessed = 1;
        pde.ExecuteDisable = 0;
        pde.PageFrameNumber = pt_pfn;

        if (!write_physical_address(device_handle,
                                    PFN_TO_PAGE(pdpte.PageFrameNumber) +
                                        helper.AsIndex.Pd * sizeof(PDE_64),
                                    &pde, sizeof(PDE_64))) {
          return false;
        }

        // flush caches after PDE modification
        flush_caches(device_handle, reinterpret_cast<void*>(current_va));
      }

      // setup PTE
      PTE_64 pte = {0};
      pte.Present = 1;
      pte.Write = 1;
      pte.Global = 0;
      pte.Accessed = 1;
      pte.Supervisor = 0;
      pte.ExecuteDisable = 0;
      pte.PageFrameNumber = page_frame_number;

      if (!write_physical_address(
              device_handle, PFN_TO_PAGE(pde.PageFrameNumber) + helper.AsIndex.Pt * sizeof(PTE_64),
              &pte, sizeof(PTE_64))) {
        return false;
      }

      // flush caches after PTE modification
      flush_caches(device_handle, reinterpret_cast<void*>(current_va));
    }
  }

  // flush caches
  return page_table_manager_t::flush_caches(device_handle, reinterpret_cast<void*>(base_va));
}
auto page_table_manager_t::flush_caches(HANDLE device_handle, void* address) -> bool {
  if (!device_handle) {
    return false;
  }

  // get kernel function addresses
  static std::uint64_t kernel_ke_flush_entire_tb = 0;
  static std::uint64_t kernel_ke_invalidate_all_caches = 0;
  static std::uint64_t kernel_ke_flush_single_tb = 0;

  // get exported functions from ntoskrnl
  if (!kernel_ke_flush_entire_tb) {
    kernel_ke_flush_entire_tb = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "KeFlushEntireTb");
    if (!kernel_ke_flush_entire_tb) {
      mapper_log("ERROR", "failed to get KeFlushEntireTb export");
      return false;
    }
  }

  if (!kernel_ke_invalidate_all_caches) {
    kernel_ke_invalidate_all_caches = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "KeInvalidateAllCaches");
    if (!kernel_ke_invalidate_all_caches) {
      mapper_log("ERROR", "failed to get KeInvalidateAllCaches export");
      return false;
    }
  }

  // get KeFlushSingleTb from PDB offsets
  if (!kernel_ke_flush_single_tb) {
    kernel_ke_flush_single_tb = g_driver_mapper->get_pdb_offsets().KeFlushSingleTb;
    if (!kernel_ke_flush_single_tb) {
      mapper_log("ERROR", "failed to get KeFlushSingleTb address from PDB");
      return false;
    }
  }

  // call KeFlushEntireTb(TRUE, TRUE) - flushes CR3/CR4 on all cores
  if (!g_memory_manager->call_kernel_function<void>(device_handle, nullptr,
                                                    kernel_ke_flush_entire_tb,
                                                    TRUE,     // FlushCurrentTb
                                                    TRUE)) {  // FlushGlobalTb
    mapper_log("ERROR", "failed to flush entire TLB");
    return false;
  }

  // call KeInvalidateAllCaches() - executes WBINVD on all cores
  if (!g_memory_manager->call_kernel_function<void>(device_handle, nullptr,
                                                    kernel_ke_invalidate_all_caches)) {
    mapper_log("ERROR", "failed to invalidate all caches");
    return false;
  }

  if (address) {
    // call KeFlushSingleTb(address, 0, 1) - executes INVLPG on all cores
    if (!g_memory_manager->call_kernel_function<void>(
            device_handle, nullptr, kernel_ke_flush_single_tb,
            reinterpret_cast<std::uintptr_t>(address), 0, 1)) {
      mapper_log("ERROR", "failed to flush single TLB entry");
      return false;
    }
  }

  return true;
}

auto page_table_manager_t::get_pml4e(std::uint32_t pml4_idx) -> std::uint64_t {
  return static_cast<std::uint64_t>(pml4_idx) << 39;
}

auto page_table_manager_t::get_pdpt(std::uint32_t pdpt_idx) -> std::uint64_t {
  return static_cast<std::uint64_t>(pdpt_idx) << 30;
}

auto page_table_manager_t::get_pd(std::uint32_t pd_idx) -> std::uint64_t {
  return static_cast<std::uint64_t>(pd_idx) << 21;
}

auto page_table_manager_t::get_pt(std::uint32_t pt_idx) -> std::uint64_t {
  return static_cast<std::uint64_t>(pt_idx) << 12;
}

auto page_table_manager_t::physical_to_virtual(HANDLE device_handle, std::uint64_t physical_address)
    -> std::uint64_t {
  // get MmGetVirtualForPhysical export
  static std::uint64_t kernel_MmGetVirtualForPhysical = 0;
  if (!kernel_MmGetVirtualForPhysical) {
    kernel_MmGetVirtualForPhysical = g_utils->get_kernel_module_export(
        device_handle, g_utils->get_kernel_module_address("ntoskrnl.exe"),
        "MmGetVirtualForPhysical");
    if (!kernel_MmGetVirtualForPhysical) {
      return 0;
    }
  }

  PHYSICAL_ADDRESS phys_addr;
  phys_addr.QuadPart = physical_address;

  std::uint64_t virtual_address = 0;
  if (!g_memory_manager->call_kernel_function(device_handle, &virtual_address,
                                              kernel_MmGetVirtualForPhysical, phys_addr)) {
    return 0;
  }

  return virtual_address;
}

// helper to get PDE address
auto page_table_manager_t::get_pde_address(HANDLE device_handle, std::uint64_t virtual_address)
    -> std::uint64_t {
  const auto mi_get_pde_address = g_driver_mapper->get_pdb_offsets().MiGetPdeAddress;
  if (g_driver_mapper->get_pdb_offsets().MiGetPdeAddress) {
    std::uint64_t pde_address = 0;
    if (g_memory_manager->call_kernel_function(device_handle, &pde_address,
                                               g_driver_mapper->get_pdb_offsets().MiGetPdeAddress,
                                               virtual_address)) {
      return pde_address;
    }
  }

  return 0;
}

// helper to get PTE address
auto page_table_manager_t::get_pte_address(HANDLE device_handle, std::uint64_t virtual_address)
    -> std::uint64_t {
  const auto mi_get_pte_address = g_driver_mapper->get_pdb_offsets().MiGetPteAddress;
  if (mi_get_pte_address) {
    std::uint64_t pte_address = 0;
    if (g_memory_manager->call_kernel_function(device_handle, &pte_address, mi_get_pte_address,
                                               virtual_address)) {
      return pte_address;
    }
  }

  return 0;
}