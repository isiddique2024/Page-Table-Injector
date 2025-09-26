#pragma once
#include "validation.hpp"
namespace validation {

  auto virtual_to_physical(void* virtual_address) -> PHYSICAL_ADDRESS {
    PHYSICAL_ADDRESS physical_address{0};
    const uintptr_t va = reinterpret_cast<uintptr_t>(virtual_address);

    // check for 2MB page (PDE large page)
    PDE_2MB_64* pde = reinterpret_cast<PDE_2MB_64*>(globals::mi_get_pde_address(va));
    if (pde && pde->Present && pde->LargePage) {
      const uintptr_t pfn = pde->PageFrameNumber;
      physical_address.QuadPart = (pfn << 21) | (va & 0x1FFFFF);
      return physical_address;
    }

    // fall back to regular 4KB page
    PTE_64* const pte = reinterpret_cast<PTE_64*>(globals::mi_get_pte_address(va));
    if (!pte || !pte->Present) {
      return physical_address;
    }

    const uintptr_t pfn = pte->PageFrameNumber;

    physical_address.QuadPart = (pfn << PAGE_SHIFT) | (va & 0xFFF);
    return physical_address;
  }

  auto is_pfn_valid(uintptr_t pfn) -> bool {
    return pfn >= globals::mm_lowest_physical_page && pfn <= globals::mm_highest_physical_page;
  }

  auto is_physical_address_valid(uintptr_t physical_address) -> bool {
    auto pfn = PAGE_TO_PFN(physical_address);
    return is_pfn_valid(pfn);
  }

  auto is_virtual_address_valid(void* virtual_address) -> bool {
    return virtual_address && globals::mm_is_address_valid(virtual_address);
  }

  auto validate_allocated_page(void* virtual_address, const char* page_type) -> NTSTATUS {
    if (!virtual_address) {
      log("ERROR", "failed to allocate %s", page_type);
      return STATUS_NO_MEMORY;
    }

    if (!is_virtual_address_valid(virtual_address)) {
      log("ERROR", "allocated %s 0x%p is not valid", page_type, virtual_address);
      return STATUS_INVALID_ADDRESS;
    }

    auto phys_addr = validation::virtual_to_physical(virtual_address);
    if (phys_addr.QuadPart == 0) {
      log("ERROR", "failed to get physical address for %s 0x%p", page_type, virtual_address);
      return STATUS_INVALID_ADDRESS;
    }

    auto pfn = PAGE_TO_PFN(phys_addr.QuadPart);
    if (!is_pfn_valid(pfn)) {
      log("ERROR", "%s PFN 0x%llx outside valid range [0x%llx-0x%llx]", page_type, pfn,
          globals::mm_lowest_physical_page, globals::mm_highest_physical_page);
      return STATUS_INVALID_ADDRESS;
    }

    return STATUS_SUCCESS;
  }

  auto validate_page_table_index(uint32_t index, const char* table_type) -> bool {
    if (index >= 512) {
      log("ERROR", "invalid %s index: %u", table_type, index);
      return false;
    }
    return true;
  }

  auto validate_pfn_with_context(uintptr_t pfn, const char* context) -> bool {
    if (!is_pfn_valid(pfn)) {
      log("ERROR", "%s PFN 0x%llx outside valid range [0x%llx-0x%llx]", context, pfn,
          globals::mm_lowest_physical_page, globals::mm_highest_physical_page);
      return false;
    }
    return true;
  }

  auto validate_process_state(PEPROCESS process, uint32_t pid) -> bool {
    if (!process) {
      log("ERROR", "process %u is null", pid);
      return false;
    }

    if (globals::ps_get_process_exit_status(process) != STATUS_PENDING) {
      log("ERROR", "process %u is not active (exit status: 0x%08X)", pid,
          globals::ps_get_process_exit_status(process));
      return false;
    }

    return true;
  }

  auto acquire_process_rundown_protection(PEPROCESS process, uint32_t pid) -> bool {
    if (!process) {
      log("ERROR", "process %u is null for rundown protection", pid);
      return false;
    }

    // try to acquire rundown protection
    if (!NT_SUCCESS(globals::ps_acquire_process_exit_synchronization(process))) {
      log("ERROR", "failed to acquire rundown protection for process %u", pid);
      return false;
    }

    // double-check process is still active after acquiring protection
    if (globals::ps_get_process_exit_status(process) != STATUS_PENDING) {
      globals::ps_release_process_exit_synchronization(process);
      log("ERROR", "process %u exited after acquiring rundown protection", pid);
      return false;
    }

    return true;
  }

  auto release_process_rundown_protection(PEPROCESS process) -> void {
    if (process) {
      globals::ps_release_process_exit_synchronization(process);
    }
  }

  auto validate_size_parameters(size_t size, size_t page_count, size_t max_size) -> bool {
    if (size == 0) {
      log("ERROR", "invalid size: 0");
      return false;
    }

    if (size > max_size) {
      log("ERROR", "size %zu exceeds maximum %zu", size, max_size);
      return false;
    }

    if (page_count == 0) {
      log("ERROR", "invalid page count: 0");
      return false;
    }

    if (page_count > 0x200000) {  // reasonable max
      log("ERROR", "page count %zu exceeds reasonable maximum", page_count);
      return false;
    }

    return true;
  }

  auto validate_index_range(uint32_t start_idx, uint32_t end_idx, const char* range_type) -> bool {
    if (start_idx >= 512 || end_idx > 512) {
      log("ERROR", "invalid %s index range bounds: %u-%u (max 511)", range_type, start_idx,
          end_idx);
      return false;
    }

    if (start_idx >= end_idx) {
      log("ERROR", "invalid %s index range order: %u >= %u", range_type, start_idx, end_idx);
      return false;
    }

    return true;
  }

  auto validate_virtual_address_alignment(uintptr_t va, size_t alignment, const char* context)
      -> bool {
    if ((va & (alignment - 1)) != 0) {
      log("ERROR", "unaligned %s VA: 0x%llx (alignment: 0x%zx)", context, va, alignment);
      return false;
    }
    return true;
  }
}  // namespace validation