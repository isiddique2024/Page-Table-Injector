#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <memory>

// class forward declarations
class memory_manager_t;
class service_manager_t;
class trace_cleaner_t;
class page_table_manager_t;
class pe_parser_t;
class utils_t;

#define PAGE_SIZE 0x1000

// driver allocation modes
namespace settings {

  enum class driver_alloc_mode {
    ALLOC_IN_SYSTEM_CONTEXT,
    ALLOC_IN_NTOSKRNL_DATA_SECTION,
    ALLOC_IN_CURRENT_PROCESS_CONTEXT
  };

  // memory types
  enum class memory_type {
    NORMAL_PAGE,
    LARGE_PAGE,
    HUGE_PAGE
  };

  // hide types for MmPfnDatabase
  enum class hide_type {
    NONE,
    PFN_EXISTS_BIT,
    MI_REMOVE_PHYSICAL_MEMORY,
    SET_PARITY_ERROR,
    SET_LOCK_BIT,
    HIDE_TRANSLATION
  };

  // additional options
  enum class experimental_options {
    NONE,
    MANIPULATE_SYSTEM_PARTITION
  };
}  // namespace settings

class driver_mapper_t {
public:
  driver_mapper_t() = default;
  ~driver_mapper_t() = default;

  // main mapping interface
  auto map_driver(
      std::vector<std::uint8_t>& driver_data, std::uint64_t param1 = 0, std::uint64_t param2 = 0,
      bool free_after_exec = false, bool destroy_headers = true,
      bool pass_alloc_address_as_first_param = false, NTSTATUS* exit_code = nullptr,
      settings::driver_alloc_mode alloc_mode = settings::driver_alloc_mode::ALLOC_IN_SYSTEM_CONTEXT,
      settings::memory_type mem_type = settings::memory_type::NORMAL_PAGE,
      settings::hide_type driver_hide = settings::hide_type::NONE,
      settings::hide_type dll_hide = settings::hide_type::NONE,
      settings::experimental_options experimental_options = settings::experimental_options::NONE)
      -> std::uint64_t;

  auto prepare_local_image(void* local_image, const std::vector<std::uint8_t>& driver_data,
                           PIMAGE_NT_HEADERS64 nt_headers) -> bool;

  // kernel function resolution
  auto get_kernel_export(const std::string& module_name, const std::string& function_name)
      -> std::uint64_t;
  auto get_ntoskrnl_base() -> std::uint64_t;

  // PDB and symbol resolution
  struct pdb_offsets {
    // driver vars
    uintptr_t NtoskrnlBase;
    uintptr_t DriverAllocBase;
    uintptr_t DriverSize;
    uint32_t DriverHideType;
    uint32_t DllHideType;
    uint32_t ExperimentalOptions;

    // memory management (Mm)
    uintptr_t MmGetPhysicalAddress;
    uintptr_t MmPfnDatabase;
    uintptr_t MmAllocateIndependentPages;
    uintptr_t MmSetPageProtection;
    uintptr_t MmFreeIndependentPages;
    uintptr_t MmAllocateContiguousMemory;
    uintptr_t MmFreeContiguousMemory;
    uintptr_t MmCopyMemory;
    uintptr_t MmGetVirtualForPhysical;
    uintptr_t MmCopyVirtualMemory;
    uintptr_t MmMarkPhysicalMemoryAsBad;
    uintptr_t MmUserProbeAddress;
    uintptr_t MmGetSystemRoutineAddress;
    uintptr_t MmGetPhysicalMemoryRanges;
    uintptr_t MmIsAddressValid;
    uintptr_t MmAllocateSecureKernelPages;
    uintptr_t MmPhysicalMemoryBlock;

    // memory info (Mi) functions
    uintptr_t MiGetVmAccessLoggingPartition;
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
    uintptr_t MiLockPageTablePage;
    uintptr_t MiAllocateLargeZeroPages;

    // proc/obj management
    uintptr_t PsLoadedModuleList;
    uintptr_t PsAcquireProcessExitSynchronization;
    uintptr_t PsReleaseProcessExitSynchronization;
    uintptr_t PsGetProcessExitStatus;
    uintptr_t PsSetCreateThreadNotifyRoutine;
    uintptr_t PsSetCreateProcessNotifyRoutineEx;
    uintptr_t PsLookupProcessByProcessId;
    uintptr_t PsLookupThreadByThreadId;
    uintptr_t PsGetNextProcessThread;
    uintptr_t PsSuspendThread;
    uintptr_t PsResumeThread;
    uintptr_t PsQueryThreadStartAddress;
    uintptr_t PsGetCurrentThreadId;
    uintptr_t PsGetProcessPeb;
    uintptr_t PsGetProcessImageFileName;
    uintptr_t IoGetCurrentProcess;
    uintptr_t ObfDereferenceObject;

    // processor support functions
    uintptr_t PspExitThread;

    // executive functions
    uintptr_t ExAllocatePool2;
    uintptr_t ExFreePoolWithTag;
    uintptr_t ExGetPreviousMode;

    // kernel executive functions
    uintptr_t KeBalanceSetManager;
    uintptr_t KeRaiseIrqlToDpcLevel;
    uintptr_t KeLowerIrql;
    uintptr_t KiProcessListHead;
    uintptr_t KiPageFault;
    uintptr_t KeFlushSingleTb;
    uintptr_t KeQuerySystemTimePrecise;
    uintptr_t KiKvaShadow;
    uintptr_t KeInitializeApc;
    uintptr_t KeInsertQueueApc;
    uintptr_t KeUsermodeCallback;
    uintptr_t KeAlertThread;
    uintptr_t KeDelayExecutionThread;

    // runtime library
    uintptr_t RtlInitAnsiString;
    uintptr_t RtlInitUnicodeString;
    uintptr_t RtlAnsiStringToUnicodeString;
    uintptr_t RtlCompareUnicodeString;
    uintptr_t RtlFreeUnicodeString;
    uintptr_t RtlGetVersion;
    uintptr_t RtlCreateUserThread;

    // Zw/Nt functions
    uintptr_t ZwOpenProcess;
    uintptr_t ZwClose;
    uintptr_t ZwWaitForSingleObject;
    uintptr_t ZwQueryInformationProcess;
    uintptr_t NtAlertResumeThread;

    // debug
    uintptr_t DbgPrint;

    // crt functions
    uintptr_t memcpy;
    uintptr_t memset;
    uintptr_t memcmp;
    uintptr_t strncmp;
    uintptr_t strlen;
    uintptr_t _wcsicmp;
    uintptr_t rand;
    uintptr_t srand;
    uintptr_t swprintf_s;
    uintptr_t snprintf;

    // offsets

    uintptr_t ActiveProcessLinks;
    uintptr_t _EPROCESS_ThreadListHead;
    uintptr_t _KPROCESS_ThreadListHead;
    uintptr_t _EPROCESS_SharedCommitLinks;
    uintptr_t _EPROCESS_SharedCommitCharge;
    uintptr_t _EPROCESS_RundownProtect;
    uintptr_t _EPROCESS_Vm;
    uintptr_t _EPROCESS_Flags3;

    // trace cleaning - ntoskrnl
    uintptr_t PiDDBCacheTable;
    uintptr_t PiDDBLock;

    // trace cleaning - ci.dll
    uintptr_t g_KernelHashBucketList;
    uintptr_t g_PEProcessHashBucketList;
    uintptr_t g_PEProcessList;
    uintptr_t g_HashCacheLock;
    uintptr_t g_CiEaCacheLookasideList;
    uintptr_t g_CiValidationLookasideList;
    uintptr_t RtlPcToFileName;

    // trace cleaning - WdFilter.sys
    uintptr_t MpBmDocOpenRules;
    uintptr_t MpFreeDriverInfoEx;
  };

  auto get_pdb_offsets() const -> const pdb_offsets&;
  auto get_device_handle() -> HANDLE {
    return device_handle_;
  }

  // Utility methods
  auto is_vulnerable_driver_loaded() -> bool;
  auto cleanup_traces(const std::string& driver_name) -> bool;

private:
  // core mapping logic
  auto allocate_driver_memory(std::uint32_t image_size, settings::driver_alloc_mode alloc_mode,
                              settings::memory_type mem_type, bool destroy_headers)
      -> std::uint64_t;

  auto copy_pe_sections(void* local_image, const std::vector<std::uint8_t>& driver_data) -> bool;

  auto relocate_image(void* local_image, std::uint64_t kernel_base, std::uint64_t original_base)
      -> bool;

  auto resolve_imports(void* local_image) -> bool;

  auto fix_security_cookie(void* local_image, std::uint64_t kernel_image_base) -> bool;

  auto call_driver_entry(std::uint64_t entry_point, std::uint64_t param1, std::uint64_t param2,
                         bool pass_alloc_address_as_first_param, std::uint64_t allocated_base)
      -> NTSTATUS;

  // mem allocation helpers
  auto allocate_in_system_context(std::uint32_t size) -> std::uint64_t;
  auto allocate_in_process_context(std::uint32_t size, settings::memory_type mem_type)
      -> std::uint64_t;
  auto allocate_in_ntoskrnl_section(std::uint32_t size) -> std::uint64_t;

  auto resolve_pdb_offsets() -> pdb_offsets;

  // member variables
  HANDLE device_handle_ = INVALID_HANDLE_VALUE;
  std::uint64_t ntoskrnl_base_ = 0;
  pdb_offsets offsets_ = {};
  bool initialized_ = false;

  // initialization and cleanup
  auto initialize() -> bool;
  auto cleanup() -> void;
};

// global driver mapper instance
inline std::unique_ptr<driver_mapper_t> g_driver_mapper = std::make_unique<driver_mapper_t>();