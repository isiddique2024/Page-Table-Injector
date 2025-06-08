#pragma once

#define ENABLE_DEBUG_PRINT 1

#if ENABLE_DEBUG_PRINT
#define log(level, format, ...) \
    globals::dbg_print("[=] %s: %s: " format, level, __FUNCTION__, ##__VA_ARGS__)
#else
#define log(level, format, ...) ((void)0)
#endif

#define MAX_FREE_SPACES 128

#define dereference(ptr) (const uintptr_t)(ptr + *( int * )( ( BYTE * )ptr + 3 ) + 7)
#define in_range(x,a,b)    (x >= a && x <= b) 
#define get_bits( x )    (in_range((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (in_range(x,'0','9') ? x - '0' : 0))
#define get_byte( x )    (get_bits(x[0]) << 4 | get_bits(x[1]))
#define size_align(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)
#define to_lower_i(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define to_lower_c(Char) ((Char >= (char*)'A' && Char <= (char*)'Z') ? (Char + 32) : Char)

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12
#define PTE_SHIFT 3
#define VA_SHIFT (63 - 47)
#define BYTES_TO_PAGES(size) (((size) >> PAGE_SHIFT) + (((size) & (PAGE_SIZE - 1)) != 0))
#define MI_GET_VIRTUAL_ADDRESS_MAPPED_BY_PTE(pte) ((PVOID)((LONG_PTR)(((LONG_PTR)(pte) - 0xFFFFF68000000000) << (25L)) >> 16))

#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)
#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)

typedef unsigned int uint32_t;
typedef unsigned long ulong32_t;

enum hide_type {
	NONE,
	PFN_EXISTS_BIT,
	MI_REMOVE_PHYSICAL_MEMORY,
	SET_PARITY_ERROR,
	SET_LOCK_BIT,
};

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used: nameless struct/union

#pragma pack(push, 1)
typedef union CR3_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Ignored1 : 3;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Ignored2 : 7;
		ULONG64 Pml4 : 40;
		ULONG64 Reserved : 12;
	};
} PTE_CR3;

typedef union VIRT_ADDR_
{
	ULONG64 Value;
	void* Pointer;
	struct
	{
		ULONG64 Offset : 12;
		ULONG64 PtIndex : 9;
		ULONG64 PdIndex : 9;
		ULONG64 PdptIndex : 9;
		ULONG64 Pml4Index : 9;
		ULONG64 Reserved : 16;
	};
} VIRTUAL_ADDRESS;

typedef union PML4E_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Ignored1 : 1;
		ULONG64 Reserved1 : 1;
		ULONG64 Ignored2 : 4;
		ULONG64 Pdpt : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PML4E_NEW;

typedef union PDPTE_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 PageSize : 1;
		ULONG64 Ignored2 : 4;
		ULONG64 Pd : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PDPTE_NEW;

typedef union PDE_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 PageSize : 1;
		ULONG64 Ignored2 : 4;
		ULONG64 Pt : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PDE_NEW;

typedef union PTE_
{
	ULONG64 Value;
	VIRTUAL_ADDRESS VirtualAddress;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 Pat : 1;
		ULONG64 Global : 1;
		ULONG64 Ignored1 : 3;
		ULONG64 PageFrame : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PTE_NEW;
#pragma pack(pop)

#pragma warning(pop)

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	VOID *EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_CRITICAL_SECTION
{
	VOID *DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	PVOID OwningThread;
	PVOID LockSemaphore;
	ULONG SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG ImageUsesLargePages : 1;
	ULONG IsProtectedProcess : 1;
	ULONG IsLegacyProcess : 1;
	ULONG IsImageDynamicallyRelocated : 1;
	ULONG SpareBits : 4;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	VOID *ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	ULONG CrossProcessFlags;
	ULONG ProcessInJob : 1;
	ULONG ProcessInitializing : 1;
	ULONG ReservedBits0 : 30;
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG SpareUlong;
	VOID *FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	VOID **ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	VOID **ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG ImageProcessAffinityMask;
	ULONG GdiHandleBuffer[34];
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	VOID *ActivationContextData;
	VOID *ProcessAssemblyStorageMap;
	VOID *SystemDefaultActivationContextData;
	VOID *SystemAssemblyStorageMap;
	ULONG MinimumStackCommit;
	VOID *FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[4];
	ULONG FlsHighIndex;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
} PEB, *PPEB;
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
	ULONG HandleCount;
	// Next part is platform dependent
	// ...
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _PAGE_INFORMATION
{
	PML4E_64 *PML4E;
	PDPTE_64 *PDPTE;
	PDE_64 *PDE;
	PTE_64 *PTE;
}PAGE_INFORMATION, *PPAGE_INFORMATION;

//0x1 bytes (sizeof)
struct _MMPFNENTRY1
{
	UCHAR PageLocation : 3;                                                   //0x0
	UCHAR WriteInProgress : 1;                                                //0x0
	UCHAR Modified : 1;                                                       //0x0
	UCHAR ReadInProgress : 1;                                                 //0x0
	UCHAR CacheAttribute : 2;                                                 //0x0
};

//0x8 bytes (sizeof)
struct _MIPFNBLINK
{
	union
	{
		struct
		{
			ULONGLONG Blink : 40;                                             //0x0
			ULONGLONG NodeBlinkLow : 19;                                      //0x0
			ULONGLONG TbFlushStamp : 3;                                       //0x0
			ULONGLONG PageBlinkDeleteBit : 1;                                 //0x0
			ULONGLONG PageBlinkLockBit : 1;                                   //0x0
			ULONGLONG ShareCount : 62;                                        //0x0
			ULONGLONG PageShareCountDeleteBit : 1;                            //0x0
			ULONGLONG PageShareCountLockBit : 1;                              //0x0
		};
		LONGLONG EntireField;                                               //0x0
		struct
		{
			ULONGLONG LockNotUsed : 62;                                       //0x0
			ULONGLONG DeleteBit : 1;                                          //0x0
			ULONGLONG LockBit : 1;                                            //0x0
		};
	};
};

struct _MMPFNENTRY3 {
	UCHAR Priority : 3;
	UCHAR OnProtectedStandby : 1;
	UCHAR InPageError : 1;
	UCHAR SystemChargedPage : 1;
	UCHAR RemovalRequested : 1;
	UCHAR ParityError : 1;
};

struct _MI_PFN_FLAGS {
	union {
		struct {
			USHORT ReferenceCount;
			UCHAR PageLocation : 3;
			UCHAR WriteInProgress : 1;
			UCHAR Modified : 1;
			UCHAR ReadInProgress : 1;
			UCHAR CacheAttribute : 2;
			UCHAR Priority : 3;
			UCHAR OnProtectedStandby : 1;
			UCHAR InPageError : 1;
			UCHAR SystemChargedPage : 1;
			UCHAR RemovalRequested : 1;
			UCHAR ParityError : 1;
		};
		ULONG EntireField;
	};
};

struct _MI_PFN_FLAGS4 {
	union {
		struct {
			ULONGLONG PteFrame : 40;
		} Bits;
		ULONGLONG EntireField;
	};
};

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

// hyperspace context structure
struct hyperspace_ctx {
	PEPROCESS orig_peproc;
	uintptr_t clone_peproc_page_base;
	PEPROCESS clone_peproc;
	uintptr_t hyperspace_pml4_va;
	uintptr_t hyperspace_pml4_pa;
	uintptr_t orig_pml4_pa;  // Removed orig_pml4_va since we're using physical operations
	bool initialized;

	// self-reference entry tracking
	bool has_self_reference_entry;
	uint32_t self_reference_entry_index;

	// target pid for callback filtering
	uint32_t target_pid;
};

struct ntoskrnl_mapping_info {
	uintptr_t original_base;
	uintptr_t original_size;
	uintptr_t hyperspace_base;
	uint32_t pml4_index;
	uint32_t pdpt_index;
	uint32_t pd_index;
	uintptr_t new_pdpt_pa;
	uintptr_t new_pd_pa;
	uintptr_t new_pt_pa; // only used if not large page
	uintptr_t* allocated_pages; // track all allocated physical pages
	size_t allocated_pages_count;
	size_t allocated_pages_capacity;

	uintptr_t* allocated_large_pages; // track all allocated physical pages
	size_t allocated_large_pages_count;
	size_t allocated_large_pages_capacity;
};

struct self_reference_entry_info {
	uint32_t index;
	bool found;
	PML4E_64 original_entry;
};

inline namespace function_types {
	// memory management
	using mm_allocate_independent_pages_ex_t = void* (__fastcall*)(size_t bytes, int node, std::uint64_t* a3, unsigned int a4);
	using mm_set_page_protection_t = char(__fastcall*)(uint64_t address, uint32_t size, unsigned long new_protect);
	using mm_free_independent_pages = __int64(__fastcall*)(unsigned __int64 address, unsigned __int64 bytes);
	using mm_allocate_contiguous_memory_t = PVOID(__stdcall*)(SIZE_T number_of_bytes, PHYSICAL_ADDRESS HighestAcceptableAddress);
	using mm_free_contiguous_memory_t = void(__stdcall*)(void* base_address);
	using mm_copy_memory_t = NTSTATUS(__stdcall*)(PVOID destination_address, MM_COPY_ADDRESS source_address, SIZE_T number_of_bytes, ULONG flags, PSIZE_T number_of_bytes_transferred);
	using mm_get_virtual_for_physical_t = PVOID(__stdcall*)(PHYSICAL_ADDRESS physical_address);
	using mm_copy_virtual_memory_t = NTSTATUS(__stdcall*)(PEPROCESS source_process, PVOID source_address, PEPROCESS target_process, PVOID target_address, SIZE_T buffer_size, KPROCESSOR_MODE previous_mode, PSIZE_T return_size);
	using mm_mark_physical_memory_as_bad_t = NTSTATUS(__stdcall*)(PPHYSICAL_ADDRESS start_address, PLARGE_INTEGER number_of_bytes);
	using mm_user_probe_address_t = PVOID*;
	using mm_get_system_routine_address_t = PVOID(__stdcall*)(PUNICODE_STRING system_routine_name);
	using mm_get_physical_address_t = PHYSICAL_ADDRESS(__stdcall*)(PVOID base_address);

	// memory info (MI) functions
	using mi_get_vm_access_logging_partition_t = __int64(*)(VOID);
	using mi_create_decay_pfn_t = _SLIST_ENTRY*(*)();
	using mi_get_ultra_page_t = __int64(*)(__int64 a1, char a2);
	using mi_reserve_ptes_t = void* (*)(std::uintptr_t mi_system_pte_info, std::uintptr_t number_of_ptes);
	using mi_get_pte_address_t = void* (*)(std::uintptr_t va);
	using mi_get_pde_address_t = void* (*)(std::uintptr_t va);
	using mi_remove_physical_memory_t = NTSTATUS(__stdcall*)(std::uintptr_t physical_page, std::uintptr_t number_of_pages, unsigned long flags);
	using mi_flush_cache_range_t = __int64(__fastcall*)(std::uintptr_t physical_page, std::uintptr_t number_of_pages);
	using mi_flush_entire_tb_due_to_attribute_change_t = __int64(__fastcall*)();
	using mi_get_page_table_pfn_buddy_raw_t = PEPROCESS(__fastcall*)(void* pfn_entry);
	using mi_set_page_table_pfn_buddy_t = __int64(__fastcall*)(__int64 pfn_entry, unsigned __int64 eprocess_maybe, char unk3);

	// proc/obj management
	using ps_set_create_thread_notify_routine_t = NTSTATUS(__stdcall*)(PCREATE_THREAD_NOTIFY_ROUTINE notify_routine);
	using ps_set_create_process_notify_routine_ex_t = NTSTATUS(__stdcall*)(PCREATE_PROCESS_NOTIFY_ROUTINE_EX notify_routine, BOOLEAN Remove);
	using ps_lookup_process_by_process_id_t = NTSTATUS(__stdcall*)(HANDLE process_id, PEPROCESS* process);
	using ps_lookup_thread_by_thread_id_t = NTSTATUS(__stdcall*)(HANDLE thread_id, PETHREAD* thread);
	using ps_get_next_process_thread_t = PETHREAD(__stdcall*)(PEPROCESS process, PETHREAD thread);
	using ps_suspend_thread_t = NTSTATUS(__stdcall*)(PETHREAD thread, PULONG previous_suspend_count);
	using ps_query_thread_start_address_t = __int64(__stdcall*)(__int64 thread, int a2);
	using ps_get_current_thread_id_t = HANDLE(__stdcall*)();
	using ps_get_process_peb_t = PPEB(__fastcall*)(PEPROCESS process);
	using ps_get_process_image_file_name_t = PCHAR(__fastcall*)(PEPROCESS process);
	using io_get_current_process_t = PEPROCESS(__stdcall*)();
	using obf_dereference_object_t = LONG_PTR(__fastcall*)(PVOID object);

	// executive functions
	using ex_allocate_pool2_t = PVOID(__stdcall*)(POOL_FLAGS flags, SIZE_T number_of_bytes, ULONG tag);
	using ex_free_pool_with_tag_t = void(__stdcall*)(PVOID p, ULONG tag);
	using ex_get_previous_mode_t = KPROCESSOR_MODE(__stdcall*)();

	// runtime library
	using rtl_init_ansi_string_t = void(__stdcall*)(PANSI_STRING destination_string, PCSZ source_string);
	using rtl_init_unicode_string_t = void(__stdcall*)(PUNICODE_STRING destination_string, PCWSTR source_string);
	using rtl_ansi_string_to_unicode_string_t = NTSTATUS(__stdcall*)(PUNICODE_STRING destination_string, PCANSI_STRING source_string, BOOLEAN allocate_destination_string);
	using rtl_compare_unicode_string_t = LONG(__stdcall*)(PCUNICODE_STRING string1, PCUNICODE_STRING string2, BOOLEAN case_in_sensitive);
	using rtl_free_unicode_string_t = void(__stdcall*)(PUNICODE_STRING unicode_string);
	using rtl_get_version_t = NTSTATUS(__stdcall*)(PRTL_OSVERSIONINFOW version_information);
	using rtl_create_user_thread_t = NTSTATUS(*)(
		HANDLE ProcessHandle,
		PSECURITY_DESCRIPTOR SecurityDescriptor,
		BOOLEAN CreateSuspended,
		ULONG StackZeroBits,
		PULONG StackReserved,
		PULONG StackCommit,
		PVOID StartAddress,
		PVOID StartParameter,
		PHANDLE ThreadHandle,
		PCLIENT_ID ClientId
		);

	// zw/nt functions
	using zw_open_process_t = NTSTATUS(__stdcall*)(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PCLIENT_ID ClientId
		);

	using zw_close_t = NTSTATUS(__stdcall*)(HANDLE Handle);

	using zw_wait_for_single_object_t = NTSTATUS(__stdcall*)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

	// debug
	using dbg_print_t = ULONG(__cdecl*)(PCCH format, ...);

	// crt functions
	using memcpy_t = void* (__cdecl*)(void* dest, const void* src, size_t count);
	using memset_t = void* (__cdecl*)(void* dest, int c, size_t count);
	using memcmp_t = int (__cdecl*)(const void* buf1, const void* buf2, size_t count);
	using strncmp_t = int(__cdecl*)(const char* str1, const char* str2, size_t count);
	using strlen_t = size_t(__cdecl*)(const char* str);
	using _wcsicmp_t = int(__cdecl*)(const wchar_t* str1, const wchar_t* str2);

	// existing types
	using ke_flush_entire_tb_t = VOID(*)(BOOLEAN invalid, BOOLEAN all_processors);
	using ke_invalidate_all_caches_t = VOID(*)(VOID);

	using ke_raise_irql_to_dpc_level_t = KIRQL(__stdcall*)(VOID);
	using ke_lower_irql_t = VOID(__stdcall*)(KIRQL new_irql);

}

namespace globals {
	// func address to hook in win32k.sys
	uintptr_t hook_address = 0;
	void* shell_address = 0;
	constexpr auto SHELL_SIZE = 12;
	uintptr_t hook_pointer = 0;
	uintptr_t ntos_base = 0;

	uint32_t driver_hide_type = 0;
	uint32_t dll_hide_type = 0;

	function_types::ke_flush_entire_tb_t ke_flush_entire_tb = nullptr;
	function_types::ke_invalidate_all_caches_t ke_invalidate_all_caches = nullptr;
	function_types::mm_allocate_independent_pages_ex_t mm_allocate_independent_pages_ex = nullptr;
	function_types::mm_free_contiguous_memory_t mm_free_contiguous_memory = nullptr;
	function_types::mm_set_page_protection_t mm_set_page_protection = nullptr;
	function_types::mm_free_independent_pages mm_free_independent_pages = nullptr;

	function_types::mi_get_vm_access_logging_partition_t mi_get_vm_access_logging_partition = nullptr;
	function_types::mi_create_decay_pfn_t mi_create_decay_pfn = nullptr;
	function_types::mi_get_ultra_page_t mi_get_ultra_page = nullptr;
	function_types::mi_reserve_ptes_t mi_reserve_ptes = nullptr;
	function_types::mi_get_pte_address_t mi_get_pte_address = nullptr;
	function_types::mi_get_pde_address_t mi_get_pde_address = nullptr;
	function_types::mi_remove_physical_memory_t mi_remove_physical_memory = nullptr;
	function_types::mi_flush_entire_tb_due_to_attribute_change_t mi_flush_entire_tb_due_to_attribute_change = nullptr;
	function_types::mi_flush_cache_range_t mi_flush_cache_range = nullptr;
	function_types::mi_get_page_table_pfn_buddy_raw_t mi_get_page_table_pfn_buddy_raw = nullptr;
	function_types::mi_set_page_table_pfn_buddy_t mi_set_page_table_pfn_buddy = nullptr;

	function_types::mm_get_physical_address_t mm_get_physical_address = nullptr;
	function_types::mm_allocate_contiguous_memory_t mm_allocate_contiguous_memory = nullptr;
	function_types::mm_copy_memory_t mm_copy_memory = nullptr;
	function_types::mm_get_virtual_for_physical_t mm_get_virtual_for_physical = nullptr;
	function_types::mm_copy_virtual_memory_t mm_copy_virtual_memory = nullptr;
	function_types::mm_mark_physical_memory_as_bad_t mm_mark_physical_memory_as_bad = nullptr;
	function_types::mm_user_probe_address_t mm_user_probe_address = nullptr;
	function_types::mm_get_system_routine_address_t mm_get_system_routine_address = nullptr;
	uintptr_t ps_loaded_module_list = 0;
	function_types::ps_set_create_thread_notify_routine_t ps_set_create_thread_notify_routine = nullptr;
	function_types::ps_set_create_process_notify_routine_ex_t ps_set_create_process_notify_routine_ex = nullptr;
	function_types::ps_lookup_process_by_process_id_t ps_lookup_process_by_process_id = nullptr;
	function_types::ps_lookup_thread_by_thread_id_t ps_lookup_thread_by_thread_id = nullptr;
	function_types::ps_get_next_process_thread_t ps_get_next_process_thread = nullptr;
	function_types::ps_suspend_thread_t ps_suspend_thread = nullptr;
	function_types::ps_suspend_thread_t ps_resume_thread = nullptr;
	function_types::ps_query_thread_start_address_t ps_query_thread_start_address = nullptr;
	function_types::ps_get_current_thread_id_t ps_get_current_thread_id = nullptr;
	function_types::ps_get_process_peb_t ps_get_process_peb = nullptr;
	function_types::ps_get_process_image_file_name_t ps_get_process_image_file_name = nullptr;
	function_types::io_get_current_process_t io_get_current_process = nullptr;
	function_types::obf_dereference_object_t obf_dereference_object = nullptr;

	uintptr_t psp_exit_thread = 0;

	function_types::ex_allocate_pool2_t ex_allocate_pool2 = nullptr;
	function_types::ex_free_pool_with_tag_t ex_free_pool_with_tag = nullptr;
	function_types::ex_get_previous_mode_t ex_get_previous_mode = nullptr;

	uintptr_t ke_balance_set_manager = 0;
	function_types::ke_raise_irql_to_dpc_level_t ke_raise_irql_to_dpc_level = nullptr;
	function_types::ke_lower_irql_t ke_lower_irql = nullptr;
	PLIST_ENTRY ki_process_list_head = 0;
	uintptr_t ki_page_fault = 0;

	function_types::rtl_init_ansi_string_t rtl_init_ansi_string = nullptr;
	function_types::rtl_init_unicode_string_t rtl_init_unicode_string = nullptr;
	function_types::rtl_ansi_string_to_unicode_string_t rtl_ansi_string_to_unicode_string = nullptr;
	function_types::rtl_compare_unicode_string_t rtl_compare_unicode_string = nullptr;
	function_types::rtl_free_unicode_string_t rtl_free_unicode_string = nullptr;
	function_types::rtl_get_version_t rtl_get_version = nullptr;
	function_types::rtl_create_user_thread_t rtl_create_user_thread = nullptr;

	function_types::zw_open_process_t zw_open_process = nullptr;
	function_types::zw_close_t zw_close = nullptr;
	function_types::zw_wait_for_single_object_t zw_wait_for_single_object = nullptr;

	function_types::dbg_print_t dbg_print = nullptr;

	function_types::memcpy_t memcpy = nullptr;
	function_types::memset_t memset = nullptr;
	function_types::memcmp_t memcmp = nullptr;
	function_types::strncmp_t strncmp = nullptr;
	function_types::strlen_t strlen = nullptr;
	function_types::_wcsicmp_t _wcsicmp = nullptr;

	LONG some_dword = 0;
	uintptr_t mm_pfn_db = 0;
	uintptr_t mm_physical_memory_block = 0;
	hyperspace_ctx ctx = { 0 };

	uintptr_t active_process_links = 0x0;
	uintptr_t _eprocess_thread_list_head;
	uintptr_t _kprocess_thread_list_head;
	uintptr_t _eprocess_shared_commit_links;
	uintptr_t _eprocess_shared_commit_charge;
	uintptr_t _eprocess_rundown_protect;
	uintptr_t _eprocess_vm;
	uintptr_t _eprocess_flags3;

	uintptr_t _kprocess_dirbase = 0x28;
	uintptr_t _kthread_pkprocess = 0x220;
	uintptr_t _kthread_apcstate_pkprocess = 0xB8;

	PEPROCESS proc = 0x0;
	unsigned long build_version = 0;
	bool initialized = false;
}

struct pdb_offsets {
	// driver vars
	uintptr_t DriverAllocBase;
	uintptr_t DriverSize;
	uint32_t DriverHideType;
	uint32_t DllHideType;

	// memory management (Mm) functions
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

	// proc/obj management functions
	uintptr_t PsLoadedModuleList;
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

	// kernel exec functions
	uintptr_t KeBalanceSetManager;
	uintptr_t KeRaiseIrqlToDpcLevel;
	uintptr_t KeLowerIrql;
	uintptr_t KiProcessListHead;
	uintptr_t KiPageFault;

	// runtime library functions
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

	// debug functions
	uintptr_t DbgPrint;

	// crt functions
	uintptr_t memcpy;
	uintptr_t memset;
	uintptr_t memcmp;
	uintptr_t strncmp;
	uintptr_t strlen;
	uintptr_t _wcsicmp;

	// struct offsets
	uintptr_t ActiveProcessLinks;
	uintptr_t _EPROCESS_ThreadListHead;
	uintptr_t _KPROCESS_ThreadListHead;
	uintptr_t _EPROCESS_SharedCommitLinks;
	uintptr_t _EPROCESS_SharedCommitCharge;
	uintptr_t _EPROCESS_RundownProtect;
	uintptr_t _EPROCESS_Vm;
	uintptr_t _EPROCESS_Flags3;
};

#pragma function(memset) 
extern "C" {
	void* memset(void* dest, int value, size_t count) {
		_ReadWriteBarrier();
		__stosb((unsigned char*)dest, (unsigned char)value, count);
		_ReadWriteBarrier();
		return dest;
	}
}
