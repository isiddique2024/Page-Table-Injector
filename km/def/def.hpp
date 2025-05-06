#pragma once

#define ENABLE_DEBUG_PRINT 1

#if ENABLE_DEBUG_PRINT
#define log(level, format, ...) \
    DbgPrint("[=] %s: %s: " format, level, __FUNCTION__, ##__VA_ARGS__)
#else
#define log(level, format, ...) ((void)0)
#endif

#define MAX_FREE_SPACES 128

#define PFN_TO_PAGE(pfn) ( pfn << 12 )
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


enum remove_type {
	PFN_EXISTS_BIT,
	MI_REMOVE_PHYSICAL_MEMORY,
	MM_PHYSICAL_MEMORY_BLOCK,
	MARK_PHYSICAL_MEMORY_AS_BAD
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

inline namespace function_types {
	using mm_allocate_independent_pages_ex_t = void* (__fastcall*)(
		size_t bytes,
		int node,
		std::uint64_t* a3,
		unsigned int a4
		);

	using mm_free_independent_pages = __int64(__fastcall*)(unsigned __int64 address, unsigned __int64 bytes);

	using mi_reserve_ptes_t = void*(*)(
		std::uintptr_t mi_system_pte_info,
		std::uintptr_t number_of_ptes
		);

	using mi_get_pte_address_t = void* (*)(std::uintptr_t va);

	using mi_remove_physical_memory_t = NTSTATUS(__stdcall*)(std::uintptr_t physical_page, std::uintptr_t number_of_pages, unsigned long flags);

	using mi_flush_cache_range_t = __int64(__fastcall*)(std::uintptr_t physical_page, std::uintptr_t number_of_pages);

	using mi_flush_entire_tb_due_to_attribute_change_t = __int64(__fastcall*)();

	using mi_map_contiguous_memory_large_t = __int64(__fastcall*)(ULONG_PTR bug_check_parameter2, unsigned __int64 a2, unsigned int a3, __int64 a4, DWORD* a5);

	using mi_get_large_page_t = __int64(__fastcall*)(
		__int64 partition,
		unsigned __int64 address,
		unsigned int page_size_index,
		int node,
		unsigned int cache_type,
		unsigned int flags,
		__int64 coalesce_context,
		int* heat_list
		);


	using mi_convert_large_active_page_to_chain_t = __int64(__fastcall*)(__int64 large_page);

	using ke_flush_single_tb_t = VOID(*)(PVOID virtual_address, BOOLEAN all_processors, BOOLEAN broadcast);

	using ke_flush_entire_tb_t = VOID(*)(BOOLEAN invalid, BOOLEAN all_processors);

	using ke_invalidate_all_caches_t = VOID(*)(VOID);

}


namespace globals {
	// func address to hook in win32k.sys
	uintptr_t hook_address = 0;

	// address to shellcode that calls handler
	void* shell_address = 0;

	// size of shellcode
	constexpr auto SHELL_SIZE = 12;

	// original function used for restoring when unload
	uintptr_t hook_pointer = 0;

	uintptr_t ntos_base = 0;

	function_types::ke_flush_entire_tb_t ke_flush_entire_tb = nullptr;
	function_types::ke_invalidate_all_caches_t ke_invalidate_all_caches = nullptr;
	function_types::mm_allocate_independent_pages_ex_t mm_allocate_independent_pages_ex = nullptr;
	function_types::mm_free_independent_pages mm_free_independent_pages = nullptr;
	function_types::mi_reserve_ptes_t mi_reserve_ptes = nullptr;
	function_types::mi_reserve_ptes_t mi_expand_ptes = nullptr;
	function_types::mi_reserve_ptes_t mi_empty_pte_bins = nullptr;
	function_types::mi_get_pte_address_t mi_get_pte_address = nullptr;
	function_types::mi_remove_physical_memory_t mi_remove_physical_memory = nullptr;
	function_types::mi_get_large_page_t mi_get_large_page = nullptr;
	function_types::mi_flush_entire_tb_due_to_attribute_change_t mi_flush_entire_tb_due_to_attribute_change = nullptr;
	function_types::mi_flush_cache_range_t mi_flush_cache_range = nullptr;

	uintptr_t mm_pfn_db = 0;
	uintptr_t mm_physical_memory_block = 0;
	uintptr_t active_process_links = 0x0;

	unsigned long build_version = 0;

	bool initialized = false;
}

struct pdb_offsets {
	uintptr_t MiReservePtes;
	uintptr_t MiGetPteAddress;
	uintptr_t MiSystemPartition;
	uintptr_t MiInitializePfn;
	uintptr_t MiGetPage;
	uintptr_t MmAllocateIndependentPages;
	uintptr_t MmFreeIndependentPages;
	uintptr_t MiWaitForFreePage;
	uintptr_t MiRemovePhysicalMemory;
	uintptr_t MiFlushEntireTbDueToAttributeChange;
	uintptr_t MiFlushCacheRange;
	uintptr_t MiPinDriverAddressLog;
	uintptr_t ActiveProcessLinks;
};

extern "C"
{
	NTSTATUS NTAPI MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize
	);

	NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);

	NTSTATUS NTAPI MmMarkPhysicalMemoryAsBad(
		IN PPHYSICAL_ADDRESS StartAddress, 
		IN OUT PLARGE_INTEGER NumberOfBytes
	);

}