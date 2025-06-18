#pragma once
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

#define NtCurrentProcess ((HANDLE)(LONG_PTR)-1)
#define PAGE_SHIFT 12L
#define PFN_TO_PAGE(pfn) ((pfn) << PAGE_SHIFT)
#define STATUS_SUCCESS 0x00000000

#define BYTES_TO_PAGES(Size)  (((Size) >> PAGE_SHIFT) + \
                               (((Size) & (PAGE_SIZE - 1)) != 0))
#define PTE_SHIFT 3
#define VA_SHIFT (63 - 47)
#define MiGetVirtualAddressMappedByPte(PTE) ((std::uintptr_t)((LONG_PTR)(((LONG_PTR)(PTE) - 0xFFFFF68000000000) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT))



typedef union _PHYSICAL_ADDRESS {
	struct {
		ULONG LowPart;
		LONG HighPart;
	};
	LONGLONG QuadPart;
} PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;


namespace nt
{
	constexpr auto PAGE_SIZE = 0x1000;
	constexpr auto LARGE_PAGE_SIZE = 0x200000;
	constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

	constexpr auto SystemModuleInformation = 11;
	constexpr auto SystemHandleInformation = 16;
	constexpr auto SystemExtendedHandleInformation = 64;
	
	typedef NTSTATUS(*NtLoadDriver)(PUNICODE_STRING DriverServiceName);
	typedef NTSTATUS(*NtUnloadDriver)(PUNICODE_STRING DriverServiceName);
	typedef NTSTATUS(*RtlAdjustPrivilege)(_In_ ULONG Privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);

    enum driver_alloc_mode {
		ALLOC_IN_SYSTEM_CONTEXT,
        ALLOC_IN_NTOSKRNL_DATA_SECTION,
        ALLOC_IN_CURRENT_PROCESS_CONTEXT
    };

	enum memory_type {
		NORMAL_PAGE,
		LARGE_PAGE,
		HUGE_PAGE
	};

	enum hide_type {
		NONE,
		PFN_EXISTS_BIT,
		MI_REMOVE_PHYSICAL_MEMORY,
		SET_PARITY_ERROR,
		SET_LOCK_BIT,
		HIDE_TRANSLATION
	};

	typedef struct _DRIVER_OBJECT
	{
		SHORT Type;                                                             //0x0
		SHORT Size;                                                             //0x2
		struct _DEVICE_OBJECT* DeviceObject;                                    //0x8
		ULONG Flags;                                                            //0x10
		VOID* DriverStart;                                                      //0x18
		ULONG DriverSize;                                                       //0x20
		VOID* DriverSection;                                                    //0x28
		struct _DRIVER_EXTENSION* DriverExtension;                              //0x30
		struct _UNICODE_STRING DriverName;                                      //0x38
		struct _UNICODE_STRING* HardwareDatabase;                               //0x48
		struct _FAST_IO_DISPATCH* FastIoDispatch;                               //0x50
		LONG(*DriverInit)(struct _DRIVER_OBJECT* arg1, struct _UNICODE_STRING* arg2); //0x58
		VOID(*DriverStartIo)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2);  //0x60
		VOID(*DriverUnload)(struct _DRIVER_OBJECT* arg1);                      //0x68
		LONG(*MajorFunction[28])(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2); //0x70
	} DRIVER_OBJECT;
	typedef struct _DRIVER_OBJECT* PDRIVER_OBJECT;

	typedef struct _SYSTEM_HANDLE
	{
		PVOID Object;
		HANDLE UniqueProcessId;
		HANDLE HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG HandleAttributes;
		ULONG Reserved;
	} SYSTEM_HANDLE, *PSYSTEM_HANDLE;


	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		ULONG_PTR HandleCount;
		ULONG_PTR Reserved;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

	//Thanks to Pvt Comfy for remember to update this https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_pool_type
	typedef enum class _POOL_TYPE {
		NonPagedPool,
		NonPagedPoolExecute = NonPagedPool,
		PagedPool,
		NonPagedPoolMustSucceed = NonPagedPool + 2,
		DontUseThisType,
		NonPagedPoolCacheAligned = NonPagedPool + 4,
		PagedPoolCacheAligned,
		NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
		MaxPoolType,
		NonPagedPoolBase = 0,
		NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
		NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
		NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
		NonPagedPoolSession = 32,
		PagedPoolSession = NonPagedPoolSession + 1,
		NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
		DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
		NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
		PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
		NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
		NonPagedPoolNx = 512,
		NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
		NonPagedPoolSessionNx = NonPagedPoolNx + 32,
	} POOL_TYPE;

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
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

	/*added by psec*/
	typedef enum _MEMORY_CACHING_TYPE_ORIG {
		MmFrameBufferCached = 2
	} MEMORY_CACHING_TYPE_ORIG;

	typedef enum _MEMORY_CACHING_TYPE {
		MmNonCached = FALSE,
		MmCached = TRUE,
		MmWriteCombined = MmFrameBufferCached,
		MmHardwareCoherentCached,
		MmNonCachedUnordered,       // IA64
		MmUSWCCached,
		MmMaximumCacheType,
		MmNotMapped = -1
	} MEMORY_CACHING_TYPE;

	typedef CCHAR KPROCESSOR_MODE;

	typedef enum _MODE {
		KernelMode,
		UserMode,
		MaximumMode
	} MODE;

	typedef enum _MM_PAGE_PRIORITY {
		LowPagePriority,
		NormalPagePriority = 16,
		HighPagePriority = 32
	} MM_PAGE_PRIORITY;
	/**/
	typedef enum _PS_PROTECTED_SIGNER
	{
		PsProtectedSignerNone = 0,
		PsProtectedSignerAuthenticode = 1,
		PsProtectedSignerCodeGen = 2,
		PsProtectedSignerAntimalware = 3,
		PsProtectedSignerLsa = 4,
		PsProtectedSignerWindows = 5,
		PsProtectedSignerWinTcb = 6,
		PsProtectedSignerMax = 7
	} PS_PROTECTED_SIGNER;

	typedef enum _PS_PROTECTED_TYPE
	{
		PsProtectedTypeNone = 0,
		PsProtectedTypeProtectedLight = 1,
		PsProtectedTypeProtected = 2,
		PsProtectedTypeMax = 3

	} PS_PROTECTED_TYPE;
	struct _PS_PROTECTION
	{
		union
		{
			UCHAR Level;                                                        //0x0
			struct
			{
				UCHAR Type : 3;                                                   //0x0
				UCHAR Audit : 1;                                                  //0x0
				UCHAR Signer : 4;                                                 //0x0
			};
		};
	};

	struct _EX_FAST_REF
	{
		union
		{
			VOID* Object;                                                       //0x0
			ULONGLONG RefCnt : 4;                                                 //0x0
			ULONGLONG Value;                                                    //0x0
		};
	};
}
typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    ULONGLONG Mutant;                                                       //0x8
    ULONGLONG ImageBaseAddress;                                             //0x10
    ULONGLONG Ldr;                                                          //0x18
    ULONGLONG ProcessParameters;                                            //0x20
    ULONGLONG SubSystemData;                                                //0x28
    ULONGLONG ProcessHeap;                                                  //0x30
    ULONGLONG FastPebLock;                                                  //0x38
    ULONGLONG AtlThunkSListPtr;                                             //0x40
    ULONGLONG IFEOKey;                                                      //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x50
            ULONG ProcessInitializing : 1;                                    //0x50
            ULONG ProcessUsingVEH : 1;                                        //0x50
            ULONG ProcessUsingVCH : 1;                                        //0x50
            ULONG ProcessUsingFTH : 1;                                        //0x50
            ULONG ProcessPreviouslyThrottled : 1;                             //0x50
            ULONG ProcessCurrentlyThrottled : 1;                              //0x50
            ULONG ProcessImagesHotPatched : 1;                                //0x50
            ULONG ReservedBits0 : 24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        ULONGLONG KernelCallbackTable;                                      //0x58
        ULONGLONG UserSharedInfoPtr;                                        //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    ULONGLONG ApiSetMap;                                                    //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    ULONGLONG TlsBitmap;                                                    //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    ULONGLONG ReadOnlySharedMemoryBase;                                     //0x88
    ULONGLONG SharedData;                                                   //0x90
    ULONGLONG ReadOnlyStaticServerData;                                     //0x98
    ULONGLONG AnsiCodePageData;                                             //0xa0
    ULONGLONG OemCodePageData;                                              //0xa8
    ULONGLONG UnicodeCaseTableData;                                         //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    ULONGLONG ProcessHeaps;                                                 //0xf0
    ULONGLONG GdiSharedHandleTable;                                         //0xf8
    ULONGLONG ProcessStarterHelper;                                         //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    ULONGLONG LoaderLock;                                                   //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    ULONGLONG PostProcessInitRoutine;                                       //0x230
    ULONGLONG TlsExpansionBitmap;                                           //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    ULONGLONG pShimData;                                                    //0x2d8
    ULONGLONG AppCompatInfo;                                                //0x2e0
    typedef struct _STRING64 CSDVersion;                                            //0x2e8
    ULONGLONG ActivationContextData;                                        //0x2f8
    ULONGLONG ProcessAssemblyStorageMap;                                    //0x300
    ULONGLONG SystemDefaultActivationContextData;                           //0x308
    ULONGLONG SystemAssemblyStorageMap;                                     //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    ULONGLONG SparePointers[4];                                             //0x320
    ULONG SpareUlongs[5];                                                   //0x340
    ULONGLONG WerRegistrationData;                                          //0x358
    ULONGLONG WerShipAssertPtr;                                             //0x360
    ULONGLONG pUnused;                                                      //0x368
    ULONGLONG pImageHeaderHash;                                             //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     //0x378
            ULONG CritSecTracingEnabled : 1;                                  //0x378
            ULONG LibLoaderTracingEnabled : 1;                                //0x378
            ULONG SpareTracingBits : 29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct LIST_ENTRY64 TppWorkerpList;                                     //0x390
    ULONGLONG WaitOnAddressHashTable[128];                                  //0x3a0
    ULONGLONG TelemetryCoverageHeader;                                      //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    ULONGLONG LeapSecondData;                                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled : 1;                                     //0x7c0
            ULONG Reserved : 31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
} PEB64, * PPEB64;

extern "C" NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern "C" NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
extern "C" NTSTATUS NTAPI NtLoadDriver(IN PUNICODE_STRING DriverServiceName);
extern "C" NTSTATUS NTAPI NtUnloadDriver(IN PUNICODE_STRING DriverServiceName);