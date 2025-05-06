#pragma once
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

#define NtCurrentProcess ((HANDLE)(LONG_PTR)-1)
#define PAGE_SHIFT 12L

#define STATUS_SUCCESS 0x00000000

#define BYTES_TO_PAGES(Size)  (((Size) >> PAGE_SHIFT) + \
                               (((Size) & (PAGE_SIZE - 1)) != 0))
#define PTE_SHIFT 3
#define VA_SHIFT (63 - 47)
#define MiGetVirtualAddressMappedByPte(PTE) ((std::uintptr_t)((LONG_PTR)(((LONG_PTR)(PTE) - 0xFFFFF68000000000) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT))

namespace nt
{
	constexpr auto PAGE_SIZE = 0x1000;
	constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

	constexpr auto SystemModuleInformation = 11;
	constexpr auto SystemHandleInformation = 16;
	constexpr auto SystemExtendedHandleInformation = 64;
	
	typedef NTSTATUS(*NtLoadDriver)(PUNICODE_STRING DriverServiceName);
	typedef NTSTATUS(*NtUnloadDriver)(PUNICODE_STRING DriverServiceName);
	typedef NTSTATUS(*RtlAdjustPrivilege)(_In_ ULONG Privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);



    typedef union _pml4e
    {
        std::uint64_t value;
        struct
        {
            std::uint64_t present : 1;          // Must be 1, region invalid if 0.
            std::uint64_t writeable : 1;        // If 0, writes not allowed.
            std::uint64_t user_supervisor : 1;   // If 0, user-mode accesses not allowed.
            std::uint64_t PageWriteThrough : 1; // Determines the memory type used to access PDPT.
            std::uint64_t page_cache : 1; // Determines the memory type used to access PDPT.
            std::uint64_t accessed : 1;         // If 0, this entry has not been used for translation.
            std::uint64_t Ignored1 : 1;
            std::uint64_t large_page : 1;         // Must be 0 for PML4E.
            std::uint64_t Ignored2 : 4;
            std::uint64_t pfn : 36; // The page frame number of the PDPT of this PML4E.
            std::uint64_t Reserved : 4;
            std::uint64_t Ignored3 : 11;
            std::uint64_t nx : 1; // If 1, instruction fetches not allowed.
        };
    } pml4e, * ppml4e;
    static_assert(sizeof(pml4e) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

    typedef union _pdpte
    {
        std::uint64_t value;
        struct
        {
            std::uint64_t present : 1;          // Must be 1, region invalid if 0.
            std::uint64_t rw : 1;        // If 0, writes not allowed.
            std::uint64_t user_supervisor : 1;   // If 0, user-mode accesses not allowed.
            std::uint64_t PageWriteThrough : 1; // Determines the memory type used to access PD.
            std::uint64_t page_cache : 1; // Determines the memory type used to access PD.
            std::uint64_t accessed : 1;         // If 0, this entry has not been used for translation.
            std::uint64_t Ignored1 : 1;
            std::uint64_t large_page : 1;         // If 1, this entry maps a 1GB page.
            std::uint64_t Ignored2 : 4;
            std::uint64_t pfn : 36; // The page frame number of the PD of this PDPTE.
            std::uint64_t Reserved : 4;
            std::uint64_t Ignored3 : 11;
            std::uint64_t nx : 1; // If 1, instruction fetches not allowed.
        };
    } pdpte, * ppdpte;
    static_assert(sizeof(pdpte) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

    typedef union _pde
    {
        std::uint64_t value;
        struct
        {
            std::uint64_t present : 1;          // Must be 1, region invalid if 0.
            std::uint64_t rw : 1;        // If 0, writes not allowed.
            std::uint64_t user_supervisor : 1;   // If 0, user-mode accesses not allowed.
            std::uint64_t PageWriteThrough : 1; // Determines the memory type used to access PT.
            std::uint64_t page_cache : 1; // Determines the memory type used to access PT.
            std::uint64_t accessed : 1;         // If 0, this entry has not been used for translation.
            std::uint64_t Ignored1 : 1;
            std::uint64_t large_page : 1; // If 1, this entry maps a 2MB page.
            std::uint64_t Ignored2 : 4;
            std::uint64_t pfn : 36; // The page frame number of the PT of this PDE.
            std::uint64_t Reserved : 4;
            std::uint64_t Ignored3 : 11;
            std::uint64_t nx : 1; // If 1, instruction fetches not allowed.
        };
    } pde, * ppde;
    static_assert(sizeof(pde) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

    typedef union _pte
    {
        std::uint64_t value;
        struct
        {
            std::uint64_t present : 1;          // Must be 1, region invalid if 0.
            std::uint64_t rw : 1;        // If 0, writes not allowed.
            std::uint64_t user_supervisor : 1;   // If 0, user-mode accesses not allowed.
            std::uint64_t PageWriteThrough : 1; // Determines the memory type used to access the memory.
            std::uint64_t page_cache : 1; // Determines the memory type used to access the memory.
            std::uint64_t accessed : 1;         // If 0, this entry has not been used for translation.
            std::uint64_t Dirty : 1;            // If 0, the memory backing this page has not been written to.
            std::uint64_t PageAccessType : 1;   // Determines the memory type used to access the memory.
            std::uint64_t Global : 1;           // If 1 and the PGE bit of CR4 is set, translations are global.
            std::uint64_t Ignored2 : 3;
            std::uint64_t pfn : 36; // The page frame number of the backing physical page.
            std::uint64_t reserved : 4;
            std::uint64_t Ignored3 : 7;
            std::uint64_t ProtectionKey : 4;  // If the PKE bit of CR4 is set, determines the protection key.
            std::uint64_t nx : 1; // If 1, instruction fetches not allowed.
        };
    } pte, * ppte;
    static_assert(sizeof(pte) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

    typedef union
    {
        struct
        {
            UINT64 Present : 1;
#define PT_ENTRY_64_PRESENT_BIT                                      0
#define PT_ENTRY_64_PRESENT_FLAG                                     0x01
#define PT_ENTRY_64_PRESENT_MASK                                     0x01
#define PT_ENTRY_64_PRESENT(_)                                       (((_) >> 0) & 0x01)
            UINT64 Write : 1;
#define PT_ENTRY_64_WRITE_BIT                                        1
#define PT_ENTRY_64_WRITE_FLAG                                       0x02
#define PT_ENTRY_64_WRITE_MASK                                       0x01
#define PT_ENTRY_64_WRITE(_)                                         (((_) >> 1) & 0x01)
            UINT64 Supervisor : 1;
#define PT_ENTRY_64_SUPERVISOR_BIT                                   2
#define PT_ENTRY_64_SUPERVISOR_FLAG                                  0x04
#define PT_ENTRY_64_SUPERVISOR_MASK                                  0x01
#define PT_ENTRY_64_SUPERVISOR(_)                                    (((_) >> 2) & 0x01)
            UINT64 PageLevelWriteThrough : 1;
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH_BIT                     3
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH_FLAG                    0x08
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH_MASK                    0x01
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH(_)                      (((_) >> 3) & 0x01)
            UINT64 PageLevelCacheDisable : 1;
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE_BIT                     4
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE_FLAG                    0x10
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE_MASK                    0x01
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE(_)                      (((_) >> 4) & 0x01)
            UINT64 Accessed : 1;
#define PT_ENTRY_64_ACCESSED_BIT                                     5
#define PT_ENTRY_64_ACCESSED_FLAG                                    0x20
#define PT_ENTRY_64_ACCESSED_MASK                                    0x01
#define PT_ENTRY_64_ACCESSED(_)                                      (((_) >> 5) & 0x01)
            UINT64 Dirty : 1;
#define PT_ENTRY_64_DIRTY_BIT                                        6
#define PT_ENTRY_64_DIRTY_FLAG                                       0x40
#define PT_ENTRY_64_DIRTY_MASK                                       0x01
#define PT_ENTRY_64_DIRTY(_)                                         (((_) >> 6) & 0x01)
            UINT64 LargePage : 1;
#define PT_ENTRY_64_LARGE_PAGE_BIT                                   7
#define PT_ENTRY_64_LARGE_PAGE_FLAG                                  0x80
#define PT_ENTRY_64_LARGE_PAGE_MASK                                  0x01
#define PT_ENTRY_64_LARGE_PAGE(_)                                    (((_) >> 7) & 0x01)
            UINT64 Global : 1;
#define PT_ENTRY_64_GLOBAL_BIT                                       8
#define PT_ENTRY_64_GLOBAL_FLAG                                      0x100
#define PT_ENTRY_64_GLOBAL_MASK                                      0x01
#define PT_ENTRY_64_GLOBAL(_)                                        (((_) >> 8) & 0x01)

            /**
             * [Bits 11:9] Ignored.
             */
            UINT64 Ignored1 : 3;
#define PT_ENTRY_64_IGNORED_1_BIT                                    9
#define PT_ENTRY_64_IGNORED_1_FLAG                                   0xE00
#define PT_ENTRY_64_IGNORED_1_MASK                                   0x07
#define PT_ENTRY_64_IGNORED_1(_)                                     (((_) >> 9) & 0x07)

            /**
             * [Bits 47:12] Physical address of the 4-KByte page referenced by this entry.
             */
            UINT64 PageFrameNumber : 36;
#define PT_ENTRY_64_PAGE_FRAME_NUMBER_BIT                            12
#define PT_ENTRY_64_PAGE_FRAME_NUMBER_FLAG                           0xFFFFFFFFF000
#define PT_ENTRY_64_PAGE_FRAME_NUMBER_MASK                           0xFFFFFFFFF
#define PT_ENTRY_64_PAGE_FRAME_NUMBER(_)                             (((_) >> 12) & 0xFFFFFFFFF)
            UINT64 Reserved1 : 4;

            /**
             * [Bits 58:52] Ignored.
             */
            UINT64 Ignored2 : 7;
#define PT_ENTRY_64_IGNORED_2_BIT                                    52
#define PT_ENTRY_64_IGNORED_2_FLAG                                   0x7F0000000000000
#define PT_ENTRY_64_IGNORED_2_MASK                                   0x7F
#define PT_ENTRY_64_IGNORED_2(_)                                     (((_) >> 52) & 0x7F)
            UINT64 ProtectionKey : 4;
#define PT_ENTRY_64_PROTECTION_KEY_BIT                               59
#define PT_ENTRY_64_PROTECTION_KEY_FLAG                              0x7800000000000000
#define PT_ENTRY_64_PROTECTION_KEY_MASK                              0x0F
#define PT_ENTRY_64_PROTECTION_KEY(_)                                (((_) >> 59) & 0x0F)
            UINT64 ExecuteDisable : 1;
#define PT_ENTRY_64_EXECUTE_DISABLE_BIT                              63
#define PT_ENTRY_64_EXECUTE_DISABLE_FLAG                             0x8000000000000000
#define PT_ENTRY_64_EXECUTE_DISABLE_MASK                             0x01
#define PT_ENTRY_64_EXECUTE_DISABLE(_)                               (((_) >> 63) & 0x01)
        };

        UINT64 Flags;
    } PTE;
    typedef union
    {
        struct
        {
            /**
             * [Bit 0] Present; must be 1 to reference a page table.
             */
            UINT64 Present : 1;
#define PDE_64_PRESENT_BIT                                           0
#define PDE_64_PRESENT_FLAG                                          0x01
#define PDE_64_PRESENT_MASK                                          0x01
#define PDE_64_PRESENT(_)                                            (((_) >> 0) & 0x01)

            /**
             * [Bit 1] Read/write; if 0, writes may not be allowed to the 2-MByte region controlled by this entry.
             *
             * @see Vol3A[4.6(Access Rights)]
             */
            UINT64 Write : 1;
#define PDE_64_WRITE_BIT                                             1
#define PDE_64_WRITE_FLAG                                            0x02
#define PDE_64_WRITE_MASK                                            0x01
#define PDE_64_WRITE(_)                                              (((_) >> 1) & 0x01)

            /**
             * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 2-MByte region controlled by this entry.
             *
             * @see Vol3A[4.6(Access Rights)]
             */
            UINT64 Supervisor : 1;
#define PDE_64_SUPERVISOR_BIT                                        2
#define PDE_64_SUPERVISOR_FLAG                                       0x04
#define PDE_64_SUPERVISOR_MASK                                       0x01
#define PDE_64_SUPERVISOR(_)                                         (((_) >> 2) & 0x01)

            /**
             * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the page table referenced by this
             * entry.
             *
             * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
             */
            UINT64 PageLevelWriteThrough : 1;
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH_BIT                          3
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH_FLAG                         0x08
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH_MASK                         0x01
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH(_)                           (((_) >> 3) & 0x01)

            /**
             * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the page table referenced by this
             * entry.
             *
             * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
             */
            UINT64 PageLevelCacheDisable : 1;
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE_BIT                          4
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE_FLAG                         0x10
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE_MASK                         0x01
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE(_)                           (((_) >> 4) & 0x01)

            /**
             * [Bit 5] Accessed; indicates whether this entry has been used for linear-address translation.
             *
             * @see Vol3A[4.8(Accessed and Dirty Flags)]
             */
            UINT64 Accessed : 1;
#define PDE_64_ACCESSED_BIT                                          5
#define PDE_64_ACCESSED_FLAG                                         0x20
#define PDE_64_ACCESSED_MASK                                         0x01
#define PDE_64_ACCESSED(_)                                           (((_) >> 5) & 0x01)
            UINT64 Reserved1 : 1;

            /**
             * [Bit 7] Page size; must be 0 (otherwise, this entry maps a 2-MByte page).
             */
            UINT64 LargePage : 1;
#define PDE_64_LARGE_PAGE_BIT                                        7
#define PDE_64_LARGE_PAGE_FLAG                                       0x80
#define PDE_64_LARGE_PAGE_MASK                                       0x01
#define PDE_64_LARGE_PAGE(_)                                         (((_) >> 7) & 0x01)

            /**
             * [Bits 11:8] Ignored.
             */
            UINT64 Ignored1 : 4;
#define PDE_64_IGNORED_1_BIT                                         8
#define PDE_64_IGNORED_1_FLAG                                        0xF00
#define PDE_64_IGNORED_1_MASK                                        0x0F
#define PDE_64_IGNORED_1(_)                                          (((_) >> 8) & 0x0F)

            /**
             * [Bits 47:12] Physical address of 4-KByte aligned page table referenced by this entry.
             */
            UINT64 PageFrameNumber : 36;
#define PDE_64_PAGE_FRAME_NUMBER_BIT                                 12
#define PDE_64_PAGE_FRAME_NUMBER_FLAG                                0xFFFFFFFFF000
#define PDE_64_PAGE_FRAME_NUMBER_MASK                                0xFFFFFFFFF
#define PDE_64_PAGE_FRAME_NUMBER(_)                                  (((_) >> 12) & 0xFFFFFFFFF)
            UINT64 Reserved2 : 4;

            /**
             * [Bits 62:52] Ignored.
             */
            UINT64 Ignored2 : 11;
#define PDE_64_IGNORED_2_BIT                                         52
#define PDE_64_IGNORED_2_FLAG                                        0x7FF0000000000000
#define PDE_64_IGNORED_2_MASK                                        0x7FF
#define PDE_64_IGNORED_2(_)                                          (((_) >> 52) & 0x7FF)

            /**
             * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 2-MByte region
             * controlled by this entry); otherwise, reserved (must be 0).
             *
             * @see Vol3A[4.6(Access Rights)]
             */
            UINT64 ExecuteDisable : 1;
#define PDE_64_EXECUTE_DISABLE_BIT                                   63
#define PDE_64_EXECUTE_DISABLE_FLAG                                  0x8000000000000000
#define PDE_64_EXECUTE_DISABLE_MASK                                  0x01
#define PDE_64_EXECUTE_DISABLE(_)                                    (((_) >> 63) & 0x01)
        };

        UINT64 Flags;
    } PDE;
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