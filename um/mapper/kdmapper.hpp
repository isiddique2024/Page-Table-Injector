#pragma once
#include "../pdb/pdb.hpp"
#include <Windows.h>
#include <iostream>
#include <string>
#include <stdint.h>
#include "portable_executable.hpp"
#include "utils.hpp"
#include "nt.hpp"
#include "intel_driver.hpp"
#include <random>
#include <numeric>


#define PAGE_SIZE 0x1000

namespace kdmapper
{
	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	__forceinline uint64_t MapDriver(HANDLE iqvw64e_device_handle, BYTE* data, ULONG64 param1 = 0, ULONG64 param2 = 0, bool free = false, bool destroyHeader = true, bool PassAllocationAddressAsFirstParam = false, NTSTATUS* exitCode = nullptr);
	__forceinline void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
	__forceinline bool FixSecurityCookie(void* local_image, uint64_t kernel_image_base);
	__forceinline bool ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports);
	__forceinline uint64_t AllocIndependentPages(HANDLE device_handle, uint32_t size);
	__forceinline int Init();
}

__forceinline uint64_t kdmapper::AllocIndependentPages(HANDLE device_handle, uint32_t size)
{

	const auto base = intel_driver::MmAllocateIndependentPagesEx(device_handle, size);
	if (!base)
	{
		Log(L"[-] Error allocating independent pages" << std::endl);
		return 0;
	}

	if (!intel_driver::MmSetPageProtection(device_handle, base, size, PAGE_EXECUTE_READWRITE))
	{
		Log(L"[-] Failed to change page protections" << std::endl);
		intel_driver::MmFreeIndependentPages(device_handle, base, size);
		return 0;
	}

	return base;
}


__forceinline uint64_t kdmapper::MapDriver(HANDLE iqvw64e_device_handle, BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, bool PassAllocationAddressAsFirstParam, NTSTATUS* exitCode) {

	Log(L"[+] Starting Driver Map" << std::endl);

	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(data);
	if (!nt_headers) {
		Log(L"[-] Invalid format of PE image" << std::endl);
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Log(L"[-] Image is not 64-bit" << std::endl);
		return 0;
	}

	uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;
	void* local_image_base = nullptr;
	uint64_t alloc_size = image_size;

	auto status = shadowsyscall<NTSTATUS>("NtAllocateVirtualMemory", NtCurrentProcess, &local_image_base, 0, &alloc_size, MEM_RESERVE | MEM_COMMIT, 0x40);

	if (!NT_SUCCESS(status) || !local_image_base) {
		Log(L"[-] Failed to allocate local memory. NTSTATUS: 0x" << std::hex << status << std::endl);
		return 0;
	}

	Log(L"[+] Successfully allocated local memory at: " << local_image_base << L" with size: " << alloc_size << L" bytes" << std::endl);

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	uintptr_t kernel_image_base = 0;
	
	kernel_image_base = AllocIndependentPages(iqvw64e_device_handle, image_size);
	if (!kernel_image_base) {
		Log(L"[-] Failed to allocate remote image in kernel" << std::endl);
		alloc_size = 0; // Set size to 0 for release
		shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &local_image_base, &alloc_size, MEM_RELEASE);
		return 0;
	}

	do {
		Log(L"[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl);

		// Copy image headers
		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		Log(L"[+] Image headers copied to local memory" << std::endl);

		// Copy image sections
		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);
		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0) {
				Log(L"[+] Skipping uninitialized section: " << i << std::endl);
				continue;
			}
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
			Log(L"[+] Copied section: " << i << std::endl);
		}

		uint64_t realBase = kernel_image_base;
		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
			Log(L"[+] Skipped 0x" << std::hex << TotalVirtualHeaderSize << L" bytes of PE Header" << std::endl);
		}

		// Resolve relocs and imports
		Log(L"[+] Resolving relocations" << std::endl);
		RelocateImageByDelta(GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		Log(L"[+] Fixing security cookie" << std::endl);
		if (!FixSecurityCookie(local_image_base, kernel_image_base)) {
			Log(L"[-] Failed to fix security cookie" << std::endl);
			return 0;
		}

		Log(L"[+] Resolving imports" << std::endl);
		if (!ResolveImports(iqvw64e_device_handle, GetImports(local_image_base))) {
			Log(L"[-] Failed to resolve imports" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		Log(L"[+] Writing image to kernel memory" << std::endl);

		// Write fixed image
		if (!intel_driver::WriteMemory(iqvw64e_device_handle, realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
			Log(L"[-] Failed to write local image to remote image" << std::endl);
			kernel_image_base = realBase;
			break;
		}
	
		// Call driver entry point
		const uint64_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;
		Log(L"[<] Calling DriverEntry at 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl);


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

		uintptr_t ntoskrnl_base = utils::GetKernelModuleAddress("ntoskrnl.exe");
		if (!ntoskrnl_base) {
			Log(L"[-] Failed to get ntoskrnl.exe base address" << std::endl);
			return 0;
		}

		std::string kernel = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
		std::string pdbPath = EzPdbDownload(kernel);
		kernel.clear();

		if (pdbPath.empty()) {
			return 0;
		}

		EZPDB pdb;
		if (!EzPdbLoad(pdbPath, &pdb)) {
			return 0;
		}

		// I'm not using most of these functions, a lot of them were experimental.
		pdb_offsets offsets = {
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiReservePtes"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiGetPteAddress"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiSystemPartition"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiInitializePfn"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiGetPage"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmAllocateIndependentPages"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MmFreeIndependentPages"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiWaitForFreePage"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiRemovePhysicalMemory"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiFlushEntireTbDueToAttributeChange"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiFlushCacheRange"),
			ntoskrnl_base + EzPdbGetRva(&pdb, "MiPinDriverAddressLog"),
			EzPdbGetStructPropertyOffset(&pdb, ("_EPROCESS"), L"ActiveProcessLinks")
		};

		EzPdbUnload(pdbPath, &pdb);

		Log(L"[<] Driver Mapped" << std::endl);

		if (!intel_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point, kernel_image_base, (uintptr_t)image_size, &offsets)) {
			Log(L"[-] Failed to call driver entry" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (exitCode) {
			*exitCode = status;
			Log(L"[+] DriverEntry returned status: 0x" << std::hex << status << std::endl);
		}

		// Free memory
		if (free) {
			Log(L"[+] Freeing kernel memory" << std::endl);
			bool free_status = intel_driver::MmFreeIndependentPages(iqvw64e_device_handle, realBase, image_size);

			if (free_status) {
				Log(L"[+] Memory has been released" << std::endl);
			}
			else {
				Log(L"[-] WARNING: Failed to free memory!" << std::endl);
			}
		}

		alloc_size = 0;
		Log(L"[+] Releasing local memory" << std::endl);
		shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &local_image_base, &alloc_size, MEM_RELEASE);
		return realBase;

	} while (false);

	alloc_size = 0;
	Log(L"[+] Releasing local memory after failure" << std::endl);
	shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &local_image_base, &alloc_size, MEM_RELEASE);

	Log(L"[+] Freeing kernel memory after failure" << std::endl);
	bool free_status = intel_driver::MmFreeIndependentPages(iqvw64e_device_handle, kernel_image_base, image_size);

	if (free_status) {
		Log(L"[+] Memory has been released" << std::endl);
	}
	else {
		Log(L"[-] WARNING: Failed to free memory!" << std::endl);
	}

	return 0;
}


__forceinline void kdmapper::RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

// Fix cookie by @Jerem584
__forceinline bool kdmapper::FixSecurityCookie(void* local_image, uint64_t kernel_image_base)
{
	auto headers = GetNtHeaders(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		Log(L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		Log(L"[+] StackCookie not defined, fix cookie skipped" << std::endl);
		return true; // as I said, it is not an error and we should allow that behavior
	}

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image; //since our local image is already relocated the base returned will be kernel address

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
		Log(L"[-] StackCookie already fixed!? this probably wrong" << std::endl);
		return false;
	}

	Log(L"[+] Fixing stack cookie" << std::endl);

	auto new_cookie = (0x2B992DDFA232) ^ shadowcall<DWORD>("GetCurrentProcessId") ^ shadowcall<DWORD>("GetCurrentThreadId"); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie;
	return true;
}

__forceinline bool kdmapper::ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
#if !defined(DISABLE_OUTPUT)
			//std::cout << ("[-] Dependency ") << current_import.module_name << " wasn't found" << std::endl;
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			uint64_t function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != intel_driver::ntoskrnlAddr) {
					function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, intel_driver::ntoskrnlAddr, current_function_data.name);
					if (!function_address) {
#if !defined(DISABLE_OUTPUT)
						//std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
#endif
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}
	return true;
}

__forceinline int kdmapper::Init() {

	utils::init_mapper_dependencies();

	void* iqvw64e_device_handle = intel_driver::Load();
	if (iqvw64e_device_handle == (void*)(0x5232)) {
		return NULL;
	}
	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	NTSTATUS exit_code = 0;
	if (!kdmapper::MapDriver(iqvw64e_device_handle, (std::uint8_t*)driver_shell, 0, 0, false, true, false, &exit_code)) {
		intel_driver::Unload(iqvw64e_device_handle);
		return NULL;
	}

	intel_driver::Unload(iqvw64e_device_handle);
	return 1;
}
