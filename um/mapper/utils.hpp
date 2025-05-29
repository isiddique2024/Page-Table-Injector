#pragma once
#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>
#include <cwctype>
#include <locale>
//#define DISABLE_OUTPUT 1
#if defined(DISABLE_OUTPUT)
#define Log(content) 
#else
#define Log(content) \
    do { \
        std::wstringstream _wss; \
        _wss << content; \
        std::wstring _wcontent = _wss.str(); \
        std::transform(_wcontent.begin(), _wcontent.end(), _wcontent.begin(), \
            [](wchar_t c) { return ::towlower(c); }); \
        if (_wcontent.length() > 3) { \
            std::wcout << _wcontent.substr(0, 3) << L" " << __FUNCTION__ << L"" << _wcontent.substr(3); \
        } else { \
            std::wcout << _wcontent << L" " << __FUNCTION__ << L""; \
        } \
    } while(0)
#endif


#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <fstream>

#include "nt.hpp"
#include "../lib/sys.hpp"

namespace utils
{
	std::wstring GetFullTempPath();
	bool ReadFileToMemory(const std::wstring& file_path, std::vector<uint8_t>* out_buffer);
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);
	uint64_t GetKernelModuleAddress(const std::string& module_name);
	ULONG GetKernelModuleSize(const std::string& module_name);
	BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
	uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	PVOID FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size);
	PVOID FindUnusedSpace(HANDLE device_handle, uintptr_t base, unsigned long section_size, size_t required_size, size_t chunk_size = 0x10000);
	auto init_mapper_dependencies() -> int;
}


std::wstring utils::GetFullTempPath() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = shadowcall<DWORD>("GetTempPathW",sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		Log(L"[-] Failed to get temp path" << std::endl);
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}

bool utils::ReadFileToMemory(const std::wstring& file_path, std::vector<uint8_t>* out_buffer) {
	std::ifstream file_ifstream(file_path, std::ios::binary);

	if (!file_ifstream)
		return false;

	out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
	file_ifstream.close();

	return true;
}

 bool utils::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size)) {
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

 __forceinline auto utils::init_mapper_dependencies() -> int {

	 shadowcall<HMODULE>({ "LoadLibraryA", "Kernel32.dll" }, ("Dbghelp.dll"));
	 shadowcall<HMODULE>({ "LoadLibraryA", "Kernel32.dll" }, ("urlmon.dll"));
	 shadowcall<HMODULE>({ "LoadLibraryA", "Kernel32.dll" }, ("Ole32.dll"));
	 shadowcall<HMODULE>({ "LoadLibraryA", "Kernel32.dll" }, ("Advapi32.dll"));
	 shadowcall<HMODULE>({ "LoadLibraryA", "Kernel32.dll" }, ("bcrypt.dll"));
	 shadowcall<HMODULE>({ "LoadLibraryA", "Kernel32.dll" }, ("Wintrust.dll"));

	 HANDLE hToken;
	 NTSTATUS status;

	 status = shadowsyscall<NTSTATUS>("NtOpenProcessToken",
		 ((HANDLE)(LONG_PTR)-1),
		 TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		 &hToken
	 );

	 if (!NT_SUCCESS(status)) {
		 return FALSE;
	 }

	 TOKEN_PRIVILEGES tkp;
	 tkp.PrivilegeCount = 1;
	 tkp.Privileges[0].Luid.LowPart = 0x14;
	 tkp.Privileges[0].Luid.HighPart = 0;
	 tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	 status = shadowsyscall<NTSTATUS>("NtAdjustPrivilegesToken",
		 hToken,
		 FALSE,
		 &tkp,
		 sizeof(TOKEN_PRIVILEGES),
		 NULL,
		 NULL
	 );

	 shadowsyscall<NTSTATUS>("NtClose", hToken);
	 return NT_SUCCESS(status);
 }
#include <windows.h>
#include <winternl.h>
#include <string>

 uint64_t utils::GetKernelModuleAddress(const std::string& module_name) {
	 void* buffer = nullptr;
	 DWORD buffer_size = 0;
	 NTSTATUS status = shadowsyscall<NTSTATUS>("NtQuerySystemInformation", static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	 while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
		 if (buffer != nullptr) {
			 SIZE_T region_size = 0;
			 shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
		 }

		 SIZE_T alloc_size = buffer_size;
		 status = shadowsyscall<NTSTATUS>("NtAllocateVirtualMemory", NtCurrentProcess, &buffer, 0, &alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		 status = shadowsyscall<NTSTATUS>("NtQuerySystemInformation", static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	 }

	 if (!NT_SUCCESS(status)) {
		 if (buffer != nullptr) {
			 SIZE_T region_size = 0;
			 shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
		 }
		 return 0;
	 }

	 const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
	 if (!modules) {
		 return 0;
	 }

	 for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		 const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

		 if (!_stricmp(current_module_name.c_str(), module_name.c_str())) {
			 const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

			 SIZE_T region_size = 0;
			 shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
			 return result;
		 }
	 }

	 SIZE_T region_size = 0;
	 shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
	 return 0;
 }

 ULONG utils::GetKernelModuleSize(const std::string& module_name) {
	 void* buffer = nullptr;
	 DWORD buffer_size = 0;
	 NTSTATUS status = shadowsyscall<NTSTATUS>("NtQuerySystemInformation", static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	 while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
		 if (buffer != nullptr) {
			 SIZE_T region_size = 0;
			 shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
		 }

		 SIZE_T alloc_size = buffer_size;
		 status = shadowsyscall<NTSTATUS>("NtAllocateVirtualMemory", NtCurrentProcess, &buffer, 0, &alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		 status = shadowsyscall<NTSTATUS>("NtQuerySystemInformation", static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	 }

	 if (!NT_SUCCESS(status)) {
		 if (buffer != nullptr) {
			 SIZE_T region_size = 0;
			 shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
		 }
		 return 0;
	 }

	 const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
	 if (!modules) {
		 return 0;
	 }

	 for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		 const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

		 if (!_stricmp(current_module_name.c_str(), module_name.c_str())) {
			 const ULONG result = modules->Modules[i].ImageSize;

			 SIZE_T region_size = 0;
			 shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
			 return result;
		 }
	 }

	 SIZE_T region_size = 0;
	 shadowsyscall<NTSTATUS>("NtFreeVirtualMemory", NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
	 return 0;
 }

BOOLEAN utils::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;
	return (*szMask) == 0;
}

uintptr_t utils::FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	size_t max_len = dwLen - (strlen)(szMask);
	for (uintptr_t i = 0; i < max_len; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (uintptr_t)(dwAddress + i);
	return 0;
}

PVOID utils::FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size) {
	size_t namelength = (strlen)(sectionName);
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(modulePtr + ((PIMAGE_DOS_HEADER)modulePtr)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, sectionName, namelength) == 0 &&
			namelength == (strlen)((char*)section->Name)) {
			if (!section->VirtualAddress) {
				return 0;
			}
			if (size) {
				*size = section->Misc.VirtualSize;
			}
			return (PVOID)(modulePtr + section->VirtualAddress);
		}
	}
	return 0;
}


