#pragma once
#include <Windows.h>
#include <stdint.h>
#include <vector>
#include <string>

namespace portable_executable
{
	struct RelocInfo
	{
		uint64_t address;
		uint16_t* item;
		uint32_t count;
	};

	struct ImportFunctionInfo
	{
		std::string name;
		uint64_t* address;
	};

	struct ImportInfo
	{
		std::string module_name;
		std::vector<ImportFunctionInfo> function_datas;
	};

	using vec_sections = std::vector<IMAGE_SECTION_HEADER>;
	using vec_relocs = std::vector<RelocInfo>;
	using vec_imports = std::vector<ImportInfo>;

}

__forceinline PIMAGE_NT_HEADERS64 GetNtHeaders(void* image_base) {

	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);

	if (dos_header->e_magic != (IMAGE_DOS_SIGNATURE))
		return nullptr;

	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint64_t>(image_base) + dos_header->e_lfanew);

	if (nt_headers->Signature != (IMAGE_NT_SIGNATURE))
		return nullptr;

	return nt_headers;
}

__forceinline portable_executable::vec_relocs GetRelocs(void* image_base) {
	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base);

	if (!nt_headers)
		return {};

	portable_executable::vec_relocs relocs;
	DWORD reloc_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	if (!reloc_va) //Fix from @greetmark of UnknownCheats Forum
		return {};

	auto current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(image_base) + reloc_va);
	const auto reloc_end = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(current_base_relocation) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	while (current_base_relocation < reloc_end && current_base_relocation->SizeOfBlock) {
		portable_executable::RelocInfo reloc_info;

		reloc_info.address = reinterpret_cast<uint64_t>(image_base) + current_base_relocation->VirtualAddress;
		reloc_info.item = reinterpret_cast<uint16_t*>(reinterpret_cast<uint64_t>(current_base_relocation) + sizeof(IMAGE_BASE_RELOCATION));
		reloc_info.count = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

		relocs.push_back(reloc_info);

		current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(current_base_relocation) + current_base_relocation->SizeOfBlock);
	}

	return relocs;
}

__forceinline portable_executable::vec_imports GetImports(void* image_base) {
	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base);

	if (!nt_headers)
		return {};

	DWORD import_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	//not imports necesary
	if (!import_va)
		return {};

	portable_executable::vec_imports imports;

	auto current_import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<uint64_t>(image_base) + import_va);

	while (current_import_descriptor->FirstThunk) {
		portable_executable::ImportInfo import_info;

		import_info.module_name = std::string(reinterpret_cast<char*>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->Name));

		auto current_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->FirstThunk);
		auto current_originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->OriginalFirstThunk);

		while (current_originalFirstThunk->u1.Function) {
			portable_executable::ImportFunctionInfo import_function_data;

			auto thunk_data = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uint64_t>(image_base) + current_originalFirstThunk->u1.AddressOfData);

			import_function_data.name = thunk_data->Name;
			import_function_data.address = &current_first_thunk->u1.Function;

			import_info.function_datas.push_back(import_function_data);

			++current_originalFirstThunk;
			++current_first_thunk;
		}

		imports.push_back(import_info);
		++current_import_descriptor;
	}

	return imports;
}