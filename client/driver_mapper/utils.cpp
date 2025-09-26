#include "utils.hpp"
#include <fstream>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include "memory_manager.hpp"
#include <NTSecAPI.h>

#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
auto utils_t::write_memory_to_file(const std::wstring& file_path, const void* data,
                                   std::size_t size) -> bool {
  std::ofstream file(file_path, std::ios::binary);
  if (!file.is_open()) {
    return false;
  }

  return file.write(reinterpret_cast<const char*>(data), size).good();
}

auto utils_t::create_file_from_memory(const std::wstring& desired_file_path, const char* address,
                                      std::size_t size) -> bool {
  return write_memory_to_file(desired_file_path, address, size);
}

auto utils_t::read_file(const std::string& file_path) -> std::vector<uint8_t> {
  std::ifstream file(file_path, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    return {};
  }

  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> buffer(size);
  if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
    return {};
  }

  return buffer;
}
auto utils_t::get_temp_path() -> std::wstring {
  wchar_t temp_path[MAX_PATH + 1] = {0};
  auto result = GetTempPathW(sizeof(temp_path) / sizeof(wchar_t), temp_path);
  if (result == 0 || result > MAX_PATH) {
    return L"";
  }

  // remove trailing backslash if present
  std::wstring path(temp_path);
  if (!path.empty() && path.back() == L'\\') {
    path.pop_back();
  }

  return path;
}

auto utils_t::get_kernel_module_address(const std::string& module_name) -> std::uint64_t {
  void* buffer = nullptr;
  ULONG buffer_size = 0;

  auto status =
      NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
                               buffer, buffer_size, &buffer_size);

  while (status == STATUS_INFO_LENGTH_MISMATCH) {
    if (buffer) {
      SIZE_T region_size = 0;
      NtFreeVirtualMemory(NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
    }

    SIZE_T alloc_size = buffer_size;
    status = NtAllocateVirtualMemory(NtCurrentProcess, &buffer, 0, &alloc_size,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
      return 0;
    }

    status =
        NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
                                 buffer, buffer_size, &buffer_size);
  }

  if (!NT_SUCCESS(status) || !buffer) {
    if (buffer) {
      SIZE_T region_size = 0;
      NtFreeVirtualMemory(NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
    }
    return 0;
  }

  auto modules = static_cast<rtl_process_modules_t*>(buffer);
  std::uint64_t result = 0;

  for (auto i = 0u; i < modules->number_of_modules; ++i) {
    auto current_module_name =
        std::string(reinterpret_cast<char*>(modules->modules[i].full_path_name) +
                    modules->modules[i].offset_to_file_name);

    if (_stricmp(current_module_name.c_str(), module_name.c_str()) == 0) {
      result = reinterpret_cast<std::uint64_t>(modules->modules[i].image_base);
      break;
    }
  }

  SIZE_T region_size = 0;
  NtFreeVirtualMemory(NtCurrentProcess, &buffer, &region_size, MEM_RELEASE);
  return result;
}

auto utils_t::find_pattern(std::uintptr_t address, std::uintptr_t length,
                           const std::uint8_t* pattern, const char* mask) -> std::uintptr_t {
  auto mask_length = std::strlen(mask);
  auto max_search = length - mask_length;

  for (std::uintptr_t i = 0; i < max_search; ++i) {
    if (compare_memory(reinterpret_cast<const std::uint8_t*>(address + i), pattern, mask)) {
      return address + i;
    }
  }

  return 0;
}

auto utils_t::find_pattern_at_kernel(HANDLE device_handle, std::uintptr_t address,
                                     std::uintptr_t length, const std::uint8_t* pattern,
                                     const char* mask) -> std::uintptr_t {
  if (!address) {
    return 0;
  }

  if (length > 1024 * 1024 * 1024) {  // if read is > 1GB
    return 0;
  }

  auto section_data = std::make_unique<std::uint8_t[]>(length);
  if (!g_memory_manager->read_memory(device_handle, address, section_data.get(), length)) {
    return 0;
  }

  auto result =
      find_pattern(reinterpret_cast<std::uintptr_t>(section_data.get()), length, pattern, mask);

  if (result <= 0) {
    return 0;
  }

  result = address - reinterpret_cast<std::uintptr_t>(section_data.get()) + result;
  return result;
}

auto utils_t::find_section(const char* section_name, std::uintptr_t module_ptr, std::uint32_t* size)
    -> std::uintptr_t {
  if (!module_ptr || !section_name) {
    return 0;
  }

  auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_ptr);
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    return 0;
  }

  auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(module_ptr + dos_header->e_lfanew);
  if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
    return 0;
  }

  auto section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(
      reinterpret_cast<std::uintptr_t>(&nt_headers->OptionalHeader) +
      nt_headers->FileHeader.SizeOfOptionalHeader);

  for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
    if (strcmp(reinterpret_cast<char*>(section_header[i].Name), section_name) == 0) {
      if (size) {
        *size = section_header[i].Misc.VirtualSize;
      }
      return module_ptr + section_header[i].VirtualAddress;
    }
  }

  return 0;
}

auto utils_t::find_section_at_kernel(HANDLE device_handle, const char* section_name,
                                     std::uintptr_t module_ptr, std::uint32_t* size)
    -> std::uintptr_t {
  if (!module_ptr || !section_name) {
    return 0;
  }

  std::uint8_t headers[0x1000];
  if (!g_memory_manager->read_memory(device_handle, module_ptr, headers, sizeof(headers))) {
    return 0;
  }

  std::uint32_t section_size = 0;
  auto section =
      find_section(section_name, reinterpret_cast<std::uintptr_t>(headers), &section_size);

  if (!section || !section_size) {
    return 0;
  }

  if (size) {
    *size = section_size;
  }

  return section - reinterpret_cast<std::uintptr_t>(headers) + module_ptr;
}

auto utils_t::find_pattern_in_section_at_kernel(HANDLE device_handle, const char* section_name,
                                                std::uintptr_t module_ptr,
                                                const std::uint8_t* pattern, const char* mask)
    -> std::uintptr_t {
  std::uint32_t section_size = 0;
  auto section = find_section_at_kernel(device_handle, section_name, module_ptr, &section_size);

  if (!section || !section_size) {
    return 0;
  }

  return find_pattern_at_kernel(device_handle, section, section_size, pattern, mask);
}

auto utils_t::resolve_relative_address(HANDLE device_handle, void* instruction,
                                       std::uint32_t offset_offset, std::uint32_t instruction_size)
    -> void* {
  auto instr = reinterpret_cast<std::uintptr_t>(instruction);
  std::int32_t rip_offset = 0;

  if (!g_memory_manager->read_memory(device_handle, instr + offset_offset, &rip_offset,
                                     sizeof(std::int32_t))) {
    return nullptr;
  }

  auto resolved_addr = reinterpret_cast<void*>(instr + instruction_size + rip_offset);
  return resolved_addr;
}
auto utils_t::compare_memory(const std::uint8_t* data, const std::uint8_t* pattern,
                             const char* mask) -> bool {
  for (; *mask; ++mask, ++data, ++pattern) {
    if (*mask == 'x' && *data != *pattern) {
      return false;
    }
  }
  return *mask == '\0';
}

auto utils_t::get_current_process_id() -> std::uint32_t {
  return GetCurrentProcessId();
}

auto utils_t::get_current_thread_id() -> std::uint32_t {
  return GetCurrentThreadId();
}

auto utils_t::get_error_as_string(DWORD error_message_id) -> std::string {
  LPSTR message_buffer = nullptr;
  auto size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, error_message_id, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                             (LPSTR)&message_buffer, 0, NULL);
  std::string message(message_buffer, size);
  LocalFree(message_buffer);
  return message;
}

auto utils_t::get_current_user_sid() -> std::unique_ptr<void, decltype(&free)> {
  HANDLE h_token = NULL;
  DWORD dw_token_length = 0;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h_token)) {
    return {nullptr, free};
  }

  // Get required buffer size
  GetTokenInformation(h_token, TokenUser, NULL, 0, &dw_token_length);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    CloseHandle(h_token);
    return {nullptr, free};
  }

  // Allocate buffer and get token info
  auto p_token_user = std::make_unique<char[]>(dw_token_length);
  auto token_user = reinterpret_cast<PTOKEN_USER>(p_token_user.get());

  if (!GetTokenInformation(h_token, TokenUser, token_user, dw_token_length, &dw_token_length)) {
    CloseHandle(h_token);
    return {nullptr, free};
  }

  // Copy the SID
  auto sid_length = GetLengthSid(token_user->User.Sid);
  auto p_sid = std::unique_ptr<void, decltype(&free)>(std::malloc(sid_length), free);

  if (p_sid && CopySid(sid_length, p_sid.get(), token_user->User.Sid)) {
    CloseHandle(h_token);
    return p_sid;
  }

  CloseHandle(h_token);
  return {nullptr, free};
}

auto utils_t::get_policy_handle(WCHAR* system_name) -> LSA_HANDLE {
  LSA_OBJECT_ATTRIBUTES object_attributes;
  LSA_UNICODE_STRING lus_system_name;
  LSA_HANDLE lsah_policy_handle;

  ZeroMemory(&object_attributes, sizeof(object_attributes));

  PLSA_UNICODE_STRING p_system_name = nullptr;
  if (system_name) {
    auto system_name_length = static_cast<USHORT>(wcslen(system_name));
    lus_system_name.Buffer = system_name;
    lus_system_name.Length = system_name_length * sizeof(WCHAR);
    lus_system_name.MaximumLength = (system_name_length + 1) * sizeof(WCHAR);
    p_system_name = &lus_system_name;
  }

  auto nts_result =
      LsaOpenPolicy(p_system_name, &object_attributes, POLICY_ALL_ACCESS, &lsah_policy_handle);

  if (nts_result != STATUS_SUCCESS) {
    return NULL;
  }

  return lsah_policy_handle;
}

auto utils_t::init_lsa_string(PVOID p_lsa_string, LPCWSTR pwsz_string) -> bool {
  auto p_lsa_unicode_string = static_cast<PLSA_UNICODE_STRING>(p_lsa_string);

  DWORD dw_len = 0;
  if (!p_lsa_unicode_string) {
    return false;
  }

  if (pwsz_string) {
    dw_len = static_cast<DWORD>(wcslen(pwsz_string));
    if (dw_len > 0x7ffe) {
      return false;
    }
  }

  p_lsa_unicode_string->Buffer = const_cast<WCHAR*>(pwsz_string);
  p_lsa_unicode_string->Length = static_cast<USHORT>(dw_len * sizeof(WCHAR));
  p_lsa_unicode_string->MaximumLength = static_cast<USHORT>((dw_len + 1) * sizeof(WCHAR));

  return true;
}

auto utils_t::check_privilege_exists(PSID account_sid, LSA_HANDLE policy_handle) -> bool {
  LSA_UNICODE_STRING* user_rights = nullptr;
  ULONG count_of_rights = 0;

  auto nts_result =
      LsaEnumerateAccountRights(policy_handle, account_sid, &user_rights, &count_of_rights);

  if (nts_result == STATUS_SUCCESS) {
    for (ULONG i = 0; i < count_of_rights; i++) {
      std::wstring privilege_name(user_rights[i].Buffer, user_rights[i].Length / sizeof(WCHAR));
      if (privilege_name == L"SeLockMemoryPrivilege") {
        LsaFreeMemory(user_rights);
        return true;
      }
    }
    LsaFreeMemory(user_rights);
    return false;
  } else if (nts_result == STATUS_OBJECT_NAME_NOT_FOUND) {  // STATUS_OBJECT_NAME_NOT_FOUND
    return false;
  } else {
    return false;
  }
}

auto utils_t::add_privileges_to_account(PSID account_sid, LSA_HANDLE policy_handle) -> void {
  LSA_UNICODE_STRING luc_privilege;

  if (!init_lsa_string(&luc_privilege, L"SeLockMemoryPrivilege")) {
    return;
  }

  auto nts_result = LsaAddAccountRights(policy_handle, account_sid, &luc_privilege, 1);
  // Note: You might want to log the result here for debugging
}

auto utils_t::check_lock_memory_privilege() -> NTSTATUS {
  HANDLE h_token = NULL;
  DWORD token_privileges_size = 0;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h_token)) {
    return STATUS_UNSUCCESSFUL;
  }

  // Get required buffer size
  GetTokenInformation(h_token, TokenPrivileges, NULL, 0, &token_privileges_size);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    CloseHandle(h_token);
    return STATUS_UNSUCCESSFUL;
  }

  auto token_privileges_buffer = std::make_unique<char[]>(token_privileges_size);
  auto token_privileges = reinterpret_cast<PTOKEN_PRIVILEGES>(token_privileges_buffer.get());

  if (!GetTokenInformation(h_token, TokenPrivileges, token_privileges, token_privileges_size,
                           &token_privileges_size)) {
    CloseHandle(h_token);
    return STATUS_UNSUCCESSFUL;
  }

  // Look up SeLockMemoryPrivilege LUID
  LUID lock_memory_luid;
  if (!LookupPrivilegeValueW(NULL, L"SeLockMemoryPrivilege", &lock_memory_luid)) {
    CloseHandle(h_token);
    return STATUS_UNSUCCESSFUL;
  }

  // Check if the privilege exists in token
  for (DWORD i = 0; i < token_privileges->PrivilegeCount; i++) {
    if (token_privileges->Privileges[i].Luid.LowPart == lock_memory_luid.LowPart &&
        token_privileges->Privileges[i].Luid.HighPart == lock_memory_luid.HighPart) {
      auto attributes = token_privileges->Privileges[i].Attributes;

      if (attributes & SE_PRIVILEGE_ENABLED) {
        CloseHandle(h_token);
        return STATUS_SUCCESS;
      } else {
        CloseHandle(h_token);
        return STATUS_UNSUCCESSFUL;
      }
    }
  }

  CloseHandle(h_token);
  return STATUS_UNSUCCESSFUL;
}

auto utils_t::add_lock_memory_privilege() -> NTSTATUS {
  // get current user's SID
  auto current_user_sid = get_current_user_sid();
  if (!current_user_sid) {
    return STATUS_UNSUCCESSFUL;
  }

  // get policy handle
  auto policy_handle = get_policy_handle();
  if (!policy_handle) {
    return STATUS_UNSUCCESSFUL;
  }

  // check if privilege already exists
  if (check_privilege_exists(static_cast<PSID>(current_user_sid.get()), policy_handle)) {
    LsaClose(policy_handle);
    return STATUS_SUCCESS;
  }

  // add the privilege
  add_privileges_to_account(static_cast<PSID>(current_user_sid.get()), policy_handle);

  // cleanup
  LsaClose(policy_handle);

  return STATUS_SUCCESS;
}

auto utils_t::ensure_lock_memory_privilege() -> NTSTATUS {
  // check if the privilege is already enabled in the current process
  auto status = check_lock_memory_privilege();
  if (NT_SUCCESS(status)) {
    return STATUS_SUCCESS;
  }

  // if not enabled, try to add it to the user account
  status = add_lock_memory_privilege();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  return STATUS_SUCCESS;
}

auto utils_t::enable_privilege(const std::wstring& privilege_name) -> bool {
  HANDLE token_handle = nullptr;
  if (!NT_SUCCESS(NtOpenProcessToken(NtCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                     &token_handle))) {
    return false;
  }

  LUID privilege_luid = {};
  if (!LookupPrivilegeValueW(nullptr, privilege_name.c_str(), &privilege_luid)) {
    NtClose(token_handle);
    return false;
  }

  TOKEN_PRIVILEGES token_privileges = {};
  token_privileges.PrivilegeCount = 1;
  token_privileges.Privileges[0].Luid = privilege_luid;
  token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  auto result = NT_SUCCESS(NtAdjustPrivilegesToken(token_handle, FALSE, &token_privileges,
                                                   sizeof(TOKEN_PRIVILEGES), nullptr, nullptr));

  NtClose(token_handle);
  return result;
}

auto utils_t::initialize_dependencies() -> bool {
  // enable necessary privileges
  if (!enable_privilege(L"SeDebugPrivilege")) {
    return false;
  }

  if (!enable_privilege(L"SeLoadDriverPrivilege")) {
    return false;
  }

  if (!enable_privilege(L"SeLockMemoryPrivilege")) {
    return false;
  }

  return true;
}

auto utils_t::get_kernel_module_export(HANDLE device_handle, std::uint64_t kernel_module_base,
                                       const std::string& function_name) -> std::uint64_t {
  if (!kernel_module_base)
    return 0;

  IMAGE_DOS_HEADER dos_header = {0};
  IMAGE_NT_HEADERS64 nt_headers = {0};

  if (!g_memory_manager->read_memory(device_handle, kernel_module_base, &dos_header,
                                     sizeof(dos_header)) ||
      dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
      !g_memory_manager->read_memory(device_handle, kernel_module_base + dos_header.e_lfanew,
                                     &nt_headers, sizeof(nt_headers)) ||
      nt_headers.Signature != IMAGE_NT_SIGNATURE)
    return 0;

  const auto export_base =
      nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  const auto export_base_size =
      nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

  if (!export_base || !export_base_size)
    return 0;

  PIMAGE_EXPORT_DIRECTORY export_data = nullptr;
  SIZE_T export_data_size = export_base_size;
  auto status =
      NtAllocateVirtualMemory(NtCurrentProcess, reinterpret_cast<void**>(&export_data), 0,
                              &export_data_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  if (!NT_SUCCESS(status) || !export_data)
    return 0;

  if (!g_memory_manager->read_memory(device_handle, kernel_module_base + export_base, export_data,
                                     export_base_size)) {
    SIZE_T free_size = 0;
    NtFreeVirtualMemory(NtCurrentProcess, reinterpret_cast<void**>(&export_data), &free_size,
                        MEM_RELEASE);
    return 0;
  }

  const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

  const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
  const auto ordinal_table =
      reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
  const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

  for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
    const std::string current_function_name =
        std::string(reinterpret_cast<char*>(name_table[i] + delta));

    if (!stricmp(current_function_name.c_str(), function_name.c_str())) {
      const auto function_ordinal = ordinal_table[i];
      if (function_table[function_ordinal] <= 0x1000) {
        // wrong function address?
        SIZE_T free_size = 0;
        NtFreeVirtualMemory(NtCurrentProcess, reinterpret_cast<void**>(&export_data), &free_size,
                            MEM_RELEASE);
        return 0;
      }
      const auto function_address = kernel_module_base + function_table[function_ordinal];

      if (function_address >= kernel_module_base + export_base &&
          function_address <= kernel_module_base + export_base + export_base_size) {
        SIZE_T free_size = 0;
        NtFreeVirtualMemory(NtCurrentProcess, reinterpret_cast<void**>(&export_data), &free_size,
                            MEM_RELEASE);
        return 0;
      }

      SIZE_T free_size = 0;
      NtFreeVirtualMemory(NtCurrentProcess, reinterpret_cast<void**>(&export_data), &free_size,
                          MEM_RELEASE);
      return function_address;
    }
  }

  SIZE_T free_size = 0;
  NtFreeVirtualMemory(NtCurrentProcess, reinterpret_cast<void**>(&export_data), &free_size,
                      MEM_RELEASE);
  return 0;
}

// helper function to find a section in kernel module
auto utils_t::find_kernel_section(HANDLE device_handle, const char* section_name,
                                  std::uint64_t module_base, std::uint32_t* section_size)
    -> std::uint64_t {
  // read DOS header
  IMAGE_DOS_HEADER dos_header{};
  if (!g_memory_manager->read_memory(device_handle, module_base, &dos_header, sizeof(dos_header))) {
    return 0;
  }

  if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
    return 0;
  }

  // read NT headers
  IMAGE_NT_HEADERS64 nt_headers{};
  auto nt_headers_addr = module_base + dos_header.e_lfanew;
  if (!g_memory_manager->read_memory(device_handle, nt_headers_addr, &nt_headers,
                                     sizeof(nt_headers))) {
    return 0;
  }

  if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
    return 0;
  }

  // iterate through sections
  auto section_header_addr = nt_headers_addr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                             nt_headers.FileHeader.SizeOfOptionalHeader;

  for (auto i = 0; i < nt_headers.FileHeader.NumberOfSections; ++i) {
    IMAGE_SECTION_HEADER section{};
    auto current_section_addr = section_header_addr + (i * sizeof(IMAGE_SECTION_HEADER));

    if (!g_memory_manager->read_memory(device_handle, current_section_addr, &section,
                                       sizeof(section))) {
      continue;
    }

    // compare section name
    if (std::memcmp(section.Name, section_name, std::strlen(section_name)) == 0) {
      *section_size = section.Misc.VirtualSize;
      return module_base + section.VirtualAddress;
    }
  }

  return 0;
}

// helper function to find unused space in a memory region
auto utils_t::find_unused_space(HANDLE device_handle, std::uint64_t start_addr,
                                std::uint32_t region_size, std::uint32_t required_size,
                                std::uint32_t alignment) -> std::uint64_t {
  // ensure alignment is at least PAGE_SIZE
  if (alignment < PAGE_SIZE) {
    alignment = PAGE_SIZE;
  }

  // buffer to read chunks of memory
  const auto chunk_size = 0x1000;  // 4KB chunks
  auto buffer = std::make_unique<std::uint8_t[]>(chunk_size);

  // scan the region for unused space
  for (auto current_addr = start_addr; current_addr + required_size <= start_addr + region_size;
       current_addr += alignment) {
    bool found_unused = true;

    // check if the required size is all zeros (unused)
    for (auto offset = 0u; offset < required_size; offset += chunk_size) {
      auto read_size = min(chunk_size, required_size - offset);

      if (!g_memory_manager->read_memory(device_handle, current_addr + offset, buffer.get(),
                                         read_size)) {
        found_unused = false;
        break;
      }

      // check if all bytes are zero
      for (auto i = 0u; i < read_size; ++i) {
        if (buffer[i] != 0) {
          found_unused = false;
          break;
        }
      }

      if (!found_unused)
        break;
    }

    if (found_unused) {
      return current_addr;
    }
  }

  return 0;
}
