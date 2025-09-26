#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <random>
#include <memory>

#define DISABLE_DEBUG_PRINT_MAPPER 0
#if DISABLE_DEBUG_PRINT_MAPPER
  #define mapper_log(level, format, ...) ((void)0)
#else
  #define mapper_log(level, format, ...)                                  \
    do {                                                                  \
      const char* prefix;                                                 \
      if (strcmp(level, "SUCCESS") == 0)                                  \
        prefix = "[+]";                                                   \
      else if (strcmp(level, "ERROR") == 0)                               \
        prefix = "[!]";                                                   \
      else if (strcmp(level, "WARNING") == 0)                             \
        prefix = "[-]";                                                   \
      else                                                                \
        prefix = "[?]";                                                   \
      printf("%s %s: " format "\n", prefix, __FUNCTION__, ##__VA_ARGS__); \
    } while (0)
#endif

// system information classes
typedef enum _SYSTEM_INFORMATION_CLASS {
  SystemModuleInformation = 11,
  SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS;

// status definitions
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

// forward declarations for external NT functions
extern "C" {
NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                  PVOID SystemInformation, ULONG SystemInformationLength,
                                  PULONG ReturnLength);
NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                 PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                             ULONG FreeType);
NTSTATUS NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
                                 PTOKEN_PRIVILEGES NewState, ULONG BufferLength,
                                 PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);
NTSTATUS NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
NTSTATUS NtClose(HANDLE Handle);
}

#define NtCurrentProcess ((HANDLE)(LONG_PTR)-1)

class utils_t {
public:
  utils_t() = default;
  ~utils_t() = default;

  // file operations
  auto write_memory_to_file(const std::wstring& file_path, const void* data, std::size_t size)
      -> bool;
  auto create_file_from_memory(const std::wstring& desired_file_path, const char* address,
                               std::size_t size) -> bool;

  auto read_file(const std::string& file_path) -> std::vector<uint8_t>;

  // path operations
  auto get_temp_path() -> std::wstring;

  // kernel module operations
  auto get_kernel_module_address(const std::string& module_name) -> std::uint64_t;
  auto get_kernel_module_export(HANDLE device_handle, std::uint64_t kernel_module_base,
                                const std::string& function_name) -> std::uint64_t;

  // pattern scanning
  auto find_pattern(std::uintptr_t address, std::uintptr_t length, const std::uint8_t* pattern,
                    const char* mask) -> std::uintptr_t;

  auto find_pattern_at_kernel(HANDLE device_handle, std::uintptr_t address, std::uintptr_t length,
                              const std::uint8_t* pattern, const char* mask) -> std::uintptr_t;
  auto find_section_at_kernel(HANDLE device_handle, const char* section_name,
                              std::uintptr_t module_ptr, std::uint32_t* size = nullptr)
      -> std::uintptr_t;
  auto find_pattern_in_section_at_kernel(HANDLE device_handle, const char* section_name,
                                         std::uintptr_t module_ptr, const std::uint8_t* pattern,
                                         const char* mask) -> std::uintptr_t;
  auto find_section(const char* section_name, std::uintptr_t module_ptr,
                    std::uint32_t* size = nullptr) -> std::uintptr_t;

  auto find_unused_space(HANDLE device_handle, std::uint64_t start_addr, std::uint32_t region_size,
                         std::uint32_t required_size, std::uint32_t alignment) -> std::uint64_t;
  auto find_kernel_section(HANDLE device_handle, const char* section_name,
                           std::uint64_t module_base, std::uint32_t* section_size) -> std::uint64_t;
  auto resolve_relative_address(HANDLE device_handle, void* instruction,
                                std::uint32_t offset_offset, std::uint32_t instruction_size)
      -> void*;
  auto compare_memory(const std::uint8_t* data, const std::uint8_t* pattern, const char* mask)
      -> bool;

  // process operations
  auto get_current_process_id() -> std::uint32_t;
  auto get_current_thread_id() -> std::uint32_t;
  auto enable_privilege(const std::wstring& privilege_name) -> bool;

  auto check_lock_memory_privilege() -> NTSTATUS;
  auto ensure_lock_memory_privilege() -> NTSTATUS;
  auto add_lock_memory_privilege() -> NTSTATUS;

  // initialization
  auto initialize_dependencies() -> bool;

private:
  // system module enumeration structures
  struct rtl_process_module_information_t {
    HANDLE section;
    void* mapped_base;
    void* image_base;
    std::uint32_t image_size;
    std::uint32_t flags;
    std::uint16_t load_order_index;
    std::uint16_t init_order_index;
    std::uint16_t load_count;
    std::uint16_t offset_to_file_name;
    unsigned char full_path_name[256];
  };

  struct rtl_process_modules_t {
    std::uint32_t number_of_modules;
    rtl_process_module_information_t modules[1];
  };

  auto get_current_user_sid() -> std::unique_ptr<void, decltype(&free)>;
  auto get_policy_handle(WCHAR* system_name = nullptr) -> PVOID;
  auto init_lsa_string(PVOID p_lsa_string, LPCWSTR pwsz_string) -> bool;
  auto check_privilege_exists(PVOID account_sid, PVOID policy_handle) -> bool;
  auto add_privileges_to_account(PVOID account_sid, PVOID policy_handle) -> void;
  auto get_error_as_string(DWORD error_message_id) -> std::string;
};

// global utils instance
inline std::unique_ptr<utils_t> g_utils = std::make_unique<utils_t>();