#pragma once

#include <Windows.h>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
class driver_manager_t {
public:
  driver_manager_t() = default;
  ~driver_manager_t() = default;

  enum memory_type {
    NORMAL_PAGE,
    LARGE_PAGE,
    HUGE_PAGE
  };

  enum alloc_mode {
    ALLOC_INSIDE_MAIN_MODULE,
    ALLOC_BETWEEN_LEGIT_MODULES,
    ALLOC_AT_LOW_ADDRESS,
    ALLOC_AT_HIGH_ADDRESS,
    ALLOC_AT_HYPERSPACE
  };

  [[nodiscard]] auto initialize() -> bool;

  [[nodiscard]] auto unload() -> bool;

  [[nodiscard]] auto get_module_base(std::uint32_t pid, const std::wstring& module_name)
      -> std::uintptr_t;

  [[nodiscard]] auto find_signature(std::uint32_t pid, const std::wstring& mod_name,
                                    const std::string& signature) -> std::uintptr_t;

  auto read_virtual_memory(std::uint32_t pid, std::uintptr_t address, void* buffer,
                           std::size_t size) -> bool;

  template <typename T>
  T read_virtual_memory(std::uint32_t pid, std::uintptr_t address) {
    T response{};
    read_virtual_memory(pid, address, &response, sizeof(T));
    return response;
  }

  auto write_virtual_memory(std::uint32_t pid, std::uintptr_t address, const void* buffer,
                            std::size_t size) -> bool;

  template <typename T>
  auto write_virtual_memory(std::uint32_t pid, std::uintptr_t address, const T& value) -> bool {
    return write_virtual_memory(pid, address, &value, sizeof(T));
  }

  [[nodiscard]] auto allocate_independent_pages(std::uint32_t local_pid, std::uint32_t target_pid,
                                                std::uint32_t target_tid, std::size_t size,
                                                memory_type mem_type, std::uint32_t alloc_mode)
      -> void*;

  [[nodiscard]] auto execute_dll_via_thread(std::uint32_t local_pid, std::uint32_t target_pid,
                                            std::uint32_t target_tid, void* address,
                                            unsigned int entry_point, std::uint32_t alloc_mode)
      -> bool;
  [[nodiscard]] auto execute_dll_via_thread_hijack(std::uint32_t local_pid,
                                                   std::uint32_t target_pid,
                                                   std::uint32_t target_tid, void* address,
                                                   unsigned int entry_point,
                                                   std::uint32_t alloc_mode) -> bool;

  auto swap_context_to_hyperspace(std::uint32_t target_tid) -> bool;

  auto restore_context(std::uint32_t target_tid) -> bool;

private:
  using syscall_t = NTSTATUS(__fastcall*)(uintptr_t, void*, void*, void*);
  syscall_t syscall = nullptr;

  enum class request_codes : std::uint32_t {
    base = 0x119,
    read = 0x129,
    write = 0x139,
    allocate = 0x149,
    pattern = 0x179,
    success = 0x91a,
    unique = 0x92b,
    unload = 0x93c,
    allocate_independent_pages = 0x101c,
    execute_dll_entrypoint = 0x102c,
    swap_context = 0x103c,
    restore_context = 0x104,
    thread_hijack = 0x105c,
  };

  struct unload_request {
    bool* success;
  };

  struct read_request {
    std::uint32_t pid;
    std::uintptr_t address;
    void* buffer;
    std::size_t size;
    bool success;
  };

  struct write_request {
    std::uint32_t pid;
    std::uintptr_t address;
    void* buffer;
    std::size_t size;
    bool success;
  };

  struct base_request {
    std::uint32_t pid;
    std::uintptr_t handle;
    std::array<wchar_t, 260> name;
  };

  struct allocate_independent_pages_request {
    std::uint32_t local_pid;
    std::uint32_t target_pid;
    std::uint32_t target_tid;
    void* address;
    std::size_t size;
    memory_type use_large_page;
    std::uint32_t alloc_mode;
  };

  struct execute_dll_via_thread_request {
    std::uint32_t local_pid;
    std::uint32_t target_pid;
    std::uint32_t target_tid;
    void* alloc_base;
    unsigned long entry_point;
    std::uint32_t alloc_mode;
    bool success;
  };

  struct swap_context_request {
    std::uint32_t target_tid;
    bool success;
  };

  struct pattern_request {
    std::int32_t pid;
    std::array<wchar_t, 260> mod_name;
    std::array<char, 260> signature;
    std::uintptr_t address;
  };

  struct request_data {
    std::uint32_t unique;
    request_codes code;
    void* data;
  };

  bool send_driver_request(void* data, request_codes code);
};

extern std::unique_ptr<driver_manager_t> g_driver_manager;