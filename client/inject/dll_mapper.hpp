#pragma once

#include <Windows.h>
#include <lmcons.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "driver/driver_manager.hpp"

class dll_mapper_t {
public:
  enum class execution_method {
    IAT_HOOK,
    SET_WINDOWS_HOOK,
    THREAD,
  };

public:
  void set_iat_hook_params(const char* hook_mod, const char* hook_func, const wchar_t* main_module);

  const char* get_method_name(execution_method method);

  void set_execution_method(execution_method method);

  execution_method get_execution_method() const;

  [[nodiscard]] auto run(const std::uint32_t pid, const std::uint32_t tid, void* buffer,
                         uintptr_t offsets, driver_manager_t::memory_type memory_type,
                         driver_manager_t::alloc_mode alloc_mode) -> bool;

private:
  typedef struct _execution_context {
    uint32_t state;
    std::uintptr_t target_function;
    HINSTANCE base_address;
  } execution_context, *pexecution_context;

  [[nodiscard]] auto get_nt_headers(const std::uintptr_t image_base) const -> IMAGE_NT_HEADERS*;

  [[nodiscard]] auto rva_va(const std::uintptr_t rva, IMAGE_NT_HEADERS* nt_header,
                            void* local_image) const -> void*;

  [[nodiscard]] auto relocate_image(void* remote_image, void* local_image,
                                    IMAGE_NT_HEADERS* nt_header) const -> bool;

  [[nodiscard]] auto resolve_function_address(const char* module_name,
                                              const char* function_name) const -> std::uintptr_t;

  [[nodiscard]] bool map_sections(std::uint32_t pid, void* module_base, void* local_image,
                                  IMAGE_NT_HEADERS* nt_header) const;

  [[nodiscard]] auto resolve_import(DWORD process_id, DWORD thread_id, void* local_image,
                                    IMAGE_NT_HEADERS* nt_header) const -> bool;

  uintptr_t find_iat_entry(uint32_t pid, uintptr_t module_base, const char* dll_name,
                           const char* function_name);

  bool execute_via_iat_hook(uint32_t pid, uint32_t tid, uintptr_t main_module_base,
                            void* alloc_base, DWORD entry_point,
                            driver_manager_t::alloc_mode alloc_mode);

  bool execute_via_swhk(uint32_t pid, uint32_t tid, void* alloc_base, DWORD entry_point,
                        driver_manager_t::alloc_mode alloc_mode);

  bool execute_via_thread(uint32_t pid, uint32_t tid, void* alloc_base, DWORD entry_point,
                          driver_manager_t::alloc_mode alloc_mode);

  bool execute_via_thread_hijack(uint32_t pid, uint32_t tid, void* alloc_base, DWORD entry_point,
                                 driver_manager_t::alloc_mode alloc_mode);

private:
  const char* hook_module = "user32.dll";
  const char* hook_function = "GetMessageW";
  const wchar_t* target_module = L"";
  execution_method exec_method = execution_method::IAT_HOOK;

  std::uint8_t dll_main_shellcode[92] = {
      // Function prologue - reserve stack space
      0x48, 0x83, 0xEC, 0x38,  // sub rsp, 0x38 (reserve 56 bytes on stack)

      // Load address of data structure (will be patched)
      0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00,  // mov rax, struct_addr (patched at runtime)

      // Save the structure pointer on stack
      0x48, 0x89, 0x44, 0x24, 0x20,  // mov [rsp+0x20], rax

      // Check if already executed (status != 0)
      0x48, 0x8B, 0x44, 0x24, 0x20,  // mov rax, [rsp+0x20]
      0x83, 0x38, 0x00,              // cmp dword ptr [rax], 0
      0x75, 0x39,                    // jne exit (skip if already executed)

      // Set status to 1 (executing)
      0x48, 0x8B, 0x44, 0x24, 0x20,        // mov rax, [rsp+0x20]
      0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,  // mov dword ptr [rax], 1

      // Get DLL entry point address from structure
      0x48, 0x8B, 0x44, 0x24, 0x20,  // mov rax, [rsp+0x20]
      0x48, 0x8B, 0x40, 0x08,        // mov rax, [rax+8] (fn_dll_main)
      0x48, 0x89, 0x44, 0x24, 0x28,  // mov [rsp+0x28], rax

      // Prepare DllMain parameters (follows x64 calling convention)
      0x45, 0x33, 0xC0,  // xor r8d, r8d (lpReserved = NULL)
      0xBA, 0x01, 0x00, 0x00,
      0x00,  // mov edx, 1 (fdwReason = DLL_PROCESS_ATTACH)

      // Load DLL base address from structure (first parameter)
      0x48, 0x8B, 0x44, 0x24, 0x20,  // mov rax, [rsp+0x20]
      0x48, 0x8B, 0x48, 0x10,        // mov rcx, [rax+0x10] (DLL base)

      // Call the DLL entry point function
      0xFF, 0x54, 0x24, 0x28,  // call qword ptr [rsp+0x28]

      // Set status to 2 (completed)
      0x48, 0x8B, 0x44, 0x24, 0x20,        // mov rax, [rsp+0x20]
      0xC7, 0x00, 0x02, 0x00, 0x00, 0x00,  // mov dword ptr [rax], 2

      // Function epilogue and return
      0x48, 0x83, 0xC4, 0x38,  // add rsp, 0x38 (restore stack)
      0xC3,                    // ret (return to caller)

      // Padding/alignment
      0xCC  // int3 (breakpoint, used as padding)
  };

  const unsigned long shell_data_offset = 0x6;
  const uintptr_t total_size = sizeof(dll_main_shellcode) + sizeof(execution_context);
};

inline std::unique_ptr<dll_mapper_t> g_dll_mapper = std::make_unique<dll_mapper_t>();