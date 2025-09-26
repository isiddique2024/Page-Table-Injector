#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <iostream>
#include "utils.hpp"
#include "driver_mapper.hpp"

class memory_manager_t {
public:
  memory_manager_t() = default;
  ~memory_manager_t() = default;

  // Basic memory operations
  auto read_memory(HANDLE device_handle, std::uint64_t address, void* buffer, std::uint64_t size)
      -> bool;
  auto write_memory(HANDLE device_handle, std::uint64_t address, void* buffer, std::uint64_t size)
      -> bool;
  auto mem_copy(HANDLE device_handle, std::uint64_t destination, std::uint64_t source,
                std::uint64_t size) -> bool;

  // Physical memory operations
  auto get_physical_address(HANDLE device_handle, std::uint64_t address,
                            std::uint64_t* out_physical_address) -> bool;
  auto map_io_space(HANDLE device_handle, std::uint64_t physical_address, std::uint32_t size)
      -> std::uint64_t;
  auto unmap_io_space(HANDLE device_handle, std::uint64_t address, std::uint32_t size) -> bool;
  auto write_to_read_only_memory(HANDLE device_handle, std::uint64_t address, void* buffer,
                                 std::uint32_t size) -> bool;

  // Page management
  auto allocate_independent_pages(HANDLE device_handle, std::uint32_t size) -> std::uint64_t;
  auto free_independent_pages(HANDLE device_handle, std::uint64_t address, std::uint32_t size)
      -> bool;
  auto set_page_protection(HANDLE device_handle, std::uint64_t address, std::uint32_t size,
                           std::uint32_t new_protect) -> bool;

  // Advanced allocation
  auto allocate_contiguous_memory(HANDLE device_handle, std::size_t size) -> void*;
  auto free_contiguous_memory(HANDLE device_handle, void* virtual_address) -> void;

  auto allocate_kernel_pool(HANDLE device_handle, std::size_t size, ULONG pool_type, ULONG tag)
      -> std::uint64_t;
  auto free_kernel_pool(HANDLE device_handle, std::uint64_t address) -> bool;

  // Kernel function calling
  template <typename T, typename... A>
  auto call_kernel_function(HANDLE device_handle, T* out_result,
                            std::uint64_t kernel_function_address, const A... arguments) -> bool {
    constexpr auto call_void = std::is_same_v<T, void>;
    constexpr auto num_args = sizeof...(A);

    if constexpr (!call_void) {
      if (!out_result) {
        return false;
      }
    }

    if (!kernel_function_address) {
      return false;
    }

    // For more than 4 arguments, we need a different approach
    if constexpr (num_args > 4) {
      // Use a shellcode approach for functions with more than 4 arguments
      return call_kernel_function_shellcode<T, A...>(device_handle, out_result,
                                                     kernel_function_address, arguments...);
    } else {
      // Original implementation for 4 or fewer arguments
      auto nt_add_atom =
          reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAddAtom"));
      if (!nt_add_atom) {
        return false;
      }

      std::uint8_t kernel_injected_jmp[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
      std::uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
      *reinterpret_cast<std::uint64_t*>(&kernel_injected_jmp[2]) = kernel_function_address;

      static std::uint64_t kernel_nt_add_atom = g_utils->get_kernel_module_export(
          device_handle, g_driver_mapper->get_ntoskrnl_base(), "NtAddAtom");
      if (!kernel_nt_add_atom) {
        return false;
      }

      if (!read_memory(device_handle, kernel_nt_add_atom, &original_kernel_function,
                       sizeof(kernel_injected_jmp))) {
        return false;
      }

      // Check if already hooked
      if (original_kernel_function[0] == kernel_injected_jmp[0] &&
          original_kernel_function[1] == kernel_injected_jmp[1]) {
        return false;
      }

      // Overwrite with jump
      if (!write_to_read_only_memory(device_handle, kernel_nt_add_atom, &kernel_injected_jmp,
                                     sizeof(kernel_injected_jmp))) {
        return false;
      }

      // Call function
      if constexpr (!call_void) {
        using function_fn = T(__stdcall*)(A...);
        auto function = reinterpret_cast<function_fn>(nt_add_atom);
        *out_result = function(arguments...);
      } else {
        using function_fn = void(__stdcall*)(A...);
        auto function = reinterpret_cast<function_fn>(nt_add_atom);
        function(arguments...);
      }

      // Restore original
      return write_to_read_only_memory(device_handle, kernel_nt_add_atom, original_kernel_function,
                                       sizeof(kernel_injected_jmp));
    }
  }

  // template <typename T, typename... A>
  // auto call_kernel_function(HANDLE device_handle, T* out_result,
  //                           std::uint64_t kernel_function_address, const A... arguments) -> bool
  //                           {
  //   constexpr auto call_void = std::is_same_v<T, void>;

  //  if constexpr (!call_void) {
  //    if (!out_result) {
  //      return false;
  //    }
  //  }

  //  if (!kernel_function_address) {
  //    return false;
  //  }

  //  // Get NtAddAtom export from ntdll
  //  auto nt_add_atom =
  //      reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAddAtom"));
  //  if (!nt_add_atom) {
  //    return false;
  //  }

  //  std::uint8_t kernel_injected_jmp[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00,
  //                                        0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
  //  std::uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
  //  *reinterpret_cast<std::uint64_t*>(&kernel_injected_jmp[2]) = kernel_function_address;

  //  // TODO: You'll need to implement get_kernel_module_export to find NtAddAtom in kernel
  //  static std::uint64_t kernel_nt_add_atom = g_utils->get_kernel_module_export(
  //      device_handle, g_driver_mapper->get_ntoskrnl_base(), "NtAddAtom");
  //  if (!kernel_nt_add_atom) {
  //    return false;
  //  }

  //  if (!read_memory(device_handle, kernel_nt_add_atom, &original_kernel_function,
  //                   sizeof(kernel_injected_jmp))) {
  //    return false;
  //  }

  //  // Check if already hooked
  //  if (original_kernel_function[0] == kernel_injected_jmp[0] &&
  //      original_kernel_function[1] == kernel_injected_jmp[1]) {
  //    return false;
  //  }

  //  // Overwrite with jump
  //  if (!write_to_read_only_memory(device_handle, kernel_nt_add_atom, &kernel_injected_jmp,
  //                                 sizeof(kernel_injected_jmp))) {
  //    return false;
  //  }

  //  // Call function
  //  if constexpr (!call_void) {
  //    using function_fn = T(__stdcall*)(A...);
  //    auto function = reinterpret_cast<function_fn>(nt_add_atom);
  //    *out_result = function(arguments...);
  //  } else {
  //    using function_fn = void(__stdcall*)(A...);
  //    auto function = reinterpret_cast<function_fn>(nt_add_atom);
  //    function(arguments...);
  //  }

  //  // Restore original
  //  return write_to_read_only_memory(device_handle, kernel_nt_add_atom, original_kernel_function,
  //                                   sizeof(kernel_injected_jmp));
  //}

private:
  // Intel driver communication structures
  struct copy_memory_buffer_info_t {
    std::uint64_t case_number;
    std::uint64_t reserved;
    std::uint64_t source;
    std::uint64_t destination;
    std::uint64_t length;
  };

  struct get_phys_address_buffer_info_t {
    std::uint64_t case_number;
    std::uint64_t reserved;
    std::uint64_t return_physical_address;
    std::uint64_t address_to_translate;
  };

  struct map_io_space_buffer_info_t {
    std::uint64_t case_number;
    std::uint64_t reserved;
    std::uint64_t return_value;
    std::uint64_t return_virtual_address;
    std::uint64_t physical_address_to_map;
    std::uint32_t size;
  };

  struct unmap_io_space_buffer_info_t {
    std::uint64_t case_number;
    std::uint64_t reserved1;
    std::uint64_t reserved2;
    std::uint64_t virt_address;
    std::uint64_t reserved3;
    std::uint32_t number_of_bytes;
  };

  template <typename T>
  std::uint64_t convert_arg_to_uint64(T arg) {
    if constexpr (std::is_pointer_v<T>) {
      return reinterpret_cast<std::uint64_t>(arg);
    } else if constexpr (std::is_integral_v<T>) {
      // For integral types, just cast (this handles proper sign/zero extension)
      return static_cast<std::uint64_t>(arg);
    } else if constexpr (sizeof(T) <= sizeof(std::uint64_t)) {
      // For small structs/types, copy bytes
      std::uint64_t result = 0;
      std::memcpy(&result, &arg, sizeof(T));
      return result;
    } else {
      // For larger types, we'd need to pass by reference
      static_assert(sizeof(T) <= sizeof(std::uint64_t), "Argument type too large");
      return 0;
    }
  }

  template <typename T, typename... A>
  auto call_kernel_function_shellcode(HANDLE device_handle, T* out_result,
                                      std::uint64_t kernel_function_address, const A... arguments)
      -> bool {
    // This approach allocates a structure in kernel memory with all arguments
    // and uses a simple kernel stub that reads the arguments and calls the function

    struct call_context {
      std::uint64_t function_address;
      std::uint64_t result;
      std::uint64_t args[sizeof...(A)];
    };

    // Allocate context in kernel pool
    auto context_addr = allocate_kernel_pool(device_handle, sizeof(call_context), 0, 'llac');
    if (!context_addr) {
      return false;
    }

    // Fill context
    call_context ctx = {};
    ctx.function_address = kernel_function_address;
    size_t idx = 0;
    ((ctx.args[idx++] = convert_arg_to_uint64(arguments)), ...);

    if (!write_memory(device_handle, context_addr, &ctx, sizeof(ctx))) {
      free_kernel_pool(device_handle, context_addr);
      return false;
    }

    // Use a simpler kernel function with fewer parameters that reads from our context
    // This would require a kernel helper function that you'd need to implement

    // Read result
    if constexpr (!std::is_same_v<T, void>) {
      call_context result_ctx = {};
      if (!read_memory(device_handle, context_addr, &result_ctx, sizeof(result_ctx))) {
        free_kernel_pool(device_handle, context_addr);
        return false;
      }
      *out_result = static_cast<T>(result_ctx.result);
    }

    free_kernel_pool(device_handle, context_addr);
    return true;
  }

  // Constants
  static constexpr std::uint32_t ioctl1 = 0x80862007;
};

// Global instance
inline std::unique_ptr<memory_manager_t> g_memory_manager = std::make_unique<memory_manager_t>();