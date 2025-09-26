#include "def/globals.hpp"
#include "utils/raii.hpp"
#include "utils/intrin.hpp"
#include "mem/validation.hpp"
#include "mem/phys.hpp"
#include "mem/page_table.hpp"

#include "mem/scan.hpp"
#include "mem/mem.hpp"
#include "mem/detection.hpp"
#include "utils/utils.hpp"
#include "mem/pt_hook.hpp"
#include "mem/hyperspace.hpp"
#include "init.hpp"
#include "def/request.hpp"

extern "C" void _fltused() {}

namespace {
  constexpr auto request_unique = 0x92b;

  class request_handler {
  public:
    /**
     * @brief Main request dispatcher that validates and routes incoming requests
     * @param a1 Pointer to user-mode request data
     * @param status Pointer to status output parameter
     * @return Result code indicating success or failure
     *
     * Entry point for all user-mode communications. Validates request
     * authenticity, performs safety checks, and dispatches to appropriate handler
     * functions. Only processes requests from user-mode with proper unique
     * identifier.
     */
    static auto handle(void* a1, std::int64_t* status) -> std::int64_t {
      auto current_thread = KeGetCurrentThread();
      char previous_mode =
          *reinterpret_cast<char*>(reinterpret_cast<std::uintptr_t>(current_thread) + 0x232);

      if (previous_mode != UserMode) {
        return reinterpret_cast<decltype(&request_handler::handle)>(globals::hook_pointer)(a1,
                                                                                           status);
      }

      if (!a1 || !mem::probe_user_address(a1, sizeof(request_data), sizeof(unsigned long)) ||
          !mem::safe_copy(&safe_request, a1, sizeof(request_data)) ||
          safe_request.unique != request_unique) {
        return reinterpret_cast<decltype(&request_handler::handle)>(globals::hook_pointer)(a1,
                                                                                           status);
      }

      std::int64_t result = 0;
      switch (safe_request.code) {
        case request_codes::base:
          result = handle_base_request(&safe_request);
          break;
        case request_codes::write:
          result = handle_write_request(&safe_request);
          break;
        case request_codes::read:
          result = handle_read_request(&safe_request);
          break;
        case request_codes::pattern:
          result = handle_pattern_request(&safe_request);
          break;
        case request_codes::swap_context:
          result = handle_swap_context_request(&safe_request);
          break;
        case request_codes::restore_context:
          result = handle_restore_context_request(&safe_request);
          break;
        case request_codes::allocate_independent_pages:
          result = handle_allocate_independent_pages_request(&safe_request);
          break;
        case request_codes::execute_dll_entrypoint:
          result = handle_execute_dll_via_thread_request(&safe_request);
          break;
        case request_codes::unload:
          result = handle_unload_request(&safe_request);
          break;
        default:
          if (status) {
            *status = STATUS_NOT_IMPLEMENTED;
          }
          result = 0;
          break;
      }

      return result;
    }

  private:
    static inline request_data safe_request{};

    /**
     * @brief Template function for safe copying from user-mode memory
     * @tparam T Type of structure to copy
     * @param dest Destination buffer in kernel space
     * @param src Source buffer in user space
     * @return true if copy succeeded, false otherwise
     *
     * Type-safe wrapper around mem::safe_copy that automatically determines
     * the size based on the template parameter.
     */
    template <typename T>
    static auto safe_copy(T* dest, void* src) -> bool {
      return mem::safe_copy(dest, src, sizeof(T));
    }

    /**
     * @brief Handle module base address lookup requests
     * @param request Pointer to validated request data
     * @return Request result code
     *
     * Looks up the base address of a specified module in a target process
     * and returns it to the caller through the request structure.
     */
    static auto handle_base_request(request_data* request) -> std::int64_t {
      log("INFO", "base request called");

      base_request data;
      if (!safe_copy(&data, request->data)) {
        return 0;
      }

      if (!data.pid) {
        return 0;
      }

      const auto base = utils::get_module_base(data.pid, data.name);
      if (!base) {
        return 0;
      }

      reinterpret_cast<base_request*>(request->data)->handle = base;
      return static_cast<std::int64_t>(request_codes::success);
    }

    /**
     * @brief Handle memory write requests to target processes
     * @param request Pointer to validated request data
     * @return Request result code
     *
     * Performs memory writes to target processes, automatically using hyperspace
     * context if available, otherwise falling back to standard process access.
     */
    static auto handle_write_request(request_data* request) -> std::int64_t {
      write_request data;
      if (!safe_copy(&data, request->data)) {
        return 0;
      }

      if (!data.address || !data.pid || !data.buffer || !data.size) {
        return 0;
      }

      PEPROCESS target_process = nullptr;
      if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(data.pid),
                                                   &target_process) != STATUS_SUCCESS) {
        return 0;
      }

      raii::kernel_object_ref<_KPROCESS> target_ref(target_process);

      NTSTATUS status = STATUS_SUCCESS;
      if (globals::ctx.initialized) {
        status = physical::copy_memory(
            globals::io_get_current_process(), reinterpret_cast<void*>(data.buffer),
            globals::ctx.clone_peproc, reinterpret_cast<void*>(data.address), data.size);
      } else {
        status = physical::copy_memory(globals::io_get_current_process(),
                                       reinterpret_cast<void*>(data.buffer), target_process,
                                       reinterpret_cast<void*>(data.address), data.size);
      }

      if (!NT_SUCCESS(status)) {
        return 0;
      }

      reinterpret_cast<write_request*>(request->data)->success = true;

      return static_cast<std::int64_t>(request_codes::success);
    }

    /**
     * @brief Handle memory read requests from target processes
     * @param request Pointer to validated request data
     * @return Request result code
     *
     * Performs memory reads from target processes, automatically using hyperspace
     * context if available, otherwise falling back to standard process access.
     */
    static auto handle_read_request(request_data* request) -> std::int64_t {
      read_request data;
      if (!safe_copy(&data, request->data)) {
        return 0;
      }

      if (!data.address || !data.pid || !data.buffer || !data.size) {
        return 0;
      }

      PEPROCESS target_process = nullptr;
      if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(data.pid),
                                                   &target_process) != STATUS_SUCCESS) {
        return 0;
      }

      raii::kernel_object_ref<_KPROCESS> target_ref(target_process);

      NTSTATUS status = STATUS_SUCCESS;
      if (globals::ctx.initialized) {
        status = physical::copy_memory(
            globals::ctx.clone_peproc, reinterpret_cast<void*>(data.address),
            globals::io_get_current_process(), reinterpret_cast<void*>(data.buffer), data.size);
      } else {
        status = physical::copy_memory(target_process, reinterpret_cast<void*>(data.address),
                                       globals::io_get_current_process(),
                                       reinterpret_cast<void*>(data.buffer), data.size);
      }

      if (!NT_SUCCESS(status)) {
        return 0;
      }

      reinterpret_cast<read_request*>(request->data)->success = true;

      return static_cast<std::int64_t>(request_codes::success);
    }

    /**
     * @brief Handle DLL execution via remote thread creation
     * @param request Pointer to validated request data
     * @return Request result code
     *
     * Creates and executes a remote thread that calls a DLL's entry point with
     * proper parameters. Supports both normal and hyperspace execution contexts
     * with automatic shellcode injection and cleanup.
     */
    static auto handle_execute_dll_via_thread_request(request_data* request) -> std::int64_t {
      log("INFO", "execute dll via thread request called");

      execute_dll_via_thread_request data;
      if (!safe_copy(&data, request->data)) {
        return 0;
      }

      if (!data.alloc_base || !data.entry_point || !data.target_pid) {
        log("ERROR", "invalid parameters for DLL execution");
        return 0;
      }

      std::uint8_t dll_main_shellcode[50] = {
          0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBA, 0x01,
          0x00, 0x00, 0x00, 0x45, 0x33, 0xC0, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3};

      const unsigned long dll_base_offset = 0x6;
      const unsigned long entry_point_offset = 0x10;

      // use RAII for kernel buffer
      raii::kernel_memory kernel_shellcode(PAGE_SIZE);
      if (!kernel_shellcode.is_valid()) {
        log("ERROR", "failed to allocate kernel buffer for shellcode");
        return 0;
      }

      globals::memcpy(kernel_shellcode.get(), dll_main_shellcode, sizeof(dll_main_shellcode));

      *(std::uintptr_t*)((std::uintptr_t)kernel_shellcode.get() + dll_base_offset) =
          (std::uintptr_t)data.alloc_base;
      *(std::uintptr_t*)((std::uintptr_t)kernel_shellcode.get() + entry_point_offset) =
          (std::uintptr_t)data.alloc_base + data.entry_point;

      void* remote_shellcode = allocate_memory_by_mode(data.local_pid, data.target_pid, PAGE_SIZE,
                                                       false, data.alloc_mode);
      if (!remote_shellcode) {
        log("ERROR", "failed to allocate remote shellcode");
        return 0;
      }

      // get target process with RAII
      PEPROCESS target_process = nullptr;
      if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(data.target_pid),
                                                   &target_process) != STATUS_SUCCESS) {
        log("ERROR", "failed to get target process");
        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(remote_shellcode),
                                           PAGE_SIZE);
        return 0;
      }

      raii::kernel_object_ref<_KPROCESS> target_ref(target_process);

      NTSTATUS write_status = STATUS_SUCCESS;
      if (globals::ctx.initialized) {
        write_status = physical::copy_memory(globals::io_get_current_process(),
                                             kernel_shellcode.get(), globals::ctx.clone_peproc,
                                             remote_shellcode, sizeof(dll_main_shellcode));
      } else {
        write_status =
            physical::copy_memory(globals::io_get_current_process(), kernel_shellcode.get(),
                                  target_process, remote_shellcode, sizeof(dll_main_shellcode));
      }

      if (!NT_SUCCESS(write_status)) {
        log("ERROR", "failed to write shellcode to target process");
        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(remote_shellcode),
                                           PAGE_SIZE);
        return 0;
      }

      // use RAII for handles
      raii::kernel_handle process_handle;
      OBJECT_ATTRIBUTES obj_attr = {0};
      CLIENT_ID process_client_id = {0};
      process_client_id.UniqueProcess = reinterpret_cast<HANDLE>(data.target_pid);

      InitializeObjectAttributes(&obj_attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

      NTSTATUS open_status = globals::zw_open_process(
          process_handle.address_of(), PROCESS_ALL_ACCESS, &obj_attr, &process_client_id);

      if (!NT_SUCCESS(open_status)) {
        log("ERROR", "failed to open target process: 0x%X", open_status);
        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(remote_shellcode),
                                           PAGE_SIZE);
        return 0;
      }

      raii::kernel_handle thread_handle;
      CLIENT_ID thread_client_id = {0};

      NTSTATUS thread_status = globals::rtl_create_user_thread(
          process_handle.get(), NULL, TRUE, 0, 0, 0, remote_shellcode, NULL,
          thread_handle.address_of(), &thread_client_id);

      if (!NT_SUCCESS(thread_status)) {
        log("ERROR", "RtlCreateUserThread failed with status: 0x%X", thread_status);
        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(remote_shellcode),
                                           PAGE_SIZE);
        return 0;
      }

      PETHREAD thread = nullptr;
      NTSTATUS thread_lookup_status =
          globals::ps_lookup_thread_by_thread_id(thread_client_id.UniqueThread, &thread);
      if (!NT_SUCCESS(thread_lookup_status)) {
        log("ERROR", "PsLookupThreadByThreadId failed with status: 0x%X", thread_lookup_status);
        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(remote_shellcode),
                                           PAGE_SIZE);
        return 0;
      }

      raii::kernel_object_ref<_KTHREAD> thread_ref(thread);

      if (globals::ctx.initialized) {
        NTSTATUS swap_context = hyperspace::switch_thread_context_to_hyperspace(
            (uint32_t)thread_client_id.UniqueThread, &globals::ctx);
        if (!NT_SUCCESS(swap_context)) {
          log("ERROR", "hyperspace::switch_thread_context_to_hyperspace failed: 0x%X",
              swap_context);
          return 0;
        }
      }

      unsigned long previous_suspend_count = 0;
      NTSTATUS resume_thread_status = globals::ps_resume_thread(thread, &previous_suspend_count);
      if (!NT_SUCCESS(resume_thread_status)) {
        log("ERROR", "PsResumeThread failed with status: 0x%X", resume_thread_status);
        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(remote_shellcode),
                                           PAGE_SIZE);
        return 0;
      }

      if (thread_handle.is_valid()) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -150000000LL;

        NTSTATUS wait_status =
            globals::zw_wait_for_single_object(thread_handle.get(), FALSE, &timeout);
        if (wait_status == STATUS_TIMEOUT) {
          log("WARNING", "thread execution timed out after 15 seconds");
        } else if (NT_SUCCESS(wait_status)) {
          log("INFO", "thread completed successfully");
        } else {
          log("ERROR", "wait failed with status: 0x%X", wait_status);
        }
      }

      // clear shellcode
      std::uint8_t zero_buffer[sizeof(dll_main_shellcode)] = {0};
      if (globals::ctx.initialized) {
        physical::copy_memory(globals::io_get_current_process(), zero_buffer,
                              globals::ctx.clone_peproc, remote_shellcode,
                              sizeof(dll_main_shellcode));
      } else {
        PEPROCESS cleanup_process = nullptr;
        if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(data.target_pid),
                                                     &cleanup_process) == STATUS_SUCCESS) {
          raii::kernel_object_ref<_KPROCESS> cleanup_ref(cleanup_process);
          physical::copy_memory(globals::io_get_current_process(), zero_buffer, cleanup_process,
                                remote_shellcode, sizeof(dll_main_shellcode));
        }
      }

      log("INFO", "DLL execution completed for PID: %d at address: 0x%p", data.target_pid,
          data.alloc_base);

      reinterpret_cast<execute_dll_via_thread_request*>(request->data)->success = true;
      return static_cast<std::int64_t>(request_codes::success);
    }

    /**
     * @brief Handle pattern scanning requests in target process modules
     * @param request Pointer to validated request data
     * @return Request result code
     *
     * Scans for byte patterns within specified modules of target processes
     * and returns the first matching address.
     */
    static auto handle_pattern_request(request_data* request) -> std::int64_t {
      log("INFO", "pattern request called");

      pattern_request data;
      if (!safe_copy(&data, request->data)) {
        return 0;
      }

      std::uintptr_t r_address = 0;
      NTSTATUS status =
          scan::find_pattern_usermode(data.pid, data.mod_name, data.signature, r_address);

      if (!NT_SUCCESS(status) || !r_address) {
        return 0;
      }

      reinterpret_cast<pattern_request*>(request->data)->address = r_address;
      return static_cast<std::int64_t>(request_codes::success);
    }

    /**
     * @brief Allocate memory using the specified allocation strategy
     * @param local_pid Current process ID
     * @param target_pid Target process ID for allocation
     * @param size Size of memory to allocate
     * @param use_large_page Whether to use 2MB large pages
     * @param alloc_mode Allocation strategy mode
     * @return Pointer to allocated memory, or nullptr on failure
     *
     * Router function that selects the appropriate allocation method based on
     * the specified mode (hyperspace, between modules, high/low address, etc.).
     */
    static auto allocate_memory_by_mode(uint32_t local_pid, uint32_t target_pid, size_t size,
                                        bool use_large_page, uint32_t alloc_mode) -> void* {
      switch (alloc_mode) {
        case ALLOC_INSIDE_MAIN_MODULE:
          return mem::hijack_null_pfn(local_pid, target_pid, size, use_large_page);
        case ALLOC_BETWEEN_LEGIT_MODULES:
          return mem::allocate_between_modules(local_pid, target_pid, size, use_large_page);
        case ALLOC_AT_LOW_ADDRESS:
          return mem::allocate_at_non_present_pml4e(local_pid, target_pid, size, use_large_page,
                                                    false);
        case ALLOC_AT_HIGH_ADDRESS:
          return mem::allocate_at_non_present_pml4e(local_pid, target_pid, size, use_large_page,
                                                    true);
        case ALLOC_AT_HYPERSPACE:
          return hyperspace::allocate_in_hyperspace(target_pid, size, use_large_page);
        default:
          return mem::allocate_between_modules(local_pid, target_pid, size, use_large_page);
      }
    }

    /**
     * @brief Handle stealth memory allocation requests
     * @param request Pointer to validated request data
     * @return Request result code
     *
     * Allocates memory using various stealth techniques. Automatically
     * initializes hyperspace context if hyperspace allocation is requested and
     * not yet initialized.
     */
    static auto handle_allocate_independent_pages_request(request_data* request) -> std::int64_t {
      log("INFO", "allocate independent pages request called");

      allocate_independent_pages_request data;
      if (!safe_copy(&data, request->data)) {
        return 0;
      }

      void* address = nullptr;

      // handle hyperspace initialization if needed
      if (data.mode == ALLOC_AT_HYPERSPACE && !globals::ctx.initialized) {
        NTSTATUS hyperspace_context_status =
            hyperspace::initialize_hyperspace_context(data.target_pid, &globals::ctx);
        if (!NT_SUCCESS(hyperspace_context_status)) {
          log("INFO", "failed to init hyperspace context");
          return 0;
        }

        NTSTATUS install_status = hyperspace::callbacks::install_process_callback();
        if (!NT_SUCCESS(install_status)) {
          log("ERROR", "failed to install process callback in ntoskrnl");
          hyperspace::cleanup_hyperspace_context(&globals::ctx);
          return 0;
        }

        NTSTATUS create_contextualized_ntoskrnl_status =
            hyperspace::create_contextualized_ntoskrnl();
        if (!NT_SUCCESS(create_contextualized_ntoskrnl_status)) {
          log("INFO", "create contextualized ntoskrnl failed");

          hyperspace::cleanup_hyperspace_context(&globals::ctx);

          if (hyperspace::callbacks::g_process_callback_handle) {
            globals::ps_set_create_process_notify_routine_ex(
                reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(
                    hyperspace::callbacks::g_callback_shellcode_address),
                TRUE);
            hyperspace::callbacks::g_process_callback_handle = nullptr;
            hyperspace::callbacks::g_callback_shellcode_address = nullptr;
          }

          return 0;
        }
      }

      address = allocate_memory_by_mode(data.local_pid, data.target_pid, data.size,
                                        data.use_large_page, data.mode);

      if (!address) {
        return 0;
      }

      if (data.mode == ALLOC_AT_HYPERSPACE) {
        log("INFO", "hyperspace allocation completed at address: 0x%p", address);
      }

      reinterpret_cast<allocate_independent_pages_request*>(request->data)->address = address;
      return static_cast<std::int64_t>(request_codes::success);
    }

    /**
     * @brief Handle thread context switching to hyperspace
     * @param request Pointer to validated request data
     * @return Request result code
     *
     * Switches a target thread's execution context to hyperspace, allowing it
     * to access hyperspace-allocated memory and execute within the isolated
     * environment.
     */
    static auto handle_swap_context_request(request_data* request) -> std::int64_t {
      log("INFO", "swap context request called");

      swap_context_request data;
      if (!safe_copy(&data, request->data)) {
        return 0;
      }

      if (!globals::ctx.initialized) {
        return 0;
      }

      NTSTATUS switch_context_status =
          hyperspace::switch_thread_context_to_hyperspace(data.target_tid, &globals::ctx);
      if (!NT_SUCCESS(switch_context_status)) {
        return 0;
      }

      reinterpret_cast<swap_context_request*>(request->data)->success = true;

      return static_cast<std::int64_t>(request_codes::success);
    }

    /**
     * @brief Handle thread context restoration from hyperspace
     * @param request Pointer to validated request data
     * @return Request result code
     *
     * Restores a thread's execution context from hyperspace back to the original
     * process context, returning it to normal execution environment.
     */
    static auto handle_restore_context_request(request_data* request) -> std::int64_t {
      log("INFO", "restore context request called");

      swap_context_request data;
      if (!safe_copy(&data, request->data)) {
        return 0;
      }

      if (!globals::ctx.initialized) {
        return 0;
      }

      NTSTATUS restore_context_status =
          hyperspace::switch_from_hyperspace(data.target_tid, &globals::ctx);
      if (!NT_SUCCESS(restore_context_status)) {
        return 0;
      }

      reinterpret_cast<swap_context_request*>(request->data)->success = true;
      return static_cast<std::int64_t>(request_codes::success);
    }

    /**
     * @brief Handle driver unload and cleanup requests
     * @param request Pointer to validated request data
     * @return Request result code
     *
     * Performs driver cleanup by restoring original hook pointers, clearing
     * shellcode, and setting appropriate page protections for safe unloading.
     */
    static auto handle_unload_request(request_data* request) -> std::int64_t {
      log("INFO", "unload/unhook .data ptr request called");

      unload_request data;
      if (!safe_copy(&data, request->data)) {
        return 0;
      }

      if (!data.success || !globals::hook_address || !globals::shell_address) {
        log("ERROR", "invalid unload request parameters");
        return 0;
      }

      *data.success = true;

      // restore original hook
      *reinterpret_cast<std::uintptr_t*>(globals::hook_address) = globals::hook_pointer;

      // clear and unprotect shellcode
      page_table::spoof_pte_range(reinterpret_cast<uintptr_t>(globals::shell_address),
                                  globals::SHELL_SIZE_FJ, true);

      globals::memset(globals::shell_address, 0, globals::SHELL_SIZE_FJ);

      return static_cast<std::int64_t>(request_codes::success);
    }
  };

}  // namespace

/**
 * @brief Main driver entry point and initialization function
 * @param io_get_current_process_addr Address of IoGetCurrentProcess function
 * @param mm_copy_virtual_memory_addr Address of MmCopyVirtualMemory function
 * @param offsets Pointer to PDB offset structure from loader
 * @return NTSTATUS indicating initialization success or failure
 *
 * Initializes the driver by copying PDB offsets, scanning for required system
 * functions, hiding driver pages from detection, and installing the main
 * communication hook. Called by the driver loader with resolved function
 * addresses and offset information.
 */
auto entry(uintptr_t io_get_current_process_addr, uintptr_t mm_copy_virtual_memory_addr,
           pdb_offsets* offsets) -> NTSTATUS {
  if (!io_get_current_process_addr || !mm_copy_virtual_memory_addr || !offsets) {
    return STATUS_INVALID_PARAMETER;
  }

  auto io_get_current_process =
      reinterpret_cast<function_types::io_get_current_process_t>(io_get_current_process_addr);
  auto mm_copy_virtual_memory =
      reinterpret_cast<function_types::mm_copy_virtual_memory_t>(mm_copy_virtual_memory_addr);

  if (!io_get_current_process || !mm_copy_virtual_memory) {
    return STATUS_INVALID_PARAMETER;
  }

  pdb_offsets local_offsets = {0};
  size_t bytes = 0;
  const auto current_process = io_get_current_process();

  if (!current_process) {
    return STATUS_UNSUCCESSFUL;
  }

  NTSTATUS copy_status =
      mm_copy_virtual_memory(current_process, offsets, current_process, &local_offsets,
                             sizeof(pdb_offsets), KernelMode, &bytes);

  if (!NT_SUCCESS(copy_status) || bytes != sizeof(pdb_offsets)) {
    log("ERROR", "failed to copy PDB offsets: 0x%X", copy_status);
    return STATUS_UNSUCCESSFUL;
  }

  auto status_offsets = init::scan_offsets(local_offsets);
  if (!NT_SUCCESS(status_offsets)) {
    log("ERROR", "driver entry fail, failed to init global variables: 0x%X", status_offsets);
    return status_offsets;
  }

  auto status_hide = init::hide_driver_pages(globals::driver_alloc_base, globals::driver_size);
  if (!NT_SUCCESS(status_hide)) {
    log("ERROR", "driver entry fail, failed to hide driver pages: 0x%X", status_hide);
    return status_hide;
  }

  auto status_hook = init::install_hook(&request_handler::handle);
  if (!NT_SUCCESS(status_hook)) {
    log("ERROR", "driver entry fail, failed to install hook: 0x%X", status_hook);
    return status_hook;
  }

  log("INFO", "driver initialized successfully");
  return STATUS_SUCCESS;
}