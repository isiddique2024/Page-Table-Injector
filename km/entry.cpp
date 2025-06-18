#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include <cstdint>
#include <stdlib.h>

#include "def/ia32.hpp"
#include "def/def.hpp"
#include "mem/page_table.hpp"
#include "mem/phys.hpp"
#include "mem/scan.hpp"
#include "mem/mem.hpp"
#include "mem/detection.hpp"
#include "utils/utils.hpp"
#include "mem/pt_hook.hpp"
#include "mem/hyperspace.hpp"
#include "init.hpp"
#include "def/request.hpp"

namespace {
    constexpr auto request_unique = 0x92b;
    class request_handler {
    public:
        static auto handle(PVOID a1, PINT64 status) -> INT64 {
            if (globals::ex_get_previous_mode() != UserMode) {
                return reinterpret_cast<decltype(&request_handler::handle)>(globals::hook_pointer)(a1, status);
            }

            if (!a1 || !mem::probe_user_address(a1, sizeof(request_data), sizeof(DWORD)) ||
                !mem::safe_copy(&safe_request, a1, sizeof(request_data)) ||
                safe_request.unique != request_unique) {
                return reinterpret_cast<decltype(&request_handler::handle)>(globals::hook_pointer)(a1, status);
            }

            INT64 result = 0;
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

        template<typename T>
        static auto safe_copy(T* dest, void* src) -> bool {
            return mem::safe_copy(dest, src, sizeof(T));
        }
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

        static auto handle_write_request(request_data* request) -> std::int64_t {
            write_request data;
            if (!safe_copy(&data, request->data)) {
                return 0;
            }

            if (!data.address || !data.pid || !data.buffer || !data.size) {
                return 0;
            }

            PEPROCESS target_process;
            if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(data.pid), &target_process) != STATUS_SUCCESS) {
                return 0;
            }

            NTSTATUS status = STATUS_SUCCESS;

            if (globals::ctx.initialized) {

                status = physical::copy_memory(
                    globals::io_get_current_process(),
                    reinterpret_cast<void*>(data.buffer),
                    globals::ctx.clone_peproc,
                    (void*)data.address,
                    data.size
                );

            }
            else {
                status = physical::copy_memory(
                    globals::io_get_current_process(),
                    reinterpret_cast<void*>(data.buffer),
                    target_process,
                    (void*)data.address,
                    data.size
                );

                globals::obf_dereference_object(target_process);
            }

            if (!NT_SUCCESS(status)) {
                return 0;
            }

            return static_cast<std::int64_t>(request_codes::success);
        }

        static auto handle_read_request(request_data* request) -> std::int64_t {
            read_request data;
            if (!safe_copy(&data, request->data)) {
                return 0;
            }
            if (!data.address || !data.pid || !data.buffer || !data.size) {
                return 0;
            }

            PEPROCESS target_process;
            if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(data.pid), &target_process) != STATUS_SUCCESS) {
                return 0;
            }

            NTSTATUS status = STATUS_SUCCESS;

            if (globals::ctx.initialized) {
                status = physical::copy_memory(
                    globals::ctx.clone_peproc,
                    (void*)data.address,
                    globals::io_get_current_process(),
                    reinterpret_cast<void*>(data.buffer),
                    data.size
                );
            }
            else {
                status = physical::copy_memory(
                    target_process,
                    (void*)data.address,
                    globals::io_get_current_process(),
                    reinterpret_cast<void*>(data.buffer),
                    data.size
                );
            }

            globals::obf_dereference_object(target_process);

            if (!NT_SUCCESS(status)) {
                return 0;
            }

            return static_cast<std::int64_t>(request_codes::success);
        }

        static auto handle_pattern_request(request_data* request) -> std::int64_t {
            log("INFO", "pattern request called");

            pattern_request data;
            if (!safe_copy(&data, request->data)) {
                return 0;
            }

            std::uintptr_t r_address = 0;
            NTSTATUS status = scan::find_pattern_usermode(data.pid, data.mod_name, data.signature, r_address);

            if (!NT_SUCCESS(status) || !r_address) {
                return 0;
            }

            reinterpret_cast<pattern_request*>(request->data)->address = r_address;
            return static_cast<std::int64_t>(request_codes::success);
        }

        static auto allocate_memory_by_mode(uint32_t local_pid, uint32_t target_pid, size_t size,
            bool use_large_page, uint32_t alloc_mode) -> void* {
            switch (alloc_mode) {
            case ALLOC_INSIDE_MAIN_MODULE:
                return mem::hijack_null_pfn(local_pid, target_pid, size, use_large_page);
            case ALLOC_BETWEEN_LEGIT_MODULES:
                return mem::allocate_between_modules(local_pid, target_pid, size, use_large_page);
            case ALLOC_AT_LOW_ADDRESS:
                return mem::allocate_at_non_present_pml4e(local_pid, target_pid, size, use_large_page, false);
            case ALLOC_AT_HIGH_ADDRESS:
                return mem::allocate_at_non_present_pml4e(local_pid, target_pid, size, use_large_page, true);
            case ALLOC_AT_HYPERSPACE:
                return hyperspace::allocate_in_hyperspace(target_pid, size, use_large_page);
            default:
                return mem::allocate_between_modules(local_pid, target_pid, size, use_large_page);
            }
        }


        static auto handle_allocate_independent_pages_request(request_data* request) -> std::int64_t {
            log("INFO", "allocate independent pages request called");

            allocate_independent_pages_request data;
            if (!safe_copy(&data, request->data)) {
                return 0;
            }

            void* address = nullptr;

            // handle hyperspace initialization
            if (data.mode == ALLOC_AT_HYPERSPACE && !globals::ctx.initialized) {
                NTSTATUS hyperspace_context_status = hyperspace::initialize_hyperspace_context(data.target_pid, &globals::ctx);
                if (!NT_SUCCESS(hyperspace_context_status)) {
                    log("INFO", "failed to init hyperspace context");
                    return 0;
                }

                NTSTATUS install_status = hyperspace::callbacks::install_process_callback();
                if (!NT_SUCCESS(install_status)) {
                    log("ERROR", "failed to install process callback in ntoskrnl");
                    return 0;
                }

                NTSTATUS create_contextualized_ntoskrnl_status = hyperspace::create_contextualized_ntoskrnl();
                if (!NT_SUCCESS(create_contextualized_ntoskrnl_status)) {
                    log("INFO", "create contextualized ntoskrnl failed");
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


        static auto handle_swap_context_request(request_data* request) -> std::int64_t {
            log("INFO", "swap context request called");

            swap_context_request data;
            if (!safe_copy(&data, request->data)) {
                return 0;
            }

            if (!globals::ctx.initialized)
                return 0;

            NTSTATUS switch_context_status = hyperspace::switch_thread_context_to_hyperspace(data.target_tid, &globals::ctx);
            if (!NT_SUCCESS(switch_context_status)) {
                return 0;
            }

            return static_cast<std::int64_t>(request_codes::success);
        }

        static auto handle_restore_context_request(request_data* request) -> std::int64_t {
            log("INFO", "swap context request called");

            swap_context_request data;
            if (!safe_copy(&data, request->data)) {
                return 0;
            }

            if (!globals::ctx.initialized)
                return 0;

            NTSTATUS restore_context_status = hyperspace::switch_from_hyperspace(data.target_tid, &globals::ctx);
            if (!NT_SUCCESS(restore_context_status)) {
                return 0;
            }

            return static_cast<std::int64_t>(request_codes::success);
        }
        static auto handle_execute_dll_via_thread_request(request_data* request) -> std::int64_t {
            log("INFO", "execute dll via thread request called");

            execute_dll_via_thread_request data;
            if (!safe_copy(&data, request->data)) {
                return 0;
            }

            // validate input parameters
            if (!data.alloc_base || !data.entry_point || !data.target_pid) {
                log("ERROR", "Invalid parameters for DLL execution");
                return 0;
            }

            // shellcode that calls DLL main
            std::uint8_t dll_main_shellcode[50] = {
                // Function prologue
                0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28 (allocate shadow space)

                // Load DLL base address 
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rcx, dll_base

                // Load DLL entry point 
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, entry_point

                // Set up DllMain parameters
                0xBA, 0x01, 0x00, 0x00, 0x00,             // mov edx, 1 (DLL_PROCESS_ATTACH)
                0x45, 0x33, 0xC0,                         // xor r8d, r8d (lpReserved = NULL)

                // Call DllMain
                0xFF, 0xD0,                               // call rax

                // Function epilogue
                0x48, 0x83, 0xC4, 0x28,                   // add rsp, 0x28
                0xC3                                      // ret
            };

            const unsigned long dll_base_offset = 0x6;
            const unsigned long entry_point_offset = 0x10;

            // alloc memory for shellcode in kernel (temp buffer)
            void* kernel_shellcode = mem::allocate_independent_pages(PAGE_SIZE);
            if (!kernel_shellcode) {
                log("ERROR", "failed to allocate kernel buffer for shellcode");
                return 0;
            }

            // copy shellcode to kernel buffer
            globals::memcpy(kernel_shellcode, dll_main_shellcode, sizeof(dll_main_shellcode));

            // patch the DLL base address
            *(std::uintptr_t*)((std::uintptr_t)kernel_shellcode + dll_base_offset) = (std::uintptr_t)data.alloc_base;

            // patch the entry point address
            *(std::uintptr_t*)((std::uintptr_t)kernel_shellcode + entry_point_offset) = (std::uintptr_t)data.alloc_base + data.entry_point;

            // alloc shellcode remotely in target process
            void* remote_shellcode = allocate_memory_by_mode(data.local_pid, data.target_pid, PAGE_SIZE, false, data.alloc_mode);

            if (!remote_shellcode) {
                log("ERROR", "failed to allocate remote shellcode");
                globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(kernel_shellcode), PAGE_SIZE);
                return 0;
            }

            // write shellcode to target process
            PEPROCESS target_process;
            if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(data.target_pid), &target_process) != STATUS_SUCCESS) {
                log("ERROR", "failed to get target process");
                globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(kernel_shellcode), PAGE_SIZE);
                return 0;
            }

            NTSTATUS write_status = STATUS_SUCCESS;
            if (globals::ctx.initialized) {
                write_status = physical::copy_memory(
                    globals::io_get_current_process(),
                    kernel_shellcode,
                    globals::ctx.clone_peproc,
                    remote_shellcode,
                    sizeof(dll_main_shellcode)
                );
            }
            else {
                write_status = physical::copy_memory(
                    globals::io_get_current_process(),
                    kernel_shellcode,
                    target_process,
                    remote_shellcode,
                    sizeof(dll_main_shellcode)
                );
            }

            globals::obf_dereference_object(target_process);

            if (!NT_SUCCESS(write_status)) {
                log("ERROR", "failed to write shellcode to target process");
                globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(kernel_shellcode), PAGE_SIZE);
                return 0;
            }

            // open target process for thread creation
            HANDLE process_handle = nullptr;
            OBJECT_ATTRIBUTES obj_attr = { 0 };
            CLIENT_ID process_client_id = { 0 };
            process_client_id.UniqueProcess = reinterpret_cast<HANDLE>(data.target_pid);

            InitializeObjectAttributes(&obj_attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

            NTSTATUS open_status = globals::zw_open_process(
                &process_handle,
                PROCESS_ALL_ACCESS,
                &obj_attr,
                &process_client_id
            );

            if (!NT_SUCCESS(open_status)) {
                log("ERROR", "Failed to open target process: 0x%X", open_status);
                globals::mm_free_independent_pages((uintptr_t)kernel_shellcode, PAGE_SIZE);
                return 0;
            }

            HANDLE thread_handle = nullptr;
            CLIENT_ID thread_client_id = { 0 };

            // create thread using RtlCreateUserThread in target process
            NTSTATUS thread_status = globals::rtl_create_user_thread(
                process_handle,             // Target process handle
                NULL,                       // Security descriptor
                TRUE,                       // Create suspended
                0,                          // Stack zero bits
                0,                          // Stack reserved
                0,                          // Stack commit
                remote_shellcode,           // Start address (kernel_shellcode)
                NULL,                       // Start parameter
                &thread_handle,
                &thread_client_id
            );

            if (!NT_SUCCESS(thread_status)) {
                log("ERROR", "RtlCreateUserThread failed with status: 0x%X", thread_status);
                globals::zw_close(process_handle);
                globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(kernel_shellcode), PAGE_SIZE);
                return 0;
            }

            PETHREAD thread;
            NTSTATUS thread_lookup_status = globals::ps_lookup_thread_by_thread_id(thread_client_id.UniqueThread, &thread);
            if (!NT_SUCCESS(thread_lookup_status)) {
                log("ERROR", "PsLookupThreadByThreadId failed with status: 0x%X", thread_lookup_status);
                globals::zw_close(process_handle);
                globals::zw_close(thread_handle);
                globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(kernel_shellcode), PAGE_SIZE);
                return 0;
            }

            // switch to hyperspace context if needed
            if (globals::ctx.initialized) {
                NTSTATUS swap_context = hyperspace::switch_thread_context_to_hyperspace((uint32_t)thread_client_id.UniqueThread, &globals::ctx);
                if (!NT_SUCCESS(swap_context)) {
                    log("ERROR", "hyperspace::switch_thread_context_to_hyperspace failed with status: 0x%X", swap_context);
                    globals::obf_dereference_object(thread);
                    globals::zw_close(process_handle);
                    globals::zw_close(thread_handle);
                    globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(kernel_shellcode), PAGE_SIZE);
                    return 0;
                }
            }

            // resume the thread
            unsigned long previous_suspend_count = 0;
            NTSTATUS resume_thread_status = globals::ps_resume_thread(thread, &previous_suspend_count);
            if (!NT_SUCCESS(resume_thread_status)) {
                log("ERROR", "PsResumeThread failed with status: 0x%X", resume_thread_status);
                globals::obf_dereference_object(thread);
                globals::zw_close(process_handle);
                globals::zw_close(thread_handle);
                globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(kernel_shellcode), PAGE_SIZE);
                return 0;
            }

            // wait for thread completion (with timeout)
            if (thread_handle) {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -150000000LL; // 15 seconds

                NTSTATUS wait_status = globals::zw_wait_for_single_object(
                    thread_handle,
                    FALSE,
                    &timeout
                );

                if (wait_status == STATUS_TIMEOUT) {
                    log("WARNING", "thread execution timed out after 15 seconds");
                }
                else if (NT_SUCCESS(wait_status)) {
                    log("INFO", "thread completed successfully");
                }
                else {
                    log("ERROR", "wait failed with status: 0x%X", wait_status);
                }
            }

            // clean up
            // zero out the shellcode in remote process
            std::uint8_t zero_buffer[sizeof(dll_main_shellcode)] = { 0 };
            globals::memcpy(kernel_shellcode, zero_buffer, sizeof(dll_main_shellcode));

            if (globals::ctx.initialized) {
                physical::copy_memory(
                    globals::io_get_current_process(),
                    kernel_shellcode,
                    globals::ctx.clone_peproc,
                    remote_shellcode,
                    sizeof(dll_main_shellcode)
                );
            }
            else {
                PEPROCESS cleanup_process;
                if (globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(data.target_pid), &cleanup_process) == STATUS_SUCCESS) {
                    physical::copy_memory(
                        globals::io_get_current_process(),
                        kernel_shellcode,
                        cleanup_process,
                        remote_shellcode,
                        sizeof(dll_main_shellcode)
                    );
                    globals::obf_dereference_object(cleanup_process);
                }
            }

            // close handles and free memory
            globals::obf_dereference_object(thread);
            globals::zw_close(thread_handle);
            globals::zw_close(process_handle);

            // free kernel buffer
            globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(kernel_shellcode), PAGE_SIZE);

            log("INFO", "DLL execution completed for PID: %d at address: 0x%p", data.target_pid, data.alloc_base);

            reinterpret_cast<execute_dll_via_thread_request*>(request->data)->success = true;

            return static_cast<std::int64_t>(request_codes::success);
        }
      
        static auto handle_unload_request(request_data* request) -> std::int64_t {
            log("INFO", "unload/unhook .data ptr request called");

            *reinterpret_cast<unload_request*>(request->data)->buffer = true;

            *reinterpret_cast<std::uintptr_t*>(globals::hook_address) = globals::hook_pointer;

            page_table::spoof_pte_range(reinterpret_cast<uintptr_t>(globals::shell_address), globals::SHELL_SIZE, true);

            globals::memset(globals::shell_address, 0, globals::SHELL_SIZE);

            return static_cast<std::int64_t>(request_codes::success);
        }

    };

} 

auto entry(uintptr_t io_get_current_process_addr, uintptr_t mm_copy_virtual_memory_addr, pdb_offsets* offsets) -> NTSTATUS
{
    if (!io_get_current_process_addr || !mm_copy_virtual_memory_addr || !offsets) {
        return STATUS_NOT_FOUND;
    }

    auto io_get_current_process = reinterpret_cast<function_types::io_get_current_process_t>(io_get_current_process_addr);
    auto mm_copy_virtual_memory = reinterpret_cast<function_types::mm_copy_virtual_memory_t>(mm_copy_virtual_memory_addr);

    pdb_offsets local_offsets = { 0 };
    size_t bytes = 0;
    const auto current_process = io_get_current_process();

    NTSTATUS copy_status = mm_copy_virtual_memory(
        current_process,
        offsets,
        current_process,
        &local_offsets,
        sizeof(pdb_offsets), 
        KernelMode,
        &bytes
    );

    if (!NT_SUCCESS(copy_status)) {
        return STATUS_UNSUCCESSFUL;
    }

    auto status_offsets = init::scan_offsets(local_offsets);
    if (!NT_SUCCESS(status_offsets)) 
    {
        log("INFO", "driver entry fail, failed to init global variables");
        return status_offsets;
    }

    auto status_hide = init::hide_driver_pages(local_offsets.DriverAllocBase, local_offsets.DriverSize);
    if (!NT_SUCCESS(status_hide)) 
    {
        log("INFO", "driver entry fail, failed to hide driver pages");
        return status_hide;
    }

    auto status_hook = init::install_hook(&request_handler::handle);
    if (!NT_SUCCESS(status_hook))
    {
        log("INFO", "driver entry fail, failed to install hook");
        return status_hook;
    }

    return STATUS_SUCCESS;
}