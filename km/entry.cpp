#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include <cstdint>

#include "def/ia32.hpp"
#include "def/def.hpp"
#include "mem/phys.hpp"
#include "mem/scan.hpp"
#include "mem/pte.hpp"
#include "mem/mem.hpp"
#include "mem/detection.hpp"
#include "utils/utils.hpp"
#include "init.hpp"
#include "def/request.hpp"

extern "C" int _fltused = 0;

namespace {
    constexpr auto request_unique = 0x92b;
    class request_handler {
    public:
        static auto handle(PVOID a1, PINT64 status) -> INT64 {
            if (ExGetPreviousMode() != UserMode) {
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
            case request_codes::allocate_independent_pages:
                result = handle_allocate_independent_pages_request(&safe_request);
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

            NTSTATUS status = physical::init();
            if (!NT_SUCCESS(status))
                return 0;

            PEPROCESS target_process;
            if (PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(data.pid), &target_process) != STATUS_SUCCESS) {
                return 0;
            }

            status = physical::copy_memory(
                IoGetCurrentProcess(),
                reinterpret_cast<void*>(data.buffer),
                target_process,
                (void*)data.address,
                data.size
            );

            ObfDereferenceObject(target_process);

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

            NTSTATUS status = physical::init();
            if (!NT_SUCCESS(status))
                return 0;

            PEPROCESS target_process;
            if (PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(data.pid), &target_process) != STATUS_SUCCESS) {
                return 0;
            }

            status = physical::copy_memory(
                target_process,                
                (void*)data.address,           
                IoGetCurrentProcess(),     
                reinterpret_cast<void*>(data.buffer), 
                data.size                     
            );

            ObfDereferenceObject(target_process);

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

        static auto handle_allocate_independent_pages_request(request_data* request) -> std::int64_t {
            log("INFO", "allocate independent pages request called");

            allocate_independent_pages_request data;
            if (!safe_copy(&data, request->data)) {
                return 0;
            }

            void* address = 0;

            switch (data.mode) 
            {
                case ALLOC_INSIDE_MAIN_MODULE:
                    address = mem::hijack_null_pfn(data.local_pid, data.target_pid, data.size, data.use_large_page);
                    break;

                case ALLOC_BETWEEN_LEGIT_MODULES:
                    address = mem::allocate_between_modules(data.local_pid, data.target_pid, data.size, data.use_large_page);
                    break;

                case ALLOC_AT_LOW_ADDRESS:
                    address = mem::allocate_at_non_present_pml4e(data.local_pid, data.target_pid, data.size, data.use_large_page, false); // low address (usermode space)
                    break;

                case ALLOC_AT_HIGH_ADDRESS:
                    address = mem::allocate_at_non_present_pml4e(data.local_pid, data.target_pid, data.size, data.use_large_page, true); // high address (kernel space)
                    break;

                default:
                    address = mem::allocate_between_modules(data.local_pid, data.target_pid, data.size, data.use_large_page);
                    break;
            }

            if (!address) {
                return 0;
            }

            detections::inspect_process_page_tables(data.target_pid);

            reinterpret_cast<allocate_independent_pages_request*>(request->data)->address = address;
            return static_cast<std::int64_t>(request_codes::success);
        }

        static auto handle_unload_request(request_data* request) -> std::int64_t {
            log("INFO", "unload/unhook .data ptr request called");

            *reinterpret_cast<unload_request*>(request->data)->buffer = true;

            *reinterpret_cast<std::uintptr_t*>(globals::hook_address) = globals::hook_pointer;

            pte::spoof_pte_range(reinterpret_cast<uintptr_t>(globals::shell_address), globals::SHELL_SIZE, true);

            memset(globals::shell_address, 0, globals::SHELL_SIZE);

            return static_cast<std::int64_t>(request_codes::success);
        }

    };

} 

auto entry(const uintptr_t address, const uintptr_t size, pdb_offsets* offsets) -> NTSTATUS
{
    pdb_offsets local_offsets = { 0 };
    if (!mem::safe_copy(&local_offsets, offsets, sizeof(pdb_offsets))) 
    {
        log("ERROR", "failed to copy offsets struct");
        return STATUS_UNSUCCESSFUL;
    }

    auto status_offsets = init::scan_offsets(local_offsets);
    if (!NT_SUCCESS(status_offsets)) 
    {
        log("INFO", "driver entry fail, failed to init global variables");
        return status_offsets;
    }

    auto status_hide = init::hide_driver_pages(address, size);
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