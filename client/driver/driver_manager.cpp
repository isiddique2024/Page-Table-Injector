#include "driver_manager.hpp"

auto driver_manager_t::initialize() -> bool {
  auto ntdll = LoadLibraryA("ntdll.dll");
  if (!ntdll) {
    return false;
  }

  syscall = reinterpret_cast<syscall_t>(
      GetProcAddress(ntdll, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter"));
  return syscall != nullptr;
}

auto driver_manager_t::unload() -> bool {
  unload_request data{};
  bool buffer = false;
  data.success = &buffer;

  send_driver_request(&data, request_codes::unload);

  return buffer;
}

auto driver_manager_t::get_module_base(std::uint32_t pid, const std::wstring& module_name)
    -> std::uintptr_t {
  base_request data{};
  data.pid = pid;
  data.handle = 0;
  std::copy(module_name.begin(), module_name.end(), data.name.begin());

  send_driver_request(&data, request_codes::base);
  return data.handle;
}

auto driver_manager_t::find_signature(std::uint32_t pid, const std::wstring& mod_name,
                                      const std::string& signature) -> std::uintptr_t {
  pattern_request data{};
  data.pid = pid;
  data.address = 0;
  std::copy(mod_name.begin(), mod_name.end(), data.mod_name.begin());
  std::copy(signature.begin(), signature.end(), data.signature.begin());

  send_driver_request(&data, request_codes::pattern);
  return data.address;
}

auto driver_manager_t::read_virtual_memory(std::uint32_t pid, std::uintptr_t address, void* buffer,
                                           std::size_t size) -> bool {
  read_request data{pid, address, buffer, size};
  send_driver_request(&data, request_codes::read);
  return data.success;
}

auto driver_manager_t::write_virtual_memory(std::uint32_t pid, std::uintptr_t address,
                                            const void* buffer, std::size_t size) -> bool {
  write_request data{pid, address, const_cast<void*>(buffer), size};
  send_driver_request(&data, request_codes::write);
  return data.success;
}

auto driver_manager_t::allocate_independent_pages(std::uint32_t local_pid, std::uint32_t target_pid,
                                                  std::uint32_t target_tid, std::size_t size,
                                                  bool use_large_pages, std::uint32_t alloc_mode)
    -> void* {
  allocate_independent_pages_request data{local_pid, target_pid,      target_tid, nullptr,
                                          size,      use_large_pages, alloc_mode};
  send_driver_request(&data, request_codes::allocate_independent_pages);
  return data.address;
}

auto driver_manager_t::execute_dll_via_thread(std::uint32_t local_pid, std::uint32_t target_pid,
                                              std::uint32_t target_tid, void* address,
                                              unsigned int entry_point, std::uint32_t alloc_mode)
    -> bool {
  execute_dll_via_thread_request data{local_pid, target_pid,  target_tid,
                                      address,   entry_point, alloc_mode};
  send_driver_request(&data, request_codes::execute_dll_entrypoint);
  return data.success;
}

auto driver_manager_t::execute_dll_via_thread_hijack(std::uint32_t local_pid,
                                                     std::uint32_t target_pid,
                                                     std::uint32_t target_tid, void* address,
                                                     unsigned int entry_point,
                                                     std::uint32_t alloc_mode) -> bool {
  execute_dll_via_thread_request data{local_pid, target_pid,  target_tid,
                                      address,   entry_point, alloc_mode};
  send_driver_request(&data, request_codes::thread_hijack);
  return data.success;
}

auto driver_manager_t::swap_context_to_hyperspace(std::uint32_t target_tid) -> bool {
  swap_context_request data{target_tid};
  send_driver_request(&data, request_codes::swap_context);
  return data.success;
}

auto driver_manager_t::restore_context(std::uint32_t target_tid) -> bool {
  swap_context_request data{target_tid};
  send_driver_request(&data, request_codes::restore_context);
  return data.success;
}

bool driver_manager_t::send_driver_request(void* data, request_codes code) {
  if (!data || code == request_codes::success || code == request_codes::unique) {
    return false;
  }

  request_data request{static_cast<std::uint32_t>(request_codes::unique), code, data};

  LARGE_INTEGER auxiliary_counter = {0};
  LARGE_INTEGER perf_counter = {0};

  auxiliary_counter.QuadPart = reinterpret_cast<std::int64_t>(&request);

  const auto result = syscall(1, &auxiliary_counter, &perf_counter, nullptr);

  return (result >= 0) &&
         perf_counter.QuadPart == static_cast<std::int64_t>(request_codes::success);
}

// global driver instance
std::unique_ptr<driver_manager_t> g_driver_manager = std::make_unique<driver_manager_t>();