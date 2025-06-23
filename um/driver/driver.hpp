#include <Windows.h>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

class driver_t {
public:
  driver_t() = default;
  ~driver_t() = default;

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

  [[nodiscard]] inline auto initialize() -> bool {
    auto ntdll = shadowcall<HMODULE>("LoadLibraryA", "ntdll.dll");
    if (!ntdll) {
      return false;
    }

    NtConvertBetweenAuxiliaryCounterAndPerformanceCounter =
        reinterpret_cast<NtConvertBetweenAuxiliaryCounterAndPerformanceCounter_t>(
            shadowcall<FARPROC>("GetProcAddress", ntdll,
                                "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter"));
    return NtConvertBetweenAuxiliaryCounterAndPerformanceCounter != nullptr;
  }

  [[nodiscard]] inline auto unload() -> bool {
    unload_request data{};
    bool buffer = false;
    data.buffer = &buffer;

    const auto result = send_driver_request(&data, request_codes::unload);
    return result && buffer;
  }

  inline [[nodiscard]] auto get_module_base(std::uint32_t pid, const std::wstring& module_name)
      -> std::uintptr_t {
    base_request data{};
    data.pid = pid;
    data.handle = 0;
    std::copy(module_name.begin(), module_name.end(), data.name.begin());

    send_driver_request(&data, request_codes::base);
    return data.handle;
  }

  [[nodiscard]] inline auto find_signature(std::uint32_t pid, const std::wstring& mod_name,
                                           const std::string& signature) -> std::uintptr_t {
    pattern_request data{};
    data.pid = pid;
    data.address = 0;
    std::copy(mod_name.begin(), mod_name.end(), data.mod_name.begin());
    std::copy(signature.begin(), signature.end(), data.signature.begin());

    send_driver_request(&data, request_codes::pattern);
    return data.address;
  }

  inline auto read_virtual_memory(std::uint32_t pid, std::uintptr_t address, void* buffer,
                                  std::size_t size) -> bool {
    read_request data{pid, address, buffer, size};
    return send_driver_request(&data, request_codes::read);
  }

  template <typename T>
  inline T read_virtual_memory(std::uint32_t pid, std::uintptr_t address) {
    T response{};
    read_virtual_memory(pid, address, &response, sizeof(T));
    return response;
  }

  inline auto write_virtual_memory(std::uint32_t pid, std::uintptr_t address, const void* buffer,
                                   std::size_t size) -> bool {
    write_request data{pid, address, const_cast<void*>(buffer), size};
    return send_driver_request(&data, request_codes::write);
  }

  template <typename T>
  inline auto write_virtual_memory(std::uint32_t pid, std::uintptr_t address, const T& value)
      -> bool {
    return write_virtual_memory(pid, address, &value, sizeof(T));
  }

  [[nodiscard]] inline auto allocate_independent_pages(std::uint32_t local_pid,
                                                       std::uint32_t target_pid,
                                                       std::uint32_t target_tid, std::size_t size,
                                                       bool use_large_pages,
                                                       std::uint32_t alloc_mode) -> void* {
    allocate_independent_pages_request data{local_pid, target_pid,      target_tid, nullptr,
                                            size,      use_large_pages, alloc_mode};
    send_driver_request(&data, request_codes::allocate_independent_pages);
    return data.address;
  }

  [[nodiscard]] inline auto execute_dll_via_thread(std::uint32_t local_pid,
                                                   std::uint32_t target_pid,
                                                   std::uint32_t target_tid, void* address,
                                                   unsigned int entry_point,
                                                   std::uint32_t alloc_mode) -> bool {
    execute_dll_via_thread_request data{local_pid, target_pid,  target_tid,
                                        address,   entry_point, alloc_mode};
    send_driver_request(&data, request_codes::execute_dll_entrypoint);
    return data.success;
  }

  inline auto swap_context_to_hyperspace(std::uint32_t target_tid) -> bool {
    swap_context_request data{target_tid};
    return send_driver_request(&data, request_codes::swap_context);
  }

  inline auto restore_context(std::uint32_t target_tid) -> bool {
    swap_context_request data{target_tid};
    return send_driver_request(&data, request_codes::restore_context);
  }

private:
  using NtConvertBetweenAuxiliaryCounterAndPerformanceCounter_t = NTSTATUS(__fastcall*)(uintptr_t,
                                                                                        void*,
                                                                                        void*,
                                                                                        void*);
  NtConvertBetweenAuxiliaryCounterAndPerformanceCounter_t
      NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = nullptr;

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
    restore_context = 0x104
  };

  struct unload_request {
    bool* buffer;
  };

  struct read_request {
    std::uint32_t pid;
    std::uintptr_t address;
    void* buffer;
    std::size_t size;
  };

  struct write_request {
    std::uint32_t pid;
    std::uintptr_t address;
    void* buffer;
    std::size_t size;
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
    bool use_large_page;
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

  inline bool send_driver_request(void* data, request_codes code) {
    if (!data || code == request_codes::success || code == request_codes::unique) {
      return false;
    }

    request_data request{static_cast<std::uint32_t>(request_codes::unique), code, data};

    LARGE_INTEGER auxiliary_counter = {0};
    LARGE_INTEGER perf_counter = {0};

    auxiliary_counter.QuadPart = reinterpret_cast<std::int64_t>(&request);

    auto result = shadowcall<NTSTATUS>("NtConvertBetweenAuxiliaryCounterAndPerformanceCounter", 1,
                                       &auxiliary_counter, &perf_counter, nullptr);

    return perf_counter.QuadPart == static_cast<std::int64_t>(request_codes::success);
  }
};

inline std::unique_ptr<driver_t> driver = std::make_unique<driver_t>();