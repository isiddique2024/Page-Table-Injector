#pragma once

#include <Windows.h>
#include <string>
#include <memory>

class service_manager_t {
public:
  service_manager_t() = default;
  ~service_manager_t() = default;

  // drv loading/unloading
  auto load_vulnerable_driver() -> HANDLE;
  auto unload_vulnerable_driver(HANDLE device_handle) -> bool;
  auto is_driver_running() -> bool;

  // service management
  auto register_and_start_service(const std::wstring& driver_path) -> bool;
  auto stop_and_remove_service(const std::wstring& driver_name) -> bool;

  // drv verification
  auto verify_driver_integrity(HANDLE device_handle, std::uint64_t ntoskrnl_addr) -> bool;
  auto check_for_hooks(HANDLE device_handle) -> bool;

  // getters
  auto get_driver_name() const -> const std::string& {
    return driver_name_ + ".sys";
  }
  auto get_driver_name_w() -> std::wstring {
    std::wstring name(driver_name_.begin(), driver_name_.end());
    return name;
  }
  auto get_driver_path() const -> std::wstring;

private:
  // drv resource management
  auto create_driver_file() -> std::wstring;
  auto destroy_driver_file(const std::wstring& driver_path) -> void;
  auto generate_random_driver_name() -> std::string;

  // privilege management
  auto acquire_load_driver_privilege() -> bool;
  auto acquire_debug_privilege() -> bool;

  // device communication
  auto open_device_handle() -> HANDLE;

  // member variables
  std::string driver_name_;

  // vuln driver resource
  static const unsigned char driver_resource_[];
  static const std::size_t driver_resource_size_;

  // consts
  static constexpr std::uint32_t iqvw64e_timestamp = 0x5284EAC3;
};

// global instance
inline std::unique_ptr<service_manager_t> g_service_manager = std::make_unique<service_manager_t>();