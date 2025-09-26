#pragma once

#include <Windows.h>
#include <tchar.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <functional>

class window_manager_t {
public:
  window_manager_t();

  std::optional<HWND> find_window(const std::wstring& target_class_name);

  bool get_process_and_thread_id(HWND window, unsigned long& process_id, std::uint32_t& thread_id);

  bool initialize_and_find_window(std::wstring window_name, unsigned long& process_id,
                                  std::uint32_t& thread_id);

private:
  bool nt_enum_windows(WNDENUMPROC lp_enum_func, LPARAM l_param);

  std::wstring remove_zero_width_space(const std::wstring& str);

  bool contains_zero_width_space(const std::wstring& str);
};

extern std::unique_ptr<window_manager_t> g_window_manager;