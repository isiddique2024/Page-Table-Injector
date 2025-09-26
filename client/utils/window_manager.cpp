#include "window_manager.hpp"

window_manager_t::window_manager_t() {}

std::optional<HWND> window_manager_t::find_window(const std::wstring& target_class_name) {
  struct enum_window_data {
    HWND result;
    const std::wstring& target;
    const std::function<std::wstring(const std::wstring&)>& remove_zero_width_space_fn;
    const std::function<bool(const std::wstring&)>& contains_zero_width_space_fn;
  };

  auto remove_zero_width_space_fn = [this](const std::wstring& str) {
    return this->remove_zero_width_space(str);
  };
  auto contains_zero_width_space_fn = [this](const std::wstring& str) {
    return this->contains_zero_width_space(str);
  };

  enum_window_data data = {nullptr, target_class_name, remove_zero_width_space_fn,
                           contains_zero_width_space_fn};

  ::EnumWindows(
      [](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<enum_window_data*>(lParam);
        std::array<wchar_t, 80> class_name{};
        ::GetClassNameW(hwnd, class_name.data(), static_cast<int>(class_name.size()));

        std::array<wchar_t, 256> window_title{};
        ::GetWindowTextW(hwnd, window_title.data(), static_cast<int>(window_title.size()));

        std::wstring processed_name = data->remove_zero_width_space_fn(class_name.data());
        std::wstring title = window_title.data();

        if (processed_name == data->target) {
          data->result = hwnd;
          return FALSE;
        }
        return TRUE;
      },
      reinterpret_cast<LPARAM>(&data));

  return data.result ? std::optional<HWND>{data.result} : std::nullopt;
}

bool window_manager_t::get_process_and_thread_id(HWND window, unsigned long& process_id,
                                                 std::uint32_t& thread_id) {
  thread_id = ::GetWindowThreadProcessId(window, &process_id);
  return true;
}

bool window_manager_t::initialize_and_find_window(std::wstring window_name,
                                                  unsigned long& process_id,
                                                  std::uint32_t& thread_id) {
  std::optional<HWND> main_window;
  while (!(main_window = find_window(window_name))) {
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  if (!get_process_and_thread_id(*main_window, process_id, thread_id)) {
    return false;
  }
  return true;
}

std::wstring window_manager_t::remove_zero_width_space(const std::wstring& str) {
  std::wstring copy = str;
  copy.erase(std::remove(copy.begin(), copy.end(), L'\u200B'), copy.end());
  return copy;
}

bool window_manager_t::contains_zero_width_space(const std::wstring& str) {
  return str.find(L'\u200B') != std::wstring::npos;
}

// global window_manager instance
std::unique_ptr<window_manager_t> g_window_manager = std::make_unique<window_manager_t>();