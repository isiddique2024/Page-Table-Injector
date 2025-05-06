#pragma once
#include <Windows.h>
#include <tchar.h>
#include <optional>
#include <string>
#include <array>
#include <algorithm>
#include <thread>
#include <chrono>
#include <memory>
#include "../lib/sys.hpp"
#include <winternl.h>

class window_manager_t {
public:
    window_manager_t() {
        shadowcall<HMODULE>("LoadLibraryA", "win32u.dll");
        shadowcall<HMODULE>("LoadLibraryA", "user32.dll");
    }

    std::optional<HWND> find_window(const std::wstring& target_class_name) {
        struct enum_window_data {
            HWND result;
            const std::wstring& target;
            const std::function<std::wstring(const std::wstring&)>& remove_zero_width_space_fn;
            const std::function<bool(const std::wstring&)>& contains_zero_width_space_fn;
        };

        auto remove_zero_width_space_fn = [this](const std::wstring& str) { return this->remove_zero_width_space(str); };
        auto contains_zero_width_space_fn = [this](const std::wstring& str) { return this->contains_zero_width_space(str); };

        enum_window_data data = {
            nullptr,
            target_class_name,
            remove_zero_width_space_fn,
            contains_zero_width_space_fn
        };

        nt_enum_windows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* data = reinterpret_cast<enum_window_data*>(lParam);
            std::array<wchar_t, 80> class_name{};
            shadowcall<int>({ "GetClassNameW", "user32.dll" }, hwnd, class_name.data(), static_cast<int>(class_name.size()));
            std::array<wchar_t, 256> window_title{};
            shadowcall<int>({ "GetWindowTextW", "user32.dll" }, hwnd, window_title.data(), static_cast<int>(window_title.size()));

            std::wstring processed_name = data->remove_zero_width_space_fn(class_name.data());
            std::wstring title = window_title.data();

            if (processed_name == data->target ){
                data->result = hwnd;
                return FALSE;
            }
            return TRUE;
            }, reinterpret_cast<LPARAM>(&data));

        return data.result ? std::optional<HWND>{data.result} : std::nullopt;
    }

    bool get_process_and_thread_id(HWND window, std::uint32_t& process_id, std::uint32_t& thread_id) {
        thread_id = shadowcall<DWORD>({ "GetWindowThreadProcessId", "user32.dll" }, window, &process_id);
        return true;
    }

    bool initialize_and_find_window(std::wstring window_name, std::uint32_t& process_id, std::uint32_t& thread_id) {
        std::optional<HWND> main_window;
        while (!(main_window = find_window(window_name))) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        if (!get_process_and_thread_id(*main_window, process_id, thread_id)) {
            return false;
        }
        return true;
    }

private:
    bool nt_enum_windows(WNDENUMPROC lp_enum_func, LPARAM l_param) {
        constexpr NTSTATUS STATUS_BUFFER_TOO_SMALL = static_cast<NTSTATUS>(0xC0000023);
        const unsigned int initial_hwnd_count = 1024;
        std::vector<HWND> hwnds(initial_hwnd_count);
        unsigned int hwnds_found = 0;
        auto nt_status = shadowcall<NTSTATUS>(
            { "NtUserBuildHwndList", "win32u.dll" },
            nullptr, nullptr, false, false, 0,
            static_cast<unsigned int>(hwnds.size()), hwnds.data(), &hwnds_found
        );
        if (nt_status == STATUS_BUFFER_TOO_SMALL) {
            hwnds.resize(hwnds_found);
            nt_status = shadowcall<NTSTATUS>(
                { "NtUserBuildHwndList", "win32u.dll" },
                nullptr, nullptr, false, false, 0,
                static_cast<unsigned int>(hwnds.size()), hwnds.data(), &hwnds_found
            );
        }
        if (nt_status == STATUS_SUCCESS) {
            for (unsigned int i = 0; i < hwnds_found; ++i) {
                auto hwnd = hwnds[i];
                if (!lp_enum_func(hwnd, l_param)) {
                    return false;
                }
            }
            return true;
        }
        else {
            return false;
        }
    }

    std::wstring remove_zero_width_space(const std::wstring& str) {
        std::wstring copy = str;
        copy.erase(std::remove(copy.begin(), copy.end(), L'\u200B'), copy.end());
        return copy;
    }

    bool contains_zero_width_space(const std::wstring& str) {
        return str.find(L'\u200B') != std::wstring::npos;
    }
};

inline std::unique_ptr<window_manager_t> window_manager = std::make_unique<window_manager_t>();