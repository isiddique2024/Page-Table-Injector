#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <windows.h>

#include "cli/cli.hpp"
#include "driver/driver_shell.hpp"
#include "mapper/kdmapper.hpp"
#include "utils/utils.hpp"
#include "driver/driver.hpp"
#include "inject/inject.hpp"
#include "utils/window.hpp"
#include "inject/dll_shell.hpp"

int main(int argc, char* argv[]) {
    // init CLI11 app
    CLI::App app{ "Physical Memory Manual Mapper" };

    // define variables to store arguments
    std::string window_name;
    std::string dll_path = "memory"; // default to in-memory DLL
    std::uint32_t mem_type = driver->memory_type::NORMAL_PAGE;
    std::uint32_t alloc_mode = driver->alloc_mode::ALLOC_BETWEEN_LEGIT_MODULES;
    std::string hook_module = "user32.dll";
    std::string hook_function = "GetMessageW";
    std::string target_module = "";

    // add options
    app.add_option("window_name", window_name, "Name of the target window (e.g., \"Notepad\")")
        ->required();

    app.add_option("dll_path", dll_path, "Path to the DLL file to inject, or \"memory\" to use the in-memory message box DLL");

    app.add_option("memory_type", mem_type, "Memory type: 0 for NORMAL_PAGE, 1 for LARGE_PAGE, 2 for HUGE_PAGE")
        ->check(CLI::Range(0, 2));

    app.add_option("alloc_mode", alloc_mode, "Allocation mode: 0 for ALLOC_INSIDE_MAIN_MODULE, 1 for ALLOC_BETWEEN_LEGIT_MODULES, 2 for ALLOC_AT_LOW_ADDRESS, 3 for ALLOC_AT_HIGH_ADDRESS")
        ->check(CLI::Range(0, 3));

    app.add_option("hook_module", hook_module, "Module to hook in the IAT (e.g., \"user32.dll\")");

    app.add_option("hook_function", hook_function, "Function to hook in the IAT (e.g., \"GetMessageW\")");

    app.add_option("target_module", target_module, "Module whose IAT to hook (e.g., \"Notepad.exe\")");

    // add example
    app.footer("Example: pm-mapper.exe Notepad C:\\path\\to\\payload.dll 0 1 user32.dll GetMessageW Notepad.exe");

    // parse arguments
    try {
        app.parse(argc, argv);
    }
    catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    // convert window_name to wstring
    std::wstring w_window_name(window_name.begin(), window_name.end());

    // convert target_module to wstring
    std::wstring w_target_module(target_module.begin(), target_module.end());

    // load needed libraries
    shadowcall<HMODULE>("LoadLibraryA", ("Dbghelp.dll"));
    shadowcall<HMODULE>("LoadLibraryA", ("urlmon.dll"));
    shadowcall<HMODULE>("LoadLibraryA", ("Ole32.dll"));
    shadowcall<HMODULE>("LoadLibraryA", ("Advapi32.dll"));
    shadowcall<HMODULE>("LoadLibraryA", ("bcrypt.dll"));

    // initialize the driver
    if (!kdmapper::Init()) {
        log("ERROR", "driver failed to map");
        return 1;
    }

    if (!driver->initialize()) {
        log("ERROR", "driver failed to initialize");
        return 1;
    }

    log("SUCCESS", "waiting for window...");

    // find the window
    std::uint32_t pid, tid;
    if (!window_manager->initialize_and_find_window(w_window_name.c_str(), pid, tid)) {
        log("ERROR", "failed to find window");
        return 1;
    }

    log("SUCCESS", "window found, preparing to inject...");

    // determine payload source
    void* dll_bytes = nullptr;
    size_t dll_size = 0;
    std::vector<uint8_t> file_bytes;

    if (dll_path == "memory") {
        // use in-memory DLL (MessageBox)
        dll_bytes = (void*)dll_shell;
        log("INFO", "using in-memory DLL payload");
    }
    else {
        // load DLL from disk
        file_bytes = utils::read_file(dll_path);
        if (file_bytes.empty()) {
            log("ERROR", "failed to read DLL file");
            return 1;
        }

        dll_bytes = file_bytes.data();
        dll_size = file_bytes.size();
        log("INFO", "using DLL from disk");
    }

    // map memory type to string for logging
    std::string mem_type_str;
    if (mem_type == driver->memory_type::NORMAL_PAGE) {
        mem_type_str = "NORMAL_PAGE";
    }
    else if (mem_type == driver->memory_type::LARGE_PAGE) {
        mem_type_str = "LARGE_PAGE";
    }
    else if (mem_type == driver->memory_type::HUGE_PAGE) {
        mem_type_str = "HUGE_PAGE";
    }
    else {
        mem_type_str = "UNKNOWN";
    }

    // map allocation mode to string for logging
    std::string alloc_mode_str;
    if (alloc_mode == driver->alloc_mode::ALLOC_INSIDE_MAIN_MODULE) {
        alloc_mode_str = "ALLOC_INSIDE_MAIN_MODULE";
    }
    else if (alloc_mode == driver->alloc_mode::ALLOC_BETWEEN_LEGIT_MODULES) {
        alloc_mode_str = "ALLOC_BETWEEN_LEGIT_MODULES";
    }
    else if (alloc_mode == driver->alloc_mode::ALLOC_AT_LOW_ADDRESS) {
        alloc_mode_str = "ALLOC_AT_LOW_ADDRESS";
    }
    else if (alloc_mode == driver->alloc_mode::ALLOC_AT_HIGH_ADDRESS) {
        alloc_mode_str = "ALLOC_AT_HIGH_ADDRESS";
    }
    else {
        alloc_mode_str = "UNKNOWN";
    }

    log("INFO", "memory type: %s", mem_type_str.c_str());
    log("INFO", "allocation mode: %s", alloc_mode_str.c_str());
    log("INFO", "IAT Hook module: %s", hook_module.c_str());
    log("INFO", "IAT Hook function: %s", hook_function.c_str());
    log("INFO", "IAT Target module: %s", target_module.empty() ? "Main Module" : target_module.c_str());

    // initialize the injector with the IAT hook parameters
    injector->set_iat_hook_params(hook_module.c_str(), hook_function.c_str(), w_target_module.c_str());

    if (!injector->run(pid, tid, dll_bytes, dll_size, static_cast<driver_t::memory_type>(mem_type), static_cast<driver_t::alloc_mode>(alloc_mode))) {
        log("ERROR", "failed to inject");
        return 1;
    }

    log("SUCCESS", "injection completed successfully");

    driver->unload();

    return 0;
}