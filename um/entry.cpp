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

    // define variables and defaults to store arguments
    std::string window_name;
    std::string dll_path = "memory";
    std::uint32_t driver_alloc_mode = nt::ALLOC_IN_SYSTEM_CONTEXT;
    std::uint32_t driver_mem_type = nt::NORMAL_PAGE;
    std::uint32_t driver_hide_type = nt::SET_PARITY_ERROR;
    std::uint32_t dll_mem_type = driver->memory_type::NORMAL_PAGE;
    std::uint32_t dll_alloc_mode = driver->alloc_mode::ALLOC_BETWEEN_LEGIT_MODULES;
    std::uint32_t dll_hide_type = nt::SET_PARITY_ERROR;
    std::string hook_module = "user32.dll";
    std::string hook_function = "GetMessageW";
    std::string target_module = "";
    std::string execution_method = "iat";

    // additional options for better UX
    bool verbose = false;
    bool dry_run = false;

    // required argument - target window
    app.add_option("target", window_name, "Target window name (e.g., \"Notepad\")")
        ->required();

    // optional DLL path with validation
    app.add_option("-d,--dll", dll_path, "Path to DLL file or \"memory\" for embedded MessageBox DLL")
        ->check(CLI::ExistingFile.description("") | CLI::IsMember({ "memory" }))
        ->capture_default_str();

    auto execution_map = std::map<std::string, std::string>{
      {"iat", "iat"},
      {"thread", "thread"},
      {"swhk", "swhk"}
    };

    app.add_option("-e,--execution", execution_method, "DLL execution method")
        ->transform(CLI::CheckedTransformer(execution_map, CLI::ignore_case))
        ->capture_default_str()
        ->description("iat: Hook Import Address Table (default)\n"
            "thread: Create remote thread for DLL entry point execution\n"
            "swhk: Use SetWindowsHookEx for DLL entry point execution");

    // driver configuration group
    auto* driver_group = app.add_option_group("Driver Options", "Driver memory allocation settings");

    auto driver_alloc_map = std::map<std::string, std::uint32_t>{
        {"system", nt::ALLOC_IN_SYSTEM_CONTEXT},
        {".data", nt::ALLOC_IN_NTOSKRNL_DATA_SECTION},
        {"current-process", nt::ALLOC_IN_CURRENT_PROCESS_CONTEXT}
    };

    auto driver_memory_type_map = std::map<std::string, std::uint32_t>{
        {"normal", nt::NORMAL_PAGE},
        {"large", nt::LARGE_PAGE},
        {"huge", nt::HUGE_PAGE}
    };

    auto hide_type_map = std::map<std::string, std::uint32_t>{
        {"none", nt::NONE},
        {"pfn_exists_bit", nt::PFN_EXISTS_BIT},
        {"mi_remove_physical_memory", nt::MI_REMOVE_PHYSICAL_MEMORY},
        {"set_parity_error", nt::SET_PARITY_ERROR},
        {"set_lock_bit", nt::SET_LOCK_BIT},
        {"hide_translation", nt::HIDE_TRANSLATION}
    };

    driver_group->add_option("--driver-alloc", driver_alloc_mode, "Driver allocation strategy")
        ->transform(CLI::CheckedTransformer(driver_alloc_map, CLI::ignore_case))
        ->capture_default_str()
        ->description("system: System context allocation\n"
            ".data: Inside ntoskrnl .data section\n"
            "current-process: Current process context (default)");

    driver_group->add_option("--driver-memory", driver_mem_type, "Driver memory page size")
        ->transform(CLI::CheckedTransformer(driver_memory_type_map, CLI::ignore_case))
        ->capture_default_str()
        ->description("normal: 4KB pages (default)\n"
            "large: 2MB pages\n"
            "huge: 1GB pages (not supported yet)");

    driver_group->add_option("--driver-hide", driver_hide_type, "Driver memory hide type")
        ->transform(CLI::CheckedTransformer(hide_type_map, CLI::ignore_case))
        ->capture_default_str()
        ->description("none: No memory hide\n"
            "pfn_exists_bit: MmCopyMemory returns STATUS_INVALID_ADDRESS on driver page\n"
            "mi_remove_physical_memory: Page removed from physical memory ranges\n"
            "set_parity_error: MmCopyMemory returns STATUS_HARDWARE_MEMORY_ERROR (default)\n"
            "set_lock_bit: Anti-debug mechanism - causes system crash if page copied\n"
            "hide_translation: MmGetVirtualForPhysical returns 0 for the physical address");

    // DLL configuration group
    auto* dll_group = app.add_option_group("DLL Options", "DLL memory allocation settings");

    auto dll_alloc_map = std::map<std::string, std::uint32_t>{
        {"inside-main", driver->alloc_mode::ALLOC_INSIDE_MAIN_MODULE},
        {"between-modules", driver->alloc_mode::ALLOC_BETWEEN_LEGIT_MODULES},
        {"low-address", driver->alloc_mode::ALLOC_AT_LOW_ADDRESS},
        {"high-address", driver->alloc_mode::ALLOC_AT_HIGH_ADDRESS},
        {"hyperspace", driver->alloc_mode::ALLOC_AT_HYPERSPACE},
    };

    auto dll_memory_map = std::map<std::string, std::uint32_t>{
        {"normal", driver->memory_type::NORMAL_PAGE},
        {"large", driver->memory_type::LARGE_PAGE},
        {"huge", driver->memory_type::HUGE_PAGE}
    };

    dll_group->add_option("--dll-alloc", dll_alloc_mode, "DLL allocation strategy")
        ->transform(CLI::CheckedTransformer(dll_alloc_map, CLI::ignore_case))
        ->capture_default_str()
        ->description("inside-main: Hijack PTEs in main module\n"
            "between-modules: Allocate between legitimate modules (default)\n"
            "low-address: Usermode space (PML4 0-255)\n"
            "high-address: Kernel space (PML4 256-511)\n"
            "hyperspace: Hidden usermode address space (PML4 0-255)");

    dll_group->add_option("--dll-memory", dll_mem_type, "DLL memory page size")
        ->transform(CLI::CheckedTransformer(dll_memory_map, CLI::ignore_case))
        ->capture_default_str()
        ->description("normal: 4KB pages (default)\n"
            "large: 2MB pages\n"
            "huge: 1GB pages (not supported yet)");

    dll_group->add_option("--dll-hide", dll_hide_type, "DLL memory hide type")
        ->transform(CLI::CheckedTransformer(hide_type_map, CLI::ignore_case))
        ->capture_default_str()
        ->description("none: No memory hide\n"
            "pfn_exists_bit: MmCopyMemory returns STATUS_INVALID_ADDRESS on DLL page\n"
            "mi_remove_physical_memory: Page removed from physical memory ranges\n"
            "set_parity_error: MmCopyMemory returns STATUS_HARDWARE_MEMORY_ERROR (default)\n"
            "set_lock_bit: Anti-debug mechanism - causes system crash if page copied\n"
            "hide_translation: MmGetVirtualForPhysical returns 0 for the physical address");

    // hook configuration group  
    auto* hook_group = app.add_option_group("Hook Options", "IAT hooking configuration (only used with --execution iat)");

    hook_group->add_option("--hook-module", hook_module, "Module to hook in the IAT")
        ->capture_default_str();

    hook_group->add_option("--hook-function", hook_function, "Function to hook in the IAT")
        ->capture_default_str();

    hook_group->add_option("--target-module", target_module,
        "Module whose IAT to hook (empty = main module)");

    // utility options
    app.add_flag("-v,--verbose", verbose, "Enable detailed logging");
    app.add_flag("--dry-run", dry_run, "Show configuration without injecting");

    // enhanced help with examples
    app.get_formatter()->column_width(60);
    app.footer(R"(Examples:
  Basic Usage:
    pm-mapper.exe Notepad                    # Inject embedded DLL with IAT hooking (default)
    pm-mapper.exe Notepad -d payload.dll     # Inject custom DLL with IAT hooking
    pm-mapper.exe Notepad -e thread          # Inject embedded DLL with thread execution

  Thread execution with hyperspace allocation:
    pm-mapper.exe Notepad -e thread --dll-alloc hyperspace

  SetWindowsHook execution with hyperspace allocation:
    pm-mapper.exe Notepad -d memory -e swhk --dll-alloc hyperspace

  Driver current process allocation and stealthy DLL allocation with IAT:
    pm-mapper.exe Notepad -d memory -e iat --driver-alloc current-process --driver-memory large --dll-alloc between-modules --dll-memory normal --hook-module user32.dll --hook-function GetMessageW --target-module notepad.exe

  Thread execution with custom allocation:
    pm-mapper.exe Notepad -d memory -e thread --driver-alloc current-process --dll-alloc low-address --dll-memory normal

  System-level allocation with IAT:
    pm-mapper.exe Notepad -d memory -e iat --driver-alloc system --dll-alloc inside-main --dll-memory normal --hook-module user32.dll --hook-function GetMessageW --target-module notepad.exe

  Driver and DLL large page allocation with thread execution:
    pm-mapper.exe Notepad -d memory -e thread --driver-alloc current-process --driver-memory large --dll-alloc low-address --dll-memory large

  Advanced stealth with custom hide options (IAT):
    pm-mapper.exe Notepad -d memory -e iat --driver-hide set_parity_error --dll-hide set_parity_error --driver-memory large --dll-alloc between-modules

  Anti-debug configuration (WARNING: Will crash system if detected):
    pm-mapper.exe Notepad -d memory --driver-hide set_lock_bit --dll-hide set_lock_bit

  Preview Mode:
    pm-mapper.exe Notepad --dry-run -v      # Show configuration without injecting

Note: Use quotes around window names with spaces
      Thread execution method is recommended for hyperspace allocation)");

    // parse arguments
    try {
        app.parse(argc, argv);
    }
    catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    // validate and warnings
    if (driver_mem_type == nt::HUGE_PAGE || dll_mem_type == driver->memory_type::HUGE_PAGE) {
        log("WARNING", "huge pages (1GB) are not yet supported, falling back to large pages");
        if (driver_mem_type == nt::HUGE_PAGE) driver_mem_type = nt::LARGE_PAGE;
        if (dll_mem_type == driver->memory_type::HUGE_PAGE) dll_mem_type = driver->memory_type::LARGE_PAGE;
    }

    // warn about dangerous hide options
    if (driver_hide_type == nt::SET_LOCK_BIT || dll_hide_type == nt::SET_LOCK_BIT) {
        log("WARNING", "set_lock_bit is an anti-debug mechanism that will crash the system if the page is copied by security tools");
    }

    // show configuration if verbose or dry-run
    if (verbose || dry_run) {
        std::cout << "\n=== PM-Mapper Configuration ===\n";
        std::cout << "Target Window: " << window_name << "\n";
        std::cout << "DLL Source: " << dll_path << "\n";
        std::cout << "Execution Method: " << execution_method << "\n";

        // map back to readable names for display
        std::string driver_alloc_str, driver_mem_str, driver_hide_str;
        std::string dll_alloc_str, dll_mem_str, dll_hide_str;

        for (auto& [name, val] : driver_alloc_map)
            if (val == driver_alloc_mode) { driver_alloc_str = name; break; }
        for (auto& [name, val] : driver_memory_type_map)
            if (val == driver_mem_type) { driver_mem_str = name; break; }
        for (auto& [name, val] : hide_type_map)
            if (val == driver_hide_type) { driver_hide_str = name; break; }
        for (auto& [name, val] : dll_alloc_map)
            if (val == dll_alloc_mode) { dll_alloc_str = name; break; }
        for (auto& [name, val] : dll_memory_map)
            if (val == dll_mem_type) { dll_mem_str = name; break; }
        for (auto& [name, val] : hide_type_map)
            if (val == dll_hide_type) { dll_hide_str = name; break; }

        std::cout << "Driver: " << driver_alloc_str << " allocation, " << driver_mem_str << " pages, " << driver_hide_str << " hiding\n";
        std::cout << "DLL: " << dll_alloc_str << " allocation, " << dll_mem_str << " pages, " << dll_hide_str << " hiding\n";

        if (execution_method == "iat") {
            std::cout << "Hook: " << hook_function << " in " << hook_module;
            if (!target_module.empty()) std::cout << " (target: " << target_module << ")";
            std::cout << "\n";
        }
        else {
            std::cout << "Thread: DLL entry point execution\n";
        }

        std::cout << std::string(40, '=') << "\n\n";

        if (dry_run) {
            std::cout << "[DRY RUN] Configuration validated - no injection performed\n";
            return 0;
        }
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
    if (!kdmapper::Init(static_cast<nt::driver_alloc_mode>(driver_alloc_mode), static_cast<nt::memory_type>(driver_mem_type), 
        static_cast<nt::hide_type>(driver_hide_type), static_cast<nt::hide_type>(dll_hide_type))) 
    {
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
        log("INFO", "using DLL from disk: %s", dll_path.c_str());
    }

    // enhanced logging with readable names
    std::string driver_alloc_mode_str;
    if (driver_alloc_mode == nt::ALLOC_IN_SYSTEM_CONTEXT) {
        driver_alloc_mode_str = "ALLOC_IN_SYSTEM_CONTEXT";
    }
    else if (driver_alloc_mode == nt::ALLOC_IN_NTOSKRNL_DATA_SECTION) {
        driver_alloc_mode_str = "ALLOC_IN_NTOSKRNL_DATA_SECTION";
    }
    else if (driver_alloc_mode == nt::ALLOC_IN_CURRENT_PROCESS_CONTEXT) {
        driver_alloc_mode_str = "ALLOC_IN_CURRENT_PROCESS_CONTEXT";
    }
    else {
        driver_alloc_mode_str = "UNKNOWN";
    }

    std::string driver_mem_type_str;
    if (driver_mem_type == nt::NORMAL_PAGE) {
        driver_mem_type_str = "NORMAL_PAGE";
    }
    else if (driver_mem_type == nt::LARGE_PAGE) {
        driver_mem_type_str = "LARGE_PAGE";
    }
    else if (driver_mem_type == nt::HUGE_PAGE) {
        driver_mem_type_str = "HUGE_PAGE";
    }
    else {
        driver_mem_type_str = "UNKNOWN";
    }

    std::string driver_hide_type_str;
    if (driver_hide_type == nt::NONE) {
        driver_hide_type_str = "NONE";
    }
    else if (driver_hide_type == nt::PFN_EXISTS_BIT) {
        driver_hide_type_str = "PFN_EXISTS_BIT";
    }
    else if (driver_hide_type == nt::MI_REMOVE_PHYSICAL_MEMORY) {
        driver_hide_type_str = "MI_REMOVE_PHYSICAL_MEMORY";
    }
    else if (driver_hide_type == nt::SET_PARITY_ERROR) {
        driver_hide_type_str = "SET_PARITY_ERROR";
    }
    else if (driver_hide_type == nt::SET_LOCK_BIT) {
        driver_hide_type_str = "SET_LOCK_BIT";
    }
    else if (driver_hide_type == nt::HIDE_TRANSLATION) {
        driver_hide_type_str = "HIDE_TRANSLATION";
    }
    else {
        driver_hide_type_str = "UNKNOWN";
    }

    std::string dll_alloc_mode_str;
    if (dll_alloc_mode == driver->alloc_mode::ALLOC_INSIDE_MAIN_MODULE) {
        dll_alloc_mode_str = "ALLOC_INSIDE_MAIN_MODULE";
    }
    else if (dll_alloc_mode == driver->alloc_mode::ALLOC_BETWEEN_LEGIT_MODULES) {
        dll_alloc_mode_str = "ALLOC_BETWEEN_LEGIT_MODULES";
    }
    else if (dll_alloc_mode == driver->alloc_mode::ALLOC_AT_LOW_ADDRESS) {
        dll_alloc_mode_str = "ALLOC_AT_LOW_ADDRESS";
    }
    else if (dll_alloc_mode == driver->alloc_mode::ALLOC_AT_HIGH_ADDRESS) {
        dll_alloc_mode_str = "ALLOC_AT_HIGH_ADDRESS";
    }
    else if (dll_alloc_mode == driver->alloc_mode::ALLOC_AT_HYPERSPACE) {
        dll_alloc_mode_str = "ALLOC_AT_HYPERSPACE";
    }
    else {
        dll_alloc_mode_str = "UNKNOWN";
    }

    std::string dll_mem_type_str;
    if (dll_mem_type == driver->memory_type::NORMAL_PAGE) {
        dll_mem_type_str = "NORMAL_PAGE";
    }
    else if (dll_mem_type == driver->memory_type::LARGE_PAGE) {
        dll_mem_type_str = "LARGE_PAGE";
    }
    else if (dll_mem_type == driver->memory_type::HUGE_PAGE) {
        dll_mem_type_str = "HUGE_PAGE";
    }
    else {
        dll_mem_type_str = "UNKNOWN";
    }

    std::string dll_hide_type_str;
    if (dll_hide_type == nt::NONE) {
        dll_hide_type_str = "NONE";
    }
    else if (dll_hide_type == nt::PFN_EXISTS_BIT) {
        dll_hide_type_str = "PFN_EXISTS_BIT";
    }
    else if (dll_hide_type == nt::MI_REMOVE_PHYSICAL_MEMORY) {
        dll_hide_type_str = "MI_REMOVE_PHYSICAL_MEMORY";
    }
    else if (dll_hide_type == nt::SET_PARITY_ERROR) {
        dll_hide_type_str = "SET_PARITY_ERROR";
    }
    else if (dll_hide_type == nt::SET_LOCK_BIT) {
        dll_hide_type_str = "SET_LOCK_BIT";
    }
    else if (dll_hide_type == nt::HIDE_TRANSLATION) {
        dll_hide_type_str = "HIDE_TRANSLATION";
    }
    else {
        dll_hide_type_str = "UNKNOWN";
    }

    if (verbose) {
        log("INFO", "execution method: %s", execution_method.c_str());
        log("INFO", "driver allocation mode: %s", driver_alloc_mode_str.c_str());
        log("INFO", "driver memory type: %s", driver_mem_type_str.c_str());
        log("INFO", "driver hide type: %s", driver_hide_type_str.c_str());
        log("INFO", "dll allocation mode: %s", dll_alloc_mode_str.c_str());
        log("INFO", "dll memory type: %s", dll_mem_type_str.c_str());
        log("INFO", "dll hide type: %s", dll_hide_type_str.c_str());

        if (execution_method == "iat") {
            log("INFO", "IAT Hook module: %s", hook_module.c_str());
            log("INFO", "IAT Hook function: %s", hook_function.c_str());
            log("INFO", "IAT Target module: %s", target_module.empty() ? "Main Module" : target_module.c_str());
        }
    }

    // set execution method and initialize the injector
    if (execution_method == "iat") {
        injector->set_iat_hook_params(hook_module.c_str(), hook_function.c_str(), w_target_module.c_str());
        injector->set_execution_method(injector_t::execution_method::IAT_HOOK);
    }
    else if (execution_method == "swhk") { 
        injector->set_execution_method(injector_t::execution_method::SET_WINDOWS_HOOK);
    }
    else {
        injector->set_execution_method(injector_t::execution_method::THREAD);
    }

    log("INFO", "press any key to inject");

    getchar();

    if (!injector->run(pid, tid, dll_bytes, dll_size, static_cast<driver_t::memory_type>(dll_mem_type), static_cast<driver_t::alloc_mode>(dll_alloc_mode))) {
        log("ERROR", "failed to inject");
        return 1;
    }

    log("SUCCESS", "injection completed successfully");

    driver->unload();


    return 0;
}