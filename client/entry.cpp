#include <windows.h>

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>

#include "lib/cli.h"
#include "driver/driver_shell.h"
#include "utils/logging.h"
#include "driver_mapper/service_manager.hpp"
#include "driver_mapper/driver_mapper.hpp"
#include "driver/driver_manager.hpp"
#include "driver_mapper/utils.hpp"
#include "inject/dll_mapper.hpp"
#include "utils/window_manager.hpp"
#include "inject/dll_shell.h"

long crash_handler(EXCEPTION_POINTERS* exception_info) {
  if (exception_info && exception_info->ExceptionRecord)
    debug_log("ERROR", "exception occurred at address: %p with exception code: 0x%lx",
              exception_info->ExceptionRecord->ExceptionAddress,
              exception_info->ExceptionRecord->ExceptionCode);

  const auto vuln_driver_handle = g_driver_mapper->get_device_handle();

  if (vuln_driver_handle)
    g_service_manager->unload_vulnerable_driver(vuln_driver_handle);

  return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, char* argv[]) {
  // init CLI11 app
  CLI::App app{"Page Table Injector"};

  // define variables and defaults to store arguments
  std::string window_name;
  std::string dll_path = "memory";
  settings::driver_alloc_mode driver_alloc_mode =
      settings::driver_alloc_mode::ALLOC_IN_SYSTEM_CONTEXT;
  settings::memory_type driver_mem_type = settings::memory_type::NORMAL_PAGE;
  settings::hide_type driver_hide_type = settings::hide_type::NONE;
  std::uint32_t dll_mem_type = g_driver_manager->memory_type::NORMAL_PAGE;
  std::uint32_t dll_alloc_mode = g_driver_manager->alloc_mode::ALLOC_AT_LOW_ADDRESS;
  settings::hide_type dll_hide_type = settings::hide_type::NONE;
  settings::experimental_options selected_option = settings::experimental_options::NONE;
  std::string hook_module = "user32.dll";
  std::string hook_function = "GetMessageW";
  std::string target_module = "";
  std::string execution_method = "iat";

  // additional options for better UX
  bool verbose = false;
  bool dry_run = false;

  // required argument - target window
  app.add_option("target", window_name, "Target window name (e.g., \"Notepad\")")->required();

  // optional DLL path with validation
  app.add_option("-d,--dll", dll_path, "Path to DLL file or \"memory\" for embedded MessageBox DLL")
      ->check(CLI::ExistingFile.description("") | CLI::IsMember({"memory"}))
      ->capture_default_str();

  auto execution_map =
      std::map<std::string, std::string>{{"iat", "iat"}, {"thread", "thread"}, {"swhk", "swhk"}};

  app.add_option("-e,--execution", execution_method, "DLL execution method")
      ->transform(CLI::CheckedTransformer(execution_map, CLI::ignore_case))
      ->capture_default_str()
      ->description("iat: Hook Import Address Table (default)\n"
                    "thread: Create remote thread for DLL entry point execution\n"
                    "swhk: Use SetWindowsHookEx for DLL entry point execution\n");

  // driver configuration group
  auto* driver_group = app.add_option_group("Driver Options", "Driver memory allocation settings");

  auto driver_alloc_map = std::map<std::string, settings::driver_alloc_mode>{
      {"system", settings::driver_alloc_mode::ALLOC_IN_SYSTEM_CONTEXT},
      {".data", settings::driver_alloc_mode::ALLOC_IN_NTOSKRNL_DATA_SECTION},
      {"current-process", settings::driver_alloc_mode::ALLOC_IN_CURRENT_PROCESS_CONTEXT}};

  auto driver_memory_type_map =
      std::map<std::string, settings::memory_type>{{"normal", settings::memory_type::NORMAL_PAGE},
                                                   {"large", settings::memory_type::LARGE_PAGE},
                                                   {"huge", settings::memory_type::HUGE_PAGE}};

  auto hide_type_map = std::map<std::string, settings::hide_type>{
      {"none", settings::hide_type::NONE},
      {"pfn_exists_bit", settings::hide_type::PFN_EXISTS_BIT},
      {"mi_remove_physical_memory", settings::hide_type::MI_REMOVE_PHYSICAL_MEMORY},
      {"set_parity_error", settings::hide_type::SET_PARITY_ERROR},
      {"set_lock_bit", settings::hide_type::SET_LOCK_BIT},
      {"hide_translation", settings::hide_type::HIDE_TRANSLATION}};

  auto experimental_options_map = std::map<std::string, settings::experimental_options>{
      {"none", settings::experimental_options::NONE},
      {"manipulate_system_partition", settings::experimental_options::MANIPULATE_SYSTEM_PARTITION}};

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
                    "pfn_exists_bit: MmCopyMemory returns STATUS_INVALID_ADDRESS on "
                    "driver page\n"
                    "mi_remove_physical_memory: Page removed from physical memory "
                    "ranges\n"
                    "set_parity_error: MmCopyMemory returns STATUS_HARDWARE_MEMORY_ERROR "
                    "(default)\n"
                    "set_lock_bit: Anti-debug mechanism - causes system crash if page "
                    "copied\n"
                    "hide_translation: MmGetVirtualForPhysical returns 0 for the "
                    "physical address");

  // DLL configuration group
  auto* dll_group = app.add_option_group("DLL Options", "DLL memory allocation settings");

  auto dll_alloc_map = std::map<std::string, std::uint32_t>{
      {"inside-main", g_driver_manager->alloc_mode::ALLOC_INSIDE_MAIN_MODULE},
      {"between-modules", g_driver_manager->alloc_mode::ALLOC_BETWEEN_LEGIT_MODULES},
      {"low-address", g_driver_manager->alloc_mode::ALLOC_AT_LOW_ADDRESS},
      {"high-address", g_driver_manager->alloc_mode::ALLOC_AT_HIGH_ADDRESS},
      {"hyperspace", g_driver_manager->alloc_mode::ALLOC_AT_HYPERSPACE},
  };

  auto dll_memory_map =
      std::map<std::string, std::uint32_t>{{"normal", g_driver_manager->memory_type::NORMAL_PAGE},
                                           {"large", g_driver_manager->memory_type::LARGE_PAGE},
                                           {"huge", g_driver_manager->memory_type::HUGE_PAGE}};

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
                    "pfn_exists_bit: MmCopyMemory returns STATUS_INVALID_ADDRESS on DLL "
                    "page\n"
                    "mi_remove_physical_memory: Page removed from physical memory "
                    "ranges\n"
                    "set_parity_error: MmCopyMemory returns STATUS_HARDWARE_MEMORY_ERROR "
                    "(default)\n"
                    "set_lock_bit: Anti-debug mechanism - causes system crash if page "
                    "copied\n"
                    "hide_translation: MmGetVirtualForPhysical returns 0 for the "
                    "physical address");

  // hook configuration group
  auto* hook_group = app.add_option_group(
      "Hook Options", "IAT hooking configuration (only used with --execution iat)");

  hook_group->add_option("--hook-module", hook_module, "Module to hook in the IAT")
      ->capture_default_str();

  hook_group->add_option("--hook-function", hook_function, "Function to hook in the IAT")
      ->capture_default_str();

  hook_group->add_option("--target-module", target_module,
                         "Module whose IAT to hook (empty = main module)");

  auto* experimental_group =
      app.add_option_group("Experimental Options", "Extra functionality and tweaks");

  experimental_group
      ->add_option("--experimental", selected_option, "Experimental operations to perform")
      ->transform(CLI::CheckedTransformer(experimental_options_map, CLI::ignore_case))
      ->capture_default_str()
      ->description("none: No experimental operations (default)\n"
                    "manipulate_system_partition: modify MiSystemPartition to affect "
                    "MmGetPhysicalMemoryRanges");

  // utility options
  app.add_flag("-v,--verbose", verbose, "Enable detailed logging");
  app.add_flag("--dry-run", dry_run, "Show configuration without injecting");

  // enhanced help with examples
  app.get_formatter()->column_width(60);
  app.footer(R"(Examples:
  Basic Usage:
    pt-injector.exe Notepad                    # Inject embedded DLL with IAT hooking (default)
    pt-injector.exe Notepad -d payload.dll     # Inject custom DLL with IAT hooking
    pt-injector.exe Notepad -e thread          # Inject embedded DLL with thread execution

  Thread execution with hyperspace allocation:
    pt-injector.exe Notepad -e thread --dll-alloc hyperspace

  SetWindowsHook execution with hyperspace allocation:
    pt-injector.exe Notepad -d memory -e swhk --dll-alloc hyperspace

  Driver current process allocation and stealthy DLL allocation with IAT:
    pt-injector.exe Notepad -d memory -e iat --driver-alloc current-process --driver-memory large --dll-alloc between-modules --dll-memory normal --hook-module user32.dll --hook-function GetMessageW --target-module notepad.exe

  Thread execution with custom allocation:
    pt-injector.exe Notepad -d memory -e thread --driver-alloc current-process --dll-alloc low-address --dll-memory normal

  System-level allocation with IAT:
    pt-injector.exe Notepad -d memory -e iat --driver-alloc system --dll-alloc inside-main --dll-memory normal --hook-module user32.dll --hook-function GetMessageW --target-module notepad.exe

  Driver and DLL large page allocation with thread execution:
    pt-injector.exe Notepad -d memory -e thread --driver-alloc current-process --driver-memory large --dll-alloc low-address --dll-memory large

  Advanced stealth with custom hide options (IAT):
    pt-injector.exe Notepad -d memory -e iat --driver-hide set_parity_error --dll-hide set_parity_error --driver-memory large --dll-alloc between-modules

  Anti-debug configuration (WARNING: Will crash system if detected):
    pt-injector.exe Notepad -d memory --driver-hide set_lock_bit --dll-hide set_lock_bit

  Preview Mode:
    pt-injector.exe Notepad --dry-run -v      # Show configuration without injecting

Note: Use quotes around window names with spaces
      Thread execution method is recommended for hyperspace allocation)");

  // parse arguments
  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  }

  // warn about dangerous hide options
  if (driver_hide_type == settings::hide_type::SET_LOCK_BIT ||
      dll_hide_type == settings::hide_type::SET_LOCK_BIT) {
    debug_log("WARNING", "set_lock_bit is an anti-debug mechanism that will crash the system if "
                         "the page is copied by security tools");
  }

  // show configuration if verbose or dry-run
  if (verbose || dry_run) {
    std::cout << "\n=== PT-Injector Configuration ===\n";
    std::cout << "Target Window: " << window_name << "\n";
    std::cout << "DLL Source: " << dll_path << "\n";
    std::cout << "Execution Method: " << execution_method << "\n";

    // map back to readable names for display
    std::string driver_alloc_str, driver_mem_str, driver_hide_str;
    std::string dll_alloc_str, dll_mem_str, dll_hide_str;

    for (auto& [name, val] : driver_alloc_map)
      if (val == driver_alloc_mode) {
        driver_alloc_str = name;
        break;
      }
    for (auto& [name, val] : driver_memory_type_map)
      if (val == driver_mem_type) {
        driver_mem_str = name;
        break;
      }
    for (auto& [name, val] : hide_type_map)
      if (val == driver_hide_type) {
        driver_hide_str = name;
        break;
      }
    for (auto& [name, val] : dll_alloc_map)
      if (val == dll_alloc_mode) {
        dll_alloc_str = name;
        break;
      }
    for (auto& [name, val] : dll_memory_map)
      if (val == dll_mem_type) {
        dll_mem_str = name;
        break;
      }
    for (auto& [name, val] : hide_type_map)
      if (val == dll_hide_type) {
        dll_hide_str = name;
        break;
      }

    std::cout << "Driver: " << driver_alloc_str << " allocation, " << driver_mem_str << " pages, "
              << driver_hide_str << " hiding\n";
    std::cout << "DLL: " << dll_alloc_str << " allocation, " << dll_mem_str << " pages, "
              << dll_hide_str << " hiding\n";

    if (execution_method == "iat") {
      std::cout << "Hook: " << hook_function << " in " << hook_module;
      if (!target_module.empty())
        std::cout << " (target: " << target_module << ")";
      std::cout << "\n";
    } else {
      std::cout << "Thread: DLL entry point execution\n";
    }

    if (selected_option != settings::experimental_options::NONE) {
      std::string experimental_str;
      for (auto& [name, val] : experimental_options_map)
        if (val == selected_option) {
          experimental_str = name;
          break;
        }
      std::cout << "Experimental: " << experimental_str << "\n";
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

  // initialize the driver
  SetUnhandledExceptionFilter(crash_handler);

  std::vector<std::uint8_t> driver_data(driver_shell, driver_shell + sizeof(driver_shell));
  NTSTATUS exit_code = 0xC0000001;
  auto status_map_driver =
      g_driver_mapper->map_driver(driver_data, 0, 0, false, true, false, &exit_code,
                                  static_cast<settings::driver_alloc_mode>(driver_alloc_mode),
                                  static_cast<settings::memory_type>(driver_mem_type),
                                  static_cast<settings::hide_type>(driver_hide_type),
                                  static_cast<settings::hide_type>(dll_hide_type),
                                  static_cast<settings::experimental_options>(selected_option));

  if (!status_map_driver || exit_code == 0xC0000001) {
    debug_log("ERROR", "failed to map driver");
    return 1;
  }

  if (!g_driver_manager->initialize()) {
    debug_log("ERROR", "driver failed to initialize");
    return 1;
  }

  debug_log("INFO", "waiting for window...");

  // find the window
  std::uint32_t tid;
  unsigned long pid;
  if (!g_window_manager->initialize_and_find_window(w_window_name.c_str(), pid, tid)) {
    debug_log("ERROR", "failed to find window");
    return 1;
  }

  debug_log("SUCCESS", "window found, preparing to inject...");

  // determine payload source
  void* dll_bytes = nullptr;
  size_t dll_size = 0;
  std::vector<uint8_t> file_bytes;

  if (dll_path == "memory") {
    // use in-memory DLL (MessageBox)
    dll_bytes = (void*)dll_shell;
    debug_log("INFO", "using in-memory DLL payload");
  } else {
    // load DLL from disk
    file_bytes = g_utils->read_file(dll_path);
    if (file_bytes.empty()) {
      debug_log("ERROR", "failed to read DLL file");
      return 1;
    }

    dll_bytes = file_bytes.data();
    dll_size = file_bytes.size();
    debug_log("INFO", "using DLL from disk: %s", dll_path.c_str());
  }

  // enhanced logging with readable names
  std::string driver_alloc_mode_str;
  if (driver_alloc_mode == settings::driver_alloc_mode::ALLOC_IN_SYSTEM_CONTEXT) {
    driver_alloc_mode_str = "ALLOC_IN_SYSTEM_CONTEXT";
  } else if (driver_alloc_mode == settings::driver_alloc_mode::ALLOC_IN_NTOSKRNL_DATA_SECTION) {
    driver_alloc_mode_str = "ALLOC_IN_NTOSKRNL_DATA_SECTION";
  } else if (driver_alloc_mode == settings::driver_alloc_mode::ALLOC_IN_CURRENT_PROCESS_CONTEXT) {
    driver_alloc_mode_str = "ALLOC_IN_CURRENT_PROCESS_CONTEXT";
  } else {
    driver_alloc_mode_str = "UNKNOWN";
  }

  std::string driver_mem_type_str;
  if (driver_mem_type == settings::memory_type::NORMAL_PAGE) {
    driver_mem_type_str = "NORMAL_PAGE";
  } else if (driver_mem_type == settings::memory_type::LARGE_PAGE) {
    driver_mem_type_str = "LARGE_PAGE";
  } else if (driver_mem_type == settings::memory_type::HUGE_PAGE) {
    driver_mem_type_str = "HUGE_PAGE";
  } else {
    driver_mem_type_str = "UNKNOWN";
  }

  std::string driver_hide_type_str;
  if (driver_hide_type == settings::hide_type::NONE) {
    driver_hide_type_str = "NONE";
  } else if (driver_hide_type == settings::hide_type::PFN_EXISTS_BIT) {
    driver_hide_type_str = "PFN_EXISTS_BIT";
  } else if (driver_hide_type == settings::hide_type::MI_REMOVE_PHYSICAL_MEMORY) {
    driver_hide_type_str = "MI_REMOVE_PHYSICAL_MEMORY";
  } else if (driver_hide_type == settings::hide_type::SET_PARITY_ERROR) {
    driver_hide_type_str = "SET_PARITY_ERROR";
  } else if (driver_hide_type == settings::hide_type::SET_LOCK_BIT) {
    driver_hide_type_str = "SET_LOCK_BIT";
  } else if (driver_hide_type == settings::hide_type::HIDE_TRANSLATION) {
    driver_hide_type_str = "HIDE_TRANSLATION";
  } else {
    driver_hide_type_str = "UNKNOWN";
  }

  std::string dll_alloc_mode_str;
  if (dll_alloc_mode == g_driver_manager->alloc_mode::ALLOC_INSIDE_MAIN_MODULE) {
    dll_alloc_mode_str = "ALLOC_INSIDE_MAIN_MODULE";
  } else if (dll_alloc_mode == g_driver_manager->alloc_mode::ALLOC_BETWEEN_LEGIT_MODULES) {
    dll_alloc_mode_str = "ALLOC_BETWEEN_LEGIT_MODULES";
  } else if (dll_alloc_mode == g_driver_manager->alloc_mode::ALLOC_AT_LOW_ADDRESS) {
    dll_alloc_mode_str = "ALLOC_AT_LOW_ADDRESS";
  } else if (dll_alloc_mode == g_driver_manager->alloc_mode::ALLOC_AT_HIGH_ADDRESS) {
    dll_alloc_mode_str = "ALLOC_AT_HIGH_ADDRESS";
  } else if (dll_alloc_mode == g_driver_manager->alloc_mode::ALLOC_AT_HYPERSPACE) {
    dll_alloc_mode_str = "ALLOC_AT_HYPERSPACE";
  } else {
    dll_alloc_mode_str = "UNKNOWN";
  }

  std::string dll_mem_type_str;
  if (dll_mem_type == g_driver_manager->memory_type::NORMAL_PAGE) {
    dll_mem_type_str = "NORMAL_PAGE";
  } else if (dll_mem_type == g_driver_manager->memory_type::LARGE_PAGE) {
    dll_mem_type_str = "LARGE_PAGE";
  } else if (dll_mem_type == g_driver_manager->memory_type::HUGE_PAGE) {
    dll_mem_type_str = "HUGE_PAGE";
  } else {
    dll_mem_type_str = "UNKNOWN";
  }

  std::string dll_hide_type_str;
  if (dll_hide_type == settings::hide_type::NONE) {
    dll_hide_type_str = "NONE";
  } else if (dll_hide_type == settings::hide_type::PFN_EXISTS_BIT) {
    dll_hide_type_str = "PFN_EXISTS_BIT";
  } else if (dll_hide_type == settings::hide_type::MI_REMOVE_PHYSICAL_MEMORY) {
    dll_hide_type_str = "MI_REMOVE_PHYSICAL_MEMORY";
  } else if (dll_hide_type == settings::hide_type::SET_PARITY_ERROR) {
    dll_hide_type_str = "SET_PARITY_ERROR";
  } else if (dll_hide_type == settings::hide_type::SET_LOCK_BIT) {
    dll_hide_type_str = "SET_LOCK_BIT";
  } else if (dll_hide_type == settings::hide_type::HIDE_TRANSLATION) {
    dll_hide_type_str = "HIDE_TRANSLATION";
  } else {
    dll_hide_type_str = "UNKNOWN";
  }

  if (verbose) {
    debug_log("INFO", "execution method: %s", execution_method.c_str());
    debug_log("INFO", "driver allocation mode: %s", driver_alloc_mode_str.c_str());
    debug_log("INFO", "driver memory type: %s", driver_mem_type_str.c_str());
    debug_log("INFO", "driver hide type: %s", driver_hide_type_str.c_str());
    debug_log("INFO", "dll allocation mode: %s", dll_alloc_mode_str.c_str());
    debug_log("INFO", "dll memory type: %s", dll_mem_type_str.c_str());
    debug_log("INFO", "dll hide type: %s", dll_hide_type_str.c_str());

    if (execution_method == "iat") {
      debug_log("INFO", "IAT Hook module: %s", hook_module.c_str());
      debug_log("INFO", "IAT Hook function: %s", hook_function.c_str());
      debug_log("INFO", "IAT Target module: %s",
                target_module.empty() ? "Main Module" : target_module.c_str());
    }
  }

  // set execution method and initialize the injector
  if (execution_method == "iat") {
    g_dll_mapper->set_iat_hook_params(hook_module.c_str(), hook_function.c_str(),
                                      w_target_module.c_str());
    g_dll_mapper->set_execution_method(dll_mapper_t::execution_method::IAT_HOOK);
  } else if (execution_method == "swhk") {
    g_dll_mapper->set_execution_method(dll_mapper_t::execution_method::SET_WINDOWS_HOOK);
  } else {
    g_dll_mapper->set_execution_method(dll_mapper_t::execution_method::THREAD);
  }

  debug_log("INFO", "press any key to inject");

  getchar();

  if (!g_dll_mapper->run(pid, tid, dll_bytes, dll_size,
                         static_cast<driver_manager_t::memory_type>(dll_mem_type),
                         static_cast<driver_manager_t::alloc_mode>(dll_alloc_mode))) {
    debug_log("ERROR", "failed to inject");
    return 1;
  }

  debug_log("SUCCESS", "injection completed successfully");

  if (!g_driver_manager->unload()) {
    debug_log("ERROR", "failed to unhook/unload driver");
  }

  return 0;
}