#pragma once

namespace utils {
  /**
   * @brief Retrieve the Windows build number of the current system
   * @return Windows build number (e.g., 22000 for Windows 11, 19041 for Windows
   * 10)
   *
   * Uses RtlGetVersion to obtain the current operating system version
   * information. Useful for implementing version-specific code paths and
   * compatibility checks.
   */
  auto get_windows_version() -> unsigned long;

  auto kva_shadow_enabled() -> bool;

  /**
   * @brief Get the base address of a module loaded in a target process
   * @param pid Process ID of the target process
   * @param module_name Wide string name of the module to find (e.g.,
   * L"ntdll.dll") Pass empty string (L"") to get the main executable base
   * @return Base address of the module, or 0 if not found or on error
   *
   * Walks the target process's PEB and LDR structures using physical memory reads
   * to locate a specific module. Case-insensitive module name comparison.
   * Special behavior: empty module_name returns the first (main) module's base.
   */
  auto get_module_base(uintptr_t pid, LPCWSTR module_name) -> uintptr_t;

}  // namespace utils