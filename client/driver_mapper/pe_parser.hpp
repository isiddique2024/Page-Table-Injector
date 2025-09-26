#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <functional>
#include <cstdint>
#include "utils.hpp"

class pe_parser_t {
public:
  pe_parser_t() = default;
  ~pe_parser_t() = default;

  // Structure definitions
  struct import_function_t {
    std::string name;
    std::uint64_t* address;
  };

  struct import_info_t {
    std::string module_name;
    std::vector<import_function_t> functions;

    // compatibility alias
    const std::vector<import_function_t>& function_datas() const {
      return functions;
    }
    std::vector<import_function_t>& function_datas() {
      return functions;
    }
  };

  struct reloc_info_t {
    std::uint64_t address;
    std::uint16_t* item;
    std::uint32_t count;
  };

  // function pointer type for import resolution
  using import_resolver_t = std::function<std::uint64_t(const std::string& module_name,
                                                        const std::string& function_name)>;

  // func declarations
  auto validate_dos_header(const void* buffer, std::size_t buffer_size) -> bool;
  auto validate_nt_headers(const void* buffer, std::size_t buffer_size) -> bool;
  auto get_nt_headers(void* buffer) -> PIMAGE_NT_HEADERS64;
  auto get_imports(void* buffer) -> std::vector<import_info_t>;
  auto get_relocs(void* image_base) -> std::vector<reloc_info_t>;
  auto relocate_image_by_delta(void* image_base, std::uint64_t delta) -> bool;
  auto process_imports(void* buffer, import_resolver_t resolver) -> bool;
  auto resolve_imports(void* image_base, HANDLE device_handle, std::uint64_t ntoskrnl_addr) -> bool;
  auto find_section(void* image_base, const std::string& section_name) -> PIMAGE_SECTION_HEADER;
  auto get_module_export(HANDLE device_handle, std::uint64_t module_base,
                         const std::string& export_name) -> std::uint64_t;
  auto is_valid_pe(void* buffer) -> bool;
  auto fix_security_cookie(void* image_base, std::uint64_t kernel_image_base) -> bool;
};

// global pe parser instance
inline std::unique_ptr<pe_parser_t> g_pe_parser = std::make_unique<pe_parser_t>();