#pragma once

enum class request_codes : std::uint32_t {
  base = 0x119,
  read = 0x129,
  write = 0x139,
  pattern = 0x179,
  success = 0x91a,
  unique = 0x92b,
  unload = 0x93c,
  allocate_independent_pages = 0x101c,
  execute_dll_entrypoint = 0x102c,
  swap_context = 0x103c,
  restore_context = 0x104c,
};

enum alloc_mode {
  ALLOC_INSIDE_MAIN_MODULE,
  ALLOC_BETWEEN_LEGIT_MODULES,
  ALLOC_AT_LOW_ADDRESS,
  ALLOC_AT_HIGH_ADDRESS,
  ALLOC_AT_HYPERSPACE
};

struct unload_request {
  bool* success;
};

struct read_request {
  std::uint32_t pid;
  std::uintptr_t address;
  void* buffer;
  size_t size;
  bool success;
};

struct write_request {
  std::uint32_t pid;
  std::uintptr_t address;
  void* buffer;
  size_t size;
  bool success;
};

struct base_request {
  std::uint32_t pid;
  std::uintptr_t handle;
  wchar_t name[260];
};

struct allocate_independent_pages_request {
  std::uint32_t local_pid;
  std::uint32_t target_pid;
  std::uint32_t target_tid;
  void* address;
  size_t size;
  bool use_large_page;
  std::uint32_t mode;
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

struct pattern_request {
  std::int32_t pid;
  wchar_t mod_name[260];
  char signature[260];
  std::uintptr_t address;
};

struct swap_context_request {
  std::uint32_t target_tid;
  bool success;
};

struct request_data {
  std::uint32_t unique;
  request_codes code;
  void* data;
};