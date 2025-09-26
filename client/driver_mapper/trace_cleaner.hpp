#pragma once

#include <Windows.h>
#include <string>
#include <memory>

#define NtCurrentProcess ((HANDLE)(LONG_PTR)-1)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

class trace_cleaner_t {
public:
  trace_cleaner_t() = default;
  ~trace_cleaner_t() = default;

  // main cleaning interface
  auto clean_all_traces(HANDLE device_handle, const std::string& driver_name) -> bool;

  // individual cleaning methods
  auto clear_piddb_cache_table(HANDLE device_handle, const std::string& driver_name) -> bool;
  auto clear_kernel_hash_bucket_list(HANDLE device_handle, const std::string& driver_name) -> bool;
  auto clear_mm_unloaded_drivers(HANDLE device_handle, const std::string& driver_name) -> bool;
  auto clear_wd_filter_driver_list(HANDLE device_handle, const std::string& driver_name) -> bool;
  auto clear_ci_lookaside_lists(HANDLE device_handle) -> bool;
  auto clear_pin_driver_address_log(HANDLE device_handle, bool clear_after_dump) -> bool;

private:
  // handle info structs
  typedef struct _system_handle {
    PVOID obj;
    HANDLE unique_pid;
    HANDLE handle_value;
    ULONG granted_access;
    USHORT creator_back_trace_index;
    USHORT obj_type_index;
    ULONG handle_attributes;
    ULONG reserved;
  } system_handle, *psystem_handle;

  typedef struct _system_handle_info_ex {
    std::uintptr_t handle_count;
    std::uintptr_t reserved;
    system_handle handles[1];
  } system_handle_info_ex, *psystem_handle_info_ex;

  // PiDDB structs and functions
  struct piddb_cache_entry_t {
    LIST_ENTRY list;                // +0x00
    UNICODE_STRING driver_name;     // +0x10
    std::uint32_t time_date_stamp;  // +0x20
    NTSTATUS load_status;           // +0x24
    char padding[16];               // +0x28
  };

  // hash bucket structs
  struct hash_bucket_entry_t {
    struct hash_bucket_entry_t* next;
    UNICODE_STRING driver_name;
    std::uint32_t cert_hash[5];
  };

  struct pe_process_hash_bucket_t {
    pe_process_hash_bucket_t* next;   // offset 0x00
    HANDLE process_id;                // offset 0x08 (i[1], *((_QWORD *)v14 + 1))
    std::uint32_t unknown1;           // offset 0x10
    hash_bucket_entry_t* entry_list;  // offset 0x18 (k[3], (__int64 *)k[3])
    std::uint32_t entry_count;        // offset 0x20 (v7 = (int *)(v14 + 32))
    std::uint32_t unknown2;           // offset 0x24
    std::uint32_t flag1;              // offset 0x28 (*((_DWORD *)k + 0xA))
    std::uint32_t flag2;              // offset 0x2C (*((_DWORD *)k + 0xC))
  };

  struct rtl_balanced_links_t {
    struct rtl_balanced_links_t* parent;
    struct rtl_balanced_links_t* left_child;
    struct rtl_balanced_links_t* right_child;
    char balance;
    unsigned char reserved[3];
  };

  struct rtl_avl_table_t {
    rtl_balanced_links_t balanced_root;
    void* ordered_pointer;
    std::uint32_t which_ordered_element;
    std::uint32_t number_generic_table_elements;
    std::uint32_t depth_of_tree;
    void* restart_key;
    std::uint32_t delete_count;
    void* compare_routine;
    void* allocate_routine;
    void* free_routine;
    void* table_context;
  };

  struct lookaside_list_ex_t {
    struct general_lookaside_pool_t {
      union {
        SLIST_HEADER list_head;
        SINGLE_LIST_ENTRY single_list_head;
      };
      USHORT depth;           // +0x10
      USHORT maximum_depth;   // +0x12
      ULONG total_allocates;  // +0x14
      union {
        ULONG allocate_misses;  // +0x18
        ULONG allocate_hits;    // +0x18
      };
      ULONG total_frees;  // +0x1c
      union {
        ULONG free_misses;  // +0x20
        ULONG free_hits;    // +0x20
      };
      ULONG type;                  // +0x24 (POOL_TYPE)
      ULONG tag;                   // +0x28
      ULONG size;                  // +0x2c
      PVOID allocate_ex;           // +0x30
      PVOID free_ex;               // +0x38
      LIST_ENTRY list_entry;       // +0x40
      ULONG last_total_allocates;  // +0x50
      union {
        ULONG last_allocate_misses;  // +0x54
        ULONG last_allocate_hits;    // +0x54
      };
      ULONG future[2];  // +0x58
    } L;
  };

  // MiPinDriverAddress struct
  struct pin_driver_log_entry_t {
    std::uint32_t flags_and_address_low;
    std::uint32_t address_high;
  };

  // resource management helpers
  auto acquire_resource_exclusive(HANDLE device_handle, void* resource, bool wait) -> bool;
  auto release_resource(HANDLE device_handle, void* resource) -> bool;

  // AVL table operations
  auto lookup_element_generic_table_avl(HANDLE device_handle, rtl_avl_table_t* table,
                                        piddb_cache_entry_t* local_entry) -> std::uint64_t;
  auto delete_element_generic_table_avl(HANDLE device_handle, void* table, void* buffer) -> bool;

  // list manipulation
  auto unlink_list_entry(HANDLE device_handle, std::uint64_t entry_addr) -> bool;
  auto free_pool_memory(HANDLE device_handle, std::uint64_t address) -> bool;

  // enumeration helpers
  auto find_driver_in_piddb_entries(HANDLE device_handle, std::uint64_t piddb_table_addr)
      -> std::pair<std::wstring, std::uint64_t>;
  auto find_driver_in_hash_bucket_list(HANDLE device_handle, std::uint64_t ci_base,
                                       const std::string& driver_name) -> bool;
  auto find_driver_in_unloaded_list(HANDLE device_handle, const std::string& driver_name) -> bool;
  auto print_pe_process_hash_bucket_list(HANDLE device_handle) -> bool;

  // consts
  static constexpr std::uint32_t iqvw64e_timestamp = 0x5284EAC3;
};

// global trace cleaner instance
inline std::unique_ptr<trace_cleaner_t> g_trace_cleaner = std::make_unique<trace_cleaner_t>();