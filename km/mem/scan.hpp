class scan {
private:
  ULONG_PTR m_base_address;
  const char* m_pattern;
  ULONG_PTR m_pattern_address;

  struct pattern_info {
    UCHAR* bytes;
    BOOLEAN* mask;
    SIZE_T length;
  };

  static int hex_to_int(char c) {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return 0;
  }

  static pattern_info parse_pattern(const char* pattern) {
    pattern_info info = {nullptr, nullptr, 0};
    SIZE_T temp_len = globals::strlen(pattern);
    SIZE_T byte_count = 0;
    for (SIZE_T i = 0; i < temp_len; ++i) {
      if (pattern[i] == ' ')
        continue;
      byte_count++;
      if (pattern[i] != '?') {
        i++;
      }
    }

    info.bytes = (UCHAR*)globals::ex_allocate_pool2(POOL_FLAG_NON_PAGED, byte_count, 'nrtp');
    info.mask = (BOOLEAN*)globals::ex_allocate_pool2(POOL_FLAG_NON_PAGED, byte_count, 'ksam');

    if (!info.bytes || !info.mask) {
      if (info.bytes)
        globals::ex_free_pool_with_tag(info.bytes, 0);
      if (info.mask)
        globals::ex_free_pool_with_tag(info.mask, 0);
      return info;
    }

    SIZE_T j = 0;
    for (SIZE_T i = 0; i < temp_len; i++) {
      if (pattern[i] == ' ')
        continue;

      if (pattern[i] == '?') {
        info.bytes[j] = 0;
        info.mask[j] = FALSE;
      } else {
        info.bytes[j] = (hex_to_int(pattern[i]) << 4) | hex_to_int(pattern[i + 1]);
        info.mask[j] = TRUE;
        i++;
      }
      j++;
    }

    info.length = j;
    return info;
  }

  uintptr_t find_pattern(uintptr_t module_base, const char* pattern) {
    if (!module_base)
      return 0;

    pattern_info info = parse_pattern(pattern);
    if (!info.bytes || !info.mask)
      return 0;

    const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
    const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(module_base + dos_header->e_lfanew);
    const auto section_header = IMAGE_FIRST_SECTION(nt_headers);

    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
      const auto& section = section_header[i];
      if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
          !(section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {
        const UCHAR* section_start =
            reinterpret_cast<const UCHAR*>(module_base + section.VirtualAddress);
        const SIZE_T section_size = section.Misc.VirtualSize;

        if (section_size < info.length) {
          continue;
        }

        for (SIZE_T j = 0; j <= section_size - info.length; ++j) {
          BOOLEAN found = TRUE;
          for (SIZE_T k = 0; k < info.length; ++k) {
            if (info.mask[k] && section_start[j + k] != info.bytes[k]) {
              found = FALSE;
              break;
            }
          }

          if (found) {
            globals::ex_free_pool_with_tag(info.bytes, 0);
            globals::ex_free_pool_with_tag(info.mask, 0);
            return reinterpret_cast<uintptr_t>(section_start + j);
          }
        }
      }
    }

    globals::ex_free_pool_with_tag(info.bytes, 0);
    globals::ex_free_pool_with_tag(info.mask, 0);
    return 0;
  }

  static ULONG_PTR resolve_relative_address(ULONG_PTR address, ULONG offset_from_opcode,
                                            ULONG instruction_length) {
    LONG relative_offset = *(PLONG)(address + offset_from_opcode);
    return address + instruction_length + relative_offset;
  }

  template <typename T>
  static T safe_cast(ULONG_PTR value) {
    return (T)value;
  }

  template <>
  static ULONG safe_cast<ULONG>(ULONG_PTR value) {
    return (ULONG)value;
  }

public:
  scan(ULONG_PTR base_address, const char* pattern)
      : m_base_address(base_address), m_pattern(pattern) {
    m_pattern_address = find_pattern(m_base_address, m_pattern);
  }

  ULONG_PTR get_pattern_address() const {
    return m_pattern_address;
  }

  template <typename T = ULONG_PTR>
  T resolve_call(ULONG offset = 0, ULONG instruction_length = 5) {
    if (!m_pattern_address)
      return T{};
    ULONG_PTR resolved =
        resolve_relative_address(m_pattern_address + offset, 1, instruction_length);
    return safe_cast<T>(resolved);
  }

  template <typename T = ULONG_PTR>
  T resolve_mov(ULONG offset = 0, ULONG instruction_length = 7) {
    if (!m_pattern_address)
      return T{};
    ULONG_PTR resolved =
        resolve_relative_address(m_pattern_address + offset, 3, instruction_length);
    return safe_cast<T>(resolved);
  }

  template <typename T = ULONG_PTR>
  T resolve_test(ULONG offset = 0, ULONG instruction_length = 6) {
    if (!m_pattern_address)
      return T{};
    ULONG_PTR resolved =
        resolve_relative_address(m_pattern_address + offset, 2, instruction_length);
    return safe_cast<T>(resolved);
  }

  template <typename T = ULONG_PTR>
  T resolve_lea(ULONG offset = 0, ULONG instruction_length = 7) {
    if (!m_pattern_address)
      return T{};
    ULONG_PTR resolved =
        resolve_relative_address(m_pattern_address + offset, 3, instruction_length);
    return safe_cast<T>(resolved);
  }

  template <typename T = ULONG_PTR>
  T resolve_relative(ULONG offset, ULONG instruction_length) {
    if (!m_pattern_address)
      return T{};
    ULONG_PTR resolved = resolve_relative_address(m_pattern_address, offset, instruction_length);
    return safe_cast<T>(resolved);
  }

  template <typename T = ULONG_PTR, typename custom_resolver>
  T resolve_custom(custom_resolver resolver, ULONG offset = 0) {
    if (!m_pattern_address)
      return T{};
    return safe_cast<T>(resolver(m_pattern_address + offset));
  }

  operator bool() const {
    return m_pattern_address != 0;
  }

  static uintptr_t ida_findpattern_buffer(void* buffer, size_t size, const char* pattern) {
    pattern_info info = parse_pattern(pattern);
    if (!info.bytes || !info.mask || size < info.length) {
      if (info.bytes)
        globals::ex_free_pool_with_tag(info.bytes, 0);
      if (info.mask)
        globals::ex_free_pool_with_tag(info.mask, 0);
      return 0;
    }

    const auto buffer_bytes = reinterpret_cast<uint8_t*>(buffer);

    for (uintptr_t i = 0; i <= size - info.length; i++) {
      bool found = true;
      for (size_t j = 0; j < info.length; j++) {
        if (info.mask[j] && buffer_bytes[i + j] != info.bytes[j]) {
          found = false;
          break;
        }
      }
      if (found) {
        globals::ex_free_pool_with_tag(info.bytes, 0);
        globals::ex_free_pool_with_tag(info.mask, 0);
        return i;
      }
    }

    globals::ex_free_pool_with_tag(info.bytes, 0);
    globals::ex_free_pool_with_tag(info.mask, 0);
    return 0;
  }

  static auto find_pattern_usermode(uint32_t pid, const wchar_t* mod_name, const char* pattern,
                                    uintptr_t& r_addr) -> NTSTATUS {
    PEPROCESS target_proc;
    NTSTATUS status =
        globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(pid), &target_proc);
    if (!NT_SUCCESS(status)) {
      return status;
    }

    uintptr_t base = 0;
    uintptr_t module_size = 0;
    PPEB peb_address = globals::ps_get_process_peb(target_proc);
    if (!peb_address) {
      globals::obf_dereference_object(target_proc);
      return STATUS_NOT_FOUND;
    }

    PEB peb;
    physical::read_process_memory(target_proc, reinterpret_cast<uintptr_t>(peb_address), &peb,
                                  sizeof(PEB));

    if (!peb.Ldr || !peb.Ldr->Initialized) {
      globals::obf_dereference_object(target_proc);
      return STATUS_NOT_FOUND;
    }

    UNICODE_STRING module_name_unicode;
    globals::rtl_init_unicode_string(&module_name_unicode, mod_name);

    PEB_LDR_DATA ldr_data{};
    physical::read_process_memory(target_proc, reinterpret_cast<uintptr_t>(peb.Ldr), &ldr_data,
                                  sizeof(PEB_LDR_DATA));

    PLIST_ENTRY current_entry = ldr_data.InLoadOrderModuleList.Flink;
    PLIST_ENTRY first_entry = current_entry;

    do {
      LDR_DATA_TABLE_ENTRY entry{};
      physical::read_process_memory(target_proc,
                                    reinterpret_cast<uintptr_t>(CONTAINING_RECORD(
                                        current_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)),
                                    &entry, sizeof(LDR_DATA_TABLE_ENTRY));

      WCHAR dll_name[256]{};
      if (entry.BaseDllName.Length > 0 && entry.BaseDllName.Buffer) {
        physical::read_process_memory(
            target_proc, reinterpret_cast<uintptr_t>(entry.BaseDllName.Buffer), dll_name,
            min(entry.BaseDllName.Length, static_cast<USHORT>(sizeof(dll_name) - sizeof(WCHAR))));

        UNICODE_STRING dll_name_unicode{};
        dll_name_unicode.Length = entry.BaseDllName.Length;
        dll_name_unicode.MaximumLength = entry.BaseDllName.MaximumLength;
        dll_name_unicode.Buffer = dll_name;

        if (globals::rtl_compare_unicode_string(&dll_name_unicode, &module_name_unicode, TRUE) ==
            0) {
          base = reinterpret_cast<uintptr_t>(entry.DllBase);
          module_size = entry.SizeOfImage;
          break;
        }
      }

      LIST_ENTRY next_entry;
      physical::read_process_memory(target_proc, reinterpret_cast<uintptr_t>(current_entry),
                                    &next_entry, sizeof(LIST_ENTRY));
      current_entry = next_entry.Flink;

    } while (current_entry != first_entry);

    if (!base || !module_size) {
      globals::obf_dereference_object(target_proc);
      return STATUS_NOT_FOUND;
    }

    const auto end = base + module_size;
    void* temp_buffer = globals::mm_allocate_independent_pages_ex(PAGE_SIZE, -1, 0, 0);
    if (!temp_buffer) {
      globals::obf_dereference_object(target_proc);
      return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (auto current_address = base; current_address < end; current_address += PAGE_SIZE) {
      globals::memset(temp_buffer, 0, PAGE_SIZE);

      NTSTATUS read_status = physical::read_process_memory(
          target_proc, current_address, temp_buffer, min(PAGE_SIZE, end - current_address));

      if (!NT_SUCCESS(read_status)) {
        continue;
      }

      const auto scan_size = min(PAGE_SIZE, end - current_address);
      const auto pattern_offset = ida_findpattern_buffer(temp_buffer, scan_size, pattern);

      if (pattern_offset) {
        const auto address = current_address + pattern_offset;
        r_addr = address;
        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(temp_buffer), PAGE_SIZE);
        globals::obf_dereference_object(target_proc);
        return STATUS_SUCCESS;
      }
    }

    r_addr = 0;
    globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(temp_buffer), PAGE_SIZE);
    globals::obf_dereference_object(target_proc);
    return STATUS_NOT_FOUND;
  }
};
