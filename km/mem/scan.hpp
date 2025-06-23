#pragma once
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

  /**
   * @brief Convert hexadecimal character to integer value
   * @param c Hexadecimal character ('0'-'9', 'a'-'f', 'A'-'F')
   * @return Integer value (0-15), or 0 for invalid characters
   *
   * Helper function for parsing hexadecimal patterns during byte sequence
   * conversion.
   */
  int hex_to_int(char c) {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return 0;
  }

  /**
   * @brief Parse pattern string into byte array and mask for searching
   * @param pattern Pattern string with hex bytes and wildcards (e.g., "48 8B ?
   * ? 05")
   * @return pattern_info structure containing parsed bytes, mask, and length
   *
   * Converts human-readable pattern strings into searchable byte arrays.
   * Wildcards ('?') are marked in the mask array for flexible matching.
   * Allocates memory that must be freed by the caller.
   */
  pattern_info parse_pattern(const char* pattern) {
    pattern_info info = {nullptr, nullptr, 0};

    // First pass: count valid bytes in pattern
    SIZE_T count = 0;
    for (SIZE_T i = 0; pattern[i]; i++) {
      if (pattern[i] == ' ')
        continue;
      if (pattern[i] == '?') {
        count++;
        i++;  // Skip next character as it's part of the same byte
      } else {
        count++;
        i++;  // Skip next character as it's part of the same byte
      }
    }

    info.bytes = (UCHAR*)globals::ex_allocate_pool2(POOL_FLAG_NON_PAGED, count, 'nrtp');
    info.mask = (BOOLEAN*)globals::ex_allocate_pool2(POOL_FLAG_NON_PAGED, count, 'ksam');

    if (!info.bytes || !info.mask) {
      if (info.bytes)
        globals::ex_free_pool_with_tag(info.bytes, 0);
      if (info.mask)
        globals::ex_free_pool_with_tag(info.mask, 0);
      return info;
    }

    // Second pass: fill in bytes and mask
    SIZE_T j = 0;
    for (SIZE_T i = 0; pattern[i]; i++) {
      if (pattern[i] == ' ')
        continue;

      if (pattern[i] == '?') {
        info.bytes[j] = 0;
        info.mask[j] = FALSE;
        i++;  // Skip the second character
      } else {
        info.bytes[j] = (hex_to_int(pattern[i]) << 4) | hex_to_int(pattern[i + 1]);
        info.mask[j] = TRUE;
        i++;  // Skip the second character
      }
      j++;
    }

    info.length = j;
    return info;
  }

  /**
   * @brief Search for byte pattern within a module's memory space
   * @param module_base Base address of the target module
   * @param pattern Pattern string to search for
   * @return Address of first match, or 0 if not found
   *
   * Performs efficient pattern matching within module boundaries using
   * PE header information to determine search scope. Supports wildcard
   * matching for flexible signature detection.
   */
  uintptr_t find_pattern(uintptr_t module_base, const char* pattern) {
    if (!module_base)
      return 0;

    pattern_info info = parse_pattern(pattern);
    if (!info.bytes || !info.mask)
      return 0;

    const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
    const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
    const SIZE_T search_size = nt->OptionalHeader.SizeOfImage;
    const UCHAR* data = reinterpret_cast<const UCHAR*>(module_base);

    for (SIZE_T i = 0; i < search_size - info.length; i++) {
      BOOLEAN found = TRUE;

      for (SIZE_T j = 0; j < info.length; j++) {
        if (info.mask[j] && data[i + j] != info.bytes[j]) {
          found = FALSE;
          break;
        }
      }

      if (found) {
        globals::ex_free_pool_with_tag(info.bytes, 0);

        globals::ex_free_pool_with_tag(info.mask, 0);
        return module_base + i;
      }
    }

    globals::ex_free_pool_with_tag(info.bytes, 0);
    globals::ex_free_pool_with_tag(info.mask, 0);
    return 0;
  }

  /**
   * @brief Search for byte pattern within a module's memory space
   * @param module_base Base address of the target module
   * @param pattern Pattern string to search for
   * @return Address of first match, or 0 if not found
   *
   * Performs efficient pattern matching within module boundaries using
   * PE header information to determine search scope. Supports wildcard
   * matching for flexible signature detection.
   */
  static ULONG_PTR resolve_relative_address(ULONG_PTR address, ULONG offset_from_opcode,
                                            ULONG instruction_length) {
    LONG relative_offset = *(PLONG)(address + offset_from_opcode);
    return address + instruction_length + relative_offset;
  }

  /**
   * @brief Type-safe casting with template specialization support
   * @tparam T Target type for casting
   * @param value Source value to cast
   * @return Value cast to target type
   *
   * Provides safe type conversion with specialized handling for specific
   * types that require different casting behavior.
   */
  template <typename T>
  static T safe_cast(ULONG_PTR value) {
    return (T)value;
  }

  template <>
  static ULONG safe_cast<ULONG>(ULONG_PTR value) {
    return (ULONG)value;
  }

public:
  /**
   * @brief Construct pattern scanner for specified module and signature
   * @param base_address Base address of target module
   * @param pattern Byte pattern string to search for
   *
   * Initializes scanner and immediately performs pattern search.
   * Results can be retrieved using accessor methods or conversion operators.
   */
  scan(ULONG_PTR base_address, const char* pattern)
      : m_base_address(base_address), m_pattern(pattern) {
    m_pattern_address = find_pattern(m_base_address, m_pattern);
  }

  /**
   * @brief Get the raw address where pattern was found
   * @return Address of pattern match, or 0 if not found
   *
   * Returns the exact memory location where the byte pattern was located
   * without any additional processing or resolution.
   */
  ULONG_PTR get_pattern_address() const {
    return m_pattern_address;
  }

  /**
   * @brief Resolve CALL instruction target address
   * @tparam T Return type for resolved address
   * @param offset Offset from pattern start to CALL instruction
   * @param instruction_length Length of CALL instruction (default: 5 bytes)
   * @return Resolved target address of the CALL instruction
   *
   * Follows CALL instructions to determine their target addresses by
   * resolving RIP-relative addressing used in x86-64 architecture.
   */
  template <typename T = ULONG_PTR>
  T resolve_call(ULONG offset = 0, ULONG instruction_length = 5) {
    if (!m_pattern_address)
      return T{};
    ULONG_PTR resolved =
        resolve_relative_address(m_pattern_address + offset, 1, instruction_length);
    return safe_cast<T>(resolved);
  }

  /**
   * @brief Resolve MOV instruction operand address
   * @tparam T Return type for resolved address
   * @param offset Offset from pattern start to MOV instruction
   * @param instruction_length Length of MOV instruction (default: 7 bytes)
   * @return Resolved operand address of the MOV instruction
   *
   * Extracts target addresses from MOV instructions that use RIP-relative
   * addressing to access global variables or memory locations.
   */
  template <typename T = ULONG_PTR>
  T resolve_mov(ULONG offset = 0, ULONG instruction_length = 7) {
    if (!m_pattern_address)
      return T{};
    ULONG_PTR resolved =
        resolve_relative_address(m_pattern_address + offset, 3, instruction_length);
    return safe_cast<T>(resolved);
  }

  /**
   * @brief Resolve TEST instruction operand address
   * @tparam T Return type for resolved address
   * @param offset Offset from pattern start to TEST instruction
   * @param instruction_length Length of TEST instruction (default: 6 bytes)
   * @return Resolved operand address of the TEST instruction
   *
   * Follows TEST instructions to determine memory operand addresses
   * when they use RIP-relative addressing modes.
   */
  template <typename T = ULONG_PTR>
  T resolve_test(ULONG offset = 0, ULONG instruction_length = 6) {
    if (!m_pattern_address)
      return T{};
    ULONG_PTR resolved =
        resolve_relative_address(m_pattern_address + offset, 2, instruction_length);
    return safe_cast<T>(resolved);
  }

  /**
   * @brief Resolve LEA instruction effective address
   * @tparam T Return type for resolved address
   * @param offset Offset from pattern start to LEA instruction
   * @param instruction_length Length of LEA instruction (default: 7 bytes)
   * @return Resolved effective address from LEA instruction
   *
   * Calculates the effective address that would be loaded by a LEA
   * instruction using RIP-relative addressing.
   */
  template <typename T = ULONG_PTR>
  T resolve_lea(ULONG offset = 0, ULONG instruction_length = 7) {
    if (!m_pattern_address)
      return T{};
    ULONG_PTR resolved =
        resolve_relative_address(m_pattern_address + offset, 3, instruction_length);
    return safe_cast<T>(resolved);
  }

  /**
   * @brief Resolve custom relative addressing with specified parameters
   * @tparam T Return type for resolved address
   * @param offset Offset to relative operand within instruction
   * @param instruction_length Total instruction length
   * @return Resolved absolute address
   *
   * General-purpose relative address resolver for custom instruction
   * formats not covered by the specialized resolvers.
   */
  template <typename T = ULONG_PTR>
  T resolve_relative(ULONG offset, ULONG instruction_length) {
    if (!m_pattern_address)
      return T{};
    ULONG_PTR resolved = resolve_relative_address(m_pattern_address, offset, instruction_length);
    return safe_cast<T>(resolved);
  }

  /**
   * @brief Apply custom resolution logic using user-provided function
   * @tparam T Return type for resolved value
   * @tparam custom_resolver Type of custom resolver function
   * @param resolver Custom function to process the pattern address
   * @param offset Offset from pattern start to apply resolver
   * @return Result of custom resolver function
   *
   * Flexible interface for applying custom address resolution logic
   * for specialized instruction formats or complex address calculations.
   */
  template <typename T = ULONG_PTR, typename custom_resolver>
  T resolve_custom(custom_resolver resolver, ULONG offset = 0) {
    if (!m_pattern_address)
      return T{};
    return safe_cast<T>(resolver(m_pattern_address + offset));
  }

  /**
   * @brief Boolean conversion operator for pattern match validation
   * @return true if pattern was found, false otherwise
   *
   * Allows scanner objects to be used in boolean contexts to check
   * if the pattern search was successful.
   */
  operator bool() const {
    return m_pattern_address != 0;
  }

  /**
   * @brief Search for IDA-style pattern within a memory buffer
   * @param buffer Memory buffer to search within
   * @param size Size of the memory buffer
   * @param pattern IDA-style pattern string (e.g., "48 8B ? ? 05")
   * @return Offset within buffer where pattern was found, or 0 if not found
   *
   * Static utility function for pattern matching within arbitrary memory
   * buffers using IDA Pro-style pattern syntax with wildcard support.
   */
  static uintptr_t ida_findpattern_buffer(void* buffer, size_t size, const char* pattern) {
    const auto pattern_bytes = reinterpret_cast<const uint8_t*>(pattern);
    auto pattern_size = strlen(pattern);

    uint8_t first = get_byte(pattern_bytes, 0);
    uintptr_t pattern_offset = 0;

    for (uintptr_t i = 0; i <= size - pattern_size; i++) {
      const auto buffer_bytes = reinterpret_cast<uint8_t*>(buffer);

      if (buffer_bytes[i] != first) {
        continue;
      }

      for (size_t j = 0; j < pattern_size; j++) {
        if (pattern_bytes[j] == '?') {
          continue;
        }

        if (pattern_bytes[j] != buffer_bytes[i + j]) {
          break;
        }

        if (j + 1 == pattern_size) {
          pattern_offset = i;
          return pattern_offset;
        }
      }
    }

    return 0;
  }

  /**
   * @brief Search for pattern within user-mode process module
   * @param pid Target process ID
   * @param mod_name Module name to search within (e.g., L"ntdll.dll")
   * @param pattern Byte pattern string to search for
   * @param r_addr Output parameter for found address
   * @return NTSTATUS indicating success or failure
   *
   * Comprehensive pattern scanning function that locates modules within
   * target processes and performs page-by-page pattern matching using
   * physical memory reads to bypass memory protection mechanisms.
   */
  static auto find_pattern_usermode(uint32_t pid, const wchar_t* mod_name, const char* pattern,
                                    uintptr_t& r_addr) -> NTSTATUS {
    PEPROCESS target_proc;
    const auto status =
        globals::ps_lookup_process_by_process_id(reinterpret_cast<HANDLE>(pid), &target_proc);
    if (!NT_SUCCESS(status)) {
      log("ERROR", "failed to find process");
      return status;
    }

    uintptr_t base = 0;
    uintptr_t module_size = 0;

    // get PEB address
    PPEB peb_address = globals::ps_get_process_peb(target_proc);
    if (!peb_address) {
      log("ERROR", "failed to get process PEB");
      globals::obf_dereference_object(target_proc);
      return STATUS_NOT_FOUND;
    }

    // read PEB using physical memory read
    PEB peb;
    physical::read_process_memory(target_proc, reinterpret_cast<uintptr_t>(peb_address), &peb,
                                  sizeof(PEB));

    if (!peb.Ldr || !peb.Ldr->Initialized) {
      log("ERROR", "PEB loader data not initialized");
      globals::obf_dereference_object(target_proc);
      return STATUS_NOT_FOUND;
    }

    // create Unicode string for comparison
    UNICODE_STRING module_name_unicode;
    globals::rtl_init_unicode_string(&module_name_unicode, mod_name);

    // get LDR_DATA_TABLE_ENTRY for InLoadOrderModuleList
    PEB_LDR_DATA ldr_data{};
    physical::read_process_memory(target_proc, reinterpret_cast<uintptr_t>(peb.Ldr), &ldr_data,
                                  sizeof(PEB_LDR_DATA));

    // get the first entry address
    PLIST_ENTRY current_entry = ldr_data.InLoadOrderModuleList.Flink;
    PLIST_ENTRY first_entry = current_entry;

    do {
      // read the current LDR_DATA_TABLE_ENTRY
      LDR_DATA_TABLE_ENTRY entry{};
      physical::read_process_memory(target_proc,
                                    reinterpret_cast<uintptr_t>(CONTAINING_RECORD(
                                        current_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)),
                                    &entry, sizeof(LDR_DATA_TABLE_ENTRY));

      // read the module name
      WCHAR dll_name[256]{};
      if (entry.BaseDllName.Length > 0 && entry.BaseDllName.Buffer) {
        physical::read_process_memory(
            target_proc, reinterpret_cast<uintptr_t>(entry.BaseDllName.Buffer), dll_name,
            min(entry.BaseDllName.Length, static_cast<USHORT>(sizeof(dll_name) - sizeof(WCHAR))));

        // create a UNICODE_STRING for comparison
        UNICODE_STRING dll_name_unicode{};
        dll_name_unicode.Length = entry.BaseDllName.Length;
        dll_name_unicode.MaximumLength = entry.BaseDllName.MaximumLength;
        dll_name_unicode.Buffer = dll_name;

        // compare and check if this is the module we're looking for
        if (globals::rtl_compare_unicode_string(&dll_name_unicode, &module_name_unicode, TRUE) ==
            0) {
          base = reinterpret_cast<uintptr_t>(entry.DllBase);
          module_size = entry.SizeOfImage;
          break;
        }
      }

      // read the next entry
      LIST_ENTRY next_entry;
      physical::read_process_memory(target_proc, reinterpret_cast<uintptr_t>(current_entry),
                                    &next_entry, sizeof(LIST_ENTRY));
      current_entry = next_entry.Flink;

    } while (current_entry != first_entry);

    if (!base || !module_size) {
      log("ERROR", "failed to find base or module size");
      globals::obf_dereference_object(target_proc);
      return STATUS_NOT_FOUND;
    }

    const auto end = base + module_size;
    log("INFO", "starting pattern scan for process %d, base: 0x%llx, size: 0x%llx", pid, base,
        module_size);

    // allocate a buffer for reading pages
    void* temp_buffer = globals::mm_allocate_independent_pages_ex(PAGE_SIZE, -1, 0, 0);
    if (!temp_buffer) {
      log("ERROR", "failed to allocate temporary buffer");
      globals::obf_dereference_object(target_proc);
      return STATUS_INSUFFICIENT_RESOURCES;
    }

    // loop through memory, page by page, and search for the pattern
    for (auto current_address = base; current_address < end; current_address += PAGE_SIZE) {
      // clear the buffer
      globals::memset(temp_buffer, 0, PAGE_SIZE);

      // try to read the page contents using physical memory
      NTSTATUS read_status = physical::read_process_memory(
          target_proc, current_address, temp_buffer, min(PAGE_SIZE, end - current_address));

      // skip if reading failed or page is not accessible
      if (!NT_SUCCESS(read_status)) {
        continue;
      }

      // check if the page is all zeros (might be unmapped or not committed)
      BOOLEAN all_zeros = TRUE;
      for (size_t i = 0; i < min(PAGE_SIZE, end - current_address); i++) {
        if (((PUCHAR)temp_buffer)[i] != 0) {
          all_zeros = FALSE;
          break;
        }
      }

      if (all_zeros) {
        continue;
      }

      const auto scan_size = min(PAGE_SIZE, end - current_address);

      // apply pattern search to the buffer we read rather than directly to
      // memory
      const auto pattern_offset =
          ida_findpattern_buffer(temp_buffer, scan_size - globals::strlen(pattern), pattern);

      if (pattern_offset) {
        // convert buffer offset to actual address
        const auto address = current_address + pattern_offset;
        log("INFO", "signature found -> 0x%llx", address);
        r_addr = address;

        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(temp_buffer), PAGE_SIZE);

        globals::obf_dereference_object(target_proc);
        return STATUS_SUCCESS;
      }
    }

    log("ERROR", "pattern not found for module \"%ws\" using pattern \"%s\"", mod_name, pattern);
    r_addr = 0;

    globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(temp_buffer), PAGE_SIZE);

    globals::obf_dereference_object(target_proc);
    return STATUS_NOT_FOUND;
  }
};
