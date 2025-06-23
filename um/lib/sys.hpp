#pragma once
// [FAQ / Examples] here: https://github.com/annihilatorq/shadow_syscall

// Creator Discord - @ntraiseharderror,
// Telegram - https://t.me/annihilatorq,
// Github - https://github.com/annihilatorq

// Credits to https://github.com/can1357/linux-pe for the very pretty structs
// Special thanks to @inversion

#ifndef SHADOWSYSCALL_HPP
#define SHADOWSYSCALL_HPP

#define SHADOWSYSCALLS_CACHING true

#if SHADOWSYSCALLS_CACHING
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#endif

#include <cstdint>
#include <string>
#include <string_view>
#include <cstring>
#include <optional>
#include <array>
#include <span>
#include <variant>
#include <iostream>
#include <algorithm>
#include <intrin.h>

namespace shadow
{
    static constexpr bool is_arch_x64 = sizeof(std::nullptr_t) == 8;

    namespace win
    {
        static constexpr std::uint32_t NUM_DATA_DIRECTORIES = 16;
        static constexpr std::uint32_t img_npos = 0xFFFFFFFF;

        union version_t
        {
            uint16_t identifier;
            struct {
                uint8_t major;
                uint8_t minor;
            };
        };

        union ex_version_t
        {
            uint32_t identifier;
            struct {
                uint16_t major;
                uint16_t minor;
            };
        };

        struct section_string_t
        {
            char short_name[8];

            std::string_view to_string() { return std::string_view{ short_name }; }
            const std::string_view to_string() const { return std::string_view{ short_name }; }

            explicit operator std::string_view() { return to_string(); }
            explicit operator std::string_view() const { return to_string(); }

            char operator[](size_t n) { return to_string()[n]; }
            char operator[](size_t n) const { return to_string()[n]; }

            bool operator==(const section_string_t& other) { return to_string() == other.to_string(); }
            bool operator==(const section_string_t& other) const { return to_string() == other.to_string(); }
        };

        struct unicode_string
        {
            std::uint16_t length;
            std::uint16_t maximum_length;
            wchar_t* buffer;

            std::wstring_view to_wstring() noexcept { return std::wstring_view{ buffer }; }
            const std::wstring_view to_wstring() const noexcept { return std::wstring_view{ buffer }; }
        };

        struct list_entry
        {
            list_entry* flink;
            list_entry* blink;
        };

        enum directory_id : std::uint8_t
        {
            directory_entry_export = 0,				// Export Directory
            directory_entry_import = 1,				// Import Directory
            directory_entry_resource = 2,			// Resource Directory
            directory_entry_exception = 3,			// Exception Directory
            directory_entry_security = 4,			// Security Directory
            directory_entry_basereloc = 5,			// Base Relocation Table
            directory_entry_debug = 6,				// Debug Directory
            directory_entry_copyright = 7,			// (X86 usage)
            directory_entry_architecture = 7,		// Architecture Specific Data
            directory_entry_globalptr = 8,			// RVA of GP
            directory_entry_tls = 9,                // TLS Directory
            directory_entry_load_config = 10,		// Load Configuration Directory
            directory_entry_bound_import = 11,		// Bound Import Directory in headers
            directory_entry_iat = 12,               // Import Address Table
            directory_entry_delay_import = 13,		// Delay Load Import Descriptors
            directory_entry_com_descriptor = 14,	// COM Runtime descriptor
            directory_reserved0 = 15,               // -
        };

        struct data_directory_t
        {
            std::uint32_t rva;
            std::uint32_t size;

            inline bool present() const noexcept { return size > 0; }
        };

        struct raw_data_directory_t
        {
            uint32_t                    ptr_raw_data;
            uint32_t                    size;
            inline bool present() const noexcept { return size > 0; }
        };

        struct data_directories_x64_t
        {
            union
            {
                struct
                {
                    data_directory_t      export_directory;
                    data_directory_t      import_directory;
                    data_directory_t      resource_directory;
                    data_directory_t      exception_directory;
                    raw_data_directory_t  security_directory;  // File offset instead of RVA!
                    data_directory_t      basereloc_directory;
                    data_directory_t      debug_directory;
                    data_directory_t      architecture_directory;
                    data_directory_t      globalptr_directory;
                    data_directory_t      tls_directory;
                    data_directory_t      load_config_directory;
                    data_directory_t      bound_import_directory;
                    data_directory_t      iat_directory;
                    data_directory_t      delay_import_directory;
                    data_directory_t      com_descriptor_directory;
                    data_directory_t      _reserved0;
                };
                data_directory_t          entries[NUM_DATA_DIRECTORIES];
            };
        };

        struct data_directories_x86_t
        {
            union
            {
                struct
                {
                    data_directory_t      export_directory;
                    data_directory_t      import_directory;
                    data_directory_t      resource_directory;
                    data_directory_t      exception_directory;
                    raw_data_directory_t  security_directory;  // File offset instead of RVA!
                    data_directory_t      basereloc_directory;
                    data_directory_t      debug_directory;
                    data_directory_t      copyright_directory;
                    data_directory_t      globalptr_directory;
                    data_directory_t      tls_directory;
                    data_directory_t      load_config_directory;
                    data_directory_t      bound_import_directory;
                    data_directory_t      iat_directory;
                    data_directory_t      delay_import_directory;
                    data_directory_t      com_descriptor_directory;
                    data_directory_t      _reserved0;
                };
                data_directory_t          entries[NUM_DATA_DIRECTORIES];
            };
        };

        struct export_directory_t
        {
            uint32_t characteristics;
            uint32_t timedate_stamp;
            version_t version;
            uint32_t name;
            uint32_t base;
            uint32_t num_functions;
            uint32_t num_names;
            uint32_t rva_functions;
            uint32_t rva_names;
            uint32_t rva_name_ordinals;

            auto rva_table(std::uintptr_t base_address) const {
                return reinterpret_cast<std::uint32_t*>(base_address + rva_functions);
            }

            auto ordinal_table(std::uintptr_t base_address) const {
                return reinterpret_cast<std::uint16_t*>(base_address + rva_name_ordinals);
            }
        };

        enum class subsystem_id : uint16_t
        {
            unknown = 0x0000,					// Unknown subsystem.
            native = 0x0001,					// Image doesn't require a subsystem.
            windows_gui = 0x0002,				// Image runs in the Windows GUI subsystem.
            windows_cui = 0x0003,				// Image runs in the Windows character subsystem
            os2_cui = 0x0005,					// image runs in the OS/2 character subsystem.
            posix_cui = 0x0007,                 // image runs in the Posix character subsystem.
            native_windows = 0x0008,			// image is a native Win9x driver.
            windows_ce_gui = 0x0009,			// Image runs in the Windows CE subsystem.
            efi_application = 0x000A,
            efi_boot_service_driver = 0x000B,
            efi_runtime_driver = 0x000C,
            efi_rom = 0x000D,
            xbox = 0x000E,
            windows_boot_application = 0x0010,
            xbox_code_catalog = 0x0011,
        };

        struct ldr_data_table_entry
        {
            list_entry in_load_order_links;
            list_entry in_memory_order_links;
            void* reserved2[2];
            void* dll_base;
            void* entry_point;
            void* reserved3;
            unicode_string path;
            unicode_string name;
            void* reserved5[3];
            union {
                std::uint32_t check_sum;
                void* reserved6;
            };
            std::uint32_t time_date_stamp;
        };

        struct peb_ldr_data_t
        {
            std::uint32_t length;
            std::uint8_t initialized;
            void* ss_handle;
            list_entry in_load_order_module_list;
            list_entry in_memory_order_module_list;
            list_entry in_initialization_order_module_list;
        };

        struct peb_t
        {
            uint8_t reserved1[2];
            uint8_t being_debugged;
            uint8_t reserved2[1];
            const char* reserved3[2];
            peb_ldr_data_t* ldr_data;

            static auto address() noexcept
            {
#if defined(_M_X64)
                return reinterpret_cast<const peb_t*>(__readgsqword(0x60));
#elif defined(_M_IX86)
                return reinterpret_cast<const peb_t*>(__readfsdword(0x30));
#else
#error Unsupported platform.
#endif
            }

            static auto loader_data() noexcept {
                return reinterpret_cast<peb_ldr_data_t*>(address()->ldr_data);
            }
        };

        struct section_header_t
        {
            section_string_t			name;
            union
            {
                uint32_t                physical_address;
                uint32_t                virtual_size;
            };
            uint32_t                    virtual_address;

            uint32_t                    size_raw_data;
            uint32_t                    ptr_raw_data;

            uint32_t                    ptr_relocs;
            uint32_t                    ptr_line_numbers;
            uint16_t                    num_relocs;
            uint16_t                    num_line_numbers;

            uint32_t					characteristics_flags;
        };

        struct file_header_t
        {
            std::uint16_t machine;
            std::uint16_t num_sections;
            std::uint32_t timedate_stamp;
            std::uint32_t ptr_symbols;
            std::uint32_t num_symbols;
            std::uint16_t size_optional_header;
            std::uint16_t characteristics;
        };

        struct optional_header_x64_t
        {
            // Standard fields.
            uint16_t                    magic;
            version_t                   linker_version;

            uint32_t                    size_code;
            uint32_t                    size_init_data;
            uint32_t                    size_uninit_data;

            uint32_t                    entry_point;
            uint32_t                    base_of_code;

            // NT additional fields.
            uint64_t                    image_base;
            uint32_t                    section_alignment;
            uint32_t                    file_alignment;

            ex_version_t                os_version;
            ex_version_t                img_version;
            ex_version_t                subsystem_version;
            uint32_t                    win32_version_value;

            uint32_t                    size_image;
            uint32_t                    size_headers;

            uint32_t                    checksum;
            subsystem_id                subsystem;
            uint16_t					characteristics;

            uint64_t                    size_stack_reserve;
            uint64_t                    size_stack_commit;
            uint64_t                    size_heap_reserve;
            uint64_t                    size_heap_commit;

            uint32_t                    ldr_flags;

            uint32_t                    num_data_directories;
            data_directories_x64_t      data_directories;
        };

        struct optional_header_x86_t
        {
            // Standard fields.
            uint16_t                    magic;
            version_t                   linker_version;

            uint32_t                    size_code;
            uint32_t                    size_init_data;
            uint32_t                    size_uninit_data;

            uint32_t                    entry_point;
            uint32_t                    base_of_code;
            uint32_t                    base_of_data;

            // NT additional fields.
            uint32_t                    image_base;
            uint32_t                    section_alignment;
            uint32_t                    file_alignment;

            ex_version_t                os_version;
            ex_version_t                img_version;
            ex_version_t                subsystem_version;
            uint32_t                    win32_version_value;

            uint32_t                    size_image;
            uint32_t                    size_headers;

            uint32_t                    checksum;
            subsystem_id                subsystem;
            uint16_t					characteristics;

            uint32_t                    size_stack_reserve;
            uint32_t                    size_stack_commit;
            uint32_t                    size_heap_reserve;
            uint32_t                    size_heap_commit;

            uint32_t                    ldr_flags;

            uint32_t                    num_data_directories;
            data_directories_x86_t      data_directories;

            __forceinline bool has_directory(const data_directory_t* dir) const {
                return &data_directories.entries[num_data_directories] < dir && dir->present();
            }

            __forceinline bool has_directory(directory_id id) const {
                return has_directory(&data_directories.entries[id]);
            }
        };

        template<bool x64 = is_arch_x64>
        using optional_header_t = std::conditional_t<x64, optional_header_x64_t, optional_header_x86_t>;


        template<bool x64 = is_arch_x64>
        struct nt_headers_t
        {
            uint32_t                    signature;
            file_header_t               file_header;
            optional_header_t<x64>      optional_header;

            // Section getters
            __forceinline section_header_t* get_sections() { return (section_header_t*)((uint8_t*)&optional_header + file_header.size_optional_header); }
            __forceinline section_header_t* get_section(size_t n) { return n >= file_header.num_sections ? nullptr : get_sections() + n; }
            __forceinline const section_header_t* get_sections() const { return const_cast<nt_headers_t*>(this)->get_sections(); }
            __forceinline const section_header_t* get_section(size_t n) const { return const_cast<nt_headers_t*>(this)->get_section(n); }

            // Section iterator
            template<typename T>
            struct proxy
            {
                T* base;
                uint16_t count;
                T* begin() const { return base; }
                T* end() const { return base + count; }
            };
            __forceinline proxy<section_header_t> sections() { return { get_sections(), file_header.num_sections }; }
            __forceinline proxy<const section_header_t> sections() const { return { get_sections(), file_header.num_sections }; }
        };

        using nt_headers_x64_t = nt_headers_t<true>;
        using nt_headers_x86_t = nt_headers_t<false>;

        struct dos_header_t
        {
            uint16_t                    e_magic;
            uint16_t                    e_cblp;
            uint16_t                    e_cp;
            uint16_t                    e_crlc;
            uint16_t                    e_cparhdr;
            uint16_t                    e_minalloc;
            uint16_t                    e_maxalloc;
            uint16_t                    e_ss;
            uint16_t                    e_sp;
            uint16_t                    e_csum;
            uint16_t                    e_ip;
            uint16_t                    e_cs;
            uint16_t                    e_lfarlc;
            uint16_t                    e_ovno;
            uint16_t                    e_res[4];
            uint16_t                    e_oemid;
            uint16_t                    e_oeminfo;
            uint16_t                    e_res2[10];
            uint32_t                    e_lfanew;

            __forceinline file_header_t* get_file_header() { return &get_nt_headers<>()->file_header; }
            __forceinline const file_header_t* get_file_header() const { return &get_nt_headers<>()->file_header; }
            template<bool x64 = is_arch_x64> inline nt_headers_t<x64>* get_nt_headers() { return (nt_headers_t<x64>*) ((uint8_t*)this + e_lfanew); }
            template<bool x64 = is_arch_x64> inline const nt_headers_t<x64>* get_nt_headers() const { return const_cast<dos_header_t*>(this)->template get_nt_headers<x64>(); }
        };

        struct image_t
        {
            dos_header_t                dos_header;

            // Basic getters.
            __forceinline dos_header_t* get_dos_headers() { return &dos_header; }
            __forceinline const dos_header_t* get_dos_headers() const { return &dos_header; }
            __forceinline file_header_t* get_file_header() { return dos_header.get_file_header(); }
            __forceinline const file_header_t* get_file_header() const { return dos_header.get_file_header(); }
            __forceinline nt_headers_t<is_arch_x64>* get_nt_headers() { return dos_header.get_nt_headers<is_arch_x64>(); }
            __forceinline const nt_headers_t<is_arch_x64>* get_nt_headers() const { return dos_header.get_nt_headers<is_arch_x64>(); }
            __forceinline optional_header_t<is_arch_x64>* get_optional_header() { return &get_nt_headers()->optional_header; }
            __forceinline const optional_header_t<is_arch_x64>* get_optional_header() const { return &get_nt_headers()->optional_header; }

            __forceinline data_directory_t* get_directory(directory_id id)
            {
                auto nt_hdrs = get_nt_headers();
                if (nt_hdrs->optional_header.num_data_directories <= id)
                    return nullptr;
                data_directory_t* dir = &nt_hdrs->optional_header.data_directories.entries[id];
                return dir->present() ? dir : nullptr;
            }

            __forceinline const data_directory_t* get_directory(directory_id id) const {
                return const_cast<image_t*>(this)->get_directory(id);
            }

            template<typename T = uint8_t>
            __forceinline T* rva_to_ptr(uint32_t rva, size_t length = 1)
            {
                // Find the section, try mapping to header if none found.
                auto scn = rva_to_section(rva);
                if (!scn) {
                    uint32_t rva_hdr_end = get_nt_headers()->optional_header.size_headers;
                    if (rva < rva_hdr_end && (rva + length) <= rva_hdr_end)
                        return (T*)((uint8_t*)&dos_header + rva);
                    return nullptr;
                }

                // Apply the boundary check.
                size_t offset = rva - scn->virtual_address;
                if ((offset + length) > scn->size_raw_data)
                    return nullptr;

                // Return the final pointer.
                return (T*)((uint8_t*)&dos_header + scn->ptr_raw_data + offset);
            }

            __forceinline section_header_t* rva_to_section(uint32_t rva)
            {
                auto nt_hdrs = get_nt_headers();
                for (size_t i = 0; i != nt_hdrs->file_header.num_sections; i++) {
                    auto section = nt_hdrs->get_section(i);
                    if (section->virtual_address <= rva && rva < (section->virtual_address + section->virtual_size))
                        return section;
                }
                return nullptr;
            }

            template<typename T = uint8_t>
            __forceinline const T* rva_to_ptr(uint32_t rva, size_t length = 1) const { return const_cast<image_t*>(this)->template rva_to_ptr<const T>(rva, length); }
            __forceinline uint32_t rva_to_fo(uint32_t rva, size_t length = 1) const { return ptr_to_raw(rva_to_ptr(rva, length)); }
            __forceinline uint32_t ptr_to_raw(const void* ptr) const { return ptr ? uint32_t(uintptr_t(ptr) - uintptr_t(&dos_header)) : img_npos; }
        };

        __forceinline auto image_from_base(std::uintptr_t base_address) {
            return reinterpret_cast<image_t*>(base_address);
        }

        __forceinline auto image_from_base(ldr_data_table_entry* module) {
            return reinterpret_cast<image_t*>(module->dll_base);
        }

        struct module_t
        {
            std::uintptr_t base_address{ 0 };
            std::uintptr_t ep_address{ 0 };
            image_t* image{ nullptr };

            [[nodiscard]] bool is_invalid() const { return base_address == 0 || ep_address == 0 || image == nullptr; }
        };

        template<typename T, typename FieldT>
        constexpr T* containing_record(FieldT* address, FieldT T::* field)
        {
            auto offset = reinterpret_cast<std::uintptr_t>(&(reinterpret_cast<T*>(0)->*field));
            return reinterpret_cast<T*>(reinterpret_cast<std::uintptr_t>(address) - offset);
        }
    }



    consteval std::uint32_t generate_compile_seed() {
        std::uint32_t hash = 0x2438529;
        for (char c : __TIME__) {
            hash ^= static_cast<std::uint32_t>(c) * 0x1928231;
        }
        return hash;
    }

    class hash_t
    {
    public: // Templates, typenames
        static constexpr bool case_sensitive = false;

        template<typename CharT>
        using string_view_t = std::basic_string_view<CharT>;
        using value_t = std::uint32_t;

    public: // Constructors

        explicit hash_t(std::string_view string) { generate<char>(string); }
        explicit hash_t(std::wstring_view string) { generate<wchar_t>(string); }
        constexpr hash_t(value_t hash) : m_value(hash) {}
        constexpr hash_t() = default;
        constexpr ~hash_t() = default;

        template<typename CharT, std::size_t N>
        consteval hash_t(const CharT(&string)[N])
        {
            constexpr auto string_length = N - 1;
            for (std::size_t i = 0; i < string_length; i++)
                m_value += hash_step<CharT>(i, string[i], m_value);
        }

    public: // Methods

        template<typename CharT>
        value_t generate(string_view_t<CharT> string)
        {
            for (std::size_t i = 0; i < string.size(); i++)
                m_value += hash_step<CharT>(i, string[i], m_value);

            return m_value;
        }

        [[nodiscard]] constexpr value_t get() { return m_value; }
        [[nodiscard]] constexpr value_t get() const { return m_value; }

    public: // Operator overloads

        [[nodiscard]] constexpr explicit operator value_t() const { return m_value; }

        constexpr auto operator<=>(const hash_t&) const = default;

        friend std::ostream& operator<<(std::ostream& os, const hash_t& hash) { return os << hash.m_value; }

    private: // Methods

        template<typename CharT>
        constexpr value_t hash_step(std::size_t i, CharT c, value_t current_value) const {
            c = case_sensitive ? c : to_lower<CharT>(c);
            return ((c + i) * 0x8912812) ^ (0x381487 + i * c) + c - ((i * 0x23813) + (current_value + i + c) * 0x31848713);
        }

        template<typename CharT>
        __forceinline constexpr CharT to_lower(CharT c) const {
            return ((c >= 'A' && c <= 'Z') ? (c + 32) : c);
        }

    private: // Variables
        value_t m_value{ generate_compile_seed() };
    };

    // Used in `shadowcall` to create a pair with syntax such as { "name", "name" }
    struct hashpair
    {
        consteval hashpair(shadow::hash_t first_, shadow::hash_t second_) :
            first(first_),
            second(second_)
        {}

        shadow::hash_t first;
        shadow::hash_t second;
    };

    namespace literals {
        __forceinline hash_t operator""_hash(const char* str, size_t) {
            return hash_t(str);
        }
    }

    /// \brief Class that's responsible for parsing exports from DLL
    /// \brief Allowed for external use
    /// \throw Fully `noexcept` constructed, creates no exceptions.
    ///
    class c_exports
    {
    public:
        __forceinline explicit c_exports(void* base_address) noexcept :
            m_module_base(reinterpret_cast<std::uintptr_t>(base_address)),
            m_export_table(get_export_directory(reinterpret_cast<std::uintptr_t>(base_address)))
        {}

        __forceinline explicit c_exports(std::uintptr_t base_address) noexcept :
            m_module_base(base_address),
            m_export_table(get_export_directory(base_address))
        {}

        __forceinline std::size_t size() const noexcept {
            return m_export_table->num_names;
        }

        __forceinline const win::export_directory_t* table() const noexcept {
            return m_export_table;
        }

        __forceinline std::string_view name(std::size_t index) const noexcept
        {
            std::span<const std::uint32_t> rva_names{
                reinterpret_cast<const std::uint32_t*>(m_module_base + m_export_table->rva_names),
                m_export_table->num_names
            };

            std::uint32_t rva_name = rva_names[index];
            const char* name_address = reinterpret_cast<const char*>(m_module_base + rva_name);

            return { name_address };
        }

        __forceinline std::uintptr_t address(std::size_t index) const noexcept
        {
            const auto rva_table = m_export_table->rva_table(m_module_base);
            const auto ordinal_table = m_export_table->ordinal_table(m_module_base);

            std::uint16_t ordinal = ordinal_table[index];
            std::uint32_t rva_function = rva_table[ordinal];
            std::uintptr_t function_address = m_module_base + rva_function;

            return function_address;
        }

        __forceinline bool is_export_forwarded(const std::uintptr_t export_address) const noexcept
        {
            auto image = win::image_from_base(m_module_base);
            auto export_data_dir = image->get_optional_header()->data_directories.export_directory;

            const std::uintptr_t export_table_start = m_module_base + export_data_dir.rva;
            const std::uintptr_t export_table_end = export_table_start + export_data_dir.size;

            return (export_address >= export_table_start) && (export_address < export_table_end);
        }

        class iterator {
        public:
            using iterator_category = std::forward_iterator_tag;
            using value_type = std::pair<std::string_view, std::uintptr_t>;
            using difference_type = std::ptrdiff_t;
            using pointer = value_type*;
            using reference = value_type&;

            __forceinline iterator(const c_exports* exports, std::size_t index) noexcept
                : m_exports(exports), m_index(index), m_value() {
                if (m_index < m_exports->size()) {
                    update_value();
                }
            }

            __forceinline reference operator*() const noexcept {
                thread_local static value_type dummy{};
                return m_value;
            }

            __forceinline pointer operator->() const noexcept {
                thread_local static value_type dummy{};
                return &m_value;
            }

            __forceinline iterator& operator=(const iterator& other) noexcept {
                if (this != &other) {
                    m_index = other.m_index;
                    m_value = other.m_value;
                }
                return *this;
            }

            __forceinline iterator& operator++() noexcept {
                if (m_index < m_exports->size()) {
                    ++m_index;

                    if (m_index < m_exports->size())
                        update_value();
                    else
                        clear_value();
                }
                else {
                    clear_value();
                }
                return *this;
            }

            __forceinline iterator operator++(int) noexcept {
                iterator temp = *this;
                ++(*this);
                return temp;
            }

            bool operator==(const iterator& other) const noexcept {
                return m_index == other.m_index && m_exports == other.m_exports;
            }

            bool operator!=(const iterator& other) const noexcept {
                return !(*this == other);
            }

        private:
            __forceinline void update_value() noexcept {
                auto& [name, address] = m_value;
                if (m_index < m_exports->size()) {
                    name = m_exports->name(m_index);
                    address = m_exports->address(m_index);
                }
            }

            __forceinline void clear_value() noexcept {
                auto& [name, address] = m_value;
                name = "";
                address = 0;
            }

            const c_exports* m_exports;
            std::size_t m_index;
            mutable value_type m_value;
        };

        iterator begin() const noexcept { return iterator(this, 0); }
        iterator end() const noexcept { return iterator(this, size()); }

        /// \brief Finds an export in the specified module.
        /// \param export_name The name of the export to find.
        /// \return Iterator pointing to [name, address] if export is found, or .end() if export is not found.
        /// \note The function is noexcept and provides a strong exception guarantee.
        ///
        __forceinline iterator find(hash_t export_name) const noexcept
        {
            if (export_name == 0)
                return end();

            auto it = std::find_if(begin(), end(), [export_name](const auto& pair) -> bool {
                const auto& [name, address] = pair;
                return export_name == hash_t{}.generate(name);
                });

            return it;
        }

        __forceinline iterator find_if(std::predicate<iterator::value_type> auto predicate)
        {
            return std::find_if(begin(), end(), predicate);
        }

    private:
        __forceinline win::export_directory_t* get_export_directory(std::uintptr_t base_address) const noexcept
        {
            auto image = win::image_from_base(base_address);
            auto export_data_dir = image->get_optional_header()->data_directories.export_directory;
            return reinterpret_cast<win::export_directory_t*>(m_module_base + export_data_dir.rva);
        }

        std::uintptr_t m_module_base;
        win::export_directory_t* m_export_table{ nullptr };
    };


    class c_modules_range
    {
    public:
        __forceinline c_modules_range(bool skip_current_module = false)
        {
            auto entry = &win::peb_t::loader_data()->in_load_order_module_list;

            // Skip current module
            m_begin = (skip_current_module ? entry->flink->flink : entry->flink);
            m_end = entry;
        }

        class iterator
        {
        public:
            __forceinline iterator(win::list_entry* entry) : m_entry(entry) {}

            __forceinline bool operator!=(const iterator& other) const {
                return m_entry != other.m_entry;
            }

            __forceinline iterator& operator++() {
                m_entry = m_entry->flink;
                return *this;
            }

            __forceinline win::ldr_data_table_entry* operator*() const {
                return win::containing_record(m_entry, &win::ldr_data_table_entry::in_load_order_links);
            }

        private:
            win::list_entry* m_entry;
        };

        iterator begin() { return iterator(m_begin); }
        const iterator begin() const { return iterator(m_begin); }

        iterator end() { return iterator(m_end); }
        const iterator end() const { return iterator(m_end); }

    private:
        win::list_entry* m_begin{ nullptr };
        win::list_entry* m_end{ nullptr };
    };



    class c_module
    {
    public:
        c_module() : m_data({}), m_hashed_name(0) {}
        explicit c_module(hash_t module_name) : m_data(find(module_name)), m_hashed_name(module_name) {}

        __forceinline [[nodiscard]] std::optional<win::module_t> get() {
            return m_data.is_invalid() ? std::nullopt : std::make_optional(m_data);
        }

        __forceinline [[nodiscard]] const std::optional<win::module_t> get() const {
            return m_data.is_invalid() ? std::nullopt : std::make_optional(m_data);
        }

        [[nodiscard]] constexpr operator std::uintptr_t() const {
            return m_data.base_address;
        }

        __forceinline auto image() const { return m_data.image; }
        __forceinline auto base_address() const { return m_data.base_address; }
        __forceinline auto entrypoint() const { return m_data.ep_address; }
        __forceinline auto exports() const { return c_exports{ m_data.base_address }; }

        __forceinline win::module_t find(hash_t module_name) const
        {
            for (const auto& module : c_modules_range{})
            {
                if (module->name.buffer == nullptr)
                    continue;

                std::wstring_view dllname{ module->name.to_wstring() };
                if (dllname.empty())
                    continue;

                auto hashed_dllname = hash_t{ dllname };
                if (hashed_dllname != module_name)
                    continue;

                auto base_address = reinterpret_cast<std::uintptr_t>(module->dll_base);
                auto ep_address = reinterpret_cast<std::uintptr_t>(module->entry_point);

                return win::module_t{
                    .base_address = base_address,
                    .ep_address = ep_address,
                    .image = reinterpret_cast<win::image_t*>(base_address)
                };
            }

            return {};
        }

    public:
        win::module_t m_data;

    private:
        hash_t m_hashed_name;
    };

    class c_export
    {
    public:
        __forceinline c_export(hash_t export_name, hash_t module_hash = 0) noexcept :
            m_address(find_export_address(export_name, module_hash))
        {}

        __forceinline std::uintptr_t find_export_address(hash_t export_name, hash_t module_hash = 0) noexcept
        {
            if (export_name == 0)
                return 0;

            constexpr bool skip_current_module = true;
            const auto loaded_modules = c_modules_range{ skip_current_module };

            for (const auto& module : loaded_modules) {

                if (module_hash != 0 && module_hash_invalid(module_hash, module->name.to_wstring()))
                    continue;

                c_exports exports{ module->dll_base };

                auto export_it = exports.find_if([export_name](const auto& pair) -> bool {
                    const auto& [name, address] = pair;
                    return export_name == hash_t{}.generate(name);
                    });

                if (export_it == exports.end())
                    continue;

                const auto& [_, address] = *export_it;
                if (exports.is_export_forwarded(address))
                    return handle_forwarded_export(address);

                return address;
            }

            return 0;
        }

        __forceinline  void* to_pointer() const {
            return reinterpret_cast<void*>(m_address);
        }

        operator std::uintptr_t() {
            return m_address;
        }

    private:
        __forceinline bool module_hash_invalid(hash_t module_hash, std::wstring_view module_name)
        {
            // Try to compare hash of full module name
            auto full_name_hash = hash_t{}.generate(module_name);

            // Try to compare hash of trimmed module name
            auto trimmed_name = module_name.substr(0, module_name.size() - 4);
            auto trimmed_name_hash = hash_t{}.generate(trimmed_name);

            // Verify both hashes
            return full_name_hash != module_hash && trimmed_name_hash != module_hash;
        }

        __forceinline std::uintptr_t handle_forwarded_export(std::uintptr_t address)
        {
            // In a forwarded export, the address is a string containing
            // information about the actual export and its location
            // They are always presented as "module_name.export_name"
            auto forwarded_export_name = reinterpret_cast<const char*>(address);

            // Split forwarded export to module name and real export name
            auto [module_name, real_export_name] = split_forwarded_export_name(forwarded_export_name, '.');

            // Perform call with the name of the real export, with a pre-known module
            return find_export_address(hash_t{}.generate(real_export_name), hash_t{}.generate(module_name));
        }

        __forceinline std::pair<std::string_view, std::string_view> split_forwarded_export_name(
            std::string_view view, char delimiter) const noexcept
        {
            auto pos = view.find(delimiter);
            if (pos != std::string_view::npos) {
                std::string_view first_part = view.substr(0, pos);
                std::string_view second_part = view.substr(pos + 1);
                return { first_part, second_part };
            }

            return { view, {} };
        }

        std::uintptr_t m_address{ 0 };
    };

    ///
    /// Syscall part
    ///

    namespace syscalls
    {
        namespace win::internals
        {
            using NTSTATUS = std::int32_t;

            // `VirtualAlloc` function pseudo-code from `kernelbase.dll`
            __forceinline void* nt_virtual_alloc(std::uintptr_t function_ptr, void* address, std::uint64_t allocation_size, std::uint32_t allocation_t, std::uint32_t flProtect)
            {
                using function_t = NTSTATUS(__stdcall*)(void*, void*, std::uint64_t, std::uint64_t*, std::uint32_t, std::uint32_t);

                void* base_address = address;
                std::uint64_t region_size = allocation_size;

                auto result = reinterpret_cast<function_t>(function_ptr)(reinterpret_cast<void*>(-1), &base_address, 0, &region_size, allocation_t & 0xFFFFFFC0, flProtect);

                return result >= 0 ? base_address : nullptr;
            }

            // `VirtualFree` function pseudo-code from `kernelbase.dll`
            __forceinline bool nt_virtual_free(std::uintptr_t function_ptr, void* address, std::uint64_t allocation_size, std::uint32_t free_t)
            {
                using function_t = NTSTATUS(__stdcall*)(void*, void*, std::uint64_t*, std::uint32_t);

                NTSTATUS result = 0;
                std::uint64_t region_size = allocation_size;
                void* base_address = address;

                if ((free_t & 0xFFFF3FFC) != 0 || (free_t & 0x8003) == 0x8000 && allocation_size)
                    result = -0x3FFFFFF3;

                result = reinterpret_cast<function_t>(function_ptr)(reinterpret_cast<void*>(-1), &base_address, &region_size, free_t);

                if (result == -0x3FFFFFBB)
                    result = reinterpret_cast<function_t>(function_ptr)(reinterpret_cast<void*>(-1), &base_address, &region_size, free_t);

                return result >= 0;
            }
        }



        class c_allocator
        {
        public:
            __forceinline void initialize() noexcept
            {
                if (m_allocate_address && m_free_address)
                    return;

                m_allocate_address = c_export("NtAllocateVirtualMemory", "ntdll.dll");
                m_free_address = c_export("NtFreeVirtualMemory", "ntdll.dll");
            }

            __forceinline void* allocate(std::uint64_t size) const noexcept {
                return win::internals::nt_virtual_alloc(m_allocate_address, nullptr, size, 0x00001000 | 0x00002000, 0x40);
            }

            __forceinline bool free(void* address, std::uint64_t size) const noexcept {
                return win::internals::nt_virtual_free(m_free_address, address, size, 0x00008000);
            }

        private:
            static inline std::uintptr_t m_allocate_address{ 0 };
            static inline std::uintptr_t m_free_address{ 0 };
        };



        template<std::uint32_t shell_size>
        class c_shellcode
        {
        public:
            template<class... Args>
            c_shellcode(Args&&... list) noexcept :
                m_shellcode{ static_cast<std::uint8_t>(std::forward<Args&&>(list))... }
            {
                static_assert((std::is_convertible_v<Args, std::uint8_t> && ...), "All arguments must be convertible to std::uint8_t");
                static_assert(shell_size != 0, "Shellcode size cannot be zero");

                m_allocator.initialize();
            }

            ~c_shellcode()
            {
                if (m_memory == nullptr)
                    return;

                m_allocator.free(m_memory, shell_size);
                m_memory = nullptr;
            }

            __forceinline void setup_shellcode() noexcept
            {
                m_memory = m_allocator.allocate(shell_size);
                if (m_memory == nullptr)
                    return;

                std::memcpy(m_memory, m_shellcode.data(), shell_size);
                m_shellcode_fn = m_memory;
            }

            __forceinline void write_uint32(std::uint32_t index, std::uint32_t value) noexcept {
                *reinterpret_cast<std::uint32_t*>(&m_shellcode[index]) = value;
            }

            void* m_shellcode_fn = nullptr;

        private:
            void* m_memory = nullptr;
            c_allocator m_allocator;
            std::array<std::uint8_t, shell_size> m_shellcode;
        };

#if SHADOWSYSCALLS_CACHING

        /// \brief For internal usage only
        ///
        class c_address_cache
        {
        public:
            using key_t = hash_t::value_t;
            using address_t = std::uintptr_t;

        public:
            __forceinline  address_t get_address(key_t export_hash) {
                std::shared_lock lock(m_cache_mutex);
                auto it = m_cache_map.find(export_hash);
                return it == m_cache_map.end() ? 0 : it->second;
            }

            __forceinline void try_emplace(key_t export_hash, address_t address) {
                std::unique_lock lock(m_cache_mutex);
                m_cache_map.try_emplace(export_hash, address);
            }

            __forceinline bool exists(key_t export_hash) {
                std::shared_lock lock(m_cache_mutex);
                return m_cache_map.find(export_hash) != m_cache_map.end();
            }

        private:
            // Making sure that's every `cache_map` call is safe.
            std::shared_mutex m_cache_mutex{};

            // Store addresses by std::uintptr_t insted of indexes
            // itself, so this map can be reused for importer needs.
            std::unordered_map<key_t, address_t> m_cache_map{};
        } static inline cache;

#endif

        template<typename ReturnType>
        class c_syscall
        {
        public:
            __forceinline explicit c_syscall(hash_t syscall_name) :
                m_syscall_name_hash(syscall_name),
                m_syscall_index(0)
            {}

            template<typename... Args>
            __forceinline ReturnType call(Args... args) noexcept
            {
                get_syscall_id();
                setup_shellcode();
                return reinterpret_cast<ReturnType(__stdcall*)(Args...)>(m_shellcode.m_shellcode_fn)(args...);
            }

        private:
            __forceinline void setup_shellcode() noexcept {
                m_shellcode.write_uint32(6, m_syscall_index);
                m_shellcode.setup_shellcode();
            }

            __forceinline void get_syscall_id()
            {
#if SHADOWSYSCALLS_CACHING
                if (auto address = cache.get_address(m_syscall_name_hash); address != 0) {
                    m_syscall_index = parse_syscall_id(address);
                    return;
                }
#endif

                auto routine_address = c_export(m_syscall_name_hash);

#if SHADOWSYSCALLS_CACHING
                cache.try_emplace(m_syscall_name_hash, routine_address);
#endif

                m_syscall_index = parse_syscall_id(routine_address);
            }

            // Syscall ID is at an offset of 4 bytes from the specified address.
            __forceinline std::uint32_t parse_syscall_id(std::uintptr_t export_address) const {
                return *reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(export_address + 4));
            }

        private:
            hash_t::value_t m_syscall_name_hash;
            std::uint32_t m_syscall_index;

            c_shellcode<13> m_shellcode =
            {
                0x49, 0x89, 0xCA,                           // mov r10, rcx
                0x48, 0xC7, 0xC0, 0x3F, 0x10, 0x00, 0x00,   // mov rax, syscall_index
                0x0F, 0x05,                                 // syscall
                0xC3                                        // ret
            };
        };


        template<typename ReturnType>
        class c_importer
        {
        public:
            __forceinline explicit c_importer(hash_t import_name, hash_t module_name = 0) :
                m_export_address(get_export_address(import_name, module_name))
            {}

            template<typename... Args>
            __forceinline ReturnType call(Args... args) noexcept
            {
                if (m_export_address == 0)
                    return ReturnType{};

                return reinterpret_cast<ReturnType(__stdcall*)(Args...)>(m_export_address)(args...);
            }

        private:
            __forceinline std::uintptr_t get_export_address(hash_t import_name, hash_t module_name)
            {
#if SHADOWSYSCALLS_CACHING
                auto address = cache.get_address(static_cast<c_address_cache::key_t>(import_name));
                if (address == 0) {
                    address = c_export(import_name, module_name);
                    cache.try_emplace(static_cast<c_address_cache::key_t>(import_name), address);
                }

                return address;
#else
                return c_export(import_name);
#endif
            }

            std::uintptr_t m_export_address{ 0 };
        };

        template <typename T>
        __forceinline auto convert_nulls_to_nullptrs(T arg)
        {
            // All credits to @Debounce, huge thanks to him/her!
            //
            // Since arguments after the fourth are written on the stack,
            // the compiler will fill the lower 32 bits from int with null,
            // and the upper 32 bits will remain undefined.
            //
            // Because the syscall handler expects a (void*)-sized pointer
            // there, this address will be garbage for it, hence AV.
            // If the argument went 1/2/3/4, the compiler would generate a
            // write to ecx/edx/r8d/r9d, by x64 convention, writing to the
            // lower half of a 64 - bit register zeroes the upper part too
            // ( i.e.ecx = 0 = > rcx = 0 ), so this problem should only exist
            // on x64 for arguments after the fourth.
            // The solution would be on templates to loop through all
            // arguments and manually cast them to size_t size.

            constexpr auto is_signed_integral = std::signed_integral<T>;
            constexpr auto is_unsigned_integral = std::unsigned_integral<T>;

            using unsigned_integral_type = std::conditional_t<is_unsigned_integral, std::uintptr_t, T>;
            using tag_type = std::conditional_t<is_signed_integral, std::intptr_t, unsigned_integral_type>;

            return static_cast<tag_type>(arg);
        }
    }
}

template <>
struct std::hash<shadow::hash_t> {
    size_t operator()(const shadow::hash_t& instance) const noexcept {
        return std::hash<shadow::hash_t::value_t>()(instance.get());
    }
};

template<typename ReturnType, class... Args>
__forceinline ReturnType shadowsyscall(shadow::hash_t syscall_name, Args&&... args)
{
    static_assert((shadow::is_arch_x64 && !std::is_same_v<ReturnType, std::monostate>),
        "shadowsyscall is not supported on the x86 architecture");

    shadow::syscalls::c_syscall<ReturnType> syscall{ syscall_name };
    return syscall.call(shadow::syscalls::convert_nulls_to_nullptrs(args) ...);
}

template<typename ReturnType, class... Args>
__forceinline ReturnType shadowcall(shadow::hash_t export_name, Args&&... args)
{
    shadow::syscalls::c_importer<ReturnType> importer{ export_name };
    return importer.call(shadow::syscalls::convert_nulls_to_nullptrs(args) ...);
}

template<typename ReturnType, class... Args>
__forceinline ReturnType shadowcall(shadow::hashpair export_and_module_names, Args&&... args)
{
    const auto& [export_name, module_name] = export_and_module_names;
    shadow::syscalls::c_importer<ReturnType> importer{ export_name, module_name };
    return importer.call(shadow::syscalls::convert_nulls_to_nullptrs(args) ...);
}

#endif