#include "memory_manager.hpp"
#include "trace_cleaner.hpp"

// status definitions
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

// IO status block struct
typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// object attributes struct
typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) \
  {                                               \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);      \
    (p)->RootDirectory = r;                       \
    (p)->Attributes = a;                          \
    (p)->ObjectName = n;                          \
    (p)->SecurityDescriptor = s;                  \
    (p)->SecurityQualityOfService = NULL;         \
  }

// forward declarations for external NT functions
extern "C" {
NTSTATUS NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
                               PVOID IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer,
                               ULONG InputBufferLength, PVOID OutputBuffer,
                               ULONG OutputBufferLength);
}

auto memory_manager_t::read_memory(HANDLE device_handle, std::uint64_t address, void* buffer,
                                   std::uint64_t size) -> bool {
  return mem_copy(device_handle, reinterpret_cast<std::uint64_t>(buffer), address, size);
}

auto memory_manager_t::write_memory(HANDLE device_handle, std::uint64_t address, void* buffer,
                                    std::uint64_t size) -> bool {
  return mem_copy(device_handle, address, reinterpret_cast<std::uint64_t>(buffer), size);
}

auto memory_manager_t::mem_copy(HANDLE device_handle, std::uint64_t destination,
                                std::uint64_t source, std::uint64_t size) -> bool {
  if (!destination || !source || !size) {
    return false;
  }

  copy_memory_buffer_info_t copy_memory_buffer = {0};
  copy_memory_buffer.case_number = 0x33;
  copy_memory_buffer.source = source;
  copy_memory_buffer.destination = destination;
  copy_memory_buffer.length = size;

  IO_STATUS_BLOCK io_status_block;
  auto status =
      NtDeviceIoControlFile(device_handle, nullptr, nullptr, nullptr, &io_status_block, ioctl1,
                            &copy_memory_buffer, sizeof(copy_memory_buffer), nullptr, 0);

  return NT_SUCCESS(status);
}

auto memory_manager_t::get_physical_address(HANDLE device_handle, std::uint64_t address,
                                            std::uint64_t* out_physical_address) -> bool {
  if (!address) {
    return false;
  }

  get_phys_address_buffer_info_t get_phys_address_buffer = {0};
  get_phys_address_buffer.case_number = 0x25;
  get_phys_address_buffer.address_to_translate = address;

  IO_STATUS_BLOCK io_status_block;
  auto status = NtDeviceIoControlFile(
      device_handle, nullptr, nullptr, nullptr, &io_status_block, ioctl1, &get_phys_address_buffer,
      sizeof(get_phys_address_buffer), &get_phys_address_buffer, sizeof(get_phys_address_buffer));

  if (!NT_SUCCESS(status)) {
    return false;
  }

  *out_physical_address = get_phys_address_buffer.return_physical_address;
  return true;
}

auto memory_manager_t::map_io_space(HANDLE device_handle, std::uint64_t physical_address,
                                    std::uint32_t size) -> std::uint64_t {
  if (!physical_address || !size) {
    return 0;
  }

  map_io_space_buffer_info_t map_io_space_buffer = {0};
  map_io_space_buffer.case_number = 0x19;
  map_io_space_buffer.physical_address_to_map = physical_address;
  map_io_space_buffer.size = size;

  IO_STATUS_BLOCK io_status_block;
  auto status = NtDeviceIoControlFile(device_handle, nullptr, nullptr, nullptr, &io_status_block,
                                      ioctl1, &map_io_space_buffer, sizeof(map_io_space_buffer),
                                      &map_io_space_buffer, sizeof(map_io_space_buffer));

  if (!NT_SUCCESS(status)) {
    return 0;
  }

  return map_io_space_buffer.return_virtual_address;
}

auto memory_manager_t::unmap_io_space(HANDLE device_handle, std::uint64_t address,
                                      std::uint32_t size) -> bool {
  if (!address || !size) {
    return false;
  }

  unmap_io_space_buffer_info_t unmap_io_space_buffer = {0};
  unmap_io_space_buffer.case_number = 0x1A;
  unmap_io_space_buffer.virt_address = address;
  unmap_io_space_buffer.number_of_bytes = size;

  IO_STATUS_BLOCK io_status_block;
  auto status =
      NtDeviceIoControlFile(device_handle, nullptr, nullptr, nullptr, &io_status_block, ioctl1,
                            &unmap_io_space_buffer, sizeof(unmap_io_space_buffer), nullptr, 0);

  return NT_SUCCESS(status);
}

auto memory_manager_t::write_to_read_only_memory(HANDLE device_handle, std::uint64_t address,
                                                 void* buffer, std::uint32_t size) -> bool {
  if (!address || !buffer || !size) {
    return false;
  }

  std::uint64_t physical_address = 0;
  if (!get_physical_address(device_handle, address, &physical_address)) {
    return false;
  }

  auto mapped_physical_memory = map_io_space(device_handle, physical_address, size);
  if (!mapped_physical_memory) {
    return false;
  }

  auto result = write_memory(device_handle, mapped_physical_memory, buffer, size);
  unmap_io_space(device_handle, mapped_physical_memory, size);

  return result;
}

auto memory_manager_t::allocate_independent_pages(HANDLE device_handle, std::uint32_t size)
    -> std::uint64_t {
  std::uint64_t allocated_pages = 0;
  if (!call_kernel_function(device_handle, &allocated_pages,
                            g_driver_mapper->get_pdb_offsets().MmAllocateIndependentPages, size, -1,
                            0, 0)) {
    return 0;
  }

  if (!set_page_protection(device_handle, allocated_pages, size, PAGE_EXECUTE_READWRITE)) {
    free_independent_pages(device_handle, allocated_pages, size);
    return 0;
  }

  return allocated_pages;
}

auto memory_manager_t::free_independent_pages(HANDLE device_handle, std::uint64_t address,
                                              std::uint32_t size) -> bool {
  std::uint64_t result = 0;
  return call_kernel_function(device_handle, &result,
                              g_driver_mapper->get_pdb_offsets().MmFreeIndependentPages, address,
                              size);
}

auto memory_manager_t::set_page_protection(HANDLE device_handle, std::uint64_t address,
                                           std::uint32_t size, std::uint32_t new_protect) -> bool {
  BOOLEAN set_prot_status = FALSE;
  if (!call_kernel_function(device_handle, &set_prot_status,
                            g_driver_mapper->get_pdb_offsets().MmSetPageProtection, address, size,
                            new_protect)) {
    return false;
  }

  return set_prot_status;
}

auto memory_manager_t::allocate_contiguous_memory(HANDLE device_handle, std::size_t size) -> void* {
  if (!size) {
    return 0;
  }

  PHYSICAL_ADDRESS max_address{};
  max_address.QuadPart = MAXULONG64;

  void* virtual_address = nullptr;
  call_kernel_function(device_handle, &virtual_address,
                       g_driver_mapper->get_pdb_offsets().MmAllocateContiguousMemory, size,
                       max_address);

  return virtual_address;
}

auto memory_manager_t::free_contiguous_memory(HANDLE device_handle, void* virtual_address) -> void {
  if (!virtual_address) {
    return;
  }

  call_kernel_function<void>(device_handle, nullptr,
                             g_driver_mapper->get_pdb_offsets().MmFreeContiguousMemory,
                             virtual_address);
}

auto memory_manager_t::allocate_kernel_pool(HANDLE device_handle, std::size_t size, ULONG pool_type,
                                            ULONG tag) -> std::uint64_t {
  if (!device_handle || !size) {
    return 0;
  }

  // get ExAllocatePoolWithTag export
  static std::uint64_t kernel_ex_allocate_pool_with_tag = 0;
  if (!kernel_ex_allocate_pool_with_tag) {
    kernel_ex_allocate_pool_with_tag = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "ExAllocatePoolWithTag");
    if (!kernel_ex_allocate_pool_with_tag) {
      mapper_log("ERROR", "failed to find ExAllocatePoolWithTag");
      return 0;
    }
  }

  // call ExAllocatePoolWithTag
  void* allocated_memory = nullptr;
  if (!call_kernel_function(device_handle, &allocated_memory, kernel_ex_allocate_pool_with_tag,
                            pool_type, size, tag)) {
    mapper_log("ERROR", "ExAllocatePoolWithTag failed");
    return 0;
  }

  if (!allocated_memory) {
    mapper_log("ERROR", "ExAllocatePoolWithTag returned null");
    return 0;
  }

  return reinterpret_cast<std::uint64_t>(allocated_memory);
}

auto memory_manager_t::free_kernel_pool(HANDLE device_handle, std::uint64_t address) -> bool {
  if (!device_handle || !address) {
    return false;
  }

  // get ExFreePoolWithTag export
  static std::uint64_t kernel_ex_free_pool_with_tag = 0;
  if (!kernel_ex_free_pool_with_tag) {
    kernel_ex_free_pool_with_tag = g_utils->get_kernel_module_export(
        device_handle, g_driver_mapper->get_ntoskrnl_base(), "ExFreePoolWithTag");
    if (!kernel_ex_free_pool_with_tag) {
      // fallback to ExFreePool if ExFreePoolWithTag is not available
      kernel_ex_free_pool_with_tag = g_utils->get_kernel_module_export(
          device_handle, g_driver_mapper->get_ntoskrnl_base(), "ExFreePool");
      if (!kernel_ex_free_pool_with_tag) {
        mapper_log("ERROR", "failed to find ExFreePool/ExFreePoolWithTag");
        return false;
      }
    }
  }

  // call ExFreePoolWithTag/ExFreePool
  return call_kernel_function<void>(device_handle, nullptr, kernel_ex_free_pool_with_tag,
                                    reinterpret_cast<void*>(address));
}
