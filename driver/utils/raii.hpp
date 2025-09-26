#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include "../def/ia32.hpp"
#include "../def/def.hpp"
#include "../mem/mem.hpp"
#include "../utils/utils.hpp"

namespace raii {
  // RAII wrapper for kernel memory
  class kernel_memory {
    void* ptr_;
    size_t size_;

    // prevent copying - private with empty definitions
    kernel_memory(const kernel_memory&) {}
    kernel_memory& operator=(const kernel_memory&) {
      return *this;
    }

  public:
    explicit kernel_memory(size_t size) : ptr_(nullptr), size_(size) {
      ptr_ = mem::allocate_independent_pages(size);
      log("RAII", "kernel_memory allocated: 0x%p, size: 0x%llx", ptr_, size_);
    }

    ~kernel_memory() {
      if (ptr_) {
        log("RAII", "kernel_memory freeing: 0x%p, size: 0x%llx", ptr_, size_);
        globals::mm_free_independent_pages(reinterpret_cast<uintptr_t>(ptr_), size_);
      }
    }

    void* get() const {
      return ptr_;
    }

    void* release() {
      void* temp = ptr_;
      if (ptr_) {
        log("RAII", "kernel_memory releasing ownership: 0x%p", ptr_);
        ptr_ = nullptr;
      }
      return temp;
    }

    bool is_valid() const {
      return ptr_ != nullptr;
    }
  };

  // RAII wrapper for process/thread references
  template <typename T>
  class kernel_object_ref {
    T* object_;
    const char* type_name_;

    // prevent copying - private with empty definitions
    kernel_object_ref(const kernel_object_ref&) {}
    kernel_object_ref& operator=(const kernel_object_ref&) {
      return *this;
    }

  public:
    explicit kernel_object_ref(T* obj = nullptr, const char* type = "object")
        : object_(obj), type_name_(type) {
      if (object_) {
        log("RAII", "kernel_object_ref<%s> acquired: 0x%p", type_name_, object_);
      }
    }

    ~kernel_object_ref() {
      if (object_) {
        log("RAII", "kernel_object_ref<%s> dereferencing: 0x%p", type_name_, object_);
        globals::obf_dereference_object(object_);
      }
    }

    T* get() const {
      return object_;
    }

    T* release() {
      T* temp = object_;
      if (object_) {
        log("RAII", "kernel_object_ref<%s> releasing ownership: 0x%p", type_name_, object_);
        object_ = nullptr;
      }
      return temp;
    }

    bool is_valid() const {
      return object_ != nullptr;
    }
  };

  // RAII wrapper for handles
  class kernel_handle {
    HANDLE handle_;

    // prevent copying - private with empty definitions
    kernel_handle(const kernel_handle&) {}
    kernel_handle& operator=(const kernel_handle&) {
      return *this;
    }

  public:
    explicit kernel_handle(HANDLE h = nullptr) : handle_(h) {
      if (handle_) {
        log("RAII", "kernel_handle acquired: 0x%p", handle_);
      }
    }

    ~kernel_handle() {
      if (handle_) {
        log("RAII", "kernel_handle closing: 0x%p", handle_);
        globals::zw_close(handle_);
      }
    }

    HANDLE get() const {
      return handle_;
    }
    HANDLE* address_of() {
      return &handle_;
    }

    HANDLE release() {
      HANDLE temp = handle_;
      if (handle_) {
        log("RAII", "kernel_handle releasing ownership: 0x%p", handle_);
        handle_ = nullptr;
      }
      return temp;
    }

    bool is_valid() const {
      return handle_ != nullptr;
    }
  };

  // convenience type aliases for common kernel objects
  using process_ref = kernel_object_ref<_KPROCESS>;
  using thread_ref = kernel_object_ref<_KTHREAD>;
}  // namespace raii