# Physical Memory Manual Mapper (PM-Mapper)

## Overview

PM-Mapper is an advanced DLL injection tool that uses direct physical memory manipulation to inject code into target processes. By modifying the target process' page tables, it can bypass many common anti-cheat and anti-tampering mechanisms that monitor virtual memory operations via the VAD (Virtual Address Descriptor) tree.

Tested from **Windows 10 20H2 19042** to **Windows 11 24H2 26100.3775** 

## Video Showcase

https://github.com/user-attachments/assets/1f3a2385-42e8-497b-a738-0909e9a77cf6


## Features

- **Multiple Allocation Methods**:
    
    - Hijack PTEs with PTE.PageFrameNumber = 0 within the main module
    - Allocate between legitimate modules
    - Allocate at a non present PML4E address in usermode space (PML4 index 0 - 255)
    - Allocate at a non present PML4E address in kernel space (PML4 index 256 - 511)
- **Memory Page Types**:
    
    - Normal Pages (4KB)
    - Large Pages (2MB) (not yet implemented)
    - Huge Pages (1GB) (not yet implemented)
- **Advanced Anti-Detection Mechanisms**:
    
    - Marks the MMPFN's ParityError bit to 1 in the _MMPFNENTRY3 structure
    - Causes MmCopyMemory to return NTSTATUS 0xC0000709 (STATUS_HARDWARE_MEMORY_ERROR) on the DLL physical pages
    - Many anti-cheat systems use MmCopyMemory to copy malicious pages, this effectively bypasses basic signature scan detections.
    - Driver uses MmMarkPhysicalMemoryAsBad on each allocated page for persistent protection
- **Support for Various Payloads**:
    
    - Load DLL from disk
    - Use embedded in-memory DLL (MessageBox by default)

## Usage

```
pm-mapper.exe [window_name] [dll_path] [memory_type] [alloc_mode] [hook_module] [hook_function] [target_module]
```

### Parameters

- **window_name**: Name of the target window (e.g., "Notepad") (required)
- **dll_path**: Path to the DLL file to inject, or "memory" to use the in-memory message box DLL (default: memory)
- **memory_type**: Memory page size to use
    - 0: NORMAL_PAGE (4KB pages) (default)
    - 1: LARGE_PAGE (2MB pages) (not yet implemented)
    - 2: HUGE_PAGE (1GB pages) (not yet implemented)
- **alloc_mode**: Memory allocation strategy
    - 0: ALLOC_INSIDE_MAIN_MODULE 
    - 1: ALLOC_BETWEEN_LEGIT_MODULES (default)
    - 2: ALLOC_AT_LOW_ADDRESS (usermode space)
    - 3: ALLOC_AT_HIGH_ADDRESS (kernel space)
- **hook_module**: Module to hook in the IAT (default: user32.dll)
- **hook_function**: Function to hook in the IAT (default: GetMessageW)
- **target_module**: Module whose IAT to hook (default: Main Module)

### Example

```
pm-mapper.exe Notepad C:\path\to\payload.dll 0 1 user32.dll GetMessageW Notepad.exe
```

This command injects the payload.dll into Notepad using normal pages, allocating between legitimate modules, and hooking the GetMessageW function from user32.dll in Notepad.exe's IAT.

## Technical Details

PM-Mapper operates at a kernel level using direct page table manipulation instead of traditional memory APIs such as ZwAllocateVirtualMemory/NtAllocateVirtualMemory. This approach makes detection significantly more difficult as it bypasses common monitoring mechanisms that operate at the virtual memory level.

### Pure Physical Memory Access

A key distinguishing feature of this project is its exclusive use of physical memory operations:

- **No Process Context Switching**: Unlike traditional DLL injectors, PM-Mapper never uses KeStackAttachProcess to attach to the target process context
- **Direct Physical Memory Manipulation**: All memory operations are performed through direct physical memory access
- **Page Table Modification**: Memory allocation is achieved by directly manipulating page tables at the physical level
- **Cross-Context Operation**: Can modify any process's memory without ever entering its execution context

This approach makes the injection practically invisible to security solutions that monitor for process context switches or virtual memory operations.

### Signature Scan Protection Mechanism

The tool employs a sophisticated protection mechanism by manipulating the Physical Frame Number (PFN) database entries:

- Each allocated physical page has its MMPFN.e3.ParityError flag set to 1
- This modification causes ntoskrnl's MmCopyMemory function to return STATUS_HARDWARE_MEMORY_ERROR (0xC0000709) on each physical address of the injected code.
- Additional protection options include removing pages from OS physical memory ranges and clearing the PFN entry from MmPfnDatabase, OR just setting the PfnExists bit to 0 within the PFN entry. Both of these cause MmCopyMemory to return STATUS_INVALID_ADDRESS (0xC0000141) (this is not implemented within the CLI options, please refer to the mem::hide_physical_memory function within mem/mem.h in the driver project)
- The kernel treats these pages as having hardware memory errors, preventing inspection. Feel free to test this using [PTView](https://github.com/VollRagm/PTView), you will notice empty bytes when trying to dump the pages to disk.

The built-in driver also maintains this same protection by calling MmMarkPhysicalMemoryAsBad on each allocated page.

### Allocation Techniques

The tool uses three main techniques for memory allocation:

1. **Between Legitimate Modules**: Finds gaps between existing DLLs and allocates memory in these spaces.
2. **Inside Main Module**: Finds and repurposes unused memory within the main module range (hijacking null PFNs within the main module range).
3. **At Non Present PML4E**: Allocates memory at a non present PML4E address in usermode OR kernel space (PML4 index 0-255; PML4 index 256-511)

## Security Notes

This tool is designed for educational and research purposes only. It demonstrates advanced memory manipulation techniques that operate at the kernel level. Use responsibly and only on systems you own or have explicit permission to test. This is an older project of mine which I've decided to release, it is likely detected on most anti-cheat solutions by now.

## Building from Source

The project requires:

- Visual Studio 2019 or newer
- Windows SDK 10
- Windows Driver Kit (WDK), matching version with Windows SDK
- C++20 or later

To build:

1. Clone the repository
2. Open the solution in Visual Studio
3. Ensure the SDK and WDK are properly installed and configured within the project settings
4. Build in Release mode for x64 architecture

## Credits
 - CLI parsing library: https://github.com/CLIUtils/CLI11
 - Physical memory read/write: https://github.com/SamuelTulach/DirectPageManipulation
 - Some injector ideas taken from: https://github.com/KANKOSHEV/face-injector-v2
 - Kernel driver manual mapper: https://github.com/TheCruZ/kdmapper
 - Import hash/direct syscall library: https://github.com/annihilatorq/shadow_syscall
 - PDB symbol parsing: https://github.com/i1tao/EzPDB

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for full details.

### Important Notice

This software is provided for **EDUCATIONAL AND RESEARCH PURPOSES ONLY**. 

By using this software, you acknowledge that:
- You will only use this software for educational, research, and non-commercial purposes
- You will not use this software for any malicious purposes including unauthorized access to computer systems
- You understand the potential legal implications of misusing the techniques demonstrated
- You accept all responsibility for how you choose to use this software

The creators and contributors of this project cannot be held responsible for any misuse of this software or the techniques it demonstrates.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
