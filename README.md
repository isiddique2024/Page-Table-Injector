# Physical Memory Manual Mapper (PM-Mapper)

## Overview

PM-Mapper is an advanced driver and DLL injection tool that uses direct physical memory manipulation to inject code into target processes. By modifying the target process' page tables, it can bypass many common anti-cheat and anti-tampering mechanisms that monitor virtual memory operations via the VAD (Virtual Address Descriptor) tree.

Tested from **Windows 10 20H2 19042** to **Windows 11 24H2 26100.3775** 

## Video Showcase

https://github.com/user-attachments/assets/1f3a2385-42e8-497b-a738-0909e9a77cf6


## Features

- **Driver Allocation Methods**:
    - Allocate within system context 
    - Map driver within ntoskrnl's .data section
    - Allocate at a non present PML4E address within current process context in kernel space (PML4 index 256 - 511)
- **Driver Memory Page Types**:
    - Normal Pages (4KB)
    - Large Pages (2MB)
    - Huge Pages (1GB) (not yet supported)
- **DLL Allocation Methods**:
    - Hijack PTEs with PTE.PageFrameNumber = 0 within the main module's .text section
    - Allocate between legitimate modules
    - Allocate at a non present PML4E address in usermode space (PML4 index 0 - 255)
    - Allocate at a non present PML4E address in kernel space (PML4 index 256 - 511)
- **DLL Memory Page Types**:
    - Normal Pages (4KB)
    - Large Pages (2MB)
    - Huge Pages (1GB) (not yet supported)
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
pm-mapper.exe [window_name] [dll_path] [driver_alloc_mode] [driver_memory_type] [dll_alloc_mode] [dll_memory_type] [hook_module] [hook_function] [target_module]
```

### Parameters

- **window_name**: Name of the target window (e.g., "Notepad") (required)
- **dll_path**: Path to the DLL file to inject, or "memory" to use the in-memory message box DLL (default: memory)
- **driver_alloc_mode**: Driver memory allocation strategy
    - 0: ALLOC_IN_SYSTEM_CONTEXT 
    - 1: ALLOC_IN_NTOSKRNL_DATA_SECTION
    - 2: ALLOC_IN_CURRENT_PROCESS_CONTEXT (kernel space) (default)
- **driver_memory_type**: Driver memory page size to use
    - 0: NORMAL_PAGE (4KB pages) (default)
    - 1: LARGE_PAGE (2MB pages) 
    - 2: HUGE_PAGE (1GB pages) (not yet supported)
- **dll_alloc_mode**: DLL memory allocation strategy
    - 0: ALLOC_INSIDE_MAIN_MODULE 
    - 1: ALLOC_BETWEEN_LEGIT_MODULES (default)
    - 2: ALLOC_AT_LOW_ADDRESS (usermode space)
    - 3: ALLOC_AT_HIGH_ADDRESS (kernel space)
- **dll_memory_type**: DLL memory page size to use
    - 0: NORMAL_PAGE (4KB pages) (default)
    - 1: LARGE_PAGE (2MB pages) 
    - 2: HUGE_PAGE (1GB pages) (not yet supported)
- **hook_module**: Module to hook in the IAT (default: user32.dll)
- **hook_function**: Function to hook in the IAT (default: GetMessageW)
- **target_module**: Module whose IAT to hook (default: Main Module)

### Example

```
pm-mapper.exe Notepad C:\path\to\payload.dll 0 0 1 0 user32.dll GetMessageW Notepad.exe
```

This command maps the driver into system memory, injects payload.dll into the Notepad process with memory allocated strategically inbetween two legitimate modules for evasion, and hooks the GetMessageW API function in user32.dll for entry point execution - all operations use standard 4KB memory pages.

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

- Each allocated physical page for the DLL has its MMPFN.e3.ParityError flag set to 1
- This modification causes ntoskrnl's MmCopyMemory function to return STATUS_HARDWARE_MEMORY_ERROR (0xC0000709) on each physical address of the injected code.
- Additional protection options include removing pages from OS physical memory ranges and clearing the PFN entry from MmPfnDatabase, OR just setting the PfnExists bit to 0 within the PFN entry. Both of these cause MmCopyMemory to return STATUS_INVALID_ADDRESS (0xC0000141) (this is not implemented within the CLI options, please refer to the mem::hide_physical_memory function within mem/mem.h in the driver project)
- The kernel treats these pages as having hardware memory errors, preventing inspection. Feel free to test this using [PTView](https://github.com/VollRagm/PTView), you will notice empty bytes when trying to dump the pages to disk.

The built-in driver also maintains this same protection by calling MmMarkPhysicalMemoryAsBad on each allocated page.

### Driver Allocation Techniques

The tool uses three main techniques for the driver memory allocation:

1. **In System Context**: Utilizes the system's kernel paging tables for allocation (MmAllocateIndependentPages).
2. **Inside Ntoskrnl .data Section:** Finds and repurposes unused memory within ntoskrnl's .data section.
3. **At Non Present PML4E Within Current Process Context**: Allocates memory at a non present PML4E address in kernel space (PML4 index 256-511), but keeps it within the current process' context.

### DLL Allocation Techniques

The tool uses three main techniques for the DLL memory allocation:

1. **Between Legitimate Modules**: Finds gaps between existing DLLs and allocates memory in these spaces.
2. **Inside Main Module**: Finds and repurposes unused memory within the main module range (hijacking null PFNs within the main module range).
3. **At Non Present PML4E**: Allocates memory at a non present PML4E address in usermode OR kernel space (PML4 index 0-255; PML4 index 256-511)

## Security Notes

This tool is designed for educational and research purposes only. It demonstrates advanced memory manipulation techniques that operate at the kernel level. Use responsibly and only on systems you own or have explicit permission to test. This is an older project of mine which I've decided to release, it is likely detected on most anti-cheat solutions by now.

## Detection Test Cases

I've implemented a proof of concept full page table walk detection for this project which can be found in mem/detection.hpp inside the kernel driver project. The test case can be ran by calling detections::inspect_process_page_tables with the target process id as the argument. Below is an example detection report of a low address allocation where each physical page has MMPFN.e3.ParityError set to 1. Another detection method is walking through MmPfnDatabase and checking for MMPFN.e3.ParityError set to 1, but I have not yet implemented this. 

![detection_test_cases](https://github.com/user-attachments/assets/0fde3456-84d4-40d6-93b0-2940e0793b65)

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
 - Process-context specific kernel driver mapper idea taken from: https://git.back.engineering/IDontCode/PSKDM
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
