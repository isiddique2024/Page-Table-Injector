# Page Table Injector (PT-Injector)

## Overview

PT-Injector is an advanced driver and DLL injection tool that uses direct physical memory manipulation to inject code into target processes. By modifying the target process' page tables, it can bypass many common anti-cheat and anti-tampering mechanisms that monitor virtual memory operations via the VAD (Virtual Address Descriptor) tree.

Tested from **Windows 10 20H2 19042** to **Windows 11 24H2 26100.6584**

## Video Showcase

https://github.com/user-attachments/assets/1f3a2385-42e8-497b-a738-0909e9a77cf6

## Features
- **DLL Execution Methods**:
	- IAT Hook (`iat`) - Hook Import Address Table to execute DLL entry point (default)
	- Thread Creation (`thread`) - Create thread (RtlCreateUserThread) for DLL entry point execution
	- SetWindowsHookEx (`swhk`) - SetWindowsHookEx for DLL entry point execution
- **Driver Allocation Methods**:
    - System context allocation (`system`)
    - Map driver within ntoskrnl's .data section (`.data`)
    - Allocate at a non present PML4E address within current process context in kernel space (`current-process`) - PML4 index 256-511
- **Driver Memory Page Types**:
    - Normal Pages (`normal`) - 4KB
    - Large Pages (`large`) - 2MB
    - Huge Pages (`huge`) - 1GB (not yet supported)
- **DLL Allocation Methods**:
    - Hijack PTEs with PTE.PageFrameNumber = 0 within the main module's .text section (`inside-main`)
    - Allocate between legitimate modules (`between-modules`)
    - Allocate at a non present PML4E address in usermode space (`low-address`) - PML4 index 0-255
    - Allocate at a non present PML4E address in kernel space (`high-address`) - PML4 index 256-511
    - Hyperspace context allocation (`hyperspace`) - Creates isolated memory context with cloned address space of target process
- **DLL Memory Page Types**:
    - Normal Pages (`normal`) - 4KB
    - Large Pages (`large`) - 2MB
    - Huge Pages (`huge`) - 1GB
- **Advanced Memory Hiding Mechanisms**:
    - No hiding (`none`) - Standard memory allocation
    - PFN exists bit manipulation (`pfn_exists_bit`) - Returns STATUS_INVALID_ADDRESS if copied by MmCopyMemory
    - Physical memory removal (`mi_remove_physical_memory`) - Removes pages from OS physical memory ranges  
    - Parity error bit (`set_parity_error`) - Returns STATUS_HARDWARE_MEMORY_ERROR on memory copy (default)
    - Lock bit anti-debug (`set_lock_bit`) - Causes system crash if page is copied by MmCopyMemory
    - Hide translation (`hide_translation`) - Sets the PteAddress field within the MmPfnDatabase entry to 0, this causes MmGetVirtualForPhysical to translate the physical address to the wrong virtual address, 0 in this case
- **Experimental Mechanisms**:
    - No hiding (`none`) - No experimental operations
    - Manipulate MiSystemPartition (`manipulate_mi_system_partition`) - Results in Windows reporting the incorrect OS physical memory ranges
- **Support for Various Payloads**:
    - Load DLL from disk
    - Use embedded in-memory DLL (MessageBox by default)
- **Enhanced User Experience**:
    - Intuitive command-line interface with named arguments
    - Verbose logging mode for detailed operation insights
    - Dry-run mode for configuration preview
    - Comprehensive help with examples
    - Input validation and error handling

## Usage

```
pt-injector.exe <target> [OPTIONS]
```

### Basic Usage Examples

```cmd
# Inject embedded DLL into Notepad using default settings (IAT hook)
pt-injector.exe Notepad

# Inject custom DLL using IAT hook (default)
pt-injector.exe Notepad -d payload.dll

# Inject embedded DLL using thread execution
pt-injector.exe Notepad -e thread

# Inject embedded DLL using SetWindowsHookEx
pt-injector.exe Notepad -e swhk

# Inject custom DLL using thread execution
pt-injector.exe Notepad -d payload.dll -e thread

# Preview configuration without executing
pt-injector.exe Notepad --dry-run -v
```

### Advanced Configuration Examples

```cmd
# Thread execution with hyperspace allocation
pt-injector.exe Notepad -e thread --dll-alloc hyperspace

# SetWindowsHookEx execution with hyperspace allocation
pt-injector.exe Notepad -e swhk --dll-alloc hyperspace

# Driver current process allocation and stealthy DLL allocation with IAT
pt-injector.exe Notepad -d memory -e iat --driver-alloc current-process --driver-memory large --dll-alloc between-modules --dll-memory normal --hook-module user32.dll --hook-function GetMessageW --target-module notepad.exe

# Thread execution with custom allocation
pt-injector.exe Notepad -d memory -e thread --driver-alloc current-process --dll-alloc low-address --dll-memory normal

# System-level allocation with IAT
pt-injector.exe Notepad -d memory -e iat --driver-alloc system --dll-alloc inside-main --dll-memory normal --hook-module user32.dll --hook-function GetMessageW --target-module notepad.exe

# Driver and DLL large page allocation with thread execution
pt-injector.exe Notepad -d memory -e thread --driver-alloc current-process --driver-memory large --dll-alloc low-address --dll-memory large

# Advanced stealth with custom hide options (IAT)
pt-injector.exe Notepad -d memory -e iat --driver-hide set_parity_error --dll-hide set_parity_error --driver-memory large --dll-alloc between-modules

# Anti-debug configuration (WARNING: Will crash system if page is copied via MmCopyMemory)
pt-injector.exe Notepad -d memory --driver-hide set_lock_bit --dll-hide set_lock_bit

# Hyperspace with advanced hiding and thread execution
pt-injector Notepad -d memory -e thread --dll-alloc hyperspace --dll-hide set_parity_error
```

## Parameters

### Required Arguments
- **target**: Target window name (e.g., "Notepad", "Calculator")

### Optional Arguments

#### DLL Options

- **-d, --dll**: Path to DLL file or "memory" for embedded MessageBox DLL (default: memory)
- **-e, --execution**: DLL execution method (default: iat)
	- `iat`: Hook Import Address Table (default)
	- `thread`: Create remote thread (RtlCreateUserThread) for DLL entry point execution
	- `swhk`: SetWindowsHookEx for DLL entry point execution

#### Driver Options  

- **--driver-alloc**: Driver allocation strategy (default: system)
  - `system`: System context allocation (default)
  - `.data`: Inside ntoskrnl .data section  
  - `current-process`: Current process context
- **--driver-memory**: Driver memory page size (default: normal)
  - `normal`: 4KB pages (default)
  - `large`: 2MB pages
  - `huge`: 1GB pages (not supported yet)
- **--driver-hide**: Driver memory hiding mechanism (default: none)
  - `none`: No memory hiding (default)
  - `pfn_exists_bit`: Returns STATUS_INVALID_ADDRESS on memory copy
  - `mi_remove_physical_memory`: Removes pages from physical memory ranges
  - `set_parity_error`: Returns STATUS_HARDWARE_MEMORY_ERROR
  - `set_lock_bit`: Anti-debug mechanism - crashes system if page copied
  - `hide_translation`: MmGetVirtualForPhysical will return the incorrect virtual address that's mapped by the PTE, 0 in this case.

#### DLL Options

- **--dll-alloc**: DLL allocation strategy (default: low-address)
  - `inside-main`: Hijack PTEs in main module
  - `between-modules`: Allocate between legitimate modules
  - `low-address`: Usermode space (PML4 0-255) (default)
  - `high-address`: Kernel space (PML4 256-511)
  - `hyperspace`: Isolated memory context with cloned address space of target process
- **--dll-memory**: DLL memory page size (default: normal)
  - `normal`: 4KB pages (default)
  - `large`: 2MB pages
  - `huge`: 1GB pages (not supported yet)
- **--dll-hide**: DLL memory hiding mechanism (default: none)
  - `none`: No memory hiding (default)
  - `pfn_exists_bit`: Returns STATUS_INVALID_ADDRESS on memory copy
  - `mi_remove_physical_memory`: Removes pages from physical memory ranges
  - `set_parity_error`: Returns STATUS_HARDWARE_MEMORY_ERROR
  - `set_lock_bit`: Anti-debug mechanism - crashes system if page copied
  - `hide_translation`: MmGetVirtualForPhysical will return the incorrect virtual address that's mapped by the PTE, 0 in this case.

#### Hook Options (only used with --execution iat)
- **--hook-module**: Module to hook in the IAT (default: user32.dll)
- **--hook-function**: Function to hook in the IAT (default: GetMessageW)  
- **--target-module**: Module whose IAT to hook (empty = main module)

#### Experimental Options
- **--experimental**: Experimental operations to perform (default: none)
  - `none`: No experimental operations (default)
  - `manipulate_system_partition`: Modify MiSystemPartition to affect physical memory ranges (WARNING: May cause system instability)

#### Utility Options
- **-v, --verbose**: Enable detailed logging
- **--dry-run**: Show configuration without injecting

### Help and Examples

Use `pt-injector.exe --help` to see comprehensive usage information with examples.

**Note**: Use quotes around window names containing spaces (e.g., "Notepad")

## Technical Details

PT-Injector operates at a kernel level using direct page table manipulation instead of traditional memory APIs such as ZwAllocateVirtualMemory/NtAllocateVirtualMemory. This approach makes detection significantly more difficult as it bypasses common monitoring mechanisms that operate using the Virtual Address Descriptor (VAD) tree.

### Pure Physical Memory Access

A key distinguishing feature of this project is its exclusive use of physical memory operations:

- **No Process Context Switching**: Unlike traditional DLL injectors, PT-Injector never uses KeStackAttachProcess to attach to the target process context
- **Direct Physical Memory Manipulation**: All memory operations are performed through direct physical memory access
- **Page Table Modification**: Memory allocation is achieved by directly manipulating page tables at the physical level
- **Cross-Context Operation**: Can modify any process's memory without ever entering its execution context

This approach makes the injection practically invisible to security solutions that monitor for process context switches or virtual memory operations.

### Hyperspace Allocation Technique

The hyperspace allocation method represents one of the more advanced stealth techniques in PT-Injector:

#### What is Hyperspace?

Hyperspace is a technique (initially created by [IDontCode](https://git.back.engineering/IDontCode) ) that creates an isolated memory context invisible to the target process. When Windows schedules a thread, it loads the CR3 register with the value from `_KTHREAD->ApcState->Process->DirectoryTableBase`. By creating a cloned EPROCESS and DirectoryTableBase (CR3) of the target process via MmAllocateIndependentPages, we can switch specific threads to this isolated context without affecting the original process.

#### Key Windows Kernel Structures 

```cpp
struct _KAPC_STATE
{
    struct _LIST_ENTRY ApcListHead[2];             // 0x0
    struct _KPROCESS* Process;                     // 0x20 <- swap with new cloned _KPROCESS
    union
    {
        UCHAR InProgressFlags;                     // 0x28
        struct
        {
            UCHAR KernelApcInProgress:1;           // 0x28
            UCHAR SpecialApcInProgress:1;          // 0x28
        };
    };
};

struct _KTHREAD
{
    struct _DISPATCHER_HEADER Header;              // 0x0
    VOID* SListFaultAddress;                       // 0x18
    ULONGLONG QuantumTarget;                       // 0x20
    // ... etc ...
    struct _KAPC_STATE ApcState;                   // contains pointer to _KPROCESS
    // ... etc ...
};

struct _KPROCESS
{
    struct _DISPATCHER_HEADER Header;              // 0x0
    struct _LIST_ENTRY ProfileListHead;            // 0x18
    ULONGLONG DirectoryTableBase;                  // 0x28 <- swap CR3 with our new cloned one
    struct _LIST_ENTRY ThreadListHead;             // 0x30
    ULONG ProcessLock;                             // 0x38
    // ... etc ...
};
```


**How Hyperspace Works:**

1. **EPROCESS/KPROCESS Cloning**: Creates a complete clone of the target process's EPROCESS/KPROCESS structure
2. **DirectoryTableBase Cloning**: Allocates a new PML4 that is a copy of the original process, swaps the cloned KPROCESS's DirectoryTableBase with the new one.
3. **Contextualized Copy of Ntoskrnl**: Creates an isolated copy of ntoskrnl.exe within the hyperspace context's PML4 high address, allows for hooking kernel functions within the hyperspace context without triggering PatchGuard. These hooks are not visible globally, only within the hyperspace context.
4. **Thread Context Switching**: Modifies specific threads to use the hyperspace context by swapping `_KTHREAD.ApcState.Process` to use our cloned KPROCESS. Please note this specific part is very easy to detect and you should look into hiding the thread.
5. **Isolated Execution**: Code executes in a completely separate memory context invisible to the original process

<img width="1920" height="969" alt="image" src="https://github.com/user-attachments/assets/a38802a5-01ef-491b-9b58-195d2c511dce" />

**Key Advantages:**

- **Complete Isolation**: Modifications are only visible within the hyperspace context
- **Inline Kernel Hooks**: Inline kernel hooks (like PspExitThread) only affects the hyperspace copy and are not visible globally.
- **Per-Thread Control**: Only selected threads see the hyperspace mappings

**Technical Implementation:**

- Creates a deep copy of ntoskrnl at the same virtual address
- Handles self-referencing PML4 entries correctly
- Initializes critical EPROCESS structures to prevent BSODs when creating a thread within the hyperspace context
- Hooks PspExitThread within the hyperspace context and restores `_KTHREAD.ApcState.Process` to the original to prevent a bug check call when the thread exits.
- Implements automatic memory cleanup on process termination by registering a process exit callback (PsSetCreateProcessNotifyRoutineEx) within a legit module of an already loaded Windows kernel driver.

**Note**:

- If your goal is to hook present and render a menu, please note you will have to give the target process's render thread access to the hyperspace context via hyperspace::switch_thread_context_to_hyperspace within the driver project.
- For simplicity's sake I'm using RtlCreateUserThread or SetWindowsHookEx for the hyperspace DLL entry point execution.
- In my opinion, this method is more ideal for an external window with internal memory access. At this moment there's quite a lot of detection vectors, but with some modifications (such as hiding threads, spoofing return addresses, not triggering thread notify routines on thread creation/deletion and ideally not using traditional process notify routines for cleanup) it can be extremely good.
- I've only tested this on Notepad and not anything else, if you run into bugs or issues please submit a pull request.
- **Hyperspace allocation was designed with thread execution in mind** - while IAT hooking is supported, thread execution is recommended for optimal compatibility.

### Signature Scan Protection Mechanism

The tool employs sophisticated protection mechanisms by manipulating the Physical Frame Number (PFN) database entries with multiple hiding options:

**Available Hide Types:**

- **None (`none`)**: Standard memory allocation without hiding
- **PFN Exists Bit (`pfn_exists_bit`)**: Sets the MMPFN.u4.PfnExists bit to 0, causing MmCopyMemory to return STATUS_INVALID_ADDRESS (0xC0000141)
- **Physical Memory Removal (`mi_remove_physical_memory`)**: Removes pages from OS physical memory ranges and clears PFN entries, also returning STATUS_INVALID_ADDRESS
- **Parity Error (`set_parity_error`)**: Sets MMPFN.e3.ParityError flag to 1, causing MmCopyMemory to return STATUS_HARDWARE_MEMORY_ERROR (0xC0000709) - Default option
- **Lock Bit Anti-Debug (`set_lock_bit`)**: Sets MMPFN.u2.LockBit to 1. It's an anti-debug mechanism that causes the CPU to yield followed by a system crash if an attempt is made to copy the page via MmCopyMemory.
- **Hide Translation (`hide_translation`)**: Sets MMPFN.PteAddress to 0. This causes MmGetVirtualForPhysical to return 0 for the virtual address that's mapped by the PTE. Ideally you should spoof the PteAddress field to another pfn's PteAddress field to make it look more legitimate.

### Driver Allocation Techniques

The tool uses three main techniques for the driver memory allocation:

1. **In System Context**: Utilizes the system's kernel paging tables for allocation (MmAllocateIndependentPages).
2. **Inside Ntoskrnl .data Section:** Finds and repurposes unused memory within ntoskrnl's .data section.
3. **At Non Present PML4E Within Current Process Context**: Allocates memory at a non present PML4E address in kernel space (PML4 index 256-511), but keeps it within the current process' context.

### DLL Allocation Techniques

The tool uses three main techniques for the DLL memory allocation:

1. **Between Legitimate Modules**: Finds gaps between existing DLLs and allocates memory in these spaces.
2. **Inside Main Module**: Finds and repurposes unused memory within the main module range (hijacking null PFNs within the main module range).
3. **At Non Present PML4E (Low)**: Allocates memory at a non present PML4E address in usermode space (PML4 index 0-255)
4. **At Non Present PML4E (High)**: Allocates memory at a non present PML4E address in kernel space (PML4 index 256-511)
5. **Hyperspace**: Creates an isolated memory context with a cloned address space of the target process, only specific threads have access to this context, thus providing the highest level of stealth when it comes specifically to memory inspection.

### Experimental Options

The tool has one experimental feature option for hiding memory:

1. **Manipulate MiSystemPartition**: This technique results in Windows reporting the incorrect physical memory ranges, screenshots of RamMap and DebugView are shown below:


<div align="left">  
<b>BEFORE Manipulating MiSystemPartition:</b>  
</div>
<p align="left">

  <img src="https://github.com/user-attachments/assets/c08f5f2a-2ace-47f9-b12a-54ebddb5a37c">
</p>
<div align="left">  
<b>AFTER Manipulating MiSystemPartition:</b>   
</div>
<p align="left">
  <img src="https://github.com/user-attachments/assets/118209cb-420f-4876-99a1-13dcf07e3179">
</p>
<p align="left">
  <img src="https://github.com/user-attachments/assets/3de87137-e571-481b-9fcf-cf169bf72bcf">
</p>

## Security Notes

This tool is designed for educational and research purposes only. It demonstrates advanced memory manipulation techniques that operate at the kernel level. Use responsibly and only on systems you own or have explicit permission to test. This is an older project of mine which I've decided to release, it is likely detected on most anti-cheat solutions by now. This project has not been tested on my bare metal system, please run it on a virtual machine. This project is also **NOT** Control Flow Guard (CFG) compliant. Please disable CFG under Exploit Protection settings if your target application is compiled with CFG, else the target application will crash on injection.

## Detection Test Cases

I've implemented a proof of concept full page table walk detection for this project which can be found in mem/detection.hpp inside the kernel driver project. The test case can be ran by calling detections::inspect_process_page_tables with the target process id as the argument. Below is an example detection report of a low address allocation where each physical page has MMPFN.e3.ParityError set to 1. Another detection method is walking through MmPfnDatabase and checking for MMPFN.e3.ParityError set to 1, but I have not yet implemented this. 

![detection_test_cases](https://github.com/user-attachments/assets/0fde3456-84d4-40d6-93b0-2940e0793b65)

## Building from Source

The project requires:

- Visual Studio 2019 or newer
- Windows SDK 10
- Windows Driver Kit (WDK), matching version with Windows SDK
- C++20 or later
- **Optional**: LLVM/Clang for alternative compilation

### Compiler Support

The project supports both MSVC and Clang compilation:

- **MSVC**: Default compiler, fully tested and supported
- **Clang**: Alternative compiler option

### Build Instructions

1. Clone the repository
2. Open the solution in Visual Studio
3. Ensure the SDK and WDK are properly installed and configured within the project settings
4. **Choose your compiler**:
    - **For MSVC**: Use default Visual Studio toolchain
    - **For Clang**:
        - Install LLVM/Clang
        - Set Platform Toolset to "LLVM (clang-cl)" in project properties
        - Or configure custom build with Clang directly
5. Build in Release mode for x64 architecture

### Clang-Specific Notes

- The project automatically detects the compiler and uses appropriate intrinsics/inline assembly
- WDK paths are dynamically resolved to support different installation versions
- Both kernel driver and user mode components support Clang compilation

### Build Configurations

- **Release x64** (Recommended for production)
- **Debug x64** (For development and debugging)
- Compatible with both MSVC and Clang toolchains

## Credits

 - CLI parsing library: https://github.com/CLIUtils/CLI11
 - Physical memory read/write: https://github.com/SamuelTulach/DirectPageManipulation
 - Manual map idea inspired from: https://github.com/KANKOSHEV/face-injector-v2
 - Process-context specific kernel driver mapper idea taken from: https://git.back.engineering/IDontCode/PSKDM
 - Hyperspace idea taken from: https://git.back.engineering/IDontCode/hyperspace
 - Kernel driver manual mapper: https://github.com/TheCruZ/kdmapper
 - PDB symbol parsing: https://github.com/i1tao/EzPDB
 - Windows kernel structures: https://www.vergiliusproject.com/kernels/x64

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