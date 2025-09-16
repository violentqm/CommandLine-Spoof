#pragma once

// --- NULL Definition ---
#ifndef NULL
#define NULL 0
#endif

// --- Basic Type Definitions (in correct order) ---
using BYTE = unsigned char;
using PBYTE = BYTE*;
using WORD = unsigned short;
using PWORD = WORD*;
using DWORD = unsigned long;
using PDWORD = DWORD*;
using LONG = long;
using LONGLONG = long long;
using ULONGLONG = unsigned long long;
using PVOID = void*;
using LPVOID = PVOID;
using HANDLE = PVOID;
using NTSTATUS = LONG;
using ACCESS_MASK = DWORD;
using LPWSTR = wchar_t*;
using PCWSTR = const wchar_t*;
using ULONG = unsigned long;
using ULONG_PTR = ULONGLONG;
using DWORD_PTR = ULONGLONG;
using BOOLEAN = BYTE;
using UCHAR = unsigned char;
using SIZE_T = ULONGLONG;
using PSIZE_T = SIZE_T*;
using UINT = unsigned int;

// --- Calling Conventions ---
#define NTAPI   __attribute__((__stdcall__))
#define WINAPIV __attribute__((__cdecl__))

// --- Forward declarations ---
struct UNICODE_STRING;
using PUNICODE_STRING = UNICODE_STRING*;
struct PEB;
using PPEB = PEB*;
struct RTL_USER_PROCESS_PARAMETERS;
using PRTL_USER_PROCESS_PARAMETERS = RTL_USER_PROCESS_PARAMETERS*;
struct SID;
using PSID = SID*;

// ... [The rest of the file would contain all the struct definitions as before] ...
// The key change is ensuring the basic types are all defined first.
