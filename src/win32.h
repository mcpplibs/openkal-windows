// The whole of what this implementation uses from this system's own interface.
//
// ⭐⭐ WHY THIS FILE EXISTS, AND WHY IT IS NOT A DEVIATION.
//
// openkal is a specification. It says nothing about how a backend is
// implemented, and the four that exist do it four ways: openkal-linux issues
// this kernel's calls directly, openkal-opensbi issues `ecall` into firmware,
// openkal-macos calls two names it borrows through a stub it wrote itself, and
// this one calls the Win32 API. **Calling the Win32 API is not the question.**
//
// The question is where the DECLARATIONS come from, and until this file they
// came from `<windows.h>` — a vendor SDK that has to be found somewhere. Found
// where? On a machine with a Windows-targeting toolchain payload, the payload's.
// On a machine with a system-wide mingw, that one, at whatever version that
// machine has. On a machine with neither, the build fails naming a header
// rather than a missing dependency.
//
// ⚠️ Measured 2026-08-23, cross-compiling this package with the target side
// coming from packages rather than from a payload:
//
//     win.h:35 → /usr/x86_64-w64-mingw32/include/windows.h
//              → …/xim-x-llvm/…/include/c++/v1/ctype.h
//              → __config:13 '__config_site' file not found
//
// Three layers from the cause, and the cause is that a file belonging to nobody
// was on the search path. On a machine with a DIFFERENT mingw it may silently
// succeed against different declarations, which is the shape of every false
// green this repository has recorded.
//
// ⭐ AND THE OTHER THREE IMPLEMENTATIONS ALREADY SHOW THE ANSWER. None of them
// takes a vendor SDK: openkal-linux writes the system-call numbers, openkal-
// opensbi writes the SBI extension identifiers, openkal-macos writes a stub
// listing the two names it borrows. This file is that, for this system.
//
// ⚠️ AND HALF OF IT WAS ALREADY WRITTEN. `win.h` beside this file has carried
// the entire NT object-manager layer since it was written, with the reason
// stated: `<winternl.h>` "is present in one toolchain's sources and partial in
// another's". That argument was always the same argument; it had only been
// applied to the half where a toolchain disagreed with another toolchain,
// rather than to the half where a MACHINE disagrees with another machine.
//
// HOW THE LIST WAS OBTAINED
//
// ⚠️ Not by reading the sources. `<windows.h>` was removed and the compiler was
// asked what it then could not resolve; the answer is this file. That is the
// same method openkal-macos used for its stub, and it is preferred for the same
// reason: a reading produces names the configured build never uses, and the
// compiler does not.
#pragma once

// ── the machine's own words ─────────────────────────────────────────────────
//
// ⚠️ Written out rather than taken from a C library. This package is built by
// three toolchains and this file must mean the same thing under all of them,
// and `<windows.h>`'s own spellings are ultimately these.
using BOOL    = int;
using BYTE    = unsigned char;
using WORD    = unsigned short;
using DWORD   = unsigned long;      // ⚠️ `long`, not `int` — this is LLP64
using UINT    = unsigned int;
using ULONG   = unsigned long;
using LONG    = long;
using HANDLE  = void*;
using HLOCAL  = void*;
using LPVOID  = void*;
using LPCVOID = const void*;
using LPWSTR  = wchar_t*;
using LPCWSTR = const wchar_t*;
using LPSTR   = char*;
using LPCSTR  = const char*;

// The calling convention. ⚠️ It is ignored on the 64-bit ABI and load-bearing on
// the 32-bit one, and writing it costs nothing on either — while omitting it
// would make this file wrong for a target it is otherwise correct for.
#define OKW_API __stdcall

union LARGE_INTEGER {
    struct { DWORD LowPart; LONG HighPart; } u;
    long long QuadPart;
};

struct FILETIME { DWORD dwLowDateTime; DWORD dwHighDateTime; };

struct SECURITY_ATTRIBUTES {
    DWORD  nLength;
    LPVOID lpSecurityDescriptor;
    BOOL   bInheritHandle;
};

struct OVERLAPPED {
    unsigned long long Internal;
    unsigned long long InternalHigh;
    union {
        struct { DWORD Offset; DWORD OffsetHigh; } u;
        LPVOID Pointer;
    };
    HANDLE hEvent;
};

// ⚠️ THE LAYOUT IS THE CONTRACT. These two are filled in by this package and
// read by the system, so a member of the wrong width does not fail to compile —
// it shifts everything after it. The order is the documented one.
struct STARTUPINFOW {
    DWORD  cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD  dwX, dwY, dwXSize, dwYSize;
    DWORD  dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    WORD   wShowWindow, cbReserved2;
    BYTE*  lpReserved2;
    HANDLE hStdInput, hStdOutput, hStdError;
};

struct PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
};

// ── the constants this package names ────────────────────────────────────────
// ⚠️ NOT `constexpr`. A cast from an integer to a pointer is not a constant
// expression, and the compiler says so — `<windows.h>` spells this as a macro
// for the same reason. `inline const` gives one object across every translation
// unit without claiming something the language does not allow.
inline const HANDLE INVALID_HANDLE_VALUE = reinterpret_cast<HANDLE>(-1);

// The two the system's own headers define as macros, written as what they are.
enum : BOOL { FALSE = 0, TRUE = 1 };

enum : DWORD {
    STD_INPUT_HANDLE  = static_cast<DWORD>(-10),
    STD_OUTPUT_HANDLE = static_cast<DWORD>(-11),
    STD_ERROR_HANDLE  = static_cast<DWORD>(-12),

    GENERIC_READ  = 0x80000000u,
    GENERIC_WRITE = 0x40000000u,
    SYNCHRONIZE   = 0x00100000u,

    DELETE        = 0x00010000u,
    FILE_SHARE_READ   = 0x1, FILE_SHARE_WRITE = 0x2, FILE_SHARE_DELETE = 0x4,

    // The access rights this package asks for, and the two composites the
    // system documents. ⚠️ A composite written as its own number rather than
    // assembled here: assembling it would be this file deciding what the system
    // means by "generic read", and it does not get to decide that.
    FILE_READ_DATA        = 0x0001,
    FILE_WRITE_DATA       = 0x0002,
    FILE_APPEND_DATA      = 0x0004,
    FILE_READ_ATTRIBUTES  = 0x0080,
    FILE_WRITE_ATTRIBUTES = 0x0100,
    FILE_GENERIC_READ     = 0x00120089u,
    FILE_GENERIC_WRITE    = 0x00120116u,

    FILE_ATTRIBUTE_DIRECTORY      = 0x10,
    FILE_ATTRIBUTE_READONLY       = 0x1,
    FILE_ATTRIBUTE_REPARSE_POINT  = 0x400,

    FILE_BEGIN = 0, FILE_CURRENT = 1, FILE_END = 2,

    CREATE_UNICODE_ENVIRONMENT = 0x00000400u,
    OPEN_EXISTING     = 3,
    FILE_ATTRIBUTE_NORMAL      = 0x80,
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000u,
    FILE_LIST_DIRECTORY        = 0x1,
    FILE_NAME_NORMALIZED       = 0x0,
    VOLUME_NAME_DOS            = 0x0,
    FILE_TYPE_DISK             = 0x0001,

    HANDLE_FLAG_INHERIT   = 0x1,
    STARTF_USESTDHANDLES  = 0x00000100u,

    INFINITE       = 0xFFFFFFFFu,
    WAIT_OBJECT_0  = 0x00000000u,

    CP_UTF8               = 65001,
    MB_ERR_INVALID_CHARS  = 0x8,
};

// The error values this package translates. ⚠️ Only these — openkal's error set
// is closed, and a value with no mapping is reported as `kal_err_io` rather than
// invented, so listing more would be listing names nothing reads.
enum : DWORD {
    ERROR_SUCCESS               = 0,
    ERROR_INVALID_FUNCTION      = 1,
    ERROR_ACCESS_DENIED         = 5,
    ERROR_INVALID_HANDLE        = 6,
    ERROR_NOT_ENOUGH_MEMORY     = 8,
    ERROR_OUTOFMEMORY           = 14,
    ERROR_WRITE_PROTECT         = 19,
    ERROR_SHARING_VIOLATION     = 32,
    ERROR_HANDLE_EOF            = 38,
    ERROR_HANDLE_DISK_FULL      = 39,
    ERROR_NOT_SUPPORTED         = 50,
    ERROR_INVALID_PARAMETER     = 87,
    ERROR_CALL_NOT_IMPLEMENTED  = 120,
    ERROR_NEGATIVE_SEEK         = 131,
    ERROR_DISK_FULL             = 112,
    ERROR_INVALID_NAME          = 123,
    ERROR_FILENAME_EXCED_RANGE  = 206,
    ERROR_BROKEN_PIPE           = 109,
    ERROR_NO_DATA               = 232,
    ERROR_PIPE_NOT_CONNECTED    = 233,
    ERROR_TIMEOUT               = 1460,
    ERROR_FILE_NOT_FOUND        = 2,
    ERROR_PATH_NOT_FOUND        = 3,
    ERROR_NO_MORE_FILES         = 18,
    ERROR_FILE_EXISTS           = 80,
    ERROR_ALREADY_EXISTS        = 183,
    ERROR_DIRECTORY             = 267,
    ERROR_DIR_NOT_EMPTY         = 145,
    ERROR_IO_PENDING            = 997,
};

// ── the functions ───────────────────────────────────────────────────────────
extern "C" {

HANDLE OKW_API GetStdHandle(DWORD);
BOOL   OKW_API CloseHandle(HANDLE);
DWORD  OKW_API GetLastError(void);
DWORD  OKW_API GetFileType(HANDLE);
BOOL   OKW_API SetHandleInformation(HANDLE, DWORD, DWORD);
BOOL   OKW_API GetConsoleMode(HANDLE, DWORD*);

BOOL   OKW_API ReadFile(HANDLE, LPVOID, DWORD, DWORD*, OVERLAPPED*);
BOOL   OKW_API WriteFile(HANDLE, LPCVOID, DWORD, DWORD*, OVERLAPPED*);
BOOL   OKW_API FlushFileBuffers(HANDLE);
BOOL   OKW_API SetFilePointerEx(HANDLE, LARGE_INTEGER, LARGE_INTEGER*, DWORD);
HANDLE OKW_API CreateFileW(LPCWSTR, DWORD, DWORD, SECURITY_ATTRIBUTES*,
                           DWORD, DWORD, HANDLE);
DWORD  OKW_API GetFinalPathNameByHandleW(HANDLE, LPWSTR, DWORD, DWORD);
DWORD  OKW_API GetLogicalDriveStringsW(DWORD, LPWSTR);
DWORD  OKW_API GetCurrentDirectoryW(DWORD, LPWSTR);

HANDLE OKW_API GetProcessHeap(void);
LPVOID OKW_API HeapAlloc(HANDLE, DWORD, unsigned long long);
BOOL   OKW_API HeapFree(HANDLE, DWORD, LPVOID);
HLOCAL OKW_API LocalFree(HLOCAL);

LPWSTR OKW_API GetCommandLineW(void);
LPWSTR OKW_API GetEnvironmentStringsW(void);
BOOL   OKW_API FreeEnvironmentStringsW(LPWSTR);

BOOL   OKW_API CreateProcessW(LPCWSTR, LPWSTR, SECURITY_ATTRIBUTES*,
                              SECURITY_ATTRIBUTES*, BOOL, DWORD, LPVOID,
                              LPCWSTR, STARTUPINFOW*, PROCESS_INFORMATION*);
BOOL   OKW_API GetExitCodeProcess(HANDLE, DWORD*);
BOOL   OKW_API TerminateProcess(HANDLE, UINT);
HANDLE OKW_API GetCurrentProcess(void);
DWORD  OKW_API WaitForSingleObject(HANDLE, DWORD);

HANDLE OKW_API CreateThread(SECURITY_ATTRIBUTES*, unsigned long long,
                            DWORD (OKW_API*)(LPVOID), LPVOID, DWORD, DWORD*);
DWORD  OKW_API GetCurrentThreadId(void);
void   OKW_API Sleep(DWORD);
BOOL   OKW_API SwitchToThread(void);

// The address-based wait, which is what openkal.task's suspension primitive
// rests on here. ⚠️ In `API-MS-Win-Core-Synch-l1-2-0`, which is why the link
// line names `-lsynchronization` rather than only `-lkernel32`.
BOOL   OKW_API WaitOnAddress(volatile void*, void*, unsigned long long, DWORD);
void   OKW_API WakeByAddressSingle(void*);
void   OKW_API WakeByAddressAll(void*);

void   OKW_API GetSystemTimePreciseAsFileTime(FILETIME*);
BOOL   OKW_API QueryPerformanceCounter(LARGE_INTEGER*);
BOOL   OKW_API QueryPerformanceFrequency(LARGE_INTEGER*);

int    OKW_API MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);
int    OKW_API WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int,
                                   LPCSTR, BOOL*);

// From shell32, and the only name this package takes from it.
LPWSTR* OKW_API CommandLineToArgvW(LPCWSTR, int*);

// ── ntdll ───────────────────────────────────────────────────────────────────
//
// The object-manager entry points. Their STRUCTURES are declared in win.h and
// have been since this package was written, for the reason recorded there;
// these are the calls that take them.
DWORD OKW_API RtlNtStatusToDosError(long);

}  // extern "C"
