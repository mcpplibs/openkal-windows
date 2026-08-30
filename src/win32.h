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

// ⭐⭐ AND WHERE THEY LIVE, WHICH IS NOT AN OPTIMISATION.
//
// Every function below is in a DLL, and `<windows.h>` says so with
// `__declspec(dllimport)`. Omitting it still LINKS: the linker notices the
// symbol resolves through an import library and synthesises a thunk that jumps
// through the import table. The program runs, so nothing here fails — and that
// is exactly why it has to be written rather than discovered.
//
// ⚠️ Measured 2026-08-23. This package's own independence check permits
// `__imp_*` because those names ARE this environment's interface reached
// through its import table, and it rejects everything else because everything
// else would be a C runtime. Declaring these without `dllimport` made the
// objects name them bare, and the check reported twenty-two of this system's
// own functions as symbols the implementation "must not" reference:
//
//     the implementation references a symbol it must not: WriteFile
//     the implementation references a symbol it must not: HeapAlloc
//
// The check was right and the declarations were wrong. It was `<windows.h>`
// that had been supplying this attribute, and replacing that header without it
// changed what the objects say about themselves.
#define OKW_IMPORT __declspec(dllimport)

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
    FILE_TYPE_CHAR             = 0x0002,
    FILE_TYPE_PIPE             = 0x0003,

    HANDLE_FLAG_INHERIT   = 0x1,
    STARTF_USESTDHANDLES  = 0x00000100u,

    INFINITE       = 0xFFFFFFFFu,
    WAIT_OBJECT_0  = 0x00000000u,
    WAIT_TIMEOUT_  = 0x00000102u,

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
    ERROR_LOCK_VIOLATION        = 33,
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

    // For openkal.exec.
    MEM_COMMIT   = 0x00001000u,
    MEM_RESERVE  = 0x00002000u,
    MEM_RELEASE  = 0x00008000u,
    PAGE_READWRITE      = 0x04u,
    PAGE_EXECUTE_READ   = 0x20u,
};

// ── the functions ───────────────────────────────────────────────────────────
extern "C" {

OKW_IMPORT HANDLE OKW_API GetStdHandle(DWORD);
OKW_IMPORT BOOL   OKW_API CloseHandle(HANDLE);
OKW_IMPORT DWORD  OKW_API GetLastError(void);
OKW_IMPORT DWORD  OKW_API GetFileType(HANDLE);
OKW_IMPORT BOOL   OKW_API SetHandleInformation(HANDLE, DWORD, DWORD);
// For kal_process_channel. The security attributes decide whether the ends are
// inheritable, which is what makes one of them able to cross a spawn.
OKW_IMPORT BOOL   OKW_API CreatePipe(HANDLE*, HANDLE*, SECURITY_ATTRIBUTES*, DWORD);
// How many bytes a pipe has without taking them, which is the one readiness
// enquiry on this system that is not `WSAPoll'. src/timeout.cpp says why both
// are needed.
OKW_IMPORT BOOL   OKW_API PeekNamedPipe(HANDLE, LPVOID, DWORD, DWORD*, DWORD*, DWORD*);
OKW_IMPORT BOOL   OKW_API GetConsoleMode(HANDLE, DWORD*);
OKW_IMPORT BOOL   OKW_API SetConsoleMode(HANDLE, DWORD);

// The console's dimensions, for openkal.terminal. The structure is this
// environment's and is declared here for the reason every other structure in
// this file is: it belongs to the environment rather than to a C library, and
// this implementation has none to take it from.
struct COORD_ { short X; short Y; };
struct SMALL_RECT_ { short Left; short Top; short Right; short Bottom; };
struct CONSOLE_SCREEN_BUFFER_INFO_ {
    COORD_      dwSize;
    COORD_      dwCursorPosition;
    unsigned short wAttributes;
    SMALL_RECT_ srWindow;
    COORD_      dwMaximumWindowSize;
};
OKW_IMPORT BOOL OKW_API GetConsoleScreenBufferInfo(HANDLE, CONSOLE_SCREEN_BUFFER_INFO_*);

OKW_IMPORT BOOL   OKW_API ReadFile(HANDLE, LPVOID, DWORD, DWORD*, OVERLAPPED*);
OKW_IMPORT BOOL   OKW_API WriteFile(HANDLE, LPCVOID, DWORD, DWORD*, OVERLAPPED*);
OKW_IMPORT BOOL   OKW_API FlushFileBuffers(HANDLE);
OKW_IMPORT BOOL   OKW_API SetFilePointerEx(HANDLE, LARGE_INTEGER, LARGE_INTEGER*, DWORD);
OKW_IMPORT HANDLE OKW_API CreateFileW(LPCWSTR, DWORD, DWORD, SECURITY_ATTRIBUTES*,
                           DWORD, DWORD, HANDLE);
OKW_IMPORT DWORD  OKW_API GetFinalPathNameByHandleW(HANDLE, LPWSTR, DWORD, DWORD);
OKW_IMPORT DWORD  OKW_API GetLogicalDriveStringsW(DWORD, LPWSTR);
OKW_IMPORT DWORD  OKW_API GetCurrentDirectoryW(DWORD, LPWSTR);

OKW_IMPORT HANDLE OKW_API GetProcessHeap(void);
OKW_IMPORT LPVOID OKW_API HeapAlloc(HANDLE, DWORD, unsigned long long);
OKW_IMPORT BOOL   OKW_API HeapFree(HANDLE, DWORD, LPVOID);
OKW_IMPORT HLOCAL OKW_API LocalFree(HLOCAL);

OKW_IMPORT LPWSTR OKW_API GetCommandLineW(void);
OKW_IMPORT LPWSTR OKW_API GetEnvironmentStringsW(void);
OKW_IMPORT BOOL   OKW_API FreeEnvironmentStringsW(LPWSTR);

OKW_IMPORT BOOL   OKW_API CreateProcessW(LPCWSTR, LPWSTR, SECURITY_ATTRIBUTES*,
                              SECURITY_ATTRIBUTES*, BOOL, DWORD, LPVOID,
                              LPCWSTR, STARTUPINFOW*, PROCESS_INFORMATION*);
OKW_IMPORT BOOL   OKW_API GetExitCodeProcess(HANDLE, DWORD*);
OKW_IMPORT BOOL   OKW_API TerminateProcess(HANDLE, UINT);

// openkal 0.11: the unit a set of started programs forms. A job object ends its
// members as one, which is what `kal_process_job_terminate' is.
//
// ⚠️ NO `SetInformationJobObject' HERE, AND ITS ABSENCE IS THE DESIGN. The limit
// that ends members when the last handle closes --- JOB_OBJECT_LIMIT_KILL_ON_JOB_
// CLOSE --- is exactly what must NOT be set: `kal_process_job_close' releases and
// does not end, because where a unit is a process group closing is releasing a
// number. Not declaring the call is how that stays true by construction.
OKW_IMPORT HANDLE OKW_API CreateJobObjectW(SECURITY_ATTRIBUTES*, LPCWSTR);
OKW_IMPORT BOOL   OKW_API AssignProcessToJobObject(HANDLE, HANDLE);
OKW_IMPORT BOOL   OKW_API TerminateJobObject(HANDLE, UINT);

// openkal 0.11: the word set when this program is asked to end. The routine runs
// on a context this environment starts, which is why the interface is a word and
// not a disposition --- see kal_process_stop_requested.
OKW_IMPORT BOOL   OKW_API SetConsoleCtrlHandler(BOOL (OKW_API*)(DWORD), BOOL);
OKW_IMPORT HANDLE OKW_API GetCurrentProcess(void);
OKW_IMPORT DWORD  OKW_API WaitForSingleObject(HANDLE, DWORD);

OKW_IMPORT HANDLE OKW_API CreateThread(SECURITY_ATTRIBUTES*, unsigned long long,
                            DWORD (OKW_API*)(LPVOID), LPVOID, DWORD, DWORD*);
OKW_IMPORT DWORD  OKW_API GetCurrentThreadId(void);
OKW_IMPORT void   OKW_API Sleep(DWORD);
OKW_IMPORT BOOL   OKW_API SwitchToThread(void);

// The address-based wait, which is what openkal.task's suspension primitive
// rests on here. ⚠️ In `API-MS-Win-Core-Synch-l1-2-0`, which is why the link
// line names `-lsynchronization` rather than only `-lkernel32`.
OKW_IMPORT BOOL   OKW_API WaitOnAddress(volatile void*, void*, unsigned long long, DWORD);
OKW_IMPORT void   OKW_API WakeByAddressSingle(void*);
OKW_IMPORT void   OKW_API WakeByAddressAll(void*);

OKW_IMPORT void   OKW_API GetSystemTimePreciseAsFileTime(FILETIME*);
OKW_IMPORT BOOL   OKW_API QueryPerformanceCounter(LARGE_INTEGER*);
OKW_IMPORT BOOL   OKW_API QueryPerformanceFrequency(LARGE_INTEGER*);

OKW_IMPORT int    OKW_API MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);
OKW_IMPORT int    OKW_API WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int,
                                   LPCSTR, BOOL*);

// Memory a program may execute, for openkal.exec. The reservation and the
// change of protection are two calls here as they are on every system this
// specification targets, and the third is the one that matters on a processor
// whose instruction path does not see the data path's writes.
OKW_IMPORT LPVOID OKW_API VirtualAlloc(LPVOID, unsigned long long, DWORD, DWORD);

// What this system reports about itself. Only two fields are read and the rest
// are named so that the record has the layout the system writes.
struct SYSTEM_INFO {
    DWORD  dwOemId;
    DWORD  dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    unsigned long long dwActiveProcessorMask;
    DWORD  dwNumberOfProcessors;
    DWORD  dwProcessorType;
    DWORD  dwAllocationGranularity;
    unsigned short wProcessorLevel;
    unsigned short wProcessorRevision;
};
OKW_IMPORT void OKW_API GetSystemInfo(SYSTEM_INFO*);
OKW_IMPORT BOOL   OKW_API VirtualProtect(LPVOID, unsigned long long, DWORD, DWORD*);
OKW_IMPORT BOOL   OKW_API VirtualFree(LPVOID, unsigned long long, DWORD);
OKW_IMPORT BOOL   OKW_API FlushInstructionCache(HANDLE, LPCVOID, unsigned long long);

// From shell32, and the only name this package takes from it.
OKW_IMPORT LPWSTR* OKW_API CommandLineToArgvW(LPCWSTR, int*);

// Reaching a library by name at run time, which is how this implementation
// obtains the network interface. src/endpoint.h says why it is not linked.
OKW_IMPORT HANDLE OKW_API LoadLibraryW(LPCWSTR);
OKW_IMPORT void*  OKW_API GetProcAddress(HANDLE, LPCSTR);

// ── ntdll ───────────────────────────────────────────────────────────────────
//
// The object-manager entry points. Their STRUCTURES are declared in win.h and
// have been since this package was written, for the reason recorded there;
// these are the calls that take them.
OKW_IMPORT DWORD OKW_API RtlNtStatusToDosError(long);

}  // extern "C"

// ── ws2_32: this system's network interface ─────────────────────────────────
//
// ⚠️⚠️ NOT DECLARED AS IMPORTS AND NOT LINKED, AND THE REASON IS A COLLISION
// RATHER THAN A PREFERENCE.
//
// This library's names ARE the BSD names --- `bind', `listen', `accept',
// `connect'. So does the C library above this implementation: openkal-musl
// compiles musl's own `src/network/*.c', which define those names and route
// them through this port. Naming `-lws2_32' on the link line puts BOTH
// definitions in one program:
//
//     ld.exe: libws2_32.a(libws2_32s00165.o): multiple definition of `connect';
//             musl/src/network/connect.o: first defined here
//
// Measured on the first run of this change, on the GNU/PE row of the C
// library's own continuous integration. It is not an ordering problem: an
// import library's member defines the thunk AND the `__imp_' pointer together,
// so reaching for either brings both.
//
// ⭐ THE NAMES ARE THEREFORE REACHED AT RUN TIME, THROUGH THE LIBRARY'S OWN
// LOADER. Nothing of ws2_32 enters this program's symbol table, so the C
// library above keeps its `bind' and this implementation still reaches the
// system's. `ws2_32.dll' is a core component of every installation of this
// system, and src/endpoint.h states what happens if it is somehow absent.
//
// ⚠️ AND THREE CONSTANTS DIFFER FROM THE OTHER SYSTEMS' WITHOUT ANNOUNCING IT:
// `AF_INET6' is 23 here, 30 on macOS and 10 on Linux; `SOL_SOCKET' is 0xffff
// here and on macOS and 1 on Linux; and this system's `poll' has no bit named
// POLLIN --- what it has is POLLRDNORM, and a caller that passed the Linux
// value would be asking about out-of-band data.
//
// A socket address here has no length byte, unlike macOS: the family occupies
// two bytes, as on Linux.

// UINT_PTR on this ABI. It is a handle value and is used as one below.
using SOCKET = unsigned long long;

inline const SOCKET INVALID_SOCKET = static_cast<SOCKET>(-1);

enum : int {
    AF_INET_ = 2, AF_INET6_ = 23,
    SOCK_STREAM_ = 1, SOCK_DGRAM_ = 2,
    IPPROTO_TCP_ = 6, IPPROTO_UDP_ = 17,
    SD_RECEIVE_ = 0, SD_SEND_ = 1, SD_BOTH_ = 2,
};

// What this system's `poll' names its bits. POLLRDNORM and POLLWRNORM are what
// "there is ordinary data to read" and "an ordinary write would proceed" are
// called here; POLLIN as a name exists and includes a band this implementation
// has no operation for.
enum : short {
    POLLRDNORM_ = 0x0100, POLLWRNORM_ = 0x0010,
    POLLERR_ = 0x0001, POLLHUP_ = 0x0002, POLLNVAL_ = 0x0004,
};

struct WSAPOLLFD_ { SOCKET fd; short events; short revents; };

// This system's socket addresses. The family occupies two bytes and the
// structure carries no length of its own.
struct ksockaddr_in {
    unsigned short family;
    unsigned short port;        // network order
    DWORD          addr;        // network order
    unsigned char  zero[8];
};

struct ksockaddr_in6 {
    unsigned short family;
    unsigned short port;        // network order
    DWORD          flowinfo;
    unsigned char  addr[16];
    DWORD          scope_id;
};

struct ksockaddr_storage { unsigned char pad[128]; };

// The shapes of the calls, so that a pointer obtained at run time is still
// type-checked. ⚠️ THE LAYOUT RULE OF THIS FILE APPLIES HERE TOO: a signature
// that is wrong does not fail to compile, because nothing checks it against the
// system --- it produces a call with the wrong arguments in the wrong places.
using pfn_WSAStartup      = int    (OKW_API*)(WORD, void*);
using pfn_WSAGetLastError = int    (OKW_API*)(void);
using pfn_WSASocketW      = SOCKET (OKW_API*)(int, int, int, void*, unsigned, DWORD);
using pfn_closesocket     = int    (OKW_API*)(SOCKET);
using pfn_bind            = int    (OKW_API*)(SOCKET, const void*, int);
using pfn_listen          = int    (OKW_API*)(SOCKET, int);
using pfn_accept          = SOCKET (OKW_API*)(SOCKET, void*, int*);
using pfn_connect         = int    (OKW_API*)(SOCKET, const void*, int);
using pfn_shutdown        = int    (OKW_API*)(SOCKET, int);
using pfn_getsockname     = int    (OKW_API*)(SOCKET, void*, int*);
using pfn_getpeername     = int    (OKW_API*)(SOCKET, void*, int*);
using pfn_sendto          = int    (OKW_API*)(SOCKET, const char*, int, int, const void*, int);
using pfn_recvfrom        = int    (OKW_API*)(SOCKET, char*, int, int, void*, int*);
using pfn_WSAPoll         = int    (OKW_API*)(WSAPOLLFD_*, ULONG, int);
