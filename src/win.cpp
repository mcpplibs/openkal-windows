#include "win.h"
#include <openkal/types.h>

// The libraries this environment's own interfaces live in, named for the ABI
// whose toolchains read a name from the object rather than from the link line.
//
// ntdll carries the object manager, which is where a name relative to a
// directory is opened --- the operation openkal declares and Win32 does not
// offer. synchronization carries the suspension primitive. shell32 carries the
// operation that splits a command line into a vector.
//
// It is here rather than in the manifest because the two ABIs this environment
// has do not merely spell a library differently: on one of them the compiler
// records the requirement in the object it produces, so a program that links
// this package needs nothing in its own manifest, and the requirement cannot
// fall out of step with the source that creates it. The other ABI has no such
// mechanism, and there the manifest names them.
#if defined(_MSC_VER)
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "synchronization.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "kernel32.lib")
#endif


namespace okw {

okw_uptr length(const char* s) { okw_uptr n = 0; while (s && s[n]) ++n; return n; }

int translate_win32(unsigned long e) {
    switch (e) {
        case ERROR_SUCCESS:                 return kal_ok;
        case ERROR_INVALID_HANDLE:
        case ERROR_INVALID_PARAMETER:
        case ERROR_NEGATIVE_SEEK:
        case ERROR_INVALID_NAME:
        case ERROR_FILENAME_EXCED_RANGE:    return kal_err_invalid;
        case ERROR_NO_DATA:
        case ERROR_BROKEN_PIPE:
        case ERROR_PIPE_NOT_CONNECTED:      return kal_err_closed;
        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_OUTOFMEMORY:             return kal_err_no_memory;
        case ERROR_DISK_FULL:
        case ERROR_HANDLE_DISK_FULL:        return kal_err_no_space;
        case ERROR_ACCESS_DENIED:
        case ERROR_WRITE_PROTECT:
        case ERROR_SHARING_VIOLATION:       return kal_err_permission;
        case ERROR_CALL_NOT_IMPLEMENTED:
        case ERROR_NOT_SUPPORTED:
        case ERROR_INVALID_FUNCTION:        return kal_err_not_supported;
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_NO_MORE_FILES:           return kal_err_not_found;
        case ERROR_FILE_EXISTS:
        case ERROR_ALREADY_EXISTS:          return kal_err_exists;
        case ERROR_DIR_NOT_EMPTY:           return kal_err_not_empty;
        case ERROR_DIRECTORY:               return kal_err_not_directory;
        case ERROR_IO_PENDING:              return kal_err_again;
        default:                            return kal_err_io;
    }
}

// The conversion the environment offers. It is used rather than written,
// because the mapping between the two encodings is this environment's own
// definition of its names and an implementation that invented a second one
// would be reconstructing the namespace rather than crossing it.
wide_name::wide_name(const char* utf8, okw_uptr len) : ok(false) {
    string.buffer = buffer;
    string.length = 0;
    string.maximum = 0;
    // The one reserved name, clause 7.12: "." denotes the directory itself.
    //
    // Two of the three environments openkal is implemented on reserve the same
    // word in their own naming and accept it wherever a name is accepted. This
    // one does not: its object manager reads "." as a name to look up, finds no
    // child so called, and reports that the argument is invalid. What it does
    // accept is an empty name beside the directory's own handle, which denotes
    // exactly the same thing --- so the translation is here, where every other
    // difference between the two spellings of a name already is.
    if (len == 1 && utf8 != nullptr && utf8[0] == '.') len = 0;
    if (len == 0) { buffer[0] = 0; ok = true; return; }
    if (len > kMaxName / 2) return;
    const int produced = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                             utf8, static_cast<int>(len),
                                             buffer, static_cast<int>(kMaxName - 1));
    if (produced <= 0) return;
    // openkal spells a separator one way and this environment the other. The
    // substitution happens here, once, on the way in.
    for (int i = 0; i < produced; ++i) if (buffer[i] == L'/') buffer[i] = L'\\';
    buffer[produced] = 0;
    string.length  = static_cast<unsigned short>(produced * 2);
    string.maximum = string.length;
    ok = true;
}

okw_uptr narrow(const wchar_t* wide, okw_uptr wide_len, char* out, okw_uptr cap) {
    if (wide_len == 0 || cap == 0) { if (cap) out[0] = 0; return 0; }
    const int produced = WideCharToMultiByte(CP_UTF8, 0, wide, static_cast<int>(wide_len),
                                             out, static_cast<int>(cap - 1), nullptr, nullptr);
    if (produced <= 0) { out[0] = 0; return 0; }
    // Reported the way openkal spells it, which is the reverse of the
    // substitution above and is the only place the difference appears.
    for (int i = 0; i < produced; ++i) if (out[i] == '\\') out[i] = '/';
    out[produced] = 0;
    return static_cast<okw_uptr>(produced);
}

bool acceptable(const char* name, okw_uptr len) {
    if (name == nullptr || len == 0) return false;
    if (name[0] == '/' || name[0] == '\\') return false;
    // A name that names a device or a drive is a name that leaves the directory
    // it was given, however it is spelled. "C:foo" is relative to a drive's own
    // position and not to the handle, which is the escape this rule exists to
    // prevent.
    for (okw_uptr i = 0; i < len; ++i) if (name[i] == ':') return false;
    okw_uptr start = 0;
    for (okw_uptr i = 0; i <= len; ++i) {
        if (i == len || name[i] == '/' || name[i] == '\\') {
            const okw_uptr n = i - start;
            if (n == 0) return false;
            if (n == 2 && name[start] == '.' && name[start + 1] == '.') return false;
            start = i + 1;
        }
    }
    return true;
}

}  // namespace okw
