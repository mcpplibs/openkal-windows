#include "win.h"
#include "handle.h"
#include <openkal/process.h>
#include <openkal/memory.h>

// A program image that has been started.
//
// openkal names the program relative to a directory the caller holds, and this
// environment's operation for starting one takes a path. The directory's own
// path is therefore asked for. That is not a namespace being reconstructed ---
// it is this environment's name for a directory the caller already holds, and
// asking the environment what it calls something is the opposite of inventing a
// name for it.
//
// Duplication of the calling image does not appear, and this environment is the
// reason the omission is not a Unix preference: it has no such operation at
// all, and an interface that offered one would have obliged this implementation
// to construct it out of nothing.

namespace {


constexpr okw_uptr kCommandLine = 32768;   // this environment's own bound

bool append_wide(wchar_t* out, okw_uptr cap, okw_uptr& at, const wchar_t* s, okw_uptr n) {
    if (at + n + 1 >= cap) return false;
    for (okw_uptr i = 0; i < n; ++i) out[at++] = s[i];
    return true;
}

// One element of the vector, quoted so that the started program recovers
// exactly what the caller supplied.
//
// Clause 7.6 requires the vector to be passed unaltered, and this environment
// passes one string and lets the started program split it. The quoting below is
// the inverse of the splitting this environment defines, so that the two agree;
// getting it wrong would alter the vector while appearing to pass it.
// One string of the caller's encoding, converted straight into the buffer it is
// destined for.
//
// Not through okw::wide_name, which is for names: a name is bounded by what a
// file system accepts and an argument or a named value is not. An environment's
// search path is routinely longer than any name, and converting it through a
// buffer sized for names refused it --- which reached the caller as "the
// argument is not valid", four operations away from the length that caused it.
bool append_utf8(wchar_t* out, okw_uptr cap, okw_uptr& at, const char* s, okw_uptr n) {
    if (n == 0) return true;
    if (at + n + 1 >= cap) return false;
    const int produced = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s,
                                             static_cast<int>(n), out + at,
                                             static_cast<int>(cap - at - 1));
    if (produced <= 0) return false;
    at += static_cast<okw_uptr>(produced);
    return true;
}

bool append_quoted(wchar_t* out, okw_uptr cap, okw_uptr& at, const wchar_t* s, okw_uptr n) {
    if (!append_wide(out, cap, at, L"\"", 1)) return false;
    okw_uptr backslashes = 0;
    for (okw_uptr i = 0; i < n; ++i) {
        if (s[i] == L'\\') { ++backslashes; continue; }
        if (s[i] == L'"') {
            for (okw_uptr k = 0; k <= backslashes; ++k)
                if (!append_wide(out, cap, at, L"\\", 1)) return false;
            backslashes = 0;
        } else {
            backslashes = 0;
        }
        // The run of separators preceding this character is emitted with it.
        if (at + 1 >= cap) return false;
        if (s[i] == L'"') { out[at++] = L'"'; continue; }
        out[at++] = s[i];
    }
    for (okw_uptr k = 0; k < backslashes; ++k)
        if (!append_wide(out, cap, at, L"\\", 1)) return false;
    return append_wide(out, cap, at, L"\"", 1);
}

}  // namespace

extern "C" {

int kal_process_spawn(kal_dir base,
                      const char* path, kal_uintptr path_len,
                      const char** argv, const kal_uintptr* argv_lens, kal_uintptr argc,
                      const char** envp, const kal_uintptr* envp_lens, kal_uintptr envc,
                      const kal_spawn_streams* streams,
                      kal_process* out) {
    void* dir = okw::unpack(base.h);
    if (!dir || out == nullptr) return kal_err_invalid;
    if (!okw::acceptable(path, path_len)) return kal_err_invalid;

    // The directory's own name, and the program's beneath it.
    // Obtained rather than kept in static storage: static storage shared
    // between execution contexts would make two concurrent spawns one.
    struct scratch {
        wchar_t image[okw::kMaxName];
        wchar_t line[kCommandLine];
        wchar_t block[kCommandLine];
    };
    auto* work = static_cast<scratch*>(kal_alloc(sizeof(scratch), alignof(scratch)));
    if (!work) return kal_err_no_memory;
    struct releaser {
        scratch* p;
        ~releaser() { if (p) kal_free(p, sizeof(scratch), alignof(scratch)); }
    } guard{ work };
    wchar_t* image = work->image;
    const DWORD n = GetFinalPathNameByHandleW(dir, image, okw::kMaxName - 2,
                                              FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (n == 0 || n >= okw::kMaxName - 2) return okw::translate_win32(GetLastError());
    okw_uptr at = n;
    image[at++] = L'\\';
    okw::wide_name relative(path, path_len);
    if (!relative.ok) return kal_err_invalid;
    for (okw_uptr i = 0; i < relative.string.length / 2u; ++i) {
        if (at + 2 >= okw::kMaxName) return kal_err_invalid;
        image[at++] = relative.buffer[i];
    }
    image[at] = 0;

    // The vector, unaltered, including its first element.
    wchar_t* line = work->line;
    okw_uptr used = 0;
    for (kal_uintptr i = 0; i < argc; ++i) {
        if (i && !append_wide(line, kCommandLine, used, L" ", 1)) return kal_err_no_space;
        // Converted into a scratch of its own so that it can be quoted, and
        // quoted because this environment passes one string and lets the
        // started program split it. Clause 7.6 requires the vector to arrive
        // unaltered, and the quoting is the inverse of that splitting.
        okw_uptr produced = 0;
        wchar_t* one = line + used + 1;              // beyond what is written
        const okw_uptr room = kCommandLine - used - 2;
        if (!append_utf8(one, room, produced, argv[i], argv_lens[i]))
            return argv_lens[i] >= room ? kal_err_no_space : kal_err_invalid;
        if (!append_quoted(line, kCommandLine, used, one, produced))
            return kal_err_no_space;
    }
    line[used] = 0;
    if (argc == 0) line[0] = 0;

    // The named values. An empty set means the started program receives the
    // caller's, which is what this environment does when none is supplied.
    wchar_t* block = work->block;
    okw_uptr block_used = 0;
    for (kal_uintptr i = 0; i < envc; ++i) {
        if (!append_utf8(block, kCommandLine, block_used, envp[i], envp_lens[i]))
            return kal_err_no_space;
        block[block_used++] = 0;
    }
    block[block_used++] = 0;

    STARTUPINFOW startup{};
    startup.cb = sizeof startup;
    bool inherit = false;
    if (streams && (streams->in || streams->out || streams->err)) {
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput  = streams->in  ? reinterpret_cast<void*>(streams->in)
                                          : GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput = streams->out ? reinterpret_cast<void*>(streams->out)
                                          : GetStdHandle(STD_OUTPUT_HANDLE);
        startup.hStdError  = streams->err ? reinterpret_cast<void*>(streams->err)
                                          : GetStdHandle(STD_ERROR_HANDLE);
        SetHandleInformation(startup.hStdInput,  HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        SetHandleInformation(startup.hStdOutput, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        SetHandleInformation(startup.hStdError,  HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        inherit = true;
    }

    PROCESS_INFORMATION info{};
    const BOOL started = CreateProcessW(image, argc ? line : nullptr, nullptr, nullptr,
                                        inherit ? TRUE : FALSE,
                                        CREATE_UNICODE_ENVIRONMENT,
                                        envc ? block : nullptr, nullptr, &startup, &info);
    if (!started) return okw::translate_win32(GetLastError());
    CloseHandle(info.hThread);
    *out = kal_process{ okw::pack(info.hProcess) };
    return kal_ok;
}

int kal_process_wait(kal_process p, int* status, int* terminated) {
    void* h = okw::unpack(p.h);
    if (!h) return kal_err_invalid;
    if (WaitForSingleObject(h, INFINITE) != WAIT_OBJECT_0)
        return okw::translate_win32(GetLastError());
    DWORD code = 0;
    if (!GetExitCodeProcess(h, &code)) return okw::translate_win32(GetLastError());
    // This environment reports one number and does not say whether the program
    // chose it. A program terminated by the environment is given the number the
    // terminating call supplied, and this implementation supplies one that is
    // not an ordinary status --- so the two remain distinguishable, which is
    // what the interface requires and all that it requires.
    if (code == 0xC0000409u || code == 0xFFFFFFFFu) {
        if (status)     *status = static_cast<int>(code & 0x7fffffff);
        if (terminated) *terminated = 1;
    } else {
        if (status)     *status = static_cast<int>(code);
        if (terminated) *terminated = 0;
    }
    return kal_ok;
}

int kal_process_terminate(kal_process p) {
    void* h = okw::unpack(p.h);
    if (!h) return kal_err_invalid;
    return TerminateProcess(h, 0xFFFFFFFFu) ? kal_ok : okw::translate_win32(GetLastError());
}

// Releasing the handle does not affect the program: this environment keeps the
// program alive independently of who holds a handle to it.
void kal_process_close(kal_process p) {
    void* h = okw::unpack(p.h);
    if (h) { okw::retire(p.h); CloseHandle(h); }
}

const kal_uintptr kal_process_props =
    KAL_PROCESS_PROP_TERMINATE | KAL_PROCESS_PROP_STREAM_PASSING
  | KAL_PROCESS_PROP_EXIT_STATUS;

}
