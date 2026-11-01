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

// THE NAMES A STARTED PROGRAM IS GIVEN, IN THE FORM EVERY PROGRAM READS.
//
// GetFinalPathNameByHandleW answers with the `\\?\' prefix, which tells this
// system to take the rest verbatim. CreateProcessW accepts it, and the started
// program inherits it as its current directory --- where the command interpreter
// refuses it ("UNC paths are not supported") and runs in the Windows directory
// instead. A batch file, which is how many tools are installed on this system,
// therefore ran somewhere other than where it was started. So the prefix is
// removed wherever the name means the same without it: a drive path within the
// classic bound, and a network share in its `\\server\share' form. A longer name
// keeps the prefix, because without it the name would not be accepted at all.
okw_uptr plain_name(wchar_t* s, okw_uptr n) {
    // MAX_PATH, less the separator and the terminator a current directory takes.
    constexpr okw_uptr kClassic = 258;
    const bool verbatim = n >= 4 && s[0] == L'\\' && s[1] == L'\\' && s[2] == L'?' && s[3] == L'\\';
    if (!verbatim) return n;
    const bool drive = n >= 7 && ((s[4] >= L'A' && s[4] <= L'Z') || (s[4] >= L'a' && s[4] <= L'z'))
                       && s[5] == L':' && s[6] == L'\\';
    const bool share = n >= 8 && (s[4] == L'U' || s[4] == L'u') && (s[5] == L'N' || s[5] == L'n')
                       && (s[6] == L'C' || s[6] == L'c') && s[7] == L'\\';
    okw_uptr drop = 0;
    if (drive && n - 4 <= kClassic)      drop = 4;   // \\?\C:\dir      -> C:\dir
    else if (share && n - 6 <= kClassic) drop = 6;   // \\?\UNC\host\x  -> \\host\x
    if (drop == 0) return n;
    for (okw_uptr i = drop; i <= n; ++i) s[i - drop] = s[i];   // the terminator too
    if (drop == 6) s[0] = L'\\';
    return n - drop;
}

// A SPAWN INHERITS ONLY THE HANDLES IT PLACED. Version 0.13.
//
// `CreateProcessW' with inheritance enabled gives the started program EVERY
// inheritable handle of this process, not only the three in its start-up
// record --- and that was once the whole of what this implementation relied
// upon: a caller-inheritable handle the caller had not placed here crossed the
// spawn anyway, because bInheritHandles does not discriminate. A detached
// child then kept a starter's own standard output open long after the starter
// had gone, and whoever waited for the end of that pipe waited for the wrong
// program to end. `PROC_THREAD_ATTRIBUTE_HANDLE_LIST' is the position this
// system offers for exactly that: it narrows what `CreateProcessW' inherits to
// the array named there, and a handle outside it is not inherited even when it
// is itself marked inheritable for some reason of the caller's own.
//
// A handle in that array must still be marked inheritable, which is the half
// this file already did: each placed handle is marked, the program is
// started, and each is put back as it was --- a borrowed standard stream is
// the caller's and not this operation's to change --- with a lock around the
// whole of it, because marking is a property of the handle and not of the
// call.
SRWLOCK_ g_starting{};

struct inheritance {
    HANDLE handle[3]{};
    DWORD  before[3]{};
    bool   marked[3]{};
    bool   held = false;
    // The handles this start actually places, deduplicated: what goes into
    // PROC_THREAD_ATTRIBUTE_HANDLE_LIST. The system refuses a list holding one
    // handle twice, which stdout and stderr placed upon the same pipe would
    // otherwise be.
    HANDLE list[3]{};
    DWORD  count = 0;

    inheritance(bool active, HANDLE in, HANDLE out, HANDLE err) {
        if (!active) return;
        AcquireSRWLockExclusive(&g_starting);
        held = true;
        const HANDLE given[3] = { in, out, err };
        for (int i = 0; i < 3; ++i) {
            handle[i] = given[i];
            if (given[i] == nullptr || given[i] == INVALID_HANDLE_VALUE) continue;
            // One stream placed twice --- output and error, typically --- is
            // marked and put back once, and named once in the list below.
            bool again = false;
            for (int j = 0; j < i; ++j) again = again || (marked[j] && handle[j] == given[i]);
            if (again) continue;
            DWORD flags = 0;
            if (!GetHandleInformation(given[i], &flags)) continue;
            before[i] = flags & HANDLE_FLAG_INHERIT;
            marked[i] = SetHandleInformation(given[i], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) != 0;
            // A handle this system would not make inheritable --- a console
            // pseudo-handle is the ordinary case --- is not named here either:
            // naming an uninheritable handle in the explicit list is refused by
            // the call that builds it, where the old, unrestricted inheritance
            // simply left such a handle uninherited.
            if (marked[i]) list[count++] = given[i];
        }
    }
    ~inheritance() {
        for (int i = 2; i >= 0; --i)
            if (marked[i]) SetHandleInformation(handle[i], HANDLE_FLAG_INHERIT, before[i]);
        if (held) ReleaseSRWLockExclusive(&g_starting);
    }
};

// The attribute list naming `window.list' to `CreateProcessW'. Obtained and
// released around one call, the way `scratch' below is: this system sizes the
// buffer for a caller, so there is a first call that only measures.
struct attribute_list {
    void* buffer = nullptr;
    unsigned long long size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;

    bool build(const inheritance& window) {
        if (window.count == 0) return false;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        buffer = kal_alloc(static_cast<kal_uintptr>(size), alignof(void*));
        if (buffer == nullptr) return false;
        list = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer);
        if (!InitializeProcThreadAttributeList(list, 1, 0, &size)) { list = nullptr; return false; }
        // `window.list' outlives this call --- it is the caller's local, held
        // until CreateProcessW returns --- so nothing here copies it again.
        if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                       const_cast<HANDLE*>(window.list),
                                       static_cast<unsigned long long>(window.count) * sizeof(HANDLE),
                                       nullptr, nullptr)) {
            DeleteProcThreadAttributeList(list);
            list = nullptr;
            return false;
        }
        return true;
    }
    ~attribute_list() {
        if (list) DeleteProcThreadAttributeList(list);
        if (buffer) kal_free(buffer, static_cast<kal_uintptr>(size), alignof(void*));
    }
};

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

// UNTIL 0.7.3 EVERY SEPARATOR WAS DROPPED, AND EVERY ELEMENT WAS QUOTED.
//
// A run of backslashes was counted and never written, so `C:\dir\file' arrived as
// `C:dirfile' and a trailing one ended the quoting early and joined the elements
// after it. And an element that needs no quoting was quoted anyway, which the
// splitting accepts and the command interpreter does not: it reads `"/c"' as a
// command rather than as its switch, and a batch file --- run through the
// interpreter --- received a line it called incorrect. Now an element is written
// as it is unless the splitting would alter it, and otherwise quoted by the rule
// the splitting inverts: backslashes before a quote are doubled and the quote
// escaped, backslashes before the closing quote are doubled, and every other
// backslash is literal.
bool append_quoted(wchar_t* out, okw_uptr cap, okw_uptr& at, const wchar_t* s, okw_uptr n) {
    bool needs = n == 0;
    for (okw_uptr i = 0; i < n && !needs; ++i)
        needs = s[i] == L' ' || s[i] == L'\t' || s[i] == L'\n' || s[i] == L'\v' || s[i] == L'"';
    if (!needs) return append_wide(out, cap, at, s, n);

    if (!append_wide(out, cap, at, L"\"", 1)) return false;
    okw_uptr backslashes = 0;
    for (okw_uptr i = 0; i < n; ++i) {
        if (s[i] == L'\\') { ++backslashes; continue; }
        const okw_uptr written = s[i] == L'"' ? 2 * backslashes + 1 : backslashes;
        for (okw_uptr k = 0; k < written; ++k)
            if (!append_wide(out, cap, at, L"\\", 1)) return false;
        backslashes = 0;
        if (!append_wide(out, cap, at, s + i, 1)) return false;
    }
    for (okw_uptr k = 0; k < 2 * backslashes; ++k)
        if (!append_wide(out, cap, at, L"\\", 1)) return false;
    return append_wide(out, cap, at, L"\"", 1);
}

// --- the handles of this interface (0.17) ------------------------------------
//
// The top byte of a process word says which of four things it names; handle.h
// leaves that byte free. A started program is its process handle, as it always
// was. A started program whose lifetime is bound to this one carries a record
// beside it (below). This program itself names no handle at all. A program
// found by its identifier is the handle `OpenProcess' gave, which keeps the
// identifier from being given to another program while it is held.
constexpr okw_uptr kind_child = 0, kind_self = 1, kind_opened = 2, kind_bound = 3;
inline okw_uptr kind_of(kal_process p) { return p.h >> 56; }
inline okw_uptr with_kind(okw_uptr w, okw_uptr kind) {
    return (w & 0x00ffffffffffffffull) | (kind << 56);
}

// A STARTED PROGRAM WHOSE LIFETIME IS BOUND TO THIS ONE (K5).
//
// The primitive is a job that ends its members when its last handle closes
// (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE): this program holds the only handle, and
// however this program ends, the system closes it. One job per started
// program, and not one for all of them, because a program that is also placed
// in a unit of the caller's (`kal_spawn.job') is already in that job, and this
// system nests a second job beneath the first only while the second is empty.
//
// The job's handle must outlive every caller-visible operation on the program,
// so the word names a record of the two handles --- a pointer to a structure of
// this implementation's own, which clause 7.2 lists among what a handle may be.
// The record is released with the process handle; the job's handle is released
// only once the program has ended, since releasing it earlier would end the
// program. A record is never reused, so a released word is refused (`gone').
struct bound_record {
    void* process;
    void* job;
    int   gone;
};
inline bound_record* bound_of(kal_process p) {
    return reinterpret_cast<bound_record*>(p.h & 0x00ffffffffffffffull);
}

// The process handle a word names, whatever its kind; null for none.
inline void* process_of(kal_process p) {
    switch (kind_of(p)) {
        case kind_child:  return okw::unpack(p.h);
        case kind_self:   return GetCurrentProcess();
        case kind_opened: return okw::unpack(with_kind(p.h, 0));
        case kind_bound: {
            bound_record* r = bound_of(p);
            return (r && !r->gone) ? r->process : nullptr;
        }
        default: return nullptr;
    }
}


// --- what a program and a unit use, and a limit on a unit (openkal 0.20) ----
//
// A PROGRAM'S MEMORY is its commit charge (`K32GetProcessMemoryInfo':
// `PagefileUsage' now, `PeakPagefileUsage' at most), which is what a job counts
// and limits. A process object keeps its counters after the program ends, for as
// long as a handle to it is held.
//
// A UNIT IS A JOB OBJECT, which counts its own members (`ActiveProcesses') and
// its own commit (`JobMemory').
//
// A LIMIT IS HELD BY THE JOB (HARD): JOB_OBJECT_LIMIT_JOB_MEMORY refuses an
// allocation that would take the job over its limit. What the specification
// states is that the WHOLE unit ends, and the job alone would only refuse: so
// each limited job reports to one completion port, a context started with the
// first limit waits on it, and on the job's report that it reached its limit it
// ends the job. A program of a limited job that ended because an allocation was
// refused, before that context ended the rest, is told apart by the job's own
// record of the violation.
struct limited { HANDLE job; int ended; };
// The number a job ended for its limit gives its programs: one with the
// customer bit set, which no status of this system's own has.
constexpr UINT kLimitCode = 0xE0DA1001u;
constexpr int kLimited = 64;
limited g_limited[kLimited];
SRWLOCK_ g_limited_lock{};
HANDLE g_port = nullptr;
int g_watching = 0;

DWORD OKW_API watch(LPVOID) {
    for (;;) {
        DWORD message = 0; unsigned long long key = 0; OVERLAPPED* detail = nullptr;
        if (!GetQueuedCompletionStatus(g_port, &message, &key, &detail, INFINITE)) continue;
        if (message != JOB_OBJECT_MSG_JOB_MEMORY_LIMIT_) continue;
        AcquireSRWLockExclusive(&g_limited_lock);
        for (auto& r : g_limited)
            if (r.job && reinterpret_cast<unsigned long long>(r.job) == key) {
                r.ended = 1;
                TerminateJobObject(r.job, kLimitCode);
            }
        ReleaseSRWLockExclusive(&g_limited_lock);
    }
}

// Whether `process' ended because a limited job it belongs to reached its limit.
bool ended_by_limit(HANDLE process) {
    bool limit = false;
    AcquireSRWLockExclusive(&g_limited_lock);
    for (const auto& r : g_limited) {
        if (!r.job) continue;
        BOOL in = FALSE;
        if (!IsProcessInJob(process, r.job, &in) || !in) continue;
        JOB_VIOLATION_ v{};
        if (r.ended || (QueryInformationJobObject(r.job, JobObjectLimitViolationInformation_, &v, sizeof v, nullptr)
                        && (v.ViolationLimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY_)))
            limit = true;
    }
    ReleaseSRWLockExclusive(&g_limited_lock);
    return limit;
}

}  // namespace

namespace {
}  // namespace

namespace okw {
// The process handle a word names, for the operations outside this file that
// wait on a started program (timeout.cpp): a word of a program started with a
// bound lifetime names its record, not its handle (0.13.2).
void* process_handle(kal_process p) { return process_of(p); }
}  // namespace okw

namespace {

// EVERY ENVIRONMENT ENTRY IS `NAME=value' (0.17, process.h).
bool entries_well_formed(const char** envp, const kal_uintptr* lens, kal_uintptr n) {
    for (kal_uintptr i = 0; i < n; ++i) {
        if (envp[i] == nullptr) return false;
        kal_uintptr eq = 0;
        while (eq < lens[i] && envp[i][eq] != '=') ++eq;
        if (eq == 0 || eq == lens[i]) return false;
    }
    return true;
}

}  // namespace

extern "C" {

// Starting a program. One function since openkal 0.11.
//
// TWO POSITIONS IN `kal_spawn' ARE REFUSED HERE, AND EACH REFUSAL
// IS OLDER THAN 0.11 --- the record moved, the answers did not.
//
// `grants': this environment has no numbering a preopen could arrive under, so
// there is no correspondence to descriptor three. KAL_PROCESS_PROP_GRANT_DIR is
// not claimed. A count of zero asks for a program with no preopens, which is
// what a program here gets anyway, so that request IS answerable and is
// answered.
//
// `KAL_SPAWN_BOUND_LIFETIME' WAS REFUSED HERE UNTIL 0.13, on the ground that no
// primitive arms it from inside the started image. None needs to: a job that
// ends its members when its last handle closes is armed from OUTSIDE, by the
// caller, and the system closes the caller's handle however the caller ends.
// See `bound_record'.
//
// AND THE UNIT IS IMPLEMENTED HERE, WHICH AN EARLIER SHAPE OF IT WAS NOT.
//
// 0.11 first spelled this as a flag: make the started program a unit, and let
// `kal_process_terminate' reach the unit afterwards. That shape could not be
// satisfied here. This system can FORM the unit --- a job object is exactly it ---
// but it cannot RECOVER one from a process handle, and `kal_process' is one word
// already holding the process. The other two implementations needed no storage
// because `getpgid(pid) == pid' recovers it from the kernel; this one would have
// needed a registry.
//
// Clause 7.1 states mechanically what needing a registry means: the
// specification "has taken a shape borrowed from one environment, and THE SHAPE
// IS AT FAULT rather than the implementation". handle.h says the same one level
// down --- its array "holds generations and nothing else", and a lookup deciding
// what a word referred to "would be a defect here".
//
// ⇒ So the shape changed rather than this file acquiring a table. The unit is now
// a handle the CALLER holds, whose identity is established at the first start, and
// both kinds of system perform that without remembering anything: here a job
// object is created and its handle reported; where the unit is a process group
// the first member's identifier is reported instead.
//
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE IS DELIBERATELY NOT SET. It would make
// `kal_process_job_close' end every member --- and closing means only releasing
// where the unit is a number, so one operation would mean two things. Ending is
// `kal_process_job_terminate' and nothing else is.
int kal_process_spawn(const kal_spawn* how,
                      const char* path, kal_uintptr path_len,
                      const char** argv, const kal_uintptr* argv_lens, kal_uintptr argc,
                      const char** envp, const kal_uintptr* envp_lens, kal_uintptr envc,
                      const kal_spawn_streams* streams,
                      kal_process* out) {
    if (how == nullptr || out == nullptr) return kal_err_invalid;
    void* dir = okw::unpack(how->base.h);
    void* run = okw::unpack(how->work.h);
    if (!dir || !run) return kal_err_invalid;
    if (!okw::acceptable(path, path_len)) return kal_err_invalid;
    if (how->grant_count > 0) return kal_err_not_supported;
    if ((how->flags & ~(KAL_SPAWN_BOUND_LIFETIME | KAL_SPAWN_ONE_STRING)) != 0) return kal_err_not_supported;
    // Clause 7.6, 0.17.1: the elements after the first joined as they are.
    const bool one_string = (how->flags & KAL_SPAWN_ONE_STRING) != 0;
    if (envc > 0 && (envp == nullptr || envp_lens == nullptr)) return kal_err_invalid;
    if (!entries_well_formed(envp, envp_lens, envc)) return kal_err_invalid;
    const bool bound = (how->flags & KAL_SPAWN_BOUND_LIFETIME) != 0;

    // The unit, created before its first member and reported to the caller. A
    // later member is assigned to the one the caller already holds.
    HANDLE unit = nullptr;
    bool   unit_is_new = false;
    if (how->job) {
        if (how->job->h != 0) {
            unit = okw::unpack(how->job->h);
            if (!unit) return kal_err_invalid;
        } else {
            unit = CreateJobObjectW(nullptr, nullptr);
            if (!unit) return okw::translate_win32(GetLastError());
            unit_is_new = true;
        }
    }
    struct unit_guard {
        HANDLE h; bool own;
        ~unit_guard() { if (own && h) CloseHandle(h); }
    } ug{ unit, unit_is_new };

    // The directory's own name, and the program's beneath it.
    // Obtained rather than kept in static storage: static storage shared
    // between execution contexts would make two concurrent spawns one.
    struct scratch {
        wchar_t image[okw::kMaxName];
        // THE DIRECTORY THE PROGRAM RUNS IN, WHICH IS NOT THE ONE IT IS NAMED
        // FROM. `CreateProcessW' has taken a current directory all along; what
        // was missing until 0.11 was a caller able to say which.
        wchar_t cwd[okw::kMaxName];
        wchar_t line[kCommandLine];
        // One element, converted before it is quoted into `line'. Its own
        // buffer: quoting lengthens an element, so converting it in place just
        // beyond what `line' holds had the quoting overwrite what it had not
        // yet read.
        wchar_t one[kCommandLine];
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
    (void)plain_name(image, at);

    // The same enquiry the image path comes from, upon the other directory.
    wchar_t* cwd = work->cwd;
    const DWORD cn = GetFinalPathNameByHandleW(run, cwd, okw::kMaxName - 1,
                                               FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (cn == 0 || cn >= okw::kMaxName - 1) return okw::translate_win32(GetLastError());
    cwd[cn] = 0;
    (void)plain_name(cwd, cn);

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
        wchar_t* one = work->one;
        const okw_uptr room = kCommandLine - 1;
        if (!append_utf8(one, room, produced, argv[i], argv_lens[i]))
            return argv_lens[i] >= room ? kal_err_no_space : kal_err_invalid;
        if (one_string && i > 0) {
            // KAL_SPAWN_ONE_STRING: the program parses this string by rules of
            // its own (the command interpreter's /c), so it is passed as it is.
            if (!append_wide(line, kCommandLine, used, one, produced)) return kal_err_no_space;
        } else if (!append_quoted(line, kCommandLine, used, one, produced)) {
            return kal_err_no_space;
        }
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

    STARTUPINFOEXW ex{};
    STARTUPINFOW& startup = ex.startup;
    startup.cb = sizeof(STARTUPINFOW);
    bool inherit = false;
    if (streams && (streams->in.h || streams->out.h || streams->err.h)) {
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput  = streams->in.h  ? reinterpret_cast<void*>(streams->in.h)
                                            : GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput = streams->out.h ? reinterpret_cast<void*>(streams->out.h)
                                            : GetStdHandle(STD_OUTPUT_HANDLE);
        startup.hStdError  = streams->err.h ? reinterpret_cast<void*>(streams->err.h)
                                            : GetStdHandle(STD_ERROR_HANDLE);
        inherit = true;
    }

    PROCESS_INFORMATION info{};
    BOOL  started = FALSE;
    DWORD refusal = 0;
    {
        inheritance window(inherit, startup.hStdInput, startup.hStdOutput, startup.hStdError);

        // ONLY THE HANDLES `window' NAMED ARE ASKED TO CROSS. Without an
        // explicit list, bInheritHandles=TRUE would still hand the started
        // program every inheritable handle of this process, so it is set only
        // together with the list that narrows what that means; a request with
        // nothing markable inherits nothing rather than everything.
        attribute_list attrs;
        // SUSPENDED WHEN IT IS TO BE PLACED, so that nothing it starts can
        // escape the job before the job holds it.
        DWORD creation = CREATE_UNICODE_ENVIRONMENT | (bound || unit ? 0x4u /* CREATE_SUSPENDED */ : 0u);
        BOOL  inherit_handles = FALSE;
        if (window.count > 0 && attrs.build(window)) {
            startup.cb = sizeof(STARTUPINFOEXW);
            ex.lpAttributeList = attrs.list;
            creation |= EXTENDED_STARTUPINFO_PRESENT;
            inherit_handles = TRUE;
        }

        started = CreateProcessW(image, argc ? line : nullptr, nullptr, nullptr,
                                 inherit_handles, creation,
                                 envc ? block : nullptr, cwd, &startup, &info);
        // Read before the handles are put back, which may set it again.
        if (!started) refusal = GetLastError();
    }
    if (!started) return okw::translate_win32(refusal);

    // ASSIGNED BEFORE THE CALLER IS TOLD ANYTHING. A program that could not be
    // put into the unit is not the program that was asked for --- it would outlive
    // a termination of the unit --- so it is ended rather than handed back.
    if (unit && !AssignProcessToJobObject(unit, info.hProcess)) {
        const DWORD why = GetLastError();
        TerminateProcess(info.hProcess, 127);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        return okw::translate_win32(why);
    }

    // THE BOUND LIFETIME (K5), nested beneath the unit where there is one.
    bound_record* record = nullptr;
    if (bound) {
        void* job = CreateJobObjectW(nullptr, nullptr);
        JOB_LIMITS limits{};
        limits.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE_;
        record = static_cast<bound_record*>(kal_alloc(sizeof(bound_record), alignof(bound_record)));
        if (!job || !record
            || !SetInformationJobObject(job, JobObjectExtendedLimitInformation_, &limits, sizeof limits)
            || !AssignProcessToJobObject(job, info.hProcess)) {
            const DWORD why = GetLastError();
            TerminateProcess(info.hProcess, 127);
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
            if (job) CloseHandle(job);
            if (record) kal_free(record, sizeof(bound_record), alignof(bound_record));
            return record ? okw::translate_win32(why) : kal_err_no_memory;
        }
        record->process = info.hProcess;
        record->job = job;
        record->gone = 0;
    }
    if (bound || unit) ResumeThread(info.hThread);
    CloseHandle(info.hThread);

    // The caller's word, written only now, and only for a unit this start made.
    if (unit_is_new) { how->job->h = okw::pack(unit); ug.own = false; }

    *out = record ? kal_process{ with_kind(reinterpret_cast<okw_uptr>(record), kind_bound) }
                  : kal_process{ okw::pack(info.hProcess) };
    return kal_ok;
}

int kal_process_self(kal_process* out) {
    if (out == nullptr) return kal_err_invalid;
    *out = kal_process{ with_kind(GetCurrentProcessId(), kind_self) };
    return kal_ok;
}

// A program found by its identifier. The handle keeps the identifier from being
// given to another program while it is held, which is what makes `started_ns'
// and `ended' answers about this program and not a later one.
int kal_process_open_id(kal_u64 id, kal_process* out) {
    if (out == nullptr || id == 0) return kal_err_invalid;
    if (id > 0xffffffffull) return kal_err_not_found;
    void* h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
                          static_cast<DWORD>(id));
    if (!h) {
        const DWORD e = GetLastError();
        return e == 87 /* ERROR_INVALID_PARAMETER: no such program */ ? kal_err_not_found
                                                                      : okw::translate_win32(e);
    }
    const okw_uptr w = okw::pack(h);
    if (w == 0 || (w >> 56) != 0) { CloseHandle(h); return kal_err_no_memory; }
    *out = kal_process{ with_kind(w, kind_opened) };
    return kal_ok;
}

int kal_process_info(kal_process p, kal_u32 wanted, kal_program_info* out) {
    if (out == nullptr || out->self_size < 8) return kal_err_invalid;
    void* h = process_of(p);
    if (!h) return kal_err_invalid;
    const kal_u32 self = out->self_size;
    kal_program_info v{};
    v.self_size = self;
    v.id = kind_of(p) == kind_self ? GetCurrentProcessId() : GetProcessId(h);
    v.present = KAL_PINFO_ID | KAL_PINFO_ENDED;
    v.ended = kind_of(p) != kind_self && WaitForSingleObject(h, 0) == 0 /* WAIT_OBJECT_0 */;
    FILETIME created{}, exited{}, kernel{}, user{};
    if ((wanted & (KAL_PINFO_STARTED | KAL_PINFO_CPU)) && GetProcessTimes(h, &created, &exited, &kernel, &user)) {
        auto ticks = [](const FILETIME& f) {
            return (static_cast<unsigned long long>(f.dwHighDateTime) << 32) | f.dwLowDateTime;
        };
        if (wanted & KAL_PINFO_STARTED) { v.started_ns = ticks(created) * 100ull; v.present |= KAL_PINFO_STARTED; }
        if (wanted & KAL_PINFO_CPU) { v.cpu_ns = (ticks(kernel) + ticks(user)) * 100ull; v.present |= KAL_PINFO_CPU; }
    }
    // MEMORY (openkal 0.20): the commit charge now and at most; the process
    // object keeps both after the program ends, while the handle is held.
    PROCESS_MEMORY_COUNTERS_EX_ m{};
    m.cb = sizeof m;
    if ((wanted & KAL_PINFO_MEMORY) && self >= sizeof v
        && K32GetProcessMemoryInfo(kind_of(p) == kind_self ? GetCurrentProcess() : h, &m, sizeof m)) {
        v.memory_bytes = v.ended ? 0 : m.PagefileUsage;
        v.memory_peak_bytes = m.PeakPagefileUsage > m.PagefileUsage ? m.PeakPagefileUsage : m.PagefileUsage;
        v.present |= KAL_PINFO_MEMORY;
    }
    const kal_u32 n = self < sizeof v ? self : static_cast<kal_u32>(sizeof v);
    auto* d = reinterpret_cast<unsigned char*>(out);
    const auto* s = reinterpret_cast<const unsigned char*>(&v);
    for (kal_u32 i = 0; i < n; ++i) d[i] = s[i];
    return kal_ok;
}

// A WORD THIS ENVIRONMENT SETS WHEN SOMEBODY HAS ASKED THIS PROGRAM TO END.
//
// AND THIS IS WHY THE INTERFACE IS A WORD RATHER THAN A HANDLER. The
// notification here arrives ON A CONTEXT OF ITS OWN --- the environment starts one
// to run the routine --- which is nothing like a disposition interrupting whatever
// was running. An interface shaped like the other system's signals would have
// had to pretend one was the other; a word both can set needs no pretending.
//
// The routine stores and wakes, which is all `kal_task_wait' needs on the other
// side. Returning false lets the default handling proceed, so a program that
// never reads the word behaves as it always did.
namespace {
kal_u32 g_stop_word = 0;
int     g_stop_armed = 0;

// HANDLED, AND THE PROGRAM CONTINUES (K3). Returning false passed the event to
// the next routine, whose default is to end the program at once --- so the
// word was set and the program was gone before anything could read it.
// Measured: a console interrupt ended the program the word was armed in.
//
// Ctrl+C and Ctrl+Break are handled and the program continues. A console that
// is closing, a user logging off and a system shutting down are recorded the
// same way; for those this system ends the program shortly after the routine
// returns, whatever it returns, which process.h states as a request that is
// not a veto.
//
// THE TAKE-OVER RULE (0.17) HOLDS WITHOUT ANYTHING HERE: a program started
// with Ctrl+C disabled (CREATE_NEW_PROCESS_GROUP) keeps that flag, which
// installing a routine does not clear, so a request its starter declined
// stays declined.
BOOL OKW_API stop_routine(DWORD) {
    g_stop_word = 1;
    WakeByAddressAll(&g_stop_word);
    return TRUE;
}
}  // namespace

// Armed on the first enquiry, so that adding this operation changes nothing
// for a program that does not use it.
const kal_u32* kal_process_stop_requested(void) {
    if (!g_stop_armed) { g_stop_armed = 1; SetConsoleCtrlHandler(stop_routine, TRUE); }
    return &g_stop_word;
}

// ENDS AS THE REQUEST WOULD HAVE ENDED THE PROGRAM (0.17): with the status this
// system records for a program a console interrupt ended, which a waiting
// starter reads as `terminated' and a shell as the interrupt.
int kal_process_end_as_requested(void) {
    if (g_stop_word == 0) return kal_err_invalid;
    ExitProcess(STATUS_CONTROL_C_EXIT_);
    return kal_err_invalid;
}

// This program itself joins or forms a unit. NATURAL HERE TOO, and by the
// route this environment already offers: a job object is created before it has
// members, so the caller simply becomes its first one.
int kal_process_job_enter(kal_job* j) {
    if (j == nullptr) return kal_err_invalid;
    HANDLE unit = nullptr;
    bool made = false;
    if (j->h != 0) {
        unit = okw::unpack(j->h);
        if (!unit) return kal_err_invalid;
    } else {
        unit = CreateJobObjectW(nullptr, nullptr);
        if (!unit) return okw::translate_win32(GetLastError());
        made = true;
    }
    if (!AssignProcessToJobObject(unit, GetCurrentProcess())) {
        const DWORD why = GetLastError();
        if (made) CloseHandle(unit);
        return okw::translate_win32(why);
    }
    if (made) j->h = okw::pack(unit);
    return kal_ok;
}

// Every program in the unit. A job ends its members as one, which is the whole
// reason this environment's job object is the right thing to build a unit from.
int kal_process_job_terminate(kal_job j) {
    HANDLE h = okw::unpack(j.h);
    if (!h) return kal_err_invalid;
    // The number a terminating call supplies here (`kal_process_terminate'
    // uses it too), so that `kal_process_wait' reports the members as ended
    // rather than as having returned 15 (0.16).
    if (!TerminateJobObject(h, 0xFFFFFFFFu)) return okw::translate_win32(GetLastError());
    return kal_ok;
}

// RELEASES AND DOES NOT END. The limit that would have ended the members on
// the last close is deliberately not set --- see the note above kal_process_spawn.
void kal_process_job_close(kal_job j) {
    HANDLE h = okw::unpack(j.h);
    if (!h) return;
    AcquireSRWLockExclusive(&g_limited_lock);
    for (auto& r : g_limited) if (r.job == h) r = limited{};
    ReleaseSRWLockExclusive(&g_limited_lock);
    okw::retire(j.h); CloseHandle(h);
}

// WHAT A UNIT USES (openkal 0.20): the job's own counts.
int kal_process_job_usage(kal_job j, kal_job_usage* out) {
    if (out == nullptr || out->self_size < 8) return kal_err_invalid;
    HANDLE h = okw::unpack(j.h);
    if (!h) return kal_err_invalid;
    JOB_ACCOUNTING_ a{};
    JOB_VIOLATION_ v{};
    if (!QueryInformationJobObject(h, JobObjectBasicAccountingInformation_, &a, sizeof a, nullptr))
        return okw::translate_win32(GetLastError());
    if (a.ActiveProcesses == 0) return kal_err_invalid;
    kal_job_usage u{};
    u.self_size = out->self_size;
    u.members = a.ActiveProcesses;
    if (QueryInformationJobObject(h, JobObjectLimitViolationInformation_, &v, sizeof v, nullptr))
        u.memory_bytes = v.JobMemory;
    const kal_u32 n = out->self_size < sizeof u ? out->self_size : static_cast<kal_u32>(sizeof u);
    auto* d = reinterpret_cast<unsigned char*>(out);
    const auto* s = reinterpret_cast<const unsigned char*>(&u);
    for (kal_u32 i = 0; i < n; ++i) d[i] = s[i];
    return kal_ok;
}

// A LIMIT ON A UNIT (openkal 0.20), held by the job and its end made whole by
// the context that waits on the job's reports.
int kal_process_job_limit(kal_job j, kal_uintptr kind, kal_u64 value) {
    if (kind != KAL_JOB_LIMIT_MEMORY) return kal_err_invalid;
    HANDLE h = okw::unpack(j.h);
    if (!h) return kal_err_invalid;
    JOB_LIMITS limits{};
    if (!QueryInformationJobObject(h, JobObjectExtendedLimitInformation_, &limits, sizeof limits, nullptr))
        return okw::translate_win32(GetLastError());
    if (value == 0) limits.LimitFlags &= ~JOB_OBJECT_LIMIT_JOB_MEMORY_;
    else { limits.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY_; limits.JobMemoryLimit = value; }

    AcquireSRWLockExclusive(&g_limited_lock);
    limited* row = nullptr;
    for (auto& r : g_limited) if (r.job == h) row = &r;
    const bool fresh = row == nullptr;
    if (!row) for (auto& r : g_limited) if (!r.job) { row = &r; break; }
    if (!row && value != 0) { ReleaseSRWLockExclusive(&g_limited_lock); return kal_err_no_memory; }
    if (fresh && value != 0) {
        if (!g_port) g_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        JOB_PORT_ port{ h, g_port };
        if (!g_port || !SetInformationJobObject(h, JobObjectAssociateCompletionPortInformation_, &port, sizeof port)) {
            const DWORD why = GetLastError();
            ReleaseSRWLockExclusive(&g_limited_lock);
            return okw::translate_win32(why);
        }
        *row = limited{ h, 0 };
    }
    ReleaseSRWLockExclusive(&g_limited_lock);
    if (!SetInformationJobObject(h, JobObjectExtendedLimitInformation_, &limits, sizeof limits))
        return okw::translate_win32(GetLastError());
    if (value != 0) {
        AcquireSRWLockExclusive(&g_limited_lock);
        const bool start = g_watching == 0;
        g_watching = 1;
        ReleaseSRWLockExclusive(&g_limited_lock);
        if (start) {
            HANDLE t = CreateThread(nullptr, 64 * 1024, &watch, nullptr, 0, nullptr);
            if (!t) {
                AcquireSRWLockExclusive(&g_limited_lock);
                g_watching = 0;
                ReleaseSRWLockExclusive(&g_limited_lock);
                return okw::translate_win32(GetLastError());
            }
            CloseHandle(t);
        }
    }
    return kal_ok;
}

// A channel: a pair of streams of which one end is meant to cross a spawn.
//
// NEITHER END IS INHERITABLE, AND UNTIL 0.7.2 THE FAR ONE WAS FROM THE MOMENT
// IT WAS CREATED.
//
// This environment decides inheritance per handle, and a start with inheritance
// enabled gives the program every inheritable handle of this process. A far end
// created inheritable therefore reached every program started while it existed:
// the program at the other end of the channel, when the channel carried that
// program's input --- it then held the writing end of its own input and never
// observed the end of it, so a parent that wrote and closed waited for ever for a
// child still reading --- and any program another context started meanwhile,
// which kept the pipe open after the program it belonged to had ended.
//
// The two descriptor implementations create both ends close-on-exec for exactly
// that reason and let the spawn place the far one deliberately, and this one now
// does the same: `kal_process_spawn' marks the handles it places for the length of
// the start (see `inheritance' above).
int kal_process_channel(kal_stream* mine, kal_stream* theirs) {
    if (mine == nullptr || theirs == nullptr) return kal_err_invalid;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = FALSE;

    HANDLE reading = nullptr, writing = nullptr;
    if (!CreatePipe(&reading, &writing, &sa, 0))
        return okw::translate_win32(GetLastError());

    // Bare handles rather than packed ones, because openkal.stream's transfer
    // operations take what this environment takes. kal_fs_stream reports a
    // file's stream the same way and for the same reason.
    *mine   = kal_stream{ reinterpret_cast<kal_uintptr>(reading) };
    *theirs = kal_stream{ reinterpret_cast<kal_uintptr>(writing) };
    return kal_ok;
}

void kal_process_channel_close(kal_stream s) {
    void* h = reinterpret_cast<void*>(s.h);
    if (h == nullptr || h == INVALID_HANDLE_VALUE) return;
    // The standard streams are borrowed. Closing one through this operation
    // would take a stream away from the whole program.
    if (h == GetStdHandle(STD_INPUT_HANDLE)  ||
        h == GetStdHandle(STD_OUTPUT_HANDLE) ||
        h == GetStdHandle(STD_ERROR_HANDLE)) return;
    CloseHandle(h);
}


int kal_process_wait(kal_process p, int* status, int* terminated) {
    if (kind_of(p) == kind_self) return kal_err_invalid;
    if (kind_of(p) == kind_opened) return kal_err_not_supported;
    void* h = process_of(p);
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
    // A program ended by a console interrupt, or ending as one asked it to
    // (kal_process_end_as_requested), is reported as ended by its environment.
    // A program of a limited job that ended for the job's limit --- ended with
    // the job, or by a refused allocation first --- is reported as limited.
    if (code == kLimitCode || ended_by_limit(h)) {
        if (status)     *status = static_cast<int>(code & 0x7fffffff);
        if (terminated) *terminated = KAL_TERMINATED_LIMIT;
    } else if (code == 0xC0000409u || code == 0xFFFFFFFFu || code == STATUS_CONTROL_C_EXIT_) {
        if (status)     *status = static_cast<int>(code & 0x7fffffff);
        if (terminated) *terminated = 1;
    } else {
        if (status)     *status = static_cast<int>(code);
        if (terminated) *terminated = 0;
    }
    return kal_ok;
}

int kal_process_terminate(kal_process p) {
    if (kind_of(p) == kind_self) return kal_err_invalid;
    if (kind_of(p) == kind_opened) return kal_err_not_supported;
    void* h = process_of(p);
    if (!h) return kal_err_invalid;
    return TerminateProcess(h, 0xFFFFFFFFu) ? kal_ok : okw::translate_win32(GetLastError());
}

// Releasing the handle does not affect the program: this environment keeps the
// program alive independently of who holds a handle to it.
void kal_process_close(kal_process p) {
    switch (kind_of(p)) {
        case kind_self: return;
        case kind_bound: {
            bound_record* r = bound_of(p);
            if (!r || r->gone) return;
            r->gone = 1;
            // The job is released only once the program has ended: releasing it
            // earlier would end the program, and releasing a handle does not.
            if (WaitForSingleObject(r->process, 0) == 0) CloseHandle(r->job);
            CloseHandle(r->process);
            return;
        }
        case kind_opened: {
            const okw_uptr w = with_kind(p.h, 0);
            void* h = okw::unpack(w);
            if (h) { okw::retire(w); CloseHandle(h); }
            return;
        }
        default: {
            void* h = okw::unpack(p.h);
            if (h) { okw::retire(p.h); CloseHandle(h); }
        }
    }
}

// ONE POSITION IS DELIBERATELY ABSENT, BECAUSE THE CALL REFUSES IT. A word
// claiming a facility the operation then declines is the disagreement clause
// 6.2 exists to prevent, so the two are written together and read together:
//
//   GRANT_DIR       kal_process_spawn refuses a non-empty `grants'
//
// BOUND_LIFETIME and STOP_REQUESTED were absent until 0.13 (K5, K3).
kal_uintptr kal_process_props(void) { return
    KAL_PROCESS_PROP_TERMINATE | KAL_PROCESS_PROP_STREAM_PASSING
  | KAL_PROCESS_PROP_EXIT_STATUS
  | KAL_PROCESS_PROP_CHANNEL
  | KAL_PROCESS_PROP_JOB
  | KAL_PROCESS_PROP_JOB_USAGE | KAL_PROCESS_PROP_JOB_LIMIT_HARD   // 0.16: the job's counts and ceiling
  | KAL_PROCESS_PROP_BOUND_LIFETIME    // K5: a job that ends with this program
  | KAL_PROCESS_PROP_STOP_REQUESTED    // K3: the routine handles, and the word is read
  | KAL_PROCESS_PROP_OPEN_ID
  | KAL_PROCESS_PROP_ONE_STRING; }   // 0.17.1: a program here receives one string

}
