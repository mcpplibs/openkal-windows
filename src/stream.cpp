#include "win.h"
#include "endpoint.h"
#include <openkal/stream.h>

// The transfer operations of openkal.stream. A file, a pipe and a socket all
// arrive here as one HANDLE-shaped word; every one of them reads and writes
// through `ReadFile'/`WriteFile', and a socket differs only in how the one
// transfer is carried out --- see below and src/net.cpp's note on why a socket
// is overlapped at all, version 0.13.

namespace {

void* handle_of(kal_stream s) { return reinterpret_cast<void*>(s.h); }

bool valid(void* h) { return h != nullptr && h != INVALID_HANDLE_VALUE; }

// One transfer upon an overlapped handle: an event of its own, issued and
// waited for synchronously, so that this call's completion does not depend on
// or contend with another transfer in the other direction upon the same
// handle. `kal_stream_read'/`kal_stream_write' remain synchronous from their
// caller's point of view; only the mechanism underneath changes.
//
// A count short of what was asked is a correct report of an overlapped
// transfer exactly as it is of a synchronous one --- this is one call, not the
// loop `kal_stream_write' performs to satisfy clause 7.4.
bool overlapped_once(void* h, void* buf, DWORD want, bool write,
                     DWORD* moved, DWORD* err) {
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ev == nullptr) { *err = GetLastError(); return false; }
    OVERLAPPED ov{};
    ov.hEvent = ev;
    const BOOL immediate = write ? WriteFile(h, buf, want, moved, &ov)
                                 : ReadFile(h, buf, want, moved, &ov);
    bool ok = immediate != 0;
    if (!ok) {
        const DWORD e = GetLastError();
        if (e == ERROR_IO_PENDING) {
            ok = GetOverlappedResult(h, &ov, moved, TRUE) != 0;
            if (!ok) *err = GetLastError();
        } else {
            *err = e;
        }
    }
    CloseHandle(ev);
    return ok;
}

}  // namespace

extern "C" {

// The three streams the environment supplies. They are borrowed: openkal does
// not release them and neither does this.
kal_stream kal_stdin (void) { return kal_stream{ reinterpret_cast<kal_uintptr>(GetStdHandle(STD_INPUT_HANDLE)) }; }
kal_stream kal_stdout(void) { return kal_stream{ reinterpret_cast<kal_uintptr>(GetStdHandle(STD_OUTPUT_HANDLE)) }; }
kal_stream kal_stderr(void) { return kal_stream{ reinterpret_cast<kal_uintptr>(GetStdHandle(STD_ERROR_HANDLE)) }; }

namespace {
// AN INTERACTIVE CONSOLE IS WRITTEN AS CHARACTERS (K10). `WriteFile' gives the
// console bytes, which it reads in the console's code page --- a page that is
// not UTF-8 on an ordinary installation --- so `é' arrived as two characters
// that are not it. The console's own call takes the characters themselves.
//
// A write may end inside a character, so the bytes of an incomplete one are
// kept for the next write to the same console; the standard streams are the
// consoles there are, and a handful of slots holds them.
struct carry { void* h; unsigned char bytes[4]; unsigned n; };
carry g_carry[4];
SRWLOCK_ g_carry_lock{};

bool console_output(void* h) {
    DWORD m = 0;
    CONSOLE_SCREEN_BUFFER_INFO_ info{};
    return GetConsoleMode(h, &m) != 0 && GetConsoleScreenBufferInfo(h, &info) != 0;
}

// The length of the UTF-8 sequence a lead byte begins; 1 for anything else,
// which the conversion then reports as a replacement character.
unsigned sequence_length(unsigned char b) {
    if (b < 0x80) return 1;
    if ((b & 0xe0) == 0xc0) return 2;
    if ((b & 0xf0) == 0xe0) return 3;
    if ((b & 0xf8) == 0xf0) return 4;
    return 1;
}

kal_intptr write_console(void* h, const unsigned char* p, kal_uintptr len) {
    AcquireSRWLockExclusive(&g_carry_lock);
    carry* c = nullptr;
    for (auto& slot : g_carry) if (slot.h == h) { c = &slot; break; }
    if (!c) for (auto& slot : g_carry) if (slot.h == nullptr) { slot.h = h; slot.n = 0; c = &slot; break; }
    unsigned char head[4]; unsigned held = 0;
    if (c) { for (unsigned i = 0; i < c->n; ++i) head[i] = c->bytes[i]; held = c->n; c->n = 0; }
    ReleaseSRWLockExclusive(&g_carry_lock);

    // The whole characters of (held bytes, then p), in chunks; an incomplete
    // last character is carried.
    kal_uintptr at = 0;
    wchar_t wide[2048];
    unsigned char bytes[4096];
    while (held > 0 || at < len) {
        kal_uintptr n = 0;
        while (held > 0 && n < held) { bytes[n] = head[n]; ++n; }
        held = 0;
        while (at < len && n < sizeof bytes) bytes[n++] = p[at++];
        // Back off an incomplete trailing character.
        kal_uintptr end = n, i = n;
        while (i > 0 && i + 4 > n && (bytes[i - 1] & 0xc0) == 0x80) --i;
        if (i > 0 && i - 1 + sequence_length(bytes[i - 1]) > n) end = i - 1;
        if (at >= len && end < n) {
            AcquireSRWLockExclusive(&g_carry_lock);
            if (c) { c->n = static_cast<unsigned>(n - end); for (unsigned k = 0; k < c->n; ++k) c->bytes[k] = bytes[end + k]; }
            ReleaseSRWLockExclusive(&g_carry_lock);
        } else if (end < n) {
            for (kal_uintptr k = end; k < n; ++k) head[k - end] = bytes[k];
            held = static_cast<unsigned>(n - end);
        }
        if (end == 0) continue;
        const int w = MultiByteToWideChar(65001 /* CP_UTF8 */, 0, reinterpret_cast<const char*>(bytes),
                                          static_cast<int>(end), wide, 2048);
        if (w <= 0) return -kal_err_invalid;
        for (int done = 0; done < w; ) {
            DWORD written = 0;
            if (!WriteConsoleW(h, wide + done, static_cast<DWORD>(w - done), &written, nullptr))
                return at ? static_cast<kal_intptr>(at) : -okw::translate_win32(GetLastError());
            if (written == 0) break;
            done += static_cast<int>(written);
        }
    }
    return static_cast<kal_intptr>(len);
}
}  // namespace

// ONE SIGNED WORD: the count, or the negated condition when no byte moved.
kal_intptr kal_stream_write(kal_stream s, const void* buf, kal_uintptr len) {
    void* h = handle_of(s);
    if (!valid(h)) return -kal_err_invalid;
    if (len > 0 && !okw::is_socket_handle(h) && console_output(h))
        return write_console(h, static_cast<const unsigned char*>(buf), len);
    const bool socket = okw::is_socket_handle(h);
    const auto* p = static_cast<const unsigned char*>(buf);
    kal_uintptr done = 0;
    while (done < len) {
        // The transfer is bounded by what one call accepts, and the loop is
        // here rather than in the caller. Clause 7.4: the alternative
        // convention places one loop in every caller and has been a recurring
        // source of defects in the interfaces that adopted it.
        const kal_uintptr want = len - done;
        const DWORD chunk = want > 0x7fffffffu ? 0x7fffffffu : static_cast<DWORD>(want);
        DWORD written = 0;
        DWORD err = 0;
        const bool ok = socket
            ? overlapped_once(h, const_cast<unsigned char*>(p + done), chunk,
                              true, &written, &err)
            : WriteFile(h, p + done, chunk, &written, nullptr) != 0;
        if (!ok) {
            if (!socket) err = GetLastError();
            if (done != 0) return static_cast<kal_intptr>(done);
            return -okw::translate_win32(err);
        }
        if (written == 0) break;
        done += written;
    }
    return static_cast<kal_intptr>(done);
}

kal_intptr kal_stream_read(kal_stream s, void* buf, kal_uintptr len) {
    void* h = handle_of(s);
    if (!valid(h)) return -kal_err_invalid;
    const bool socket = okw::is_socket_handle(h);
    if (socket && okw::read_ended(reinterpret_cast<SOCKET>(h))) return 0;
    const DWORD want = len > 0x7fffffffu ? 0x7fffffffu : static_cast<DWORD>(len);
    DWORD got = 0;
    DWORD err = 0;
    const bool ok = socket
        ? overlapped_once(h, buf, want, false, &got, &err)
        : ReadFile(h, buf, want, &got, nullptr) != 0;
    if (!ok) {
        if (!socket) err = GetLastError();
        // The end of a pipe whose other side has gone is the end of input, and
        // this environment reports it as a failure. A caller that could not
        // tell the two apart would treat every completed transfer as broken.
        if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) return 0;
        // A socket whose read direction was ended while this read waited: the
        // read was cancelled (src/net.cpp, kal_net_shutdown), and it is the
        // end of input, as the other two systems report it.
        if (socket && okw::read_ended(reinterpret_cast<SOCKET>(h))) return 0;
        return -okw::translate_win32(err);
    }
    // A short read is reported as it occurred: unlike a short write it carries
    // information the caller requires, and zero denotes the end of input.
    return static_cast<kal_intptr>(got);
}

int kal_stream_flush(kal_stream s) {
    void* h = handle_of(s);
    if (!valid(h)) return kal_err_invalid;
    // A stream that is not a file has nothing to commit, and the question is
    // asked before the operation rather than inferred from the failure it
    // produces: this environment reports several different failures for a
    // console and for a pipe, and an implementation that guessed which of them
    // meant "nothing to do" would report a real failure to reach a medium as
    // success on the day the list was incomplete.
    if (GetFileType(h) != FILE_TYPE_DISK) return kal_ok;
    if (FlushFileBuffers(h)) return kal_ok;
    return okw::translate_win32(GetLastError());
}

kal_uintptr kal_stream_props(kal_stream s) {
    void* h = handle_of(s);
    if (!valid(h)) return 0;
    // The enquiry this environment offers: reading a console's mode succeeds
    // for a console and fails otherwise. It is the same question every C
    // library asks before choosing a buffering discipline, and it is asked here
    // so that the library above need not know which environment it is upon.
    DWORD mode = 0;
    return GetConsoleMode(h, &mode) ? KAL_STREAM_PROP_INTERACTIVE : kal_uintptr{0};
}

}
