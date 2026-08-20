#include "win.h"
#include <openkal/stream.h>

namespace {

void* handle_of(kal_stream s) { return reinterpret_cast<void*>(s.h); }

bool valid(void* h) { return h != nullptr && h != INVALID_HANDLE_VALUE; }

}  // namespace

extern "C" {

// The three streams the environment supplies. They are borrowed: openkal does
// not release them and neither does this.
kal_stream kal_stdin (void) { return kal_stream{ reinterpret_cast<kal_uintptr>(GetStdHandle(STD_INPUT_HANDLE)) }; }
kal_stream kal_stdout(void) { return kal_stream{ reinterpret_cast<kal_uintptr>(GetStdHandle(STD_OUTPUT_HANDLE)) }; }
kal_stream kal_stderr(void) { return kal_stream{ reinterpret_cast<kal_uintptr>(GetStdHandle(STD_ERROR_HANDLE)) }; }

kal_io_result kal_stream_write(kal_stream s, const void* buf, kal_uintptr len) {
    void* h = handle_of(s);
    if (!valid(h)) return { 0, kal_err_invalid };
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
        if (!WriteFile(h, p + done, chunk, &written, nullptr))
            return { done, okw::translate_win32(GetLastError()) };
        if (written == 0) break;
        done += written;
    }
    return { done, done == len ? kal_ok : kal_err_io };
}

kal_io_result kal_stream_read(kal_stream s, void* buf, kal_uintptr len) {
    void* h = handle_of(s);
    if (!valid(h)) return { 0, kal_err_invalid };
    const DWORD want = len > 0x7fffffffu ? 0x7fffffffu : static_cast<DWORD>(len);
    DWORD got = 0;
    if (!ReadFile(h, buf, want, &got, nullptr)) {
        const unsigned long e = GetLastError();
        // The end of a pipe whose other side has gone is the end of input, and
        // this environment reports it as a failure. A caller that could not
        // tell the two apart would treat every completed transfer as broken.
        if (e == ERROR_BROKEN_PIPE || e == ERROR_HANDLE_EOF) return { 0, kal_ok };
        return { 0, okw::translate_win32(e) };
    }
    // A short read is reported as it occurred: unlike a short write it carries
    // information the caller requires, and zero denotes the end of input.
    return { got, kal_ok };
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
