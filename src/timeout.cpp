#include "win.h"
#include "endpoint.h"
#include <openkal/timeout.h>

// openkal.timeout on this system.
//
// THE BOUND IS APPLIED BEFORE THE OPERATION AND NOT DURING IT, which is what
// clause 6.3 leaves an implementation able to do: `WSAPoll' reports whether a
// socket would transfer without blocking, so a bounded read is a bounded wait
// for readiness followed by the ordinary read.
//
// ⚠️⚠️ AND NO SINGLE CALL ANSWERS FOR EVERY RESOURCE HERE, WHICH IS THE ONE
// PLACE THIS SYSTEM DIFFERS FROM THE OTHER TWO IN KIND RATHER THAN IN SPELLING.
//
// There, one call answers for every descriptor. Here a socket, a pipe and a
// file are different kinds of object: `WSAPoll' takes only the first, a pipe is
// asked with `PeekNamedPipe', and a file is always ready because a read from
// one does not wait. Three enquiries, one per kind, chosen by asking what the
// handle is.
//
// ⭐ AND THE PIPE IS NOT OPTIONAL. `openkal.process' makes a channel out of a
// pipe here, so a C library above this implementation reaches `poll' and
// `select' upon one --- and a `select' that reported `kal_err_not_supported'
// for a pipe would make every program that waits on a subprocess's output stop.
// Measured: openkal-musl's own network probe, on the row that builds for this
// system, reported `select reports the read end ready (errno=38)'.
//
// ⚠️ A SOCKET ALSO REPORTS `FILE_TYPE_PIPE', so the socket enquiry is made
// FIRST and the file type only decides what a non-socket is.
//
// ⇒ What remains unbounded is a character device --- a console --- and
// `kal_err_not_supported' is what this interface states for a resource an
// implementation does not cover: "AN IMPLEMENTATION MAY PROVIDE THIS FOR SOME
// OF ITS RESOURCES AND NOT OTHERS, and reports kal_err_not_supported for the
// rest. That is not the defect clause 6.4 describes."

namespace {

// A duration of zero denotes no bound, which is the convention kal_task_wait
// establishes. `WSAPoll' expresses that with a negative number.
//
// ⚠️ A BOUND SHORTER THAN A MILLISECOND ROUNDS UP TO ONE AND NOT DOWN TO NONE.
// Rounding down would turn a wait into a poll, and the header is explicit: a
// caller that asks for less is not refused and does not get less.
int bound_ms(kal_u64 ns) {
    if (ns == 0) return -1;
    kal_u64 ms = ns / 1000000ull;
    if (ms == 0) ms = 1;
    if (ms > 0x7fffffffull) ms = 0x7fffffffull;
    return static_cast<int>(ms);
}

// Whether this word names a socket, which is the first question because a
// socket also reports `FILE_TYPE_PIPE'. `getsockname' is the enquiry that
// answers it: upon a socket it succeeds or fails for a reason of its own, and
// upon anything else this system reports `WSAENOTSOCK'.
bool is_socket(SOCKET s) {
    auto* n = okw::net_or_null();
    if (n == nullptr) return false;
    ksockaddr_storage ss{};
    int len = static_cast<int>(sizeof ss);
    if (n->sockname(s, &ss, &len) == 0) return true;
    return n->last_error() != okw::WSAENOTSOCK;
}

enum class shape { socket, pipe, ready, none };

shape shape_of(SOCKET raw) {
    if (is_socket(raw)) return shape::socket;
    switch (GetFileType(reinterpret_cast<HANDLE>(raw))) {
        case FILE_TYPE_PIPE: return shape::pipe;
        case FILE_TYPE_DISK: return shape::ready;   // a read from a file does not wait
        default:             return shape::none;    // a console, or nothing at all
    }
}

// Waits for one socket. Reports kal_ok when it is ready, kal_err_again when the
// bound expired, and a translated error otherwise.
int await(SOCKET s, short events, kal_u64 ns) {
    auto* n = okw::net_or_null();
    if (n == nullptr) return kal_err_not_supported;
    WSAPOLLFD_ p{ s, events, 0 };
    const int r = n->poll(&p, 1, bound_ms(ns));
    if (r < 0) return okw::last_socket_error();
    if (r == 0) return kal_err_again;   // the bound expired
    // A socket reported as failed or hung up is ready in the sense that the
    // operation which follows will not wait: it will report what happened.
    return kal_ok;
}

// Waits for a pipe to have bytes, without taking them.
//
// ⭐ `PeekNamedPipe' IS THE ONE NON-DESTRUCTIVE READINESS ENQUIRY IN THIS WHOLE
// ECOSYSTEM, and it is why this implementation needs no read-ahead where the
// port above it does. It reports how many bytes are there and takes none.
//
// ⚠️ A CLOSED WRITING END IS READY AND NOT AN ERROR. The call then fails with
// `ERROR_BROKEN_PIPE', and a read that follows reports the end of input without
// waiting --- which is what readiness asserts. Reporting the failure here would
// make a program that reads until end-of-input wait for ever instead.
int await_pipe(HANDLE h, kal_u64 ns) {
    const int ms = bound_ms(ns);
    kal_u64 waited = 0;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(h, nullptr, 0, nullptr, &available, nullptr)) {
            const DWORD e = GetLastError();
            if (e == ERROR_BROKEN_PIPE || e == ERROR_PIPE_NOT_CONNECTED) return kal_ok;
            return okw::translate_win32(e);
        }
        if (available > 0) return kal_ok;
        if (ms == 0) return kal_err_again;
        if (ms > 0 && waited >= static_cast<kal_u64>(ms)) return kal_err_again;
        // The interval this interface reports as its granularity, so the cost of
        // the loop is the number already stated rather than a second one.
        Sleep(1);
        waited += 1;
    }
}

int await_stream(kal_stream s, short events, kal_u64 ns) {
    // ⚠️ ONE REASON TO REFUSE, AND NOT TWO. An earlier form answered a null or
    // invalid handle with `kal_err_invalid' and everything else with
    // `kal_err_not_supported', and the conformance suite reported both bounded
    // reads of the standard input as not holding: a run whose standard input is
    // not attached has a handle of zero, and the suite's list of admissible
    // answers is the interface's --- success, an expiry, or a refusal.
    //
    // ⭐ The early return was answering a DIFFERENT QUESTION. "Is this handle
    // valid" is what the unbounded operation answers; what this interface
    // answers is whether this implementation can bound an operation upon this
    // resource.
    const SOCKET raw = static_cast<SOCKET>(s.h);
    switch (shape_of(raw)) {
        case shape::socket: return await(raw, events, ns);
        case shape::pipe:
            // Writability is not enquired of: this system has no call that
            // reports whether a pipe would accept bytes without blocking, and a
            // write to one completes or reports. openkal-musl's okm_poll.c
            // records the same answer for the same reason.
            if (events == POLLWRNORM_) return kal_ok;
            return await_pipe(reinterpret_cast<HANDLE>(raw), ns);
        case shape::ready:  return kal_ok;
        case shape::none:   return kal_err_not_supported;
    }
    return kal_err_not_supported;
}

}  // namespace

extern "C" {

kal_io_result kal_timeout_read(kal_stream s, void* buf, kal_uintptr len, kal_u64 ns) {
    // A transfer of zero bytes does not wait and is not bounded. Waiting first
    // would turn a call that always succeeds into one that can expire.
    if (len == 0) return { 0, kal_ok };

    if (const int rc = await_stream(s, POLLRDNORM_, ns); rc != kal_ok)
        return { 0, rc };
    return kal_stream_read(s, buf, len);
}

kal_io_result kal_timeout_write(kal_stream s, const void* buf, kal_uintptr len, kal_u64 ns) {
    if (len == 0) return { 0, kal_ok };

    if (const int rc = await_stream(s, POLLWRNORM_, ns); rc != kal_ok)
        return { 0, rc };
    return kal_stream_write(s, buf, len);
}

int kal_timeout_accept(kal_net_listener l, kal_u64 ns, kal_net_conn* out) {
    if (out == nullptr) return kal_err_invalid;
    const SOCKET s = okw::unpack_socket(l.h);
    if (s == INVALID_SOCKET) return kal_err_invalid;

    if (const int rc = await(s, POLLRDNORM_, ns); rc != kal_ok) return rc;
    return kal_net_accept(l, out);
}

kal_io_result kal_timeout_recv_from(kal_datagram d, void* buf, kal_uintptr len,
                                    kal_endpoint* from, kal_u64 ns) {
    const SOCKET s = okw::unpack_socket(d.h);
    if (s == INVALID_SOCKET) return { 0, kal_err_invalid };

    if (const int rc = await(s, POLLRDNORM_, ns); rc != kal_ok) return { 0, rc };
    return kal_datagram_recv_from(d, buf, len, from);
}

int kal_timeout_wait_process(kal_process p, kal_u64 ns, int* status, int* terminated) {
    void* h = okw::unpack(p.h);
    if (h == nullptr) return kal_err_invalid;

    // ⭐ THE ONE OPERATION OF THIS INTERFACE THIS SYSTEM PROVIDES DIRECTLY. The
    // other two poll a child in a loop because neither has a bounded wait for
    // one; here waiting upon an object with a bound IS the primitive, and the
    // bound is stated in the same milliseconds `WSAPoll' takes.
    const DWORD r = WaitForSingleObject(h, ns == 0 ? INFINITE
                                                   : static_cast<DWORD>(bound_ms(ns)));
    if (r == WAIT_TIMEOUT_) return kal_err_again;
    if (r != WAIT_OBJECT_0) return okw::translate_win32(GetLastError());

    DWORD code = 0;
    if (!GetExitCodeProcess(h, &code)) return okw::translate_win32(GetLastError());
    if (status) *status = static_cast<int>(code);
    // This system does not distinguish a program that ended by returning from
    // one the environment ended: both are an exit code, and process.cpp reports
    // the same thing.
    if (terminated) *terminated = 0;
    return kal_ok;
}

// The bound this system distinguishes. Both `WSAPoll' and the wait upon an
// object state theirs in milliseconds, and there is no call here that takes
// less --- so a millisecond is what an implementation can honestly report.
const kal_uintptr kal_timeout_granularity_ns = 1000000u;

}  // extern "C"
