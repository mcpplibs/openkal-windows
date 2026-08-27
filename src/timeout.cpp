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
// ⚠️⚠️ AND `WSAPoll' ANSWERS FOR SOCKETS AND FOR NOTHING ELSE, WHICH IS THE ONE
// PLACE THIS SYSTEM DIFFERS FROM THE OTHER TWO IN KIND RATHER THAN IN SPELLING.
//
// There, one call answers for every descriptor. Here a socket and a file are
// different kinds of object and the readiness call takes only the first; a pipe
// is asked with `PeekNamedPipe', a file is always ready, and a console has its
// own enquiry. openkal.timeout's header anticipates exactly this: "AN
// IMPLEMENTATION MAY PROVIDE THIS FOR SOME OF ITS RESOURCES AND NOT OTHERS, and
// reports kal_err_not_supported for the rest. That is not the defect clause 6.4
// describes."
//
// ⇒ `kal_timeout_read' and `kal_timeout_write' upon a stream that is not a
// socket report `kal_err_not_supported'. That is a stated answer a caller can
// act upon --- and it is the honest one, because the alternative is to wait a
// while and then attempt the transfer anyway, which would report `kal_err_again'
// for a pipe that had data and block for one that did not.

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

// Whether this word names a socket, which is the question the note above makes
// unavoidable. `getsockname' is the enquiry that answers it: upon a socket it
// succeeds or fails for a reason of its own, and upon anything else this system
// reports `WSAENOTSOCK'.
bool is_socket(SOCKET s) {
    auto* n = okw::net_or_null();
    if (n == nullptr) return false;
    ksockaddr_storage ss{};
    int len = static_cast<int>(sizeof ss);
    if (n->sockname(s, &ss, &len) == 0) return true;
    return n->last_error() != okw::WSAENOTSOCK;
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

int await_stream(kal_stream s, short events, kal_u64 ns) {
    // ⚠️ ONE REASON TO REFUSE, AND NOT TWO. An earlier form answered a null or
    // invalid handle with `kal_err_invalid' and a valid non-socket with
    // `kal_err_not_supported', and the conformance suite reported both bounded
    // reads of the standard input as not holding: a run whose standard input is
    // not attached has a handle of zero, and the suite's list of admissible
    // answers is the interface's --- success, an expiry, or a refusal.
    //
    // ⭐ The early return was answering a DIFFERENT QUESTION. "Is this handle
    // valid" is what the unbounded operation answers; what this interface
    // answers is whether this implementation can bound an operation upon this
    // resource, and the header sanctions exactly one refusal for that: "AN
    // IMPLEMENTATION MAY PROVIDE THIS FOR SOME OF ITS RESOURCES AND NOT OTHERS,
    // and reports kal_err_not_supported for the rest." A handle that is not a
    // socket is one of the rest, and zero is not a socket.
    const SOCKET raw = static_cast<SOCKET>(s.h);
    if (!is_socket(raw)) return kal_err_not_supported;
    return await(raw, events, ns);
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
