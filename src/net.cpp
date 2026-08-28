#include "win.h"
#include "endpoint.h"
#include <openkal/net.h>

// openkal.net upon this system's network interface.
//
// A CONNECTION IS AN OWNED HANDLE AND THE STREAM IS BORROWED FROM IT, exactly as
// kal_file and kal_fs_stream are here. The owned handle carries a generation so
// that a released one stops being valid, which clause 7.2 requires; the stream
// it yields is the socket itself, because a socket IS a handle on this system
// and openkal.stream's operations here are `ReadFile' and `WriteFile'.
//
// ⭐⭐ THAT LAST SENTENCE IS THE WHOLE REASON THIS IMPLEMENTATION NEEDS NO
// SECOND TRANSFER PATH, AND IT IS TRUE ONLY BECAUSE OF THE FLAGS WORD PASSED TO
// `WSASocketW'. The ordinary `socket' makes an OVERLAPPED handle, whose reads
// and writes complete asynchronously; `ReadFile' upon one of those returns
// before the bytes have arrived. A flags word of zero makes a socket that is
// not overlapped, and the two calls then behave exactly as they do upon a pipe.
// This is stated here rather than left in the argument list because a change to
// that one zero would not fail to compile and would not fail to link.

namespace {

SOCKET socket_of(kal_net_conn c)     { return okw::unpack_socket(c.h); }
SOCKET socket_of(kal_net_listener l) { return okw::unpack_socket(l.h); }

bool bad(SOCKET s) { return s == INVALID_SOCKET; }

okw::network_calls* net() { return okw::net_or_null(); }

SOCKET make(int family, int type, int protocol) {
    auto* n = net();
    return n ? n->socket(family, type, protocol, nullptr, 0, 0) : INVALID_SOCKET;
}

int report_address(bool peer, SOCKET s, kal_endpoint* out) {
    if (out == nullptr) return kal_err_invalid;
    if (bad(s)) return kal_err_invalid;
    auto* n = net();
    if (n == nullptr) return kal_err_io;
    ksockaddr_storage ss{};
    int len = static_cast<int>(sizeof ss);
    const int r = peer ? n->peername(s, &ss, &len) : n->sockname(s, &ss, &len);
    if (r != 0) return okw::last_socket_error();
    return okw::from_system(ss, *out);
}

}  // namespace

extern "C" {

int kal_net_connect(const kal_endpoint* to, kal_net_conn* out) {
    if (to == nullptr || out == nullptr) return kal_err_invalid;
    const int family = okw::family_of(*to);
    if (family < 0) return kal_err_invalid;

    ksockaddr_storage ss{};
    int len = 0;
    if (const int rc = okw::to_system(*to, ss, len); rc != kal_ok) return rc;

    auto* n = net();
    if (n == nullptr) return kal_err_io;
    const SOCKET s = make(family, SOCK_STREAM_, IPPROTO_TCP_);
    if (bad(s)) return okw::last_socket_error();

    if (n->connect(s, &ss, len) != 0) {
        const int e = okw::last_socket_error();
        n->close(s);
        return e;
    }

    out->h = okw::pack_socket(s);
    if (out->h == 0) { n->close(s); return kal_err_no_memory; }
    return kal_ok;
}

int kal_net_listen(const kal_endpoint* local, kal_net_listener* out) {
    if (local == nullptr || out == nullptr) return kal_err_invalid;
    const int family = okw::family_of(*local);
    if (family < 0) return kal_err_invalid;

    ksockaddr_storage ss{};
    int len = 0;
    if (const int rc = okw::to_system(*local, ss, len); rc != kal_ok) return rc;

    auto* n = net();
    if (n == nullptr) return kal_err_io;
    const SOCKET s = make(family, SOCK_STREAM_, IPPROTO_TCP_);
    if (bad(s)) return okw::last_socket_error();

    // ⚠️ SO_REUSEADDR DOES NOT MEAN HERE WHAT IT MEANS ON THE OTHER TWO SYSTEMS,
    // AND THAT IS WHY IT IS NOT SET.
    //
    // There it permits a listener whose predecessor is lingering. Here it
    // permits TWO LISTENERS ON THE SAME ADDRESS AT ONCE --- a second program
    // may bind the port a first one is already serving, and which of them
    // receives a connection is unspecified. This system does not need the
    // option for the case the other two need it for: a listening socket's
    // address is released when the handle closes.
    //
    // Setting it for symmetry would therefore not make the three
    // implementations behave alike; it would make this one behave differently
    // from the other two while looking the same.

    if (n->bind(s, &ss, len) != 0) {
        const int e = okw::last_socket_error();
        n->close(s);
        return e;
    }

    // The backlog the system is asked for. A number rather than a name, because
    // this interface does not expose one and a caller has no way to state it.
    if (n->listen(s, 128) != 0) {
        const int e = okw::last_socket_error();
        n->close(s);
        return e;
    }

    out->h = okw::pack_socket(s);
    if (out->h == 0) { n->close(s); return kal_err_no_memory; }
    return kal_ok;
}

int kal_net_accept(kal_net_listener l, kal_net_conn* out) {
    if (out == nullptr) return kal_err_invalid;
    const SOCKET s = socket_of(l);
    if (bad(s)) return kal_err_invalid;
    auto* n = net();
    if (n == nullptr) return kal_err_io;

    const SOCKET c = n->accept(s, nullptr, nullptr);
    if (bad(c)) return okw::last_socket_error();

    // ⚠️ A CONNECTION INHERITS THE LISTENER'S PROPERTIES AND NOT ITS FLAGS WORD.
    // The listener was made non-overlapped; an accepted connection is
    // non-overlapped too, which is what keeps `ReadFile' synchronous upon it.
    out->h = okw::pack_socket(c);
    if (out->h == 0) { n->close(c); return kal_err_no_memory; }
    return kal_ok;
}

kal_stream kal_net_stream(kal_net_conn c) {
    // The socket itself, for the reason kal_fs_stream gives: openkal.stream's
    // operations take whatever this system's transfer calls take, and a packed
    // word is not that.
    const SOCKET s = socket_of(c);
    return kal_stream{ bad(s) ? 0u : static_cast<kal_uintptr>(s) };
}

int kal_net_peer(kal_net_conn c, kal_endpoint* out) {
    return report_address(true, socket_of(c), out);
}

int kal_net_local(kal_net_conn c, kal_endpoint* out) {
    return report_address(false, socket_of(c), out);
}

int kal_net_listener_local(kal_net_listener l, kal_endpoint* out) {
    return report_address(false, socket_of(l), out);
}

int kal_net_shutdown(kal_net_conn c, int direction) {
    const SOCKET s = socket_of(c);
    if (bad(s)) return kal_err_invalid;

    // This system numbers the directions from zero and this interface from one,
    // so the mapping is written out rather than arithmetic upon the argument. A
    // direction this interface does not define is refused rather than passed
    // through, because the system would read an unknown number as "receive".
    int how;
    switch (direction) {
        case KAL_SHUT_READ:  how = SD_RECEIVE_; break;
        case KAL_SHUT_WRITE: how = SD_SEND_;    break;
        case KAL_SHUT_BOTH:  how = SD_BOTH_;    break;
        default: return kal_err_invalid;
    }

    auto* n = net();
    if (n == nullptr) return kal_err_io;
    if (n->shutdown(s, how) != 0) return okw::last_socket_error();
    return kal_ok;
}

void kal_net_close(kal_net_conn c) {
    const SOCKET s = socket_of(c);
    if (bad(s)) return;
    if (auto* n = net()) n->close(s);
    okw::retire(c.h);
}

void kal_net_close_listener(kal_net_listener l) {
    const SOCKET s = socket_of(l);
    if (bad(s)) return;
    if (auto* n = net()) n->close(s);
    okw::retire(l.h);
}

// Both positions hold on this system: it speaks IPv6, and its `shutdown' ends
// transfer in one direction while the other continues.
kal_uintptr kal_net_props(void) { return KAL_NET_PROP_IPV6 | KAL_NET_PROP_HALFCLOSE; }

}  // extern "C"
