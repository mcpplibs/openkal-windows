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
// THE SOCKET IS MADE OVERLAPPED (WSA_FLAG_OVERLAPPED), AND VERSION 0.13
// REQUIRES IT. A synchronous handle on this system has one completion event
// shared by every operation upon it; two synchronous transfers issued from two
// contexts contend for that one event regardless of which direction each is
// in, so a read blocked waiting for the peer held back a write the peer was
// waiting for on the same connection --- clause 6.6 forbids exactly that.
// `ReadFile' and `WriteFile' upon the overlapped socket therefore each carry an
// `OVERLAPPED' of their own (src/stream.cpp), so the two directions no longer
// share anything to contend over. An earlier revision made the socket
// non-overlapped instead, on the reasoning that it would then behave exactly as
// a pipe does upon `ReadFile'; measured against two contexts and a bound, a
// write on one waited for a read blocked on the other, which is the connection
// clause 6.6 exists to rule out.

namespace {

SOCKET socket_of(kal_net_conn c)     { return okw::unpack_socket(c.h); }
SOCKET socket_of(kal_net_listener l) { return okw::unpack_socket(l.h); }

bool bad(SOCKET s) { return s == INVALID_SOCKET; }

okw::network_calls* net() { return okw::net_or_null(); }

SOCKET make(int family, int type, int protocol) {
    auto* n = net();
    return n ? n->socket(family, type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED_)
             : INVALID_SOCKET;
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

// A RENDEZVOUS AT A NAME (0.17). This system binds a local socket to a path
// and to nothing beneath a handle, and it has one working directory per
// process --- so the name is the directory's own, as the system resolves it,
// joined with the name. The address holds 108 bytes.
int at_name(kal_dir base, const char* name, kal_uintptr len, bool listen, kal_uintptr& out) {
    void* dir = okw::unpack(base.h);
    if (!dir || len == 0 || !okw::acceptable(name, len)) return kal_err_invalid;
    for (kal_uintptr i = 0; i < len; ++i) if (name[i] == '/' || name[i] == '\\') return kal_err_invalid;
    if ((kal_fs_props(base) & KAL_FS_PROP_LOCAL_ENDPOINT) == 0) return kal_err_not_supported;
    wchar_t wide[okw::kMaxName];
    DWORD n = GetFinalPathNameByHandleW(dir, wide, okw::kMaxName, 0);
    if (n == 0 || n >= okw::kMaxName) return okw::translate_win32(GetLastError());
    const wchar_t* w = wide;
    if (n >= 4 && w[0] == L'\\' && w[1] == L'\\' && w[2] == L'?' && w[3] == L'\\') { w += 4; n -= 4; }
    struct { unsigned short family; char path[108]; } addr{};
    addr.family = 1;
    char narrow[3 * okw::kMaxName];
    const okw_uptr dn = okw::narrow(w, n, narrow, sizeof narrow, false);
    if (dn == 0 || dn + 1 + len + 1 > sizeof addr.path) return kal_err_invalid;
    okw_uptr at = 0;
    for (okw_uptr i = 0; i < dn; ++i) addr.path[at++] = narrow[i];
    if (addr.path[at - 1] != '\\') addr.path[at++] = '\\';
    for (kal_uintptr i = 0; i < len; ++i) addr.path[at++] = name[i];
    addr.path[at] = 0;

    auto* nc = net();
    if (nc == nullptr) return kal_err_io;
    const SOCKET s = make(1 /* AF_UNIX */, SOCK_STREAM_, 0);
    if (bad(s)) return okw::last_socket_error();
    const int addr_len = static_cast<int>(sizeof addr.family + at + 1);
    auto* sa = reinterpret_cast<ksockaddr_storage*>(&addr);
    int rc = listen ? nc->bind(s, sa, addr_len) : nc->connect(s, sa, addr_len);
    if (rc == 0 && listen) rc = nc->listen(s, 128);
    if (rc != 0) {
        const int wsa = nc->last_error ? nc->last_error() : 0;
        const int e = okw::last_socket_error();
        nc->close(s);
        if (listen && wsa == 10048 /* WSAEADDRINUSE */) return kal_err_exists;
        if (!listen && (wsa == 10061 /* WSAECONNREFUSED */ || wsa == 2 || wsa == 10022)) return kal_err_not_found;
        return e;
    }
    out = okw::pack_socket(s);
    if (out == 0) { nc->close(s); return kal_err_no_memory; }
    return kal_ok;
}

}  // namespace

extern "C" {

int kal_net_listen_at(kal_dir base, const char* name, kal_uintptr len, kal_net_listener* out) {
    if (out == nullptr) return kal_err_invalid;
    return at_name(base, name, len, true, out->h);
}

int kal_net_connect_at(kal_dir base, const char* name, kal_uintptr len, kal_net_conn* out) {
    if (out == nullptr) return kal_err_invalid;
    return at_name(base, name, len, false, out->h);
}

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

    // SO_REUSEADDR DOES NOT MEAN HERE WHAT IT MEANS ON THE OTHER TWO SYSTEMS,
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

    // A CONNECTION INHERITS THE LISTENER'S PROPERTIES. The listener is made
    // overlapped, and an accepted connection is overlapped too --- which is what
    // src/stream.cpp's transfer path upon it relies upon.
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
    // A READ WAITING IN THE DIRECTION THAT ENDED ENDS TOO (0.17). This system
    // leaves an overlapped receive pending after `shutdown(SD_RECEIVE)', where
    // the other two systems end it with the end of input, so it is cancelled
    // here and src/stream.cpp reports the cancelled read as that end. Measured:
    // a program that ended a connection from another context waited two
    // minutes for its reader, on this system alone.
    if (how != SD_SEND_) CancelIoEx(reinterpret_cast<HANDLE>(s), nullptr);
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
