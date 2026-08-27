// Conversion between kal_endpoint and this system's socket addresses, the
// second error mapping, and the one initialisation this system's network
// interface requires.
//
// SHARED BY openkal.net AND openkal.datagram BECAUSE ALL THREE ARE. Either
// interface may be provided without the other, so none of this belongs to
// either; writing it twice would be one decision stated in two places, and the
// two would eventually disagree about which lengths are accepted.
#pragma once
#include "handle.h"
#include <openkal/types.h>

namespace okw {

// ── the network's own error values ──────────────────────────────────────────
//
// ⚠️ A SECOND MAPPING, AND NOT AN ALTERNATIVE SPELLING OF THE FIRST. Every
// other call in this implementation reports through `GetLastError'; these
// report through `WSAGetLastError', and the numbering does not overlap ---
// every value below is ten thousand and something. Passing one of them to
// `translate_win32' produces `kal_err_io' for all of them, which is a mapping
// that compiles, runs, and tells a caller nothing.
enum : int {
    WSAEINTR = 10004, WSAEACCES = 10013, WSAEFAULT = 10014, WSAEINVAL = 10022,
    WSAEMFILE = 10024, WSAEWOULDBLOCK = 10035, WSAEINPROGRESS = 10036,
    WSAEALREADY = 10037, WSAENOTSOCK = 10038, WSAEDESTADDRREQ = 10039,
    WSAEMSGSIZE = 10040, WSAEAFNOSUPPORT = 10047, WSAEADDRINUSE = 10048,
    WSAEADDRNOTAVAIL = 10049, WSAENETDOWN = 10050, WSAENETUNREACH = 10051,
    WSAENETRESET = 10052, WSAECONNABORTED = 10053, WSAECONNRESET = 10054,
    WSAENOBUFS = 10055, WSAEISCONN = 10056, WSAENOTCONN = 10057,
    WSAESHUTDOWN = 10058, WSAETIMEDOUT = 10060, WSAECONNREFUSED = 10061,
    WSAEHOSTUNREACH = 10065, WSANOTINITIALISED = 10093,
};

inline int translate_wsa(int e) {
    switch (e) {
        case 0:                                        return kal_ok;
        case WSAEINVAL: case WSAEFAULT: case WSAENOTSOCK:
        case WSAEADDRNOTAVAIL: case WSAEAFNOSUPPORT:
        case WSAEISCONN: case WSAENOTCONN:             return kal_err_invalid;
        case WSAEWOULDBLOCK: case WSAEINPROGRESS:
        case WSAEALREADY: case WSAEINTR:               return kal_err_again;
        case WSAENOBUFS:                               return kal_err_no_memory;
        case WSAEACCES:                                return kal_err_permission;
        case WSAECONNRESET: case WSAECONNABORTED:
        case WSAESHUTDOWN: case WSAENETRESET:          return kal_err_closed;
        case WSAECONNREFUSED: case WSAEHOSTUNREACH:
        case WSAENETUNREACH: case WSAENETDOWN:         return kal_err_not_found;
        case WSAEADDRINUSE:                            return kal_err_exists;
        case WSAEMFILE:                                return kal_err_no_space;
        // ⚠️ NOT `kal_err_not_supported'. `WSANOTINITIALISED' means this
        // implementation failed to start the network interface, which is a
        // fault of this implementation and not an absence of the facility ---
        // reporting it as unsupported would tell a caller to stop asking.
        case WSANOTINITIALISED:                        return kal_err_io;
        default:                                       return kal_err_io;
    }
}

inline int last_socket_error() { return translate_wsa(WSAGetLastError()); }

// ── starting this system's network interface ────────────────────────────────
//
// ⚠️ IT HAS TO BE STARTED, AND THERE IS NO OTHER PLACE TO DO IT. Every socket
// call fails with `WSANOTINITIALISED' until `WSAStartup' has been called in
// this image, and openkal has no operation a program calls first.
//
// ⭐ NOT A FUNCTION-LOCAL STATIC WITH A RUNTIME INITIALISER, AND THE MANIFEST
// SAYS WHY: every static in this package is initialised by a constant, so no
// guard variable is emitted. One with a runtime initialiser would emit a call
// to `__cxa_guard_acquire' --- a C runtime symbol, in the one package whose
// continuous integration asserts it references none.
//
// ⚠️ THE FLAG IS READ AND WRITTEN WITHOUT SYNCHRONISATION, AND THAT IS SAFE
// HERE RATHER THAN OVERLOOKED. Two contexts racing produce a second
// `WSAStartup', which this system reference-counts and which is documented as
// callable more than once. This implementation never calls `WSACleanup' --- the
// interface stays started for the life of the image, which is what a program
// that opened a socket wants --- so the count never reaches zero and the
// duplicate costs nothing.
inline void ensure_network() {
    static int started = 0;
    if (started) return;
    unsigned char record[1024];   // larger than the documented layout; see win32.h
    if (WSAStartup(0x0202 /* version 2.2 */, record) == 0) started = 1;
}

// ── addresses ───────────────────────────────────────────────────────────────

// The port is carried in host order by kal_endpoint and in network order by the
// system. The conversion is written out rather than taken from `htons', which
// is in the same library and would be one more name to import for two lines.
inline unsigned short to_net_port(kal_u32 port) {
    const unsigned short p = static_cast<unsigned short>(port & 0xffffu);
    return static_cast<unsigned short>((p << 8) | (p >> 8));
}
inline kal_u32 from_net_port(unsigned short net) {
    return static_cast<kal_u32>((net << 8) | (net >> 8)) & 0xffffu;
}

// Fills a system address from an endpoint, and reports its length.
//
// A LENGTH THIS IMPLEMENTATION DOES NOT KNOW IS REFUSED RATHER THAN READ AS ONE
// IT DOES. The specification defines the set of lengths and allows it to grow;
// an implementation that ignored the field would misread every address a later
// revision defines, and would do so silently.
inline int to_system(const kal_endpoint& ep, ksockaddr_storage& out, int& len) {
    for (auto& b : out.pad) b = 0;

    if (ep.addr_len == 4) {
        auto* v4 = reinterpret_cast<ksockaddr_in*>(&out);
        v4->family = static_cast<unsigned short>(AF_INET_);
        v4->port   = to_net_port(ep.port);
        DWORD a = 0;
        for (int i = 0; i < 4; ++i)
            a |= static_cast<DWORD>(ep.addr[i]) << (i * 8);   // already network order
        v4->addr = a;
        len = static_cast<int>(sizeof(ksockaddr_in));
        return kal_ok;
    }

    // Sixteen bytes is an address; twenty is an address followed by a scope
    // identifier, which is carried in the four bytes after it.
    if (ep.addr_len == 16 || ep.addr_len == 20) {
        auto* v6 = reinterpret_cast<ksockaddr_in6*>(&out);
        v6->family   = static_cast<unsigned short>(AF_INET6_);
        v6->port     = to_net_port(ep.port);
        v6->flowinfo = 0;
        for (int i = 0; i < 16; ++i) v6->addr[i] = ep.addr[i];
        DWORD scope = 0;
        if (ep.addr_len == 20)
            for (int i = 0; i < 4; ++i)
                scope |= static_cast<DWORD>(ep.addr[16 + i]) << (i * 8);
        v6->scope_id = scope;
        len = static_cast<int>(sizeof(ksockaddr_in6));
        return kal_ok;
    }

    return kal_err_invalid;
}

// Fills an endpoint from a system address. A family this implementation does
// not know leaves the endpoint zeroed and reports it, for the same reason.
inline int from_system(const ksockaddr_storage& in, kal_endpoint& out) {
    for (auto& b : out.addr) b = 0;
    out.addr_len = 0;
    out.port     = 0;

    const auto* head = reinterpret_cast<const ksockaddr_in*>(&in);

    if (head->family == AF_INET_) {
        const DWORD a = head->addr;
        for (int i = 0; i < 4; ++i)
            out.addr[i] = static_cast<kal_u8>((a >> (i * 8)) & 0xffu);
        out.addr_len = 4;
        out.port     = from_net_port(head->port);
        return kal_ok;
    }

    if (head->family == AF_INET6_) {
        const auto* v6 = reinterpret_cast<const ksockaddr_in6*>(&in);
        for (int i = 0; i < 16; ++i) out.addr[i] = v6->addr[i];
        // A zero scope identifier is reported as the shorter form. The two
        // lengths denote the same address when the scope is zero, and reporting
        // the shorter one keeps an address that came in as sixteen bytes going
        // back out as sixteen.
        if (v6->scope_id == 0) {
            out.addr_len = 16;
        } else {
            for (int i = 0; i < 4; ++i)
                out.addr[16 + i] = static_cast<kal_u8>((v6->scope_id >> (i * 8)) & 0xffu);
            out.addr_len = 20;
        }
        out.port = from_net_port(v6->port);
        return kal_ok;
    }

    return kal_err_invalid;
}

// Which socket family an endpoint asks for, or -1 for a length that is not one
// of the defined ones.
inline int family_of(const kal_endpoint& ep) {
    if (ep.addr_len == 4) return AF_INET_;
    if (ep.addr_len == 16 || ep.addr_len == 20) return AF_INET6_;
    return -1;
}

// A socket, as an owned handle. The packing is handle.h's, which is what every
// owned handle in this implementation uses; a socket value is a handle value on
// this system, so the same arithmetic recovers it.
inline kal_uintptr pack_socket(SOCKET s) {
    return s == INVALID_SOCKET ? 0u : pack(reinterpret_cast<void*>(s));
}
inline SOCKET unpack_socket(kal_uintptr w) {
    void* h = unpack(w);
    return h == nullptr ? INVALID_SOCKET : reinterpret_cast<SOCKET>(h);
}

}  // namespace okw
