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

// ── reaching this system's network interface ────────────────────────────────
//
// ⚠️⚠️ RESOLVED AT RUN TIME RATHER THAN LINKED, AND src/win32.h RECORDS THE
// MEASUREMENT: this library's names are the BSD names, the C library above this
// implementation defines the same names, and an import library puts both
// definitions in one program. Nothing of ws2_32 enters this program's symbol
// table now.
//
// ⚠️ IT ALSO HAS TO BE STARTED. Every socket call fails with
// `WSANOTINITIALISED' until `WSAStartup' has been called in this image, and
// openkal has no operation a program calls first --- so the first operation
// that needs the interface starts it.
//
// ⭐ NOT A FUNCTION-LOCAL STATIC WITH A RUNTIME INITIALISER, AND THE MANIFEST
// SAYS WHY: every static in this package is initialised by a constant, so no
// guard variable is emitted. One with a runtime initialiser would emit a call
// to `__cxa_guard_acquire' --- a C runtime symbol, in the one package whose
// continuous integration asserts it references none.
//
// ⚠️ THE TABLE IS READ AND WRITTEN WITHOUT SYNCHRONISATION, AND THAT IS SAFE
// HERE RATHER THAN OVERLOOKED. Two contexts racing resolve the same pointers
// from the same library to the same values and perform a second `WSAStartup',
// which this system reference-counts and documents as callable more than once.
// This implementation never calls `WSACleanup' --- the interface stays
// available for the life of the image, which is what a program that opened a
// socket wants --- so the count never reaches zero.
struct network_calls {
    int ready;                       // 0 not tried, 1 available, -1 absent
    pfn_WSAGetLastError last_error;
    pfn_WSASocketW      socket;
    pfn_closesocket     close;
    pfn_bind            bind;
    pfn_listen          listen;
    pfn_accept          accept;
    pfn_connect         connect;
    pfn_shutdown        shutdown;
    pfn_getsockname     sockname;
    pfn_getpeername     peername;
    pfn_sendto          send_to;
    pfn_recvfrom        recv_from;
    pfn_WSAPoll         poll;
};

inline network_calls& net_calls() {
    static network_calls c = {};    // constant-initialised: no guard is emitted
    return c;
}

// ⚠️ THE LIBRARY'S NAME IS WRITTEN AS WIDE CHARACTERS BY HAND. This package has
// no C library to take a literal converter from, and `L"ws2_32.dll"' is the
// language's own; it is spelled out so that no header is needed for it.
inline bool ensure_network() {
    network_calls& c = net_calls();
    if (c.ready != 0) return c.ready > 0;

    static const wchar_t name[] = { L'w', L's', L'2', L'_', L'3', L'2', L'.',
                                    L'd', L'l', L'l', L'\0' };
    HANDLE lib = LoadLibraryW(name);
    if (lib == nullptr) { c.ready = -1; return false; }

    auto at = [lib](const char* n) { return GetProcAddress(lib, n); };
    auto start = reinterpret_cast<pfn_WSAStartup>(at("WSAStartup"));
    c.last_error = reinterpret_cast<pfn_WSAGetLastError>(at("WSAGetLastError"));
    c.socket     = reinterpret_cast<pfn_WSASocketW>(at("WSASocketW"));
    c.close      = reinterpret_cast<pfn_closesocket>(at("closesocket"));
    c.bind       = reinterpret_cast<pfn_bind>(at("bind"));
    c.listen     = reinterpret_cast<pfn_listen>(at("listen"));
    c.accept     = reinterpret_cast<pfn_accept>(at("accept"));
    c.connect    = reinterpret_cast<pfn_connect>(at("connect"));
    c.shutdown   = reinterpret_cast<pfn_shutdown>(at("shutdown"));
    c.sockname   = reinterpret_cast<pfn_getsockname>(at("getsockname"));
    c.peername   = reinterpret_cast<pfn_getpeername>(at("getpeername"));
    c.send_to    = reinterpret_cast<pfn_sendto>(at("sendto"));
    c.recv_from  = reinterpret_cast<pfn_recvfrom>(at("recvfrom"));
    c.poll       = reinterpret_cast<pfn_WSAPoll>(at("WSAPoll"));

    // ⚠️ EVERY ONE OF THEM, OR NONE. A table with one null entry is worse than
    // no table: the operations that resolved would work and the one that did
    // not would call through zero, which is the failure clause 6.1 exists to
    // turn into a link error and this arrangement cannot.
    if (!start || !c.last_error || !c.socket || !c.close || !c.bind ||
        !c.listen || !c.accept || !c.connect || !c.shutdown || !c.sockname ||
        !c.peername || !c.send_to || !c.recv_from || !c.poll) {
        c.ready = -1;
        return false;
    }

    unsigned char record[1024];   // larger than the documented layout; see win32.h
    if (start(0x0202 /* version 2.2 */, record) != 0) { c.ready = -1; return false; }
    c.ready = 1;
    return true;
}

// The error this system last reported for a socket operation. ⚠️ Reached through
// the table, so a caller that failed BEFORE the table was built --- which is the
// only way `ensure_network' returns false --- is told `kal_err_io' rather than
// calling through a null pointer.
inline int last_socket_error() {
    network_calls& c = net_calls();
    if (c.ready <= 0 || c.last_error == nullptr) return kal_err_io;
    return translate_wsa(c.last_error());
}

// The table, or a null pointer when this system's network interface could not
// be reached at all. ⚠️ Every operation of both interfaces begins here, so a
// system without `ws2_32.dll' --- which is not a system this package expects to
// meet --- reports `kal_err_io' rather than calling through zero.
inline network_calls* net_or_null() {
    return ensure_network() ? &net_calls() : nullptr;
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
