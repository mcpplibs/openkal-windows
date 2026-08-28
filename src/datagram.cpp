#include "win.h"
#include "endpoint.h"
#include <openkal/datagram.h>

// openkal.datagram upon this system's network interface.
//
// A DATAGRAM IS NOT PACKED AS A kal_stream, and the handle type is its own for
// that reason: kal_stream_read reports a count and not a boundary, so reading a
// datagram through it would lose the property that distinguishes this interface.
// The packing is the same, the type is not, and the type is what prevents the
// mistake.

namespace {

SOCKET socket_of(kal_datagram d) { return okw::unpack_socket(d.h); }

okw::network_calls* net() { return okw::net_or_null(); }

bool bad(SOCKET s) { return s == INVALID_SOCKET; }

// The largest transfer one call accepts. This system states a count as an
// `int', and a datagram larger than that cannot exist, so the clamp is a
// statement about the type rather than a limit this implementation imposes.
constexpr kal_uintptr kMaxOne = 0x7fffffffu;

}  // namespace

extern "C" {

int kal_datagram_open(const kal_endpoint* local, kal_datagram* out) {
    if (out == nullptr) return kal_err_invalid;

    // A null local endpoint asks for one that may send and whose receiving
    // address is unspecified. IPv4 is chosen for it, because a family must be
    // named at the point the socket is made and this is the one every
    // environment that has a network at all provides.
    int family = AF_INET_;
    if (local != nullptr) {
        family = okw::family_of(*local);
        if (family < 0) return kal_err_invalid;
    }

    auto* n = net();
    if (n == nullptr) return kal_err_io;
    const SOCKET s = n->socket(family, SOCK_DGRAM_, IPPROTO_UDP_, nullptr, 0, 0);
    if (bad(s)) return okw::last_socket_error();

    if (local != nullptr) {
        ksockaddr_storage ss{};
        int len = 0;
        if (const int rc = okw::to_system(*local, ss, len); rc != kal_ok) {
            n->close(s);
            return rc;
        }
        if (n->bind(s, &ss, len) != 0) {
            const int e = okw::last_socket_error();
            n->close(s);
            return e;
        }
    }

    out->h = okw::pack_socket(s);
    if (out->h == 0) { n->close(s); return kal_err_no_memory; }
    return kal_ok;
}

int kal_datagram_local(kal_datagram d, kal_endpoint* out) {
    if (out == nullptr) return kal_err_invalid;
    const SOCKET s = socket_of(d);
    if (bad(s)) return kal_err_invalid;

    auto* n = net();
    if (n == nullptr) return kal_err_io;
    ksockaddr_storage ss{};
    int len = static_cast<int>(sizeof ss);
    if (n->sockname(s, &ss, &len) != 0) return okw::last_socket_error();
    return okw::from_system(ss, *out);
}

kal_intptr kal_datagram_send_to(kal_datagram d, const void* buf, kal_uintptr len,
                                const kal_endpoint* to) {
    const SOCKET s = socket_of(d);
    if (bad(s) || to == nullptr) return -kal_err_invalid;
    if (len > kMaxOne) return -kal_err_invalid;

    auto* n = net();
    if (n == nullptr) return -kal_err_io;
    ksockaddr_storage ss{};
    int addrlen = 0;
    if (const int rc = okw::to_system(*to, ss, addrlen); rc != kal_ok)
        return -rc;

    const int r = n->send_to(s, static_cast<const char*>(buf), static_cast<int>(len),
                             0, &ss, addrlen);
    if (r < 0) return -okw::last_socket_error();

    // A MESSAGE IS SENT WHOLE OR NOT AT ALL, which is what this interface
    // states. The system reports a count anyway; a count short of the length
    // would mean the medium had split the message, which for a datagram socket
    // it does not do. Reporting the short count as success would give a caller a
    // partial send this interface says cannot occur, so it is reported as a
    // failure of the medium instead.
    const kal_uintptr sent = static_cast<kal_uintptr>(r);
    return sent == len ? static_cast<kal_intptr>(sent) : -kal_err_io;
}

kal_intptr kal_datagram_recv_from(kal_datagram d, void* buf, kal_uintptr len,
                                  kal_endpoint* from) {
    const SOCKET s = socket_of(d);
    if (bad(s)) return -kal_err_invalid;
    if (len > kMaxOne) len = kMaxOne;

    auto* n = net();
    if (n == nullptr) return -kal_err_io;
    ksockaddr_storage ss{};
    int addrlen = static_cast<int>(sizeof ss);

    const int r = n->recv_from(s, static_cast<char*>(buf), static_cast<int>(len),
                               0, &ss, &addrlen);
    if (r < 0) {
        // ⚠️ THE ONE FAILURE THIS SYSTEM REPORTS THAT THE OTHER TWO DO NOT.
        //
        // A message longer than the buffer is truncated here AND reported as a
        // failure --- `WSAEMSGSIZE' --- where the other two systems truncate
        // silently. This interface states that "a message longer than the
        // buffer is truncated and the excess is lost, which is what the medium
        // does", so the truncation is the specified behaviour and the report is
        // this system's addition. The bytes that fit are in the caller's buffer
        // either way; refusing them would lose a message the interface says was
        // delivered.
        //
        // The count is not recoverable from this call, so what is reported is
        // the whole of the buffer, which is what was filled.
        if (n->last_error() == okw::WSAEMSGSIZE) {
            if (from != nullptr && okw::from_system(ss, *from) != kal_ok) {
                for (auto& b : from->addr) b = 0;
                from->addr_len = 0;
                from->port     = 0;
            }
            // A message longer than the buffer: the bytes placed are the
            // buffer's length, and reporting the count is reporting what the
            // caller may read.
            return static_cast<kal_intptr>(len);
        }
        return -okw::last_socket_error();
    }

    if (from != nullptr) {
        // A sender whose family this implementation does not know leaves the
        // endpoint zeroed rather than partly filled. The transfer still happened
        // and is reported; what is unknown is who sent it.
        if (okw::from_system(ss, *from) != kal_ok) {
            for (auto& b : from->addr) b = 0;
            from->addr_len = 0;
            from->port     = 0;
        }
    }
    return static_cast<kal_intptr>(r);
}

void kal_datagram_close(kal_datagram d) {
    const SOCKET s = socket_of(d);
    if (bad(s)) return;
    if (auto* n = net()) n->close(s);
    okw::retire(d.h);
}

// Broadcast is not claimed. The system provides it only after SO_BROADCAST has
// been set, and this interface has no operation that would set it; a word
// claiming a facility no operation reaches is the disagreement clause 6.2 exists
// to prevent.
kal_uintptr kal_datagram_props(void) { return KAL_DGRAM_PROP_IPV6; }

}  // extern "C"
