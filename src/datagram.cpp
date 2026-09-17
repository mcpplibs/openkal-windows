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
//
// SENDING AND RECEIVING GO THROUGH `WSASendTo'/`WSARecvFrom' WITH AN
// `OVERLAPPED' OF THEIR OWN, VERSION 0.13, FOR THE REASON src/net.cpp STATES:
// the socket is made overlapped, so a synchronous call sharing the handle's one
// completion event would contend with a transfer in the other direction upon
// it. `kal_datagram_open' makes the socket with `WSA_FLAG_OVERLAPPED'.

namespace {

SOCKET socket_of(kal_datagram d) { return okw::unpack_socket(d.h); }

okw::network_calls* net() { return okw::net_or_null(); }

bool bad(SOCKET s) { return s == INVALID_SOCKET; }

// The largest transfer one call accepts. This system states a count as an
// `int', and a datagram larger than that cannot exist, so the clamp is a
// statement about the type rather than a limit this implementation imposes.
constexpr kal_uintptr kMaxOne = 0x7fffffffu;

// One overlapped operation upon the socket: an event of its own, issued and
// waited for synchronously. `err' carries the WSA error when this reports
// failure; a caller that must translate it uses okw::translate_wsa.
//
// A DATAGRAM TOO LARGE FOR THE BUFFER IS REPORTED TWO WAYS, AND BOTH ARE
// NORMALISED TO ONE HERE. `WSARecvFrom' that fails immediately is read through
// `WSAGetLastError', which gives `WSAEMSGSIZE' --- the Winsock-specific value
// the rest of this file already expects. One that goes pending completes with
// `STATUS_BUFFER_OVERFLOW', and `GetOverlappedResult' reports that through the
// generic channel as `ERROR_MORE_DATA', a different number for the same
// condition. Measured on windows-2022, where the pending path is the one this
// operation actually takes: the immediate path was never reached in that
// measurement, and reporting `ERROR_MORE_DATA' unnormalised left the
// truncation this interface is required to report as a success reported as an
// unrecognised failure instead.
bool overlapped_once(SOCKET s, bool send, WSABUF_& wsabuf, DWORD flags,
                     void* addr, int* addrlen, DWORD* moved, int* err) {
    auto* n = okw::net_or_null();
    if (n == nullptr) { *err = 0; return false; }
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ev == nullptr) { *err = 0; return false; }
    OVERLAPPED ov{};
    ov.hEvent = ev;
    const int rc = send
        ? n->send_to_ov(s, &wsabuf, 1, moved, flags,
                        addr, addrlen ? *addrlen : 0, &ov, nullptr)
        : n->recv_from_ov(s, &wsabuf, 1, moved, &flags,
                          addr, addrlen, &ov, nullptr);
    bool ok = rc == 0;
    if (!ok) {
        const int e = n->last_error();
        if (e == static_cast<int>(ERROR_IO_PENDING)) {
            ok = GetOverlappedResult(reinterpret_cast<HANDLE>(s), &ov, moved, TRUE) != 0;
            if (!ok) {
                const DWORD ge = GetLastError();
                *err = ge == ERROR_MORE_DATA ? static_cast<int>(okw::WSAEMSGSIZE)
                                             : static_cast<int>(ge);
            }
        } else {
            *err = e;
        }
    }
    CloseHandle(ev);
    return ok;
}

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
    const SOCKET s = n->socket(family, SOCK_DGRAM_, IPPROTO_UDP_, nullptr, 0,
                               WSA_FLAG_OVERLAPPED_);
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

    ksockaddr_storage ss{};
    int addrlen = 0;
    if (const int rc = okw::to_system(*to, ss, addrlen); rc != kal_ok)
        return -rc;

    WSABUF_ wsabuf{ static_cast<DWORD>(len),
                    const_cast<char*>(static_cast<const char*>(buf)) };
    DWORD sent = 0;
    int err = 0;
    if (!overlapped_once(s, true, wsabuf, 0, &ss, &addrlen, &sent, &err))
        return -okw::translate_wsa(err);

    // A MESSAGE IS SENT WHOLE OR NOT AT ALL, which is what this interface
    // states. The system reports a count anyway; a count short of the length
    // would mean the medium had split the message, which for a datagram socket
    // it does not do. Reporting the short count as success would give a caller a
    // partial send this interface says cannot occur, so it is reported as a
    // failure of the medium instead.
    const kal_uintptr moved = static_cast<kal_uintptr>(sent);
    return moved == len ? static_cast<kal_intptr>(moved) : -kal_err_io;
}

kal_intptr kal_datagram_recv_from(kal_datagram d, void* buf, kal_uintptr len,
                                  kal_endpoint* from) {
    const SOCKET s = socket_of(d);
    if (bad(s)) return -kal_err_invalid;
    if (len > kMaxOne) len = kMaxOne;

    ksockaddr_storage ss{};
    int addrlen = static_cast<int>(sizeof ss);

    WSABUF_ wsabuf{ static_cast<DWORD>(len), static_cast<char*>(buf) };
    DWORD got = 0;
    int err = 0;
    if (!overlapped_once(s, false, wsabuf, 0, &ss, &addrlen, &got, &err)) {
        // THE ONE FAILURE THIS SYSTEM REPORTS THAT THE OTHER TWO DO NOT.
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
        if (err == okw::WSAEMSGSIZE) {
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
        return -okw::translate_wsa(err);
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
    return static_cast<kal_intptr>(got);
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
