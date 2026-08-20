// Handle construction shared by the interfaces whose handles are owned.
//
// Clause 6.6 requires that a released handle not be treated as valid, and
// recommends dividing the word into an index and a generation. That is what
// this file does, and it is the same construction the Linux implementation
// uses for the same reason.
//
// It is not a translation table. The environment's handle is recovered
// arithmetically from the word; the array holds generations and nothing else,
// and no lookup decides what a word refers to. That is the distinction clause
// 7.1 draws, and it is the reason a table would be a defect here and this is
// not.
//
// The bound is stated rather than assumed. This environment's handle values are
// small multiples of four in every ordinary program, and a value beyond the
// bound is carried in the word with no generation --- so the word still names
// the right object, and the release of that one particular handle is not
// detected. An implementation that silently failed such a handle would be worse
// than one that admits the boundary.
#pragma once
#include "win.h"

namespace okw {

inline constexpr okw_uptr kSlots = 1u << 16;

inline unsigned* generations() {
    static unsigned g[kSlots];
    return g;
}

inline okw_uptr slot_of(void* h) {
    const okw_uptr v = reinterpret_cast<okw_uptr>(h);
    return (v >> 2) & (kSlots - 1);
}

inline bool within_bound(void* h) {
    return reinterpret_cast<okw_uptr>(h) < (kSlots << 2);
}

inline okw_uptr pack(void* h) {
    if (h == nullptr || h == INVALID_HANDLE_VALUE) return 0;
    const okw_uptr v = reinterpret_cast<okw_uptr>(h);
    if (!within_bound(h)) return v;                    // carried without a generation
    return (static_cast<okw_uptr>(generations()[slot_of(h)]) << 32) | (v + 1u);
}

// Returns the environment's handle, or null if the word does not name a live one.
inline void* unpack(okw_uptr w) {
    if (w == 0) return nullptr;
    const okw_uptr low = w & 0xffffffffu;
    if (low == 0) return reinterpret_cast<void*>(w);    // carried without a generation
    void* h = reinterpret_cast<void*>(low - 1u);
    if (!within_bound(h)) return reinterpret_cast<void*>(w);
    if (static_cast<unsigned>(w >> 32) != generations()[slot_of(h)]) return nullptr;
    return h;
}

inline void retire(okw_uptr w) {
    void* h = unpack(w);
    if (h && within_bound(h)) ++generations()[slot_of(h)];
}

}  // namespace okw
