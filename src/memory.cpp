#include "win.h"
#include <openkal/memory.h>

// Clause 7.3: where the environment already provides an allocator, this one is
// built upon it and not beside it. This environment provides one --- the
// process heap is a facility of the environment rather than of any runtime a
// program may carry --- so it is used, and no second claimant is introduced.
//
// The hazard the clause names is two allocators drawing on one region on a
// system whose heap grows by extending a single region. Here there is one
// allocator and the question does not arise.

namespace {


constexpr okw_uptr kNatural = 16;   // what this environment's heap guarantees

void* g_heap = nullptr;

void* heap() {
    // As in src/time.cpp: remembered rather than recomputed, without the guard
    // a C++ runtime would supply. The environment returns the same handle to
    // every caller, so two contexts arriving together store the same value.
    if (!g_heap) g_heap = GetProcessHeap();
    return g_heap;
}

}  // namespace

extern "C" {

void* kal_alloc(kal_uintptr size, kal_uintptr align) {
    if (size == 0) return nullptr;
    void* h = heap();
    if (!h) return nullptr;
    if (align <= kNatural) return HeapAlloc(h, 0, size);

    // An alignment wider than the heap's own is satisfied by asking for more
    // and recording, immediately before the region returned, what must be
    // released. The record is reachable because the returned address is at
    // least sixteen bytes above the allocation's base by construction.
    const kal_uintptr total = size + align + sizeof(void*) * 2;
    auto* base = static_cast<unsigned char*>(HeapAlloc(h, 0, total));
    if (!base) return nullptr;
    auto addr = reinterpret_cast<kal_uintptr>(base) + sizeof(void*) * 2;
    addr = (addr + align - 1) & ~(align - 1);
    auto* user = reinterpret_cast<unsigned char*>(addr);
    reinterpret_cast<void**>(user)[-1] = base;
    return user;
}

// The size and alignment are those passed to the allocation. The interface
// carries them so that an implementation need keep no record of its own, and
// this one keeps none except in the over-aligned case, where the address
// returned is not the address obtained.
void kal_free(void* p, kal_uintptr size, kal_uintptr align) {
    if (!p || size == 0) return;
    void* h = heap();
    if (!h) return;
    if (align <= kNatural) { HeapFree(h, 0, p); return; }
    HeapFree(h, 0, reinterpret_cast<void**>(p)[-1]);
}

}
