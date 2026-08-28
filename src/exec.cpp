#include "win.h"
#include <openkal/exec.h>

// openkal.exec on this system.
//
// A reservation obtained writable and made executable afterwards. This system
// permits a region that is both at once and this implementation does not
// produce one: two of the three environments the specification targets refuse
// it, so an implementation that returned one here would be offering a program a
// shape it could not use elsewhere --- and the program would discover that only
// on the other system. The interface states the narrower contract and this
// implementation keeps to it.
//
// ⭐ THE THIRD CALL IS NOT OPTIONAL AND IS NOT PRESENT ON THE OTHER TWO SYSTEMS'
// IMPLEMENTATIONS. A processor whose instruction path does not observe the data
// path's writes must be told; this system publishes an operation for exactly
// that and documents it as required after writing code into memory. On the
// architecture this package is built for it is inexpensive, and on the other
// architecture this system runs on it is the difference between executing what
// was written and executing what was there before.

namespace {

// The reservation granularity. `VirtualAlloc' rounds a size up to a page and an
// address down to the allocation granularity, so a caller's size is rounded
// here only so that the reservation and the release agree about the number ---
// which they must, because the release takes the size the reservation was given.
constexpr unsigned long long kPage = 4096;

unsigned long long round_up(unsigned long long n, unsigned long long to) {
    return (n + to - 1) & ~(to - 1);
}

}  // namespace

extern "C" {

void* kal_exec_alloc(kal_uintptr size) {
    if (size == 0) return nullptr;
    const unsigned long long bytes = round_up(size, kPage);
    return VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

int kal_exec_publish(void* p, kal_uintptr size) {
    if (p == nullptr || size == 0) return kal_err_invalid;
    const unsigned long long bytes = round_up(size, kPage);
    DWORD previous = 0;
    if (!VirtualProtect(p, bytes, PAGE_EXECUTE_READ, &previous))
        return okw::translate_win32(GetLastError());
    if (!FlushInstructionCache(GetCurrentProcess(), p, bytes))
        return okw::translate_win32(GetLastError());
    return kal_ok;
}

void kal_exec_free(void* p, kal_uintptr size) {
    if (p == nullptr || size == 0) return;
    // ⚠️ THE SIZE IS ZERO AND THAT IS NOT AN OVERSIGHT. This system's release
    // takes a size of zero with `MEM_RELEASE' and refuses any other value: the
    // region released is the whole of the one that was reserved, which is what
    // this operation means. Passing the caller's size would fail with an
    // invalid-parameter report and leak the reservation.
    VirtualFree(p, 0, MEM_RELEASE);
}

// A published region may be reserved for writing again: this system's
// protection call is not one-way, and a second `VirtualProtect' to
// PAGE_READWRITE succeeds. The position is set accordingly, and a caller that
// must change published bytes need not abandon the region.
// This system grants executable memory to every program; nothing here is
// withheld from an artifact for the way it was produced.
kal_uintptr kal_exec_props(void) {
    return KAL_EXEC_PROP_REPUBLISH | KAL_EXEC_PROP_AVAILABLE;
}

}  // extern "C"
