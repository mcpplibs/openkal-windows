// openkal.region (openkal 0.20): a range of the address space reserved first
// and backed as it is used.
//
// THIS SYSTEM IS WHERE THE INTERFACE'S SHAPE COMES FROM. It reserves addresses
// (`VirtualAlloc' with MEM_RESERVE), backs them on request and charges the
// backing then (MEM_COMMIT), returns the backing while keeping the addresses
// (`VirtualFree' with MEM_DECOMMIT), lets the backing's contents go without
// giving the backing up (MEM_RESET), and releases a reservation only whole
// (MEM_RELEASE) --- which is why the specification has no partial release.
// Backing is charged apart from reservation, so KAL_REGION_PROP_OVERCOMMIT is
// not claimed.
//
// AN ALIGNMENT COARSER THAN THE SYSTEM'S GRANULARITY (64 KiB) is not something
// `VirtualAlloc' takes. A range of the size and the alignment together is
// reserved, released, and the aligned part of it reserved at its address; a
// context that took those addresses meanwhile makes the second reservation
// fail, and the attempt is repeated. This is the arrangement the system's own
// allocators used before the call that takes an alignment, which is not in
// every version this implementation runs on.
#include "win.h"
#include <openkal/memory.h>
#include <openkal/region.h>

namespace {

okw_uptr granularity() { return static_cast<okw_uptr>(kal_memory_granularity()); }
bool multiple(okw_uptr v, okw_uptr g) { return (v & (g - 1)) == 0; }

constexpr DWORD MEM_COMMIT_  = 0x00001000u;
constexpr DWORD MEM_RESERVE_ = 0x00002000u;
constexpr DWORD MEM_DECOMMIT_ = 0x00004000u;
constexpr DWORD MEM_RELEASE_ = 0x00008000u;
constexpr DWORD MEM_RESET_   = 0x00080000u;
constexpr DWORD PAGE_NOACCESS_  = 0x01u;
constexpr DWORD PAGE_READWRITE_ = 0x04u;

int translate_last() {
    const DWORD e = GetLastError();
    return e == 8 /* ERROR_NOT_ENOUGH_MEMORY */ || e == 1455 /* ERROR_COMMITMENT_LIMIT */
         ? kal_err_no_memory : kal_err_invalid;
}

}  // namespace

extern "C" {

void* kal_region_reserve(kal_uintptr size, kal_uintptr align, kal_uintptr flags) {
    const okw_uptr g = granularity();
    if (size == 0 || !multiple(size, g) || align < g || (align & (align - 1)) != 0) return nullptr;
    if ((flags & ~KAL_REGION_COMMIT) != 0) return nullptr;
    const DWORD type = MEM_RESERVE_ | ((flags & KAL_REGION_COMMIT) ? MEM_COMMIT_ : 0u);
    const DWORD protect = (flags & KAL_REGION_COMMIT) ? PAGE_READWRITE_ : PAGE_NOACCESS_;
    if (align <= g) return VirtualAlloc(nullptr, size, type, protect);
    const okw_uptr total = size + align - g;
    if (total < size) return nullptr;
    for (int attempt = 0; attempt < 16; ++attempt) {
        void* wide = VirtualAlloc(nullptr, total, MEM_RESERVE_, PAGE_NOACCESS_);
        if (!wide) return nullptr;
        const okw_uptr at = (reinterpret_cast<okw_uptr>(wide) + align - 1) & ~(align - 1);
        VirtualFree(wide, 0, MEM_RELEASE_);
        if (void* p = VirtualAlloc(reinterpret_cast<void*>(at), size, type, protect)) return p;
    }
    return nullptr;
}

int kal_region_commit(void* addr, kal_uintptr len) {
    const okw_uptr g = granularity(), a = reinterpret_cast<okw_uptr>(addr);
    if (addr == nullptr || !multiple(a, g) || !multiple(len, g)) return kal_err_invalid;
    if (len == 0) return kal_ok;
    return VirtualAlloc(addr, len, MEM_COMMIT_, PAGE_READWRITE_) ? kal_ok : translate_last();
}

int kal_region_decommit(void* addr, kal_uintptr len) {
    const okw_uptr g = granularity(), a = reinterpret_cast<okw_uptr>(addr);
    if (addr == nullptr || !multiple(a, g) || !multiple(len, g)) return kal_err_invalid;
    if (len == 0) return kal_ok;
    return VirtualFree(addr, len, MEM_DECOMMIT_) ? kal_ok : translate_last();
}

int kal_region_discard(void* addr, kal_uintptr len) {
    const okw_uptr g = granularity(), a = reinterpret_cast<okw_uptr>(addr);
    if (addr == nullptr || !multiple(a, g) || !multiple(len, g)) return kal_err_invalid;
    if (len == 0) return kal_ok;
    return VirtualAlloc(addr, len, MEM_RESET_, PAGE_READWRITE_) ? kal_ok : translate_last();
}

void kal_region_release(void* addr, kal_uintptr size) {
    if (addr == nullptr || size == 0) return;
    VirtualFree(addr, 0, MEM_RELEASE_);
}

kal_uintptr kal_region_props(void) { return 0; }

}
