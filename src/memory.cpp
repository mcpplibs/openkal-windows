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


// The quantum this environment allocates and protects memory in.
//
// THIS SYSTEM HAS TWO, AND THE COARSER IS REPORTED. It protects memory in
// pages of four kilobytes and RESERVES it in units of sixty-four --- so a value
// taken from either alone is wrong for the other, and a specification that
// derived one number from the page size of one family of systems would be wrong
// here. What the operation promises is that an address and a length that are
// multiples of the reported value are acceptable to every operation of the
// interface, so the coarser of the two is the only answer that keeps the
// promise.
kal_uintptr kal_memory_granularity(void) {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    const kal_uintptr page  = info.dwPageSize ? info.dwPageSize : 4096u;
    const kal_uintptr grain = info.dwAllocationGranularity
                            ? info.dwAllocationGranularity : 65536u;
    return page > grain ? page : grain;
}

// WHAT THIS PROGRAM MAY USE, AND WHAT IT CAN BE GIVEN NOW (0.23): the machine's
// memory and what is free of it (GlobalMemoryStatusEx), each no more than a
// limit on the program, or on the job it is in, leaves.
int kal_memory_info(kal_memory_status* out) {
    if (out == nullptr || out->self_size < sizeof(kal_u32) * 2) return kal_err_invalid;
    kal_memory_status v{};
    v.self_size = out->self_size;
    MEMORYSTATUSEX_ m{};
    m.dwLength = sizeof m;
    if (GlobalMemoryStatusEx(&m)) {
        v.total_bytes = m.ullTotalPhys;
        v.available_bytes = m.ullAvailPhys;
        v.present = KAL_MSTATUS_TOTAL | KAL_MSTATUS_AVAILABLE;
        JOB_LIMITS l{};
        if (QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation_, &l, sizeof l, nullptr)) {
            constexpr DWORD process_memory = 0x100u;   // JOB_OBJECT_LIMIT_PROCESS_MEMORY
            auto bound = [&](unsigned long long limit, unsigned long long used) {
                if (limit == 0) return;
                if (limit < v.total_bytes) v.total_bytes = limit;
                const unsigned long long left = limit > used ? limit - used : 0;
                if (left < v.available_bytes) v.available_bytes = left;
            };
            if (l.LimitFlags & process_memory) {
                PROCESS_MEMORY_COUNTERS_EX_ c{};
                c.cb = sizeof c;
                K32GetProcessMemoryInfo(GetCurrentProcess(), &c, sizeof c);
                bound(l.ProcessMemoryLimit, c.PagefileUsage);
            }
            if (l.LimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY_) {
                JOB_VIOLATION_ j{};
                QueryInformationJobObject(nullptr, JobObjectLimitViolationInformation_, &j, sizeof j, nullptr);
                bound(l.JobMemoryLimit, j.JobMemory);
            }
        }
    }
    const kal_u32 n = out->self_size < sizeof v ? out->self_size : static_cast<kal_u32>(sizeof v);
    auto* d = reinterpret_cast<unsigned char*>(out);
    const auto* src = reinterpret_cast<const unsigned char*>(&v);
    for (kal_u32 i = 0; i < n; ++i) d[i] = src[i];
    return kal_ok;
}

}
