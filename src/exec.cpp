#include "win.h"
#include "handle.h"
#include <openkal/exec.h>
#include <openkal/map.h>
#include <openkal/memory.h>

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
// THE THIRD CALL IS NOT OPTIONAL AND IS NOT PRESENT ON THE OTHER TWO SYSTEMS'
// IMPLEMENTATIONS. A processor whose instruction path does not observe the data
// path's writes must be told; this system publishes an operation for exactly
// that and documents it as required after writing code into memory. On the
// architecture this package is built for it is inexpensive, and on the other
// architecture this system runs on it is the difference between executing what
// was written and executing what was there before.
//
// A PART OF A REGION THAT IS A FILE'S (0.21, provided from 0.19.0). This system
// maps a view of a file only where nothing is mapped, or where a PLACEHOLDER of
// exactly the view's extent is (Windows 10 1803): a reservation that holds no
// memory yet, which a view or an allocation replaces and which a view gives
// back when it is unmapped. So a region is made of placeholders from the start:
// one, reserved for the whole region and replaced by a view of a section of the
// region's own size backed by the paging file (`made'). Its bytes are the
// section's, not the view's, and that is what lets a part become a file's later
// without losing the rest: the view is unmapped back to a placeholder, the
// placeholder split at the part, the part replaced by a view of the file and
// the rest by views of the same section at the same offsets, which hold what
// they held. A region is then a short table of such views (`region', below);
// clause 7.1 admits it because this system's view is the only shape there is,
// and the table is one entry per view the caller asked for and nothing else.
//
// Views are placed in this system's sixty-four kibibytes, so a part whose
// offset or size is not a multiple of them is refused with
// kal_err_not_supported and the region is unchanged; a loader copies such a
// part, and lays an image out in those blocks (clause 12).
//
// WHERE THE SYSTEM HAS NO PLACEHOLDERS a region is an allocation of its own, as
// it was before 0.19.0, and KAL_EXEC_PROP_FILE is not claimed.

namespace {

constexpr unsigned long long kPage = 4096;
constexpr unsigned long long kView = 65536;

unsigned long long round_up(unsigned long long n, unsigned long long to) {
    return (n + to - 1) & ~(to - 1);
}

// --- the placeholders ------------------------------------------------------------
struct calls {
    pfn_VirtualAlloc2_          alloc2 = nullptr;
    pfn_MapViewOfFile3_         map3 = nullptr;
    pfn_UnmapViewOfFile2_       unmap2 = nullptr;
    pfn_PrefetchVirtualMemory_  prefetch = nullptr;
    bool usable = false;
};

// A VIEW OF THE REGION'S SECTION is mapped with every access a region's part
// will be given and made writable at once: a view's protection may later be
// changed only to one its mapping allowed, and a part of a region is published
// executable. Nothing is in the view between the two calls, which are this
// implementation's own; the caller receives it writable and not executable.
bool section_view(const calls& c, HANDLE section, char* at, unsigned long long from, unsigned long long len) {
    if (c.map3(section, GetCurrentProcess(), at, from, len, MEM_REPLACE_PLACEHOLDER_, PAGE_EXECUTE_READWRITE,
               nullptr, 0) != at)
        return false;
    DWORD before = 0;
    if (VirtualProtect(at, len, PAGE_READWRITE, &before)) return true;
    UnmapViewOfFile(at);
    return false;
}

// A placeholder reserved, split, a view of a section placed in one half and
// made executable, and the view given back to a placeholder: the whole of what
// a region uses, tried once, so that a system that names these calls and does
// not perform them --- an emulator of this system --- is not claimed to.
bool works(const calls& c) {
    const HANDLE self = GetCurrentProcess();
    HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0,
                                        static_cast<DWORD>(2 * kView), nullptr);
    if (!section) return false;
    auto* p = static_cast<char*>(c.alloc2(self, nullptr, 2 * kView, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER_,
                                          PAGE_NOACCESS, nullptr, 0));
    bool ok = p != nullptr && VirtualFree(p, kView, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER_);
    ok = ok && section_view(c, section, p, 0, kView);
    DWORD before = 0;
    if (ok) { p[0] = 1; ok = VirtualProtect(p, kPage, PAGE_EXECUTE_READ, &before) && p[0] == 1; }
    ok = ok && c.unmap2(self, p, MEM_PRESERVE_PLACEHOLDER_);
    if (p) {
        UnmapViewOfFile(p);
        VirtualFree(p, 0, MEM_RELEASE);
        VirtualFree(p + kView, 0, MEM_RELEASE);
    }
    CloseHandle(section);
    return ok;
}

SRWLOCK_ g_calls_lock{};
calls g_calls;
volatile long long g_calls_known = 0;

const calls& placeholders() {
    if (okw::atomic::load(&g_calls_known)) return g_calls;
    AcquireSRWLockExclusive(&g_calls_lock);
    if (!okw::atomic::load(&g_calls_known)) {
        static const wchar_t kernelbase[] = L"kernelbase.dll";
        g_calls.alloc2 = reinterpret_cast<pfn_VirtualAlloc2_>(okw::system_function(kernelbase, "VirtualAlloc2"));
        g_calls.map3 = reinterpret_cast<pfn_MapViewOfFile3_>(okw::system_function(kernelbase, "MapViewOfFile3"));
        g_calls.unmap2 = reinterpret_cast<pfn_UnmapViewOfFile2_>(okw::system_function(kernelbase, "UnmapViewOfFile2"));
        g_calls.prefetch = reinterpret_cast<pfn_PrefetchVirtualMemory_>(
            okw::system_function(kernelbase, "PrefetchVirtualMemory"));
        g_calls.usable = g_calls.alloc2 && g_calls.map3 && g_calls.unmap2 && works(g_calls);
        okw::atomic::store(&g_calls_known, 1);
    }
    ReleaseSRWLockExclusive(&g_calls_lock);
    return g_calls;
}

// --- the regions made of views ---------------------------------------------------
struct piece {
    okw_uptr off, len;
    bool     file;      // a view of a file; otherwise of the region's section
    kal_u64  at;        // the file's offset, for a file's
    bool     written;   // a file's view written privately (KAL_EXEC_MAP_WRITE)
};

struct region {
    char*    base;
    okw_uptr size;
    HANDLE   section;
    piece*   pieces;
    unsigned count, cap;
    region*  next;
};

region*  g_regions = nullptr;
SRWLOCK_ g_regions_lock{};

region* find(void* base) {
    for (region* r = g_regions; r; r = r->next) if (r->base == base) return r;
    return nullptr;
}

bool grow(region& r) {
    const unsigned ncap = r.cap ? r.cap * 2 : 4;
    auto* np = static_cast<piece*>(kal_alloc(ncap * sizeof(piece), alignof(piece)));
    if (!np) return false;
    for (unsigned i = 0; i < r.count; ++i) np[i] = r.pieces[i];
    if (r.pieces) kal_free(r.pieces, r.cap * sizeof(piece), alignof(piece));
    r.pieces = np;
    r.cap = ncap;
    return true;
}

// A region at `at', or anywhere for null: a placeholder of the whole replaced by
// a view of a section of the paging file, whose bytes are zero.
void* made(const calls& c, void* at, kal_uintptr size) {
    const unsigned long long bytes = round_up(size, kView);
    const HANDLE self = GetCurrentProcess();
    HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE,
                                        static_cast<DWORD>(bytes >> 32), static_cast<DWORD>(bytes), nullptr);
    if (!section) return nullptr;
    auto* r = static_cast<region*>(kal_alloc(sizeof(region), alignof(region)));
    auto* p = static_cast<char*>(c.alloc2(self, at, bytes, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER_,
                                          PAGE_NOACCESS, nullptr, 0));
    const bool placed = p != nullptr && (at == nullptr || p == at);
    if (!r || !placed || !section_view(c, section, p, 0, bytes)) {
        if (p) VirtualFree(p, 0, MEM_RELEASE);
        if (r) kal_free(r, sizeof(region), alignof(region));
        CloseHandle(section);
        return nullptr;
    }
    *r = region{ p, static_cast<okw_uptr>(bytes), section, nullptr, 0, 0, nullptr };
    if (!grow(*r)) {
        UnmapViewOfFile(p);
        kal_free(r, sizeof(region), alignof(region));
        CloseHandle(section);
        return nullptr;
    }
    r->pieces[r->count++] = piece{ 0, static_cast<okw_uptr>(bytes), false, 0, false };
    AcquireSRWLockExclusive(&g_regions_lock);
    r->next = g_regions;
    g_regions = r;
    ReleaseSRWLockExclusive(&g_regions_lock);
    return p;
}

// The protection of a range of a region: each view of the section in it, as a
// call of this system's own reaches no further than one view. A view of a file
// keeps what it was given (exec.h: it is neither published nor written), unless
// it was given to be written, which is protected as the section's views are.
int protect(void* base, okw_uptr off, okw_uptr size, DWORD how) {
    DWORD before = 0;
    AcquireSRWLockExclusive(&g_regions_lock);
    const region* r = find(base);
    if (!r) {
        ReleaseSRWLockExclusive(&g_regions_lock);
        return VirtualProtect(static_cast<char*>(base) + off, size, how, &before)
             ? kal_ok : okw::translate_win32(GetLastError());
    }
    int e = kal_ok;
    for (unsigned i = 0; i < r->count && e == kal_ok; ++i) {
        const piece& p = r->pieces[i];
        const okw_uptr lo = p.off > off ? p.off : off;
        const okw_uptr hi = p.off + p.len < off + size ? p.off + p.len : off + size;
        if (lo >= hi || (p.file && !p.written)) continue;
        if (!VirtualProtect(r->base + lo, hi - lo, how, &before)) e = okw::translate_win32(GetLastError());
    }
    ReleaseSRWLockExclusive(&g_regions_lock);
    return e;
}

// The protections of a range, as runs, so that a view put back over them has
// them again.
struct runs {
    okw_uptr off[32], len[32];
    DWORD    prot[32];
    unsigned n = 0;
    bool take(const char* base, okw_uptr from, okw_uptr to) {
        for (okw_uptr at = from; at < to;) {
            MEMORY_BASIC_INFORMATION_ m{};
            if (VirtualQuery(base + at, &m, sizeof m) == 0 || n == 32) return false;
            okw_uptr end = static_cast<okw_uptr>(static_cast<const char*>(m.BaseAddress) - base) + m.RegionSize;
            if (end > to) end = to;
            off[n] = at; len[n] = end - at; prot[n] = m.Protect; ++n;
            at = end;
        }
        return true;
    }
    void give(char* base) const {
        DWORD before = 0;
        for (unsigned i = 0; i < n; ++i)
            if (prot[i] != PAGE_READWRITE) VirtualProtect(base + off[i], len[i], prot[i], &before);
    }
};

// A handle for the file of its own, with the access a view of it needs.
void* reopen(void* file, unsigned long access) {
    okw::unicode_string empty{ 0, 0, nullptr };
    okw::object_attributes attrs{};
    attrs.length = sizeof attrs;
    attrs.root_directory = file;
    attrs.object_name = &empty;
    okw::io_status_block status{};
    void* h = nullptr;
    const long rc = okw::NtCreateFile(&h, access | SYNCHRONIZE, &attrs, &status, nullptr, FILE_ATTRIBUTE_NORMAL,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, okw::file_open,
                                      okw::file_non_directory_file | okw::file_synchronous_io_nonalert,
                                      nullptr, 0);
    return okw::ok(rc) ? h : nullptr;
}

}  // namespace

namespace okw {
// The file and its offset where `address' lies in a part of a region that is a
// file's, for the fault report (observe.cpp): false elsewhere, and where the
// table is held by another context at the moment.
bool exec_file_part(okw_uptr address, okw_uptr* view, kal_u64* at) {
    if (!TryAcquireSRWLockShared(&g_regions_lock)) return false;
    bool found = false;
    for (const region* r = g_regions; r && !found; r = r->next) {
        const okw_uptr b = reinterpret_cast<okw_uptr>(r->base);
        if (address < b || address >= b + r->size) continue;
        for (unsigned i = 0; i < r->count; ++i) {
            const piece& p = r->pieces[i];
            if (!p.file || address < b + p.off || address >= b + p.off + p.len) continue;
            *view = b + p.off;
            *at = p.at;
            found = true;
            break;
        }
    }
    ReleaseSRWLockShared(&g_regions_lock);
    return found;
}
}  // namespace okw

extern "C" {

void* kal_exec_alloc(kal_uintptr size) {
    if (size == 0) return nullptr;
    const calls& c = placeholders();
    if (c.usable) return made(c, nullptr, size);
    return VirtualAlloc(nullptr, round_up(size, kPage), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

// AT AN ADDRESS (0.23): this system's reservation takes an address and fails,
// reserving nothing, where anything is there or the address is not a multiple
// of its sixty-four kibibytes of reservation.
void* kal_exec_alloc_at(void* at, kal_uintptr size) {
    if (size == 0 || at == nullptr) return nullptr;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const unsigned long long quantum = si.dwAllocationGranularity ? si.dwAllocationGranularity : 65536;
    if (reinterpret_cast<unsigned long long>(at) % quantum != 0) return nullptr;
    const calls& c = placeholders();
    if (c.usable) return made(c, at, size);
    const unsigned long long bytes = round_up(size, kPage);
    void* p = VirtualAlloc(at, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p != nullptr && p != at) { VirtualFree(p, 0, MEM_RELEASE); return nullptr; }
    return p;
}

int kal_exec_publish(void* p, kal_uintptr size) {
    if (p == nullptr || size == 0) return kal_err_invalid;
    const unsigned long long bytes = round_up(size, kPage);
    if (const int e = protect(p, 0, bytes, PAGE_EXECUTE_READ); e != kal_ok) return e;
    if (!FlushInstructionCache(GetCurrentProcess(), p, bytes))
        return okw::translate_win32(GetLastError());
    return kal_ok;
}

void kal_exec_free(void* p, kal_uintptr size) {
    if (p == nullptr || size == 0) return;
    AcquireSRWLockExclusive(&g_regions_lock);
    region* r = nullptr;
    for (region** at = &g_regions; *at; at = &(*at)->next)
        if ((*at)->base == p) { r = *at; *at = r->next; break; }
    ReleaseSRWLockExclusive(&g_regions_lock);
    if (r == nullptr) {
        // THE SIZE IS ZERO AND THAT IS NOT AN OVERSIGHT. This system's release
        // takes a size of zero with `MEM_RELEASE' and refuses any other value:
        // the region released is the whole of the one that was reserved, which
        // is what this operation means.
        VirtualFree(p, 0, MEM_RELEASE);
        return;
    }
    // Each view, which releases its addresses with it, and the section.
    for (unsigned i = 0; i < r->count; ++i) UnmapViewOfFile(r->base + r->pieces[i].off);
    CloseHandle(r->section);
    kal_free(r->pieces, r->cap * sizeof(piece), alignof(piece));
    kal_free(r, sizeof(region), alignof(region));
}

// A published region may be reserved for writing again: this system's
// protection call is not one-way, and a second `VirtualProtect' to
// PAGE_READWRITE succeeds. The position is set accordingly, and a caller that
// must change published bytes need not abandon the region.
// This system grants executable memory to every program; nothing here is
// withheld from an artifact for the way it was produced.
// PART OF A REGION (0.17). This system reserves in sixty-four kibibytes and
// protects in pages; the second is what a part is measured in.
kal_uintptr kal_exec_granularity(void) {
    static kal_uintptr page = 0;
    if (page == 0) {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        page = si.dwPageSize ? si.dwPageSize : kPage;
    }
    return page;
}

int kal_exec_publish_part(void* region, kal_uintptr offset, kal_uintptr size) {
    const kal_uintptr g = kal_exec_granularity();
    if (region == nullptr || size == 0 || (offset & (g - 1)) != 0 || (size & (g - 1)) != 0
        || (reinterpret_cast<kal_uintptr>(region) & (g - 1)) != 0)
        return kal_err_invalid;
    if (const int e = protect(region, offset, size, PAGE_EXECUTE_READ); e != kal_ok) return e;
    if (!FlushInstructionCache(GetCurrentProcess(), static_cast<char*>(region) + offset, size))
        return okw::translate_win32(GetLastError());
    return kal_ok;
}

// READ-ONLY AFTER RELOCATION (0.23). KAL_EXEC_PROP_SEAL_FOREVER is not
// claimed: this system's protection of a view or an allocation can always be
// changed again by the program that holds it, so a part asked to be sealed for
// ever is made read-only, as exec.h states for an implementation that does not
// claim the position.
int kal_exec_seal_part(void* region, kal_uintptr offset, kal_uintptr size, kal_uintptr flags) {
    const kal_uintptr g = kal_exec_granularity();
    if (region == nullptr || size == 0 || (offset & (g - 1)) != 0 || (size & (g - 1)) != 0
        || (reinterpret_cast<kal_uintptr>(region) & (g - 1)) != 0 || (flags & ~KAL_EXEC_SEAL_FOREVER) != 0)
        return kal_err_invalid;
    return protect(region, offset, size, PAGE_READONLY);
}

// A PART THAT IS A FILE'S (0.21): see the head of this file.
int kal_exec_map_part(void* base, kal_uintptr offset, kal_uintptr size, kal_file file, kal_u64 at,
                      kal_uintptr how) {
    const kal_uintptr g = kal_exec_granularity();
    constexpr kal_uintptr known = KAL_EXEC_MAP_EXECUTE | KAL_EXEC_MAP_PREFETCH | KAL_EXEC_MAP_BTI | KAL_EXEC_MAP_WRITE;
    if (base == nullptr || size == 0 || (offset & (g - 1)) != 0 || (size & (g - 1)) != 0
        || at % KAL_MAP_ALIGNMENT != 0 || (how & ~known) != 0
        || ((how & KAL_EXEC_MAP_WRITE) && (how & KAL_EXEC_MAP_EXECUTE)))
        return kal_err_invalid;
    void* fh = okw::unpack(file.h);
    if (!fh) return kal_err_invalid;
    const calls& c = placeholders();
    if (!c.usable) return kal_err_not_supported;

    okw::io_status_block s{};
    unsigned long access = 0;
    if (!okw::ok(okw::NtQueryInformationFile(fh, &s, &access, sizeof access, okw::file_access_information_class)))
        return kal_err_invalid;
    if ((access & FILE_READ_DATA) == 0) return kal_err_permission;
    okw::file_standard_information standard{};
    const long q = okw::NtQueryInformationFile(fh, &s, &standard, sizeof standard,
                                               okw::file_standard_information_class);
    if (!okw::ok(q)) return okw::translate_nt(q);
    const kal_u64 length = standard.end_of_file > 0 ? static_cast<kal_u64>(standard.end_of_file) : 0;
    if (at > length || size > length - at) return kal_err_invalid;
    if (GetFileType(fh) != FILE_TYPE_DISK) return kal_err_not_supported;
    // Views are placed in this system's sixty-four kibibytes.
    if (offset % kView != 0 || size % kView != 0) return kal_err_not_supported;

    // The file's section, executable where asked: a file whose access does not
    // let it be executed is a property of the file. One written privately is a
    // section of copies on write (PAGE_WRITECOPY), which never changes the file.
    const bool execute = (how & KAL_EXEC_MAP_EXECUTE) != 0;
    const bool written = (how & KAL_EXEC_MAP_WRITE) != 0;
    const DWORD view_prot = execute ? PAGE_EXECUTE_READ : written ? PAGE_WRITECOPY : PAGE_READONLY;
    void* xh = reopen(fh, FILE_READ_DATA | (execute ? FILE_EXECUTE_ : 0u));
    if (!xh) return execute ? kal_err_not_supported : kal_err_permission;
    HANDLE fsec = CreateFileMappingW(xh, nullptr, view_prot, 0, 0, nullptr);
    const DWORD why = fsec ? 0 : GetLastError();
    okw::NtClose(xh);
    if (!fsec) return why == ERROR_ACCESS_DENIED ? kal_err_not_supported : okw::translate_win32(why);

    const HANDLE self = GetCurrentProcess();
    AcquireSRWLockExclusive(&g_regions_lock);
    int e = kal_ok;
    region* r = find(base);
    unsigned k = 0;
    if (!r || offset + size > r->size) e = kal_err_invalid;
    // The view of the section that holds the whole part: a part already a
    // file's, or one across two views, is refused (a part is made a file's once).
    if (e == kal_ok) {
        while (k < r->count && !(r->pieces[k].off <= offset && offset < r->pieces[k].off + r->pieces[k].len)) ++k;
        if (k == r->count || r->pieces[k].file || offset + size > r->pieces[k].off + r->pieces[k].len)
            e = kal_err_invalid;
    }
    if (e == kal_ok && r->count + 2 > r->cap && !grow(*r)) e = kal_err_no_memory;
    runs left, middle, right;
    const okw_uptr p0 = e == kal_ok ? r->pieces[k].off : 0;
    const okw_uptr p1 = e == kal_ok ? p0 + r->pieces[k].len : 0;
    if (e == kal_ok && !(left.take(r->base, p0, offset) && middle.take(r->base, offset, offset + size)
                         && right.take(r->base, offset + size, p1)))
        e = kal_err_not_supported;
    if (e == kal_ok && !c.unmap2(self, r->base + p0, MEM_PRESERVE_PLACEHOLDER_))
        e = okw::translate_win32(GetLastError());
    if (e != kal_ok) {
        ReleaseSRWLockExclusive(&g_regions_lock);
        CloseHandle(fsec);
        return e;
    }
    // From here the region's addresses are placeholders until each is a view
    // again; the section holds what they held.
    if (p0 < offset) VirtualFree(r->base + p0, offset - p0, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER_);
    if (offset + size < p1) VirtualFree(r->base + offset, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER_);
    auto own = [&](okw_uptr off, okw_uptr len) { return len == 0 || section_view(c, r->section, r->base + off, off, len); };
    const bool before = own(p0, offset - p0);
    bool part = c.map3(fsec, self, r->base + offset, at, size, MEM_REPLACE_PLACEHOLDER_,
                       view_prot, nullptr, 0) == r->base + offset;
    const DWORD part_why = part ? 0 : GetLastError();
    // A file that could not be mapped leaves the part what it was.
    if (!part) own(offset, size);
    const bool after = own(offset + size, p1 - offset - size);
    left.give(r->base);
    if (!part) middle.give(r->base);
    right.give(r->base);
    // The table: the view that was, as the three it is now.
    piece pieces[3];
    unsigned n = 0;
    if (p0 < offset) pieces[n++] = piece{ p0, offset - p0, false, 0, false };
    pieces[n++] = piece{ offset, size, part, part ? at : 0, part && written };
    if (offset + size < p1) pieces[n++] = piece{ offset + size, p1 - offset - size, false, 0, false };
    for (unsigned i = r->count; i > k + 1; --i) r->pieces[i + n - 2] = r->pieces[i - 1];
    for (unsigned i = 0; i < n; ++i) r->pieces[k + i] = pieces[i];
    r->count += n - 1;
    ReleaseSRWLockExclusive(&g_regions_lock);
    CloseHandle(fsec);
    if (!before || !after) return kal_err_no_memory;
    if (!part) return part_why == ERROR_ACCESS_DENIED ? kal_err_not_supported : okw::translate_win32(part_why);
    // THE PAGES READ IN NOW (0.23): one request for the part's pages rather
    // than a fault for each. A request about time; a system without the call
    // maps the part as without it.
    if ((how & KAL_EXEC_MAP_PREFETCH) && c.prefetch) {
        WIN32_MEMORY_RANGE_ENTRY_ range{ r->base + offset, size };
        c.prefetch(self, 1, &range, 0);
    }
    return kal_ok;
}

// KAL_EXEC_MAP_BTI is accepted and not enforced: this system's processors
// mark no branch targets for it to hold a program to.
kal_uintptr kal_exec_props(void) {
    return KAL_EXEC_PROP_REPUBLISH | KAL_EXEC_PROP_AVAILABLE | KAL_EXEC_PROP_PLACE
         | (placeholders().usable ? KAL_EXEC_PROP_FILE : 0u);
}

}  // extern "C"
