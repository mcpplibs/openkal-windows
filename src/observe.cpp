// openkal.debug and openkal.prof for a program of this environment (0.23):
// the fault reported by what ends the program, an address named, and samples
// taken (SPEC.md clause 11, entry 56).
//
// THE FAULT is reported from the filter this system calls for an exception no
// handler of the program took --- the one that ends it --- and after the filter
// that was there before, so that a fault a runtime's own filter handles is not
// reported. Memory that may not be there --- a frame of a broken chain --- is
// read through ReadProcessMemory, which refuses where a load would fault again,
// and nothing is allocated: a program that faulted may have done so inside its
// allocator. An exhausted stack is reported from a context of its own.
//
// SAMPLES are taken by a context of this program's own, which suspends each
// other context that used the processor since the last tick, reads where it
// stands, and lets it go: this system delivers no timer to the context that is
// running. Nothing is allocated while a context is suspended; the one that is
// may hold the lock an allocation takes.
#include "win.h"
#include <openkal/debug.h>
#include <openkal/exec.h>
#include <openkal/prof.h>
#include <openkal/task.h>
#include <openkal/time.h>

namespace okw { bool exec_file_part(okw_uptr address, okw_uptr* view, kal_u64* at); }

namespace {

// --- the registers of a context (CONTEXT, of this system's two processors) ------
#if defined(__aarch64__) || defined(_M_ARM64)
constexpr okw_uptr kContextSize = 0x390, kFlagsAt = 0x0, kFpAt = 0xF0, kSpAt = 0x100, kPcAt = 0x108;
constexpr DWORD kContextWanted = 0x00400003u;   // CONTEXT_ARM64 | CONTROL | INTEGER
#else
constexpr okw_uptr kContextSize = 0x4D0, kFlagsAt = 0x30, kFpAt = 0xA0, kSpAt = 0x98, kPcAt = 0xF8;
constexpr DWORD kContextWanted = 0x00100003u;   // CONTEXT_AMD64 | CONTROL | INTEGER
#endif

struct frame_regs { okw_uptr pc, fp, sp; };

frame_regs from_context(const void* ctx) {
    const auto* b = static_cast<const unsigned char*>(ctx);
    frame_regs r{};
    auto word = [&](okw_uptr at) { okw_uptr v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | b[at + i]; return v; };
    r.pc = word(kPcAt); r.fp = word(kFpAt); r.sp = word(kSpAt);
    return r;
}

bool peek(okw_uptr at, void* out, okw_uptr n) {
    unsigned long long got = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(at), out, n, &got) && got == n;
}

// The return addresses of a chain of frame pointers.
int walk(frame_regs r, okw_uptr* pcs, int max) {
    int n = 0;
    if (r.pc && n < max) pcs[n++] = r.pc;
    okw_uptr fp = r.fp;
    for (int i = 0; i < 256 && n < max; ++i) {
        if (fp == 0 || (fp & 7) != 0 || fp < r.sp) break;
        okw_uptr pair[2];
        if (!peek(fp, pair, sizeof pair)) break;
        if (pair[1] == 0) break;
        pcs[n++] = pair[1];
        if (pair[0] <= fp) break;      // a chain runs toward older frames
        fp = pair[0];
    }
    return n;
}

// --- writing without a C library ---------------------------------------------
struct line {
    char b[512]; okw_uptr n = 0;
    line& s(const char* t) { while (*t && n + 1 < sizeof b) b[n++] = *t++; return *this; }
    line& s(const char* t, okw_uptr len) { for (okw_uptr i = 0; i < len && n + 1 < sizeof b; ++i) b[n++] = t[i]; return *this; }
    line& hex(okw_uptr v) {
        char d[18]; int k = 0;
        do { d[k++] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v);
        s("0x");
        while (k) { if (n + 1 < sizeof b) b[n++] = d[--k]; else --k; }
        return *this;
    }
    line& dec(okw_uptr v) {
        char d[24]; int k = 0;
        do { d[k++] = static_cast<char>('0' + v % 10); v /= 10; } while (v);
        while (k) { if (n + 1 < sizeof b) b[n++] = d[--k]; else --k; }
        return *this;
    }
    void out() {
        void* h = GetStdHandle(STD_ERROR_HANDLE);
        DWORD wrote = 0;
        for (okw_uptr at = 0; h && h != INVALID_HANDLE_VALUE && at < n; at += wrote)
            if (!WriteFile(h, b + at, static_cast<DWORD>(n - at), &wrote, nullptr) || wrote == 0) break;
        n = 0;
    }
};

// --- reading a file at an offset ------------------------------------------------
struct file {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit file(const wchar_t* name) {
        h = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    ~file() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    bool ok() const { return h != INVALID_HANDLE_VALUE; }
    bool read(void* out, okw_uptr n, unsigned long long at) const {
        okw_uptr got = 0;
        while (got < n) {
            OVERLAPPED ov{};
            ov.u.Offset = static_cast<DWORD>(at + got);
            ov.u.OffsetHigh = static_cast<DWORD>((at + got) >> 32);
            DWORD r = 0;
            if (!ReadFile(h, static_cast<char*>(out) + got, static_cast<DWORD>(n - got), &r, &ov) || r == 0) return false;
            got += r;
        }
        return true;
    }
};

// --- where an address lies -----------------------------------------------------
//
// In a part of a region that is a file's (exec.cpp): the file this system
// names for the view, an ELF image. In an image this system loaded --- the
// program, a library --- the module's file, a PE image, and the offset in it
// from the module's own section headers.
enum class format { none, elf, pe };
struct where_t {
    format   kind = format::none;
    okw_uptr base = 0;          // the module's, for a PE image
    okw_uptr offset = 0;        // in the file
    wchar_t  path[600];
    okw_uptr plen = 0;
    char     shown[600];        // the path, for the report
    okw_uptr slen = 0;
};

bool locate(okw_uptr addr, where_t& w) {
    okw_uptr view = 0; kal_u64 at = 0;
    if (okw::exec_file_part(addr, &view, &at)) {
        // The object manager's name, opened through its root.
        static const wchar_t root[] = L"\\\\?\\GLOBALROOT";
        okw_uptr k = 0;
        for (; root[k]; ++k) w.path[k] = root[k];
        const DWORD n = K32GetMappedFileNameW(GetCurrentProcess(), reinterpret_cast<void*>(addr), w.path + k,
                                              static_cast<DWORD>(sizeof w.path / sizeof w.path[0] - k - 1));
        if (n == 0) return false;
        w.plen = k + n;
        w.path[w.plen] = 0;
        w.kind = format::elf;
        w.offset = addr - view + static_cast<okw_uptr>(at);
        w.slen = okw::narrow(w.path + k, n, w.shown, sizeof w.shown, false);
        return true;
    }
    MEMORY_BASIC_INFORMATION_ m{};
    if (VirtualQuery(reinterpret_cast<void*>(addr), &m, sizeof m) == 0 || m.Type != MEM_IMAGE_) return false;
    const okw_uptr base = reinterpret_cast<okw_uptr>(m.AllocationBase);
    const DWORD n = GetModuleFileNameW(reinterpret_cast<HANDLE>(base), w.path,
                                       static_cast<DWORD>(sizeof w.path / sizeof w.path[0] - 1));
    if (n == 0 || n >= sizeof w.path / sizeof w.path[0] - 1) return false;
    w.plen = n;
    w.path[n] = 0;
    // The section holding the address, in the module's headers as loaded.
    unsigned lfanew = 0;
    unsigned char fh[20];
    if (!peek(base + 0x3c, &lfanew, 4) || !peek(base + lfanew + 4, fh, sizeof fh)) return false;
    const unsigned sections = fh[2] | (fh[3] << 8);
    const unsigned optional = fh[16] | (fh[17] << 8);
    const okw_uptr rva = addr - base;
    w.offset = rva;   // where no section holds it: the headers, which are the file's first bytes
    for (unsigned i = 0; i < sections && i < 96; ++i) {
        unsigned char sh[40];
        if (!peek(base + lfanew + 24 + optional + i * 40, sh, sizeof sh)) break;
        auto u32 = [&](int at) { return static_cast<okw_uptr>(sh[at] | (sh[at + 1] << 8) | (sh[at + 2] << 16))
                                        | (static_cast<okw_uptr>(sh[at + 3]) << 24); };
        const okw_uptr va = u32(12), vsize = u32(8), raw = u32(20);
        if (rva >= va && rva < va + vsize) { w.offset = rva - va + raw; break; }
    }
    w.kind = format::pe;
    w.base = base;
    w.slen = okw::narrow(w.path, n, w.shown, sizeof w.shown, false);
    return true;
}

// --- the symbol that covers an offset -------------------------------------------
struct ehdr64 { unsigned char ident[16]; okw_u32 tv; okw_u32 version; okw_u64 entry, phoff, shoff;
                okw_u32 flags; unsigned short ehsize, phentsize, phnum, shentsize, shnum, shstrndx; };
struct phdr64 { okw_u32 type, flags; okw_u64 offset, vaddr, paddr, filesz, memsz, align; };
struct shdr64 { okw_u32 name, type; okw_u64 flags, addr, offset, size; okw_u32 link, info; okw_u64 align, entsize; };
struct sym64  { okw_u32 name; unsigned char info, other; unsigned short shndx; okw_u64 value, size; };

bool elf_symbol(const file& f, okw_uptr off, char* name, okw_uptr cap, okw_uptr& len, okw_uptr& delta) {
    ehdr64 eh{};
    if (!f.read(&eh, sizeof eh, 0) || eh.ident[0] != 0x7f || eh.ident[1] != 'E' || eh.ident[4] != 2) return false;
    okw_uptr vaddr = ~okw_uptr{0};
    for (unsigned i = 0; i < eh.phnum; ++i) {
        phdr64 ph{};
        if (!f.read(&ph, sizeof ph, eh.phoff + i * sizeof ph)) return false;
        if (ph.type == 1 && off >= ph.offset && off < ph.offset + ph.filesz) { vaddr = off - ph.offset + ph.vaddr; break; }
    }
    if (vaddr == ~okw_uptr{0}) return false;
    shdr64 table{}, strings{};
    bool have = false;
    static const unsigned kinds[2] = { 2 /* SHT_SYMTAB */, 11 /* SHT_DYNSYM */ };
    for (unsigned want : kinds) {
        for (unsigned i = 0; i < eh.shnum && !have; ++i) {
            shdr64 sh{};
            if (!f.read(&sh, sizeof sh, eh.shoff + i * sizeof sh)) return false;
            if (sh.type != want) continue;
            if (!f.read(&strings, sizeof strings, eh.shoff + sh.link * sizeof sh)) return false;
            table = sh; have = true;
        }
        if (have) break;
    }
    if (!have || table.entsize != sizeof(sym64)) return false;
    okw_u64 best = 0; okw_u32 best_name = 0; bool any = false;
    sym64 chunk[64];
    const okw_u64 count = table.size / sizeof(sym64);
    for (okw_u64 at = 0; at < count; at += 64) {
        const okw_u64 n = count - at < 64 ? count - at : 64;
        if (!f.read(chunk, n * sizeof(sym64), table.offset + at * sizeof(sym64))) return false;
        for (okw_u64 k = 0; k < n; ++k) {
            const sym64& sy = chunk[k];
            if ((sy.info & 15) != 2 /* STT_FUNC */ && (sy.info & 15) != 1 /* STT_OBJECT */) continue;
            if (sy.shndx == 0 || sy.value > vaddr) continue;
            if (sy.size != 0 && vaddr >= sy.value + sy.size) continue;
            if (!any || sy.value > best) { best = sy.value; best_name = sy.name; any = true; }
        }
    }
    if (!any) return false;
    okw_uptr n = 0;
    char c = 1;
    while (n + 1 < cap && f.read(&c, 1, strings.offset + best_name + n) && c) name[n++] = c;
    len = n; delta = vaddr - best;
    return n != 0;
}

// The COFF symbol table a PE file keeps where its linker was not told to drop
// it: eighteen bytes a symbol, the value relative to its section, and the
// strings after the table.
bool pe_symbol(const file& f, okw_uptr rva, char* name, okw_uptr cap, okw_uptr& len, okw_uptr& delta) {
    unsigned lfanew = 0;
    unsigned char fh[20];
    if (!f.read(&lfanew, 4, 0x3c) || !f.read(fh, sizeof fh, lfanew + 4)) return false;
    auto u32 = [](const unsigned char* p) { return static_cast<okw_u32>(p[0] | (p[1] << 8) | (p[2] << 16))
                                                   | (static_cast<okw_u32>(p[3]) << 24); };
    const unsigned sections = fh[2] | (fh[3] << 8);
    const okw_u32 table = u32(fh + 8), count = u32(fh + 12);
    const unsigned optional = fh[16] | (fh[17] << 8);
    if (table == 0 || count == 0) return false;
    // The section that holds the address, numbered from one.
    unsigned section = 0;
    okw_uptr in_section = 0;
    for (unsigned i = 0; i < sections && i < 96; ++i) {
        unsigned char sh[40];
        if (!f.read(sh, sizeof sh, lfanew + 24 + optional + i * 40)) return false;
        const okw_uptr va = u32(sh + 12), vsize = u32(sh + 8);
        if (rva >= va && rva < va + vsize) { section = i + 1; in_section = rva - va; break; }
    }
    if (section == 0) return false;
    okw_u32 best = 0; unsigned char best_name[8] = {}; bool any = false;
    unsigned char chunk[64 * 18];
    okw_u32 first = 0, held = 0;     // the records `chunk' holds
    // An auxiliary record follows its symbol and is not one, so the walk steps
    // over them, across the chunks it reads.
    for (okw_u32 i = 0; i < count;) {
        if (i < first || i >= first + held) {
            first = i;
            held = count - i < 64 ? count - i : 64;
            if (!f.read(chunk, held * 18, table + static_cast<unsigned long long>(i) * 18)) return false;
        }
        const unsigned char* sy = chunk + (i - first) * 18;
        const okw_u32 value = u32(sy + 8);
        const unsigned sec = sy[12] | (sy[13] << 8);
        const unsigned type = sy[14] | (sy[15] << 8);
        const unsigned cls = sy[16];
        i += 1 + sy[17];
        if (sec != section || (cls != 2 && cls != 3) || value > in_section) continue;
        if ((type & 0x30) != 0x20 && cls != 2) continue;   // a function, or an external
        if (!any || value > best) { best = value; for (int k = 0; k < 8; ++k) best_name[k] = sy[k]; any = true; }
    }
    if (!any) return false;
    okw_uptr n = 0;
    if (u32(best_name) == 0) {
        const unsigned long long strings = table + static_cast<unsigned long long>(count) * 18;
        char c = 1;
        while (n + 1 < cap && f.read(&c, 1, strings + u32(best_name + 4) + n) && c) name[n++] = c;
    } else {
        while (n < 8 && n + 1 < cap && best_name[n]) { name[n] = static_cast<char>(best_name[n]); ++n; }
    }
    len = n; delta = in_section - best;
    return n != 0;
}

bool symbol_at(const where_t& w, okw_uptr addr, char* name, okw_uptr cap, okw_uptr& len, okw_uptr& delta) {
    file f(w.path);
    if (!f.ok()) return false;
    if (w.kind == format::elf) return elf_symbol(f, w.offset, name, cap, len, delta);
    if (w.kind == format::pe) return pe_symbol(f, addr - w.base, name, cap, len, delta);
    return false;
}

// --- the fault report ---------------------------------------------------------------
struct report_t {
    where_t w;
    char    name[256];
    okw_uptr pcs[64];
};
report_t g_report;          // one fault is reported; it is not reentered
volatile long long g_reporting = 0;

void describe_frame(line& l, okw_uptr pc) {
    where_t& w = g_report.w;
    w = where_t{};
    if (!locate(pc, w)) return;
    l.s(" ").s(w.shown, w.slen).s("+").hex(w.offset);
    okw_uptr nlen = 0, delta = 0;
    if (symbol_at(w, pc, g_report.name, sizeof g_report.name, nlen, delta))
        l.s(" ").s(g_report.name, nlen).s("+").hex(delta);
}

const char* fault_name(DWORD code) {
    switch (code) {
        case 0xC0000005u: return "an access the program may not make (EXCEPTION_ACCESS_VIOLATION)";
        case 0xC0000006u: return "an access the memory cannot serve (EXCEPTION_IN_PAGE_ERROR)";
        case 0xC000001Du: return "an instruction the program may not execute (EXCEPTION_ILLEGAL_INSTRUCTION)";
        case 0xC0000096u: return "an instruction the program may not execute (EXCEPTION_PRIV_INSTRUCTION)";
        case 0xC00000FDu: return "the stack is exhausted (EXCEPTION_STACK_OVERFLOW)";
        case 0xC0000094u: return "an arithmetic fault (EXCEPTION_INT_DIVIDE_BY_ZERO)";
        case 0xC0000095u: return "an arithmetic fault (EXCEPTION_INT_OVERFLOW)";
        case 0x80000002u: return "an access the memory cannot serve (EXCEPTION_DATATYPE_MISALIGNMENT)";
        default:          return nullptr;
    }
}

void report(const EXCEPTION_POINTERS_* e) {
    const EXCEPTION_RECORD_* r = e->ExceptionRecord;
    line l;
    // An access names the address it reached in its second parameter.
    const okw_uptr addr = (r->ExceptionCode == 0xC0000005u || r->ExceptionCode == 0xC0000006u) && r->NumberParameters >= 2
                        ? static_cast<okw_uptr>(r->ExceptionInformation[1])
                        : reinterpret_cast<okw_uptr>(r->ExceptionAddress);
    l.s("openkal: fault: ").s(fault_name(r->ExceptionCode)).s(" at ").hex(addr).s("\n");
    l.out();
    const int n = walk(from_context(e->ContextRecord), g_report.pcs, 64);
    for (int i = 0; i < n; ++i) {
        l.s("openkal:   #").dec(static_cast<okw_uptr>(i)).s(" ").hex(g_report.pcs[i]);
        describe_frame(l, i == 0 ? g_report.pcs[i] : g_report.pcs[i] - 1);
        l.s("\n");
        l.out();
    }
}

DWORD OKW_API report_elsewhere(LPVOID e) { report(static_cast<const EXCEPTION_POINTERS_*>(e)); return 0; }

TOP_LEVEL_FILTER_ g_before = nullptr;

long OKW_API ending(EXCEPTION_POINTERS_* e) {
    // A filter that was there first, and handles the fault, has the program go on.
    const long earlier = g_before ? g_before(e) : 0 /* EXCEPTION_CONTINUE_SEARCH */;
    if (earlier == -1 /* EXCEPTION_CONTINUE_EXECUTION */) return earlier;
    if (fault_name(e->ExceptionRecord->ExceptionCode) && okw::atomic::exchange(&g_reporting, 1) == 0) {
        if (e->ExceptionRecord->ExceptionCode == 0xC00000FDu) {
            // An exhausted stack has no room for the report.
            HANDLE t = CreateThread(nullptr, 256 * 1024, &report_elsewhere, e, 0, nullptr);
            if (t) { WaitForSingleObject(t, 10000); CloseHandle(t); }
        } else {
            report(e);
        }
    }
    return earlier;
}

// INSTALLED AT INCEPTION, for every program of this implementation.
OKW_START_FN(install_fault_report) { g_before = SetUnhandledExceptionFilter(&ending); }
OKW_AT_START(install_fault_report);

// --- touches (0.23) ------------------------------------------------------------------
//
// A part being recorded keeps its access and loses its execution; this
// system then reports a first execution of a page as an access violation of
// the kind that executes (the first parameter 8), which a first look resolves
// --- the page executable again, its address recorded once --- and the
// instruction is carried out. Every other exception passes on to the
// program's handlers.
struct touched_part {
    okw_uptr from = 0, to = 0;
    DWORD prot = 0;
    volatile long long* seen = nullptr;     // a bit for each page
};
constexpr int kTouchedParts = 16;
touched_part g_parts[kTouchedParts];
volatile long long g_part_count = 0;
volatile long long g_touching = 0;
okw_uptr g_touch_page = 4096;
void* g_touch_handler = nullptr;

struct touch_ring {
    okw_uptr* pages = nullptr;
    volatile long long* ready = nullptr;
    okw_uptr cap = 0;
    volatile long long written = 0, taken = 0;
};
touch_ring g_touches;

DWORD without_execution(DWORD prot) {
    switch (prot) {
        case 0x10: return PAGE_NOACCESS;           // PAGE_EXECUTE
        case 0x20: return PAGE_READONLY;           // PAGE_EXECUTE_READ
        case 0x40: return PAGE_READWRITE;          // PAGE_EXECUTE_READWRITE
        case 0x80: return PAGE_WRITECOPY;          // PAGE_EXECUTE_WRITECOPY
        default:   return 0;
    }
}

// One protection for the whole of [from, to), and that one executable; 0 otherwise.
DWORD protection_of(okw_uptr from, okw_uptr to) {
    DWORD prot = 0;
    for (okw_uptr at = from; at < to;) {
        MEMORY_BASIC_INFORMATION_ m{};
        if (VirtualQuery(reinterpret_cast<void*>(at), &m, sizeof m) == 0 || m.State != MEM_COMMIT) return 0;
        if (prot == 0) prot = m.Protect; else if (prot != m.Protect) return 0;
        at = reinterpret_cast<okw_uptr>(m.BaseAddress) + m.RegionSize;
    }
    return without_execution(prot) ? prot : 0;
}

// The protection of [from, to) set, each run of it within one allocation in
// turn: a call of this system's own reaches no further than one view.
void protect_runs(okw_uptr from, okw_uptr to, DWORD prot) {
    for (okw_uptr at = from; at < to;) {
        MEMORY_BASIC_INFORMATION_ m{};
        if (VirtualQuery(reinterpret_cast<void*>(at), &m, sizeof m) == 0) return;
        okw_uptr end = reinterpret_cast<okw_uptr>(m.BaseAddress) + m.RegionSize;
        if (end > to) end = to;
        DWORD before = 0;
        VirtualProtect(reinterpret_cast<void*>(at), end - at, prot, &before);
        at = end;
    }
}

long OKW_API touch_look(EXCEPTION_POINTERS_* e) {
    const EXCEPTION_RECORD_* r = e->ExceptionRecord;
    if (r->ExceptionCode != 0xC0000005u || r->NumberParameters < 2 || r->ExceptionInformation[0] != 8
        || !okw::atomic::load(&g_touching))
        return 0;   // EXCEPTION_CONTINUE_SEARCH
    const okw_uptr addr = static_cast<okw_uptr>(r->ExceptionInformation[1]);
    const long long n = okw::atomic::load(&g_part_count);
    for (long long k = 0; k < n; ++k) {
        touched_part& t = g_parts[k];
        if (addr < t.from || addr >= t.to) continue;
        const okw_uptr page = addr & ~(g_touch_page - 1);
        const okw_uptr index = (page - t.from) / g_touch_page;
        const long long bit = 1ll << (index & 63);
        const long long was = okw::atomic::fetch_or(&t.seen[index >> 6], bit);
        DWORD before = 0;
        VirtualProtect(reinterpret_cast<void*>(page), g_touch_page, t.prot, &before);
        if (!(was & bit) && g_touches.pages) {
            const long long mine = okw::atomic::fetch_add(&g_touches.written, 1);
            if (static_cast<okw_uptr>(mine - okw::atomic::load(&g_touches.taken)) < g_touches.cap) {
                g_touches.pages[static_cast<okw_uptr>(mine) % g_touches.cap] = page;
                okw::atomic::store(&g_touches.ready[static_cast<okw_uptr>(mine) % g_touches.cap], mine + 1);
            }
        }
        return -1;   // EXCEPTION_CONTINUE_EXECUTION
    }
    return 0;
}

// --- samples -----------------------------------------------------------------------
constexpr okw_uptr kRing = 65536;
constexpr okw_uptr kCommitChunk = 64;          // samples committed at a time

struct ring {
    kal_prof_sample* slots = nullptr;
    volatile long long* ready = nullptr;       // the sequence number + 1 of the sample a slot holds
    volatile long long written = 0;
    volatile long long taken = 0;
    volatile long long on = 0;
    volatile long long stop = 0;
    HANDLE thread = nullptr;
    DWORD  sampler = 0;
    DWORD  period_us = 0;
    bool   committed[kRing / kCommitChunk];
};
ring g_ring;

struct watched { DWORD id; HANDLE h; unsigned long long cycles; };
constexpr int kWatched = 256;

DWORD OKW_API sampler(LPVOID) {
    static watched threads[kWatched];
    int count = 0;
    const DWORD self = GetCurrentThreadId();
    const DWORD pid = GetCurrentProcessId();
    HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION_, TIMER_ALL_ACCESS_);
    if (!timer) timer = CreateWaitableTimerExW(nullptr, nullptr, 0, TIMER_ALL_ACCESS_);
    LARGE_INTEGER due{};
    due.QuadPart = -static_cast<long long>(g_ring.period_us) * 10;
    const LONG period_ms = static_cast<LONG>(g_ring.period_us / 1000 ? g_ring.period_us / 1000 : 1);
    if (timer) SetWaitableTimer(timer, &due, period_ms, nullptr, nullptr, FALSE);
    alignas(16) static unsigned char context[kContextSize];
    unsigned ticks = 0;
    while (!okw::atomic::load(&g_ring.stop)) {
        if (timer) WaitForSingleObject(timer, INFINITE); else Sleep(period_ms);
        // The contexts of this program, looked for again every tenth of a second.
        if (ticks++ % (100000 / (g_ring.period_us ? g_ring.period_us : 1000) + 1) == 0) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD_, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                THREADENTRY32_ te{};
                te.dwSize = sizeof te;
                for (BOOL more = Thread32First(snap, &te); more; more = Thread32Next(snap, &te)) {
                    if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
                    bool known = false;
                    for (int i = 0; i < count && !known; ++i) known = threads[i].id == te.th32ThreadID;
                    if (known || count == kWatched) continue;
                    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME_ | THREAD_GET_CONTEXT_ | THREAD_QUERY_LIMITED_INFORMATION_,
                                          FALSE, te.th32ThreadID);
                    if (h) threads[count++] = watched{ te.th32ThreadID, h, 0 };
                }
                CloseHandle(snap);
            }
        }
        for (int i = 0; i < count; ++i) {
            watched& t = threads[i];
            // A context that ended is forgotten; one that did not run is not sampled.
            if (WaitForSingleObject(t.h, 0) == WAIT_OBJECT_0) {
                CloseHandle(t.h);
                threads[i--] = threads[--count];
                continue;
            }
            // What it has used: the processor's cycles where this system counts
            // them for a context, its times otherwise --- coarser, and a context
            // that ran less than a tick of them is not seen to have run.
            unsigned long long used = 0;
            bool known = QueryThreadCycleTime(t.h, &used) != 0;
            if (!known) {
                FILETIME created{}, exited{}, kernel{}, user{};
                known = GetThreadTimes(t.h, &created, &exited, &kernel, &user) != 0;
                used = ((static_cast<unsigned long long>(kernel.dwHighDateTime) << 32) | kernel.dwLowDateTime)
                     + ((static_cast<unsigned long long>(user.dwHighDateTime) << 32) | user.dwLowDateTime);
            }
            if (known && used == t.cycles) continue;
            t.cycles = used;
            const long long at = okw::atomic::load(&g_ring.written);
            if (static_cast<okw_uptr>(at - okw::atomic::load(&g_ring.taken)) >= kRing) continue;   // full: not recorded
            const okw_uptr slot = static_cast<okw_uptr>(at) % kRing;
            if (!g_ring.committed[slot / kCommitChunk]) {
                if (!VirtualAlloc(&g_ring.slots[slot - slot % kCommitChunk], kCommitChunk * sizeof(kal_prof_sample),
                                  MEM_COMMIT, PAGE_READWRITE))
                    continue;
                g_ring.committed[slot / kCommitChunk] = true;
            }
            kal_prof_sample& s = g_ring.slots[slot];
            for (okw_uptr k = 0; k < kContextSize; ++k) context[k] = 0;
            *reinterpret_cast<DWORD*>(context + kFlagsAt) = kContextWanted;
            if (SuspendThread(t.h) == static_cast<DWORD>(-1)) continue;
            const bool have = GetThreadContext(t.h, context) != 0;
            int n = 0;
            if (have) {
                okw_uptr pcs[KAL_PROF_SAMPLE_DEPTH];
                n = walk(from_context(context), pcs, KAL_PROF_SAMPLE_DEPTH);
                for (int k = 0; k < n; ++k) s.pc[k] = pcs[k];
            }
            ResumeThread(t.h);
            if (!have) continue;
            s.time_ns = kal_time_monotonic();
            s.context = t.id;
            s.depth = static_cast<kal_u32>(n);
            s.reserved = 0;
            g_ring.written = at + 1;
            okw::atomic::store(&g_ring.ready[slot], at + 1);
        }
    }
    for (int i = 0; i < count; ++i) CloseHandle(threads[i].h);
    if (timer) CloseHandle(timer);
    return 0;
}

}  // namespace

extern "C" {

kal_uintptr kal_debug_props(void) { return KAL_DEBUG_PROP_FAULT_REPORT; }

// AN ADDRESS NAMED (0.23 for a program of this environment): the file that
// holds it --- an image a loader made a region's part, the program, a library
// --- and that file's symbol table.
kal_intptr kal_debug_symbolize(kal_uintptr address, char* out, kal_uintptr cap, kal_uintptr* start) {
    if (address == 0) return -static_cast<kal_intptr>(kal_err_not_found);
    where_t w;
    if (!locate(address, w)) return -static_cast<kal_intptr>(kal_err_not_found);
    char name[1024];
    okw_uptr nlen = 0, delta = 0;
    if (!symbol_at(w, address, name, sizeof name, nlen, delta)) return -static_cast<kal_intptr>(kal_err_not_found);
    if (out && cap) for (okw_uptr i = 0; i < nlen && i < cap; ++i) out[i] = name[i];
    if (start) *start = address - delta;
    return static_cast<kal_intptr>(nlen);
}

// THIS IMPLEMENTATION DOES NOT MEASURE A PROGRAM ITSELF: a loader that binds
// an image does (clause 12.3). So the program is not measured, a counter is
// accepted and never read, and a phase is accepted and recorded nowhere.
int  kal_prof_active(void) { return 0; }
int  kal_prof_counter(const char*, kal_uintptr, const volatile kal_u64*) { return kal_ok; }
void kal_prof_mark(const char*, kal_uintptr, int) {}

kal_uintptr kal_prof_props(void) { return KAL_PROF_PROP_SAMPLES | KAL_PROF_PROP_TOUCHES; }

int kal_prof_sample_begin(kal_u32 per_second) {
    if (per_second == 0 || per_second > 10000) return kal_err_invalid;
    if (okw::atomic::exchange(&g_ring.on, 1) != 0) return kal_err_again;
    if (!g_ring.slots) {
        // Addresses for a minute of samples at a thousand a second, committed
        // as samples are written; the marks beside them, committed now.
        g_ring.slots = static_cast<kal_prof_sample*>(VirtualAlloc(nullptr, kRing * sizeof(kal_prof_sample),
                                                                  MEM_RESERVE, PAGE_READWRITE));
        g_ring.ready = static_cast<volatile long long*>(VirtualAlloc(nullptr, kRing * sizeof(long long),
                                                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!g_ring.slots || !g_ring.ready) { okw::atomic::store(&g_ring.on, 0); return kal_err_no_memory; }
    }
    g_ring.period_us = 1000000u / per_second;
    okw::atomic::store(&g_ring.stop, 0);
    g_ring.thread = CreateThread(nullptr, 64 * 1024, &sampler, nullptr, 0, &g_ring.sampler);
    if (!g_ring.thread) { okw::atomic::store(&g_ring.on, 0); return kal_err_no_memory; }
    return kal_ok;
}

kal_intptr kal_prof_sample_take(kal_prof_sample* out, kal_uintptr count) {
    if (out == nullptr && count != 0) return -static_cast<kal_intptr>(kal_err_invalid);
    if (!g_ring.slots) return 0;
    kal_uintptr n = 0;
    while (n < count) {
        const long long t = okw::atomic::load(&g_ring.taken);
        if (okw::atomic::load(&g_ring.ready[static_cast<okw_uptr>(t) % kRing]) != t + 1) break;
        out[n++] = g_ring.slots[static_cast<okw_uptr>(t) % kRing];
        okw::atomic::store(&g_ring.taken, t + 1);
    }
    return static_cast<kal_intptr>(n);
}

int kal_prof_sample_end(void) {
    if (!okw::atomic::load(&g_ring.on)) return kal_err_invalid;
    okw::atomic::store(&g_ring.stop, 1);
    if (g_ring.thread) {
        WaitForSingleObject(g_ring.thread, INFINITE);
        CloseHandle(g_ring.thread);
        g_ring.thread = nullptr;
    }
    okw::atomic::store(&g_ring.on, 0);
    return kal_ok;
}

// TOUCHES (0.23).
int kal_prof_touch_begin(const void* at, kal_uintptr size) {
    const okw_uptr g = kal_exec_granularity();
    const okw_uptr from = reinterpret_cast<okw_uptr>(at);
    if (size == 0 || (from & (g - 1)) != 0 || (size & (g - 1)) != 0) return kal_err_invalid;
    const DWORD prot = protection_of(from, from + size);
    if (prot == 0) return kal_err_invalid;
    const long long k = okw::atomic::load(&g_part_count);
    if (k == kTouchedParts) return kal_err_no_memory;
    g_touch_page = g;
    if (!g_touches.pages) {
        constexpr okw_uptr cap = 65536;
        auto* m = static_cast<unsigned char*>(VirtualAlloc(nullptr, cap * (sizeof(okw_uptr) + sizeof(long long)),
                                                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!m) return kal_err_no_memory;
        g_touches.pages = reinterpret_cast<okw_uptr*>(m);
        g_touches.ready = reinterpret_cast<volatile long long*>(m + cap * sizeof(okw_uptr));
        g_touches.cap = cap;
    }
    const okw_uptr words = (size / g + 63) / 64;
    auto* seen = static_cast<volatile long long*>(VirtualAlloc(nullptr, words * sizeof(long long),
                                                               MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!seen) return kal_err_no_memory;
    if (!g_touch_handler) g_touch_handler = AddVectoredExceptionHandler(1, &touch_look);
    if (!g_touch_handler) return kal_err_no_memory;
    g_parts[k] = touched_part{ from, from + size, prot, seen };
    okw::atomic::store(&g_part_count, k + 1);
    okw::atomic::store(&g_touching, 1);
    protect_runs(from, from + size, without_execution(prot));
    return kal_ok;
}

kal_intptr kal_prof_touch_take(kal_uintptr* out, kal_uintptr count) {
    if (out == nullptr && count != 0) return -static_cast<kal_intptr>(kal_err_invalid);
    if (!g_touches.pages) return 0;
    kal_uintptr n = 0;
    while (n < count) {
        const long long t = okw::atomic::load(&g_touches.taken);
        if (okw::atomic::load(&g_touches.ready[static_cast<okw_uptr>(t) % g_touches.cap]) != t + 1) break;
        out[n++] = g_touches.pages[static_cast<okw_uptr>(t) % g_touches.cap];
        okw::atomic::store(&g_touches.taken, t + 1);
    }
    return static_cast<kal_intptr>(n);
}

// Every part as it was; the pages' bits stay for the life of the program.
int kal_prof_touch_end(void) {
    const long long n = okw::atomic::load(&g_part_count);
    if (n == 0) return kal_err_invalid;
    for (long long k = 0; k < n; ++k) protect_runs(g_parts[k].from, g_parts[k].to, g_parts[k].prot);
    okw::atomic::store(&g_touching, 0);
    okw::atomic::store(&g_part_count, 0);
    return kal_ok;
}

}  // extern "C"
