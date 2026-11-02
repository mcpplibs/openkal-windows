#include "rights.h"
#include "handle.h"
#include <openkal/env.h>
#include <openkal/memory.h>

// The rights of directory handles on this system (openkal 0.23, rights.h).
//
// THE SAME TABLE AS ON THE OTHER TWO SYSTEMS, AND TWO DIFFERENCES THAT ARE THIS
// SYSTEM'S. A handle is a pointer-sized value and not a small number, so the
// table is indexed by its slot (handle.h) and each entry keeps the handle it is
// for. And names on the volumes of this system compare without regard to case,
// spelt in more than one way: a listing answers that a name is absent only
// where no other spelling could name an entry --- a name of ASCII alone, with
// no `~' (a short name the listing does not report), in a directory whose
// entries are ASCII alone.

namespace okw::rights {

volatile bool g_any = false;

namespace {

SRWLOCK_ g_lock{};
struct held {
    held() { AcquireSRWLockExclusive(&g_lock); }
    ~held() { ReleaseSRWLockExclusive(&g_lock); }
};

void copy(void* d, const void* s, okw_uptr n) {
    auto* o = static_cast<unsigned char*>(d);
    const auto* i = static_cast<const unsigned char*>(s);
    for (okw_uptr k = 0; k < n; ++k) o[k] = i[k];
}
void zero(void* d, okw_uptr n) { auto* o = static_cast<unsigned char*>(d); for (okw_uptr k = 0; k < n; ++k) o[k] = 0; }

inline bool separator(char c) { return c == '/' || c == '\\'; }
inline unsigned char folded(char c) {
    const auto u = static_cast<unsigned char>(c);
    return (u >= 'A' && u <= 'Z') ? static_cast<unsigned char>(u + 32) : u;
}

okw_u64 hash(const char* s, okw_uptr n, okw_u64 h = 1469598103934665603ull) {
    for (okw_uptr i = 0; i < n; ++i) { h ^= static_cast<unsigned char>(s[i]); h *= 1099511628211ull; }
    return h;
}
// A name as the volume compares it, for a listing.
okw_u64 folded_hash(const char* s, okw_uptr n, okw_u64 h = 1469598103934665603ull) {
    for (okw_uptr i = 0; i < n; ++i) { h ^= separator(s[i]) ? '/' : folded(s[i]); h *= 1099511628211ull; }
    return h;
}

void* grab(okw_uptr n) { return kal_alloc(n, 16); }
void  give_back(void* p, okw_uptr n) { if (p) kal_free(p, n, 16); }

int resource_preference() { return kal_env_resources(); }

// --- a set of 64-bit keys, with a byte beside each -----------------------------
struct keyset {
    okw_u64* keys = nullptr;          // zero is never a key
    unsigned char* vals = nullptr;
    okw_uptr cap = 0, used = 0;

    bool grow() {
        const okw_uptr ncap = cap ? cap * 2 : 256;
        auto* nk = static_cast<okw_u64*>(grab(ncap * sizeof(okw_u64)));
        auto* nv = static_cast<unsigned char*>(grab(ncap));
        if (!nk || !nv) { give_back(nk, ncap * sizeof(okw_u64)); give_back(nv, ncap); return false; }
        zero(nk, ncap * sizeof(okw_u64));
        for (okw_uptr i = 0; i < cap; ++i) {
            if (keys[i] == 0) continue;
            okw_uptr j = keys[i] & (ncap - 1);
            while (nk[j] != 0) j = (j + 1) & (ncap - 1);
            nk[j] = keys[i]; nv[j] = vals[i];
        }
        give_back(keys, cap * sizeof(okw_u64)); give_back(vals, cap);
        keys = nk; vals = nv; cap = ncap;
        return true;
    }
    bool add(okw_u64 k, unsigned char v) {
        if (k == 0) k = 1;
        if ((used + 1) * 2 > cap && !grow()) return false;
        okw_uptr j = k & (cap - 1);
        while (keys[j] != 0) { if (keys[j] == k) return false; j = (j + 1) & (cap - 1); }
        keys[j] = k; vals[j] = v; ++used;
        return true;
    }
    int find(okw_u64 k) const {
        if (k == 0) k = 1;
        if (cap == 0) return -1;
        okw_uptr j = k & (cap - 1);
        while (keys[j] != 0) { if (keys[j] == k) return vals[j]; j = (j + 1) & (cap - 1); }
        return -1;
    }
    void clear() {
        give_back(keys, cap * sizeof(okw_u64)); give_back(vals, cap);
        keys = nullptr; vals = nullptr; cap = used = 0;
    }
};

// --- the trees ---------------------------------------------------------------
constexpr int kRoots = 64;
constexpr okw_uptr kBatch = 64 * 1024;
constexpr unsigned char kDirectory = 1, kOther = 2;

struct root {
    bool       live = false;
    int        refs = 0;
    okw_u32    flags = 0;
    void*      base = nullptr;   // a handle of the root, to list beneath
    void*      record = nullptr; // opened to append
    char*      rprefix = nullptr;
    okw_uptr   rplen = 0;
    keyset     seen;
    char*      batch = nullptr;
    okw_uptr   batched = 0;
    keyset     listed;           // directory path -> 1 (settled) or 2 (cannot settle)
    keyset     names;            // (directory path, name) -> kind
    okw_uptr   budget = 0;
};
root g_roots[kRoots];

struct entry {
    void*    h = nullptr;
    int      root = -1;
    okw_u32  flags = 0;
    char*    prefix = nullptr;
    okw_uptr plen = 0;
};
constexpr int kEntries = 4096;
entry g_entries[kEntries];
unsigned short g_slot[okw::kSlots];   // entry index + 1; zero for none

entry* entry_of(void* h) {
    if (!h || !okw::within_bound(h)) return nullptr;
    const unsigned short s = g_slot[okw::slot_of(h)];
    if (s == 0 || g_entries[s - 1].h != h) return nullptr;
    return &g_entries[s - 1];
}

entry* new_entry(void* h) {
    if (!h || !okw::within_bound(h)) return nullptr;
    for (int i = 0; i < kEntries; ++i)
        if (g_entries[i].h == nullptr) {
            g_entries[i].h = h;
            g_slot[okw::slot_of(h)] = static_cast<unsigned short>(i + 1);
            return &g_entries[i];
        }
    return nullptr;
}

void drop_entry(entry* e) {
    if (!e) return;
    if (e->h && okw::within_bound(e->h)) g_slot[okw::slot_of(e->h)] = 0;
    give_back(e->prefix, e->plen + 1);
    *e = entry{};
}

int new_root() {
    for (int i = 0; i < kRoots; ++i) if (!g_roots[i].live) { g_roots[i] = root{}; g_roots[i].live = true; return i; }
    return -1;
}

okw_uptr budget_for_preference() {
    switch (resource_preference()) {
        case 1:  return okw_uptr{1} << 20;   // performance
        case 2:  return 0;                   // economy: nothing kept
        default: return okw_uptr{1} << 16;   // balanced
    }
}

// The path of `name' beneath the root of `e' --- after `lead', where given ---
// into `out', with `/' between components; its length, or 0 when it does not
// fit. "." components are dropped; the root itself is "" written as length 1.
okw_uptr full_path(const entry& e, const char* name, okw_uptr len, char* out, okw_uptr cap,
                   const char* lead = nullptr, okw_uptr lead_len = 0) {
    okw_uptr o = 0;
    auto put = [&](const char* s, okw_uptr n) {
        if (n == 0 || (n == 1 && s[0] == '.')) return true;
        if (o + n + 1 >= cap) return false;
        if (o) out[o++] = '/';
        copy(out + o, s, n); o += n;
        return true;
    };
    auto parts = [&](const char* s, okw_uptr n) {
        okw_uptr start = 0;
        for (okw_uptr i = 0; s && i <= n; ++i)
            if (i == n || separator(s[i])) { if (!put(s + start, i - start)) return false; start = i + 1; }
        return true;
    };
    if (!parts(lead, lead_len) || !parts(e.prefix, e.plen) || !parts(name, len)) return 0;
    out[o] = '\0';
    return o == 0 ? 1 : o;
}

// --- the record ----------------------------------------------------------------
void flush(root& r) {
    if (!r.record || r.batched == 0) return;
    okw_uptr at = 0;
    while (at < r.batched) {
        DWORD wrote = 0;
        if (!WriteFile(r.record, r.batch + at, static_cast<DWORD>(r.batched - at), &wrote, nullptr) || wrote == 0) break;
        at += wrote;
    }
    r.batched = 0;
}

void append(root& r, char kind, const char* path, okw_uptr n) {
    if (!r.record) return;
    if (!r.batch) { r.batch = static_cast<char*>(grab(kBatch)); if (!r.batch) return; }
    if (n + 2 > kBatch) return;
    if (r.batched + n + 2 > kBatch) flush(r);
    r.batch[r.batched++] = kind;
    copy(r.batch + r.batched, path, n); r.batched += n;
    r.batch[r.batched++] = '\0';
}

// --- the listings of a tree that does not change ---------------------------------
okw_u64 name_key(okw_u64 dir, const char* s, okw_uptr n) { return folded_hash(s, n, dir ^ 0x9e3779b97f4a7c15ull); }

bool ascii(const char* s, okw_uptr n) {
    for (okw_uptr i = 0; i < n; ++i) if (static_cast<unsigned char>(s[i]) >= 0x80) return false;
    return true;
}

// Lists `dir' (a path beneath the root, "" for the root) into the root's names.
// Answers 1 where the listing settles absence, 2 where it cannot (an entry not
// of ASCII alone), 0 where it could not be listed.
int list(root& r, const char* dir, okw_uptr dlen, okw_u64 key) {
    const int was = r.listed.find(key);
    if (was > 0) return was;
    if (r.budget == 0) return 0;
    void* h = nullptr;
    {
        okw::wide_name w(dir, dlen);
        if (!w.ok) return 0;
        okw::object_attributes attrs{};
        attrs.length = sizeof attrs;
        attrs.root_directory = r.base;
        attrs.object_name = &w.string;
        attrs.attributes = okw::obj_case_insensitive;
        okw::io_status_block status{};
        const long rc = okw::NtCreateFile(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attrs, &status, nullptr,
                                          FILE_ATTRIBUTE_NORMAL,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                          okw::file_open,
                                          okw::file_directory_file | okw::file_synchronous_io_nonalert,
                                          nullptr, 0);
        if (!okw::ok(rc)) return 0;
    }
    alignas(16) static unsigned char buf[16384];   // under the table's lock
    okw_uptr count = 0;
    int answer = 1;
    bool first = true;
    for (bool more = true; more;) {
        okw::io_status_block status{};
        const long rc = okw::NtQueryDirectoryFile(h, nullptr, nullptr, nullptr, &status, buf, sizeof buf,
                                                  okw::file_directory_information_class, 0, nullptr, first ? 1 : 0);
        first = false;
        if (static_cast<unsigned long>(rc) == 0x80000006u) break;   // STATUS_NO_MORE_FILES
        if (!okw::ok(rc)) { answer = 0; break; }
        for (okw_uptr at = 0;;) {
            const auto* e = reinterpret_cast<const okw::file_directory_information*>(buf + at);
            const okw_uptr chars = e->file_name_length / 2;
            char name[1024];
            const okw_uptr n = okw::narrow(e->file_name, chars, name, sizeof name);
            const bool dot = (chars == 1 && e->file_name[0] == L'.')
                          || (chars == 2 && e->file_name[0] == L'.' && e->file_name[1] == L'.');
            if (!dot) {
                if (n == 0 || !ascii(name, n)) answer = 2;
                if (count >= r.budget) { answer = 0; more = false; break; }
                r.names.add(name_key(key, name, n), (e->file_attributes & FILE_ATTRIBUTE_DIRECTORY) ? kDirectory : kOther);
                ++count;
            }
            if (e->next_entry_offset == 0) break;
            at += e->next_entry_offset;
        }
    }
    okw::NtClose(h);
    if (answer == 0) return 0;
    r.budget -= count;
    r.listed.add(key, static_cast<unsigned char>(answer));
    return answer;
}

// A handle for the record of its own, opened to append: every write then lands
// at the end, whoever else holds the file, and the holder's position does not
// move.
void* reopen_to_append(void* record) {
    okw::unicode_string empty{ 0, 0, nullptr };
    okw::object_attributes attrs{};
    attrs.length = sizeof attrs;
    attrs.root_directory = record;
    attrs.object_name = &empty;
    okw::io_status_block status{};
    void* h = nullptr;
    const long rc = okw::NtCreateFile(&h, FILE_APPEND_DATA | SYNCHRONIZE, &attrs, &status, nullptr,
                                      FILE_ATTRIBUTE_NORMAL,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      okw::file_open,
                                      okw::file_non_directory_file | okw::file_synchronous_io_nonalert,
                                      nullptr, 0);
    return okw::ok(rc) ? h : nullptr;
}

void* duplicate(void* h) {
    void* out = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &out, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return nullptr;
    return out;
}

}  // namespace

okw_u32 of(void* h) {
    if (!g_any) return 0;
    held l;
    const entry* e = entry_of(h);
    return e ? e->flags : 0;
}

int attenuate(void* h, okw_u32 add, void* record, void** out) {
    void* nh = duplicate(h);
    if (!nh) return okw::translate_win32(GetLastError());
    void* rec = nullptr;
    if (add & recorded) {
        rec = reopen_to_append(record);
        if (!rec) { okw::NtClose(nh); return kal_err_invalid; }
    }
    held l;
    const entry* from = entry_of(h);
    entry* e = new_entry(nh);
    if (!e) { okw::NtClose(nh); if (rec) okw::NtClose(rec); return kal_err_no_memory; }
    const okw_u32 inherited = from ? from->flags : 0;
    // A NEW ROOT WHERE THERE IS SOMETHING NEW TO RECORD OR TO STATE; otherwise
    // the handle is the same tree with fewer rights.
    const bool new_tree = from == nullptr || (add & (recorded | unchanging)) != 0;
    if (new_tree) {
        const int ri = new_root();
        if (ri < 0) { drop_entry(e); okw::NtClose(nh); if (rec) okw::NtClose(rec); return kal_err_no_memory; }
        root& r = g_roots[ri];
        r.flags = inherited | add;
        r.refs = 1;
        r.base = duplicate(nh);
        r.record = rec;
        r.budget = (r.flags & unchanging) ? budget_for_preference() : 0;
        // A RECORD ALREADY KEPT FOR THE TREE GOES ON BEING KEPT, and its names
        // stay relative to the directory it is of.
        if (from && from->root >= 0 && !(add & recorded) && g_roots[from->root].record) {
            const root& f = g_roots[from->root];
            r.record = duplicate(f.record);
            r.flags |= recorded;
            char lead[4096];
            okw_uptr n = full_path(*from, "", 0, lead, sizeof lead, f.rprefix, f.rplen);
            if (n == 1 && lead[0] == '\0') n = 0;
            r.rprefix = static_cast<char*>(grab(n + 1));
            if (r.rprefix) { copy(r.rprefix, lead, n); r.rprefix[n] = '\0'; r.rplen = n; }
        }
        e->root = ri;
        e->prefix = static_cast<char*>(grab(1)); if (e->prefix) e->prefix[0] = '\0';
        e->plen = 0;
    } else {
        e->root = from->root;
        if (e->root >= 0) g_roots[e->root].refs++;
        e->prefix = static_cast<char*>(grab(from->plen + 1));
        if (e->prefix) { copy(e->prefix, from->prefix, from->plen); e->prefix[from->plen] = '\0'; }
        e->plen = e->prefix ? from->plen : 0;
    }
    e->flags = inherited | add;
    g_any = true;
    *out = nh;
    return kal_ok;
}

bool derive(void* parent, void* child, const char* name, okw_uptr len) {
    if (!g_any) return true;
    held l;
    const entry* p = entry_of(parent);
    if (!p) return true;
    entry* e = new_entry(child);
    if (!e) return false;
    e->flags = p->flags;
    e->root = p->root;
    if (e->root >= 0) g_roots[e->root].refs++;
    char buf[4096];
    const okw_uptr n = full_path(*p, name, len, buf, sizeof buf);
    const okw_uptr plen = (n == 1 && buf[0] == '\0') ? 0 : n;
    e->prefix = static_cast<char*>(grab(plen + 1));
    if (e->prefix) { copy(e->prefix, buf, plen); e->prefix[plen] = '\0'; }
    e->plen = e->prefix ? plen : 0;
    return true;
}

void forget(void* h) {
    if (!g_any) return;
    held l;
    entry* e = entry_of(h);
    if (!e) return;
    const int ri = e->root;
    drop_entry(e);
    if (ri >= 0 && --g_roots[ri].refs <= 0) {
        // The last handle of the tree: what it recorded is written now. The
        // root itself stays until the program ends, which writes its `e'.
        flush(g_roots[ri]);
        g_roots[ri].names.clear();
        g_roots[ri].listed.clear();
        if (g_roots[ri].base) { okw::NtClose(g_roots[ri].base); g_roots[ri].base = nullptr; }
    }
}

void note(void* h, char kind, const char* name, okw_uptr len) {
    if (!g_any) return;
    held l;
    const entry* e = entry_of(h);
    if (!e || e->root < 0 || !(e->flags & recorded)) return;
    root& r = g_roots[e->root];
    if (!r.record) return;
    char buf[4096];
    okw_uptr n = full_path(*e, name, len, buf, sizeof buf, r.rprefix, r.rplen);
    if (n == 0) return;
    if (n == 1 && buf[0] == '\0') { buf[0] = '.'; buf[1] = '\0'; }
    if (!r.seen.add(hash(buf, n, static_cast<okw_u64>(static_cast<unsigned char>(kind)) * 0x100000001b3ull), 1)) return;
    append(r, kind, buf, n);
}

bool known_absent(void* h, const char* name, okw_uptr len) {
    if (!g_any) return false;
    // A name another spelling could reach is asked of the system.
    for (okw_uptr i = 0; i < len; ++i)
        if (name[i] == '~' || static_cast<unsigned char>(name[i]) >= 0x80) return false;
    held l;
    const entry* e = entry_of(h);
    if (!e || e->root < 0 || !(e->flags & unchanging)) return false;
    root& r = g_roots[e->root];
    if (!r.base) return false;
    char path[4096];
    const okw_uptr n = full_path(*e, name, len, path, sizeof path);
    if (n == 0 || (n == 1 && path[0] == '\0')) return false;
    okw_uptr start = 0;
    okw_u64 dir = folded_hash("", 0);
    for (okw_uptr i = 0; i <= n; ++i) {
        if (i < n && path[i] != '/') continue;
        if (list(r, path, start == 0 ? 0 : start - 1, dir) != 1) return false;
        const int kind = r.names.find(name_key(dir, path + start, i - start));
        if (kind < 0) return true;
        if (i == n) return false;
        if (kind != kDirectory) return false;
        dir = folded_hash(path, i);
        start = i + 1;
    }
    return false;
}

void changed(void* h) {
    if (!g_any) return;
    held l;
    const entry* e = entry_of(h);
    if (!e || e->root < 0) return;
    root& r = g_roots[e->root];
    r.names.clear();
    r.listed.clear();
    if (r.flags & unchanging) r.budget = budget_for_preference();
}

bool conveyed(void* h, okw_u32* flags, void** record, const char** prefix, okw_uptr* prefix_len) {
    if (!g_any) return false;
    held l;
    const entry* e = entry_of(h);
    if (!e) return false;
    *flags = e->flags;
    *record = (e->root >= 0 && (e->flags & recorded)) ? g_roots[e->root].record : nullptr;
    static char lead[4096];
    okw_uptr n = 0;
    if (e->root >= 0) {
        const root& r = g_roots[e->root];
        n = full_path(*e, "", 0, lead, sizeof lead, r.rprefix, r.rplen);
        if (n == 1 && lead[0] == '\0') n = 0;
    }
    *prefix = lead;
    *prefix_len = n;
    return true;
}

void adopt(void* h, okw_u32 flags, void* record, const char* prefix, okw_uptr prefix_len) {
    held l;
    entry* e = new_entry(h);
    if (!e) return;
    const int ri = new_root();
    if (ri < 0) { drop_entry(e); return; }
    root& r = g_roots[ri];
    r.flags = flags;
    r.refs = 1;
    r.base = duplicate(h);
    if (record) {
        // Not inherited by the programs this one starts, as the grant itself
        // is not, unless it grants the handle on.
        SetHandleInformation(record, HANDLE_FLAG_INHERIT, 0);
        r.record = record;
    }
    r.budget = (flags & unchanging) ? budget_for_preference() : 0;
    r.rprefix = static_cast<char*>(grab(prefix_len + 1));
    if (r.rprefix) { copy(r.rprefix, prefix, prefix_len); r.rprefix[prefix_len] = '\0'; r.rplen = prefix_len; }
    e->root = ri;
    e->flags = flags;
    e->prefix = static_cast<char*>(grab(1));
    if (e->prefix) e->prefix[0] = '\0';
    e->plen = 0;
    g_any = true;
}

void end_of_program() {
    if (!g_any) return;
    static volatile long long ended = 0;
    if (okw::atomic::exchange(&ended, 1)) return;
    held l;
    for (auto& r : g_roots) {
        if (!r.live || !r.record) continue;
        if (!r.batch) r.batch = static_cast<char*>(grab(kBatch));
        if (r.batch) {
            if (r.batched + 2 > kBatch) flush(r);
            r.batch[r.batched++] = 'e';
            r.batch[r.batched++] = '\0';
        }
        flush(r);
    }
}

}  // namespace okw::rights

namespace {
// A program whose runtime ends it without kal_exit --- this system's own C
// runtime --- writes its records as that runtime runs its terminators.
OKW_END_FN(records_at_exit) { okw::rights::end_of_program(); }
OKW_AT_END(records_at_exit);
}  // namespace
