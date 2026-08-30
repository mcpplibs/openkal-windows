#include "win.h"
#include "handle.h"
#include <openkal/fs.h>
#include <openkal/memory.h>
#include <openkal/time.h>

// Directories and open files.
//
// Every operation here is relative to a directory the program holds, which is
// what openkal declares and what Win32 does not offer. The object manager
// beneath Win32 does: NtCreateFile takes a root directory in its object
// attributes and a name relative to it, and refuses a name that leaves it.
//
// That is the whole reason this file is written one layer below the interface
// most programs on this system use. An implementation written on Win32 would
// have to recover each directory's path with GetFinalPathNameByHandleW and
// concatenate --- a name resolver inside an implementation, which clause 7.1
// excludes. There is nothing to resolve here.
//
// It is also the strongest evidence available that openkal's decomposition is
// not a Unix shape wearing a different name. This environment has no common
// ancestry with the systems the interface was drawn against, and the operation
// it offers is the same operation.

namespace {


constexpr okw_u64 kEpochDifference = 116444736000000000ull;

kal_duration to_nanoseconds(okw_i64 ticks) {
    const okw_u64 t = static_cast<okw_u64>(ticks);
    return t < kEpochDifference ? 0u : (t - kEpochDifference) * 100ull;
}

// The supplied directories.
//
// A hosted system does not confine an ordinary program, so it is supplied the
// directory it was started in and every volume the system has. Each is reported
// under the name the environment knows it by, spelled the way openkal spells a
// name, because a C library above openkal must both resolve an absolute name
// and report one.
//
// Every volume, and not only the one the working directory is on. This system
// has no single root: a name on one volume is not beneath a name on another,
// and a program supplied only its own volume cannot reach a program installed
// elsewhere --- which is not a confinement anybody chose, and which the other
// two systems, having one root, do not impose. What made it visible was a
// program on one volume failing to start a program on another, reported four
// operations later as "no such file".
struct preopen { char name[okw::kMaxName]; okw_uptr len; okw_uptr handle; };

constexpr kal_uintptr kMaxPreopens = 27;   // the working directory, and 26 volumes

preopen* table(kal_uintptr* count) {
    static preopen t[kMaxPreopens];
    static kal_uintptr used = 0;
    static bool opened = false;
    if (!opened) {
        opened = true;

        // Opened by the whole name this environment uses, and reported by as
        // much of it as openkal's naming wants: a volume is opened as "X:\\"
        // and reported as "X:", so that the remainder of an absolute name
        // beneath it does not begin with a separator.
        const auto add = [](preopen& slot, const wchar_t* open_by, DWORD report) {
            void* h = CreateFileW(open_by, FILE_LIST_DIRECTORY | GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (h == INVALID_HANDLE_VALUE) return false;
            slot.len = okw::narrow(open_by, report, slot.name, sizeof slot.name);
            slot.handle = okw::pack(h);
            return true;
        };

        wchar_t cwd[okw::kMaxName];
        const DWORD n = GetCurrentDirectoryW(okw::kMaxName, cwd);
        if (n > 0 && n < okw::kMaxName && add(t[used], cwd, n)) ++used;

        // The volumes, in the form this environment reports them: a run of
        // strings, each terminated, the run terminated again.
        wchar_t volumes[512];
        const DWORD v = GetLogicalDriveStringsW(512, volumes);
        if (v > 0 && v < 512) {
            for (const wchar_t* p = volumes; *p && used < kMaxPreopens; ) {
                DWORD length = 0;
                while (p[length]) ++length;
                // Reported as "X:\" and named here without the separator, so
                // that a program resolving an absolute name finds the longest
                // supplied name that is a prefix of it and the remainder does
                // not begin with one.
                const DWORD keep = (length >= 3 && p[length - 1] == L'\\') ? length - 1 : length;
                if (add(t[used], p, keep)) ++used;
                p += length + 1;
            }
        }
    }
    if (count) *count = used;
    return t;
}

void* dir_handle(kal_dir d) { return okw::unpack(d.h); }
void* file_handle(kal_file f) { return okw::unpack(f.h); }

// One opening operation, since the object manager has one.
long open_relative(void* root, const char* name, kal_uintptr len,
                   unsigned long access, unsigned long disposition,
                   unsigned long options, void** out) {
    okw::wide_name w(name, len);
    if (!w.ok) return static_cast<long>(0xC0000106);   // STATUS_NAME_TOO_LONG
    okw::object_attributes attrs{};
    attrs.length = sizeof attrs;
    attrs.root_directory = root;
    attrs.object_name = &w.string;
    attrs.attributes = okw::obj_case_insensitive;
    okw::io_status_block status{};
    return okw::NtCreateFile(out, access | SYNCHRONIZE, &attrs, &status, nullptr,
                             FILE_ATTRIBUTE_NORMAL,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             disposition, options | okw::file_synchronous_io_nonalert,
                             nullptr, 0);
}

// The caller must state how much of the structure exists on its side.
bool info_ok(const kal_node_info* out) {
    return out != nullptr && out->self_size >= sizeof(kal_u32) * 2;
}

void put_bytes(void* dst, const void* src, kal_uintptr n) {
    auto* d = static_cast<unsigned char*>(dst);
    const auto* s = static_cast<const unsigned char*>(src);
    for (kal_uintptr i = 0; i < n; ++i) d[i] = s[i];
}

// Copies a name into a caller's buffer and reports the length it HAS.
kal_uintptr put_name(const char* src, kal_uintptr n,
                     char* out, kal_uintptr cap, kal_uintptr* len) {
    if (out != nullptr && cap != 0) put_bytes(out, src, n < cap ? n : cap);
    if (len) *len = n;
    return n;
}

// Writes no more of the structure than the caller says exists on its side, and
// reports which fields it filled.
int fill(void* h, kal_u32 wanted, kal_node_info* out) {
    (void)wanted;
    okw::io_status_block s{};
    okw::file_basic_information basic{};
    okw::file_standard_information standard{};
    long r = okw::NtQueryInformationFile(h, &s, &basic, sizeof basic,
                                         okw::file_basic_information_class);
    if (!okw::ok(r)) return okw::translate_nt(r);
    r = okw::NtQueryInformationFile(h, &s, &standard, sizeof standard,
                                    okw::file_standard_information_class);
    if (!okw::ok(r)) return okw::translate_nt(r);

    const kal_u32 self = out->self_size;
    kal_node_info v{};
    v.self_size   = self;
    v.present     = KAL_INFO_KIND | KAL_INFO_SIZE | KAL_INFO_MODIFIED
                  | KAL_INFO_WRITABLE;
    v.size        = static_cast<kal_u64>(standard.end_of_file);
    v.modified_ns = to_nanoseconds(basic.last_write_time);
    v.kind = (basic.attributes & FILE_ATTRIBUTE_REPARSE_POINT) ? kal_node_link
           : (basic.attributes & FILE_ATTRIBUTE_DIRECTORY)     ? kal_node_directory
                                                               : kal_node_file;
    v.writable = (basic.attributes & FILE_ATTRIBUTE_READONLY) ? 0 : 1;

    // ⭐ THE IDENTITY IS TWO WORDS BECAUSE ONE IS NOT ENOUGH, AND THIS
    // ENVIRONMENT SAYS SO ITSELF: the index it keeps for a file is unique
    // WITHIN A VOLUME, so two files on two volumes can share one. The volume's
    // serial number is the other word. Where either enquiry is refused --- a
    // handle to something that is not on a volume --- the position is left
    // clear and a caller is told that this is not known, rather than being told
    // that two different nodes are the same.
    // ⚠️⚠️ THE VOLUME ENQUIRY REPORTS AN OVERFLOW AND ANSWERS ANYWAY, AND
    // TREATING THE OVERFLOW AS A FAILURE THREW THE ANSWER AWAY.
    //
    // FILE_FS_VOLUME_INFORMATION ends in the volume's LABEL, which is as long
    // as the label is. A buffer holding the fixed part and one character of it
    // is enough for every field this reads --- the serial number precedes the
    // label --- and the object manager still reports STATUS_BUFFER_OVERFLOW,
    // because the label did not fit. That value is 0x80000005: negative, so
    // `okw::ok' said no, so the position was left clear.
    //
    // ⭐ WHICH IS A CORRECT REPORT OF SOMETHING THAT WAS NOT TRUE. The
    // implementation was saying "this node's identity is not known here", a
    // caller was believing it, and the identity was sitting in the buffer. It
    // surfaced two packages away, in openkal-musl's probe: `two different files
    // have different identities' did not hold on Windows, because both had been
    // given the zero this branch leaves behind.
    //
    // Room for a label is given so the ordinary case SUCCEEDS, and the overflow
    // is accepted so the extraordinary one still answers. Both are checked
    // rather than one, because a label longer than this is a volume nobody
    // tests with and the buffer would be back to reporting an overflow.
    struct {
        okw::file_fs_volume_information info;
        wchar_t label_tail[128];
    } volume{};
    okw::file_internal_information index{};
    const long ri = okw::NtQueryInformationFile(h, &s, &index, sizeof index,
                                                okw::file_internal_information_class);
    const long rv = okw::NtQueryVolumeInformationFile(h, &s, &volume, sizeof volume,
                                                      okw::fs_volume_information_class);
    if (okw::ok(ri) && (okw::ok(rv) || rv == okw::status_buffer_overflow)) {
        v.identity[0] = static_cast<kal_u64>(volume.info.serial_number);
        v.identity[1] = static_cast<kal_u64>(index.index_number);
        v.present |= KAL_INFO_IDENTITY;
    }

    const kal_u32 n = self < sizeof v ? self : (kal_u32)sizeof v;
    put_bytes(out, &v, n);
    return kal_ok;
}

void fill_absent(kal_node_info* out) {
    const kal_u32 self = out->self_size;
    kal_node_info v{};
    v.self_size = self;
    v.present   = KAL_INFO_KIND;
    v.kind      = kal_node_absent;
    const kal_u32 n = self < sizeof v ? self : (kal_u32)sizeof v;
    put_bytes(out, &v, n);
}

// Enumeration holds a buffer and a handle of its own, obtained by opening the
// directory through itself: an enumeration that shared the caller's handle
// would share its position, and two enumerations of one directory would consume
// each other's entries.
struct listing {
    void*    handle;
    okw_uptr used;
    okw_uptr at;
    bool     first;
    // Aligned deliberately. The records this environment writes here begin with
    // fields it reads as machine words, and it requires the buffer they are
    // written into to be aligned for them. Placed after three words and a
    // boolean, an array of bytes lands one past a word boundary, and the
    // enumeration then reports nothing at all --- while an implementation of
    // this environment's interfaces that does not check accepts it and returns
    // the entries, which is the harder way to find this.
    alignas(16) unsigned char buffer[8192];
    // The name reported to the caller. It belongs to the enumeration rather
    // than to the context performing it: two contexts enumerating two
    // directories would otherwise share one buffer, and openkal requires that
    // concurrent operations upon distinct handles be permitted.
    char     reported[512];
};

}  // namespace

extern "C" {

kal_uintptr kal_fs_preopen_count(void) { kal_uintptr n = 0; table(&n); return n; }

int kal_fs_preopen(kal_uintptr index, kal_dir* out,
                   char* name_out, kal_uintptr name_cap, kal_uintptr* name_len) {
    kal_uintptr n = 0;
    preopen* t = table(&n);
    if (index >= n || out == nullptr) return kal_err_invalid;
    if (t[index].handle == 0) return kal_err_permission;
    *out = kal_dir{ t[index].handle };
    put_name(t[index].name, t[index].len, name_out, name_cap, name_len);
    return kal_ok;
}

int kal_fs_open_dir(kal_dir base, const char* name, kal_uintptr len, kal_dir* out) {
    void* root = dir_handle(base);
    if (!root || out == nullptr || !okw::acceptable(name, len)) return kal_err_invalid;
    void* h = nullptr;
    const long r = open_relative(root, name, len, FILE_LIST_DIRECTORY | GENERIC_READ,
                                 okw::file_open, okw::file_directory_file, &h);
    if (!okw::ok(r)) return okw::translate_nt(r);
    *out = kal_dir{ okw::pack(h) };
    return kal_ok;
}

int kal_fs_open(kal_dir base, const char* name, kal_uintptr len,
                kal_uintptr flags, kal_file* out) {
    void* root = dir_handle(base);
    if (!root || out == nullptr || !okw::acceptable(name, len)) return kal_err_invalid;

    unsigned long access = 0;
    if (flags & KAL_OPEN_READ)  access |= FILE_GENERIC_READ;
    if (flags & KAL_OPEN_WRITE) access |= FILE_GENERIC_WRITE;
    if (flags & KAL_OPEN_APPEND) {
        // Appending is granted rather than arranged. A caller that positioned
        // itself and then wrote would otherwise overwrite, and a caller that
        // shared the file with another writer would overwrite that one's work;
        // the object manager appends every transfer when this is the access
        // granted, which is the property the flag names.
        access &= ~static_cast<unsigned long>(FILE_WRITE_DATA);
        access |= FILE_APPEND_DATA;
    }
    if (access == 0) access = FILE_GENERIC_READ;

    // The whole of the intent, expressed once. Clause 7.8: an open followed by
    // a truncation is two operations, and a program that stopped between them
    // would leave the tail of a longer previous contents behind.
    unsigned long disposition;
    const bool create   = (flags & KAL_OPEN_CREATE)    != 0;
    const bool exclusive= (flags & KAL_OPEN_EXCLUSIVE) != 0;
    const bool truncate = (flags & KAL_OPEN_TRUNCATE)  != 0;
    if (create && exclusive)  disposition = okw::file_create;
    else if (create && truncate) disposition = okw::file_overwrite_if;
    else if (create)          disposition = okw::file_open_if;
    else if (truncate)        disposition = okw::file_overwrite;
    else                      disposition = okw::file_open;

    void* h = nullptr;
    const long r = open_relative(root, name, len, access, disposition,
                                 okw::file_non_directory_file, &h);
    if (!okw::ok(r)) return okw::translate_nt(r);
    *out = kal_file{ okw::pack(h) };
    return kal_ok;
}

void kal_fs_close_dir(kal_dir d) {
    void* h = dir_handle(d);
    if (h) { okw::retire(d.h); okw::NtClose(h); }
}

void kal_fs_close_file(kal_file f) {
    void* h = file_handle(f);
    if (h) { okw::retire(f.h); okw::NtClose(h); }
}

// A file's stream is the file. The environment's handle is what openkal.stream
// holds here, so no conversion is required and none is performed --- which is a
// property of this implementation rather than of the specification.
kal_stream kal_fs_stream(kal_file f) {
    void* h = file_handle(f);
    return kal_stream{ h ? reinterpret_cast<kal_uintptr>(h) : 0u };
}

// The greatest length of a name this implementation accepts.
kal_uintptr kal_fs_max_name(void) { return okw::kMaxName - 1; }

int kal_fs_seek(kal_file f, kal_i64 offset, int whence, kal_u64* result) {
    void* h = file_handle(f);
    if (!h) return kal_err_invalid;
    LARGE_INTEGER distance{}; distance.QuadPart = offset;
    LARGE_INTEGER arrived{};
    DWORD method = FILE_BEGIN;
    if (whence == KAL_SEEK_CURRENT) method = FILE_CURRENT;
    else if (whence == KAL_SEEK_END) method = FILE_END;
    if (!SetFilePointerEx(h, distance, &arrived, method))
        return okw::translate_win32(GetLastError());
    if (result) *result = static_cast<kal_u64>(arrived.QuadPart);
    return kal_ok;
}

int kal_fs_truncate(kal_file f, kal_u64 size) {
    void* h = file_handle(f);
    if (!h) return kal_err_invalid;
    okw::io_status_block s{};
    okw::file_end_of_file_information info{ static_cast<okw_i64>(size) };
    // Through the object manager rather than through SetEndOfFile, which sets
    // the length to wherever the caller last positioned itself and would
    // therefore move a position the caller did not ask to move.
    const long r = okw::NtSetInformationFile(h, &s, &info, sizeof info,
                                             okw::file_end_of_file_information_class);
    return okw::ok(r) ? kal_ok : okw::translate_nt(r);
}

int kal_fs_info(kal_dir base, const char* name, kal_uintptr len,
                kal_uintptr flags, kal_u32 wanted, kal_node_info* out) {
    void* root = dir_handle(base);
    if (!root || !info_ok(out) || !okw::acceptable(name, len)) return kal_err_invalid;
    void* h = nullptr;
    // RESOLVES BY DEFAULT, SO THAT ASKING AND OPENING ANSWER THE SAME QUESTION.
    // Without FILE_OPEN_REPARSE_POINT this environment follows the node to what
    // it finally refers to, which is what `kal_fs_open' does; with it, the node
    // itself is opened and reported.
    const unsigned long options = okw::file_open_for_backup_intent
        | ((flags & KAL_FS_NO_RESOLVE) ? okw::file_open_reparse_point : 0u);
    const long r = open_relative(root, name, len, FILE_READ_ATTRIBUTES,
                                 okw::file_open, options, &h);
    if (!okw::ok(r)) {
        // Clause 7.7: a name that does not exist is an answer, not a failure. A
        // caller that asks what a name refers to has been answered when told
        // that it refers to nothing --- and so is a node whose content names
        // something absent, when the enquiry resolves.
        const int e = okw::translate_nt(r);
        if (e == kal_err_not_found || e == kal_err_not_directory) {
            fill_absent(out);
            return kal_ok;
        }
        return e;
    }
    const int e = fill(h, wanted, out);
    okw::NtClose(h);
    return e;
}

int kal_fs_file_info(kal_file f, kal_u32 wanted, kal_node_info* out) {
    void* h = file_handle(f);
    if (!h || !info_ok(out)) return kal_err_invalid;
    return fill(h, wanted, out);
}

int kal_fs_set_modified(kal_file f, kal_u64 modified_ns) {
    void* h = file_handle(f);
    if (!h) return kal_err_invalid;
    okw::file_basic_information basic{};
    // Every field of this record is a time, and this environment reads a zero
    // as "leave that one alone". So one field is written and the record says
    // nothing about the other three, which is what the interface asked for.
    basic.last_write_time =
        static_cast<okw_i64>(modified_ns / 100ull + kEpochDifference);
    okw::io_status_block iosb{};
    const long r = okw::NtSetInformationFile(h, &iosb, &basic, sizeof basic,
                                             okw::file_basic_information_class);
    return okw::ok(r) ? kal_ok : okw::translate_nt(r);
}

// The modification time of a NAME, including a directory. Version 0.10.
//
// ⚠️ AND THE OPEN IS NOT `kal_fs_open''S. That one names `FILE_NON_DIRECTORY_FILE'
// --- correctly, since it opens a FILE --- and a directory is exactly what this
// declaration exists to reach. Opening for the attribute alone also means a
// caller need not be able to write the contents to stamp them, which is what
// `utimensat' means everywhere else.
int kal_fs_set_modified_at(kal_dir base, const char* name, kal_uintptr len,
                           kal_u64 modified_ns) {
    void* root = dir_handle(base);
    if (!root || !okw::acceptable(name, len)) return kal_err_invalid;

    void* h = nullptr;
    const long r = open_relative(root, name, len, FILE_WRITE_ATTRIBUTES,
                                 okw::file_open,
                                 okw::file_open_for_backup_intent, &h);
    if (!okw::ok(r)) return okw::translate_nt(r);

    okw::file_basic_information basic{};
    basic.last_write_time =
        static_cast<okw_i64>(modified_ns / 100ull + kEpochDifference);
    okw::io_status_block iosb{};
    const long w = okw::NtSetInformationFile(h, &iosb, &basic, sizeof basic,
                                             okw::file_basic_information_class);
    okw::NtClose(h);
    return okw::ok(w) ? kal_ok : okw::translate_nt(w);
}

// --- exclusion upon a range of a file ---------------------------------------
//
// ⭐ THIS SYSTEM EXCLUDES PER HANDLE, WHICH IS WHAT openkal STATES. The other
// two kernels carry an older form held by the PROCESS and have to reach past it;
// here there is nothing to reach past.
//
// ⚠️ AND THIS SYSTEM'S EXCLUSION IS MANDATORY RATHER THAN ADVISORY: a write that
// crosses a locked range is refused by the system, where elsewhere it is refused
// only to a program that asked. That is a difference a caller can observe, and
// it is the environment's own; nothing here can or should simulate the weaker
// one.
static int lock_range(kal_file f, kal_u64 start, kal_u64 len,
                      bool exclusive, bool wait, bool release) {
    void* h = file_handle(f);
    if (!h) return kal_err_invalid;

    okw_i64 offset = static_cast<okw_i64>(start);
    // openkal spells "to the end, however far that comes to be" as zero; this
    // system has no such spelling and takes a count, so the largest one stands
    // for it --- which is what every C library on this system does for the same
    // reason.
    okw_i64 length = len ? static_cast<okw_i64>(len)
                         : static_cast<okw_i64>(0x7fffffffffffffffll);

    okw::io_status_block iosb{};
    const long r = release
        ? okw::NtUnlockFile(h, &iosb, &offset, &length, 0)
        : okw::NtLockFile(h, nullptr, nullptr, nullptr, &iosb, &offset, &length,
                          0, static_cast<unsigned char>(wait ? 0 : 1),
                          static_cast<unsigned char>(exclusive ? 1 : 0));
    return okw::ok(r) ? kal_ok : okw::translate_nt(r);
}

int kal_fs_lock(kal_file f, kal_u64 start, kal_u64 len, kal_uintptr mode) {
    const bool shared    = (mode & KAL_LOCK_SHARED)    != 0;
    const bool exclusive = (mode & KAL_LOCK_EXCLUSIVE) != 0;
    if (shared == exclusive) return kal_err_invalid;
    return lock_range(f, start, len, exclusive, (mode & KAL_LOCK_WAIT) != 0, false);
}

int kal_fs_unlock(kal_file f, kal_u64 start, kal_u64 len) {
    return lock_range(f, start, len, false, false, true);
}

// How much the volume holds, in bytes.
//
// ⚠️ `available' AND NOT `total free'. This system reports the units this
// CALLER may use, which is the question openkal asks; a quota makes the two
// differ and the larger of them is not an answer a program can act upon.
int kal_fs_capacity(kal_dir d, kal_u64* total, kal_u64* available) {
    void* h = dir_handle(d);
    if (!h) return kal_err_invalid;

    okw::io_status_block s{};
    okw::file_fs_size_information info{};
    const long r = okw::NtQueryVolumeInformationFile(h, &s, &info, sizeof info,
                                                     okw::fs_size_information_class);
    if (!okw::ok(r)) return okw::translate_nt(r);

    const kal_u64 unit = static_cast<kal_u64>(info.sectors_per_unit)
                       * static_cast<kal_u64>(info.bytes_per_sector);
    if (total)     *total     = static_cast<kal_u64>(info.total_allocation_units) * unit;
    if (available) *available = static_cast<kal_u64>(info.available_allocation_units) * unit;
    return kal_ok;
}

int kal_fs_mkdir(kal_dir base, const char* name, kal_uintptr len) {
    void* root = dir_handle(base);
    if (!root || !okw::acceptable(name, len)) return kal_err_invalid;
    void* h = nullptr;
    const long r = open_relative(root, name, len, FILE_LIST_DIRECTORY,
                                 okw::file_create, okw::file_directory_file, &h);
    if (!okw::ok(r)) return okw::translate_nt(r);
    okw::NtClose(h);
    return kal_ok;
}

int kal_fs_remove(kal_dir base, const char* name, kal_uintptr len) {
    void* root = dir_handle(base);
    if (!root || !okw::acceptable(name, len)) return kal_err_invalid;
    void* h = nullptr;
    // One operation removes a name, and this environment distinguishes two
    // kinds of name where the interface does not, so neither kind is asked for.
    const long r = open_relative(root, name, len, DELETE, okw::file_open,
                                 okw::file_open_for_backup_intent, &h);
    if (!okw::ok(r)) return okw::translate_nt(r);
    okw::io_status_block s{};
    okw::file_disposition_information info{ 1 };
    const long d = okw::NtSetInformationFile(h, &s, &info, sizeof info,
                                             okw::file_disposition_information_class);
    okw::NtClose(h);
    return okw::ok(d) ? kal_ok : okw::translate_nt(d);
}

int kal_fs_rename(kal_dir from, const char* a, kal_uintptr alen,
                  kal_dir to, const char* b, kal_uintptr blen) {
    void* source_root = dir_handle(from);
    void* target_root = dir_handle(to);
    if (!source_root || !target_root) return kal_err_invalid;
    if (!okw::acceptable(a, alen) || !okw::acceptable(b, blen)) return kal_err_invalid;

    void* h = nullptr;
    const long r = open_relative(source_root, a, alen, DELETE | SYNCHRONIZE,
                                 okw::file_open, okw::file_open_for_backup_intent, &h);
    if (!okw::ok(r)) return okw::translate_nt(r);

    okw::wide_name w(b, blen);
    if (!w.ok) { okw::NtClose(h); return kal_err_invalid; }

    // The renaming record carries the name inline. It is obtained rather than
    // kept in static storage, because static storage shared between execution
    // contexts would make two concurrent renames one.
    const kal_uintptr storage_bytes = sizeof(okw::file_rename_information)
                                    + okw::kMaxName * sizeof(wchar_t);
    auto* info = static_cast<okw::file_rename_information*>(
        kal_alloc(storage_bytes, alignof(okw::file_rename_information)));
    if (!info) { okw::NtClose(h); return kal_err_no_memory; }
    info->replace_if_exists = 1;
    info->root_directory = target_root;
    info->file_name_length = w.string.length;
    for (unsigned i = 0; i < w.string.length / 2; ++i) info->file_name[i] = w.buffer[i];

    okw::io_status_block s{};
    const long n = okw::NtSetInformationFile(
        h, &s, info, static_cast<unsigned long>(sizeof(okw::file_rename_information)
                                                + w.string.length),
        okw::file_rename_information_class);
    okw::NtClose(h);
    kal_free(info, storage_bytes, alignof(okw::file_rename_information));
    return okw::ok(n) ? kal_ok : okw::translate_nt(n);
}

int kal_fs_list_begin(kal_dir d, kal_uintptr* iter) {
    void* root = dir_handle(d);
    if (!root || iter == nullptr) return kal_err_invalid;
    void* own = nullptr;
    okw::wide_name empty("", 0);
    okw::object_attributes attrs{};
    attrs.length = sizeof attrs;
    attrs.root_directory = root;
    attrs.object_name = &empty.string;
    attrs.attributes = okw::obj_case_insensitive;
    okw::io_status_block status{};
    const long r = okw::NtCreateFile(&own, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attrs, &status,
                                     nullptr, FILE_ATTRIBUTE_NORMAL,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                     okw::file_open,
                                     okw::file_directory_file | okw::file_synchronous_io_nonalert,
                                     nullptr, 0);
    if (!okw::ok(r)) return okw::translate_nt(r);

    auto* s = static_cast<listing*>(kal_alloc(sizeof(listing), alignof(listing)));
    if (!s) { okw::NtClose(own); return kal_err_no_memory; }
    s->handle = own; s->used = 0; s->at = 0; s->first = true;
    *iter = reinterpret_cast<kal_uintptr>(s);
    return kal_ok;
}

int kal_fs_list_next(kal_dir, kal_uintptr* iter,
                     char* name_out, kal_uintptr name_cap,
                     kal_uintptr* name_len, int* kind) {
    if (iter == nullptr || *iter == 0) return kal_err_invalid;
    auto* s = reinterpret_cast<listing*>(*iter);

    for (;;) {
        if (s->at >= s->used) {
            okw::io_status_block status{};
            const long r = okw::NtQueryDirectoryFile(
                s->handle, nullptr, nullptr, nullptr, &status,
                s->buffer, static_cast<unsigned long>(sizeof s->buffer),
                okw::file_directory_information_class, 0, nullptr, s->first ? 1 : 0);
            s->first = false;
            if (!okw::ok(r)) {
                okw::NtClose(s->handle);
                kal_free(s, sizeof(listing), alignof(listing));
                *iter = 0;
                if (name_len) *name_len = 0;
                // The end of a directory is reported here as a distinct status
                // and is the ordinary outcome, not a failure.
                return (static_cast<unsigned long>(r) == 0x80000006u) ? kal_ok
                                                                      : okw::translate_nt(r);
            }
            s->used = status.information ? status.information : sizeof s->buffer;
            s->at = 0;
        }

        auto* e = reinterpret_cast<okw::file_directory_information*>(s->buffer + s->at);
        const okw_uptr step = e->next_entry_offset ? e->next_entry_offset
                                                   : (s->used - s->at);
        s->at += step;
        if (e->next_entry_offset == 0) s->used = s->at;   // the batch is spent

        const okw_uptr chars = e->file_name_length / 2;
        // The two entries that name the directory and its parent are omitted.
        // They exist to support ascent, which this interface does not offer.
        if (chars == 1 && e->file_name[0] == L'.') continue;
        if (chars == 2 && e->file_name[0] == L'.' && e->file_name[1] == L'.') continue;

        const okw_uptr n = okw::narrow(e->file_name, chars, s->reported, sizeof s->reported);
        put_name(s->reported, n, name_out, name_cap, name_len);
        if (kind) *kind = (e->file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) ? kal_node_link
                        : (e->file_attributes & FILE_ATTRIBUTE_DIRECTORY)     ? kal_node_directory
                                                                              : kal_node_file;
        return kal_ok;
    }
}

// The properties of the volume a directory is on.
//
// AN ENQUIRY TAKING THE RESOURCE, BECAUSE EVERY POSITION IS A PROPERTY OF THE
// FORMAT. This environment reports the volume's abilities itself, so nothing is
// guessed: names on the volume this system is ordinarily installed on are
// compared without regard to case, and a volume attached to the same machine
// may be otherwise --- and a word per implementation could state neither.
// Whether the environment beneath actually performs a lock.
//
// ⚠️ ASKED ON A DIRECTORY, WHICH IS NOT A THING THIS SYSTEM LOCKS --- and that is
// what makes the question answerable without disturbing anything. A system that
// implements the operation refuses a directory as a wrong request; one that has
// not implemented it says so with a different value, and that difference is the
// whole of the enquiry. Nothing is locked either way.
//
// Answered once. It is a property of what is beneath this program rather than of
// a volume, so it does not vary between the directories one program holds.
static bool locking_available() {
    static int cached = -1;
    if (cached >= 0) return cached != 0;
    const kal_uintptr count = kal_fs_preopen_count();
    cached = 1;
    if (count > 0) {
        kal_dir probe{};
        char name[8]; kal_uintptr len = 0;
        if (kal_fs_preopen(0, &probe, name, sizeof name, &len) == kal_ok) {
            void* h = dir_handle(probe);
            if (h) {
                okw::io_status_block iosb{};
                okw_i64 off = 0, len2 = 1;
                const long r = okw::NtLockFile(h, nullptr, nullptr, nullptr, &iosb,
                                               &off, &len2, 0, 1, 1);
                if (okw::ok(r)) okw::NtUnlockFile(h, &iosb, &off, &len2, 0);
                else if (r == okw::status_not_implemented) cached = 0;
            }
        }
    }
    return cached != 0;
}

kal_uintptr kal_fs_props(kal_dir d) {
    void* h = dir_handle(d);
    // ⚠️⚠️ LOCKING IS ASKED ABOUT RATHER THAN ASSUMED, AND THE REASON IS NOT
    // THE VOLUME.
    //
    // This system locks a byte range, and the three continuous-integration rows
    // that run on it measure that it does. A FOURTH row cross-builds and runs
    // the result under an emulator of this system --- which EXPORTS the call and
    // answers `STATUS_NOT_IMPLEMENTED' when it is made.
    //
    // ⭐ So the property is not a property of the volume here, nor of the
    // format: it is a property of what is beneath the program at the moment it
    // asks. A word that claimed the position regardless would be describing the
    // INTERFACE rather than the environment --- and the whole purpose of a
    // capability word is that a caller may ask before it calls and be told the
    // truth about where it is.
    const kal_uintptr lockable = locking_available() ? KAL_FS_PROP_LOCKS : 0;
    const kal_uintptr conservative =
        KAL_FS_PROP_MODIFIED_TIME | KAL_FS_PROP_ATOMIC_RENAME
        | lockable | KAL_FS_PROP_CAPACITY;
    if (!h) return 0;

    okw::io_status_block s{};
    struct { okw::file_fs_attribute_information info; wchar_t rest[64]; } a{};
    const long r = okw::NtQueryVolumeInformationFile(h, &s, &a, sizeof a,
                                                     okw::fs_attribute_information_class);
    if (!okw::ok(r)) return conservative;

    kal_uintptr p = conservative;
    if (a.info.attributes & okw::fs_case_sensitive_search) p |= KAL_FS_PROP_CASE_SENSITIVE;

    // ⚠️ LINKS ARE REPORTED AND ARE NOT MADE, AND THE ASYMMETRY IS THIS
    // IMPLEMENTATION'S RATHER THAN THE SPECIFICATION'S.
    //
    // A volume that supports reparse points holds nodes whose content is
    // another name, and `kal_fs_info' reports one when it meets it --- so the
    // position for meeting them is claimed. Creating one on this system
    // requires a privilege an ordinary program does not hold, or the developer
    // mode of the system; and reading one requires a control code this
    // implementation does not yet issue. Neither is claimed, so a caller asks
    // and is told before it tries, which is what the enquiry is for.
    if (a.info.attributes & okw::fs_supports_reparse_points) p |= KAL_FS_PROP_LINKS;
    return p;
}

// Nodes whose content is another name.
//
// Refused, and the enquiry above says so in advance. Creating one on this
// system requires SeCreateSymbolicLinkPrivilege or the system's developer mode,
// and reading one requires a file-system control code this implementation does
// not issue. A caller reads KAL_FS_PROP_MAKE_LINKS --- which is not claimed
// here --- rather than discovering it by the attempt.
int kal_fs_link_create(kal_dir, const char*, kal_uintptr,
                       const char*, kal_uintptr, kal_uintptr) {
    return kal_err_not_supported;
}

kal_intptr kal_fs_link_read(kal_dir, const char*, kal_uintptr,
                            char*, kal_uintptr) {
    return -kal_err_not_supported;
}

}
