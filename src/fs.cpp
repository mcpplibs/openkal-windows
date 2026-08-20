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
// A hosted system does not confine an ordinary program, so it is supplied both
// the directory it was started in and the volume that directory is on. Each is
// reported under the name the environment knows it by, spelled the way openkal
// spells a name, because a C library above openkal must both resolve an
// absolute name and report one.
struct preopen { char name[okw::kMaxName]; okw_uptr len; okw_uptr handle; };

preopen* table(kal_uintptr* count) {
    static preopen t[2];
    static bool opened = false;
    if (!opened) {
        opened = true;
        wchar_t cwd[okw::kMaxName];
        const DWORD n = GetCurrentDirectoryW(okw::kMaxName, cwd);
        if (n > 0 && n < okw::kMaxName) {
            t[0].len = okw::narrow(cwd, n, t[0].name, sizeof t[0].name);
            void* h = CreateFileW(cwd, FILE_LIST_DIRECTORY | GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            t[0].handle = h == INVALID_HANDLE_VALUE ? 0 : okw::pack(h);

            // The volume, named the way this environment names it. A program
            // resolving an absolute name finds the longest supplied name that
            // is a prefix of it, so both are needed and neither is a root in
            // the sense another system would mean.
            if (n >= 3 && cwd[1] == L':') {
                wchar_t root[4] = { cwd[0], L':', L'\\', 0 };
                t[1].len = okw::narrow(root, 3, t[1].name, sizeof t[1].name);
                void* r = CreateFileW(root, FILE_LIST_DIRECTORY | GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING,
                                      FILE_FLAG_BACKUP_SEMANTICS, nullptr);
                t[1].handle = r == INVALID_HANDLE_VALUE ? 0 : okw::pack(r);
            }
        }
    }
    if (count) *count = t[1].handle ? 2u : 1u;
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

int fill(void* h, kal_node_info* out) {
    okw::io_status_block s{};
    okw::file_basic_information basic{};
    okw::file_standard_information standard{};
    long r = okw::NtQueryInformationFile(h, &s, &basic, sizeof basic,
                                         okw::file_basic_information_class);
    if (!okw::ok(r)) return okw::translate_nt(r);
    r = okw::NtQueryInformationFile(h, &s, &standard, sizeof standard,
                                    okw::file_standard_information_class);
    if (!okw::ok(r)) return okw::translate_nt(r);

    out->size = static_cast<kal_uintptr>(standard.end_of_file);
    out->modified_ns = to_nanoseconds(basic.last_write_time);
    out->kind = (basic.attributes & FILE_ATTRIBUTE_REPARSE_POINT) ? kal_node_link
              : (basic.attributes & FILE_ATTRIBUTE_DIRECTORY)     ? kal_node_directory
                                                                  : kal_node_file;
    out->writable = (basic.attributes & FILE_ATTRIBUTE_READONLY) ? 0 : 1;
    return kal_ok;
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
    unsigned char buffer[8192];
};

}  // namespace

extern "C" {

kal_uintptr kal_fs_preopen_count(void) { kal_uintptr n = 0; table(&n); return n; }

int kal_fs_preopen(kal_uintptr index, kal_dir* out, const char** name, kal_uintptr* len) {
    kal_uintptr n = 0;
    preopen* t = table(&n);
    if (index >= n || out == nullptr) return kal_err_invalid;
    if (t[index].handle == 0) return kal_err_permission;
    *out = kal_dir{ t[index].handle };
    if (name) *name = t[index].name;
    if (len)  *len  = t[index].len;
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

int kal_fs_open_file(kal_dir base, const char* name, kal_uintptr len,
                     int write, int create, kal_file* out) {
    kal_uintptr flags = KAL_OPEN_READ;
    if (write)  flags |= KAL_OPEN_WRITE;
    if (create) flags |= KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE;
    return kal_fs_open(base, name, len, flags, out);
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
kal_uintptr kal_fs_stream(kal_file f) {
    void* h = file_handle(f);
    return h ? reinterpret_cast<kal_uintptr>(h) : 0u;
}

int kal_fs_seek(kal_file f, __INT64_TYPE__ offset, int whence, __UINT64_TYPE__* result) {
    void* h = file_handle(f);
    if (!h) return kal_err_invalid;
    LARGE_INTEGER distance{}; distance.QuadPart = offset;
    LARGE_INTEGER arrived{};
    DWORD method = FILE_BEGIN;
    if (whence == KAL_SEEK_CURRENT) method = FILE_CURRENT;
    else if (whence == KAL_SEEK_END) method = FILE_END;
    if (!SetFilePointerEx(h, distance, &arrived, method))
        return okw::translate_win32(GetLastError());
    if (result) *result = static_cast<__UINT64_TYPE__>(arrived.QuadPart);
    return kal_ok;
}

int kal_fs_truncate(kal_file f, __UINT64_TYPE__ size) {
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

int kal_fs_info(kal_dir base, const char* name, kal_uintptr len, kal_node_info* out) {
    void* root = dir_handle(base);
    if (!root || out == nullptr || !okw::acceptable(name, len)) return kal_err_invalid;
    void* h = nullptr;
    const long r = open_relative(root, name, len, FILE_READ_ATTRIBUTES,
                                 okw::file_open, okw::file_open_for_backup_intent, &h);
    if (!okw::ok(r)) {
        // Clause 7.7: a name that does not exist is an answer, not a failure. A
        // caller that asks what a name refers to has been answered when told
        // that it refers to nothing.
        const int e = okw::translate_nt(r);
        if (e == kal_err_not_found || e == kal_err_not_directory) {
            *out = kal_node_info{ 0, 0, kal_node_absent, 0 };
            return kal_ok;
        }
        return e;
    }
    const int e = fill(h, out);
    okw::NtClose(h);
    return e;
}

int kal_fs_file_info(kal_file f, kal_node_info* out) {
    void* h = file_handle(f);
    if (!h || out == nullptr) return kal_err_invalid;
    return fill(h, out);
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

    // The renaming record carries the name inline, so it is built in a buffer
    // whose size is known at compile time and whose bound is the same bound
    // every name in this implementation has.
    static thread_local unsigned char storage[sizeof(okw::file_rename_information)
                                              + okw::kMaxName * sizeof(wchar_t)];
    auto* info = reinterpret_cast<okw::file_rename_information*>(storage);
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

int kal_fs_list_next(kal_dir, kal_uintptr* iter, const char** name,
                     kal_uintptr* len, int* kind) {
    if (iter == nullptr || *iter == 0) return kal_err_invalid;
    auto* s = reinterpret_cast<listing*>(*iter);
    static thread_local char reported[okw::kMaxName];

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
                if (name) *name = nullptr;
                if (len)  *len  = 0;
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

        const okw_uptr n = okw::narrow(e->file_name, chars, reported, sizeof reported);
        if (name) *name = reported;
        if (len)  *len  = n;
        if (kind) *kind = (e->file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) ? kal_node_link
                        : (e->file_attributes & FILE_ATTRIBUTE_DIRECTORY)     ? kal_node_directory
                                                                              : kal_node_file;
        return kal_ok;
    }
}

// Names on this system are compared without regard to case, and a program that
// created two names differing only in case would succeed on one implementation
// and not on this one. The position reports it in advance, which no operation
// could.
const kal_uintptr kal_fs_props =
    KAL_FS_PROP_MODIFIED_TIME | KAL_FS_PROP_ATOMIC_RENAME;

}
