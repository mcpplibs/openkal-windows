// What this environment offers, and the translation onto what openkal defines.
//
// openkal is a contract and says nothing about what else a program contains.
// An implementation is selected by the program, and the program may itself
// supply the facilities the implementation would otherwise borrow; if it does,
// and the names agree, the implementation's calls resolve to the program's and
// the program's resolve back to the implementation. This implementation
// therefore uses the environment's own interfaces --- Win32 and the object
// manager beneath it --- and no C runtime symbol at all. CI asserts that
// against the objects.
//
// The interesting half of this file is naming.
//
// openkal has no global namespace of paths: every operation is relative to a
// directory the program holds. That decomposition was chosen because a global
// namespace is unavailable in a capability-based kernel and an implementation
// upon one would have to construct it. Windows is the case that shows the
// choice was not merely a concession to such kernels: Win32 has no operation
// that opens a name relative to a directory handle, but the object manager it
// is built upon does --- NtCreateFile takes a root directory in its object
// attributes, and that is exactly the shape openkal asks for.
//
// An implementation written on Win32 alone would have to recover each
// directory's path with GetFinalPathNameByHandleW and concatenate, which is a
// name resolver in an implementation and is what clause 7.1 excludes. Written
// one layer down, there is nothing to resolve.
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

using okw_uptr = __UINTPTR_TYPE__;
using okw_u64  = unsigned long long;
using okw_i64  = long long;
using okw_u32  = unsigned int;

namespace okw {

// --- the object manager ------------------------------------------------------
//
// Declared here rather than taken from <winternl.h>: the header is present in
// one toolchain's sources and partial in another's, and an implementation that
// compiled under one of the three toolchains this package supports would not be
// an implementation for this environment.

struct unicode_string {
    unsigned short length;        // in bytes, not characters
    unsigned short maximum;
    wchar_t*       buffer;
};

struct object_attributes {
    unsigned long   length;
    void*           root_directory;
    unicode_string* object_name;
    unsigned long   attributes;
    void*           security_descriptor;
    void*           security_quality_of_service;
};

struct io_status_block {
    union { long status; void* pointer; };
    okw_uptr information;
};

struct file_basic_information {
    okw_i64      creation_time, last_access_time, last_write_time, change_time;
    unsigned long attributes;
};

struct file_standard_information {
    okw_i64       allocation_size;
    okw_i64       end_of_file;
    unsigned long number_of_links;
    unsigned char delete_pending;
    unsigned char directory;
};

struct file_position_information { okw_i64 current_byte_offset; };
struct file_end_of_file_information { okw_i64 end_of_file; };
struct file_disposition_information { unsigned char delete_file; };

struct file_rename_information {
    unsigned char replace_if_exists;
    unsigned char pad[7];
    void*         root_directory;
    unsigned long file_name_length;
    wchar_t       file_name[1];
};

struct file_directory_information {
    unsigned long next_entry_offset;
    unsigned long file_index;
    okw_i64       creation_time, last_access_time, last_write_time, change_time;
    okw_i64       end_of_file, allocation_size;
    unsigned long file_attributes;
    unsigned long file_name_length;      // in bytes
    wchar_t       file_name[1];
};

enum : int {
    file_directory_information_class = 1,
    file_basic_information_class     = 4,
    file_standard_information_class  = 5,
    file_position_information_class  = 14,
    file_disposition_information_class = 13,
    file_end_of_file_information_class = 20,
    file_rename_information_class    = 10,
};

// The dispositions NtCreateFile takes. They are the whole of what
// kal_fs_open's flags become: an intent stated once and carried out once,
// rather than an open followed by a truncation that a program could stop
// between.
enum : unsigned long {
    file_supersede = 0, file_open = 1, file_create = 2,
    file_open_if = 3, file_overwrite = 4, file_overwrite_if = 5,
};

enum : unsigned long {
    file_directory_file    = 0x00000001,
    file_write_through     = 0x00000002,
    file_synchronous_io_nonalert = 0x00000020,
    file_non_directory_file = 0x00000040,
    file_open_for_backup_intent = 0x00004000,
    obj_case_insensitive   = 0x00000040,
};

extern "C" {
long __stdcall NtCreateFile(void** handle, unsigned long access,
                            object_attributes* attributes, io_status_block* status,
                            okw_i64* allocation, unsigned long file_attributes,
                            unsigned long share, unsigned long disposition,
                            unsigned long options, void* ea, unsigned long ea_length);
long __stdcall NtClose(void* handle);
long __stdcall NtReadFile(void* handle, void* event, void* apc, void* apc_context,
                          io_status_block* status, void* buffer, unsigned long length,
                          okw_i64* offset, unsigned long* key);
long __stdcall NtWriteFile(void* handle, void* event, void* apc, void* apc_context,
                           io_status_block* status, const void* buffer, unsigned long length,
                           okw_i64* offset, unsigned long* key);
long __stdcall NtQueryInformationFile(void* handle, io_status_block* status, void* info,
                                      unsigned long length, int cls);
long __stdcall NtSetInformationFile(void* handle, io_status_block* status, void* info,
                                    unsigned long length, int cls);
long __stdcall NtQueryDirectoryFile(void* handle, void* event, void* apc, void* apc_context,
                                    io_status_block* status, void* buffer, unsigned long length,
                                    int cls, unsigned char single, unicode_string* pattern,
                                    unsigned char restart);
long __stdcall NtFlushBuffersFile(void* handle, io_status_block* status);
unsigned long __stdcall RtlNtStatusToDosError(long status);
}

inline bool ok(long status) { return status >= 0; }

// --- translation -------------------------------------------------------------
//
// The environment's error values are mapped onto the closed set the
// specification defines. A table preserves the naturalness clause 7.1 requires;
// reconstructing a foreign namespace would not.
int translate_win32(unsigned long e);
inline int translate_nt(long status) { return translate_win32(RtlNtStatusToDosError(status)); }

// --- names -------------------------------------------------------------------
//
// openkal counts its strings in bytes and this environment counts them in
// sixteen-bit units, so every name crosses one conversion. The conversion is a
// change of representation and not a namespace being reconstructed: nothing is
// resolved, nothing is looked up, and a name that is not valid in one encoding
// is refused rather than approximated.
constexpr okw_uptr kMaxName = 4096;

struct wide_name {
    wchar_t buffer[kMaxName];
    unicode_string string;
    bool ok;
    wide_name(const char* utf8, okw_uptr len);
};

// The reverse, for reporting a name this environment produced.
okw_uptr narrow(const wchar_t* wide, okw_uptr wide_len, char* out, okw_uptr cap);

// A name is a single component or a sequence separated by a forward slash. It
// shall not begin with a separator and shall not contain a component that
// ascends: a program able to ascend from the directory it was given would not
// be confined by having been given it.
//
// The separator this environment uses is the other one, and both are accepted
// on the way in for the same reason the conversion above exists --- the caller
// speaks openkal's spelling and the object manager speaks this one.
bool acceptable(const char* name, okw_uptr len);

okw_uptr length(const char* s);

}  // namespace okw
