#include "win.h"
#include "handle.h"
#include <openkal/map.h>

// openkal.map on this system (openkal 0.18).
//
// A section of the file (CreateFileMappingW, of the file's own length) and a
// view of it (MapViewOfFile). The section is closed as soon as the view exists:
// the view keeps it alive, and a view is released by its address alone, so
// nothing is recorded --- the reason the specification gives a region no
// handle (map.h). The offset's alignment is this system's allocation
// granularity, which is the specification's constant.
//
// THE FILE'S LENGTH IS ASKED FIRST. A view cannot extend past the section, and
// a section of a writable file larger than the file would lengthen it; the
// specification refuses such a region at the call. A file that is not on a
// disk (a device, a pipe) has no contents to map.
//
// A FILE SHORTENED BENEATH A VIEW is refused by this system with
// ERROR_USER_MAPPED_FILE, which win.cpp reports as kal_err_permission --- the
// first of the two outcomes map.h permits.

namespace { void* file_of(kal_file f) { return okw::unpack(f.h); } }

extern "C" {

int kal_map_file(kal_file f, kal_u64 offset, kal_uintptr length, kal_uintptr how, void** out) {
    if (out == nullptr) return kal_err_invalid;
    *out = nullptr;
    void* h = file_of(f);
    if (h == nullptr || length == 0 || offset % KAL_MAP_ALIGNMENT != 0
        || (how & ~(KAL_MAP_WRITE | KAL_MAP_SHARED)) != 0)
        return kal_err_invalid;
    if (GetFileType(h) != FILE_TYPE_DISK) return kal_err_not_supported;
    okw::io_status_block s{};
    okw::file_standard_information standard{};
    const long q = okw::NtQueryInformationFile(h, &s, &standard, sizeof standard,
                                               okw::file_standard_information_class);
    if (!okw::ok(q)) return okw::translate_nt(q);
    const kal_u64 size = standard.end_of_file > 0 ? static_cast<kal_u64>(standard.end_of_file) : 0;
    if (offset > size || static_cast<kal_u64>(length) > size - offset) return kal_err_invalid;

    const bool write = (how & KAL_MAP_WRITE) != 0, shared = (how & KAL_MAP_SHARED) != 0;
    // Shared and written: the file's pages. Written and private: copy on write,
    // which needs only reading of the file. Otherwise read.
    const DWORD protect = write ? (shared ? PAGE_READWRITE : PAGE_WRITECOPY) : PAGE_READONLY;
    const DWORD access  = write ? (shared ? FILE_MAP_WRITE : FILE_MAP_COPY) : FILE_MAP_READ;
    HANDLE section = CreateFileMappingW(h, nullptr, protect, 0, 0, nullptr);
    if (section == nullptr) return okw::translate_win32(GetLastError());
    void* view = MapViewOfFile(section, access, static_cast<DWORD>(offset >> 32),
                               static_cast<DWORD>(offset & 0xffffffffu), length);
    const DWORD e = view ? 0 : GetLastError();
    CloseHandle(section);
    if (view == nullptr) return okw::translate_win32(e);
    *out = view;
    return kal_ok;
}

int kal_map_sync(void* region, kal_uintptr length) {
    if (region == nullptr || length == 0) return kal_err_invalid;
    // FlushViewOfFile writes the view's changed pages to the file, after which
    // a read of the file reads them --- the visibility the specification asks
    // for. A view of a copy has nothing to write and succeeds.
    return FlushViewOfFile(region, length) ? kal_ok : okw::translate_win32(GetLastError());
}

void kal_map_release(void* region, kal_uintptr length) {
    if (region == nullptr || length == 0) return;
    (void)UnmapViewOfFile(region);
}

}
