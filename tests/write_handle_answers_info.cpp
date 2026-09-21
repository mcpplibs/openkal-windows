// A regression test: a file opened for writing alone can still be described.
//
// `kal_fs_file_info` answers through NtQueryInformationFile with
// FileBasicInformation, which requires FILE_READ_ATTRIBUTES on the handle.
// `FILE_GENERIC_WRITE` does not carry that right -- winnt.h defines it as
// STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
// FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE -- so before the fix a file
// opened with KAL_OPEN_WRITE and nothing else could be written and not
// described, and the query came back kal_err_access.
//
// Through musl that surfaces as a descriptor the caller opened one line
// earlier refusing its own `fstat`:
//
//     open(..., O_WRONLY|O_CREAT|O_TRUNC)  ->  fd=3
//     fstat(3)                             ->  -1, EACCES
//
// which is what libarchive does when it opens an archive for output
// (archive_write_open_filename.c:178 and :189). Its message, `Couldn't stat
// '<path>'`, names the verb and interpolates the argument; four separate
// investigations went to the argument before anyone read the two lines.
//
// WINE DOES NOT ENFORCE THE ACCESS CHECK and answers rc=0 either way, so this
// test only reports on Windows. That is stated here because "it passes under
// Wine" was offered as evidence three times while this was open, and an
// environment that cannot produce the failing condition is not a second
// opinion about it.
#include <cstdio>
#include <openkal/fs.h>
#include <openkal/types.h>

namespace {

int failures = 0;

void check(bool ok, const char* what) {
    if (!ok) {
        std::printf("  FAILED %s\n", what);
        ++failures;
    }
}

} // namespace

int main() {
    // The first preopened directory, the same way handle_inheritance.cpp finds
    // one: a test writes where the program was given somewhere to write.
    kal_dir cwd{};
    bool haveDir = false;
    {
        const kal_uintptr n = kal_fs_preopen_count();
        for (kal_uintptr i = 0; i < n && !haveDir; ++i) {
            kal_dir d{};
            char nm[1024];
            kal_uintptr len = 0;
            if (kal_fs_preopen(i, &d, nm, sizeof nm, &len) != kal_ok) continue;
            cwd = d;
            haveDir = true;
        }
    }
    if (!haveDir) {
        std::printf("openkal-windows: no preopened directory to test in\n");
        return 1;
    }

    static const char name[] = "okw-write-handle-info.tmp";
    const kal_uintptr len = sizeof name - 1;

    kal_file f{};
    const int opened = kal_fs_open(cwd, name, len,
                                   KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE,
                                   &f);
    check(opened == kal_ok, "a file opens for writing");
    if (opened != kal_ok) {
        std::printf("openkal-windows: kal_fs_open returned %d\n", opened);
        return 1;
    }

    // THE ASSERTION. The handle was granted a line ago and the caller asks it
    // about itself; there is nothing here for the object manager to refuse.
    struct kal_node_info info = { };
    info.self_size = sizeof info;
    const int described = kal_fs_file_info(f, KAL_INFO_ALL, &info);
    std::printf("  kal_fs_file_info on a write-only handle -> %d\n", described);
    check(described == kal_ok, "a write-only handle answers kal_fs_file_info");

    // And the answer is the file's, not a zeroed structure: nothing has been
    // written, so the length is nought and the kind is a regular file.
    if (described == kal_ok) {
        check((info.present & KAL_INFO_KIND) != 0u, "the answer states the kind");
        check(info.kind == kal_node_file, "the kind is a regular file");
    }

    kal_fs_close_file(f);
    kal_fs_remove(cwd, name, len);

    std::printf("openkal-windows: a write-only handle answers for itself\n");
    return failures == 0 ? 0 : 1;
}
