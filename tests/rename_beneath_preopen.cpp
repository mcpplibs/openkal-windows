// A rename into a nested name beneath a supplied directory uses the target's
// parent handle and its leaf. A compiler status file exercises this shape.
#include <cstdio>
#include <openkal/fs.h>

namespace {
int failures = 0;
void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) ++failures;
}
}

int main() {
    kal_dir root{};
    char name[512]{};
    kal_uintptr length = 0;
    check(kal_fs_preopen(0, &root, name, sizeof name, &length) == kal_ok,
          "the working directory is supplied");
    if (!root.h) return 1;

    constexpr char directory[] = "okw-rename-nested";
    constexpr char child[] = "okw-rename-nested/child";
    constexpr char source[] = "okw-rename-nested/child/source";
    constexpr char target[] = "okw-rename-nested/child/target";
    kal_fs_remove(root, source, sizeof source - 1);
    kal_fs_remove(root, target, sizeof target - 1);
    kal_fs_remove(root, child, sizeof child - 1);
    kal_fs_remove(root, directory, sizeof directory - 1);
    check(kal_fs_mkdir(root, directory, sizeof directory - 1) == kal_ok,
          "the outer directory is made");
    check(kal_fs_mkdir(root, child, sizeof child - 1) == kal_ok,
          "the nested directory is made");
    kal_file file{};
    const int created = kal_fs_open(root, source, sizeof source - 1,
                                    KAL_OPEN_WRITE | KAL_OPEN_CREATE, &file);
    check(created == kal_ok, "the source is created under the supplied root");
    if (file.h) kal_fs_close_file(file);
    if (created == kal_ok) {
        check(kal_fs_rename_flags(root, source, sizeof source - 1,
                                  root, target, sizeof target - 1,
                                  KAL_RENAME_NO_REPLACE) == kal_ok,
              "a nested relative destination is renamed atomically");
        kal_file second{};
        const int made = kal_fs_open(root, source, sizeof source - 1,
                                     KAL_OPEN_WRITE | KAL_OPEN_CREATE, &second);
        check(made == kal_ok, "a second source is created");
        if (second.h) kal_fs_close_file(second);
        if (made == kal_ok) {
            check(kal_fs_rename_flags(root, source, sizeof source - 1,
                                      root, target, sizeof target - 1,
                                      KAL_RENAME_NO_REPLACE) == kal_err_exists,
                  "no-replace keeps the existing nested destination");
            check(kal_fs_rename(root, source, sizeof source - 1,
                                root, target, sizeof target - 1) == kal_ok,
                  "replace updates the nested destination");
        }
    }
    kal_fs_remove(root, source, sizeof source - 1);
    kal_fs_remove(root, target, sizeof target - 1);
    kal_fs_remove(root, child, sizeof child - 1);
    kal_fs_remove(root, directory, sizeof directory - 1);
    return failures ? 1 : 0;
}
