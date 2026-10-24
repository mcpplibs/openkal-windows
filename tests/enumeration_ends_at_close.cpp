// What closing a directory does to its enumerations (fs.h, openkal 0.16).
//
// The Linux implementation kept a descriptor for every directory a C library
// above it had stopped reading early (mcpplibs/openkal-linux#34), and this one
// had the same shape: only reaching the end closed the handle an enumeration
// opened. Counted in this environment's own table of the process's handles,
// because a count of open handles is not portable and the conformance suite
// cannot make it (SPEC clause 11, entry 24).
#include <cstdio>
#include "../src/win32.h"
#include <openkal/fs.h>
#include <openkal/task.h>
#include <openkal/types.h>

extern "C" OKW_IMPORT BOOL   OKW_API GetProcessHandleCount(HANDLE, DWORD*);
extern "C" OKW_IMPORT HANDLE OKW_API GetCurrentProcess(void);

namespace {

int failures = 0;

void check(bool held, const char* what) {
    std::printf("  %s  %s\n", held ? "held" : "FAIL", what);
    if (!held) ++failures;
}

DWORD handles() { DWORD n = 0; return GetProcessHandleCount(GetCurrentProcess(), &n) ? n : 0; }

struct race { kal_dir d; volatile int told; };

void reader(void* p) {
    auto* r = static_cast<race*>(p);
    kal_uintptr it = 0;
    if (kal_fs_list_begin(r->d, &it) != kal_ok) { r->told = 1; return; }
    for (;;) {
        char name[512]; kal_uintptr len = 0; int kind = 0;
        if (kal_fs_list_next(r->d, &it, name, sizeof name, &len, &kind) != kal_ok) { r->told = 1; return; }
        if (it == 0 && kal_fs_list_begin(r->d, &it) != kal_ok) { r->told = 1; return; }
    }
}

}  // namespace

int main() {
    kal_dir cwd{};
    if (kal_fs_preopen_count() == 0 || kal_fs_preopen(0, &cwd, nullptr, 0, nullptr) != kal_ok) {
        std::printf("openkal-windows: no preopened directory to test in\n");
        return 1;
    }
    kal_fs_mkdir(cwd, "okw-enum.d", 10);
    kal_file f{};
    if (kal_fs_open(cwd, "okw-enum.d/inner", 16, KAL_OPEN_WRITE | KAL_OPEN_CREATE, &f) == kal_ok)
        kal_fs_close_file(f);

    const DWORD before = handles();
    for (int i = 0; i < 64; ++i) {
        kal_dir d{}; kal_uintptr it = 0;
        if (kal_fs_open_dir(cwd, "okw-enum.d", 10, &d) != kal_ok) break;
        if (kal_fs_list_begin(d, &it) == kal_ok) {
            char name[512]; kal_uintptr len = 0; int kind = 0;
            kal_fs_list_next(d, &it, name, sizeof name, &len, &kind);
        }
        kal_fs_close_dir(d);
    }
    const DWORD after = handles();
    std::printf("  handles before=%lu after=%lu\n", (unsigned long)before, (unsigned long)after);
    if (before == 0) std::printf("  not observed  the environment did not count the process's handles\n");
    else check(after == before, "closing a directory ends an enumeration left part-way");

    {
        kal_dir once{}; kal_uintptr it = 0;
        if (kal_fs_open_dir(cwd, "okw-enum.d", 10, &once) == kal_ok && kal_fs_list_begin(once, &it) == kal_ok) {
            kal_fs_close_dir(once);
            char name[512]; kal_uintptr len = 0; int kind = 0;
            check(kal_fs_list_next(once, &it, name, sizeof name, &len, &kind) == kal_err_invalid,
                  "an enumeration of a closed directory is refused");
        }
        kal_dir a{}, b{}; kal_uintptr ia = 0;
        if (kal_fs_open_dir(cwd, "okw-enum.d", 10, &a) == kal_ok
            && kal_fs_open_dir(cwd, "okw-enum.d", 10, &b) == kal_ok
            && kal_fs_list_begin(a, &ia) == kal_ok) {
            char name[512]; kal_uintptr len = 0; int kind = 0;
            check(kal_fs_list_next(b, &ia, name, sizeof name, &len, &kind) == kal_err_invalid,
                  "an iterator is refused with a directory that did not produce it");
        }
        kal_fs_close_dir(a); kal_fs_close_dir(b);
    }

    int ended = 0;
    for (int i = 0; i < 200; ++i) {
        race r{};
        if (kal_fs_open_dir(cwd, "okw-enum.d", 10, &r.d) != kal_ok) break;
        kal_task t{};
        if (kal_task_start(reader, &r, &t) != kal_ok) { kal_fs_close_dir(r.d); break; }
        for (int spin = 0; spin < i * 10; ++spin) kal_task_yield();
        kal_fs_close_dir(r.d);
        kal_task_join(t);
        ended += r.told;
    }
    check(ended == 200, "an enumeration racing the close of its directory ends and is told so");

    kal_fs_remove(cwd, "okw-enum.d/inner", 16);
    kal_fs_remove(cwd, "okw-enum.d", 10);
    std::printf("openkal-windows: what closing a directory ends, %s\n", failures ? "FAILED" : "held");
    return failures == 0 ? 0 : 1;
}
