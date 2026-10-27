// A bounded wait for a program started with a bound lifetime (0.13.2).
//
// Such a program is named by its record rather than by its handle, and
// `kal_timeout_wait_process' read the word as a handle: every bounded wait for
// it failed. A caller that bounds a command (mcpp's `[hooks] timeout_seconds')
// then waited without the bound. The wait expires while the program runs and
// reports its status once it has ended.
#include <cstdio>
#include <cstring>
#include <openkal/fs.h>
#include <openkal/process.h>
#include <openkal/timeout.h>
#include <openkal/types.h>

namespace {

int failures = 0;

void check(bool held, const char* what) {
    if (held) { std::printf("ok: %s\n", what); return; }
    std::printf("FAIL: %s\n", what);
    ++failures;
}

bool system_volume(kal_dir* volume) {
    const kal_uintptr count = kal_fs_preopen_count();
    for (kal_uintptr i = 0; i < count; ++i) {
        char name[16]{};
        kal_uintptr len = 0;
        kal_dir d{};
        if (kal_fs_preopen(i, &d, name, sizeof name, &len) != kal_ok) continue;
        if (len == 2 && (name[0] | 0x20) == 'c' && name[1] == ':') { *volume = d; return true; }
    }
    return false;
}

// The interpreter running `command', with a lifetime bound to this program.
int start(const char* command, kal_process* p) {
    kal_dir volume{};
    if (!system_volume(&volume)) return -1;
    const char* path = "Windows/System32/cmd.exe";
    const char* argv[3] = { "cmd.exe", "/c", command };
    const kal_uintptr lens[3] = { 7, 2, std::strlen(command) };
    const kal_spawn how{ volume, volume, nullptr, nullptr, 0, KAL_SPAWN_BOUND_LIFETIME };
    return kal_process_spawn(&how, path, std::strlen(path), argv, lens, 3, nullptr, nullptr, 0, nullptr, p);
}

}  // namespace

int main() {
    if ((kal_process_props() & KAL_PROCESS_PROP_BOUND_LIFETIME) == 0) {
        std::printf("openkal-windows: no bound lifetime here; nothing to observe\n");
        return 0;
    }
    kal_process slow{};
    check(start("ping -n 3 127.0.0.1 >NUL", &slow) == kal_ok, "a bound program starts");
    int status = -1, terminated = -1;
    check(kal_timeout_wait_process(slow, 100000000ull /* 100 ms */, &status, &terminated) == kal_err_again,
          "a bounded wait expires while the bound program runs");
    check(kal_timeout_wait_process(slow, 20000000000ull /* 20 s */, &status, &terminated) == kal_ok
              && status == 0,
          "and reports its status once it has ended");

    kal_process quick{};
    check(start("exit 3", &quick) == kal_ok, "a second bound program starts");
    check(kal_timeout_wait_process(quick, 20000000000ull, &status, &terminated) == kal_ok && status == 3,
          "a bounded wait reports the status the program returned");

    if (failures == 0) std::printf("openkal-windows: a bound program is waited for with a bound\n");
    return failures == 0 ? 0 : 1;
}
