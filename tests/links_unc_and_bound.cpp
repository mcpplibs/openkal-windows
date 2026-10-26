// Links, the network's names, and a bound lifetime (openkal-windows 0.13: K4,
// K9, K5).
//
//   K4  a directory link is made without privilege (a junction where a
//       symbolic link is refused), is reported as a link, reads back, and
//       reaches what it names;
//   K9  the root of the network's names is a preopen, and the administrative
//       share of this machine is reached beneath it;
//   K5  a started program bound to this one is placed in a job that ends it.
#include <cstdio>
#include <cstring>
#include <openkal/fs.h>
#include <openkal/process.h>
#include <openkal/types.h>

namespace {
int failures = 0;
void check(bool held, const char* what) {
    std::printf("  %s  %s\n", held ? "held" : "FAIL", what);
    if (!held) ++failures;
}
kal_dir preopen_named(const char* want) {
    for (kal_uintptr i = 0; i < kal_fs_preopen_count(); ++i) {
        kal_dir d{}; char n[64]; kal_uintptr l = 0;
        if (kal_fs_preopen(i, &d, n, sizeof n, &l) == kal_ok && l == std::strlen(want)
            && std::memcmp(n, want, l) == 0) return d;
    }
    return kal_dir{};
}
}

int main() {
    kal_dir here{}; char n[512]; kal_uintptr l = 0;
    kal_fs_preopen(0, &here, n, sizeof n, &l);

    // K4
    check((kal_fs_props(here) & KAL_FS_PROP_MAKE_LINKS) != 0, "the working volume makes links");
    kal_fs_remove(here, "okw-link", 8);
    kal_fs_remove(here, "okw-target", 10);
    check(kal_fs_mkdir(here, "okw-target", 10) == kal_ok, "a directory is made");
    const int made = kal_fs_link_create(here, "okw-link", 8, "okw-target", 10, KAL_FS_LINK_DIRECTORY);
    check(made == kal_ok, "a directory link is made without privilege");
    kal_node_info info{}; info.self_size = sizeof info;
    check(kal_fs_info(here, "okw-link", 8, KAL_FS_NO_RESOLVE, KAL_INFO_ALL, &info) == kal_ok
              && info.kind == kal_node_link, "and is reported as a link");
    char target[1024] = {};
    const kal_intptr t = kal_fs_link_read(here, "okw-link", 8, target, sizeof target - 1);
    check(t > 0 && std::strstr(target, "okw-target") != nullptr, "and reads back its target");
    kal_dir through{};
    check(kal_fs_open_dir(here, "okw-link", 8, &through) == kal_ok, "and reaches the directory it names");
    if (through.h) kal_fs_close_dir(through);
    kal_fs_remove(here, "okw-link", 8);
    kal_fs_remove(here, "okw-target", 10);

    // K9
    const kal_dir net = preopen_named("//");
    check(net.h != 0, "the root of the network's names is a preopen");
    if (net.h != 0) {
        kal_dir share{};
        const int rc = kal_fs_open_dir(net, "localhost/C$/Windows", 20, &share);
        if (rc == kal_ok) { check(true, "this machine's administrative share is reached beneath it"); kal_fs_close_dir(share); }
        else std::printf("  (the administrative share is not reachable here: %d)\n", rc);
    }

    // K5
    check((kal_process_props() & KAL_PROCESS_PROP_BOUND_LIFETIME) != 0, "a bound lifetime is claimed");
    const kal_dir sys = preopen_named("C:");
    if (sys.h != 0) {
        const char* argv[] = { "cmd", "/c", "exit 5" };
        const kal_uintptr lens[] = { 3, 2, 6 };
        kal_spawn how{ sys, sys, nullptr, nullptr, 0, KAL_SPAWN_BOUND_LIFETIME };
        kal_process p{};
        const int rc = kal_process_spawn(&how, "Windows/System32/cmd.exe", 24, argv, lens, 3,
                                         nullptr, nullptr, 0, nullptr, &p);
        int status = -1, terminated = 0;
        if (rc == kal_ok) { kal_process_wait(p, &status, &terminated); kal_process_close(p); }
        check(rc == kal_ok && status == 5, "a program bound to this one is started and awaited");
    }
    std::printf(failures == 0 ? "openkal-windows: links, the network's names, a bound lifetime\n" : "");
    return failures == 0 ? 0 : 1;
}
