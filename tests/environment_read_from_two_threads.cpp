// The environment read first from two contexts at once (0.13.3).
//
// The tables behind openkal.env are filled on the first enquiry. Two contexts
// that asked at the same moment met there: one marked the tables ready and
// filled them while the other read them empty, and a variable that was set
// --- PATH --- was reported absent. The first enquiry is made here from two
// contexts released together, in a fresh copy of this program each round, and
// both are told the variable.
//
// THE COPY BEGINS BEFORE THE TEST LIBRARY DOES. mtest's state reads its own
// variables through openkal when the first case or child of this file is
// declared, which would fill the tables before the two contexts ask. The copy
// is therefore recognised from the system's own command line, by the
// arguments child_command("copy") gives it, during this file's initialisation
// and ahead of every declaration, and it ends there with its status.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "../src/win32.h"
#include <openkal/env.h>
#include <openkal/fs.h>
#include <openkal/process.h>
#include <openkal/task.h>
#include <openkal/types.h>
#include <openkal/abort.h>
import mcpplibs.mtest;

using namespace mcpplibs::mtest;

namespace {

volatile kal_u32 g_gate = 0;
volatile int g_found[2] = { 0, 0 };

void ask(void* p) {
    const int i = static_cast<int>(reinterpret_cast<kal_uintptr>(p));
    while (g_gate == 0) {}
    char value[4096];
    g_found[i] = kal_env_var("PATH", 4, value, sizeof value) > 0 ? 1 : 0;
}

// The copy: both contexts ask for PATH first thing; 0 when both were told.
int copy() {
    kal_task a{}, b{};
    if (kal_task_start(ask, reinterpret_cast<void*>(kal_uintptr{ 0 }), &a) != kal_ok) return 3;
    if (kal_task_start(ask, reinterpret_cast<void*>(kal_uintptr{ 1 }), &b) != kal_ok) return 3;
    g_gate = 1;
    kal_task_join(a);
    kal_task_join(b);
    return g_found[0] && g_found[1] ? 0 : 1;
}

// Whether the system's command line ends with the arguments of the copy.
bool started_as_copy() {
    const wchar_t* line = GetCommandLineW();
    const wchar_t tail[] = L" --mtest-child copy";
    kal_uintptr n = 0, t = sizeof tail / sizeof tail[0] - 1;
    while (line[n]) ++n;
    while (n > 0 && line[n - 1] == L' ') --n;
    if (n < t) return false;
    for (kal_uintptr i = 0; i < t; ++i) if (line[n - t + i] != tail[i]) return false;
    return true;
}

[[maybe_unused]] const int g_copy = started_as_copy() ? (kal_exit(copy()), 0) : 0;

}  // namespace

// Declared so that the copy's arguments are mtest's; it is entered above.
child copy_of_this{"copy", [](std::vector<std::string>) { return copy(); }};

UTest environment_read_from_two_threads_test{"environment_read_from_two_threads", [] {
    char self[1024];
    const kal_intptr n = kal_env_image(self, sizeof self - 1);
    if (n <= 0) { fail("this program's image is named"); return; }
    self[n] = 0;
    // `C:\...\x.exe' named relative to the volume the image is on.
    kal_dir volume{};
    for (kal_uintptr i = 0; i < kal_fs_preopen_count(); ++i) {
        char name[16]{}; kal_uintptr len = 0; kal_dir d{};
        if (kal_fs_preopen(i, &d, name, sizeof name, &len) != kal_ok) continue;
        if (len == 2 && (name[0] | 0x20) == (self[0] | 0x20) && name[1] == ':') { volume = d; break; }
    }
    if (!volume.h) skip("the image's volume is not granted; nothing to observe");
    const char* path = self + 3;   // past `C:\'
    int failures = 0;
    for (int round = 0; round < 20; ++round) {
        const std::vector<std::string> command = child_command("copy");
        std::vector<const char*> args;
        std::vector<kal_uintptr> lens;
        for (const auto& a : command) { args.push_back(a.c_str()); lens.push_back(a.size()); }
        const kal_spawn how{ volume, volume, nullptr, nullptr, 0, 0 };
        kal_process p{};
        if (kal_process_spawn(&how, path, std::strlen(path), args.data(), lens.data(), args.size(), nullptr, nullptr, 0, nullptr, &p) != kal_ok) {
            fail("a copy starts");
            return;
        }
        int status = -1, terminated = 0;
        kal_process_wait(p, &status, &terminated);
        if (status != 0) ++failures;
    }
    expect(failures == 0) << "in " << failures << " of 20 copies a context read the environment before it was filled";
}};
