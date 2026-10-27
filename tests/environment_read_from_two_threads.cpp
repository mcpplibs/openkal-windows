// The environment read first from two contexts at once (0.13.3).
//
// The tables behind openkal.env are filled on the first enquiry. Two contexts
// that asked at the same moment met there: one marked the tables ready and
// filled them while the other read them empty, and a variable that was set
// --- PATH --- was reported absent. The first enquiry is made here from two
// contexts released together, in a fresh copy of this program each round, and
// both are told the variable.
#include <cstdio>
#include <cstring>
#include <openkal/env.h>
#include <openkal/fs.h>
#include <openkal/process.h>
#include <openkal/task.h>
#include <openkal/types.h>

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

}  // namespace

int main(int argc, char** argv) {
    if (argc > 1 && std::strcmp(argv[1], "--copy") == 0) return copy();

    char self[1024];
    const kal_intptr n = kal_env_image(self, sizeof self - 1);
    if (n <= 0) { std::printf("FAIL: this program's image is named\n"); return 1; }
    self[n] = 0;
    // `C:\...\x.exe' named relative to the volume the image is on.
    kal_dir volume{};
    for (kal_uintptr i = 0; i < kal_fs_preopen_count(); ++i) {
        char name[16]{}; kal_uintptr len = 0; kal_dir d{};
        if (kal_fs_preopen(i, &d, name, sizeof name, &len) != kal_ok) continue;
        if (len == 2 && (name[0] | 0x20) == (self[0] | 0x20) && name[1] == ':') { volume = d; break; }
    }
    if (!volume.h) { std::printf("openkal-windows: the image's volume is not granted; nothing to observe\n"); return 0; }
    const char* path = self + 3;   // past `C:\'
    int failures = 0;
    for (int round = 0; round < 20; ++round) {
        const char* args[2] = { self, "--copy" };
        const kal_uintptr lens[2] = { std::strlen(self), 6 };
        const kal_spawn how{ volume, volume, nullptr, nullptr, 0, 0 };
        kal_process p{};
        if (kal_process_spawn(&how, path, std::strlen(path), args, lens, 2, nullptr, nullptr, 0, nullptr, &p) != kal_ok) {
            std::printf("FAIL: a copy starts\n");
            return 1;
        }
        int status = -1, terminated = 0;
        kal_process_wait(p, &status, &terminated);
        if (status != 0) ++failures;
    }
    if (failures) {
        std::printf("FAIL: in %d of 20 copies a context read the environment before it was filled\n", failures);
        return 1;
    }
    std::printf("openkal-windows: the environment read first from two contexts at once\n");
    return 0;
}
