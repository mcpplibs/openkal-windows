// The vector joined as it is, where a program receives one string (SPEC.md
// clause 7.6, version 0.17.1, KAL_SPAWN_ONE_STRING).
//
// The command interpreter reads the rest of its command line after `/s /c' as a
// command of its own grammar, with the outer pair of quotation marks removed. A
// command holding quotation marks --- a path with a space in it --- could not be
// given to it through the quoting that recovers a vector: each inner mark
// arrived escaped with a backslash, which the interpreter does not read. With
// the flag the command arrives as written, and its output says so.
#include <cstdio>
#include <cstring>
#include <openkal/fs.h>
#include <openkal/process.h>
#include <openkal/stream.h>
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

// Runs the interpreter with `command' after `/d /s /c' and returns what it wrote.
int run(kal_uintptr flags, const char* command, char* out, kal_uintptr cap, kal_uintptr* got) {
    kal_dir volume{};
    if (!system_volume(&volume)) return -1;
    const char* path = "Windows/System32/cmd.exe";
    const char* argv[5] = { "cmd.exe", "/d", "/s", "/c", command };
    const kal_uintptr lens[5] = { 7, 2, 2, 2, std::strlen(command) };
    kal_stream mine{}, theirs{};
    if (kal_process_channel(&mine, &theirs) != kal_ok) return -1;
    const kal_spawn how{ volume, volume, nullptr, nullptr, 0, flags };
    const kal_spawn_streams streams{ kal_stream{}, theirs, theirs };
    kal_process p{};
    const int rc = kal_process_spawn(&how, path, std::strlen(path), argv, lens, 5,
                                     nullptr, nullptr, 0, &streams, &p);
    kal_process_channel_close(theirs);
    if (rc != kal_ok) { kal_process_channel_close(mine); return rc; }
    *got = 0;
    for (;;) {
        const kal_intptr n = kal_stream_read(mine, out + *got, cap - 1 - *got);
        if (n <= 0) break;
        *got += static_cast<kal_uintptr>(n);
    }
    out[*got] = '\0';
    int status = 0, terminated = 0;
    kal_process_wait(p, &status, &terminated);
    kal_process_close(p);
    kal_process_channel_close(mine);
    return 0;
}

}  // namespace

int main() {
    check((kal_process_props() & KAL_PROCESS_PROP_ONE_STRING) != 0, "the position is claimed");
    char out[4096];
    kal_uintptr got = 0;
    const char* command = "\"echo \"a b\" && echo c\"";
    const int rc = run(KAL_SPAWN_ONE_STRING, command, out, sizeof out, &got);
    if (rc == -1) { std::printf("skip: no C: volume among the preopens\n"); return 0; }
    check(rc == kal_ok, "the interpreter starts with the command line joined as it is");
    check(std::strstr(out, "\"a b\"") != nullptr && std::strstr(out, "c") != nullptr,
          "and runs the command as written, quotation marks included");
    return failures;
}
