// A regression test for version 0.13: a spawn inherits only the handles it
// placed.
//
// Before the fix, kal_process_spawn called CreateProcessW with inheritance
// enabled whenever any stream was placed, and bInheritHandles does not
// discriminate: the started program received every inheritable handle of this
// process, not only the ones this operation named. A detached child then kept
// a starter's own standard output open long after the starter had gone, and
// whoever waited for the end of that pipe waited for the wrong program to end.
//
// This test builds the condition directly. It makes one end of a pipe
// inheritable for a reason of its own -- exactly as a caller's own handle may
// legitimately be -- and never places it in a spawn; it starts a long-lived
// child with one legitimate placed stream (the child's own standard input,
// which keeps a shell reading from it alive); and it closes its own copy of
// the unplaced end. If the fix holds, nothing else holds that handle and the
// pipe's other end reports the end of input promptly; if the leak is present,
// the child's own duplicate keeps the pipe open and the bounded read does not
// complete within the bound -- which is what turns a hang into a report.
#include <cstdio>
#include <cstring>
#include "../src/win32.h"
#include <openkal/fs.h>
#include <openkal/process.h>
#include <openkal/stream.h>
#include <openkal/timeout.h>
#include <openkal/types.h>

namespace {

int failures = 0;

void check(bool held, const char* what) {
    if (held) { std::printf("ok: %s\n", what); return; }
    std::printf("FAIL: %s\n", what);
    ++failures;
}

// A volume, found among the preopens by its own name: exactly a letter and a
// colon, which is how src/fs.cpp reports one and how it distinguishes a
// volume from the working directory beside it (whose own name is a full path
// and is therefore longer). openkal names no absolute path; every volume is
// supplied as a directory a name may be resolved relative to.
bool find_a_volume(kal_dir* out) {
    const kal_uintptr n = kal_fs_preopen_count();
    for (kal_uintptr i = 0; i < n; ++i) {
        char name[16]{};
        kal_uintptr len = 0;
        kal_dir d{};
        if (kal_fs_preopen(i, &d, name, sizeof name, &len) != kal_ok) continue;
        if (len == 2 && name[1] == ':') { *out = d; return true; }
    }
    return false;
}

}  // namespace

int main() {
    kal_dir sys{};
    if (!find_a_volume(&sys)) {
        std::printf("SKIP: no volume was found among the preopens\n");
        return 0;
    }

    // The handle this test makes inheritable and never places. A real caller
    // has legitimate reasons to hold an inheritable handle it does not intend
    // for THIS spawn -- one made for a different, earlier or later, start.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    HANDLE leak_read = nullptr, leak_write = nullptr;
    if (!CreatePipe(&leak_read, &leak_write, &sa, 0)) {
        std::printf("SKIP: the pipe for the leak this test looks for could not be made\n");
        return 0;
    }

    // The one stream this spawn legitimately places: the child's standard
    // input, which keeps a shell reading from it alive until told to stop.
    kal_stream mine{}, child_stdin{};
    if (kal_process_channel(&mine, &child_stdin) != kal_ok) {
        std::printf("SKIP: a channel for the child's standard input could not be made\n");
        CloseHandle(leak_read);
        CloseHandle(leak_write);
        return 0;
    }

    const char* path = "Windows/System32/cmd.exe";
    const kal_uintptr path_len = std::strlen(path);
    const kal_spawn how{ sys, sys, nullptr, nullptr, 0, 0 };
    const kal_spawn_streams streams{ child_stdin, kal_stream{0}, kal_stream{0} };
    kal_process child{};
    const int spawned = kal_process_spawn(&how, path, path_len, &path, &path_len, 1,
                                          nullptr, nullptr, 0, &streams, &child);
    if (spawned != kal_ok) {
        std::printf("SKIP: cmd.exe could not be started (kal error %d)\n", spawned);
        kal_process_channel_close(mine);
        kal_process_channel_close(child_stdin);
        CloseHandle(leak_read);
        CloseHandle(leak_write);
        return 0;
    }
    // The child's own copy of its standard input. This end belongs to the
    // child now; this process keeps `mine', which is what lets it end the
    // shell later.
    kal_process_channel_close(child_stdin);

    // The handle this test made inheritable and never placed, closed here on
    // this process's side only. Whether anything else still holds it is
    // exactly what the read below observes.
    CloseHandle(leak_write);

    char buf[8];
    const kal_stream leak_stream{ reinterpret_cast<kal_uintptr>(leak_read) };
    const kal_intptr r = kal_timeout_read(leak_stream, buf, sizeof buf,
                                          5000ull * 1000ull * 1000ull);
    check(r == 0,
          "a handle made inheritable and not placed in the spawn is not inherited by it");

    // End the shell and wait for it, so the process does not outlive this
    // test whether the observation above held or not.
    const char exit_cmd[] = "exit\r\n";
    kal_stream_write(mine, exit_cmd, sizeof exit_cmd - 1);
    kal_process_channel_close(mine);
    int status = 0, terminated = 0;
    if (kal_timeout_wait_process(child, 5000ull * 1000ull * 1000ull, &status, &terminated) != kal_ok)
        kal_process_terminate(child);
    kal_process_close(child);
    CloseHandle(leak_read);

    std::printf("openkal-windows: a spawn inherits only the handles it placed\n");
    return failures == 0 ? 0 : 1;
}
