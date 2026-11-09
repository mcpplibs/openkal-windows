// What a started program receives: the three streams and nothing else,
// including a handle the caller itself holds as inheritable (SPEC.md clause
// 7.13, version 0.14.1).
//
// tests/handle_inheritance.cpp observes the case version 0.13 repaired from the
// caller's side, by the end of a pipe. This test observes the clause from the
// started program's side. The copy it starts is handed the NUMBER of a handle
// the caller made inheritable and did not place, and writes through that
// number; the caller then reads the pipe. A byte that arrives was written
// through a handle the copy should not have had. Inherited handles keep their
// values in the started program, which is what makes the number meaningful
// there when the handle was conveyed and meaningless when it was not.
//
// It is observed without placed streams and with one, because the two reach
// CreateProcessW by different paths: inheritance disabled, and inheritance
// enabled and narrowed to an explicit list.
//
// A grant is a directory handle the caller places on purpose, and reaches the
// started program by the same list (from 0.19.0, openkal 0.23); what it
// receives is observed in tests/openkal_0_23.cpp.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "../src/win32.h"
#include <openkal/env.h>
#include <openkal/fs.h>
#include <openkal/process.h>
#include <openkal/stream.h>
#include <openkal/timeout.h>
#include <openkal/types.h>
import mcpplibs.mtest;

using namespace mcpplibs::mtest;

// The one declaration src/win32.h does not carry, because the implementation
// never needs to know where its own program is.
extern "C" OKW_IMPORT unsigned long OKW_API GetModuleFileNameW(void*, wchar_t*, unsigned long);

namespace {

void check(bool held, const char* what) { expect(held) << what; }

constexpr kal_u64 kBound = 10000ull * 1000ull * 1000ull;   // ten seconds

// This program's own name, expressed the way openkal names things: the volume
// it is on, found among the preopens by its own name ("X:"), and the remainder
// relative to it. Answers false for a name this test does not attempt to
// express, which is reported as a skip rather than as a failure of the
// implementation.
bool locate_self(kal_dir* volume, char* relative, kal_uintptr cap) {
    wchar_t wide[1024];
    const unsigned long n = GetModuleFileNameW(nullptr, wide, 1024);
    if (n < 4 || n >= 1024 || wide[1] != L':' || wide[2] != L'\\') return false;
    if (n - 3 >= cap) return false;
    for (unsigned long i = 3; i < n; ++i) {
        if (wide[i] >= 0x80) return false;
        relative[i - 3] = wide[i] == L'\\' ? '/' : static_cast<char>(wide[i]);
    }
    relative[n - 3] = '\0';

    const kal_uintptr count = kal_fs_preopen_count();
    for (kal_uintptr i = 0; i < count; ++i) {
        char name[16]{};
        kal_uintptr len = 0;
        kal_dir d{};
        if (kal_fs_preopen(i, &d, name, sizeof name, &len) != kal_ok) continue;
        if (len == 2 && name[1] == ':' && (name[0] | 0x20) == (static_cast<char>(wide[0]) | 0x20)) {
            *volume = d;
            return true;
        }
    }
    return false;
}

// This program's environment without the test runner's report. A copy that
// inherited MTEST_REPORT would hold the report open, and the number it writes
// through could name that file and not nothing.
std::vector<std::string> environment_without_report() {
    std::vector<std::string> out;
    for (kal_uintptr i = 0; i < kal_env_var_count(); ++i) {
        char name[512];
        const kal_intptr n = kal_env_var_at(i, name, sizeof name);
        if (n <= 0 || static_cast<kal_uintptr>(n) >= sizeof name) continue;
        const std::string key(name, static_cast<std::size_t>(n));
        if (key == "MTEST_REPORT" || key == "MTEST_PROTOCOL") continue;
        const kal_intptr v = kal_env_var(key.data(), key.size(), nullptr, 0);
        if (v < 0) continue;
        std::string value(static_cast<std::size_t>(v), '\0');
        if (v > 0) kal_env_var(key.data(), key.size(), value.data(), value.size());
        out.push_back(key + "=" + value);
    }
    return out;
}

// Starts a copy that writes one byte through `value', awaits it, and reports
// whether the byte reached the pipe the caller holds the other end of.
// `place' selects whether the start places one stream of its own.
void observe(kal_dir volume, const char* self, bool place, const char* what) {
    HANDLE pipe_read = nullptr, pipe_write = nullptr;
    if (!CreatePipe(&pipe_read, &pipe_write, nullptr, 0)) {
        skip(std::string(what) + " (the pipe could not be made)");
    }
    // Inheritable for a reason of the caller's own, and never placed.
    SetHandleInformation(pipe_write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    char value[32];
    std::snprintf(value, sizeof value, "%llu",
                  static_cast<unsigned long long>(reinterpret_cast<kal_uintptr>(pipe_write)));
    const std::vector<std::string> command = child_command("write-through", std::vector<std::string>{ value });
    std::vector<const char*> argv;
    std::vector<kal_uintptr> lens;
    for (const auto& a : command) { argv.push_back(a.c_str()); lens.push_back(a.size()); }
    const std::vector<std::string> environment = environment_without_report();
    std::vector<const char*> envp;
    std::vector<kal_uintptr> elens;
    for (const auto& e : environment) { envp.push_back(e.c_str()); elens.push_back(e.size()); }

    kal_stream mine{}, theirs{};
    const bool channel = place && kal_process_channel(&mine, &theirs) == kal_ok;
    const kal_spawn_streams streams{ kal_stream{0}, theirs, kal_stream{0} };

    const kal_spawn how{ volume, volume, nullptr, nullptr, 0, 0 };
    kal_process child{};
    const int spawned = kal_process_spawn(&how, self, std::strlen(self), argv.data(), lens.data(), argv.size(),
                                          envp.data(), elens.data(), envp.size(), channel ? &streams : nullptr,
                                          &child);
    check(spawned == kal_ok, "a copy of this program is started");
    if (channel) kal_process_channel_close(theirs);

    int status = -1, terminated = -1;
    if (spawned == kal_ok) {
        if (kal_timeout_wait_process(child, kBound, &status, &terminated) != kal_ok)
            kal_process_terminate(child);
        kal_process_close(child);
    }
    if (channel) kal_process_channel_close(mine);

    // The copy has ended, so only this process can still hold the write end.
    // Once it is closed, a pipe nobody wrote to reports its end at once.
    CloseHandle(pipe_write);
    char buf[8];
    const kal_stream reader{ reinterpret_cast<kal_uintptr>(pipe_read) };
    const kal_intptr got = kal_timeout_read(reader, buf, sizeof buf, kBound);
    check(spawned == kal_ok && terminated == 0 && got == 0, what);
    CloseHandle(pipe_read);
}

}  // namespace

// The started side: write one byte through the number it was given. Where the
// handle was not conveyed the number names nothing, or names some object of
// this program's own that refuses the write.
child write_through{"write-through", [](std::vector<std::string> args) {
    if (args.size() != 1) return 2;
    const HANDLE h = reinterpret_cast<HANDLE>(
        static_cast<kal_uintptr>(std::strtoull(args[0].c_str(), nullptr, 10)));
    DWORD wrote = 0;
    WriteFile(h, "x", 1, &wrote, nullptr);
    return 0;
}};

UTest what_a_started_program_receives_test{"what_a_started_program_receives", [] {

    kal_dir volume{};
    char self[1024];
    if (!locate_self(&volume, self, sizeof self)) {
        skip("this program's own name could not be expressed against a volume");
    }

    observe(volume, self, false,
            "an unplaced inheritable handle does not reach a program started without streams");
    observe(volume, self, true,
            "an unplaced inheritable handle does not reach a program started with a placed stream");

    std::printf("openkal-windows: what a started program receives\n");
}};
