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
// It also observes that a grant is refused. This environment has no numbering a
// preopen could arrive under, KAL_PROCESS_PROP_GRANT_DIR is not claimed, and a
// program started without the directories it was asked to receive is not the
// program the caller asked for (clause 6.2).
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../src/win32.h"
#include <openkal/fs.h>
#include <openkal/process.h>
#include <openkal/stream.h>
#include <openkal/timeout.h>
#include <openkal/types.h>

// The one declaration src/win32.h does not carry, because the implementation
// never needs to know where its own program is.
extern "C" OKW_IMPORT unsigned long OKW_API GetModuleFileNameW(void*, wchar_t*, unsigned long);

namespace {

int failures = 0;

void check(bool held, const char* what) {
    if (held) { std::printf("ok: %s\n", what); return; }
    std::printf("FAIL: %s\n", what);
    ++failures;
}

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

// Starts a copy that writes one byte through `value', awaits it, and reports
// whether the byte reached the pipe the caller holds the other end of.
// `place' selects whether the start places one stream of its own.
void observe(kal_dir volume, const char* self, bool place, const char* what) {
    HANDLE pipe_read = nullptr, pipe_write = nullptr;
    if (!CreatePipe(&pipe_read, &pipe_write, nullptr, 0)) {
        std::printf("SKIP: %s (the pipe could not be made)\n", what);
        return;
    }
    // Inheritable for a reason of the caller's own, and never placed.
    SetHandleInformation(pipe_write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    char value[32];
    std::snprintf(value, sizeof value, "%llu",
                  static_cast<unsigned long long>(reinterpret_cast<kal_uintptr>(pipe_write)));
    const char* argv[3] = { "what_a_started_program_receives", "--write-through", value };
    const kal_uintptr lens[3] = { std::strlen(argv[0]), std::strlen(argv[1]), std::strlen(argv[2]) };

    kal_stream mine{}, theirs{};
    const bool channel = place && kal_process_channel(&mine, &theirs) == kal_ok;
    const kal_spawn_streams streams{ kal_stream{0}, theirs, kal_stream{0} };

    const kal_spawn how{ volume, volume, nullptr, nullptr, 0, 0 };
    kal_process child{};
    const int spawned = kal_process_spawn(&how, self, std::strlen(self), argv, lens, 3,
                                          nullptr, nullptr, 0, channel ? &streams : nullptr,
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

int main(int argc, char** argv) {
    // The started side: write one byte through the number it was given. Where
    // the handle was not conveyed the number names nothing, or names some
    // object of this program's own that refuses the write.
    if (argc == 3 && std::strcmp(argv[1], "--write-through") == 0) {
        const HANDLE h = reinterpret_cast<HANDLE>(
            static_cast<kal_uintptr>(std::strtoull(argv[2], nullptr, 10)));
        DWORD wrote = 0;
        WriteFile(h, "x", 1, &wrote, nullptr);
        return 0;
    }

    kal_dir volume{};
    char self[1024];
    if (!locate_self(&volume, self, sizeof self)) {
        std::printf("SKIP: this program's own name could not be expressed against a volume\n");
        return 0;
    }

    observe(volume, self, false,
            "an unplaced inheritable handle does not reach a program started without streams");
    observe(volume, self, true,
            "an unplaced inheritable handle does not reach a program started with a placed stream");

    // A grant this implementation does not claim is refused, not ignored.
    check((kal_process_props() & KAL_PROCESS_PROP_GRANT_DIR) == 0,
          "the directory grant is not claimed");
    {
        const kal_preopen grant{ volume, "x", 1 };
        const kal_spawn how{ volume, volume, nullptr, &grant, 1, 0 };
        const char* argv1[1] = { "x" };
        const kal_uintptr lens1[1] = { 1 };
        kal_process p{};
        check(kal_process_spawn(&how, "x", 1, argv1, lens1, 1, nullptr, nullptr, 0,
                                nullptr, &p) == kal_err_not_supported,
              "a grant is refused rather than a program started without it");
    }

    std::printf("openkal-windows: what a started program receives\n");
    return failures == 0 ? 0 : 1;
}
