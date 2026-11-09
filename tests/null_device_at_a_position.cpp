// The null device at a position (openkal 0.22, clause 7.15): this system's
// `NUL'. The started copy finds a character device at its three positions,
// reads the end of input and has every write accepted; the caller's own handle
// for the device is released with the start, so its count of handles is what it
// was; and a flag beside a placed stream at one position is refused.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "../src/win32.h"
#include <openkal/fs.h>
#include <openkal/process.h>
#include <openkal/stream.h>
#include <openkal/timeout.h>
#include <openkal/types.h>
import mcpplibs.mtest;

using namespace mcpplibs::mtest;

extern "C" OKW_IMPORT unsigned long OKW_API GetModuleFileNameW(void*, wchar_t*, unsigned long);
extern "C" OKW_IMPORT BOOL OKW_API GetProcessHandleCount(HANDLE, DWORD*);

namespace {

void check(bool held, const char* what) { expect(held) << what; }

constexpr kal_u64 kBound = 10000ull * 1000ull * 1000ull;   // ten seconds

DWORD handles() {
    DWORD n = 0;
    GetProcessHandleCount(GetCurrentProcess(), &n);
    return n;
}

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

}  // namespace

// The started side. 41-43: a position is not a character device. 44: a read
// did not report the end of input. 45: a write was not accepted.
child null_device{"null", [](std::vector<std::string> args) {
    if (!args.empty()) return 46;
    if (GetFileType(GetStdHandle(STD_INPUT_HANDLE))  != FILE_TYPE_CHAR) return 41;
    if (GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) != FILE_TYPE_CHAR) return 42;
    if (GetFileType(GetStdHandle(STD_ERROR_HANDLE))  != FILE_TYPE_CHAR) return 43;
    char b[8];
    if (kal_stream_read(kal_stdin(), b, sizeof b) != 0) return 44;
    if (kal_stream_write(kal_stdout(), "discarded", 9) != 9) return 45;
    return 0;
}};

UTest null_device_at_a_position_test{"null_device_at_a_position", [] {

    kal_dir volume{};
    char self[1024];
    if (!locate_self(&volume, self, sizeof self)) {
        skip("this program's own name could not be expressed against a volume");
    }
    check((kal_process_props() & KAL_PROCESS_PROP_NULL_STREAMS) != 0, "the null device is claimed");

    const std::vector<std::string> command = child_command("null");
    std::vector<const char*> args;
    std::vector<kal_uintptr> lens;
    for (const auto& a : command) { args.push_back(a.c_str()); lens.push_back(a.size()); }
    const kal_spawn how{ volume, volume, nullptr, nullptr, 0,
                         KAL_SPAWN_NULL_IN | KAL_SPAWN_NULL_OUT | KAL_SPAWN_NULL_ERR };
    auto run = [&](int& status, int& terminated) {
        kal_process child{};
        const int spawned = kal_process_spawn(&how, self, std::strlen(self), args.data(), lens.data(), args.size(),
                                              nullptr, nullptr, 0, nullptr, &child);
        if (spawned == kal_ok) {
            if (kal_timeout_wait_process(child, kBound, &status, &terminated) != kal_ok)
                kal_process_terminate(child);
            kal_process_close(child);
        }
        return spawned;
    };
    int status = -1, terminated = -1;
    check(run(status, terminated) == kal_ok, "a copy is started with the null device at its three positions");
    expect(terminated == 0 && status == 0)
        << "the copy finds a character device there, reads its end and writes to it (reported " << status << ")";
    // Counted across a second start: the first start of a process opens
    // handles of the system's own that it keeps (measured on the runner, not
    // under Wine), and those are not this operation's.
    const DWORD before = handles();
    run(status, terminated);
    check(handles() == before, "the caller holds no handle for the device afterwards");

    kal_stream mine{}, theirs{};
    if (kal_process_channel(&mine, &theirs) == kal_ok) {
        const kal_spawn_streams placed{ kal_stream{0}, theirs, kal_stream{0} };
        const kal_spawn out_null{ volume, volume, nullptr, nullptr, 0, KAL_SPAWN_NULL_OUT };
        kal_process p{};
        check(kal_process_spawn(&out_null, self, std::strlen(self), args.data(), lens.data(), args.size(),
                                nullptr, nullptr, 0, &placed, &p) == kal_err_invalid,
              "the null device beside a placed stream at one position is refused");
        kal_process_channel_close(theirs);
        kal_process_channel_close(mine);
    }

    std::printf("openkal-windows: the null device at a position\n");
}};
