// What openkal-windows 0.19 does beside openkal 0.23, as this system does it.
//
// A GRANT ARRIVES AS AN INHERITED HANDLE: the started program has the granted
// directories and nothing else, holds them uninheritable, and a program it
// starts without grants --- the variable naming them inherited all the same ---
// has the directories a program has by default, because the variable names the
// program that wrote it. A RECORD ACROSS A START: a program granted a recorded
// handle appends what it reached to its caller's record, and its end. A PART
// OF A REGION THAT IS A FILE'S leaves the rest of the region as it was, and a
// part this system cannot place a view at is refused with the region
// unchanged. A PREFERENCE FOR ECONOMY lowers the started program's memory
// priority, and one for performance leaves it the system's --- the starter's,
// which a started program has. A FAULT is reported by what ends the program, naming the program's
// own file.
#include <cstdio>
#include <cstring>
#include "../src/win32.h"
#include "../src/handle.h"
#include <openkal/abort.h>
#include <openkal/env.h>
#include <openkal/exec.h>
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

kal_uintptr length(const char* s) { return std::strlen(s); }

// This program's volume among the preopens ("X:"), and its name beneath it.
char g_self[1024];
char g_dir[1024];       // the directory it is in, beneath the volume
char g_volume_name[3];

bool locate_self(kal_dir* volume) {
    char image[1024];
    const kal_intptr n = kal_env_image(image, sizeof image - 1);
    if (n < 4 || image[1] != ':' || (image[2] != '\\' && image[2] != '/')) return false;
    image[n] = '\0';
    for (kal_intptr i = 3; i <= n; ++i) g_self[i - 3] = image[i] == '\\' ? '/' : image[i];
    std::strcpy(g_dir, g_self);
    char* slash = std::strrchr(g_dir, '/');
    if (slash) *slash = '\0'; else g_dir[0] = '\0';
    const kal_uintptr count = kal_fs_preopen_count();
    for (kal_uintptr i = 0; i < count; ++i) {
        char name[16]{}; kal_uintptr len = 0; kal_dir d{};
        if (kal_fs_preopen(i, &d, name, sizeof name, &len) != kal_ok) continue;
        if (len == 2 && name[1] == ':' && (name[0] | 0x20) == (image[0] | 0x20)) {
            *volume = d;
            g_volume_name[0] = name[0]; g_volume_name[1] = ':'; g_volume_name[2] = '\0';
            return true;
        }
    }
    return false;
}

kal_dir by_name(const char* want) {
    for (kal_uintptr i = 0; i < kal_fs_preopen_count(); ++i) {
        char name[64]{}; kal_uintptr len = 0; kal_dir d{};
        if (kal_fs_preopen(i, &d, name, sizeof name, &len) == kal_ok && len == length(want)
            && std::memcmp(name, want, len) == 0)
            return d;
    }
    return kal_dir{};
}

// Starts this program with `errand', from the volume named `volume_name' among
// the caller's preopens, and returns its status, or -1.
int start(kal_dir volume, const char* errand, const kal_preopen* grants, kal_uintptr n, kal_uintptr flags,
          const kal_spawn_streams* streams = nullptr, bool null_grants = false) {
    const char* argv[2] = { "openkal_0_23", errand };
    const kal_uintptr lens[2] = { length(argv[0]), length(errand) };
    const kal_spawn how{ volume, volume, nullptr, null_grants ? nullptr : grants, n, flags };
    kal_process p{};
    if (kal_process_spawn(&how, g_self, length(g_self), argv, lens, 2, nullptr, nullptr, 0, streams, &p) != kal_ok)
        return -1;
    int status = -1, terminated = 0;
    kal_process_wait(p, &status, &terminated);
    kal_process_close(p);
    return terminated ? -2 : status;
}

bool holds(const char* buf, long got, const char* entry) {
    const long len = static_cast<long>(length(entry)) + 1;
    for (long i = 0; i + len <= got; ++i)
        if (std::memcmp(buf + i, entry, static_cast<size_t>(len)) == 0 && (i == 0 || buf[i - 1] == 0)) return true;
    return false;
}

[[gnu::noinline]] void fault_here() { *static_cast<volatile int*>(nullptr) = 1; }

// This program's memory priority (0 to 5; MEMORY_PRIORITY_LOW is 2), or -1
// where the system does not report it.
int memory_priority() {
    using get_t = BOOL (OKW_API*)(HANDLE, int, LPVOID, DWORD);
    const auto get = reinterpret_cast<get_t>(okw::system_function(L"kernel32.dll", "GetProcessInformation"));
    unsigned long priority = 0;
    if (!get || !get(GetCurrentProcess(), 0 /* ProcessMemoryPriority */, &priority, sizeof priority)) return -1;
    return static_cast<int>(priority);
}

}  // namespace

int main(int argc, char** argv) {
    const char* errand = argc > 1 ? argv[1] : "";

    if (std::strcmp(errand, "--read") == 0) {
        // The recorded grant is the first preopen: a file read, a name absent,
        // and the end through kal_exit, which ends the record.
        kal_dir d = by_name("/granted");
        kal_file f{};
        if (kal_fs_open(d, "present.txt", 11, KAL_OPEN_READ, &f) != kal_ok) kal_exit(52);
        kal_fs_close_file(f);
        kal_node_info i{}; i.self_size = sizeof i;
        kal_fs_info(d, "absent.txt", 10, 0, KAL_INFO_KIND, &i);
        kal_exit(0);
    }
    if (std::strcmp(errand, "--grants") == 0) {
        if (kal_fs_preopen_count() != 2) return 41;
        kal_dir own_volume{};
        if (!locate_self(&own_volume)) return 47;
        kal_dir granted = by_name("/granted");
        if (!granted.h) return 42;
        DWORD flags = 1;
        if (!GetHandleInformation(okw::unpack(granted.h), &flags) || (flags & HANDLE_FLAG_INHERIT)) return 43;
        // A program this one starts without grants, the variable inherited.
        kal_dir volume{};
        for (kal_uintptr i = 0; i < kal_fs_preopen_count(); ++i) {
            char name[16]{}; kal_uintptr len = 0; kal_dir d{};
            if (kal_fs_preopen(i, &d, name, sizeof name, &len) == kal_ok && len == 2 && name[1] == ':') volume = d;
        }
        if (!volume.h) return 44;
        return start(volume, "--defaults", nullptr, 0, 0, nullptr, true) == 0 ? 0 : 45;
    }
    if (std::strcmp(errand, "--defaults") == 0)
        return kal_fs_preopen_count() > 2 && by_name("/granted").h == 0 ? 0 : 46;
    if (std::strcmp(errand, "--priority") == 0) {
        const int p = memory_priority();
        return p < 0 ? 69 : 70 + p;
    }
    if (std::strcmp(errand, "--fault") == 0) { fault_here(); return 0; }

    kal_dir volume{};
    if (!locate_self(&volume)) {
        std::printf("SKIP: this program's own name could not be expressed against a volume\n");
        return 0;
    }
    char tmp[1100];
    std::snprintf(tmp, sizeof tmp, "%s/okw-0.23.tmp", g_dir);
    kal_fs_mkdir(volume, tmp, length(tmp));
    kal_dir dir{};
    check(kal_fs_open_dir(volume, tmp, length(tmp), &dir) == kal_ok, "a directory for the test is opened");
    {
        kal_file f{};
        if (kal_fs_open(dir, "present.txt", 11, KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE, &f) == kal_ok) {
            kal_stream_write(kal_fs_stream(f), "x", 1);
            kal_fs_close_file(f);
        }
    }

    // GRANTS.
    check((kal_process_props() & KAL_PROCESS_PROP_GRANT_DIR) != 0, "the directory grant is claimed");
    {
        const kal_preopen grants[2] = { { dir, "/granted", 8 }, { volume, g_volume_name, 2 } };
        check(start(volume, "--grants", grants, 2, 0) == 0,
              "the started program has its grants, uninheritable, and one it starts without grants has the defaults");
    }

    // A RECORD ACROSS A START.
    {
        kal_file rec{};
        check(kal_fs_open(dir, "record", 6, KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE, &rec) == kal_ok,
              "a record file is opened");
        kal_dir_rights rights{};
        rights.self_size = sizeof rights;
        rights.flags = KAL_DIR_RECORDED | KAL_DIR_READ_ONLY;
        rights.record = rec;
        kal_dir rd{};
        check(kal_fs_dir_attenuate(dir, &rights, &rd) == kal_ok, "the directory is attenuated, recorded");
        const kal_preopen grants[2] = { { rd, "/granted", 8 }, { volume, g_volume_name, 2 } };
        check(start(volume, "--read", grants, 2, 0) == 0, "a program granted the recorded handle reads through it");
        kal_fs_close_dir(rd);
        kal_fs_close_file(rec);
        char buf[4096] = {};
        long got = 0;
        kal_file r{};
        if (kal_fs_open(dir, "record", 6, KAL_OPEN_READ, &r) == kal_ok) {
            const kal_intptr n = kal_stream_read(kal_fs_stream(r), buf, sizeof buf);
            got = n > 0 ? static_cast<long>(n) : 0;
            kal_fs_close_file(r);
        }
        check(holds(buf, got, "rpresent.txt"), "the started program's read is in its caller's record");
        check(holds(buf, got, "aabsent.txt"), "and so is the name it found absent");
        check(holds(buf, got, "e"), "and the record of the program that ended is ended");
    }

    // A PART OF A REGION THAT IS A FILE'S.
    if (kal_exec_props() & KAL_EXEC_PROP_FILE) {
        constexpr kal_uintptr block = 65536;
        kal_file f{};
        bool written = kal_fs_open(dir, "part.bin", 8, KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE, &f) == kal_ok;
        static unsigned char bytes[block];
        for (kal_uintptr i = 0; i < block; ++i) bytes[i] = static_cast<unsigned char>(i * 7 + 1);
        written = written && kal_stream_write(kal_fs_stream(f), bytes, block) == static_cast<kal_intptr>(block);
        if (f.h) kal_fs_close_file(f);
        kal_file rf{};
        auto* r = static_cast<unsigned char*>(kal_exec_alloc(3 * block));
        if (written && r && kal_fs_open(dir, "part.bin", 8, KAL_OPEN_READ, &rf) == kal_ok) {
            for (kal_uintptr i = 0; i < block; ++i) { r[i] = static_cast<unsigned char>(i + 3); r[2 * block + i] = static_cast<unsigned char>(i + 5); }
            r[block] = 9;
            check(kal_exec_map_part(r, 4096, 4096, rf, 0, 0) == kal_err_not_supported && r[block] == 9,
                  "a part this system cannot place a view at is refused, and the region is unchanged");
            check(kal_exec_map_part(r, block, block, rf, 0, 0) == kal_ok, "a part of the region is made the file's");
            bool rest = true, part = true;
            for (kal_uintptr i = 0; i < block; ++i) {
                rest = rest && r[i] == static_cast<unsigned char>(i + 3) && r[2 * block + i] == static_cast<unsigned char>(i + 5);
                part = part && r[block + i] == bytes[i];
            }
            check(part, "the part holds the file's bytes");
            check(rest, "and the rest of the region holds what was written to it");
            check(kal_exec_seal_part(r, 0, 3 * block, 0) == kal_ok && r[0] == 3 && r[2 * block] == 5,
                  "the region is sealed across its views, and reads as before");
            kal_fs_close_file(rf);
        }
        if (r) kal_exec_free(r, 3 * block);
        kal_fs_remove(dir, "part.bin", 8);
    } else {
        std::printf("  this system has no placeholders; a part of a region is not made a file's\n");
    }

    // ECONOMY.
    {
        const int mine = memory_priority();
        const int low = start(volume, "--priority", nullptr, 0, KAL_SPAWN_RESOURCES_ECONOMY, nullptr, true);
        if (low == 69 || mine < 0) std::printf("  this system does not report a program's memory priority\n");
        else {
            check(low == 72, "a program started for economy has a low memory priority");
            check(start(volume, "--priority", nullptr, 0, KAL_SPAWN_RESOURCES_PERFORMANCE, nullptr, true) == 70 + mine,
                  "and one started for performance has the system's, its starter's");
        }
    }

    // A FAULT.
    {
        kal_stream mine{}, theirs{};
        if (kal_process_channel(&mine, &theirs) == kal_ok) {
            const kal_spawn_streams streams{ {0}, {0}, theirs };
            const int s = start(volume, "--fault", nullptr, 0, 0, &streams, true);
            kal_process_channel_close(theirs);
            static char report[16384];
            kal_uintptr have = 0;
            for (;;) {
                const kal_intptr r = kal_stream_read(mine, report + have, sizeof report - 1 - have);
                if (r <= 0) break;
                have += static_cast<kal_uintptr>(r);
            }
            kal_process_channel_close(mine);
            report[have] = '\0';
            check(s == -2, "a program that faults is reported as ended by the system");
            check(std::strstr(report, "openkal: fault: ") != nullptr && std::strstr(report, "openkal:   #0 ") != nullptr,
                  "and what ends it reports the fault and its frames");
            const char* base = std::strrchr(g_self, '/');
            check(base && std::strstr(report, base + 1) != nullptr, "and names the program's own file");
#if defined(__MINGW32__)
            // A linker of this ABI keeps the symbol table in the file.
            check(std::strstr(report, "fault_here") != nullptr, "and the function that faulted");
#endif
        }
    }

    kal_fs_remove(dir, "present.txt", 11);
    kal_fs_remove(dir, "record", 6);
    kal_fs_close_dir(dir);
    kal_fs_remove(volume, tmp, length(tmp));
    std::printf("openkal-windows: openkal 0.23\n");
    return failures == 0 ? 0 : 1;
}
