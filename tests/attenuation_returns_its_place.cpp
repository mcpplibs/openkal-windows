// A regression test: a directory attenuated and closed leaves nothing behind.
//
// `kal_fs_dir_attenuate` keeps a table of the trees it has made, 64 places for
// the life of the program. A place was taken by every attenuation and given
// back by none: closing the handle released what the tree had listed and kept
// the place. A program that grants the same directories, read-only, to each
// program it starts --- a language server and the engine it restarts --- was
// refused once 64 grants had been made in all, with every one of them closed:
// `kal_err_no_memory`, which its caller printed as "out of memory" on a machine
// with memory to spare (mcpp-language-server issue 86: the 22nd engine start of
// a session with three read-only grants, the 17th with four).
//
// A tree that keeps a record still holds its place until the program ends,
// which is when its record is ended; this test attenuates without one.
#include <cstdio>
#include <string>
#include <openkal/fs.h>
#include <openkal/types.h>
import mcpplibs.mtest;

using namespace mcpplibs::mtest;

namespace {

void check(bool ok, const char* what) { expect(ok) << what; }

} // namespace

UTest attenuation_returns_its_place_test{"attenuation_returns_its_place", [] {
    kal_dir cwd{};
    bool haveDir = false;
    {
        const kal_uintptr n = kal_fs_preopen_count();
        for (kal_uintptr i = 0; i < n && !haveDir; ++i) {
            kal_dir d{};
            char nm[1024];
            kal_uintptr len = 0;
            if (kal_fs_preopen(i, &d, nm, sizeof nm, &len) != kal_ok) continue;
            cwd = d;
            haveDir = true;
        }
    }
    if (!haveDir) {
        fail("a preopened directory to test in");
        return;
    }

    // Four times the table, each attenuation closed before the next.
    int refused = 0, first_refused = -1;
    for (int i = 0; i < 256; ++i) {
        kal_dir_rights rights{};
        rights.self_size = sizeof rights;
        rights.flags = (i % 2) ? (KAL_DIR_READ_ONLY | KAL_DIR_UNCHANGING) : KAL_DIR_READ_ONLY;
        kal_dir held{};
        const int rc = kal_fs_dir_attenuate(cwd, &rights, &held);
        if (rc != kal_ok) {
            if (first_refused < 0) { first_refused = i; std::printf("  attenuation %d -> %d\n", i + 1, rc); }
            ++refused;
            continue;
        }
        // The handle is of use while it is held: a name beneath it answers.
        kal_node_info info = {};
        info.self_size = sizeof info;
        check(kal_fs_info(held, "okw-attenuation-probe.tmp", 25, 0, KAL_INFO_KIND, &info) == kal_ok, "the attenuated directory answers");
        kal_fs_close_dir(held);
    }
    check(refused == 0, "256 attenuations, each closed before the next, are all made");

    // And the table still bounds what is HELD at once: 64 trees, and the 65th is
    // refused while they are; closing them gives every place back.
    kal_dir many[80] = {};
    int made = 0;
    for (int i = 0; i < 80; ++i) {
        kal_dir_rights rights{};
        rights.self_size = sizeof rights;
        rights.flags = KAL_DIR_READ_ONLY | KAL_DIR_UNCHANGING;
        if (kal_fs_dir_attenuate(cwd, &rights, &many[made]) != kal_ok) break;
        ++made;
    }
    std::printf("  held at once: %d\n", made);
    check(made >= 1 && made < 80, "the trees held at once are bounded");
    for (int i = 0; i < made; ++i) kal_fs_close_dir(many[i]);
    {
        kal_dir_rights rights{};
        rights.self_size = sizeof rights;
        rights.flags = KAL_DIR_READ_ONLY | KAL_DIR_UNCHANGING;
        kal_dir again{};
        const int rc = kal_fs_dir_attenuate(cwd, &rights, &again);
        check(rc == kal_ok, "a directory is attenuated again once the held ones are closed");
        if (rc == kal_ok) kal_fs_close_dir(again);
    }

    std::printf("openkal-windows: a closed attenuation gives its place back\n");
}};
