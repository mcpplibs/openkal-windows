// A regression test: a node has one identity, however it was reached.
//
// `kal_fs_info` (a name) and `kal_fs_file_info` (an open file) both report an
// identity of two words, the volume's and the file's. The first word came from
// two places: by handle, FileFsVolumeInformation's serial number, 32 bits; by
// name, where the system has the record of Windows 11 24H2
// (FileStatBasicInformation), that record's serial number, the 64 bits the
// file system keeps. On builds 26100 and later the two words differed for
// every file: a file a program had opened and the same file asked about by
// name were two nodes.
//
// It surfaced three packages away. clangd keys the files it has entered by
// identity; its include analysis asked for a header by its resolved name, was
// answered with the other identity, found nothing and dereferenced the empty
// result (mcpp-language-server issue 86: the engine ended on every module unit
// that includes a library header, on Windows 11 24H2 and on nothing earlier).
//
// A SYSTEM WITHOUT THE RECORD CANNOT FAIL THIS. Windows Server 2022 (build
// 20348) answers a name by the older record or by opening, both of which use
// the handle's word, and wine has no record at all: the test reports there and
// proves nothing. The row that proves it is a 26100 build, which CI has.
#include <cstdio>
#include <string>
#include <openkal/fs.h>
#include <openkal/types.h>
import mcpplibs.mtest;

using namespace mcpplibs::mtest;

namespace {

void check(bool ok, const char* what) { expect(ok) << what; }

bool same(const kal_node_info& a, const kal_node_info& b) {
    return a.identity[0] == b.identity[0] && a.identity[1] == b.identity[1];
}

} // namespace

UTest one_identity_for_a_node_test{"one_identity_for_a_node", [] {
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

    static const char names[2][32] = { "okw-one-identity-a.tmp", "okw-one-identity-b.tmp" };
    kal_node_info opened[2] = {};
    for (int i = 0; i < 2; ++i) {
        const kal_uintptr len = std::char_traits<char>::length(names[i]);
        kal_file f{};
        const int rc = kal_fs_open(cwd, names[i], len, KAL_OPEN_READ | KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE, &f);
        check(rc == kal_ok, "a file is created");
        if (rc != kal_ok) return;

        opened[i].self_size = sizeof opened[i];
        check(kal_fs_file_info(f, KAL_INFO_ALL, &opened[i]) == kal_ok, "the open file answers");
        check((opened[i].present & KAL_INFO_IDENTITY) != 0u, "the open file has an identity");

        // By name twice: the first enquiry of a volume may be answered by
        // opening the node, and the ones after it by the record alone. While
        // the file is open, and below once it is closed.
        for (int round = 0; round < 2; ++round) {
            kal_node_info named = {};
            named.self_size = sizeof named;
            check(kal_fs_info(cwd, names[i], len, 0, KAL_INFO_ALL, &named) == kal_ok, "the name answers");
            check((named.present & KAL_INFO_IDENTITY) != 0u, "the name has an identity");
            std::printf("  %s: open %llx:%llx, by name (%d) %llx:%llx\n", names[i],
                        static_cast<unsigned long long>(opened[i].identity[0]), static_cast<unsigned long long>(opened[i].identity[1]),
                        round, static_cast<unsigned long long>(named.identity[0]), static_cast<unsigned long long>(named.identity[1]));
            check(same(opened[i], named), "an open file is the node its name refers to");
        }
        kal_fs_close_file(f);

        kal_node_info after = {};
        after.self_size = sizeof after;
        check(kal_fs_info(cwd, names[i], len, KAL_FS_NO_RESOLVE, KAL_INFO_ALL, &after) == kal_ok, "the name answers, the file closed");
        check(same(opened[i], after), "the name is the same node after the file is closed");
    }
    // And two files are two nodes: the identity is not a constant.
    check(!same(opened[0], opened[1]), "two files have two identities");

    // The directory itself, by a name of several components.
    {
        static const char dir[] = "okw-one-identity-d";
        kal_fs_mkdir(cwd, dir, sizeof dir - 1);   // or it is there from a run that was interrupted
        static const char inner[] = "okw-one-identity-d/inner.tmp";
        kal_file f{};
        const int rc = kal_fs_open(cwd, inner, sizeof inner - 1, KAL_OPEN_READ | KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE, &f);
        check(rc == kal_ok, "a file is created beneath a directory");
        if (rc == kal_ok) {
            kal_node_info o = {}, n = {};
            o.self_size = sizeof o; n.self_size = sizeof n;
            check(kal_fs_file_info(f, KAL_INFO_ALL, &o) == kal_ok, "the open file answers");
            check(kal_fs_info(cwd, inner, sizeof inner - 1, 0, KAL_INFO_ALL, &n) == kal_ok, "its name of two components answers");
            check(same(o, n), "a name of several components is the node that was opened");
            kal_fs_close_file(f);
            kal_fs_remove(cwd, inner, sizeof inner - 1);
        }
        kal_fs_remove(cwd, dir, sizeof dir - 1);
    }
    for (int i = 0; i < 2; ++i) kal_fs_remove(cwd, names[i], std::char_traits<char>::length(names[i]));

    std::printf("openkal-windows: an open file is the node its name refers to\n");
}};
