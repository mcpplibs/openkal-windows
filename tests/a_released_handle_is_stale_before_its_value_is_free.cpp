// A handle is retired before its value is closed (0.21.1 and 0.22.1; openkal-linux#53,
// the same construction).
//
// The system gives a closed value to the next handle made in any context. Until
// then a connection, a listener and a datagram socket were closed first and
// retired second: a file opened by another context between the two took the
// value with the generation the socket's handle still had, and the retire then
// made the file's handle stale, so its stream was no stream and its reads
// returned nothing of the file.
//
// One context accepts connections and closes them, one connects and closes, and
// this one opens, reads and closes a file. Every read returns the file.
#include <cstring>
#include <openkal/fs.h>
#include <openkal/net.h>
#include <openkal/stream.h>
#include <openkal/task.h>
#include <openkal/time.h>
#include <openkal/types.h>
import mcpplibs.mtest;

using namespace mcpplibs::mtest;

namespace {

constexpr char kName[] = "okw_retire_probe.txt";
constexpr char kText[] = "the file's bytes";   // 16

volatile kal_u32 g_stop = 0;
volatile long g_served = 0;
kal_net_listener g_listener{};
kal_endpoint g_at{};

void accepting(void*) {
    for (;;) {
        kal_net_conn c{};
        if (kal_net_accept(g_listener, &c) != kal_ok) break;
        kal_stream_write(kal_net_stream(c), "okw", 3);
        kal_net_close(c);
        g_served = g_served + 1;
        if (g_stop) break;
    }
}

void connecting(void*) {
    while (!g_stop) {
        kal_net_conn c{};
        if (kal_net_connect(&g_at, &c) == kal_ok) kal_net_close(c);
    }
    // One more, so the accepting context leaves its wait and sees the word.
    kal_net_conn last{};
    if (kal_net_connect(&g_at, &last) == kal_ok) kal_net_close(last);
}

}  // namespace

UTest a_released_handle_is_stale_before_its_value_is_free{
    "a_released_handle_is_stale_before_its_value_is_free", [] {
    // The working directory, which is the first directory the environment supplies.
    kal_dir dir{}; char name[4096]; kal_uintptr len = 0;
    expect(fatal(kal_fs_preopen(0, &dir, name, sizeof name, &len) == kal_ok));
    {
        kal_file f{};
        expect(fatal(kal_fs_open(dir, kName, sizeof kName - 1,
                                 KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE, &f) == kal_ok));
        expect(fatal(kal_stream_write(kal_fs_stream(f), kText, 16) == 16));
        kal_fs_close_file(f);
    }

    kal_endpoint any{};
    any.addr[0] = 127; any.addr[3] = 1; any.addr_len = 4;
    expect(fatal(kal_net_listen(&any, &g_listener) == kal_ok));
    expect(fatal(kal_net_listener_local(g_listener, &g_at) == kal_ok));

    kal_task a{}, b{};
    expect(fatal(kal_task_start(accepting, nullptr, &a) == kal_ok));
    expect(fatal(kal_task_start(connecting, nullptr, &b) == kal_ok));

    long opened = 0, stale = 0, other = 0;
    const kal_duration until = kal_time_monotonic() + 3'000'000'000ull;
    while (kal_time_monotonic() < until) {
        for (int i = 0; i < 64; ++i) {
            kal_file f{};
            if (kal_fs_open(dir, kName, sizeof kName - 1, KAL_OPEN_READ, &f) != kal_ok) continue;
            ++opened;
            char buf[32]{};
            const kal_intptr n = kal_stream_read(kal_fs_stream(f), buf, sizeof buf);
            if (n < 0) ++stale;
            else if (n != 16 || std::memcmp(buf, kText, 16) != 0) ++other;
            kal_fs_close_file(f);
        }
    }
    g_stop = 1;
    kal_task_join(b);
    kal_task_join(a);
    kal_net_close_listener(g_listener);

    expect(gt(opened, 0L));
    expect(gt(static_cast<long>(g_served), 0L)) << "no connection was closed beside the opens; the test measured nothing";
    expect(eq(stale, 0L)) << "files whose handle was stale when its stream was taken, of " << opened;
    expect(eq(other, 0L)) << "files whose read was not the file, of " << opened;

    kal_fs_remove(dir, kName, sizeof kName - 1);
}};
