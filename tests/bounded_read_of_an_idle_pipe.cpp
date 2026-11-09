// A bounded read of a pipe with nothing in it expires near its bound (0.13.3).
//
// The wait counted its sleeps of one millisecond as milliseconds, and a sleep
// of one millisecond lasts until the next tick of the system's timer --- 15.6
// ms by default --- so a 100 ms bound waited about a second and a half. The
// read expires here within four times its bound, which a counted loop on a
// default timer does not.
#include <cstdio>
#include <openkal/process.h>
#include <openkal/stream.h>
#include <openkal/time.h>
#include <openkal/timeout.h>
#include <openkal/types.h>
import mcpplibs.mtest;

using namespace mcpplibs::mtest;

UTest bounded_read_of_an_idle_pipe_test{"bounded_read_of_an_idle_pipe", [] {
    kal_stream mine{}, theirs{};
    if (kal_process_channel(&mine, &theirs) != kal_ok) {
        fail("a channel is made");
        return;
    }
    char byte = 0;
    const kal_duration started = kal_time_monotonic();
    const kal_intptr n = kal_timeout_read(mine, &byte, 1, 100000000ull /* 100 ms */);
    const kal_duration took = kal_time_monotonic() - started;
    kal_process_channel_close(theirs);
    kal_process_channel_close(mine);
    expect(n == -kal_err_again) << "a bounded read of an idle pipe expires (it answered " << static_cast<long long>(n) << ")";
    expect(took <= 400000000ull) << "it expires near its bound (100 ms asked, "
                                 << static_cast<unsigned long long>(took / 1000000ull) << " ms taken)";
}};
