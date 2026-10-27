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

int main() {
    kal_stream mine{}, theirs{};
    if (kal_process_channel(&mine, &theirs) != kal_ok) {
        std::printf("FAIL: a channel is made\n");
        return 1;
    }
    char byte = 0;
    const kal_duration started = kal_time_monotonic();
    const kal_intptr n = kal_timeout_read(mine, &byte, 1, 100000000ull /* 100 ms */);
    const kal_duration took = kal_time_monotonic() - started;
    kal_process_channel_close(theirs);
    kal_process_channel_close(mine);
    int failures = 0;
    if (n != -kal_err_again) {
        std::printf("FAIL: a bounded read of an idle pipe expires (it answered %lld)\n", static_cast<long long>(n));
        ++failures;
    }
    if (took > 400000000ull) {
        std::printf("FAIL: it expires near its bound (100 ms asked, %llu ms taken)\n",
                    static_cast<unsigned long long>(took / 1000000ull));
        ++failures;
    }
    if (failures == 0) std::printf("openkal-windows: a bounded read of an idle pipe expires near its bound\n");
    return failures == 0 ? 0 : 1;
}
