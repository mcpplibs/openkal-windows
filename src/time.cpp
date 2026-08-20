#include "win.h"
#include <openkal/time.h>

namespace {

okw_u64 g_frequency = 0;

okw_u64 frequency() {
    // Read once and remembered. The initialiser is not a constant, so a
    // function-local static would need the guard a C++ runtime supplies, and
    // this arrangement has no C++ runtime. Two contexts arriving together
    // compute the same value and store it, so the race has one outcome.
    if (g_frequency == 0) {
        LARGE_INTEGER v{};
        QueryPerformanceFrequency(&v);
        g_frequency = v.QuadPart > 0 ? static_cast<okw_u64>(v.QuadPart) : 1u;
    }
    return g_frequency;
}

okw_u64 counter() {
    LARGE_INTEGER v{};
    QueryPerformanceCounter(&v);
    return static_cast<okw_u64>(v.QuadPart);
}

}  // namespace

extern "C" {

kal_duration kal_time_monotonic(void) {
    const okw_u64 f = frequency();
    const okw_u64 c = counter();
    // Divided before multiplied where the counter is large, so that a machine
    // that has been running for a month does not report a wrapped value: the
    // product of a counter and a billion overflows sixty-four bits after about
    // two seconds at a ten-megahertz frequency.
    return (c / f) * 1000000000ull + ((c % f) * 1000000000ull) / f;
}

kal_duration kal_time_wall(void) {
    FILETIME ft{};
    GetSystemTimePreciseAsFileTime(&ft);
    const okw_u64 ticks = (static_cast<okw_u64>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    // This environment counts hundreds of nanoseconds from 1601; the interface
    // counts nanoseconds from 1970. The constant is the difference, and it is
    // the whole of the translation.
    constexpr okw_u64 kEpochDifference = 116444736000000000ull;
    return ticks < kEpochDifference ? 0u : (ticks - kEpochDifference) * 100ull;
}

kal_duration kal_time_monotonic_granularity(void) {
    const okw_u64 ns = 1000000000ull / frequency();
    return ns == 0 ? 1u : ns;
}

void kal_time_sleep(kal_duration ns) {
    if (ns == 0) return;
    const okw_u64 f = frequency();
    const okw_u64 target = counter() + (ns / 1000000000ull) * f
                         + ((ns % 1000000000ull) * f) / 1000000000ull;
    // The environment's own suspension is expressed in milliseconds and rounds
    // towards whichever multiple of the scheduler's period it likes, so it is
    // asked for slightly less and the remainder is waited out against the
    // counter. The specification requires that the call not return early, and
    // an implementation that returned early would make every timed wait above
    // it wrong without reporting it.
    const okw_u64 whole_ms = ns / 1000000ull;
    if (whole_ms > 1) Sleep(static_cast<DWORD>(whole_ms - 1));
    while (counter() < target) SwitchToThread();
}

// The counter this environment supplies continues while the machine is
// suspended, which the corresponding position records. That is the opposite of
// the Linux implementation, and the difference is why the position exists.
const kal_uintptr kal_time_props =
    KAL_TIME_PROP_WALL_AVAILABLE | KAL_TIME_PROP_SLEEP_PRECISE;

}
