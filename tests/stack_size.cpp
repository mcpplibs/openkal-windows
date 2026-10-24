// The least stack size a started context is given (openkal 0.16).
//
// WHAT IS OBSERVED IS ROOM: a recursion of three quarters of the request
// completes, and the context is told at least the size it asked for. Asking for
// nothing gives the 8 MiB the other two implementations give.
#include <cstdio>
#include <openkal/task.h>
#include <openkal/types.h>

namespace {

int failures = 0;

void check(bool held, const char* what) {
    std::printf("  %s  %s\n", held ? "held" : "FAIL", what);
    if (!held) ++failures;
}

long recurse(long n);
long (*volatile g_recurse)(long) = recurse;
long recurse(long n) {
    volatile char pad[1000];
    pad[0] = static_cast<char>(n);
    if (n == 0) return 0;
    return g_recurse(n - 1) + pad[0];
}

struct probe { kal_uintptr ask; kal_uintptr told; volatile int done; };

void room(void* p) {
    auto* q = static_cast<probe*>(p);
    void* base = nullptr; kal_uintptr size = 0;
    if (kal_task_stack(&base, &size) == kal_ok) q->told = size;
    g_recurse(static_cast<long>(q->ask / 1024 * 3 / 4));
    q->done = 1;
}

}  // namespace

int main() {
    const kal_uintptr asks[] = { 1u << 20, 16u << 20, 64u << 20 };
    for (kal_uintptr ask : asks) {
        probe q{ ask, 0, 0 };
        kal_task t{};
        check(kal_task_start_sized(room, &q, ask, &t) == kal_ok, "a context with a least stack size starts");
        kal_task_join(t);
        std::printf("  asked %llu, told %llu\n", (unsigned long long)ask, (unsigned long long)q.told);
        check(q.told >= ask, "the context is told at least the size asked for");
        check(q.done == 1, "the context has the room it asked for");
    }
    probe d{ 0, 0, 0 };
    kal_task t{};
    check(kal_task_start(room, &d, &t) == kal_ok, "a context starts");
    kal_task_join(t);
    std::printf("  asked nothing, told %llu\n", (unsigned long long)d.told);
    check(d.told >= (8u << 20), "a context that asks for nothing is given 8 MiB");

    kal_task never{};
    check(kal_task_start_sized(room, nullptr, ~kal_uintptr{0} - 4095, &never) == kal_err_no_memory,
          "a stack larger than the address space is reported as exhaustion");
    std::printf("openkal-windows: a least stack size, %s\n", failures ? "FAILED" : "held");
    return failures == 0 ? 0 : 1;
}
