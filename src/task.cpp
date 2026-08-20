#include "win.h"
#include <openkal/task.h>
#include <openkal/time.h>
#include <openkal/memory.h>

// Execution contexts, and the primitive they are built upon.
//
// This environment supplies both directly, and the second is the interesting
// one: WaitOnAddress compares a word with an expected value and suspends
// without an intervening opportunity for the value to change unobserved, which
// is exactly what openkal.task declares and what a caller cannot construct for
// itself. openkal's primitive was drawn from the futex of one kernel; that a
// second environment offers the same operation, under a different name and
// with no shared ancestry, is evidence that the primitive is the shape of the
// thing rather than the shape of one kernel.

namespace {

struct context {
    void (*entry)(void*);
    void*  arg;
    void*  thread;
};

DWORD __stdcall run(void* p) {
    auto* c = static_cast<context*>(p);
    c->entry(c->arg);
    return 0;
}

}  // namespace

extern "C" {

int kal_task_start(void (*entry)(void*), void* arg, kal_task* out) {
    if (entry == nullptr || out == nullptr) return kal_err_invalid;
    auto* c = static_cast<context*>(kal_alloc(sizeof(context), alignof(context)));
    if (!c) return kal_err_no_memory;
    c->entry = entry; c->arg = arg;
    // The stack is the implementation's, which is what the specification says
    // of it: an environment that does not allocate stacks separately cannot
    // honour a request for one, so there is no parameter for it.
    void* h = CreateThread(nullptr, 0, run, c, 0, nullptr);
    if (!h) {
        const int e = okw::translate_win32(GetLastError());
        kal_free(c, sizeof(context), alignof(context));
        return e;
    }
    c->thread = h;
    *out = kal_task{ reinterpret_cast<kal_uintptr>(c) };
    return kal_ok;
}

int kal_task_join(kal_task t) {
    auto* c = reinterpret_cast<context*>(t.h);
    if (!c) return kal_err_invalid;
    const DWORD r = WaitForSingleObject(c->thread, INFINITE);
    const int e = r == WAIT_OBJECT_0 ? kal_ok : okw::translate_win32(GetLastError());
    CloseHandle(c->thread);
    kal_free(c, sizeof(context), alignof(context));
    return e;
}

void kal_task_yield(void) { SwitchToThread(); }

kal_uintptr kal_task_current(void) { return static_cast<kal_uintptr>(GetCurrentThreadId()); }

int kal_task_wait(const kal_u32* word, kal_u32 expected,
                  kal_u64 timeout_ns) {
    auto* address = const_cast<volatile void*>(static_cast<const volatile void*>(word));

    if (timeout_ns == 0) {
        kal_u32 compare = expected;
        if (WaitOnAddress(address, &compare, 4, INFINITE)) return kal_ok;
        const unsigned long e = GetLastError();
        return e == ERROR_TIMEOUT ? kal_err_again : okw::translate_win32(e);
    }

    // A timeout is a floor and not a hint.
    //
    // This environment takes a whole number of milliseconds and measures it
    // against a clock whose tick is longer than that, so a wait given thirty
    // milliseconds returns after fifteen. A caller that asked to be suspended
    // for a duration and was returned to before it elapsed has been given a
    // wrong answer, and every timed wait built upon this one inherits it.
    //
    // So the deadline is computed once from the monotonic source and the wait
    // is re-entered until that source has passed it. The timeout is reported
    // only when the time has genuinely gone.
    const kal_u64 deadline = kal_time_monotonic() + timeout_ns;
    for (;;) {
        const kal_u64 now = kal_time_monotonic();
        if (now >= deadline) return kal_err_again;
        const kal_u64 remaining = deadline - now;
        const kal_u64 rounded = (remaining + 999999ull) / 1000000ull;
        const DWORD ms = rounded > 0xfffffffeull ? 0xfffffffeu
                                                 : static_cast<DWORD>(rounded ? rounded : 1);
        kal_u32 compare = expected;
        if (WaitOnAddress(address, &compare, 4, ms)) return kal_ok;
        const unsigned long e = GetLastError();
        if (e != ERROR_TIMEOUT) return okw::translate_win32(e);
    }
}

int kal_task_wake(const kal_u32* word, kal_uintptr count, kal_uintptr* woken) {
    void* address = const_cast<void*>(static_cast<const void*>(word));
    if (count == 0) { if (woken) *woken = 0; return kal_ok; }
    if (count == 1) WakeByAddressSingle(address);
    else            WakeByAddressAll(address);
    // This environment does not report how many contexts it woke. The count is
    // reported as the number that were asked for rather than invented: a
    // caller uses it to decide whether to wake again, and an implementation
    // that reported zero would make it wake for ever.
    if (woken) *woken = count;
    return kal_ok;
}

// A context started here observes the thread-local storage of the toolchain
// that compiled the program: this environment's loader establishes it for every
// thread it creates, which is why the position can be reported here without
// this implementation doing anything to earn it.
const kal_uintptr kal_task_props =
    KAL_TASK_PROP_PREEMPTIVE | KAL_TASK_PROP_PARALLEL
  | KAL_TASK_PROP_WAIT_TIMEOUT | KAL_TASK_PROP_THREAD_LOCAL;

}
