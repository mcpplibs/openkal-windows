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

// THE SIZE A CONTEXT IS GIVEN WHEN IT ASKS FOR NONE. This environment would
// reserve what the program's header states, 1 MiB by default, and the two other
// implementations give a context the 8 MiB the host's C library on their systems
// gives a thread; a program that asks for nothing --- C++'s `std::thread' cannot
// ask --- is given the same room on all three. It is a reservation, committed as
// the stack grows, so the size costs address space and not memory.
//
// No guard is added. This environment places its own below the committed part
// of the stack and moves it as the stack grows, and the compilers that target it
// probe a frame larger than a page one page at a time, so a large frame cannot
// step over it.
constexpr unsigned long long kDefaultStack = 8ull * 1024u * 1024u;

// What a request for `want' bytes is reserved as. The bounds this environment
// reports to the context include the pages it keeps for its guard, so the
// reservation exceeds the request by more than those; what the context is told
// by kal_task_stack is then at least what it asked for.
constexpr unsigned long long kSlack = 256u * 1024u;

unsigned long long stack_for(unsigned long long want) {
    if (want > (1ull << 46)) return 0;
    const unsigned long long w = (want + 0xffffu) & ~0xffffull;   // the reservation granularity
    return (w > kDefaultStack ? w : kDefaultStack) + kSlack;
}

constexpr DWORD stack_size_param_is_a_reservation = 0x00010000;

int start(void (*entry)(void*), void* arg, unsigned long long want, kal_task* out) {
    if (entry == nullptr || out == nullptr) return kal_err_invalid;
    const unsigned long long bytes = stack_for(want);
    if (bytes == 0) return kal_err_no_memory;
    auto* c = static_cast<context*>(kal_alloc(sizeof(context), alignof(context)));
    if (!c) return kal_err_no_memory;
    c->entry = entry; c->arg = arg;
    void* h = CreateThread(nullptr, bytes, run, c, stack_size_param_is_a_reservation, nullptr);
    if (!h) {
        const int e = okw::translate_win32(GetLastError());
        kal_free(c, sizeof(context), alignof(context));
        return e;
    }
    c->thread = h;
    *out = kal_task{ reinterpret_cast<kal_uintptr>(c) };
    return kal_ok;
}

}  // namespace

extern "C" {

int kal_task_start(void (*entry)(void*), void* arg, kal_task* out) {
    return start(entry, arg, 0, out);
}

// A least size, version 0.16: at least the size asked for, and never less than
// the default.
int kal_task_start_sized(void (*entry)(void*), void* arg, kal_uintptr stack_size,
                         kal_task* out) {
    return start(entry, arg, stack_size, out);
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

// The stack the calling context runs on. Version 0.15.
//
// ASKED OF THE ENVIRONMENT, WHICH BUILT IT. Every context here is a thread of
// this system's own --- the first one included --- so there is one question and
// one answer for all of them: the loader arranged the region the thread runs on
// and this call reports it. Nothing is recorded and nothing is measured, and the
// call itself cannot fail, which is why the only refusal this operation has is
// an argument that is not there.
int kal_task_stack(void** base, kal_uintptr* size) {
    if (base == nullptr || size == nullptr) return kal_err_invalid;
    unsigned long long low = 0, high = 0;
    GetCurrentThreadStackLimits(&low, &high);
    if (high <= low) return kal_err_io;
    *base = reinterpret_cast<void*>(static_cast<okw_uptr>(low));
    *size = static_cast<kal_uintptr>(high - low);
    return kal_ok;
}

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

// How many contexts can run at the same moment. Version 0.10.
//
// Added because its absence was a WRONG ANSWER and not a refusal: the
// property word says whether contexts run at once and not how many can, so a C
// library above answered 1 with no error and a program sizing a pool of workers
// got one worker.
//
// THE ACTIVE MASK AND NOT THE COUNT FIELD. This record carries both, and they
// differ whenever a program is confined to part of the machine --- which is the
// case a program sizing itself most needs to get right.
kal_uintptr kal_task_parallelism(void) {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    kal_uintptr count = 0;
    for (unsigned long long bit = info.dwActiveProcessorMask; bit; bit &= bit - 1)
        ++count;
    if (count) return count;
    // Zero is "cannot say", and openkal distinguishes it from one on purpose.
    return static_cast<kal_uintptr>(info.dwNumberOfProcessors);
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
kal_uintptr kal_task_props(void) { return
    KAL_TASK_PROP_PREEMPTIVE | KAL_TASK_PROP_PARALLEL
  | KAL_TASK_PROP_WAIT_TIMEOUT | KAL_TASK_PROP_THREAD_LOCAL
  | KAL_TASK_PROP_PRIORITY; }

// THE PHYSICAL CORES BENEATH THE PROCESSORS THIS PROGRAM MAY RUN ON. The system
// lists each core with the processors of it (RelationProcessorCore); a core
// counts when one of its processors is in the process's affinity mask --- of
// processor group 0, which is the set kal_task_parallelism counts here, so the
// two answers are about the same processors. Zero is "cannot say".
kal_uintptr kal_task_cores(void) {
    unsigned long long process = 0, system = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &process, &system)) return 0;
    DWORD length = 0;
    GetLogicalProcessorInformationEx(0 /* RelationProcessorCore */, nullptr, &length);
    if (length == 0) return 0;
    auto* buffer = static_cast<unsigned char*>(kal_alloc(length, 16));
    if (!buffer) return 0;
    kal_uintptr cores = 0;
    if (GetLogicalProcessorInformationEx(0, buffer, &length)) {
        // SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX: Relationship and Size, then
        // PROCESSOR_RELATIONSHIP, whose GroupCount is at 30 and whose first
        // GROUP_AFFINITY (Mask, then Group) is at 32.
        for (DWORD at = 0; at + 48 <= length;) {
            const unsigned char* record = buffer + at;
            DWORD size = 0;
            for (int i = 0; i < 4; ++i) size |= static_cast<DWORD>(record[4 + i]) << (8 * i);
            if (size == 0) break;
            unsigned long long mask = 0;
            for (int i = 0; i < 8; ++i) mask |= static_cast<unsigned long long>(record[32 + i]) << (8 * i);
            const unsigned group = static_cast<unsigned>(record[40]) | (static_cast<unsigned>(record[41]) << 8);
            if (group == 0 && (mask & process)) ++cores;
            at += size;
        }
    }
    kal_free(buffer, length, 16);
    return cores;
}

// THE CALLING THREAD'S CLAIM. Background mode lowers the thread's processor,
// I/O and memory priority together, which is this system's word for work that
// runs when nothing else wants the machine; below-normal is the lower claim
// short of it. Each other claim first leaves background mode. A thread may
// raise its own priority within its process's class.
int kal_task_set_priority(kal_uintptr priority) {
    constexpr int kBackgroundBegin = 0x00010000, kBackgroundEnd = 0x00020000;
    constexpr int kNormal = 0, kBelowNormal = -1;
    if (priority != KAL_TASK_PRIORITY_DEFAULT && priority != KAL_TASK_PRIORITY_LOW
        && priority != KAL_TASK_PRIORITY_BACKGROUND)
        return kal_err_invalid;
    HANDLE self = GetCurrentThread();
    if (priority == KAL_TASK_PRIORITY_BACKGROUND) {
        if (!SetThreadPriority(self, kNormal)) return okw::translate_win32(GetLastError());
        if (SetThreadPriority(self, kBackgroundBegin) || GetLastError() == 402 /* ERROR_THREAD_MODE_ALREADY_BACKGROUND */)
            return kal_ok;
        // AN ENVIRONMENT WITHOUT BACKGROUND MODE (Wine refuses it) is given the
        // scheduling half of it: the idle priority, the lowest a thread may
        // set for itself.
        constexpr int kIdle = -15;   // THREAD_PRIORITY_IDLE
        return SetThreadPriority(self, kIdle) ? kal_ok : okw::translate_win32(GetLastError());
    }
    // Leaving background mode is refused to a thread not in it, and by an
    // environment without the mode; in either the thread was not in it, and
    // the claim below is what decides the answer.
    SetThreadPriority(self, kBackgroundEnd);
    if (!SetThreadPriority(self, priority == KAL_TASK_PRIORITY_LOW ? kBelowNormal : kNormal))
        return okw::translate_win32(GetLastError());
    return kal_ok;
}

}
