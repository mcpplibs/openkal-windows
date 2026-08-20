#include "win.h"
#include <openkal/abort.h>

extern "C" {

[[noreturn]] void kal_abort(const char* msg, kal_uintptr len) {
    if (msg != nullptr && len != 0) {
        void* h = GetStdHandle(STD_ERROR_HANDLE);
        if (h != INVALID_HANDLE_VALUE && h != nullptr) {
            DWORD written = 0;
            const unsigned char* p = reinterpret_cast<const unsigned char*>(msg);
            kal_uintptr done = 0;
            while (done < len) {
                if (!WriteFile(h, p + done, static_cast<DWORD>(len - done), &written, nullptr)
                    || written == 0) break;
                done += written;
            }
        }
    }
    // The environment's own means of stopping a program whose state has been
    // declared impossible. It is distinguishable from an ordinary status, which
    // is what the specification requires of it, and it runs nothing on the way
    // out --- which ExitProcess would not promise, because it runs the
    // detach notifications of every loaded module first.
    TerminateProcess(GetCurrentProcess(), 0xC0000409u /* fail fast */);
    for (;;) { }
}

// Termination is immediate. Clause 7.8: registered exit handlers and static
// destructors shall not run, and a caller must be able to reason about what
// executes after the call.
//
// TerminateProcess rather than ExitProcess, for exactly that reason: the latter
// notifies every loaded module before the process ends, and a module's
// notification is code the caller did not ask to run.
[[noreturn]] void kal_exit(int code) {
    TerminateProcess(GetCurrentProcess(), static_cast<UINT>(code));
    for (;;) { }
}

}
