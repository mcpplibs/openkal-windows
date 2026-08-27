#include "win32.h"
#include <openkal/terminal.h>

// openkal.terminal upon this environment's console operations.
//
// THE TWO POSITIONS THIS INTERFACE DEFINES ARE TWO CONSOLE FLAGS, AND THEY ARE
// NOT THE SAME TWO A UNIX TERMINAL HAS. This environment assembles lines under
// ENABLE_LINE_INPUT and shows what is typed under ENABLE_ECHO_INPUT, which is
// the same division openkal.terminal draws; what differs is that the flags live
// on the INPUT handle and this interface takes a stream. A caller asking about
// the output handle is answered for the output handle, which reports neither
// position, and that is correct rather than a limitation: the mode of an output
// console is not what the interface asks about.

namespace {

void* handle_of(kal_stream s) { return reinterpret_cast<void*>(s.h); }
bool  valid(void* h) { return h != nullptr && h != INVALID_HANDLE_VALUE; }

// This environment's console input flags.
constexpr DWORD enable_line_input = 0x0002;
constexpr DWORD enable_echo_input = 0x0004;

}  // namespace

extern "C" {

int kal_terminal_get_mode(kal_stream s, kal_uintptr* mode) {
    if (mode == nullptr) return kal_err_invalid;
    void* h = handle_of(s);
    if (!valid(h)) return kal_err_invalid;

    DWORD m = 0;
    // Reading a console's mode succeeds for a console and fails otherwise, which
    // is the same enquiry kal_stream_props performs. A stream that is not a
    // console is therefore reported as unsupported rather than as an error of
    // this environment.
    if (!GetConsoleMode(h, &m)) return kal_err_not_supported;

    kal_uintptr out = 0;
    if ((m & enable_line_input) != 0) out |= KAL_TERM_LINE_EDIT;
    if ((m & enable_echo_input) != 0) out |= KAL_TERM_ECHO;
    *mode = out;
    return kal_ok;
}

int kal_terminal_set_mode(kal_stream s, kal_uintptr mode) {
    void* h = handle_of(s);
    if (!valid(h)) return kal_err_invalid;

    // READ, MODIFY, WRITE. The console mode carries processed input, mouse
    // input, window input and virtual terminal processing, none of which this
    // interface names. Writing a word composed from the two positions alone
    // would turn all of them off, and a program that asked only to stop echoing
    // would find its console changed in ways it did not ask for.
    DWORD m = 0;
    if (!GetConsoleMode(h, &m)) return kal_err_not_supported;

    if ((mode & KAL_TERM_LINE_EDIT) != 0) m |=  enable_line_input;
    else                                  m &= ~enable_line_input;
    if ((mode & KAL_TERM_ECHO) != 0)      m |=  enable_echo_input;
    else                                  m &= ~enable_echo_input;

    // A position this implementation does not distinguish is ignored rather than
    // refused, which clause 6.2 requires of a word.
    if (!SetConsoleMode(h, m)) return kal_err_not_supported;
    return kal_ok;
}

int kal_terminal_size(kal_stream s, kal_uintptr* cols, kal_uintptr* rows) {
    if (cols == nullptr || rows == nullptr) return kal_err_invalid;
    void* h = handle_of(s);
    if (!valid(h)) return kal_err_invalid;

    CONSOLE_SCREEN_BUFFER_INFO_ info{};
    // Both outputs are left untouched on failure, which the interface requires.
    if (!GetConsoleScreenBufferInfo(h, &info)) return kal_err_not_supported;

    // THE WINDOW AND NOT THE BUFFER. This environment's screen buffer may be
    // taller than the window that shows it, and a program drawing a full screen
    // against the buffer's height would scroll its own output away. The window
    // is what a caller asking for the size of the display means.
    *cols = static_cast<kal_uintptr>(info.srWindow.Right  - info.srWindow.Left + 1);
    *rows = static_cast<kal_uintptr>(info.srWindow.Bottom - info.srWindow.Top  + 1);
    return kal_ok;
}

kal_uintptr kal_terminal_props(kal_stream s) {
    void* h = handle_of(s);
    if (!valid(h)) return 0;

    kal_uintptr p = 0;

    DWORD m = 0;
    if (GetConsoleMode(h, &m)) p |= KAL_TERM_PROP_MODE;

    // Asked for rather than derived from the first: an input console answers the
    // mode and not the size, and an output console answers the size and not the
    // mode. Deriving either from the other would make the word claim a facility
    // the next call refuses.
    CONSOLE_SCREEN_BUFFER_INFO_ info{};
    if (GetConsoleScreenBufferInfo(h, &info)) p |= KAL_TERM_PROP_SIZE;

    return p;
}

}  // extern "C"
