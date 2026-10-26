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
constexpr DWORD enable_processed_input = 0x0001;
constexpr DWORD enable_line_input      = 0x0002;
constexpr DWORD enable_echo_input      = 0x0004;
constexpr DWORD enable_virtual_terminal_input = 0x0200;

// KAL_TERM_PASS_CONTROL IS ENABLE_PROCESSED_INPUT, INVERTED. This environment
// keeps the keystrokes it reserves --- the interrupt, and the pair that stops
// and starts output --- behind one flag, so the position is set exactly when
// that flag is clear. The two environments this specification is otherwise
// implemented on spread the same reservation over three flags of their own;
// what the position states is that none of them reserves anything, which is one
// question on either side.

}  // namespace

namespace {
// An output handle of a console answers this; an input handle does not.
bool output_handle(void* h) {
    CONSOLE_SCREEN_BUFFER_INFO_ info{};
    return GetConsoleScreenBufferInfo(h, &info) != 0;
}
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

    // A CONSOLE'S OUTPUT HANDLE HAS ITS OWN MODE, WHOSE BITS SHARE NUMBERS WITH
    // THE INPUT'S (0.17): the bit that is echo on input is the interpretation
    // of control sequences on output. An output handle answers that position
    // and no other.
    if (output_handle(h)) {
        *mode = (m & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 ? KAL_TERM_SEQUENCES : 0;
        return kal_ok;
    }

    kal_uintptr out = 0;
    if ((m & enable_line_input) != 0)      out |= KAL_TERM_LINE_EDIT;
    if ((m & enable_echo_input) != 0)      out |= KAL_TERM_ECHO;
    if ((m & enable_processed_input) == 0) out |= KAL_TERM_PASS_CONTROL;
    // KAL_TERM_PASS_INPUT IS VIRTUAL TERMINAL INPUT WITH LINE INPUT OFF.
    //
    // Measured on a console this implementation's tests allocate, with the keys
    // written into its input as the key events a keyboard produces. With line
    // input off and virtual terminal input off, the return key arrives as 0x0d
    // and Ctrl+J arrives as NOTHING: the console consumes the key and delivers
    // no byte, which is an alteration of what was typed. With virtual terminal
    // input on, the return key is 0x0d and Ctrl+J is 0x0a --- the two bytes the
    // other environments deliver with the position set. With line input on,
    // the return key ends a line as 0x0d 0x0a and no switch changes that, so the
    // position reads clear there.
    if ((m & enable_line_input) == 0 && (m & enable_virtual_terminal_input) != 0)
        out |= KAL_TERM_PASS_INPUT;
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
    if (output_handle(h)) {
        const DWORD want = (mode & KAL_TERM_SEQUENCES) != 0
            ? (m | ENABLE_VIRTUAL_TERMINAL_PROCESSING) : (m & ~ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        // A console before this system's tenth version does not interpret the
        // sequences and refuses the bit; the mode read back says so.
        if (want != m) SetConsoleMode(h, want);
        return kal_ok;
    }
    const bool unaltered = (m & enable_line_input) == 0 && (m & enable_virtual_terminal_input) != 0;

    if ((mode & KAL_TERM_LINE_EDIT) != 0) m |=  enable_line_input;
    else                                  m &= ~enable_line_input;
    if ((mode & KAL_TERM_ECHO) != 0)      m |=  enable_echo_input;
    else                                  m &= ~enable_echo_input;
    if ((mode & KAL_TERM_PASS_CONTROL) != 0) m &= ~enable_processed_input;
    else                                     m |=  enable_processed_input;

    // THE POSITION IS ONE FLAG HERE, SO WRITING IT AGAIN SETTLES NOTHING THE
    // CALLER DID NOT ASK ABOUT. The rule the specification states beside
    // set_mode --- that a position whose requested value is the one in effect
    // is not written --- binds an implementation whose position stands for
    // several mechanisms; this one stands for exactly one, and assigning it
    // from the mode word is the same act as leaving it alone.

    // KAL_TERM_PASS_INPUT is virtual terminal input, and only while line input
    // is off: with lines assembled this environment alters input whatever the
    // switch says, so a request for the position there leaves it as it stands,
    // which is what terminal.h states of such an environment. A position whose
    // requested value is the one in effect is not written.
    bool asked_vt = false;
    if (((mode & KAL_TERM_PASS_INPUT) != 0) != unaltered) {
        if ((mode & KAL_TERM_PASS_INPUT) != 0) {
            if ((mode & KAL_TERM_LINE_EDIT) == 0) { m |= enable_virtual_terminal_input; asked_vt = true; }
        } else {
            m &= ~enable_virtual_terminal_input;
        }
    }

    // A position this implementation does not distinguish is ignored rather than
    // refused, which clause 6.2 requires of a word. A console that predates
    // virtual terminal input refuses the whole word when it is asked for, so
    // the word is written again without it: the other positions are
    // established, and the read-back says the fourth was not.
    if (!SetConsoleMode(h, m)) {
        if (!asked_vt || !SetConsoleMode(h, m & ~enable_virtual_terminal_input))
            return kal_err_not_supported;
    }
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
