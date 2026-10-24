// What a console delivers for the return key and for Ctrl+J, measured, and what
// KAL_TERM_PASS_INPUT (openkal 0.16) reports for it.
//
// mcpplibs/openkal#48: above the two other implementations the return key
// reached a program in raw mode as a line feed, the same byte Ctrl+J produces.
// The position that answers it is meant to make the bytes a program reads the
// same on all three when it is set, so this test writes the keys into a console
// of its own as key events --- the form a keyboard produces --- reads them back
// through kal_stream_read, prints what arrived under each mode, and checks:
//
//   with line input off, the position reads set, and the return key is 0x0d
//   and Ctrl+J is 0x0a, which is what the other two deliver with it set;
//   with line input on, the position reads clear.
//
// A console is allocated rather than inherited, because a runner's own may be
// absent or redirected. A watchdog ends the test if a read waits for a key that
// never arrives, so a wrong expectation is a failure rather than a hang.
#include <windows.h>
#include <cstdio>
#include <openkal/stream.h>
#include <openkal/terminal.h>
#include <openkal/types.h>

namespace {

int failures = 0;

void check(bool held, const char* what) {
    std::printf("  %s  %s\n", held ? "held" : "FAIL", what);
    std::fflush(stdout);
    if (!held) ++failures;
}

DWORD WINAPI watchdog(void*) {
    Sleep(20000);
    std::printf("  FAIL  a read waited for a key that never arrived\n");
    std::fflush(stdout);
    ExitProcess(3);
}

void key(INPUT_RECORD* r, WORD vk, WORD scan, wchar_t ch, DWORD ctrl, BOOL down) {
    ZeroMemory(r, sizeof *r);
    r->EventType = KEY_EVENT;
    r->Event.KeyEvent.bKeyDown = down;
    r->Event.KeyEvent.wRepeatCount = 1;
    r->Event.KeyEvent.wVirtualKeyCode = vk;
    r->Event.KeyEvent.wVirtualScanCode = scan;
    r->Event.KeyEvent.uChar.UnicodeChar = ch;
    r->Event.KeyEvent.dwControlKeyState = ctrl;
}

// How Ctrl+J is spelled as a key event. A keyboard produces the virtual key
// 'J', its scan code, the control state and the character the layout gives it;
// which of those the console reads is what is being measured, so each spelling
// is tried and printed.
int g_spelling = 0;

// Writes the keys `keys' as presses and releases, then reads `want' bytes.
int type_and_read(HANDLE in, kal_stream s, const char* keys, unsigned char* out, int want) {
    FlushConsoleInputBuffer(in);
    INPUT_RECORD rec[32];
    int n = 0;
    for (const char* k = keys; *k; ++k) {
        WORD vk; WORD scan = 0; wchar_t ch; DWORD ctrl = 0;
        if (*k == 'E')      { vk = VK_RETURN; scan = 0x1c; ch = L'\r'; }
        else if (*k == 'J') {
            vk = 'J'; ch = L'\n';
            switch (g_spelling) {
            case 0: scan = 0x24; ctrl = LEFT_CTRL_PRESSED; break;   // as a keyboard sends it
            case 1: scan = 0;    ctrl = LEFT_CTRL_PRESSED; break;
            case 2: scan = 0x24; ctrl = 0;                 break;   // the character alone
            }
        }
        else                { vk = static_cast<WORD>(*k - 'a' + 'A'); ch = static_cast<wchar_t>(*k); }
        key(&rec[n++], vk, scan, ch, ctrl, TRUE);
        key(&rec[n++], vk, scan, ch, ctrl, FALSE);
    }
    DWORD written = 0;
    if (!WriteConsoleInputW(in, rec, static_cast<DWORD>(n), &written)) {
        std::printf("  WriteConsoleInputW failed: %lu\n", GetLastError());
        return -1;
    }
    DWORD queued = 0;
    GetNumberOfConsoleInputEvents(in, &queued);
    std::printf("  wrote %lu of %d events; %lu queued\n", written, n, queued);
    int got = 0;
    while (got < want) {
        // A read is made only once the console says there is input, so a key
        // event the console does not turn into a byte is reported rather than
        // waited for.
        if (WaitForSingleObject(in, 3000) != WAIT_OBJECT_0) {
            GetNumberOfConsoleInputEvents(in, &queued);
            std::printf("  no input within 3 s; %lu events still queued\n", queued);
            break;
        }
        const kal_intptr r = kal_stream_read(s, out + got, static_cast<kal_uintptr>(want - got));
        if (r <= 0) break;
        got += static_cast<int>(r);
    }
    return got;
}

void show(const char* mode, const unsigned char* b, int n) {
    std::printf("  measured  %-34s", mode);
    for (int i = 0; i < n; ++i) std::printf(" %02x", b[i]);
    std::printf("\n");
}

}  // namespace

int main() {
    FreeConsole();
    if (!AllocConsole()) {
        std::printf("openkal-windows: no console could be allocated; not observed\n");
        return 0;
    }
    HANDLE in = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, 0, nullptr);
    if (in == INVALID_HANDLE_VALUE) {
        std::printf("openkal-windows: the console's input could not be opened; not observed\n");
        return 0;
    }
    CreateThread(nullptr, 0, watchdog, nullptr, 0, nullptr);
    const kal_stream s{ reinterpret_cast<kal_uintptr>(in) };
    unsigned char b[8] = {};
    kal_uintptr m = 0;

    // Raw, with the environment's reserved keys kept: the ordinary raw mode.
    check(kal_terminal_set_mode(s, 0) == kal_ok, "line input and echo are turned off");
    check(kal_terminal_get_mode(s, &m) == kal_ok && (m & KAL_TERM_PASS_INPUT) != 0,
          "with line input off the position reads set");
    int got = type_and_read(in, s, "E", b, 1);
    show("line off, processed on: Enter", b, got);
    check(got == 1 && b[0] == 0x0d, "the return key is 0x0d");
    const char* spelled[] = { "Ctrl+J, keyboard scan code", "Ctrl+J, no scan code", "line feed, no control" };
    int lf = 0;
    for (g_spelling = 0; g_spelling < 3; ++g_spelling) {
        got = type_and_read(in, s, "J", b, 1);
        show(spelled[g_spelling], b, got);
        if (got == 1 && b[0] == 0x0a) ++lf;
        if (got == 1) check(b[0] != 0x0d, "Ctrl+J is not the byte the return key is");
    }
    g_spelling = 0;
    std::printf("  measured  %d of 3 spellings of Ctrl+J delivered 0x0a\n", lf);

    // Raw, and nothing reserved: what a program that reads keystrokes asks for.
    check(kal_terminal_set_mode(s, KAL_TERM_PASS_CONTROL | KAL_TERM_PASS_INPUT) == kal_ok,
          "every keystroke, unaltered, is requested");
    check(kal_terminal_get_mode(s, &m) == kal_ok && (m & KAL_TERM_PASS_INPUT) != 0,
          "the position reads set when it is requested with line input off");
    got = type_and_read(in, s, "E", b, 1);
    show("line off, processed off: Enter", b, got);
    check(got == 1 && b[0] == 0x0d, "the return key is 0x0d with nothing reserved");
    got = type_and_read(in, s, "J", b, 1);
    show("line off, processed off: Ctrl+J", b, got);

    // A request this environment cannot separate from line input is left as it
    // stands, and the read-back says so.
    check(kal_terminal_set_mode(s, KAL_TERM_PASS_CONTROL) == kal_ok, "altered input is requested in raw mode");
    check(kal_terminal_get_mode(s, &m) == kal_ok && (m & KAL_TERM_PASS_INPUT) != 0,
          "the read-back reports what is in effect rather than what was asked");

    // Lines assembled: the position reads clear, and what arrives is measured.
    check(kal_terminal_set_mode(s, KAL_TERM_LINE_EDIT) == kal_ok, "line input is turned on");
    check(kal_terminal_get_mode(s, &m) == kal_ok && (m & KAL_TERM_PASS_INPUT) == 0,
          "with line input on the position reads clear");
    got = type_and_read(in, s, "aE", b, 3);
    show("line on: a Enter", b, got);
    check(got >= 2 && b[0] == 'a', "a line is delivered");

    std::printf("openkal-windows: what a console delivers, %s\n", failures ? "FAILED" : "held");
    std::fflush(stdout);
    return failures == 0 ? 0 : 1;
}
