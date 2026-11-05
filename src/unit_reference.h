// Counted, opaque unit references. This codec stores no process registry.
#pragma once
#include <openkal/types.h>
namespace unit_reference {
struct writer {
    char bytes[256]{}; kal_uintptr size = 0; bool valid = true;
    void text(const char* p) { for (; *p; ++p) { if (size == sizeof bytes) { valid = false; return; } bytes[size++] = *p; } }
    void number(kal_u64 n) { char b[24]; unsigned used = 0; do { b[used++] = char('0' + n % 10); n /= 10; } while (n); while (used) { char c[2]{b[--used],0}; text(c); } }
    void next() { text(";"); }
};
struct reader {
    const char* bytes; kal_uintptr size, at = 0;
    bool token(char* p, kal_uintptr capacity) {
        kal_uintptr n = 0;
        while (at < size && bytes[at] != ';') { if (n + 1 >= capacity || bytes[at] < 33 || bytes[at] > 126) return false; p[n++] = bytes[at++]; }
        p[n] = 0; if (at < size) ++at; return n != 0;
    }
    bool number(kal_u64& n) {
        n = 0; const auto begin = at;
        while (at < size && bytes[at] != ';') { const auto c = bytes[at++]; if (c < '0' || c > '9' || n > (~kal_u64{0} - kal_u64(c - '0')) / 10) return false; n = n * 10 + kal_u64(c - '0'); }
        if (at == begin) return false; if (at < size) ++at; return true;
    }
};
inline bool same(const char* a, const char* b) { for (; *a && *a == *b; ++a, ++b) {} return *a == *b; }
inline int copy(const writer& w, char* out, kal_uintptr capacity, kal_uintptr* used) {
    if (!w.valid || capacity < w.size) return kal_err_no_space;
    for (kal_uintptr i = 0; i < w.size; ++i) out[i] = w.bytes[i]; *used = w.size; return kal_ok;
}
}
