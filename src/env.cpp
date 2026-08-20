#include "win.h"
#include <openkal/env.h>

// The parameters a program receives at inception.
//
// This environment supplies them in its own encoding and in its own shape: one
// command line rather than a vector, and a block of terminated pairs rather
// than an array. Both are converted once, here, at the first enquiry --- and
// the conversion is a change of representation rather than a namespace being
// reconstructed, because the environment's own operation is what splits the
// command line. An implementation that wrote its own splitter would be deciding
// what this environment's argument vector is, which is not its to decide.

namespace {


constexpr int kMaxArgs = 256;
constexpr int kMaxVars = 512;
constexpr okw_uptr kText = 1u << 16;

char       g_text[kText];
okw_uptr   g_used = 0;

const char* g_argv[kMaxArgs];
okw_uptr    g_argv_len[kMaxArgs];
int         g_argc = 0;

const char* g_entry[kMaxVars];      // "name=value", as the environment states it
okw_uptr    g_name_len[kMaxVars];
const char* g_value[kMaxVars];
okw_uptr    g_value_len[kMaxVars];
int         g_varc = 0;

bool        g_ready = false;

const char* store(const wchar_t* w, int wlen, okw_uptr& out_len) {
    if (g_used + 4 >= kText) { out_len = 0; return ""; }
    char* at = g_text + g_used;
    const okw_uptr n = okw::narrow(w, static_cast<okw_uptr>(wlen), at, kText - g_used);
    g_used += n + 1;
    out_len = n;
    return at;
}

int wide_length(const wchar_t* w) { int n = 0; while (w && w[n]) ++n; return n; }

void prepare() {
    if (g_ready) return;
    g_ready = true;

    int count = 0;
    wchar_t** parts = CommandLineToArgvW(GetCommandLineW(), &count);
    if (parts) {
        for (int i = 0; i < count && g_argc < kMaxArgs - 1; ++i) {
            okw_uptr len = 0;
            g_argv[g_argc] = store(parts[i], wide_length(parts[i]), len);
            g_argv_len[g_argc] = len;
            ++g_argc;
        }
        LocalFree(parts);
    }
    if (g_argc == 0) {
        // Position zero is the name the program was started by, and an
        // environment with no such name reports an empty string rather than
        // omitting it.
        g_argv[0] = ""; g_argv_len[0] = 0; g_argc = 1;
    }

    wchar_t* block = GetEnvironmentStringsW();
    if (block) {
        for (wchar_t* p = block; *p && g_varc < kMaxVars; ) {
            const int len = wide_length(p);
            // A name beginning with a separator is this environment's own
            // bookkeeping and is not a variable a program set.
            if (p[0] != L'=') {
                okw_uptr total = 0;
                const char* entry = store(p, len, total);
                okw_uptr split = 0;
                while (split < total && entry[split] != '=') ++split;
                g_entry[g_varc]     = entry;
                g_name_len[g_varc]  = split;
                g_value[g_varc]     = split < total ? entry + split + 1 : entry + total;
                g_value_len[g_varc] = split < total ? total - split - 1 : 0;
                ++g_varc;
            }
            p += len + 1;
        }
        FreeEnvironmentStringsW(block);
    }
}

bool same(const char* a, okw_uptr alen, const char* b, okw_uptr blen) {
    if (alen != blen) return false;
    for (okw_uptr i = 0; i < alen; ++i) if (a[i] != b[i]) return false;
    return true;
}

}  // namespace

extern "C" {

kal_uintptr kal_env_arg_count(void) { prepare(); return static_cast<kal_uintptr>(g_argc); }

const char* kal_env_arg(kal_uintptr index, kal_uintptr* len) {
    prepare();
    if (index >= static_cast<kal_uintptr>(g_argc)) { if (len) *len = 0; return nullptr; }
    if (len) *len = g_argv_len[index];
    return g_argv[index];
}

const char* kal_env_var(const char* name, kal_uintptr name_len, kal_uintptr* value_len) {
    prepare();
    for (int i = 0; i < g_varc; ++i) {
        // Names are compared without regard to case, because that is how this
        // environment compares them. A program that set PATH and asked for Path
        // would otherwise be told the variable is absent on one system and
        // present on another, with no operation reporting which.
        if (g_name_len[i] != name_len) continue;
        bool equal = true;
        for (kal_uintptr k = 0; k < name_len; ++k) {
            char a = g_entry[i][k], b = name[k];
            if (a >= 'a' && a <= 'z') a = static_cast<char>(a - 32);
            if (b >= 'a' && b <= 'z') b = static_cast<char>(b - 32);
            if (a != b) { equal = false; break; }
        }
        if (!equal) continue;
        if (value_len) *value_len = g_value_len[i];
        return g_value[i];
    }
    if (value_len) *value_len = 0;
    return nullptr;
}

kal_uintptr kal_env_var_count(void) { prepare(); return static_cast<kal_uintptr>(g_varc); }

const char* kal_env_var_at(kal_uintptr index, kal_uintptr* name_len,
                           const char** value, kal_uintptr* value_len) {
    prepare();
    if (index >= static_cast<kal_uintptr>(g_varc)) return nullptr;
    if (name_len)  *name_len  = g_name_len[index];
    if (value)     *value     = g_value[index];
    if (value_len) *value_len = g_value_len[index];
    return g_entry[index];
}

}
