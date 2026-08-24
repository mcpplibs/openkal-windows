// openkal.random on Windows --- BCryptGenRandom with the system-preferred RNG.
//
// ⭐ THE FLAG IS WHAT REMOVES THE HANDLE, AND THE HANDLE WAS THE WHOLE OBJECTION.
//
// `BCryptGenRandom` ordinarily takes an algorithm handle, which this backend
// would have to open on every call or cache — and caching one gives this
// interface an initialisation order it does not otherwise have.
// `BCRYPT_USE_SYSTEM_PREFERRED_RNG` says "use the system's own generator" and
// takes a null handle, which is exactly what is wanted here.
//
// ⚠️ AND NOT `ProcessPrng`, WHICH WAS TRIED FIRST AND FAILS ON A WINDOWS HOST.
// That name lives in `bcryptprimitives.dll` and no import library in either
// toolchain exports it: mingw ships `libbcrypt.a` and not the primitives, and
// this package generates its own import libraries only when cross-compiling
// (`build.mcpp` returns immediately on a Windows host, where a real SDK is
// present). Measured — the cross build linked and the native one did not:
//
//     lld-link: error: undefined symbol: __declspec(dllimport) ProcessPrng
//
// ⭐ A backend that links on one host and not another is not a backend. The
// name below is in `libbcrypt.a` on both.
#include "win.h"
#include <openkal/random.h>

extern "C" {

// From bcrypt.dll. Declared here rather than by including <windows.h> for the
// reason the whole of win.h exists: this package names what it uses.
__declspec(dllimport) long __stdcall BCryptGenRandom(void* hAlgorithm,
                                                     unsigned char* pbBuffer,
                                                     unsigned long cbBuffer,
                                                     unsigned long dwFlags);

int kal_random_fill(void* out, kal_uintptr len) {
    if (len == 0) return kal_ok;
    if (out == nullptr) return kal_err_invalid;

    // BCRYPT_USE_SYSTEM_PREFERRED_RNG. Spelled as its value for the reason the
    // rest of this file spells things: the header it lives in is the system's.
    constexpr unsigned long use_system_preferred_rng = 0x00000002ul;

    // ⚠️ NO LOOP. This call fills the whole buffer or fails; unlike a read it
    // has no short return, so a loop would always run once and would suggest a
    // partial state this interface does not have.
    const long st = BCryptGenRandom(nullptr, static_cast<unsigned char*>(out),
                                    static_cast<unsigned long>(len),
                                    use_system_preferred_rng);
    return st == 0 /* STATUS_SUCCESS */ ? kal_ok : kal_err_io;
}

// Neither blocking nor hardware. The system's generator is seeded before a
// process runs, so there is no wait to report; and whether the seed came from a
// hardware source is not something this backend can observe.
const kal_uintptr kal_random_props = 0;

}  // extern "C"
