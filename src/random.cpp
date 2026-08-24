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
//
//     lld-link: error: undefined symbol: __declspec(dllimport) ProcessPrng
//
// The cross build linked and the native one did not, and the asymmetry is in
// where the import library comes from. Cross-compiling, this package generates
// its own from `port/*.def` — a list of names, so a name it lists is a name it
// has. On a Windows host `build.mcpp` returns immediately and the VENDOR's
// import libraries are used, because they are present and complete; and the
// Windows SDK ships `bcrypt.lib` but no import library for
// `bcryptprimitives.dll`. `ProcessPrng` is documented and has no `.lib`.
//
// ⭐ A backend that links on one host and not another is not a backend. The
// name below is exported by `bcrypt.dll` and listed by `bcrypt.lib`, so it
// resolves through the vendor's libraries and through this package's generated
// one alike.
//
// ⚠️ THE FIRST DIAGNOSIS OF THIS WAS WRONG AND IS RECORDED SO IT IS NOT REPEATED:
// it read `/usr/x86_64-w64-mingw32/lib` and concluded from mingw's contents.
// mingw is not part of this ecosystem — it is the very thing `build.mcpp`
// exists to stop depending on, as the note at the top of that file says. What
// this backend links against is either the vendor's SDK or this package's own
// generated libraries, and never a third party's.
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
