// openkal.random on Windows --- ProcessPrng.
//
// ⭐ ProcessPrng AND NOT BCryptGenRandom, AND THE DIFFERENCE IS A CONTEXT.
//
// `BCryptGenRandom` is the documented CNG entry point and takes an algorithm
// handle, which means opening one — a cost this interface would pay on every
// call or would have to cache, and caching means initialisation order. Since
// Windows 10 the system exposes `ProcessPrng` in `bcryptprimitives.dll`: the
// same generator, no handle, no failure mode other than the call itself.
// Chromium and Rust's standard library both moved to it for these reasons.
//
// ⚠️ AND NOT `RtlGenRandom` (`SystemFunction036`), WHICH IS THE OLDER ANSWER.
// That name is undocumented, exported by ordinal from `advapi32`, and reached
// by a declaration each caller writes itself. It works, and this backend does
// not need it: `ProcessPrng` covers every version this package supports.
#include "win.h"
#include <openkal/random.h>

extern "C" {

// From bcryptprimitives.dll. Declared here rather than by including <windows.h>
// for the reason the whole of win32.h exists: this package names what it uses.
__declspec(dllimport) int __stdcall ProcessPrng(unsigned char* pbData,
                                                okw_uptr cbData);

int kal_random_fill(void* out, kal_uintptr len) {
    if (len == 0) return kal_ok;
    if (out == nullptr) return kal_err_invalid;

    // ⚠️ NO LOOP. `ProcessPrng` fills the whole buffer or fails; unlike a read
    // it has no short return, so a loop would be a loop that always runs once
    // and would suggest a partial state this interface does not have.
    const int ok = ProcessPrng(static_cast<unsigned char*>(out),
                               static_cast<okw_uptr>(len));
    return ok ? kal_ok : kal_err_io;
}

// Neither blocking nor hardware. The system's generator is seeded before a
// process runs, so there is no wait to report; and whether the seed came from a
// hardware source is not something this backend can observe.
const kal_uintptr kal_random_props = 0;

}  // extern "C"
