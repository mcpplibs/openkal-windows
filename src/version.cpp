#include "win.h"
#include <openkal/version.h>

// What this implementation says about itself before it is used. Both answers are
// constants; openkal/version.h states why they belong to no interface.
extern "C" {

kal_u64 kal_version(void) { return KAL_VERSION; }

kal_u64 kal_interfaces(void) {
    // ⚠️ `openkal.space' IS ABSENT AND THE WORD SAYS SO. This system starts a
    // NAMED PROGRAM and has no primitive that copies an address space, so the
    // interface is not provided at all --- a consumer that is linked learns that
    // from the linker, and one bound otherwise learns it here.
    return KAL_IFACE_ABORT  | KAL_IFACE_STREAM   | KAL_IFACE_MEMORY
         | KAL_IFACE_ENV    | KAL_IFACE_TIME     | KAL_IFACE_RANDOM
         | KAL_IFACE_FS     | KAL_IFACE_PROCESS  | KAL_IFACE_TASK
         | KAL_IFACE_EXEC   | KAL_IFACE_TERMINAL | KAL_IFACE_NET
         | KAL_IFACE_DATAGRAM | KAL_IFACE_TIMEOUT;
}

}
