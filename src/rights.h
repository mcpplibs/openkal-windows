// A directory handle with less (openkal 0.23, `kal_fs_dir_attenuate',
// SPEC.md clause 7.16): what a handle may not do, what its holder stated, and
// what it records.
//
// A table indexed by the handle's slot (handle.h), consulted by every operation
// of openkal.fs that takes a directory. It is empty in a program that
// attenuates nothing, and the one test of `g_any' is then all an operation
// pays.
#pragma once
#include "win.h"

namespace okw::rights {

inline constexpr okw_u32 read_only  = 1u;   // KAL_DIR_READ_ONLY
inline constexpr okw_u32 unchanging = 2u;   // KAL_DIR_UNCHANGING
inline constexpr okw_u32 recorded   = 4u;   // KAL_DIR_RECORDED

extern volatile bool g_any;

// The rights a directory handle carries; zero for one that carries none.
okw_u32 of(void* h);

// A new handle for the directory `h' names, carrying the rights of `h' and
// `add'; `record' is the holder's file for `recorded'. Returns a kal_err value,
// and writes the new handle to `out' on kal_ok.
int attenuate(void* h, okw_u32 add, void* record, void** out);

// A directory `child' opened beneath `parent' by `name': it carries what the
// parent carries. Returns false when the table has no room, and the caller then
// refuses the open rather than hand out a directory with more than its base.
bool derive(void* parent, void* child, const char* name, okw_uptr len);

// The handle is being closed.
void forget(void* h);

// What a name reached beneath `h' was found to be, for a recorded handle:
//   'r' read, 'w' written, 's' asked about and present, 'a' absent, 'l' listed.
// A name of length zero is the directory itself.
void note(void* h, char kind, const char* name, okw_uptr len);

// Whether a handle that states nothing changes beneath it knows `name' to be
// absent, from what it has listed --- without asking the system.
bool known_absent(void* h, const char* name, okw_uptr len);

// Something beneath was changed through a handle of this tree: what was listed
// may no longer hold.
void changed(void* h);

// THE CONVEYANCE TO A STARTED PROGRAM. What a granted handle carries, for the
// variable a start writes; and, in the started program, a preopen received
// with rights.
bool conveyed(void* h, okw_u32* flags, void** record, const char** prefix, okw_uptr* prefix_len);
void adopt(void* h, okw_u32 flags, void* record, const char* prefix, okw_uptr prefix_len);

// The program is ending: every record is written, and ended with `e'.
void end_of_program();

}  // namespace okw::rights
