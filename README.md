# openkal-windows

An implementation of [openkal](https://github.com/mcpplibs/openkal) for Windows.

```toml
[dependencies]
openkal = "0.9.0"

[target.'cfg(windows)'.dependencies]
openkal-windows = "0.5.0"
```

Its purpose is as much to test the specification as to be used. openkal was
drawn against systems that share an ancestry; a third implementation on a system
that shares none of it is what turns "this interface is not Unix's shape" from a
claim into an observation.

## What this environment settles

**The file interface is not a Unix shape.** openkal has no global namespace of
paths: every operation is relative to a directory the program holds. That was
chosen because a global namespace is unavailable in a capability-based kernel,
and the obvious objection is that no ordinary system works that way either.

This one does. Win32 has no operation that opens a name relative to a directory
handle — and the object manager Win32 is built upon does: `NtCreateFile` takes a
root directory in its object attributes and a name relative to it, and refuses a
name that leaves it. This implementation is written one layer below the
interface most programs on this system use, and there is nothing to resolve.

An implementation written on Win32 alone would have to recover each directory's
path with `GetFinalPathNameByHandleW` and concatenate, which is a name resolver
inside an implementation and is what clause 7.1 excludes. The interface asked
for the operation this system already had.

**A declined interface is a legitimate outcome, and this system is where that
stops being theory.** `openkal.space` starts a context in a copy of the calling
address space. There is no primitive here that does it: `CreateProcessW` starts
a *named program*, which is `openkal.process` and is a different operation.
Clause 3 says an implementation provides an interface in whole or not at all,
and this implementation provides fourteen of the fifteen — so a program that
calls `kal_space_start` fails at the **link**, naming the operation, which is
clause 6.1's report and is the loudest one available.

Constructing a copy out of `CreateProcessW` plus a mechanism for carrying the
caller's memory across would be the simulation clause 3.1 forbids: it would be
present, it would look like the operation, and what it produced would not be a
copy of the caller.

**Duplication of the calling image is not a Unix preference.** `openkal.process`
starts a program and does not duplicate one, and the specification's reason is
that duplication cannot be performed faithfully everywhere. This system has no
such operation at all, so an interface that offered one would have obliged this
implementation to construct it out of nothing. `CreateProcessW` is the composite
`kal_process_spawn` already is.

**The suspension primitive is the shape of the thing.** `kal_task_wait` compares
a word with an expected value and suspends without an intervening opportunity
for the value to change unobserved. It was drawn from one kernel's futex. This
system offers `WaitOnAddress`, which is the same operation, under a different
name, with no shared ancestry. A mutex built above it in the conformance suite
loses none of eighty thousand increments.

## Where this system differs, and what each difference demonstrates

**Names are compared without regard to case.** `kal_fs_props` therefore does not
report `prop_case_sensitive`. A program that creates two names differing only in
case succeeds on the Linux implementation and not on this one, and no operation
could have told it which system it was on. This is what clause 6.2's properties
are for.

**The monotonic source continues while the machine is suspended.** The Linux
implementation's stops. `prop_monotonic_suspends` reports which, and a program
measuring an interval across a suspension needs to know.

**A status does not say whether the program chose it.** This system reports one
number and does not distinguish a program that returned it from a program that
was stopped. The implementation supplies a value for termination that an
ordinary program does not return, so the two remain distinguishable — which is
what the interface requires and all that it requires.

**Handles are not small integers.** Clause 6.6 requires that a released handle
not be treated as valid, and recommends dividing the word into an index and a
generation. The construction here is the same one the Linux implementation uses,
with the environment's handle recovered arithmetically from the word: it is not
a translation table, because no lookup decides what a word refers to. The bound
is stated in `src/handle.h`, and a handle beyond it is carried without a
generation rather than refused.

## No C runtime

An implementation is selected by the program, and the program may itself supply
the facilities the implementation would otherwise borrow. If it does, and the
names agree, the implementation's calls resolve to the program's and the
program's resolve back to the implementation.

This implementation therefore uses this environment's own interfaces and no C
runtime symbol at all. CI asserts it against the objects: the only undefined
names are Win32 imports, the object manager's, the suspension primitive's, and
this implementation's own.

## The `standalone` feature

Whether this implementation is the whole of the program's environment.
Ordinarily a program already carries a runtime that has received control from
the loader, and this implementation adds nothing. Where it does not, the entry
point is this implementation's and the link line names it — which is one
function here, because this environment's loader has already established the
argument vector, the named values and thread-local storage before it transfers
control.

## Interfaces provided

Fourteen of the fifteen. `openkal.space` is declined, for the reason above.

The four that openkal 0.8 added and this implementation now provides:

| | on this system |
| --- | --- |
| `openkal.net` | Winsock, started once at the first socket and never stopped. ⚠️ `WSASocketW` with a flags word of zero rather than `socket`: the latter makes an **overlapped** handle, and `ReadFile` upon one of those returns before the bytes arrive. A non-overlapped socket is what lets a connection be a stream here with no second transfer path |
| `openkal.datagram` | the same calls with `SOCK_DGRAM`. ⚠️ This system reports a truncated message as a **failure** where the other two truncate silently; the bytes that fit are delivered either way, and the interface says the excess is lost |
| `openkal.timeout` | `WSAPoll`, which answers for sockets and for nothing else. A bounded read of a stream that is not a socket reports `kal_err_not_supported` — which the interface's own header anticipates in terms. `kal_timeout_wait_process` is the one operation of the interface this system provides **directly**, because a bounded wait upon an object is the primitive here |
| `openkal.exec` | `VirtualAlloc` writable, `VirtualProtect` executable, `FlushInstructionCache`. The third call is not optional and the other two systems' implementations do not need to make it explicit |

## Verification

The conformance suite in the specification package, built for this target. The
feature set is enumerated rather than `optional`, and the difference is the one
interface this implementation declines: a set demanding `space` would fail to
link naming `kal_space_start` rather than report an observation.

```bash
git clone https://github.com/mcpplibs/openkal .spec
bash .spec/tools/run-conformance.sh openkal-windows . \
  full,exec,random,terminal,net,datagram,timeout --target x86_64-windows-gnu
```

## Toolchains

`x86_64-windows-gnu` (GCC producing PE), and the MSVC ABI through `llvm`. The
implementation uses no GNU extension.

## This package takes no vendor SDK, on either side

The object manager's declarations were written out in `src/win.h` from the
beginning, with the reason recorded there: `<winternl.h>` is complete in one
toolchain's sources and partial in another's. That argument was always the same
argument, and it had only been applied to the half where one toolchain disagrees
with another rather than to the half where one MACHINE disagrees with another.

**Declarations.** `src/win32.h` now declares the whole of what this
implementation calls — forty-seven functions and the types and constants they
need — so nothing here opens `<windows.h>`. The list was not read out of the
sources: the header was removed and the compiler was asked what was missing.
Each name carries `__declspec(dllimport)`, which is not an optimisation — it is
what makes the objects say that these are this environment's interfaces reached
through its import table, and this package's own independence check reads exactly
that.

**Where they live.** `port/*.def` names the library each of those forty-five
symbols is exported from, and the build program turns them into import libraries.
An import library is a list of names rather than code, which is why generating
one is a complete substitute rather than an approximation. The DLL each name
belongs to was read out of the corresponding mingw import library rather than
assumed — `WaitOnAddress` and its two neighbours are **not** in `kernel32.dll`,
and putting them there produces an import table that links and then fails to
bind.

⚠️ **Supplied only where the system's own are absent.** On this system they are
present, they are the vendor's, and they list every name rather than the
forty-five this implementation calls; `-L` is searched first, so supplying ours
there would shadow them and a consumer calling a forty-sixth would be told there
is no such name.

⚠️ Measured 2026-08-22, on a clean continuous-integration runner, after every
object had compiled:

```
lld: error: unable to find library -lkernel32
```

The compile had been free of a vendor SDK since `win32.h`; the link had not.

## License

Apache-2.0.
