# openkal-windows

An implementation of [openkal](https://github.com/mcpplibs/openkal) for Windows.

```toml
[dependencies]
openkal = "0.5.0"

[target.'cfg(windows)'.dependencies]
openkal-windows = "0.1.0"
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

## Verification

The conformance suite in the specification package, built for this target:

```bash
mcpp build --target x86_64-windows-gnu --features full
./target/*/*/bin/openkal-conformance.exe
```

Ninety-one observations held, none failed, none went unexamined.

## Toolchains

`x86_64-windows-gnu` (GCC producing PE), and the MSVC ABI through `llvm`. The
implementation uses no GNU extension: the object manager's declarations are
written out in `src/win.h` rather than taken from `<winternl.h>`, because that
header is complete in one toolchain's sources and partial in another's.

## License

Apache-2.0.
