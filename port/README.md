# `port/` — what this system's own interfaces are called, and where they live

`src/win32.h` and `src/win.h` say what this implementation CALLS. These four
files say which library each of those names lives in, so that a link does not
need a vendor SDK either.

⭐ **The same argument as the headers, applied one step later.** Removing
`<windows.h>` freed the COMPILE from a toolchain-provided SDK. The LINK was
still reaching for `libkernel32.a` and its neighbours — files that exist on a
machine with mingw installed and nowhere else. Measured 2026-08-22, on a clean
CI runner, after every object compiled:

```
lld: error: unable to find library -lkernel32
lld: error: unable to find library -lntdll
lld: error: unable to find library -lshell32
lld: error: unable to find library -lsynchronization
```

⚠️ **And it had passed on a developer's machine**, which had mingw installed —
the shape this repository has recorded before as "a green that came from
history the new machine does not have".

⭐ **An import library is a list of names, not code.** It carries the DLL each
name lives in and nothing else, which is why generating one from a list is a
complete substitute rather than an approximation — the same reason
`openkal-macos/port/libSystem.tbd` is one for that system.

## The lists were measured, not read

Every object of a complete build was given to `nm`, and the undefined symbols
are what these four files contain. The DLL each belongs to was read out of the
corresponding mingw import library rather than assumed: `WaitOnAddress` and its
two neighbours are **not** in `kernel32.dll`, and putting them there would
produce an import table that fails to bind on the system it names.

## ⚠️ x86-64 only, and the reason is stated rather than assumed

`llvm-dlltool` is invoked with `-m i386:x86-64`. On the 32-bit ABI these names
would need `@N` stdcall decoration, which is a property of that ABI rather than
of this list. That target is not built today; when it is, this is where it is
answered.
