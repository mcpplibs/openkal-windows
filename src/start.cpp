// Program startup, for a program that carries no runtime of its own.
//
// Where a program already carries a runtime, that runtime's first object
// receives control from the loader and this file is not compiled. Where it does
// not, something must receive control, and on this environment that something
// is named in the image header rather than found by the linker under a fixed
// symbol --- so the name below is stated on the link line.
//
// It is short here and long on other environments, and the difference is a
// property of the environment. The loader on this system has already
// established the argument vector, the named values and the thread-local
// storage of every thread before it transfers control, and it offers each
// through an ordinary operation. There is no stack layout to parse and no
// register to install.
#ifdef OKW_STANDALONE

#include "win.h"
#include <openkal/abort.h>

extern "C" {

int main(int, char**, char**);

// The name the hand-over from the first object to a C library already has.
// Unlike the ELF arrangement it is not weak: this environment's linker does not
// offer weak references in a form every one of the three toolchains agrees on,
// and a program that selects this feature without supplying the symbol is
// better told so by the linker than given an entry that silently does nothing.
int __libc_start_main(int (*)(int, char**, char**), int, char**,
                      void (*)(), void (*)(), void (*)());

void okw_start(void);

void okw_start(void) {
    // The arguments are not passed. The library above obtains them through
    // openkal.env, which is the same information and is the form every
    // environment supplies it in --- whereas the form this environment would
    // pass them in is this environment's alone.
    __libc_start_main(main, 0, nullptr, nullptr, nullptr, nullptr);
    kal_exit(127);
}

}

#endif  // OKW_STANDALONE
