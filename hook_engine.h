#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __x86_64__

// The length of a jump sequence a hooked function's code is clobbered
// with.
#define HOOK_INITIAL_JUMP_LEN 12

// The length of a jump sequence in trampoline's body. This is different
// from HOOK_INITIAL_JUMP_LEN since we can't clobber registers.
#define HOOK_JUMP_LEN         6

// Max length of the code clobbered in a hooked functions (account for a
// partially clobbered following instructions, max instruction length in
// x86_64 is 15).
#define HOOK_CLOBBERED_LEN    (HOOK_INITIAL_JUMP_LEN + 14)

// Maximum number of jumps/calls in a trampoline body (shortest
// jump/call instruction in x86_64 is 2 bytes long).
#define HOOK_JUMP_MAX         (HOOK_INITIAL_JUMP_LEN/2 + 1)

// Maximum size of trampoline code.
#define HOOK_TRAMPOLINE_LEN   (HOOK_CLOBBERED_LEN + HOOK_JUMP_MAX * HOOK_JUMP_LEN)

// Define trampoline function. Merely reserves bytes in .code section.
// These bytes are to be later patched by hook_install().
// 
// Example:
// int my_trampoline(int param);
// HOOK_DEFINE_TRAMPOLINE(my_trampoline);
#define HOOK_DEFINE_TRAMPOLINE(name) \
__asm__(".globl " HOOK_S(name) "\n" \
        HOOK_S(name) ":\n" \
        "\t.skip " HOOK_S(HOOK_TRAMPOLINE_LEN) ", 0xcc\n" \
        "\tleaq _J_" HOOK_S(name) "(%rip), %rax;\n" \
        "\tret\n" \
        ".local _J_" HOOK_S(name) "\n" \
        ".comm _J_" HOOK_S(name) ", " HOOK_S(HOOK_JUMP_MAX*8) ", 8\n")

#else
#error Unsupported ARCH :(
#endif

// Patch function @fn, so that every time it is called, control is
// transferred to @replacement.
//
// If @trampoline is provided, instructions destroyed in @fn are
// transferred to @trampoline.
int hook_install(void *fn, void *replacement, void *trampoline);

// Install multiple hooks faster by enclosing calls to hook_install()
// into hook_begin()/hook_end().
int hook_begin(void);

// See hook_begin().
void hook_end(void);

#define HOOK_S(s) HOOK__S(s)
#define HOOK__S(s) #s

#ifdef __cplusplus
} // extern "C"

#include <type_traits>

// Validate functions compatibility. 
template<typename Fn, typename = typename std::enable_if<std::is_function<
                                 typename std::remove_pointer<Fn>::type>::value>::type>
inline int hook_install(Fn &fn, Fn &replacement, Fn &trampoline)
{
    return hook_install((void *)fn,
                        (void *)replacement,
                        (void *)trampoline);
}
#endif

