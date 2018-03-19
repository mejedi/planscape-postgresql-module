#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __x86_64__

// The longest instruction sequence we may emit to implement
// unconditional jump.           (MOV %reg, imm64; JMP %reg;)
#define JUMP_SEQUENCE_LEN     13

// The length of instruction sequence destroyed while patching absolute
// jump in.                      (JUMP_SEQUENCE_LEN + 1 following
//                                partially destroyed instruction)
#define CLOBBERED_CODE_LEN    (JUMP_SEQUENCE_LEN + 14)

// Maximum number of Jcc-s opcodes we may have to evacuate.
// Jcc-s are special, since we have to emit a jump sequence for each one
// of them.
#define JCC_MAX               (JUMP_SEQUENCE_LEN/2 + 1)

// Maximum size of trampoline code.
#define TRAMPOLINE_LEN        (CLOBBERED_CODE_LEN + JCC_MAX * JUMP_SEQUENCE_LEN)

// Define trampoline function. Merely reserves bytes in .code section.
// These bytes are to be later patched by hook_install().
// 
// Example:
// int my_trampoline(int param);
// HOOK_DEFINE_TRAMPOLINE(my_trampoline);
#define HOOK_DEFINE_TRAMPOLINE(name) \
__asm__(".globl " HOOK_S(name) "\n" HOOK_S(name) ":\n\t.skip " HOOK_S(TRAMPOLINE_LEN) ", 0xcc\n")

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

