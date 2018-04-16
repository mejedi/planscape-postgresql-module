#ifndef __x86_64__
#error Unsupported ARCH :(
#endif

#include "hook_engine.h"
#include "hde/hde64.h"

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

struct Overlay
{
    uintptr_t target; // Where in address space this will ultimately end up.
    uint8_t  *p;      // Current output position.
    uint8_t   code[HOOK_TRAMPOLINE_LEN];
};

static int g_mem_fd = -1;

static inline
void put_uint32(uint8_t *p, uint32_t v)
{
    struct u32 { uint32_t u32; } __attribute__((__packed__));
    ((struct u32*)(p))->u32 = v;
}

static inline
void put_uint64(uint8_t *p, uint64_t v)
{
    struct u64 { uint64_t u64; } __attribute__((__packed__));
    ((struct u64*)(p))->u64 = v;
}

static inline
size_t overlay_size(const struct Overlay *c)
{
    return c->p - c->code;
}

static
int install_overlay(int mem_fd, const struct Overlay *c)
{
    ssize_t c_size = overlay_size(c);
    return pwrite(mem_fd, c->code, c_size, c->target) == c_size ? 0 : -1;
}

static
void write_initial_jmp(struct Overlay *c, uintptr_t target)
{
    // movq target, %rax
    c->p[0] = 0x48;
    c->p[1] = 0xB8;
    put_uint64(c->p + 2, target);

    // jmp %rax
    c->p[10] = 0xFF;
    c->p[11] = 0xE0;

    c->p += 12;
}

static
void write_jmp(struct Overlay *c, uintptr_t target, uintptr_t **jump_table)
{
    // jmp  *jump_table(%rip)
    c->p[0] = 0xff;
    c->p[1] = 0x25;
    put_uint32(c->p + 2, (uintptr_t)(*jump_table) - (c->target + overlay_size(c) + 6));

    c->p += 6;
    (*jump_table)[0] = target;
    (*jump_table)++;
}

static
void write_call(struct Overlay *c, uintptr_t target, uintptr_t **jump_table)
{
    // call *jump_table(%rip)
    write_jmp(c, target, jump_table);
    c->p[-5] = 0x15;
}

// Patch function @fn, so that every time it is called, control is
// transferred to @replacement.
//
// If @trampoline is provided, instructions destroyed in @fn are
// transferred to @trampoline.
int hook_install(void *fn, void *replacement, void *trampoline)
{
    int rc = 0;

    // We render code in two overlays, and later overwrite @fn and
    // @trampoline with the overlays' content.
    struct Overlay fn_overlay = {(uintptr_t)fn, fn_overlay.code};
    struct Overlay t_overlay  = {(uintptr_t)trampoline, t_overlay.code};

    // Jump table is normally extracted from the trampoline. Provide a
    // placeholder if trampoline is NULL
    uint64_t jump_table_data[HOOK_JUMP_MAX], *jump_table = jump_table_data;

    // trampoline points to a symbol created with HOOK_DEFINE_TRAMPOLINE
    // macro; after TRAMPOLINE_LEN area, there's a code sequence
    // returning a pointer to a per-trampoline jump table
    if (trampoline)
        jump_table = ((uint64_t * (*)(void))((uintptr_t)trampoline + HOOK_TRAMPOLINE_LEN))();

    // Prepare code to overwrite @fn with. This will be JMP @replacement.
    write_initial_jmp(&fn_overlay, (uintptr_t)replacement);

    // Detect jumps into the code range we overwrite.
    const uintptr_t rip_hazard = (uintptr_t)fn + overlay_size(&fn_overlay);

    // @fn is going to be partially clobbered. Disassemble and evacuate
    // some instructions.
    size_t disas_offset = 0;
    while (disas_offset < overlay_size(&fn_overlay)) {

        const uint8_t *i = (const uint8_t *)fn + disas_offset;
        hde64s s;

        hde64_disasm(i, &s);
        if (s.flags & F_ERROR) return -1;
        disas_offset += s.len;

        uintptr_t rip_dest = UINTPTR_MAX;

        switch (s.opcode) {

        case 0xCC:
            // int3: this is probably a breakpoint set by a debugger
            return -1;

        case 0xE8:
            // relative call, 32 bit immediate offset
            assert(s.flags & F_IMM32);
            rip_dest = (uintptr_t)fn + disas_offset + (int32_t)s.imm.imm32;
            write_call(&t_overlay, rip_dest, &jump_table);
            goto check_rip_dest;

        case 0xE9:
            // relative jump, 8 bit immediate offset
            assert(s.flags & F_IMM8);
            rip_dest = (uintptr_t)fn + disas_offset + (int8_t)s.imm.imm8;
            write_jmp(&t_overlay, rip_dest, &jump_table);
            goto check_rip_dest;

        case 0xEB:
            // relative jump, 32 bit immediate offset
            assert(s.flags & F_IMM32);
            rip_dest = (uintptr_t)fn + disas_offset + (int32_t)s.imm.imm32;
            write_jmp(&t_overlay, rip_dest, &jump_table);
            goto check_rip_dest;

        case 0xE3:
            // jump if %ecx/ %rcx zero
            return -1;

        case 0x70 ... 0x7f:
            // Jcc jump, 8 bit immediate offset
            assert(s.flags & F_IMM8);
            rip_dest = (uintptr_t)fn + disas_offset + (int8_t)s.imm.imm8;

            t_overlay.p[0] = s.opcode ^ 1;
            t_overlay.p[1] = 6;
            t_overlay.p += 2;

            write_jmp(&t_overlay, rip_dest, &jump_table);
            goto check_rip_dest;

        case 0x0F:
            if (s.opcode2 >= 0x80 && s.opcode2 <= 0x8F) {
                // Jcc jump, 32 bit immediate offset
                assert(s.flags & F_IMM32);
                rip_dest = (uintptr_t)fn + disas_offset + (int32_t)s.imm.imm32;

                // Convert to a shorter form
                t_overlay.p[0] = (s.opcode2 - 0x10) ^ 1;
                t_overlay.p[1] = 6;
                t_overlay.p += 2;

                write_jmp(&t_overlay, rip_dest, &jump_table);
                goto check_rip_dest;
            }
            break;
        }

        // RIP-relative addressing
        if ((s.flags & F_MODRM) &&
            s.modrm_mod == 0 && s.modrm_rm == 0x5) {

            // LEA?
            if (s.opcode != 0x8D)
                return -1;

            // Convert to MOV
            t_overlay.p[0] = 0x48 + s.rex_r;
            t_overlay.p[1] = 0xB8 + s.modrm_reg;
            put_uint64(t_overlay.p + 2, (uintptr_t)fn + disas_offset + (int32_t)s.disp.disp32);
            t_overlay.p += 10;

            continue;
        }

        // Copy instruction
        memcpy(t_overlay.p, i, s.len);
        t_overlay.p += s.len;
        continue;

check_rip_dest:
        // If we've seen a jump into the range we are about to overwrite,
        // this isn't going to work.
        if (rip_dest >= (uintptr_t)fn && rip_dest < rip_hazard)
            return -1;
    }

    // If we've clobbered a *part* of an instruction, we should beter
    // int3 the surviving part.
    size_t partially_clobbered = disas_offset - overlay_size(&fn_overlay);
    memset(fn_overlay.p, 0xcc, partially_clobbered);
    fn_overlay.p += partially_clobbered;

    // Connect trampoline to the unclobbered part of @fn.
    write_jmp(&t_overlay, (uintptr_t)fn + disas_offset, &jump_table);

    // Now actually owerwrite things.
    int mem_fd = g_mem_fd;

    if (mem_fd == -1)
        mem_fd = open("/proc/self/mem", O_RDWR);

    if (mem_fd == -1)
        return -1;

    if (trampoline)
        rc = install_overlay(mem_fd, &t_overlay);

    if (rc == 0)
        rc = install_overlay(mem_fd, &fn_overlay);

    if (mem_fd != g_mem_fd)
        close(mem_fd);

    return rc;
}

int hook_begin()
{
    if (g_mem_fd == -1)
        g_mem_fd = open("/proc/self/mem", O_RDWR);

    return g_mem_fd == -1 ? -1 : 0;
}

void hook_end()
{
    if (g_mem_fd != -1)
        close(g_mem_fd);

    g_mem_fd = - 1;
}
