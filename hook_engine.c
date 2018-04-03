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

// x86_64 registers
#define RAX  0x0001
#define RCX  0x0002
#define RDX  0x0004
#define RBX  0x0008
#define RSP  0x0010
#define RBP  0x0020
#define RSI  0x0040
#define RDI  0x0080
#define R8   0x0100
#define R9   0x0200
#define R10  0x0400
#define R11  0x0800
#define R12  0x1000
#define R13  0x2000
#define R14  0x4000
#define R15  0x8000

struct Overlay
{
    uintptr_t target; // Where in address space this will ultimately end up.
    uint8_t  *p;      // Current output position.
    uint8_t   code[TRAMPOLINE_LEN];
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
int write_jmp(struct Overlay *c, uintptr_t rip_dest, int spare_regs)
{
    uintptr_t rip = c->target + overlay_size(c);
    uintptr_t rip_delta = rip_dest - rip;

    // 8 bit relative target may work
    if (rip_delta - 2 <= UINT8_MAX || rip_delta - 2 >= INT8_MIN) {
        c->p[0] = 0xEB;
        c->p[1] = (uint8_t)(rip_delta - 2);
        c->p += 2;
        return 0;
    }

    // 32 bit relative target may work
    if (rip_delta - 5 <= UINT32_MAX || rip_delta - 5 >= INT32_MIN) {
        c->p[0] = 0xE9;
        put_uint32(&c->p[1], (uint32_t)(rip_delta - 5));
        c->p += 5;
        return 0;
    }

    // movabs @rip_dest, %reg; jmp %reg;
    if ((spare_regs & 0xffff) == 0)
        return -1;

    int reg = __builtin_ctz(spare_regs);
    int reg_hi = reg >> 3;
    int reg_lo = reg & 7;

    c->p[0] = 0x48 + reg_hi;
    c->p[1] = 0xB8 + reg_lo;
    put_uint64(&c->p[2], rip_dest);
    c->p += 10;

    if (reg_hi != 0) {
        *(c->p++) = 0x40 + reg_hi;
    }

    c->p[0] = 0xff;
    c->p[1] = 0xe0 + reg_lo;
    c->p += 2;

    return 0;
}

static
int install_overlay(int mem_fd, const struct Overlay *c)
{
    ssize_t c_size = overlay_size(c);
    return pwrite(mem_fd, c->code, c_size, c->target) == c_size ? 0 : -1;
}

// Oversimplistic register usage detector
static
int regs_used(const hde64s *s)
{
    int regs = 0;

    // Better be safe than sorry
    if (s->flags & F_MODRM) {
        regs |= (1 << (s->modrm_reg | (s->rex_r << 3)));
        regs |= (1 << (s->modrm_rm | (s->rex_b << 3)));
    }

    // https://github.com/MahdiSafsafi/opcodesDB/blob/master/x86.pl
    // instructions with reg being part of the opcode
    int opcode_base;
    switch (s->opcode) {
    case 0xC8 ... 0xCF: // bswap
        opcode_base = 0xC8;
do_opcode_reg:
        regs |= (1 << ((s->opcode - opcode_base) | (s->rex_b << 3)));
        break;
    case 0xB8 ... 0xBF: // mov
        opcode_base = 0xB8;
        goto do_opcode_reg;
    case 0x58 ... 0x5F: // pop
        opcode_base = 0x58;
        goto do_opcode_reg;
    case 0x50 ... 0x57: // push
        opcode_base = 0x50;
        goto do_opcode_reg;
    case 0x90 ... 0x97: // xchg
        opcode_base = 0x90;
        goto do_opcode_reg;
    }

    return regs;
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

    // These are volatile registers we can safely wreck.
    // Assume AMD ABI, up to 4 arguments.
    int spare_regs = ~(RDI | RSI | RDX | RCX | RBX | RBP | RSP | R12 | R13 | R14 | R15);

    // Prepare code to overwrite @fn with. This will be JMP @replacement.
    rc = write_jmp(&fn_overlay, (uintptr_t)replacement, spare_regs);
    if (rc != 0) return rc;

    // Deferred jump sequences (Jcc)
    int       jump_n = 0;
    uint8_t   jump_pos[JCC_MAX];
    uintptr_t jump_dest[JCC_MAX];

    // Detect jumps into the code range we overwrite.
    uintptr_t rip_hazard = UINTPTR_MAX;

    // @fn is going to be partially clobbered. Disassemble and evacuate
    // some instructions.
    size_t disas_offset = 0;
    while (disas_offset < overlay_size(&fn_overlay)) {

        const uint8_t *i = (const uint8_t *)fn + disas_offset;
        hde64s s;

        hde64_disasm(i, &s);
        if (s.flags & F_ERROR) return -1;
        disas_offset += s.len;

        spare_regs &= ~regs_used(&s);

        // TODO: RIP-relative addressing

        uintptr_t rip_dest = UINTPTR_MAX;

        switch (s.opcode) {

        case 0xCC:
            // int3: this is probably a breakpoint set by a debugger
            return -1;

        case 0xE9:
            // relative jump, 8 bit immediate offset
            assert(s.flags & F_IMM8);
            rip_dest = (uintptr_t)fn + disas_offset + (int8_t)s.imm.imm8;
            rc = write_jmp(&t_overlay, rip_dest, spare_regs);
            if (rc != 0) return rc;
            s.len = 0;
            break;

        case 0xEB:
            // relative jump, 32 bit immediate offset
            assert(s.flags & F_IMM32);
            rip_dest = (uintptr_t)fn + disas_offset + (int32_t)s.imm.imm32;
            rc = write_jmp(&t_overlay, rip_dest, spare_regs);
            if (rc != 0) return rc;
            s.len = 0;
            break;

        case 0xE3:
        case 0x70 ... 0x7f:
            // Jcc jump, 8 bit immediate offset
            assert(s.flags & F_IMM8);
            rip_dest = (uintptr_t)fn + disas_offset + (int8_t)s.imm.imm8;
            jump_pos[jump_n] = overlay_size(&t_overlay) + s.len;
            jump_dest[jump_n] = rip_dest;
            jump_n += 1;
            // Let the instruction come through as is, will patch later.
            break;

        case 0x0F:
            if (s.opcode2 >= 0x80 && s.opcode2 <= 0x8F) {
                // Jcc jump, 32 bit immediate offset
                assert(s.flags & F_IMM32);
                rip_dest = (uintptr_t)fn + disas_offset + (int32_t)s.imm.imm32;

                // Convert to a shorter form
                t_overlay.p[0] = s.opcode2 - 0x10;
                t_overlay.p += 2;
                s.len = 0;

                jump_pos[jump_n] = overlay_size(&t_overlay);
                jump_dest[jump_n] = rip_dest;
                jump_n += 1;
            }
            break;
        }

        // Copy instruction, unless suppressed.
        if (s.len != 0) {
            memcpy(t_overlay.p, i, s.len);
            t_overlay.p += s.len;
        }

        // Update rip_hazard
        if (rip_dest >= (uintptr_t)fn && rip_dest < rip_hazard)
            rip_hazard = rip_dest;
    }

    // If we've seen a jump into the range we are about to overwrite,
    // this isn't going to work.
    if (rip_hazard - (uintptr_t)fn < disas_offset) return -1;

    // If we've clobbered a *part* of an instruction, we should beter
    // int3 the surviving part.
    size_t partially_clobbered = disas_offset - overlay_size(&fn_overlay);
    memset(fn_overlay.p, 0xcc, partially_clobbered);
    fn_overlay.p += partially_clobbered;

    // Connect trampoline to the unclobbered part of @fn.
    rc = write_jmp(&t_overlay, (uintptr_t)fn + disas_offset, spare_regs);
    if (rc != 0) return rc;

    // Finally fix Jcc-s.
    for (int i = 0; i < jump_n; i++) {
        t_overlay.code[jump_pos[i] - 1] = (uint8_t)(overlay_size(&t_overlay) - jump_pos[i]);
        rc = write_jmp(&t_overlay, jump_dest[i], spare_regs);
        if (rc != 0) return rc;
    }

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
