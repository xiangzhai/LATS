/*
 *  x86 misc helpers - sysemu code
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/timer.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "exec/address-spaces.h"
#include "exec/exec-all.h"
#include "tcg/helper-tcg.h"
#include "hamt-tlb.h"
#include "latx/include/latx-options.h"
#include "trace.h"

void helper_outb(CPUX86State *env, uint32_t port, uint32_t data)
{
    address_space_stb(&address_space_io, port, data,
                      cpu_get_mem_attrs(env), NULL);
}

target_ulong helper_inb(CPUX86State *env, uint32_t port)
{
    return address_space_ldub(&address_space_io, port,
                              cpu_get_mem_attrs(env), NULL);
}

void helper_outw(CPUX86State *env, uint32_t port, uint32_t data)
{
    address_space_stw(&address_space_io, port, data,
                      cpu_get_mem_attrs(env), NULL);
}

target_ulong helper_inw(CPUX86State *env, uint32_t port)
{
    return address_space_lduw(&address_space_io, port,
                              cpu_get_mem_attrs(env), NULL);
}

void helper_outl(CPUX86State *env, uint32_t port, uint32_t data)
{
    address_space_stl(&address_space_io, port, data,
                      cpu_get_mem_attrs(env), NULL);
}

target_ulong helper_inl(CPUX86State *env, uint32_t port)
{
    return address_space_ldl(&address_space_io, port,
                             cpu_get_mem_attrs(env), NULL);
}

/*
 * Batched REP INS/OUTS.
 *
 * The old translation emitted a loop that called helper_inb/outb (and the
 * softmmu accessors) once per element.  Every port access took the BQL, so a
 * 512-byte PIO sector cost hundreds of lock/unlock pairs.  Process a chunk at
 * a time instead: guest memory is accessed outside the BQL, and the port
 * accesses of a chunk are performed under one BQL acquisition.
 *
 * info layout:
 *   bits 0-1  size code (0=1, 1=2, 2=4 bytes)
 *   bits 3-4  address size (0=16, 1=32, 2=64 bits)
 *   bit  5    REP prefix present
 *   bits 8-11 mmu index
 *   bits 12-14 segment index
 */
#define LATX_REP_IO_CHUNK 256

static inline uint32_t latx_rep_port_read(CPUX86State *env, uint32_t port,
                                          int size_code)
{
    switch (size_code) {
    case 0:
        return address_space_ldub(&address_space_io, port,
                                  cpu_get_mem_attrs(env), NULL);
    case 1:
        return address_space_lduw(&address_space_io, port,
                                  cpu_get_mem_attrs(env), NULL);
    default:
        return address_space_ldl(&address_space_io, port,
                                 cpu_get_mem_attrs(env), NULL);
    }
}

static inline void latx_rep_port_write(CPUX86State *env, uint32_t port,
                                       int size_code, uint32_t val)
{
    switch (size_code) {
    case 0:
        address_space_stb(&address_space_io, port, val,
                          cpu_get_mem_attrs(env), NULL);
        break;
    case 1:
        address_space_stw(&address_space_io, port, val,
                          cpu_get_mem_attrs(env), NULL);
        break;
    default:
        address_space_stl(&address_space_io, port, val,
                          cpu_get_mem_attrs(env), NULL);
        break;
    }
}

static inline uint32_t latx_rep_guest_load(CPUX86State *env, uint64_t addr,
                                           int size_code, int mmu_idx,
                                           uintptr_t ra)
{
    switch (size_code) {
    case 0:
        return cpu_ldub_mmuidx_ra(env, addr, mmu_idx, ra);
    case 1:
        return cpu_lduw_mmuidx_ra(env, addr, mmu_idx, ra);
    default:
        return cpu_ldl_mmuidx_ra(env, addr, mmu_idx, ra);
    }
}

static inline void latx_rep_guest_store(CPUX86State *env, uint64_t addr,
                                        uint32_t val, int size_code,
                                        int mmu_idx, uintptr_t ra)
{
    switch (size_code) {
    case 0:
        cpu_stb_mmuidx_ra(env, addr, val, mmu_idx, ra);
        break;
    case 1:
        cpu_stw_mmuidx_ra(env, addr, val, mmu_idx, ra);
        break;
    default:
        cpu_stl_mmuidx_ra(env, addr, val, mmu_idx, ra);
        break;
    }
}

static inline uint64_t latx_rep_get_reg(CPUX86State *env, int reg,
                                        int addr_code)
{
    uint64_t v = env->regs[reg];

    if (addr_code == 0) {
        return (uint16_t)v;
    }
    if (addr_code == 1) {
        return (uint32_t)v;
    }
    return v;
}

static inline void latx_rep_set_reg(CPUX86State *env, int reg, int addr_code,
                                    uint64_t v)
{
    if (addr_code == 0) {
        env->regs[reg] = (env->regs[reg] & ~0xffffULL) | (v & 0xffff);
    } else if (addr_code == 1) {
        env->regs[reg] = (uint32_t)v;
    } else {
        env->regs[reg] = v;
    }
}

static inline uint64_t latx_rep_advance(uint64_t v, int step, int addr_code)
{
    v += step;

    if (addr_code == 0) {
        return v & 0xffff;
    }
    if (addr_code == 1) {
        return v & 0xffffffff;
    }
    return v;
}

static void latx_rep_io(CPUX86State *env, uint32_t port, uint32_t info,
                        bool is_ins)
{
    int size_code = info & 3;
    int addr_code = (info >> 3) & 3;
    bool is_rep = (info >> 5) & 1;
    int mmu_idx = (info >> 8) & 0xf;
    int seg = (info >> 12) & 7;
    int size = 1 << size_code;
    int step = env->df * size;
    uint64_t count = is_rep ?
        latx_rep_get_reg(env, R_ECX, addr_code) : 1;
    uint64_t done = 0;
    uint64_t idx = latx_rep_get_reg(env, is_ins ? R_EDI : R_ESI, addr_code);
    uint64_t seg_base = env->segs[seg].base;
    uint8_t buf[LATX_REP_IO_CHUNK * 4];
    uintptr_t ra = GETPC();
    X86CPU *cpu = env_archcpu(env);
    uint32_t old_can_do_io = cpu->parent_obj.can_do_io;
    int reg = is_ins ? R_EDI : R_ESI;

    port &= 0xffff;

    while (done < count) {
        uint64_t left = count - done;
        uint32_t n = left > LATX_REP_IO_CHUNK ? LATX_REP_IO_CHUNK : left;
        uint64_t chunk_idx = idx;

        if (is_ins) {
            /*
             * Fault the destination in before consuming I/O data so a page
             * fault restarts the whole chunk without losing port input.
             */
            for (uint32_t i = 0; i < n; i++) {
                latx_rep_guest_store(env, seg_base + chunk_idx, 0,
                                     size_code, mmu_idx, ra);
                chunk_idx = latx_rep_advance(chunk_idx, step, addr_code);
            }

            bool took_bql = !qemu_mutex_iothread_locked();

            if (took_bql) {
                qemu_mutex_lock_iothread();
            }
            cpu->parent_obj.can_do_io = 1;
            for (uint32_t i = 0; i < n; i++) {
                uint32_t v = latx_rep_port_read(env, port, size_code);
                memcpy(buf + i * size, &v, size);
            }
            cpu->parent_obj.can_do_io = old_can_do_io;
            if (took_bql) {
                qemu_mutex_unlock_iothread();
            }

            for (uint32_t i = 0; i < n; i++) {
                uint32_t v = 0;

                memcpy(&v, buf + i * size, size);
                latx_rep_guest_store(env, seg_base + idx, v,
                                     size_code, mmu_idx, ra);
                idx = latx_rep_advance(idx, step, addr_code);
                if (is_rep) {
                    latx_rep_set_reg(env, R_ECX, addr_code,
                                     count - done - i - 1);
                }
                latx_rep_set_reg(env, reg, addr_code, idx);
            }
        } else {
            for (uint32_t i = 0; i < n; i++) {
                uint32_t v = latx_rep_guest_load(env, seg_base + chunk_idx,
                                                 size_code, mmu_idx, ra);

                memcpy(buf + i * size, &v, size);
                chunk_idx = latx_rep_advance(chunk_idx, step, addr_code);
            }

            bool took_bql = !qemu_mutex_iothread_locked();

            if (took_bql) {
                qemu_mutex_lock_iothread();
            }
            cpu->parent_obj.can_do_io = 1;
            for (uint32_t i = 0; i < n; i++) {
                uint32_t v = 0;

                memcpy(&v, buf + i * size, size);
                latx_rep_port_write(env, port, size_code, v);
                idx = latx_rep_advance(idx, step, addr_code);
                if (is_rep) {
                    latx_rep_set_reg(env, R_ECX, addr_code,
                                     count - done - i - 1);
                }
                latx_rep_set_reg(env, reg, addr_code, idx);
            }
            cpu->parent_obj.can_do_io = old_can_do_io;
            if (took_bql) {
                qemu_mutex_unlock_iothread();
            }
        }

        done += n;
    }
}

void helper_rep_ins(CPUX86State *env, uint32_t port, uint32_t info)
{
    latx_rep_io(env, port, info, true);
}

void helper_rep_outs(CPUX86State *env, uint32_t port, uint32_t info)
{
    latx_rep_io(env, port, info, false);
}

target_ulong helper_read_crN(CPUX86State *env, int reg)
{
    target_ulong val;

    switch (reg) {
    default:
        val = env->cr[reg];
        break;
    case 8:
        if (!(env->hflags2 & HF2_VINTR_MASK)) {
            val = cpu_get_apic_tpr(env_archcpu(env)->apic_state);
        } else {
            val = env->int_ctl & V_TPR_MASK;
        }
        break;
    }
    return val;
}

void helper_write_crN(CPUX86State *env, int reg, target_ulong t0)
{
    switch (reg) {
    case 0:
        /*
        * If we reach this point, the CR0 write intercept is disabled.
        * But we could still exit if the hypervisor has requested the selective
        * intercept for bits other than TS and MP
        */
        if (cpu_svm_has_intercept(env, SVM_EXIT_CR0_SEL_WRITE) &&
            ((env->cr[0] ^ t0) & ~(CR0_TS_MASK | CR0_MP_MASK))) {
            cpu_vmexit(env, SVM_EXIT_CR0_SEL_WRITE, 0, GETPC());
        }
        if ((env->cr[4] & CR4_PCIDE_MASK) && !(t0 & CR0_PG_MASK)) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        cpu_x86_update_cr0(env, t0);
        break;
    case 3: {
        int64_t start = option_pcid_stats ? get_clock() : 0;
        bool noflush = (env->cr[4] & CR4_PCIDE_MASK) && (t0 & BIT_ULL(63));

        /* Bit 63 of the source is a hint, never part of the stored CR3. */
        if (env->cr[4] & CR4_PCIDE_MASK) {
            t0 &= ~BIT_ULL(63);
        }
        if ((env->efer & MSR_EFER_LMA) &&
                (t0 & ((~0ULL) << env_archcpu(env)->phys_bits))) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        if (!(env->efer & MSR_EFER_LMA)) {
            t0 &= 0xffffffffUL;
        }
        if (option_pcid_stats) {
            unsigned pcid = t0 & 0xfff;

            qatomic_inc(&env->pcid_stats.cr3_writes);
            if (env->cr[4] & CR4_PCIDE_MASK) {
                qatomic_inc(&env->pcid_stats.pcide_writes);
                qatomic_or(&env->pcid_stats.seen[pcid >> 6],
                           BIT_ULL(pcid & 63));
            }
            if (noflush) {
                qatomic_inc(&env->pcid_stats.noflush);
            }
        }
        trace_x86_pcid_cr3(env_cpu(env)->cpu_index, env->eip, env->cr[3], t0,
                           noflush);
        if (option_pcid_asid && (env->cr[4] & CR4_PCIDE_MASK) &&
            hamt_is_running() && hamt_switch_pcid(env, t0, noflush)) {
            env->cr[3] = t0;
            tlb_flush_after_pcid_switch(env_cpu(env));
        } else {
            cpu_x86_update_cr3(env, t0);
        }
        if (option_pcid_stats) {
            qatomic_add(&env->pcid_stats.cr3_ns, get_clock() - start);
        }
        break;
    }
    case 4:
        if ((t0 & cr4_reserved_bits(env)) ||
            ((env->efer & MSR_EFER_LMA) && !(t0 & CR4_PAE_MASK)) ||
            ((t0 & CR4_PCIDE_MASK) &&
             (!(env->efer & MSR_EFER_LMA) ||
              (!(env->cr[4] & CR4_PCIDE_MASK) && (env->cr[3] & 0xfff))))) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        if (((t0 ^ env->cr[4]) & CR4_LA57_MASK) &&
            (env->hflags & HF_CS64_MASK)) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        if (option_pcid_stats && (t0 & CR4_PCIDE_MASK) &&
            !(env->cr[4] & CR4_PCIDE_MASK)) {
            qatomic_inc(&env->pcid_stats.enables);
            qatomic_or(&env->pcid_stats.seen[0], 1);
        }
        cpu_x86_update_cr4(env, t0);
        break;
    case 8:
        if (!(env->hflags2 & HF2_VINTR_MASK)) {
            qemu_mutex_lock_iothread();
            cpu_set_apic_tpr(env_archcpu(env)->apic_state, t0);
            qemu_mutex_unlock_iothread();
        }
        env->int_ctl = (env->int_ctl & ~V_TPR_MASK) | (t0 & V_TPR_MASK);

        CPUState *cs = env_cpu(env);
        if (ctl_has_irq(env)) {
            cpu_interrupt(cs, CPU_INTERRUPT_VIRQ);
        } else {
            cpu_reset_interrupt(cs, CPU_INTERRUPT_VIRQ);
        }
        break;
    default:
        env->cr[reg] = t0;
        break;
    }
}

/* Legacy linear addresses wrap at 4 GiB, even inside an unaligned qword. */
static uint64_t invpcid_ldq(CPUX86State *env, target_ulong addr, uintptr_t ra)
{
    if (!(env->hflags & HF_CS64_MASK)) {
        addr = (uint32_t)addr;
        if (unlikely(addr > UINT32_MAX - 7)) {
            uint64_t value = 0;

            for (unsigned i = 0; i < 8; i++) {
                value |= (uint64_t)cpu_ldub_data_ra(env, (uint32_t)(addr + i),
                                                    ra) << (8 * i);
            }
            return value;
        }
    }
    return cpu_ldq_data_ra(env, addr, ra);
}

/*
 * The descriptor is a memory operand even for the all-context variants.
 * Complete both reads and all validation before changing any cached state.
 */
void helper_invpcid(CPUX86State *env, target_ulong addr, uint32_t reg,
                    uint32_t seg)
{
    const uintptr_t ra = GETPC();
    uint64_t type = (env->hflags & HF_CS64_MASK) ?
                    env->regs[reg] : (uint32_t)env->regs[reg];
    uint64_t pcid, linear;
    int width = env->cr[4] & CR4_LA57_MASK ? 57 : 48;

    if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_INVPCID) ||
        (IS_AMD_CPU(env) &&
         (!(env->cr[0] & CR0_PE_MASK) || (env->eflags & VM_MASK)))) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    if (env->hflags & HF_CPL_MASK) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }
    if (unlikely(env->hflags & HF_GUEST_MASK)) {
        CPUState *cs = env_cpu(env);
        hwaddr vmcb = env->vm_vmcb;

        /* The intercept precedes descriptor address and contents checks. */
        if (x86_ldl_phys(cs, vmcb + offsetof(struct vmcb, control.intercept3))
            & SVM_INTERCEPT_INVPCID) {
            x86_stq_phys(cs, vmcb + offsetof(struct vmcb, control.exit_info_2),
                         type);
            cpu_vmexit(env, SVM_EXIT_INVPCID, addr, ra);
        }
    }
    if (env->hflags & HF_CS64_MASK) {
        uint64_t end = addr + 15;

        if (end < addr || (uint64_t)sextract64(addr, 0, width) != addr ||
            (uint64_t)sextract64(end, 0, width) != end) {
            raise_exception_ra(env, seg == R_SS ? EXCP0C_STACK : EXCP0D_GPF,
                               ra);
        }
    } else {
        SegmentCache *sc = &env->segs[seg];
        uint64_t offset = (uint32_t)(addr - sc->base);
        uint64_t end = offset + 15;
        bool invalid;

        if (!(sc->flags & DESC_CS_MASK) && (sc->flags & DESC_E_MASK)) {
            invalid = offset <= sc->limit ||
                      end > ((sc->flags & DESC_B_MASK)
                             ? UINT32_MAX : UINT16_MAX);
        } else {
            invalid = end > sc->limit;
        }
        if ((env->cr[0] & CR0_PE_MASK) &&
            (!(sc->flags & DESC_P_MASK) ||
             ((sc->flags & DESC_CS_MASK) && !(sc->flags & DESC_R_MASK)))) {
            invalid = true;
        }
        if (invalid) {
            raise_exception_ra(env, seg == R_SS ? EXCP0C_STACK : EXCP0D_GPF,
                               ra);
        }
    }
    pcid = invpcid_ldq(env, addr, ra);
    linear = invpcid_ldq(env, addr + 8, ra);
    if (type > 3 || (pcid >> 12) ||
        (type <= 1 && !(env->cr[4] & CR4_PCIDE_MASK) && pcid) ||
        (type == 0 && linear !=
         (uint64_t)sextract64(linear, 0, cpu_x86_virtual_addr_width(env)))) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    if (option_pcid_stats) {
        qatomic_inc(&env->pcid_stats.invpcid[type]);
    }
    /* Over-invalidation is permitted for all four architectural types. */
    tlb_flush(env_cpu(env));
}

void helper_wrmsr(CPUX86State *env)
{
    uint64_t val;
    CPUState *cs = env_cpu(env);

    cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 1, GETPC());

    val = ((uint32_t)env->regs[R_EAX]) |
        ((uint64_t)((uint32_t)env->regs[R_EDX]) << 32);

    switch ((uint32_t)env->regs[R_ECX]) {
    case MSR_IA32_TSC:
        env->tsc_base_offset += val - cpu_get_tsc(env);
        break;
    case MSR_IA32_SYSENTER_CS:
        env->sysenter_cs = val & 0xffff;
        break;
    case MSR_IA32_SYSENTER_ESP:
        env->sysenter_esp = val;
        break;
    case MSR_IA32_SYSENTER_EIP:
        env->sysenter_eip = val;
        break;
    case MSR_IA32_APICBASE:
        cpu_set_apic_base(env_archcpu(env)->apic_state, val);
        break;
    case MSR_EFER:
        {
            uint64_t update_mask;

            update_mask = 0;
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_SYSCALL) {
                update_mask |= MSR_EFER_SCE;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
                update_mask |= MSR_EFER_LME;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR) {
                update_mask |= MSR_EFER_FFXSR;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_NX) {
                update_mask |= MSR_EFER_NXE;
            }
            if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
                update_mask |= MSR_EFER_SVME;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR) {
                update_mask |= MSR_EFER_FFXSR;
            }
            cpu_load_efer(env, (env->efer & ~update_mask) |
                          (val & update_mask));
        }
        break;
    case MSR_STAR:
        env->star = val;
        break;
    case MSR_PAT:
        env->pat = val;
        break;
    case MSR_IA32_PKRS:
        if (val & 0xFFFFFFFF00000000ull) {
            goto error;
        }
        env->pkrs = val;
        tlb_flush(cs);
        break;
    case MSR_VM_HSAVE_PA:
        env->vm_hsave = val;
        break;
#ifdef TARGET_X86_64
    case MSR_LSTAR:
        env->lstar = val;
        break;
    case MSR_CSTAR:
        env->cstar = val;
        break;
    case MSR_FMASK:
        env->fmask = val;
        break;
    case MSR_FSBASE:
        env->segs[R_FS].base = val;
        break;
    case MSR_GSBASE:
        env->segs[R_GS].base = val;
        break;
    case MSR_KERNELGSBASE:
        env->kernelgsbase = val;
        break;
#endif
    case MSR_MTRRphysBase(0):
    case MSR_MTRRphysBase(1):
    case MSR_MTRRphysBase(2):
    case MSR_MTRRphysBase(3):
    case MSR_MTRRphysBase(4):
    case MSR_MTRRphysBase(5):
    case MSR_MTRRphysBase(6):
    case MSR_MTRRphysBase(7):
        env->mtrr_var[((uint32_t)env->regs[R_ECX] -
                       MSR_MTRRphysBase(0)) / 2].base = val;
        break;
    case MSR_MTRRphysMask(0):
    case MSR_MTRRphysMask(1):
    case MSR_MTRRphysMask(2):
    case MSR_MTRRphysMask(3):
    case MSR_MTRRphysMask(4):
    case MSR_MTRRphysMask(5):
    case MSR_MTRRphysMask(6):
    case MSR_MTRRphysMask(7):
        env->mtrr_var[((uint32_t)env->regs[R_ECX] -
                       MSR_MTRRphysMask(0)) / 2].mask = val;
        break;
    case MSR_MTRRfix64K_00000:
        env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                        MSR_MTRRfix64K_00000] = val;
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                        MSR_MTRRfix16K_80000 + 1] = val;
        break;
    case MSR_MTRRfix4K_C0000:
    case MSR_MTRRfix4K_C8000:
    case MSR_MTRRfix4K_D0000:
    case MSR_MTRRfix4K_D8000:
    case MSR_MTRRfix4K_E0000:
    case MSR_MTRRfix4K_E8000:
    case MSR_MTRRfix4K_F0000:
    case MSR_MTRRfix4K_F8000:
        env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                        MSR_MTRRfix4K_C0000 + 3] = val;
        break;
    case MSR_MTRRdefType:
        env->mtrr_deftype = val;
        break;
    case MSR_MCG_STATUS:
        env->mcg_status = val;
        break;
    case MSR_MCG_CTL:
        if ((env->mcg_cap & MCG_CTL_P)
            && (val == 0 || val == ~(uint64_t)0)) {
            env->mcg_ctl = val;
        }
        break;
    case MSR_TSC_AUX:
        env->tsc_aux = val;
        break;
    case MSR_IA32_MISC_ENABLE:
        env->msr_ia32_misc_enable = val;
        break;
    case MSR_IA32_BNDCFGS:
        /* FIXME: #GP if reserved bits are set.  */
        /* FIXME: Extend highest implemented bit of linear address.  */
        env->msr_bndcfgs = val;
        cpu_sync_bndcs_hflags(env);
        break;
    default:
        if ((uint32_t)env->regs[R_ECX] >= MSR_MC0_CTL
            && (uint32_t)env->regs[R_ECX] < MSR_MC0_CTL +
            (4 * env->mcg_cap & 0xff)) {
            uint32_t offset = (uint32_t)env->regs[R_ECX] - MSR_MC0_CTL;
            if ((offset & 0x3) != 0
                || (val == 0 || val == ~(uint64_t)0)) {
                env->mce_banks[offset] = val;
            }
            break;
        }
        /* XXX: exception? */
        break;
    }
    return;
error:
    raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
}

void helper_rdmsr(CPUX86State *env)
{
    X86CPU *x86_cpu = env_archcpu(env);
    uint64_t val;

    cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 0, GETPC());

    switch ((uint32_t)env->regs[R_ECX]) {
    case MSR_IA32_TSC:
        val = cpu_get_tsc(env) + env->tsc_offset;
        break;
    case MSR_IA32_SYSENTER_CS:
        val = env->sysenter_cs;
        break;
    case MSR_IA32_SYSENTER_ESP:
        val = env->sysenter_esp;
        break;
    case MSR_IA32_SYSENTER_EIP:
        val = env->sysenter_eip;
        break;
    case MSR_IA32_APICBASE:
        val = cpu_get_apic_base(env_archcpu(env)->apic_state);
        break;
    case MSR_EFER:
        val = env->efer;
        break;
    case MSR_STAR:
        val = env->star;
        break;
    case MSR_PAT:
        val = env->pat;
        break;
    case MSR_IA32_PKRS:
        val = env->pkrs;
        break;
    case MSR_VM_HSAVE_PA:
        val = env->vm_hsave;
        break;
    case MSR_IA32_PERF_STATUS:
        /* tsc_increment_by_tick */
        val = 1000ULL;
        /* CPU multiplier */
        val |= (((uint64_t)4ULL) << 40);
        break;
#ifdef TARGET_X86_64
    case MSR_LSTAR:
        val = env->lstar;
        break;
    case MSR_CSTAR:
        val = env->cstar;
        break;
    case MSR_FMASK:
        val = env->fmask;
        break;
    case MSR_FSBASE:
        val = env->segs[R_FS].base;
        break;
    case MSR_GSBASE:
        val = env->segs[R_GS].base;
        break;
    case MSR_KERNELGSBASE:
        val = env->kernelgsbase;
        break;
    case MSR_TSC_AUX:
        val = env->tsc_aux;
        break;
#endif
    case MSR_SMI_COUNT:
        val = env->msr_smi_count;
        break;
    case MSR_MTRRphysBase(0):
    case MSR_MTRRphysBase(1):
    case MSR_MTRRphysBase(2):
    case MSR_MTRRphysBase(3):
    case MSR_MTRRphysBase(4):
    case MSR_MTRRphysBase(5):
    case MSR_MTRRphysBase(6):
    case MSR_MTRRphysBase(7):
        val = env->mtrr_var[((uint32_t)env->regs[R_ECX] -
                             MSR_MTRRphysBase(0)) / 2].base;
        break;
    case MSR_MTRRphysMask(0):
    case MSR_MTRRphysMask(1):
    case MSR_MTRRphysMask(2):
    case MSR_MTRRphysMask(3):
    case MSR_MTRRphysMask(4):
    case MSR_MTRRphysMask(5):
    case MSR_MTRRphysMask(6):
    case MSR_MTRRphysMask(7):
        val = env->mtrr_var[((uint32_t)env->regs[R_ECX] -
                             MSR_MTRRphysMask(0)) / 2].mask;
        break;
    case MSR_MTRRfix64K_00000:
        val = env->mtrr_fixed[0];
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        val = env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                              MSR_MTRRfix16K_80000 + 1];
        break;
    case MSR_MTRRfix4K_C0000:
    case MSR_MTRRfix4K_C8000:
    case MSR_MTRRfix4K_D0000:
    case MSR_MTRRfix4K_D8000:
    case MSR_MTRRfix4K_E0000:
    case MSR_MTRRfix4K_E8000:
    case MSR_MTRRfix4K_F0000:
    case MSR_MTRRfix4K_F8000:
        val = env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                              MSR_MTRRfix4K_C0000 + 3];
        break;
    case MSR_MTRRdefType:
        val = env->mtrr_deftype;
        break;
    case MSR_MTRRcap:
        if (env->features[FEAT_1_EDX] & CPUID_MTRR) {
            val = MSR_MTRRcap_VCNT | MSR_MTRRcap_FIXRANGE_SUPPORT |
                MSR_MTRRcap_WC_SUPPORTED;
        } else {
            /* XXX: exception? */
            val = 0;
        }
        break;
    case MSR_MCG_CAP:
        val = env->mcg_cap;
        break;
    case MSR_MCG_CTL:
        if (env->mcg_cap & MCG_CTL_P) {
            val = env->mcg_ctl;
        } else {
            val = 0;
        }
        break;
    case MSR_MCG_STATUS:
        val = env->mcg_status;
        break;
    case MSR_IA32_MISC_ENABLE:
        val = env->msr_ia32_misc_enable;
        break;
    case MSR_IA32_BNDCFGS:
        val = env->msr_bndcfgs;
        break;
     case MSR_IA32_UCODE_REV:
        val = x86_cpu->ucode_rev;
        break;
    case MSR_CORE_THREAD_COUNT: {
        CPUState *cs = CPU(x86_cpu);
        val = (cs->nr_threads * cs->nr_cores) | (cs->nr_cores << 16);
        break;
    }
    default:
        if ((uint32_t)env->regs[R_ECX] >= MSR_MC0_CTL
            && (uint32_t)env->regs[R_ECX] < MSR_MC0_CTL +
            (4 * env->mcg_cap & 0xff)) {
            uint32_t offset = (uint32_t)env->regs[R_ECX] - MSR_MC0_CTL;
            val = env->mce_banks[offset];
            break;
        }
        /* XXX: exception? */
        val = 0;
        break;
    }
    env->regs[R_EAX] = (uint32_t)(val);
    env->regs[R_EDX] = (uint32_t)(val >> 32);
}

void helper_flush_page(CPUX86State *env, target_ulong addr)
{
    tlb_flush_page(env_cpu(env), addr);
}

static G_NORETURN
void do_hlt(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    env->hflags &= ~HF_INHIBIT_IRQ_MASK; /* needed if sti is just before */
    cs->halted = 1;
    cs->exception_index = EXCP_HLT;
    cpu_loop_exit(cs);
}

G_NORETURN void helper_hlt(CPUX86State *env, int next_eip_addend)
{
    cpu_svm_check_intercept_param(env, SVM_EXIT_HLT, 0, GETPC());
    env->eip += next_eip_addend;

    do_hlt(env);
}

void helper_monitor(CPUX86State *env, target_ulong ptr)
{
    if ((uint32_t)env->regs[R_ECX] != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    /* XXX: store address? */
    cpu_svm_check_intercept_param(env, SVM_EXIT_MONITOR, 0, GETPC());
}

G_NORETURN void helper_mwait(CPUX86State *env, int next_eip_addend)
{
    CPUState *cs = env_cpu(env);

    if ((uint32_t)env->regs[R_ECX] != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    cpu_svm_check_intercept_param(env, SVM_EXIT_MWAIT, 0, GETPC());
    env->eip += next_eip_addend;

    /* XXX: not complete but not completely erroneous */
    if (cs->cpu_index != 0 || CPU_NEXT(cs) != NULL) {
        do_pause(env);
    } else {
        do_hlt(env);
    }
}
