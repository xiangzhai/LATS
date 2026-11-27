/*
 * SPDX-FileCopyrightText: 2024-2026 LATS Project Authors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "common.h"
#include "cpu.h"
#include "lsenv.h"
#include "reg-alloc.h"
#include "latx-options.h"
#include "translate.h"
#include "sys-excp.h"
#include <string.h>
#include "hw/i386/apic_internal.h"
#include "hw/timer/hpet.h"
#include "latx-sys-mmio.h"
#include "latx-sys-tr-mmio.h"
#include "latx-sys-hamt-dmw.h"
#include "latx-misc.h"
#include "latx-hack.h"
#include "exec/ram_addr.h"
#include "qemu/qtree.h"
#include "sys-aot.h"

uint64_t guest_hpet_base_ppage = 0xfed00000;
uint64_t guest_hpet_base_vpage;
int guset_hpet_base_vpage_stat;
#define HPET_VPAGE_SLOTS 8
static uint64_t guest_hpet_vpages[HPET_VPAGE_SLOTS];
uint64_t guest_apic_base_ppage = 0xfee00000;
uint64_t guest_apic_base_vpage;
int guset_apic_base_vpage_stat;

void latxs_tb_jmp_unlink(TranslationBlock *dest);

void latx_mem_set_hpet_vpage(uint64_t addr)
{
    uint64_t page = addr & ~0xfffULL;
    int i;

    for (i = 0; i < HPET_VPAGE_SLOTS; i++) {
        uint64_t old = qatomic_read(&guest_hpet_vpages[i]);

        if (old == page) {
            return;
        }
        if (old == 0 &&
            qatomic_cmpxchg(&guest_hpet_vpages[i], 0, page) == 0) {
            break;
        }
    }
    if (guset_hpet_base_vpage_stat == 0) {
        guset_hpet_base_vpage_stat = 1;
        guest_hpet_base_vpage = page;
#ifdef LATX_SYS_DEBUG_OPT_MMIO
        printf("%s:%d page %016lx\n", __func__, __LINE__, page);
#endif
    }
#ifdef LATX_SYS_DEBUG_OPT_MMIO
    else if (guest_hpet_base_vpage != page) {
        printf("%s:%d hpet virtual page %016lx to %016lx\n",
                __func__, __LINE__,
                guest_hpet_base_vpage, page);
    }
#endif
}

void latx_mem_clear_hpet_vpage(uint64_t addr)
{
    uint64_t page = addr & ~0xfffULL;
    int i;

    for (i = 0; i < HPET_VPAGE_SLOTS; i++) {
        qatomic_cmpxchg(&guest_hpet_vpages[i], page, 0);
    }
}

void latx_mem_clear_hpet_vpages(void)
{
    int i;

    for (i = 0; i < HPET_VPAGE_SLOTS; i++) {
        qatomic_set(&guest_hpet_vpages[i], 0);
    }
}

void latx_mem_set_apic_vpage(uint64_t addr)
{
    uint64_t page = addr & ~0xfffULL;
    if (guset_apic_base_vpage_stat == 0) {
        guset_apic_base_vpage_stat = 1;
        guest_apic_base_vpage = page;
#ifdef LATX_SYS_DEBUG_OPT_MMIO
        printf("%s:%d page %016lx\n", __func__, __LINE__, page);
#endif
    }
#ifdef LATX_SYS_DEBUG_OPT_MMIO
    else if (guest_apic_base_vpage != page) {
        printf("%s:%d apic virtual page %016lx to %016lx\n",
                __func__, __LINE__,
                guest_apic_base_vpage, page);
    }
#endif
}

void latx_do_mmio_detected_tb_invalidate(TranslationBlock *tb);

#ifdef LATX_SYS_DEBUG_OPT_MMIO
static void print_opt_mmio_tb_bytes(TranslationBlock *tb)
{
    uint8_t *p = NULL;
    if (tb_page_addr0(tb) != -1) {
        printf(" bytes ");
        p = qemu_ram_addr_to_host(tb_page_addr0(tb));
        if (tb->page_addr[1] == -1) {
            for (int j = 0; j < tb->size; ++j) {
                printf("%02x", *(p + j));
            }
        } else {
            int p0size = 0x1000 - (tb->page_addr[0] & 0xfff);
            for (int j = 0; j < p0size; ++j) {
                printf("%02x", *(p + j));
            }
            p = qemu_ram_addr_to_host(tb_page_addr1(tb));
            for (int j = 0; j < (tb->size - p0size); ++j) {
                printf("%02x", *(p + j));
            }
        }
    }
}
#endif

void latx_do_mmio_tb_retranslate(void *ptr, int type)
{
    TranslationBlock *tb = tcg_tb_lookup((uintptr_t)ptr);
    if (!tb) return;
    /* if already optimized, return */
    if (check_misc_flags(tb, MF_MMIO_OPT)) return;
    /* mark this tb to optimize */
    tb->opt_mmio_type = type;
    /* unlink this TB
     * note: TB with MF_APIC_DETECTED will not be linked */
//    latxs_tb_jmp_unlink(tb);
    latx_do_mmio_detected_tb_invalidate(tb);
#ifdef LATX_SYS_DEBUG_OPT_MMIO
    printf("%s:%d TB %p PC %lx phys %lx flags %x opt_mmio_type %d",
            __func__, __LINE__, tb, tb->pc, tb->page_addr[0], tb->flags,
            type);
    print_opt_mmio_tb_bytes(tb);
    printf("\n");
#endif
}

QemuSpin mmio_tb_waiting_lock;
QTree *mmio_tb_waiting_tree;
/*
 * Lock-free depth of mmio_tb_waiting_tree.  The translation hot path only
 * takes mmio_tb_waiting_lock when a TB is actually waiting for MMIO
 * retranslation.  A missed increment just causes one more MMIO detection
 * round, never a lost optimization.
 */
static unsigned mmio_tb_waiting_count;

typedef struct {
    uint64_t pc;
    uint64_t cs_base;
    uint64_t page_addr;
    uint32_t flags;
    int cflags;
} mmio_tb_key_t;

typedef struct {
    int index;
    int opt_mmio_type;
} mmio_tb_val_t;

#define MMIOTBDATAMAX   1024
mmio_tb_key_t mmio_tb_key_data[MMIOTBDATAMAX];
mmio_tb_val_t mmio_tb_val_data[MMIOTBDATAMAX];
int mmio_tb_data_index;

/* call with mmio_tb_waiting_lock */
static int mmio_tb_alloc(void)
{
    int start = (mmio_tb_data_index + 1) % MMIOTBDATAMAX;

    for (int n = 0; n < MMIOTBDATAMAX; n++) {
        int i = (start + n) % MMIOTBDATAMAX;

        if (mmio_tb_val_data[i].index == -1) {
            mmio_tb_val_data[i].index = i;
            mmio_tb_data_index = i;
            return i;
        }
    }
    return -1;
}

/* call with mmio_tb_waiting_lock */
static void mmio_tb_free(int i)
{
    mmio_tb_val_data[i].index = -1;
}

static gint mmio_tb_cmp(gconstpointer ap, gconstpointer bp)
{
    const mmio_tb_key_t *a = ap;
    const mmio_tb_key_t *b = bp;

    /*
     * GTree requires a strict weak ordering.  Compare every key field in a
     * deterministic order; returning a non-zero value for both (a, b) and
     * (b, a) corrupts lookups when two TBs share pc but differ in flags,
     * cflags or cs_base.
     */
    if (a->pc < b->pc) return -1;
    if (a->pc > b->pc) return 1;
    if (a->page_addr < b->page_addr) return -1;
    if (a->page_addr > b->page_addr) return 1;
    if (a->flags < b->flags) return -1;
    if (a->flags > b->flags) return 1;
    if (a->cs_base < b->cs_base) return -1;
    if (a->cs_base > b->cs_base) return 1;
    if (a->cflags < b->cflags) return -1;
    if (a->cflags > b->cflags) return 1;
    return 0;
}

static void __attribute__((constructor)) mmio_tb_init(void)
{
    qemu_spin_init(&mmio_tb_waiting_lock);
    mmio_tb_waiting_tree = q_tree_new(mmio_tb_cmp);
    for (int i = 0; i < MMIOTBDATAMAX; ++i) {
        mmio_tb_val_data[i].index = -1;
    }
}

static bool mmio_tb_insert_waiting(TranslationBlock *tb)
{
    if (check_misc_flags(tb, MF_MMIO_OPT)) return false;
    if (tb->cflags & CF_INVALID) return false;

    qemu_spin_lock(&mmio_tb_waiting_lock);

    {
        mmio_tb_key_t k;
        k.pc = tb->pc;
        k.cs_base = tb->cs_base;
        k.page_addr = tb->page_addr[0];
        k.flags = tb->flags;
        k.cflags = tb->cflags;
        mmio_tb_val_t *v = q_tree_lookup(mmio_tb_waiting_tree, &k);
        if (v) {
            qemu_spin_unlock(&mmio_tb_waiting_lock);
            return true;
        }
    }

    int id = mmio_tb_alloc();
    if (id < 0) {
        qemu_spin_unlock(&mmio_tb_waiting_lock);
        return false;
    }

    mmio_tb_key_t *k = &mmio_tb_key_data[id];
    mmio_tb_val_t *v = &mmio_tb_val_data[id];

    k->pc        = tb->pc;
    k->flags     = tb->flags;
    k->cflags    = tb->cflags;
    k->cs_base   = tb->cs_base;
    k->page_addr = tb->page_addr[0];

    v->opt_mmio_type = tb->opt_mmio_type;

#ifdef LATX_SYS_DEBUG_OPT_MMIO
    printf("%s:%d ID[%d] TB %p pc %016lx cs %x phys %016lx flags %x cflags %x optmmio %d\n", __func__, __LINE__,
            id, tb ,tb->pc, tb->cs_base, tb->page_addr[0], tb->flags, tb->cflags, tb->opt_mmio_type);
#endif

    q_tree_insert(mmio_tb_waiting_tree, k, v);
    qatomic_inc(&mmio_tb_waiting_count);

    qemu_spin_unlock(&mmio_tb_waiting_lock);
    return true;
}

void latx_mmio_tb_check(TranslationBlock *tb)
{
    if (!option_opt_mmio ||
        likely(!qatomic_read(&mmio_tb_waiting_count))) {
        return;
    }

    qemu_spin_lock(&mmio_tb_waiting_lock);

    mmio_tb_key_t k;
    k.pc = tb->pc;
    k.cs_base = tb->cs_base;
    k.page_addr = tb->page_addr[0];
    k.flags = tb->flags;
    k.cflags = tb->cflags;

    mmio_tb_val_t *v = q_tree_lookup(mmio_tb_waiting_tree, &k);
    if (v == NULL) {
        goto unlock_out;
    }

    set_misc_flags(tb, MF_MMIO_OPT);
    tb->opt_mmio_type = v->opt_mmio_type;

#ifdef LATX_SYS_DEBUG_OPT_MMIO
    printf("%s:%d ID[%d] TB %p pc %016lx phys %016lx flags %x optmmio %d\n", __func__, __LINE__,
            v->index,
            tb ,tb->pc, tb->page_addr[0], tb->flags, tb->opt_mmio_type);
#endif

    q_tree_remove(mmio_tb_waiting_tree, &k);
    mmio_tb_free(v->index);
    qatomic_dec(&mmio_tb_waiting_count);

unlock_out:
    qemu_spin_unlock(&mmio_tb_waiting_lock);
}

void latx_do_mmio_detected_tb_invalidate(TranslationBlock *tb)
{
    if (mmio_tb_insert_waiting(tb)) {
        tb_phys_invalidate(tb, -1);
    }
}

#ifdef CONFIG_LATX_OPT_BQL

extern QemuMutex qemu_global_mutex;

static void latxs_translate_mov_to_apic_eoi(IR2_OPND *label_exit)
{
    IR2_OPND t0 = la_new_itmp();
    IR2_OPND t1 = la_new_itmp();
    IR2_OPND t2 = la_new_itmp();
    IR2_OPND t3 = la_new_itmp();
    IR2_OPND t4 = la_new_itmp();

// (0) spin lock
//    printf("%s:%d global mutex spin at %p\n", __func__, __LINE__,
//            (void *)&(qemu_global_mutex.spin));
    IR2_OPND loop = la_new_label();
    //la_imm(&t0, (uint64_t)(&(qemu_global_mutex.spin)));
    la_out2i(LISA_LD_D, &t0, &la_env, offsetof(CPUX86State, qemu_global_mutex_ptr));
    if (hamt_enabled()) latxs_tr_dmw_in_fix_mem(&t0);
    la_label_name(loop, "LOOP: global mutex spin lock");
    la_out2i(LISA_ADDI_D, &t1, &la_zero, 0x0);
    la_out2i(LISA_ADDI_D, &t2, &la_zero, 0x1);
    la_out3(LISA_AMSWAP_DB_W, &t1, &t0, &t2);
    la_out2(LISA_BNEZ, &t1, &loop);
    la_comment("back to LOOP if lock fail");

    // t0 = &apic_state
    la_out2i(LISA_LD_D, &t0, &la_env, offsetof(CPUX86State, apic_state));
    if (hamt_enabled()) latxs_tr_dmw_in_fix_mem(&t0);

    IR2_OPND out_unlock = la_new_label();
    IR2_OPND s2 = la_new_label();

// (1) int isrv = get_highest_priority_int(s->isr);
    la_out2i(LISA_ADDI_D, &t2, &la_zero, 32);

    la_out2i(LISA_LD_WU,  &t1, &t0, offsetof(APICCommonState, isr[7]));
    la_out2 (LISA_CLZ_W,  &t1, &t1);
    la_out3 (LISA_SUB_D,  &t1, &t2, &t1); // 32 - clz(isr[7])
    la_out2i(LISA_ADDI_D, &t3, &la_zero, 4 * 7);
    la_out2 (LISA_BNEZ,   &t1, &s2);

    la_out2i(LISA_LD_WU,  &t1, &t0, offsetof(APICCommonState, isr[6]));
    la_out2 (LISA_CLZ_W,  &t1, &t1);
    la_out3 (LISA_SUB_D,  &t1, &t2, &t1); // 32 - clz(isr[6])
    la_out2i(LISA_ADDI_D, &t3, &la_zero, 4 * 6);
    la_out2 (LISA_BNEZ,   &t1, &s2);

    la_out2i(LISA_LD_WU,  &t1, &t0, offsetof(APICCommonState, isr[5]));
    la_out2 (LISA_CLZ_W,  &t1, &t1);
    la_out3 (LISA_SUB_D,  &t1, &t2, &t1); // 32 - clz(isr[5])
    la_out2i(LISA_ADDI_D, &t3, &la_zero, 4 * 5);
    la_out2 (LISA_BNEZ,   &t1, &s2);

    la_out2i(LISA_LD_WU,  &t1, &t0, offsetof(APICCommonState, isr[4]));
    la_out2 (LISA_CLZ_W,  &t1, &t1);
    la_out3 (LISA_SUB_D,  &t1, &t2, &t1); // 32 - clz(isr[4])
    la_out2i(LISA_ADDI_D, &t3, &la_zero, 4 * 4);
    la_out2 (LISA_BNEZ,   &t1, &s2);

    la_out2i(LISA_LD_WU,  &t1, &t0, offsetof(APICCommonState, isr[3]));
    la_out2 (LISA_CLZ_W,  &t1, &t1);
    la_out3 (LISA_SUB_D,  &t1, &t2, &t1); // 32 - clz(isr[3])
    la_out2i(LISA_ADDI_D, &t3, &la_zero, 4 * 3);
    la_out2 (LISA_BNEZ,   &t1, &s2);

    la_out2i(LISA_LD_WU,  &t1, &t0, offsetof(APICCommonState, isr[2]));
    la_out2 (LISA_CLZ_W,  &t1, &t1);
    la_out3 (LISA_SUB_D,  &t1, &t2, &t1); // 32 - clz(isr[2])
    la_out2i(LISA_ADDI_D, &t3, &la_zero, 4 * 2);
    la_out2 (LISA_BNEZ,   &t1, &s2);

    la_out2i(LISA_LD_WU,  &t1, &t0, offsetof(APICCommonState, isr[1]));
    la_out2 (LISA_CLZ_W,  &t1, &t1);
    la_out3 (LISA_SUB_D,  &t1, &t2, &t1); // 32 - clz(isr[1])
    la_out2i(LISA_ADDI_D, &t3, &la_zero, 4 * 1);
    la_out2 (LISA_BNEZ,   &t1, &s2);

    la_out2i(LISA_LD_WU,  &t1, &t0, offsetof(APICCommonState, isr[0]));
    la_out2 (LISA_CLZ_W,  &t1, &t1);
    la_out3 (LISA_SUB_D,  &t1, &t2, &t1); // 32 - clz(isr[0])
    la_out2i(LISA_ADDI_D, &t3, &la_zero, 4 * 0);
    la_out2 (LISA_BNEZ,   &t1, &s2);

// (2) if (isrv < 0) return;
    la_out1(LISA_B, &out_unlock);
    la_label_name(s2, "after read isr");
    la_out2i(LISA_ADDI_D, &t1, &t1, -1);
    // t0 = apic state
    // t1 = bit index
    // t2 = 31
    // t3 = offset from isr[0]

//    la_out1(LISA_B, label_exit); // debug

// (4) if (!(s->spurious_vec & APIC_SV_DIRECTED_IO) && apic_get_bit(s->tmr, isrv)) {
//        ioapic_eoi_broadcast(isrv);
//    }
    IR2_OPND no_broadcast_io = la_new_label();

    la_out2i(LISA_ADDI_D, &t2, &t3, offsetof(APICCommonState, tmr[0]));
    la_out3 (LISA_LDX_WU, &t2, &t0, &t2);
    la_comment("get tmr[i]");
    la_out2i(LISA_ADDI_D, &t4, &la_zero, 0x1);
    la_out3 (LISA_SLL_D,  &t4, &t4, &t1);
    la_comment("mask = 1 << (bit index)");
    la_out3(LISA_AND,  &t2, &t2, &t4);
    la_out2(LISA_BEQZ, &t2, &no_broadcast_io);
    la_comment("if tmr[i]'s bit = 1, no broadcast");

    la_out2i(LISA_LD_WU, &t2, &t0, offsetof(APICCommonState, spurious_vec));
    la_comment("get spurious_vec");
    la_out2i(LISA_SRLI_D, &t2, &t2, 12);
    la_out2i(LISA_ANDI, &t2, &t2, 0x1);
    la_comment("get spurious_vec[12]");
    la_out2(LISA_BNEZ, &t2, &no_broadcast_io);
    la_comment("if spurious_vec[12] = 1, no broadcast");

    la_out1(LISA_B, label_exit);
    la_comment("need ioapic broadcast, go to fallback");

    la_label_name(no_broadcast_io, "no ioapic broadcast, go on");

// (3) apic_reset_bit(s->isr, isrv);
    la_out2i(LISA_ADDI_D, &t3, &t3, offsetof(APICCommonState, isr[0]));
    la_out3 (LISA_LDX_WU, &t2, &t0, &t3);
    la_comment("get isr[i]");
    la_out2i(LISA_ADDI_D, &t4, &la_zero, 0x1);
    la_out3 (LISA_SLL_D,  &t4, &t4, &t1);
    la_comment("mask = 1 << (bit index)");
    la_out3(LISA_ANDN,  &t2, &t2, &t4);
    la_out3(LISA_STX_W, &t2, &t0, &t3);
    la_comment("isr[i] = isr[i] & ~mask");
    // t0 = apic state
    // t1 = bit index
    // t3 = offset of isr[i]

// (-) apic_sync_vapic(s, SYNC_FROM_VAPIC | SYNC_TO_VAPIC);

// (5)  apic_update_irq(s);
    la_out2i(LISA_LD_D, &t2, &la_env, offsetof(CPUX86State, interrupt_request_ptr));
    if (hamt_enabled()) latxs_tr_dmw_in_fix_mem(&t2);
    la_out2i(LISA_LD_WU, &t4, &t2, 0);
    la_out2i(LISA_ORI,   &t4, &t4, 0x10); // CPU_INTERRUPT_POLL
    la_out2i(LISA_ST_W,  &t4, &t2, 0);
    la_comment("cpu->interrupt_requset |= CPU_INTERRUPT_POLL");
    la_out2i(LISA_ADDI_D, &t4, &la_zero, -1);
    la_out2i(LISA_ST_W, &t4, &la_env,
                             (int)offsetof(X86CPU, neg.icount_decr.u32) -
                             (int)offsetof(X86CPU, env));
    la_comment("neg.icount_decr.u32 = -1");

// (6)  spin unlock
    la_label_name(out_unlock, "spin unlock and out");
    la_outi(LISA_DBAR, 0x0);
    //la_imm(&t0, (uint64_t)(&(qemu_global_mutex.spin)));
    la_out2i(LISA_LD_D, &t0, &la_env, offsetof(CPUX86State, qemu_global_mutex_ptr));
    if (hamt_enabled()) latxs_tr_dmw_in_fix_mem(&t0);
    la_out2i(LISA_ST_W, &la_zero, &t0, 0);

    la_tmp_free(t0);
    la_tmp_free(t1);
    la_tmp_free(t2);
    la_tmp_free(t3);
    la_tmp_free(t4);
}

#endif

bool latxs_translate_mov_opt_apic(IR1_INST *pir1)
{
    TRANSLATION_DATA *td = lsenv->tr_data;

    if (!td->opt_mmio) return false;
    if (td->opt_mmio_type != TB_OPT_MMIO_APIC) return false;
//    return false;

    td->inst_do_opt_mmio = 1;

    IR1_OPND *opnd0 = ir1_get_opnd(pir1, 0);
    IR1_OPND *opnd1 = ir1_get_opnd(pir1, 1);

    if (ir1_opnd_is_mem(opnd0) && ir1_opnd_is_pc_relative(opnd0)) {
        td->inst_do_opt_mmio = 0;
        return false;
    }
    if (ir1_opnd_is_mem(opnd1) && ir1_opnd_is_pc_relative(opnd1)) {
        td->inst_do_opt_mmio = 0;
        return false;
    }

    if (!ir1_opnd_is_mem(opnd0))   return false;
    if (ir1_opnd_has_base(opnd0))  return false;
    if (ir1_opnd_has_index(opnd0)) return false;

    uint64_t vaddr = ir1_opnd_simm(opnd0);
    uint64_t vpage = vaddr & ~0xfffULL;

#ifdef LATX_SYS_DEBUG_OPT_MMIO
    printf("%s:%d TB %p opt apic on address %016lx\n",
            __func__, __LINE__, lsenv->tr_data->curr_tb, vaddr);
#endif

    if (vpage != guest_apic_base_vpage) {
        printf("%s:%d not apic %016lx\n", __func__, __LINE__, vaddr);
        return false;
    }

#ifdef CONFIG_LATX_OPT_BQL
    int id = (vaddr & 0xfff);
    IR2_OPND eoi_opt_ok = la_new_label();
    int do_eoi_opt = 0;
    if (id == 0xb0) {
        do_eoi_opt = 1;
#ifdef LATX_SYS_DEBUG_OPT_MMIO
        printf("%s:%d TB %p opt apic eoi\n",
                __func__, __LINE__, lsenv->tr_data->curr_tb);
#endif
        IR2_OPND label_exit = la_new_label();

        latxs_translate_mov_to_apic_eoi(&label_exit);
        la_out1(LISA_B, &eoi_opt_ok);

        la_label_name(label_exit, "EOI opt fail, fallback");
        IR2_OPND t0 = la_new_itmp();
        la_outi(LISA_DBAR, 0x0);
        //la_imm(&t0, (uint64_t)(&(qemu_global_mutex.spin)));
        la_out2i(LISA_LD_D, &t0, &la_env, offsetof(CPUX86State, qemu_global_mutex_ptr));
        if (hamt_enabled()) latxs_tr_dmw_in_fix_mem(&t0);
        la_out2i(LISA_ST_W, &la_zero, &t0, 0);
        la_comment("global mutex spin unlock");
        la_tmp_free(t0);
    }
#endif

    IR2_OPND tmp = la_new_itmp();
    latxs_load_ir1_to_ir2(&tmp, opnd1, EXMode_N);
    int os = ir1_opnd_size(opnd0);

    latxs_tr_gen_call_to_helper_prologue_cfg(default_helper_cfg);

//    la_out2i(LISA_ORI, &la_a0, &la_zero, id);
    la_imm(&la_a0, vaddr);
    la_out2_(lisa_mov, &la_a1, &tmp);
    la_out2i(LISA_ORI, &la_a2, &la_zero, os);
    la_out1i(LISA_PCADDI, &la_a3, 0);

    latxs_tr_gen_call_to_helper((ADDR)latx_apic_mem_write, LATX_APIC_MEM_WRITE);

    latxs_tr_gen_call_to_helper_epilogue_cfg(default_helper_cfg);

    la_tmp_free(tmp);

#ifdef CONFIG_LATX_OPT_BQL
    if (do_eoi_opt) {
        la_label_name(eoi_opt_ok, "EOI opt OK, go on");
    }
#endif

    return true;
}

bool latxs_translate_bt_opt_apic(IR1_INST *pir1)
{
    TRANSLATION_DATA *td = lsenv->tr_data;

    if (!td->opt_mmio) return false;
    if (td->opt_mmio_type != TB_OPT_MMIO_APIC) return false;
    td->inst_do_opt_mmio = 1;

    if (ir1_opcode(pir1) != X86_INS_BT) return false;

    IR1_OPND *opnd0 = ir1_get_opnd(pir1, 0); /* bit base   : GPR/MEM */
    IR1_OPND *opnd1 = ir1_get_opnd(pir1, 1); /* bit offset : GPR/imm */

    if (!ir1_opnd_is_mem(opnd0))   return false;
    if (ir1_opnd_has_base(opnd0))  return false;
    if (ir1_opnd_has_index(opnd0)) return false;
    if (!ir1_opnd_is_imm(opnd1))   return false;

    int imm = ir1_opnd_simm(opnd1);

    uint64_t vaddr = ir1_opnd_simm(opnd0);
    uint64_t vpage = vaddr & ~0xfffULL;
    int id = (vaddr & 0xfff);

#ifdef LATX_SYS_DEBUG_OPT_MMIO
    printf("%s:%d TB %p opt apic on address %016lx\n",
            __func__, __LINE__, lsenv->tr_data->curr_tb, vaddr);
#endif

    if (vpage != guest_apic_base_vpage) {
        printf("%s:%d not apic %016lx\n", __func__, __LINE__, vaddr);
        return false;
    }

    // bt	dword ptr [0xfffffffffffe0300], 0xc
    // TODO: read cpu->apic_status.icr directly to support more inst
    if (id != 0x300) return false; // APIC 0x300: ICR
    if (imm != 0xc)  return false; // BIT 12 : Delivery Status

    // BT : CF <- required bit
    // APIC ICR[12] Delivery Status 0: idle 1: Send Pending
    // APIC does not emulate this bit : always 0

//    printf("%s:%d OPT-APIC-BT TB %p\n", __func__, __LINE__,
//            lsenv->tr_data->curr_tb);

    la_out1i(LISA_X86MTFLAG, &la_zero, 0x1);

    return true;
}

/* hw/timer/hpet.c */
extern int hpet_offset_hpet_offset_ticks;
extern int hpet_offset_hpet_counter;
extern int hpet_offset_config;
extern int ts_offset_cpu_clock_offset;

bool latxs_translate_mov_opt_hpet(IR1_INST *pir1)
{
    TranslationBlock *tb __attribute__((unused)) =
        lsenv->tr_data->curr_tb;
    IR1_OPND *dst;
    IR1_OPND *src;
    int offset;
    int i;

    if (!option_opt_mmio_hpet() || option_aot_save) {
        return false;
    }

    dst = ir1_get_opnd(pir1, 0);
    src = ir1_get_opnd(pir1, 1);
    if (!ir1_opnd_is_gpr(dst) || !ir1_opnd_is_mem(src) ||
        ir1_opnd_size(dst) != 32 || ir1_opnd_size(src) != 32) {
        return false;
    }
    offset = ir1_opnd_simm(src);
    if (offset != HPET_COUNTER && offset != HPET_COUNTER + 4) {
        return false;
    }

#ifdef LATX_SYS_DEBUG_OPT_MMIO
    printf("%s:%d TB %p PC 0x%lx candidate HPET counter read offset %x\n",
            __func__, __LINE__, tb, ir1_addr(pir1), offset);
#endif

    IR2_OPND hpet_read = la_new_label();
    IR2_OPND hpet_enable = la_new_label();
    IR2_OPND hpet_have_max = la_new_label();
    IR2_OPND hpet_store = la_new_label();
    IR2_OPND hpet_fallback = la_new_label();
    IR2_OPND hpet_done = la_new_label();
    IR2_OPND t0 = la_new_itmp();
    IR2_OPND t1 = la_new_itmp();
    IR2_OPND t2 = la_new_itmp();
    IR2_OPND t3 = la_new_itmp();
    IR2_OPND t4 = la_new_itmp();

    /* Match every HPET virtual mapping observed by the HAMT fault path. */
    latxs_convert_mem_opnd_no_offset(&t4, src);
    la_imm(&t1, ~0xfffULL);
    la_out3(LISA_AND, &t3, &t4, &t1);
    la_out2(LISA_BEQZ, &t3, &hpet_fallback);
    la_out2i(LISA_ANDI, &t2, &t4, 0xfff);
    la_out2i(LISA_ADDI_D, &t1, &la_zero, offset);
    la_out3(LISA_BNE, &t2, &t1, &hpet_fallback);
    la_imm(&t0, (uint64_t)guest_hpet_vpages);
    if (hamt_enabled()) {
        latxs_tr_dmw_in_fix_mem(&t0);
    }
    for (i = 0; i < HPET_VPAGE_SLOTS; i++) {
        la_out2i(LISA_LD_D, &t2, &t0, i * sizeof(uint64_t));
        la_out3(LISA_BEQ, &t3, &t2, &hpet_read);
    }
    la_out1(LISA_B, &hpet_fallback);

    la_label_name(hpet_read, "inline HPET counter read");

    // t0 = &HPETState
    la_out2i(LISA_LD_D, &t0, &la_env, offsetof(CPUX86State, hpet_state));
    if (hamt_enabled()) latxs_tr_dmw_in_fix_mem(&t0);

    // t1 = s->config
    la_out2i(LISA_LD_D, &t1, &t0, hpet_offset_config);
    la_outi(LISA_DBAR, 0x14);
    la_out2i(LISA_ANDI, &t1, &t1, HPET_CFG_ENABLE);
    la_out2(LISA_BNEZ, &t1, &hpet_enable);

    // if !(s->config & HPET_CFG_ENABLE)
    la_out2i(LISA_LD_D, &t1, &t0, hpet_offset_hpet_counter);
    la_out1(LISA_B, &hpet_store);

    // if (s->config & HPET_CFG_ENABLE)
    la_label(hpet_enable);
    la_out2 (LISA_RDTIME_D, &t1, &la_zero);
    la_out2i(LISA_LD_D, &t2, &t0, hpet_offset_hpet_offset_ticks);
    la_out3(LISA_ADD_D, &t1, &t1, &t2);

    la_out2i(LISA_LD_D, &t2, &la_env, offsetof(CPUX86State, timers_state));
    if (hamt_enabled()) {
        latxs_tr_dmw_in_fix_mem(&t2);
    }
    la_out2i(LISA_LD_D, &t2, &t2, ts_offset_cpu_clock_offset);
    la_out3(LISA_ADD_D, &t1, &t1, &t2);

    /* Publish and return the greatest tick observed by any vCPU. */
    la_out2i(LISA_ADDI_D, &t2, &t0, hpet_offset_hpet_counter_last);
    la_out3(LISA_AMMAX_DB_DU, &t3, &t2, &t1);
    la_out3(LISA_BGEU, &t1, &t3, &hpet_have_max);
    la_out2_(lisa_mov, &t1, &t3);
    la_label(hpet_have_max);

    la_label_name(hpet_store, "store inline HPET counter");
    if (offset == HPET_COUNTER + 4) {
        la_out2i(LISA_SRLI_D, &t1, &t1, 32);
    }
    latxs_store_ir2_to_ir1(&t1, dst);
    la_out1(LISA_B, &hpet_done);

    la_label_name(hpet_fallback, "non-HPET MOV fallback");
    latxs_load_ir1_to_ir2(&t1, src, EXMode_N);
    latxs_store_ir2_to_ir1(&t1, dst);

    la_label_name(hpet_done, "HPET MOV done");

    la_tmp_free(t0);
    la_tmp_free(t1);
    la_tmp_free(t2);
    la_tmp_free(t3);
    la_tmp_free(t4);

    return true;
}
