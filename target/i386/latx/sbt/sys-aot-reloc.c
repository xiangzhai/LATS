/*
 * SPDX-FileCopyrightText: 2024-2026 LATS Project Authors
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <syscall.h>
#include <math.h>
#include "sys-aot.h"
#include "latx-static-codes.h"
#include "tcg/tcg-ldst.h"
#include "latx-helper.h"
#include "latx-ras.h"
#include "latx-shadow-htable.h"
#include "latx-misc.h"
#include "latx-sys-mmio.h"
#include "include/crypto/aes.h"
#include "include/tcg/fast-itlb.h"
#include "include/tcg/tcg-split-tb.h"

__thread aot_rel curr_rel_table[1024];
__thread int curr_rel_entry_num;

aot_rel *rel_table;
static uint32_t rel_entry_num;
static uint32_t rel_table_capacity;
static pthread_mutex_t rel_table_lock;

aot_rel *tu_rel_table;
static uint32_t tu_rel_entry_num;
static uint32_t tu_rel_table_capacity;
static pthread_mutex_t tu_rel_table_lock;

uintptr_t relkind_to_fixup_addr[] = {
    [AOT_NATIVE_ATOMIC] =
        (uintptr_t)offsetof(struct latx_sc_table_t, aot_native_atomic),
    [AOT_NATIVE_CPU_QUERY] =
        (uintptr_t)offsetof(struct latx_sc_table_t, aot_native_cpu_query),
    [AOT_NATIVE_SYSTEM] =
        (uintptr_t)offsetof(struct latx_sc_table_t, aot_native_system),
    [AOT_NATIVE_X87] =
        (uintptr_t)offsetof(struct latx_sc_table_t, aot_native_x87),
    [AOT_NATIVE_SYSCALL] =
        (uintptr_t)offsetof(struct latx_sc_table_t, aot_native_syscall),
    [HRAS_TU_CP_CHECK_PTR] =
        (uintptr_t)offsetof(struct latx_sc_table_t, tu_cp_check_ptr_mmu_user),
    [LOAD_HRAS_CALL_HELPER] = (uintptr_t)latx_helper_lookup_tb_call,
    [LOAD_HRAS_CALL_RET0_ADDR] =
        (uintptr_t)offsetof(struct latx_sc_table_t, cs_native_to_bt_ret_0),
    [INTB_LOOKUP] = (uintptr_t)offsetof(struct latx_sc_table_t, intb_lookup),
    [INTB_LOOKUP_COMPACT] =
        (uintptr_t)offsetof(struct latx_sc_table_t, intb_lookup_compact),
    [INTB_NJC_RETURN] =
        (uintptr_t)offsetof(struct latx_sc_table_t, intb_njc_return),
    [INTB_RESUME_LOOKUP] =
        (uintptr_t)offsetof(struct latx_sc_table_t, intb_resume_lookup),
    [SCS_PROLOGUE] = (uintptr_t)offsetof(struct latx_sc_table_t, scs_prologue),
    [SCS_EPILOGUE] = (uintptr_t)offsetof(struct latx_sc_table_t, scs_epilogue),
    [RAS_TP_REPAIR] = (uintptr_t)offsetof(struct latx_sc_table_t, ras_tp_repair),
    [SCS_PROLOGUE_NOFP] = (uintptr_t)offsetof(struct latx_sc_table_t, scs_prologue_nofp),
    [SCS_EPILOGUE_NOFP] = (uintptr_t)offsetof(struct latx_sc_table_t, scs_epilogue_nofp),
    [CS_BT_TO_NATIVE] = (uintptr_t)offsetof(struct latx_sc_table_t, cs_bt_to_native),
    [CS_NATIVE_TO_BT_RET_0] = (uintptr_t)offsetof(struct latx_sc_table_t, cs_native_to_bt_ret_0),
    [CS_NATIVE_TO_BT_RET_N0] = (uintptr_t)offsetof(struct latx_sc_table_t, cs_native_to_bt_ret_n0),
    [CS_NATIVE_TO_BT_RET_N1] = (uintptr_t)offsetof(struct latx_sc_table_t, cs_native_to_bt_ret_n1),
    [CS_NATIVE_TO_BT_RET_N3] = (uintptr_t)offsetof(struct latx_sc_table_t, cs_native_to_bt_ret_n3),
    [CP_CHECK_N0_P01_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p01_mmu_user),
    [CP_CHECK_N1_P01_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p01_mmu_user),
    [CP_CHECK_N0_P01_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p01_mmu_knosmap),
    [CP_CHECK_N1_P01_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p01_mmu_knosmap),
    [CP_CHECK_N0_P0_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p0_mmu_user),
    [CP_CHECK_N1_P0_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p0_mmu_user),
    [CP_CHECK_N0_P0_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p0_mmu_knosmap),
    [CP_CHECK_N1_P0_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p0_mmu_knosmap),
    [CP_CHECK_N0_P1_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p1_mmu_user),
    [CP_CHECK_N1_P1_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p1_mmu_user),
    [CP_CHECK_N0_P1_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p1_mmu_knosmap),
    [CP_CHECK_N1_P1_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p1_mmu_knosmap),
    [CP_CHECK_N0_P01_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p01_mmu_user_intcheck),
    [CP_CHECK_N1_P01_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p01_mmu_user_intcheck),
    [CP_CHECK_N0_P01_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p01_mmu_knosmap_intcheck),
    [CP_CHECK_N1_P01_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p01_mmu_knosmap_intcheck),
    [CP_CHECK_N0_P0_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p0_mmu_user_intcheck),
    [CP_CHECK_N1_P0_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p0_mmu_user_intcheck),
    [CP_CHECK_N0_P0_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p0_mmu_knosmap_intcheck),
    [CP_CHECK_N1_P0_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p0_mmu_knosmap_intcheck),
    [CP_CHECK_N0_P1_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p1_mmu_user_intcheck),
    [CP_CHECK_N1_P1_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p1_mmu_user_intcheck),
    [CP_CHECK_N0_P1_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n0_p1_mmu_knosmap_intcheck),
    [CP_CHECK_N1_P1_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_n1_p1_mmu_knosmap_intcheck),
    [CP_CHECK_PTW_N0_P01_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p01_mmu_user),
    [CP_CHECK_PTW_N1_P01_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p01_mmu_user),
    [CP_CHECK_PTW_N0_P0_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p0_mmu_user),
    [CP_CHECK_PTW_N1_P0_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p0_mmu_user),
    [CP_CHECK_PTW_N0_P1_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p1_mmu_user),
    [CP_CHECK_PTW_N1_P1_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p1_mmu_user),
    [CP_CHECK_PTW_N0_P01_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p01_mmu_user_intcheck),
    [CP_CHECK_PTW_N1_P01_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p01_mmu_user_intcheck),
    [CP_CHECK_PTW_N0_P0_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p0_mmu_user_intcheck),
    [CP_CHECK_PTW_N1_P0_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p0_mmu_user_intcheck),
    [CP_CHECK_PTW_N0_P1_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p1_mmu_user_intcheck),
    [CP_CHECK_PTW_N1_P1_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p1_mmu_user_intcheck),
    [CP_CHECK_PTW_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_user),
    [TU_CP_CHECK_N0_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, tu_cp_check_n0_mmu_user),
    [TU_CP_CHECK_N0_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, tu_cp_check_n0_mmu_user_intcheck),
    [TU_CP_CHECK_N1_MMU_USER] = (uintptr_t)offsetof(struct latx_sc_table_t, tu_cp_check_n1_mmu_user),
    [TU_CP_CHECK_N1_MMU_USER_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, tu_cp_check_n1_mmu_user_intcheck),
    [CP_CHECK_PTW_N0_P01_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p01_mmu_knosmap),
    [CP_CHECK_PTW_N1_P01_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p01_mmu_knosmap),
    [CP_CHECK_PTW_N0_P0_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p0_mmu_knosmap),
    [CP_CHECK_PTW_N1_P0_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p0_mmu_knosmap),
    [CP_CHECK_PTW_N0_P1_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p1_mmu_knosmap),
    [CP_CHECK_PTW_N1_P1_MMU_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p1_mmu_knosmap),
    [CP_CHECK_PTW_N0_P01_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p01_mmu_knosmap_intcheck),
    [CP_CHECK_PTW_N1_P01_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p01_mmu_knosmap_intcheck),
    [CP_CHECK_PTW_N0_P0_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p0_mmu_knosmap_intcheck),
    [CP_CHECK_PTW_N1_P0_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p0_mmu_knosmap_intcheck),
    [CP_CHECK_PTW_N0_P1_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n0_p1_mmu_knosmap_intcheck),
    [CP_CHECK_PTW_N1_P1_MMU_KNOSMAP_INTCHECK] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_n1_p1_mmu_knosmap_intcheck),
    [CP_CHECK_PTW_KNOSMAP] = (uintptr_t)offsetof(struct latx_sc_table_t, cp_check_ptw_knosmap),
    [INTB_FSHT_AFTER_NJC] = offsetof(struct latx_sc_table_t, intb_fsht_after_njc),
    [INTB_FSHT_LOOKUP] = (uintptr_t)offsetof(struct latx_sc_table_t, intb_fsht_lookup),
    [INTB_FSHT_LOOKUP_TUCPFAST] = (uintptr_t)offsetof(struct latx_sc_table_t, intb_fsht_lookup_tucpfast),
    [INTB_FSHT_CALL_LOOKUP_TUCPFAST] = (uintptr_t)offsetof(struct latx_sc_table_t, intb_fsht_call_lookup_tucpfast),

    [HELPER_AAA] = (uintptr_t)helper_aaa,
    [HELPER_AAD] = (uintptr_t)helper_aad,
    [HELPER_AAM] = (uintptr_t)helper_aam,
    [HELPER_AAS] = (uintptr_t)helper_aas,
    [HELPER_ATOMIC_CMPXCHGB] = (uintptr_t)helper_atomic_cmpxchgb,
    [HELPER_ATOMIC_CMPXCHGL_LE] = (uintptr_t)helper_atomic_cmpxchgl_le,
    [HELPER_ATOMIC_CMPXCHGQ_LE] = (uintptr_t)helper_atomic_cmpxchgq_le,
    [HELPER_ATOMIC_CMPXCHGW_LE] = (uintptr_t)helper_atomic_cmpxchgw_le,
    [HELPER_ATOMIC_FETCH_ADDB] = (uintptr_t)helper_atomic_fetch_addb,
    [HELPER_ATOMIC_FETCH_ADDL_LE] = (uintptr_t)helper_atomic_fetch_addl_le,
    [HELPER_ATOMIC_FETCH_ADDQ_LE] = (uintptr_t)helper_atomic_fetch_addq_le,
    [HELPER_ATOMIC_FETCH_ADDW_LE] = (uintptr_t)helper_atomic_fetch_addw_le,
    [HELPER_ATOMIC_FETCH_ANDB] = (uintptr_t)helper_atomic_fetch_andb,
    [HELPER_ATOMIC_FETCH_ANDL_LE] = (uintptr_t)helper_atomic_fetch_andl_le,
    [HELPER_ATOMIC_FETCH_ANDQ_LE] = (uintptr_t)helper_atomic_fetch_andq_le,
    [HELPER_ATOMIC_FETCH_ANDW_LE] = (uintptr_t)helper_atomic_fetch_andw_le,
    [HELPER_ATOMIC_FETCH_ORB] = (uintptr_t)helper_atomic_fetch_orb,
    [HELPER_ATOMIC_FETCH_ORL_LE] = (uintptr_t)helper_atomic_fetch_orl_le,
    [HELPER_ATOMIC_FETCH_ORQ_LE] = (uintptr_t)helper_atomic_fetch_orq_le,
    [HELPER_ATOMIC_FETCH_ORW_LE] = (uintptr_t)helper_atomic_fetch_orw_le,
    [HELPER_ATOMIC_FETCH_XORB] = (uintptr_t)helper_atomic_fetch_xorb,
    [HELPER_ATOMIC_FETCH_XORL_LE] = (uintptr_t)helper_atomic_fetch_xorl_le,
    [HELPER_ATOMIC_FETCH_XORQ_LE] = (uintptr_t)helper_atomic_fetch_xorq_le,
    [HELPER_ATOMIC_FETCH_XORW_LE] = (uintptr_t)helper_atomic_fetch_xorw_le,
    [HELPER_ATOMIC_XCHGB] = (uintptr_t)helper_atomic_xchgb,
    [HELPER_ATOMIC_XCHGL_LE] = (uintptr_t)helper_atomic_xchgl_le,
    [HELPER_ATOMIC_XCHGQ_LE] = (uintptr_t)helper_atomic_xchgq_le,
    [HELPER_ATOMIC_XCHGW_LE] = (uintptr_t)helper_atomic_xchgw_le,
#ifdef CONFIG_SOFTMMU
    [HELPER_BPT_IO] = (uintptr_t)helper_bpt_io,
    /* [HELPER_CHECK_IOB] = (uintptr_t)helper_check_iob, */
    /* [HELPER_CHECK_IOL] = (uintptr_t)helper_check_iol, */
    /* [HELPER_CHECK_IOW] = (uintptr_t)helper_check_iow, */
    /* [HELPER_CMPXCHG16B] = (uintptr_t)helper_cmpxchg16b, */
    /* [HELPER_CMPXCHG16B_UNLOCKED] = (uintptr_t)helper_cmpxchg16b_unlocked, */
    /* [HELPER_CMPXCHG8B] = (uintptr_t)helper_cmpxchg8b, */
    /* [HELPER_CMPXCHG8B_UNLOCKED] = (uintptr_t)helper_cmpxchg8b_unlocked, */
    [HELPER_CPUID] = (uintptr_t)helper_cpuid,
    /* [HELPER_CVTPD2DQ] = (uintptr_t)helper_cvtpd2dq, */
    [HELPER_CVTPD2PI] = (uintptr_t)helper_cvtpd2pi,
    /* [HELPER_CVTPS2DQ] = (uintptr_t)helper_cvtps2dq, */
    [HELPER_CVTPS2PI] = (uintptr_t)helper_cvtps2pi,
    [HELPER_CVTSD2SI] = (uintptr_t)helper_cvtsd2si,
    [HELPER_CVTSS2SI] = (uintptr_t)helper_cvtss2si,
    [HELPER_CVTSS2SQ] = (uintptr_t)helper_cvtss2sq,
    /* [HELPER_CVTTPD2DQ] = (uintptr_t)helper_cvttpd2dq, */
    [HELPER_CVTTPD2PI] = (uintptr_t)helper_cvttpd2pi,
    /* [HELPER_CVTTPS2DQ] = (uintptr_t)helper_cvttps2dq, */
    [HELPER_CVTTPS2PI] = (uintptr_t)helper_cvttps2pi,
    [HELPER_DAA] = (uintptr_t)helper_daa,
    [HELPER_DAS] = (uintptr_t)helper_das,
    /* [HELPER_DEBUG] = (uintptr_t)helper_debug, */
    [HELPER_DIVQ_EAX] = (uintptr_t)helper_divq_EAX,
    [HELPER_F2XM1] = (uintptr_t)helper_f2xm1,
    [HELPER_FABS_ST0] = (uintptr_t)helper_fabs_ST0,
    [HELPER_FADD_ST0_FT0] = (uintptr_t)helper_fadd_ST0_FT0,
    [HELPER_FADD_STN_ST0] = (uintptr_t)helper_fadd_STN_ST0,
    [HELPER_FBLD_ST0] = (uintptr_t)helper_fbld_ST0,
    [HELPER_FBST_ST0] = (uintptr_t)helper_fbst_ST0,
    [HELPER_FCHS_ST0] = (uintptr_t)helper_fchs_ST0,
    [HELPER_FCLEX] = (uintptr_t)helper_fclex,
    [HELPER_FCOMI_ST0_FT0] = (uintptr_t)helper_fcomi_ST0_FT0,
    [HELPER_FCOM_ST0_FT0] = (uintptr_t)helper_fcom_ST0_FT0,
    [HELPER_FCOS] = (uintptr_t)helper_fcos,
    [HELPER_FDECSTP] = (uintptr_t)helper_fdecstp,
    [HELPER_FDIVR_ST0_FT0] = (uintptr_t)helper_fdivr_ST0_FT0,
    [HELPER_FDIVR_STN_ST0] = (uintptr_t)helper_fdivr_STN_ST0,
    [HELPER_FDIV_ST0_FT0] = (uintptr_t)helper_fdiv_ST0_FT0,
    [HELPER_FDIV_STN_ST0] = (uintptr_t)helper_fdiv_STN_ST0,
    [HELPER_FFREE_STN] = (uintptr_t)helper_ffree_STN,
    [HELPER_FILDL_FT0] = (uintptr_t)helper_fildl_FT0,
    [HELPER_FILDLL_ST0] = (uintptr_t)helper_fildll_ST0,
    [HELPER_FILDL_ST0] = (uintptr_t)helper_fildl_ST0,
    [HELPER_FINCSTP] = (uintptr_t)helper_fincstp,
    [HELPER_FISTLL_ST0] = (uintptr_t)helper_fistll_ST0,
    [HELPER_FISTL_ST0] = (uintptr_t)helper_fistl_ST0,
    [HELPER_FIST_ST0] = (uintptr_t)helper_fist_ST0,
    [HELPER_FLD1_ST0] = (uintptr_t)helper_fld1_ST0,
    [HELPER_FLDCW] = (uintptr_t)helper_fldcw,
    [HELPER_FLDENV] = (uintptr_t)helper_fldenv,
    [HELPER_FLDL2E_ST0] = (uintptr_t)helper_fldl2e_ST0,
    [HELPER_FLDL2T_ST0] = (uintptr_t)helper_fldl2t_ST0,
    [HELPER_FLDL_FT0] = (uintptr_t)helper_fldl_FT0,
    [HELPER_FLDLG2_ST0] = (uintptr_t)helper_fldlg2_ST0,
    [HELPER_FLDLN2_ST0] = (uintptr_t)helper_fldln2_ST0,
    [HELPER_FLDL_ST0] = (uintptr_t)helper_fldl_ST0,
    [HELPER_FLDPI_ST0] = (uintptr_t)helper_fldpi_ST0,
    [HELPER_FLDS_FT0] = (uintptr_t)helper_flds_FT0,
    [HELPER_FLDS_ST0] = (uintptr_t)helper_flds_ST0,
    [HELPER_FLDT_ST0] = (uintptr_t)helper_fldt_ST0,
    [HELPER_FLDZ_FT0] = (uintptr_t)helper_fldz_FT0,
    [HELPER_FLDZ_ST0] = (uintptr_t)helper_fldz_ST0,
    [HELPER_FMOV_FT0_STN] = (uintptr_t)helper_fmov_FT0_STN,
    [HELPER_FMOV_ST0_STN] = (uintptr_t)helper_fmov_ST0_STN,
    [HELPER_FMOV_STN_ST0] = (uintptr_t)helper_fmov_STN_ST0,
    [HELPER_FMUL_ST0_FT0] = (uintptr_t)helper_fmul_ST0_FT0,
    [HELPER_FMUL_STN_ST0] = (uintptr_t)helper_fmul_STN_ST0,
    [HELPER_FNINIT] = (uintptr_t)helper_fninit,
    [HELPER_FNSTCW] = (uintptr_t)helper_fnstcw,
    [HELPER_FNSTSW] = (uintptr_t)helper_fnstsw,
    [HELPER_FPATAN] = (uintptr_t)helper_fpatan,
    [HELPER_FPOP] = (uintptr_t)helper_fpop,
    [HELPER_FPREM] = (uintptr_t)helper_fprem,
    [HELPER_FPREM1] = (uintptr_t)helper_fprem1,
    [HELPER_FPTAN] = (uintptr_t)helper_fptan,
    [HELPER_FPUSH] = (uintptr_t)helper_fpush,
    [HELPER_FRNDINT] = (uintptr_t)helper_frndint,
    [HELPER_FRSTOR] = (uintptr_t)helper_frstor,
    [HELPER_FSAVE] = (uintptr_t)helper_fsave,
    [HELPER_FSCALE] = (uintptr_t)helper_fscale,
    [HELPER_FSIN] = (uintptr_t)helper_fsin,
    [HELPER_FSINCOS] = (uintptr_t)helper_fsincos,
    [HELPER_FSQRT] = (uintptr_t)helper_fsqrt,
    [HELPER_FSTENV] = (uintptr_t)helper_fstenv,
    [HELPER_FSTL_ST0] = (uintptr_t)helper_fstl_ST0,
    [HELPER_FSTS_ST0] = (uintptr_t)helper_fsts_ST0,
    [HELPER_FSTT_ST0] = (uintptr_t)helper_fstt_ST0,
    [HELPER_FSUBR_ST0_FT0] = (uintptr_t)helper_fsubr_ST0_FT0,
    [HELPER_FSUBR_STN_ST0] = (uintptr_t)helper_fsubr_STN_ST0,
    [HELPER_FSUB_ST0_FT0] = (uintptr_t)helper_fsub_ST0_FT0,
    [HELPER_FSUB_STN_ST0] = (uintptr_t)helper_fsub_STN_ST0,
    [HELPER_FUCOMI_ST0_FT0] = (uintptr_t)helper_fucomi_ST0_FT0,
    [HELPER_FUCOM_ST0_FT0] = (uintptr_t)helper_fucom_ST0_FT0,
    [HELPER_FWAIT] = (uintptr_t)helper_fwait,
    [HELPER_FXAM_ST0] = (uintptr_t)helper_fxam_ST0,
    [HELPER_FXCHG_ST0_STN] = (uintptr_t)helper_fxchg_ST0_STN,
    [HELPER_FXRSTOR] = (uintptr_t)helper_fxrstor,
    [HELPER_FXSAVE] = (uintptr_t)helper_fxsave,
    [HELPER_FXTRACT] = (uintptr_t)helper_fxtract,
    [HELPER_FYL2X] = (uintptr_t)helper_fyl2x,
    [HELPER_FYL2XP1] = (uintptr_t)helper_fyl2xp1,
    [HELPER_GET_DR] = (uintptr_t)helper_get_dr,
    [HELPER_HLT] = (uintptr_t)helper_hlt,
    [HELPER_IDIVQ_EAX] = (uintptr_t)helper_idivq_EAX,
    [HELPER_INB] = (uintptr_t)helper_inb,
    [HELPER_INL] = (uintptr_t)helper_inl,
    [HELPER_INTO] = (uintptr_t)helper_into,
    /* [HELPER_INVLPG] = (uintptr_t)helper_invlpg, */
    /* [HELPER_INVLPGA] = (uintptr_t)helper_invlpga, */
    [HELPER_INW] = (uintptr_t)helper_inw,
    [HELPER_REP_INS] = (uintptr_t)helper_rep_ins,
    [HELPER_REP_OUTS] = (uintptr_t)helper_rep_outs,
    [HELPER_IRET_PROTECTED] = (uintptr_t)helper_iret_protected,
    [HELPER_IRET_REAL] = (uintptr_t)helper_iret_real,
    [HELPER_LCALL_PROTECTED] = (uintptr_t)helper_lcall_protected,
    [HELPER_LCALL_REAL] = (uintptr_t)helper_lcall_real,
    /* [HELPER_LE_LDQ_MMU] = (uintptr_t)helper_le_ldq_mmu, */
    /* [HELPER_LE_LDSL_MMU] = (uintptr_t)helper_le_ldsl_mmu, */
    /* [HELPER_LE_LDSW_MMU] = (uintptr_t)helper_le_ldsw_mmu, */
    /* [HELPER_LE_LDUL_MMU] = (uintptr_t)helper_le_ldul_mmu, */
    /* [HELPER_LE_LDUW_MMU] = (uintptr_t)helper_le_lduw_mmu, */
    /* [HELPER_LE_STL_MMU] = (uintptr_t)helper_le_stl_mmu, */
    /* [HELPER_LE_STQ_MMU] = (uintptr_t)helper_le_stq_mmu, */
    /* [HELPER_LE_STW_MMU] = (uintptr_t)helper_le_stw_mmu, */
    [HELPER_LJMP_PROTECTED] = (uintptr_t)helper_ljmp_protected,
    [HELPER_LLDT] = (uintptr_t)helper_lldt,
    /* [HELPER_LMSW] = (uintptr_t)helper_lmsw, */
    [HELPER_LOAD_SEG] = (uintptr_t)helper_load_seg,
    /* [HELPER_LOOKUP_TB] = (uintptr_t)helper_lookup_tb, */
    [HELPER_LRET_PROTECTED] = (uintptr_t)helper_lret_protected,
    [HELPER_LTR] = (uintptr_t)helper_ltr,
    [HELPER_OUTB] = (uintptr_t)helper_outb,
    [HELPER_OUTL] = (uintptr_t)helper_outl,
    [HELPER_OUTW] = (uintptr_t)helper_outw,
    [HELPER_PAUSE] = (uintptr_t)helper_pause,
    [HELPER_RAISE_EXCEPTION] = (uintptr_t)helper_raise_exception,
    [HELPER_RAISE_INTERRUPT] = (uintptr_t)helper_raise_interrupt,
    [HELPER_RDMSR] = (uintptr_t)helper_rdmsr,
    [HELPER_RDPMC] = (uintptr_t)helper_rdpmc,
    [HELPER_RDTSC] = (uintptr_t)helper_rdtsc,
    /* [HELPER_RDTSCP] = (uintptr_t)helper_rdtscp, */
    [HELPER_READ_CRN] = (uintptr_t)helper_read_crN,
    /* [HELPER_RET_LDSB_MMU] = (uintptr_t)helper_ret_ldsb_mmu, */
    /* [HELPER_RET_LDUB_MMU] = (uintptr_t)helper_ret_ldub_mmu, */
    /* [HELPER_RET_STB_MMU] = (uintptr_t)helper_ret_stb_mmu, */
    [HELPER_RSM] = (uintptr_t)helper_rsm,
    [HELPER_SET_DR] = (uintptr_t)helper_set_dr,
    [HELPER_SINGLE_STEP] = (uintptr_t)helper_single_step,
    [HELPER_SYSCALL] = (uintptr_t)helper_syscall,
    [HELPER_SYSENTER] = (uintptr_t)helper_sysenter,
    [HELPER_SYSEXIT] = (uintptr_t)helper_sysexit,
    [HELPER_SYSRET] = (uintptr_t)helper_sysret,
    [HELPER_VERR] = (uintptr_t)helper_verr,
    [HELPER_VERW] = (uintptr_t)helper_verw,
    [HELPER_WRITE_CRN] = (uintptr_t)helper_write_crN,
    [HELPER_WRITE_EFLAGS] = (uintptr_t)helper_write_eflags,
    [HELPER_WRMSR] = (uintptr_t)helper_wrmsr,
    /* [HELPER_X86_CPU_DUMP_STATE] = (uintptr_t)helper_x86_cpu_dump_state, */
    [HELPER_XGETBV] = (uintptr_t)helper_xgetbv,
    [HELPER_XRSTOR] = (uintptr_t)helper_xrstor,
    [HELPER_XSAVE] = (uintptr_t)helper_xsave,
    [HELPER_XSAVEOPT] = (uintptr_t)helper_xsaveopt,
    [HELPER_XSETBV] = (uintptr_t)helper_xsetbv,
    [HELPER_LDQ_MMU] = (uintptr_t)helper_ldq_mmu,
    [HELPER_LDUB_MMU] = (uintptr_t)helper_ldub_mmu,
    [HELPER_LDUW_MMU] = (uintptr_t)helper_lduw_mmu,
    [HELPER_LDUL_MMU] = (uintptr_t)helper_ldul_mmu,
    [HELPER_LDSL_MMU] = (uintptr_t)helper_ldsl_mmu,
    [HELPER_LDSW_MMU] = (uintptr_t)helper_ldsw_mmu,
    [HELPER_LDSB_MMU] = (uintptr_t)helper_ldsb_mmu,
    [HELPER_STQ_MMU] = (uintptr_t)helper_stq_mmu,
    [HELPER_STL_MMU] = (uintptr_t)helper_stl_mmu,
    [HELPER_STW_MMU] = (uintptr_t)helper_stw_mmu,
    [HELPER_STB_MMU] = (uintptr_t)helper_stb_mmu,
    [HELPER_SOFTMMU_COMMON] = (uintptr_t)helper_softmmu_common,
    [HELPER_LATX_CMPXCHG8B] = (uintptr_t)helper_latx_cmpxchg8b,
    [HELPER_LATX_CMPXCHG16B] = (uintptr_t)helper_latx_cmpxchg16b,
    [HELPER_LATX_CMPXCHG8B_UNLOCKED] = (uintptr_t)helper_latx_cmpxchg8b_unlocked,
    [HELPER_LATX_CMPXCHG16B_UNLOCKED] = (uintptr_t)helper_latx_cmpxchg16b_unlocked,
    [HELPER_RDRAND] = (uintptr_t)helper_rdrand,
    [HELPER_INVPCID] = (uintptr_t)helper_invpcid,
    [HELPER_FLUSH_PAGE] = (uintptr_t)helper_flush_page,
    [HELPER_LAR] = (uintptr_t)helper_lar,
    [HELPER_LSL] = (uintptr_t)helper_lsl,
    [HELPER_CRC32] = (uintptr_t)helper_crc32,
    [HELPER_CHECK_IO] = (uintptr_t)helper_check_io,
    [HELPER_PCMPISTRI_XMM] = (uintptr_t)helper_pcmpistri_xmm,
    [HELPER_PCMPISTRM_XMM] = (uintptr_t)helper_pcmpistrm_xmm,
    [HELPER_PCMPESTRI_XMM] = (uintptr_t)helper_pcmpestri_xmm,
    [HELPER_PCMPESTRM_XMM] = (uintptr_t)helper_pcmpestrm_xmm,
    [HELPER_AESDEC_XMM] = (uintptr_t)helper_aesdec_xmm,
    [HELPER_AESENC_XMM] = (uintptr_t)helper_aesenc_xmm,
    [HELPER_AESIMC_XMM] = (uintptr_t)helper_aesimc_xmm,
    [HELPER_AESDECLAST_XMM] = (uintptr_t)helper_aesdeclast_xmm,
    [HELPER_AESKEYGENASSIST_XMM] = (uintptr_t)helper_aeskeygenassist_xmm,
    [HELPER_PCLMULQDQ_XMM] = (uintptr_t)helper_pclmulqdq_xmm,
    [HELPER_SHA1MSG1] = (uintptr_t)helper_sha1msg1,
    [HELPER_SHA1MSG2] = (uintptr_t)helper_sha1msg2,
    [HELPER_SHA1NEXTE] = (uintptr_t)helper_sha1nexte,
    /* [HELPER_SHA256MSG1] = (uintptr_t)helper_sha256ms1, */
    [HELPER_SHA256MSG2] = (uintptr_t)helper_sha256msg2,
    [HELPER_SHA256RNDS2] = (uintptr_t)helper_sha256rnds2,
    [HELPER_SHA1RNDS4_F0] = (uintptr_t)helper_sha1rnds4_f0,
    [HELPER_SHA1RNDS4_F1] = (uintptr_t)helper_sha1rnds4_f1,
    [HELPER_SHA1RNDS4_F2] = (uintptr_t)helper_sha1rnds4_f2,
    [HELPER_SHA1RNDS4_F3] = (uintptr_t)helper_sha1rnds4_f3,
    [HELPER_AESENCLAST_XMM] = (uintptr_t)helper_aesenclast_xmm,
    [HELPER_FISTT_ST0] = (uintptr_t)helper_fistt_ST0,
    [HELPER_FISTTL_ST0] = (uintptr_t)helper_fisttl_ST0,
    [HELPER_FISTTLL_ST0] = (uintptr_t)helper_fisttll_ST0,
    [LATX_APIC_MEM_WRITE] = (uintptr_t)latx_apic_mem_write,


    [LATXS_CONVERT_FPREGS_64_TO_X80] = (uintptr_t)latxs_convert_fpregs_64_to_x80,
    [LATXS_CONVERT_FPREGS_X80_TO_64] = (uintptr_t)latxs_convert_fpregs_x80_to_64,
    [LATX_HELPER_LOOKUP_TB_HASHTABLE] = (uintptr_t)latx_helper_lookup_tb_hashtable,
    [LATX_HELPER_RAS_TP_REPAIR_CALL] = (uintptr_t)ras_tp_repair_call,
    /* [LATXS_HELPER_LE_LDDQ_MMU] = (uintptr_t)latxs_helper_le_lddq_mmu, */
    /* [LATXS_HELPER_LE_STDQ_MMU] = (uintptr_t)latxs_helper_le_stdq_mmu, */
    [LATXS_HELPER_STDQ_MMU] = (uintptr_t)latxs_helper_stdq_mmu,
    [LATXS_HELPER_LDDQ_MMU] = (uintptr_t)latxs_helper_lddq_mmu,
    [PF_TABLE] = (uintptr_t)pf_table,
    [UPDATE_FP_STATUS] = (uintptr_t)update_fp_status,
    [UPDATE_MXCSR_STATUS] = (uintptr_t)update_mxcsr_status,
    [LOG2] = (uintptr_t)log2,
    [POW] = (uintptr_t)pow,
    [ATAN2] = (uintptr_t)atan2,
    [COS] = (uintptr_t)cos,
    [SIN] = (uintptr_t)sin,
    [LOAD_AES_Td0] = (uintptr_t)AES_Td0,
    [LOAD_AES_Td1] = (uintptr_t)AES_Td1,
    [LOAD_AES_Td2] = (uintptr_t)AES_Td2,
    [LOAD_AES_Td3] = (uintptr_t)AES_Td3,
    [LOAD_AES_Te0] = (uintptr_t)AES_Te0,
    [LOAD_AES_Te1] = (uintptr_t)AES_Te1,
    [LOAD_AES_Te2] = (uintptr_t)AES_Te2,
    [LOAD_AES_Te3] = (uintptr_t)AES_Te3,
    [LOAD_AES_sbox] = (uintptr_t)AES_sbox,
    [LOAD_AES_isbox] = (uintptr_t)AES_isbox,
    [LOAD_AES_imc_rot] = (uintptr_t)AES_imc_rot,
#endif

    [DEADBEAF] = 0xdeadbeaf,
};

/* Basic Block relocation table with @rel_entry_num elements. */
void add_rel_entry(TranslationBlock *tb)
{
    if (!option_sys_aot || !option_aot_save) {
        return;
    }
#if defined(CONFIG_SOFTMMU) && defined(CONFIG_LATX_TU)
    if (aot_tu_enabled() && (tb->flags & HF_CPL_MASK)) {
        /* User code is retranslated with fresh TU relocations when saved. */
        TB_REL_START(tb) = -1;
        TB_REL_END(tb) = -1;
        return;
    }
#endif
    /* return; */
    /* if (!in_aot_translate) { */
    /*     assert(0); */
    /* } */

    int curr_tb_rel_count = 0;

    if (TB_REL_START(tb) > -1) {
        curr_tb_rel_count = TB_REL_END(tb) - TB_REL_START(tb) + 1;
    } else {
        return;
    }
    if (TB_REL_END(tb) < TB_REL_START(tb)) {
        fprintf(stderr, "rel_end <rel_start %d %d\n",
                TB_REL_START(tb), TB_REL_END(tb));
        exit(0);
    }
    if (curr_tb_rel_count < 0) {
        fprintf(stderr, "err curr_tb_rel_count %d\n", curr_tb_rel_count);
        exit(0);

    }
    /* fprintf(stderr, " %lx curr_tb_rel_count %d\n", tb->pc, curr_tb_rel_count); */

    pthread_mutex_lock(&rel_table_lock);
    if (rel_table_capacity <= rel_entry_num + curr_tb_rel_count) {
        rel_table_capacity <<= 1;
        fprintf(stderr, "rel_table_capacity %d\n", rel_table_capacity);
        rel_table =
            (aot_rel *)realloc(rel_table, rel_table_capacity * sizeof(aot_rel));
        if (!rel_table) {
            fprintf(stderr, "realloc rel_table fail\n");
            exit(0);
        }
    }

    uint32_t i = rel_entry_num;
    rel_entry_num += curr_tb_rel_count;
    if (rel_entry_num >= rel_table_capacity) {
        fprintf(stderr, "%d %d curr_tb_rel_count %d\n",
                rel_entry_num, rel_table_capacity,
                curr_tb_rel_count);
        exit(0);
    }
    TB_REL_START(tb) = i;
    TB_REL_END(tb) = i + curr_tb_rel_count - 1;
    for (int j = 0; j < curr_tb_rel_count; j++) {
        rel_table[i].kind = curr_rel_table[j].kind;
        rel_table[i].extra_addend = curr_rel_table[j].extra_addend;
        rel_table[i].tc_offset = curr_rel_table[j].tc_offset;
        rel_table[i].rel_slots_num = curr_rel_table[j].rel_slots_num;
        i++;
    }
    pthread_mutex_unlock(&rel_table_lock);
}

void add_tu_rel_entry(TranslationBlock *tb)
{
    if (!option_sys_aot || !option_aot_save) {
        return;
    }
    /* return; */
    /* if (!in_aot_translate) { */
    /*     assert(0); */
    /* } */

    int curr_tb_rel_count = 0;

    if (TB_REL_START(tb) > -1) {
        curr_tb_rel_count = TB_REL_END(tb) - TB_REL_START(tb) + 1;
    } else {
        return;
    }
    if (TB_REL_END(tb) < TB_REL_START(tb)) {
        fprintf(stderr, "rel_end <rel_start %d %d\n",
                TB_REL_START(tb), TB_REL_END(tb));
        exit(0);
    }
    if (curr_tb_rel_count < 0) {
        fprintf(stderr, "err curr_tb_rel_count %d\n", curr_tb_rel_count);
        exit(0);

    }
    /* fprintf(stderr, " %lx curr_tb_rel_count %d\n", tb->pc, curr_tb_rel_count); */

    pthread_mutex_lock(&tu_rel_table_lock);
    if (tu_rel_table_capacity <= tu_rel_entry_num + curr_tb_rel_count) {
        tu_rel_table_capacity <<= 1;
        fprintf(stderr, "rel_table_capacity %d\n", tu_rel_table_capacity);
        tu_rel_table =
            (aot_rel *)realloc(tu_rel_table, tu_rel_table_capacity * sizeof(aot_rel));
        if (!tu_rel_table) {
            fprintf(stderr, "realloc rel_table fail\n");
            exit(0);
        }
    }

    uint32_t i = tu_rel_entry_num;
    tu_rel_entry_num += curr_tb_rel_count;
    if (tu_rel_entry_num >= tu_rel_table_capacity) {
        fprintf(stderr, "%d %d curr_tb_rel_count %d\n",
                tu_rel_entry_num, tu_rel_table_capacity,
                curr_tb_rel_count);
        exit(0);
    }
    TB_REL_START(tb) = i;
    TB_REL_END(tb) = i + curr_tb_rel_count - 1;
    for (int j = 0; j < curr_tb_rel_count; j++) {
        tu_rel_table[i].kind = curr_rel_table[j].kind;
        tu_rel_table[i].extra_addend = curr_rel_table[j].extra_addend;
        tu_rel_table[i].tc_offset = curr_rel_table[j].tc_offset;
        tu_rel_table[i].rel_slots_num = curr_rel_table[j].rel_slots_num;
        i++;
    }
    pthread_mutex_unlock(&tu_rel_table_lock);
}

/* RAS repairs are emitted after all members, but retain their source TB's
 * relocation identity. Repack the main and cold records into one range. */
void append_tu_ras_rel_entries(TranslationBlock *tb, int main_start,
                             int main_end)
{
    int main_count = main_start < 0 ? 0 : main_end - main_start + 1;
    int count = main_count + curr_rel_entry_num;

    if (!count) {
        TB_REL_START(tb) = -1;
        TB_REL_END(tb) = -2;
        return;
    }
    pthread_mutex_lock(&tu_rel_table_lock);
    while (tu_rel_entry_num + count >= tu_rel_table_capacity) {
        tu_rel_table_capacity <<= 1;
        tu_rel_table = g_realloc(tu_rel_table,
                                tu_rel_table_capacity * sizeof(*tu_rel_table));
    }
    int start = tu_rel_entry_num;
    if (main_count) {
        memcpy(&tu_rel_table[start], &tu_rel_table[main_start],
               main_count * sizeof(*tu_rel_table));
    }
    memcpy(&tu_rel_table[start + main_count], curr_rel_table,
           curr_rel_entry_num * sizeof(*tu_rel_table));
    tu_rel_entry_num += count;
    TB_REL_START(tb) = start;
    TB_REL_END(tb) = start + count - 1;
    pthread_mutex_unlock(&tu_rel_table_lock);
}

void add_curr_rel_entry(TranslationBlock *tb, aot_rel_kind kind, int tc_offset,
                  uint8_t rel_slots_num, uintptr_t x86_rip_offset,
                  uintptr_t extra_addend)
{
    if (!option_sys_aot || !option_aot_save) {
        return;
    }
#if defined(CONFIG_SOFTMMU) && defined(CONFIG_LATX_TU)
    if (!in_aot_translate && aot_tu_enabled() && (tb->flags & HF_CPL_MASK)) {
        /* Match add_rel_entry: user JIT TUs get fresh records when saved. */
        return;
    }
#endif
    if (curr_rel_entry_num >= (int)ARRAY_SIZE(curr_rel_table)) {
        fprintf(stderr, "too many relocations %d tid=%ld\n",
                curr_rel_entry_num, syscall(SYS_gettid));
        abort();
    }
    int i = curr_rel_entry_num++;
    curr_rel_table[i].kind = kind;
    /* curr_rel_table[i].x86_rip_offset = x86_rip_offset; */
    curr_rel_table[i].extra_addend = extra_addend;
    curr_rel_table[i].tc_offset = tc_offset;
    curr_rel_table[i].rel_slots_num = rel_slots_num;
    if (TB_REL_START(tb) == -1) {
        TB_REL_START(tb) = i;
    }
    TB_REL_END(tb) = i;
}

bool test_tb_reloc(aot_rel *aot_rel_table, uint32_t rel_count,
        uint64_t tb_pc)
{
    if (rel_count == 0) {
        return true;
    }
    uint64_t guest_addr;
    for (int i = 0; i < rel_count; i++) {
        int kind = aot_rel_table[i].kind;
        if (kind == LOAD_GUEST_ADDR32) {
            int rel_slots_num = aot_rel_table[i].rel_slots_num;

            if (rel_slots_num != 2 && rel_slots_num != 3) {
                return false;
            }
            guest_addr = (uint32_t)(tb_pc + aot_rel_table[i].extra_addend);
            /* A two-slot sequence cannot clear lu12i.w's sign extension. */
            if (rel_slots_num == 2 && (guest_addr & (1ULL << 31))) {
                return false;
            }
        } else if (kind == LOAD_GUEST_ADDR) {
            int rel_slots_num = aot_rel_table[i].rel_slots_num;

            if (rel_slots_num != 2 && rel_slots_num != 3) {
                return false;
            }
            guest_addr = tb_pc + aot_rel_table[i].extra_addend;
            if (rel_slots_num == 2 &&
                    !aot_guest_addr_fits_s32(guest_addr)) {
                return false;
            }
        }

    }
    return true;
}

void aot_do_tb_reloc(ENV *lsenv, TranslationBlock *tb, aot_rel *aot_rel_table,
        uint32_t rel_count)
{
    if (rel_count == 0) {
        return;
    }
    uint32_t *pinsn;
    int offset;
    uintptr_t helper_address;
    TRANSLATION_DATA *td = lsenv->tr_data;
    uint32_t mtcc_id;
    int fid;
    uint64_t guest_addr;

    mtcc_id = get_mask_from_miscflags(tb,
            MF_MTCC_ID_MASK, MF_MTCC_ID_SHIFT);
    latxs_tr_sync_region_offset(mtcc_id);

    /* fprintf(stderr, "tb %lx rel count %d\n", tb->pc, rel_count); */
    for (int i = 0; i < rel_count; i++) {
        int kind = aot_rel_table[i].kind;
        pinsn = (uint32_t *)(tb->tc.ptr + aot_rel_table[i].tc_offset);
        /* fprintf(stderr, "i %d kind %d ir2 id %d extra_addend %d\n", */
        /*         i, kind, aot_rel_table[i].tc_offset >> 2, */
        /*         aot_rel_table[i].extra_addend); */
        /* fprintf(stderr, "pinsn %p %x offset %x tid %ld\n", pinsn, */
        /*         *pinsn, */
        /*         aot_rel_table[i].tc_offset, syscall(SYS_gettid)); */
        switch (kind) {
        case AOT_NATIVE_ENTRY:
        case AOT_NATIVE_CALL:
        case AOT_NATIVE_CORE:
        case AOT_NATIVE_CORE_CALL:
        case AOT_NATIVE_DIRECT_CALL:
        case AOT_NATIVE_LINKED_CALL:
        case AOT_NATIVE_INDIRECT_CALL:
        case AOT_NATIVE_RET_MISS:
            /* Metadata only. Publish native CALL gates after normal linking. */
            break;
        case LOAD_TB_ADDR:
        case LOAD_TB_FULL_ADDR: {
            uintptr_t tb_addr = (uintptr_t)tb;
            if (kind == LOAD_TB_ADDR && split_tb_base_ok()) {
                tb_addr &= (1ULL << 32) - 1;
            }
            lsassert(aot_rel_table[i].rel_slots_num == 3);
            lsassert((*pinsn & 0xfe000000) == 0x14000000); /* lu12i.w */
            *pinsn &= 0xfe00001f;
            *pinsn |= ((tb_addr >> 12) & 0xfffff) << 5;

            pinsn++;
            lsassert((*pinsn & 0xffc00000) == 0x03800000); /* ori */
            *pinsn &= 0xffc003ff;
            *pinsn |= (tb_addr & 0xfff) << 10;

            pinsn++;

            lsassert((*pinsn & 0xfe000000) == 0x16000000); /* lu32i.d */
            *pinsn &= 0xfe00001f;
            *pinsn |= ((tb_addr >> 32) & 0xfffff) << 5;

            break;
        }
#ifdef CONFIG_SOFTMMU
        case LOAD_BY_GUEST_ADDR_CPU_NEG_ITLB:
            guest_addr = tb->pc + aot_rel_table[i].extra_addend;
            if (option_pcid_cache) {
                offset = 0;
            } else if (tb->flags & HF_CPL_MASK) {
                offset = (int)offsetof(ArchCPU, neg.itlb_user) -
                         (int)offsetof(ArchCPU, env);
            } else {
                offset = (int)offsetof(ArchCPU, neg.itlb_knosmap) -
                         (int)offsetof(ArchCPU, env);
            }
            offset += FAST_ITLB_INDEX(guest_addr) * sizeof(fast_itlb_entry_t);
            offset >>= 2;
            *pinsn = 0x26000000; /* ldptr.d a0, base, off */
            *pinsn |= 0x04; /* rd = a0 */
            *pinsn |= (option_pcid_cache ? 0x04 : 0x17) << 5;
            *pinsn |= (offset & 0x3fff) << 10;
            break;
#endif
        case LOAD_GUEST_ADDR:
        case LOAD_GUEST_ADDR32:
            guest_addr = tb->pc + aot_rel_table[i].extra_addend;
            if (kind == LOAD_GUEST_ADDR32) {
                lsassert(aot_rel_table[i].rel_slots_num == 2 ||
                        aot_rel_table[i].rel_slots_num == 3);
                guest_addr = (uint32_t)guest_addr;
                lsassert(aot_rel_table[i].rel_slots_num == 3 ||
                        !(guest_addr & (1ULL << 31)));
            } else {
                lsassert(aot_rel_table[i].rel_slots_num == 2 ||
                        aot_rel_table[i].rel_slots_num == 3);
                lsassert(aot_rel_table[i].rel_slots_num == 3 ||
                        aot_guest_addr_fits_s32(guest_addr));
            }
            lsassert((*pinsn & 0xfe000000) == 0x14000000); /* lu12i.w */
            *pinsn &= 0xfe00001f;
            *pinsn |= ((guest_addr >> 12) & 0xfffff) << 5;
            /* if (guest_addr & 0xfff) { */
            /*     assert(aot_rel_table[i].extra_addend > 1); */
            /*     pinsn++; */
            /*     if ((*pinsn & 0xffc00000) != 0x03800000) { */
            /*         fprintf(stderr, "ins 2 not ori %x\n", *pinsn); */
            /*         exit(-1); */
            /*     } */
            /*     lsassert((*pinsn & 0xffc00000) == 0x03800000); /1* ori *1/ */
            /*     *pinsn &= 0xffc003ff; */
            /*     *pinsn |= (guest_addr & 0xfff) << 10; */
            /* } */
            pinsn++;
            lsassert((*pinsn & 0xffc00000) == 0x03800000); /* ori */
            *pinsn &= 0xffc003ff;
            *pinsn |= (guest_addr & 0xfff) << 10;
            if (aot_rel_table[i].rel_slots_num == 3) {
                pinsn++;
                lsassert((*pinsn & 0xfe000000) == 0x16000000); /* lu32i.d */
                *pinsn &= 0xfe00001f;
                *pinsn |= ((guest_addr >> 32) & 0xfffff) << 5;
            }
            break;
        case INTB_FSHT_LOOKUP:
        case INTB_FSHT_LOOKUP_TUCPFAST:
        case INTB_FSHT_AFTER_NJC:
        case INTB_FSHT_CALL_LOOKUP_TUCPFAST: {
            bool direct_tail =
                kind == INTB_FSHT_CALL_LOOKUP_TUCPFAST &&
                aot_rel_table[i].extra_addend == 2;
            uintptr_t sc_off = direct_tail ?
                (uintptr_t)offsetof(struct latx_sc_table_t,
                                    intb_fsht_direct_tail_lookup_tucpfast) :
                relkind_to_fixup_addr[kind];
            mtcc_id = get_mask_from_miscflags(tb, MF_MTCC_ID_MASK, MF_MTCC_ID_SHIFT);
            fid = fsht_flags_to_id(tb->flags);

            offset = (*(uintptr_t *)((uintptr_t)&latx_sc_table[mtcc_id] + sc_off
                    + fid * sizeof(uint64_t))
                    + (uintptr_t)td->tcg_region_offset[mtcc_id]
                    - ((uintptr_t)tb->tc.ptr + aot_rel_table[i].tc_offset)) >> 2;
            if (option_large_code_cache && !int32_in_int26(offset)) {
                offset = reset_region_offset(offset, mtcc_id);
            }
            latxs_aot_ir2_jmp_near(pinsn, offset,
                    direct_tail ? 0 : aot_rel_table[i].extra_addend);
            break;
        }
        case SC_TABLE_BEGIN ... SC_TABLE_END:
            mtcc_id = get_mask_from_miscflags(tb, MF_MTCC_ID_MASK, MF_MTCC_ID_SHIFT);
            offset = (*(uintptr_t *)((uintptr_t)&latx_sc_table[mtcc_id] + relkind_to_fixup_addr[kind])
                    - ((uintptr_t)tb->tc.ptr + aot_rel_table[i].tc_offset)) >> 2;
            latxs_aot_ir2_jmp_far(pinsn, offset, aot_rel_table[i].extra_addend);
            break;
        case HRAS_TU_CP_CHECK_PTR:
        case AOT_NATIVE_SYSCALL:
        case AOT_NATIVE_ATOMIC:
        case AOT_NATIVE_CPU_QUERY:
        case AOT_NATIVE_X87:
        case AOT_NATIVE_SYSTEM:
        case INTB_RESUME_LOOKUP:
        case INTB_LOOKUP_COMPACT:
        case INTB_NJC_RETURN:
        case SC_TABLE_OFFSET_BEGIN ... SC_TABLE_OFFSET_END:
            mtcc_id = get_mask_from_miscflags(tb, MF_MTCC_ID_MASK, MF_MTCC_ID_SHIFT);
            offset = (*(uintptr_t *)((uintptr_t)&latx_sc_table[mtcc_id] + relkind_to_fixup_addr[kind])
                    + (uintptr_t)td->tcg_region_offset[mtcc_id]
                    - ((uintptr_t)tb->tc.ptr + aot_rel_table[i].tc_offset)) >> 2;
            if (option_large_code_cache && !int32_in_int26(offset)) {
                offset = reset_region_offset(offset, mtcc_id);
            }
            latxs_aot_ir2_jmp_near(pinsn, offset,
                    kind == AOT_NATIVE_SYSCALL || kind == AOT_NATIVE_ATOMIC ||
                    kind == AOT_NATIVE_CPU_QUERY || kind == AOT_NATIVE_X87 ||
                    kind == AOT_NATIVE_SYSTEM ?
                        0 : aot_rel_table[i].extra_addend);
            break;
        case LOAD_HRAS_FSHT_BASE: {
            fid = fsht_flags_to_id(tb->flags);
            lsassert(fid >= 0 && (uint32_t)fid < fsht_num);
            helper_address = fsht[fid].base;
            unsigned rd = pinsn[0] & 31;
            lsassert(aot_rel_table[i].rel_slots_num == 2 && rd &&
                     !(helper_address & 0xfff) && !(helper_address >> 51));
            lsassert((pinsn[0] & ~31U) == 0x00150000U ||
                     (pinsn[0] & 0xfe000000U) == 0x14000000U);
            lsassert((pinsn[1] & 0xfe00001fU) == (0x16000000U | rd));
            pinsn[0] = (uint32_t)helper_address ?
                (0x14000000U | (((helper_address >> 12) & 0xfffff) << 5) | rd) :
                (0x00150000U | rd);
            pinsn[1] = 0x16000000U |
                        (((helper_address >> 32) & 0xfffff) << 5) | rd;
            break;
        }
        case LOAD_HRAS_CALL_RET0_ADDR:
            helper_address = *(uintptr_t *)((uintptr_t)&latx_sc_table[mtcc_id] +
                                      relkind_to_fixup_addr[kind]);
            goto relocate_host_address;
        case LOAD_HRAS_CALL_HELPER:
        case LOAD_HELPER_BEGIN ... LOAD_HELPER_END:
            helper_address = (uintptr_t)relkind_to_fixup_addr[aot_rel_table[i].kind];
relocate_host_address:
            lsassert(helper_address);
            lsassert(aot_rel_table[i].rel_slots_num == 3);
            if (kind == LOAD_HRAS_CALL_HELPER ||
                kind == LOAD_HRAS_CALL_RET0_ADDR) {
                unsigned rd = pinsn[0] & 31;
                lsassert(rd && (pinsn[1] & 0x3ff) == (rd | (rd << 5)) &&
                         (pinsn[2] & 31) == rd);
                (void)rd;
            }
            lsassert((*pinsn & 0xfe000000) == 0x14000000); /* lu12i.w */
            *pinsn &= 0xfe00001f;
            *pinsn |= ((helper_address >> 12) & 0xfffff) << 5;

            pinsn++;
            lsassert((*pinsn & 0xffc00000) == 0x03800000); /* ori */
            *pinsn &= 0xffc003ff;
            *pinsn |= (helper_address & 0xfff) << 10;

            pinsn++;
            lsassert((*pinsn & 0xfe000000) == 0x16000000); /* lu32i.d */
            *pinsn &= 0xfe00001f;
            *pinsn |= ((helper_address >> 32) & 0xfffff) << 5;

            break;
        default:
            break;
        }
    }
}

void clear_rel_table(void)
{
    rel_entry_num = 0;
}

void aot_reloc_reset_on_tb_flush(int mtcc_id)
{
    if (!option_sys_aot || !option_aot_save) {
        return;
    }

    /* Called after the TBs have been removed, with all vCPUs quiescent. */
    if (mtcc_id == -1) {
        clear_rel_table();
    }
#if defined(CONFIG_SOFTMMU) && defined(CONFIG_LATX_TU)
    else if (mtcc_id == 0 && aot_tu_enabled()) {
        /* With AOT TU, only core TBs retain ordinary table indices. */
        clear_rel_table();
    }
#endif
    /* Without AOT TU, a partial flush may leave users of the shared table. */
}

void clear_tu_rel_table(void)
{
    tu_rel_entry_num = 0;
}

void aot_reloc_init(void)
{
    pthread_mutex_init(&rel_table_lock, NULL);
    pthread_mutex_init(&tu_rel_table_lock, NULL);
    if (rel_table_capacity == 0) {
        rel_table_capacity = 3000000;
        rel_entry_num = 0;
        rel_table = (aot_rel *)malloc(rel_table_capacity * sizeof(aot_rel));
        if (!rel_table) {
            fprintf(stderr, "malloc rel_table fail\n");
            exit(0);
        }
        assert(rel_table);
    }
    if (tu_rel_table_capacity == 0) {
        tu_rel_table_capacity = 100000;
        tu_rel_entry_num = 0;
        tu_rel_table = (aot_rel *)malloc(tu_rel_table_capacity * sizeof(aot_rel));
        if (!tu_rel_table) {
            fprintf(stderr, "malloc rel_table fail\n");
            exit(0);
        }
        assert(tu_rel_table);
    }
}
