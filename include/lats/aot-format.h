/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LATS_AOT_FORMAT_H
#define LATS_AOT_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* On-disk layout. Producers and consumers use 64-bit little-endian hosts. */
#define AOT_CORE 0x01
#define AOT_USER 0x02
#define AOT_TU   0x04
#define AOT_TU_FLAG_BIT 10

#define AOT_FORMAT_VERSION "-format37"

#define AOT_PAGE_MAGIC 0x66666666
#define AOT_MERGED_MAGIC 0x77777777
#define AOT_TB_MAGIC 0xfefefefe
#define AOT_TU_REF_MAGIC 0xfdfdfdfd
#define MERGED_PAGE 0xffffffff

#define AOT_TU_MAX_PAGES 16
/* Keep ordinary TU exploration unchanged when loading larger AOT records. */
#define AOT_TU_EXPLORE_MAX_PAGES 8

/* misc_flags: this exact member entry was reached by a guest CALL.
 * This is entry evidence, not an exhaustive indirect-target set. */
#define AOT_BLOCK_OBSERVED_CALL_ENTRY UINT32_C(0x00000100)

struct aot_tc {
    size_t offset_in_tu;
};

struct aot_block {
    uint64_t pc;
    uint64_t page_addr[2];
    uint64_t next_pc[2];
    uintptr_t jmp_target_addr[2]; /* target address */
    union {
        uint64_t search_size;
        void *search_ptr;
    };
    struct aot_tc tc;
    union {
        uintptr_t x86_next_pc;
        uint32_t tu_link_ins;
    };
    union {
        uintptr_t x86_target_pc;
        uint32_t tu_unlink_stub_offset;
    };
    uint32_t cs_base;
    uint32_t misc_flags;
    uint32_t flags;
    uint32_t cflags;
    uint32_t ir2_num;
    int inst_ptr_offset;
    uint32_t ras_tp_cold_offset;
    int label_pos_nocheck;
    int tu_jmp[2];
    int rel_start;
    int rel_end;
#if defined(CONFIG_LATX_TU) || defined(LATS_AOT_DISK_TU)
    union {
        int is_first_tb;
        int tu_size;
    };
    uint16_t jmp_reset_offset[2]; /* offset of original jump target */
    uint16_t jmp_insn_offset[2];  /* offset of direct jump insn */
    uint16_t jmp_cp_data[2];
    uint16_t tu_generation_offset_patch[2];
    uint16_t size;
    uint16_t icount;
    uint8_t link_opt[2];
    uint8_t int_opt[2];
    uint8_t eflag_use;
    uint8_t eflag_use_real;
    uint8_t last_ir1_type;
    uint8_t tu_tb_mode;
    struct {
        uint8_t eflag_type;
        uint8_t os;
        uint8_t opnd0;
        uint8_t opnd1;
        int pcoffset;
    } ptn;
#endif
};

typedef struct aot_block aot_block;

typedef enum aot_rel_kind {

    B_PROLOGUE,
    B_EPILOGUE,
    B_EPILOGUE_RET_0,
    B_NATIVE_JMP_GLUE2,

    LOAD_TB_ADDR,
    /* C helper argument: retain the full pointer with split TB metadata. */
    LOAD_TB_FULL_ADDR,
    LOAD_RIP_OFF,
    LOAD_GUEST_ADDR,
    /* Relocatable guest address with uint32_t zero-extension semantics. */
    LOAD_GUEST_ADDR32,
    LOAD_CALL_TARGET,
    LOAD_SYSCALL_OPTIMIZE_CONFIRM,

    LOAD_BY_GUEST_ADDR_CPU_NEG_ITLB,

    INTB_FSHT_LOOKUP,
    INTB_FSHT_LOOKUP_TUCPFAST,
    SC_TABLE_BEGIN,
    SC_TABLE_END,
    SC_TABLE_OFFSET_BEGIN,
    INTB_LOOKUP,
    SCS_EPILOGUE,
    SCS_PROLOGUE,
    SCS_PROLOGUE_NOFP,
    SCS_EPILOGUE_NOFP,
    CS_BT_TO_NATIVE,
    CS_BT_TO_NATIVE_RET_0,
    CS_BT_TO_NATIVE_RET_N3,
    CS_BT_TO_NATIVE_RET_N2,
    CS_BT_TO_NATIVE_RET_N1,
    CS_BT_TO_NATIVE_RET_N0,
    CP_CHECK_N0_P01_MMU_USER, CP_CHECK_N0_P01_MMU_USER_INTCHECK,
    CP_CHECK_N1_P01_MMU_USER, CP_CHECK_N1_P01_MMU_USER_INTCHECK,
    CP_CHECK_N0_P01_MMU_KNOSMAP, CP_CHECK_N0_P01_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_N1_P01_MMU_KNOSMAP, CP_CHECK_N1_P01_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_N0_P0_MMU_USER, CP_CHECK_N0_P0_MMU_USER_INTCHECK,
    CP_CHECK_N1_P0_MMU_USER, CP_CHECK_N1_P0_MMU_USER_INTCHECK,
    CP_CHECK_N0_P0_MMU_KNOSMAP, CP_CHECK_N0_P0_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_N1_P0_MMU_KNOSMAP, CP_CHECK_N1_P0_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_N0_P1_MMU_USER, CP_CHECK_N0_P1_MMU_USER_INTCHECK,
    CP_CHECK_N1_P1_MMU_USER, CP_CHECK_N1_P1_MMU_USER_INTCHECK,
    CP_CHECK_N0_P1_MMU_KNOSMAP, CP_CHECK_N0_P1_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_N1_P1_MMU_KNOSMAP, CP_CHECK_N1_P1_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_PTW_N0_P01_MMU_USER, CP_CHECK_PTW_N0_P01_MMU_USER_INTCHECK,
    CP_CHECK_PTW_N1_P01_MMU_USER, CP_CHECK_PTW_N1_P01_MMU_USER_INTCHECK,
    CP_CHECK_PTW_N0_P0_MMU_USER, CP_CHECK_PTW_N0_P0_MMU_USER_INTCHECK,
    CP_CHECK_PTW_N1_P0_MMU_USER, CP_CHECK_PTW_N1_P0_MMU_USER_INTCHECK,
    CP_CHECK_PTW_N0_P1_MMU_USER, CP_CHECK_PTW_N0_P1_MMU_USER_INTCHECK,
    CP_CHECK_PTW_N1_P1_MMU_USER, CP_CHECK_PTW_N1_P1_MMU_USER_INTCHECK,
    CP_CHECK_PTW_USER,
    TU_CP_CHECK_N0_MMU_USER, TU_CP_CHECK_N0_MMU_USER_INTCHECK,
    TU_CP_CHECK_N1_MMU_USER, TU_CP_CHECK_N1_MMU_USER_INTCHECK,
    CP_CHECK_PTW_N0_P01_MMU_KNOSMAP, CP_CHECK_PTW_N0_P01_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_PTW_N1_P01_MMU_KNOSMAP, CP_CHECK_PTW_N1_P01_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_PTW_N0_P0_MMU_KNOSMAP, CP_CHECK_PTW_N0_P0_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_PTW_N1_P0_MMU_KNOSMAP, CP_CHECK_PTW_N1_P0_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_PTW_N0_P1_MMU_KNOSMAP, CP_CHECK_PTW_N0_P1_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_PTW_N1_P1_MMU_KNOSMAP, CP_CHECK_PTW_N1_P1_MMU_KNOSMAP_INTCHECK,
    CP_CHECK_PTW_KNOSMAP,
    CS_NATIVE_TO_BT_RET_0,
    CS_NATIVE_TO_BT_RET_N0,
    CS_NATIVE_TO_BT_RET_N1,
    CS_NATIVE_TO_BT_RET_N2,
    CS_NATIVE_TO_BT_RET_N3,
    RAS_TP_REPAIR,
    SC_TABLE_OFFSET_END,

    /* Helper functions relocation. Assume we need to call a helper in our tb,
     * we'll load its address into a tmp reg and then jmp to that address, but
     * if latx has changed its code and all helper address has changed, all aot
     * tb will need to be relocated. */
    LOAD_HELPER_BEGIN,
    HELPER_AAA,
    HELPER_AAD,
    HELPER_AAM,
    HELPER_AAS,
    HELPER_ATOMIC_CMPXCHGB,
    HELPER_ATOMIC_CMPXCHGL_LE,
    HELPER_ATOMIC_CMPXCHGQ_LE,
    HELPER_ATOMIC_CMPXCHGW_LE,
    HELPER_ATOMIC_FETCH_ADDB,
    HELPER_ATOMIC_FETCH_ADDL_LE,
    HELPER_ATOMIC_FETCH_ADDQ_LE,
    HELPER_ATOMIC_FETCH_ADDW_LE,
    HELPER_ATOMIC_FETCH_ANDB,
    HELPER_ATOMIC_FETCH_ANDL_LE,
    HELPER_ATOMIC_FETCH_ANDQ_LE,
    HELPER_ATOMIC_FETCH_ANDW_LE,
    HELPER_ATOMIC_FETCH_ORB,
    HELPER_ATOMIC_FETCH_ORL_LE,
    HELPER_ATOMIC_FETCH_ORQ_LE,
    HELPER_ATOMIC_FETCH_ORW_LE,
    HELPER_ATOMIC_FETCH_XORB,
    HELPER_ATOMIC_FETCH_XORL_LE,
    HELPER_ATOMIC_FETCH_XORQ_LE,
    HELPER_ATOMIC_FETCH_XORW_LE,
    HELPER_ATOMIC_XCHGB,
    HELPER_ATOMIC_XCHGL_LE,
    HELPER_ATOMIC_XCHGQ_LE,
    HELPER_ATOMIC_XCHGW_LE,
    HELPER_BPT_IO,
    HELPER_CHECK_IO,
    /* HELPER_CHECK_IOB, */
    /* HELPER_CHECK_IOL, */
    /* HELPER_CHECK_IOW, */
    /* HELPER_CMPXCHG16B, */
    /* HELPER_CMPXCHG16B_UNLOCKED, */
    /* HELPER_CMPXCHG8B, */
    /* HELPER_CMPXCHG8B_UNLOCKED, */
    HELPER_CPUID,
    /* HELPER_CVTPD2DQ, */
    HELPER_CVTPD2PI,
    /* HELPER_CVTPS2DQ, */
    HELPER_CVTPS2PI,
    HELPER_CVTSD2SI,
    HELPER_CVTSS2SI,
    HELPER_CVTSS2SQ,
    /* HELPER_CVTTPD2DQ, */
    HELPER_CVTTPD2PI,
    /* HELPER_CVTTPS2DQ, */
    HELPER_CVTTPS2PI,
    HELPER_DAA,
    HELPER_DAS,
    /* HELPER_DEBUG, */
    HELPER_DIVQ_EAX,
    HELPER_F2XM1,
    HELPER_FABS_ST0,
    HELPER_FADD_ST0_FT0,
    HELPER_FADD_STN_ST0,
    HELPER_FBLD_ST0,
    HELPER_FBST_ST0,
    HELPER_FCHS_ST0,
    HELPER_FCLEX,
    HELPER_FCOMI_ST0_FT0,
    HELPER_FCOM_ST0_FT0,
    HELPER_FCOS,
    HELPER_FDECSTP,
    HELPER_FDIVR_ST0_FT0,
    HELPER_FDIVR_STN_ST0,
    HELPER_FDIV_ST0_FT0,
    HELPER_FDIV_STN_ST0,
    HELPER_FFREE_STN,
    HELPER_FILDL_FT0,
    HELPER_FILDLL_ST0,
    HELPER_FILDL_ST0,
    HELPER_FINCSTP,
    HELPER_FISTLL_ST0,
    HELPER_FISTL_ST0,
    HELPER_FIST_ST0,
    HELPER_FLD1_ST0,
    HELPER_FLDCW,
    HELPER_FLDENV,
    HELPER_FLDL2E_ST0,
    HELPER_FLDL2T_ST0,
    HELPER_FLDL_FT0,
    HELPER_FLDLG2_ST0,
    HELPER_FLDLN2_ST0,
    HELPER_FLDL_ST0,
    HELPER_FLDPI_ST0,
    HELPER_FLDS_FT0,
    HELPER_FLDS_ST0,
    HELPER_FLDT_ST0,
    HELPER_FLDZ_FT0,
    HELPER_FLDZ_ST0,
    HELPER_FMOV_FT0_STN,
    HELPER_FMOV_ST0_STN,
    HELPER_FMOV_STN_ST0,
    HELPER_FMUL_ST0_FT0,
    HELPER_FMUL_STN_ST0,
    HELPER_FNINIT,
    HELPER_FNSTCW,
    HELPER_FNSTSW,
    HELPER_FPATAN,
    HELPER_FPOP,
    HELPER_FPREM,
    HELPER_FPREM1,
    HELPER_FPTAN,
    HELPER_FPUSH,
    HELPER_FRNDINT,
    HELPER_FRSTOR,
    HELPER_FSAVE,
    HELPER_FSCALE,
    HELPER_FSIN,
    HELPER_FSINCOS,
    HELPER_FSQRT,
    HELPER_FSTENV,
    HELPER_FSTL_ST0,
    HELPER_FSTS_ST0,
    HELPER_FSTT_ST0,
    HELPER_FSUBR_ST0_FT0,
    HELPER_FSUBR_STN_ST0,
    HELPER_FSUB_ST0_FT0,
    HELPER_FSUB_STN_ST0,
    HELPER_FUCOMI_ST0_FT0,
    HELPER_FUCOM_ST0_FT0,
    HELPER_FWAIT,
    HELPER_FXAM_ST0,
    HELPER_FXCHG_ST0_STN,
    HELPER_FXRSTOR,
    HELPER_FXSAVE,
    HELPER_FXTRACT,
    HELPER_FYL2X,
    HELPER_FYL2XP1,
    HELPER_GET_DR,
    HELPER_HLT,
    HELPER_IDIVQ_EAX,
    HELPER_IDT_CACHE_CLEAR,
    HELPER_INB,
    HELPER_INL,
    HELPER_INTO,
    /* HELPER_INVLPG, */
    /* HELPER_INVLPGA, */
    HELPER_INW,
    HELPER_IRET_PROTECTED,
    HELPER_IRET_REAL,
    HELPER_LCALL_PROTECTED,
    HELPER_LCALL_REAL,
    /* HELPER_LE_LDQ_MMU, */
    /* HELPER_LE_LDSL_MMU, */
    /* HELPER_LE_LDSW_MMU, */
    /* HELPER_LE_LDUL_MMU, */
    /* HELPER_LE_LDUW_MMU, */
    /* HELPER_LE_STL_MMU, */
    /* HELPER_LE_STQ_MMU, */
    /* HELPER_LE_STW_MMU, */
    HELPER_LJMP_PROTECTED,
    HELPER_LLDT,
    /* HELPER_LMSW, */
    HELPER_LOAD_SEG,
    /* HELPER_LOOKUP_TB, */
    HELPER_LRET_PROTECTED,
    HELPER_LTR,
    HELPER_OUTB,
    HELPER_OUTL,
    HELPER_OUTW,
    HELPER_PAUSE,
    HELPER_RAISE_EXCEPTION,
    HELPER_RAISE_INTERRUPT,
    HELPER_RDMSR,
    HELPER_RDPMC,
    HELPER_RDTSC,
    /* HELPER_RDTSCP, */
    HELPER_READ_CRN,
    /* HELPER_RET_LDSB_MMU, */
    /* HELPER_RET_LDUB_MMU, */
    /* HELPER_RET_STB_MMU, */
    HELPER_RSM,
    HELPER_SET_DR,
    HELPER_SINGLE_STEP,
    HELPER_SYSCALL,
    HELPER_SYSENTER,
    HELPER_SYSEXIT,
    HELPER_SYSRET,
    HELPER_VERR,
    HELPER_VERW,
    HELPER_WRITE_CRN,
    HELPER_WRITE_EFLAGS,
    HELPER_WRMSR,
    /* HELPER_X86_CPU_DUMP_STATE, */
    HELPER_XGETBV,
    HELPER_XRSTOR,
    HELPER_XSAVE,
    HELPER_XSAVEOPT,
    HELPER_XSETBV,
    HELPER_LDQ_MMU,
    HELPER_STB_MMU,
    HELPER_STW_MMU,
    HELPER_STL_MMU,
    HELPER_STQ_MMU,
    HELPER_LDSB_MMU,
    HELPER_LDUB_MMU,
    HELPER_LDUW_MMU,
    HELPER_LDUL_MMU,
    HELPER_LDSW_MMU,
    HELPER_LDSL_MMU,
    HELPER_SOFTMMU_COMMON,
    HELPER_LATX_CMPXCHG8B,
    HELPER_LATX_CMPXCHG16B,
    HELPER_LATX_CMPXCHG8B_UNLOCKED,
    HELPER_LATX_CMPXCHG16B_UNLOCKED,
    HELPER_RDRAND,
    HELPER_FLUSH_PAGE,
    HELPER_LAR,
    HELPER_LSL,
    HELPER_CRC32,
    HELPER_PCMPISTRI_XMM,
    HELPER_PCMPISTRM_XMM,
    HELPER_PCMPESTRI_XMM,
    HELPER_PCMPESTRM_XMM,
    HELPER_AESDEC_XMM,
    HELPER_AESENC_XMM,
    HELPER_AESIMC_XMM,
    HELPER_AESDECLAST_XMM,
    HELPER_AESKEYGENASSIST_XMM,
    HELPER_PCLMULQDQ_XMM,
    HELPER_SHA1MSG1,
    HELPER_SHA1MSG2,
    HELPER_SHA1NEXTE,
    HELPER_SHA256MSG1,
    HELPER_SHA256MSG2,
    HELPER_SHA256RNDS2,
    HELPER_SHA1RNDS4_F0,
    HELPER_SHA1RNDS4_F1,
    HELPER_SHA1RNDS4_F2,
    HELPER_SHA1RNDS4_F3,
    HELPER_AESENCLAST_XMM,
    HELPER_FISTT_ST0,
    HELPER_FISTTL_ST0,
    HELPER_FISTTLL_ST0,
    HELPER_REP_INS,
    HELPER_REP_OUTS,
    LATX_APIC_MEM_WRITE,

    LATXS_CONVERT_FPREGS_64_TO_X80,
    LATXS_CONVERT_FPREGS_X80_TO_64,
    LATX_HELPER_LOOKUP_TB_HASHTABLE,
    LATX_HELPER_RAS_TP_REPAIR_CALL,
    /* LATXS_HELPER_LE_LDDQ_MMU, */
    /* LATXS_HELPER_LE_STDQ_MMU, */
    LATXS_HELPER_LDDQ_MMU,
    LATXS_HELPER_STDQ_MMU,
    PF_TABLE,
    UPDATE_FP_STATUS,
    UPDATE_MXCSR_STATUS,
    LOG2,
    POW,
    SIN,
    COS,
    ATAN2,
    LOAD_AES_Td0,
    LOAD_AES_Td1,
    LOAD_AES_Td2,
    LOAD_AES_Td3,
    LOAD_AES_Te0,
    LOAD_AES_Te1,
    LOAD_AES_Te2,
    LOAD_AES_Te3,
    LOAD_AES_sbox,
    LOAD_AES_isbox,
    LOAD_AES_imc_rot,
    HELPER_INVPCID,
    DEADBEAF,
    LOAD_HELPER_END,


    LOAD_TUNNEL_ADDR_BEGIN,
    INTB_LOOKUP_COMPACT,
    INTB_NJC_RETURN,
    INTB_FSHT_AFTER_NJC,
    /* Optional offline leaves; original entries and CALL code stay intact. */
    AOT_NATIVE_ENTRY,
    AOT_NATIVE_CALL,
    /* Complete shared-State function and its original source-TB CALL slot. */
    AOT_NATIVE_CORE,
    AOT_NATIVE_CORE_CALL,
    /* Source-TB owned BL within a direct-register LLVM function. */
    AOT_NATIVE_DIRECT_CALL,
    /* Source-TB owned indirect CALL and its LLVM continuation. */
    AOT_NATIVE_INDIRECT_CALL,
    INTB_FSHT_CALL_LOOKUP_TUCPFAST,
    /* Shared softRAS RET miss slot for a direct LLVM leaf. */
    AOT_NATIVE_RET_MISS,
    /* Ordinary RET miss, after discarding native frames, without a link. */
    INTB_RESUME_LOOKUP,
    /* Source-validating ordinary CALL miss; appended, outside helper footer. */
    LOAD_HRAS_CALL_HELPER,
    LOAD_HRAS_CALL_RET0_ADDR,
    LOAD_HRAS_FSHT_BASE,
    HRAS_TU_CP_CHECK_PTR,
    /* LLVM SYSCALL: save state and enter the existing guest-kernel path. */
    AOT_NATIVE_SYSCALL,
    /* A terminal request for serialized LLVM atomic memory operations. */
    AOT_NATIVE_ATOMIC,
    /* A returning call to the guest CPU model within an LLVM function. */
    AOT_NATIVE_CPU_QUERY,
    /* A returning x87 helper call within an LLVM function. */
    AOT_NATIVE_X87,
    /* Returning helpers already used by ordinary LATS instruction templates. */
    AOT_NATIVE_SYSTEM,
    /* Source-TB owned direct BL to another guarded direct-entry LLVM function. */
    AOT_NATIVE_LINKED_CALL,
} aot_rel_kind;

#define AOT_NATIVE_CALL_STUB_SIZE 64

typedef struct aot_tail {
    uint64_t flags;
    int32_t page_num;
    int32_t tb_num;
    uint32_t sys_flag_reduction_tu;
    uint32_t njc_bits;
    uint32_t aot_tu_codegen_flags;
    /* Exact interrupt mode; occupies the existing alignment gap. */
    uint32_t interrupt_mode;
    uint64_t helper_addr[LOAD_HELPER_END - LOAD_HELPER_BEGIN];
    char aot_version[128];
} aot_tail;


typedef struct aot_rel {
    int kind;

    /* @tc_offset: Offset of this relocation in translated code.
     * @rel_slot_num: How many instruction slots this relocation occupy.
     */
    uint32_t tc_offset;
    uint32_t rel_slots_num;

    /* @x86_rip_offset: Offset of this X86 instruction in x86 baisc block.
     * @extra_addend: extra addend to this relocation.
     *
     * For example, if we want to reloacate *0xdeadbeef(rip)*, we'll fill
     * relocation slots with (rip + 0xdeadbeef). rip can be determined by
     * segment_base_addr + @x86_rip_offset while 0xdeadbeef should be
     * determined by @extra_addend.
     */
    uint64_t extra_addend;
    int next_entry_id;

} aot_rel;

typedef struct page_head {
    uint32_t page_magic;
    uint32_t page_hash;
    /* Number of TB records, or number of TU payload/reference records. */
    uint32_t tb_count;
    int32_t curr_page_sum_size;
} page_head;

typedef struct aot_tu_head {
    uint32_t tb_magic;
    uint32_t tu_sum_size;
    uint32_t tb_count;
    uint32_t rel_count;
    uint64_t first_pc;
    uint64_t tu_id;
    uint32_t page_count;
    uint32_t reserved;
} aot_tu_head;

/*
 * Dependencies are relative to the TU anchor page. The fingerprint is retained
 * for save-time TU identities and offline verification. Runtime loading locates
 * the owning payload/member reference and compares the full saved page bytes.
 */
typedef struct aot_tu_page {
    int64_t pc_delta;
    uint64_t page_fingerprint;
} aot_tu_page;

/*
 * The complete TU payload is stored only in its anchor page.  Every other
 * member page carries this fixed-size reference.  anchor_delta rebases the
 * anchor from the page through which the record was found.
 */
typedef struct aot_tu_ref {
    uint32_t ref_magic;
    uint32_t ref_size;
    uint64_t tu_id;
    int64_t anchor_delta;
    uint32_t reserved[2];
} aot_tu_ref;

/* 页面信息：用于文件存储，加载时重建哈希表 */
typedef struct {
    uint32_t page_hash;      // 页面内容哈希值
    uint64_t file_offset;    // 页面在文件中的起始偏移
} page_info_t;

/* 页面信息数组头部（位于文件尾部，aot_tail 之前） */
#ifdef __cplusplus
typedef struct alignas(page_info_t) {
    uint32_t page_count;
} page_info_array_t;
#else
typedef struct {
    uint32_t page_count;
    page_info_t pages[];
} page_info_array_t;
#endif

static inline bool aot_page_info_size(uint32_t page_count, size_t *size)
{
    size_t max_count = (((size_t)-1) - sizeof(page_info_array_t)) /
        sizeof(page_info_t);

    if ((size_t)page_count > max_count) {
        return false;
    }
    *size = sizeof(page_info_array_t) + (size_t)page_count * sizeof(page_info_t);
    return true;
}

#if defined(__cplusplus)
#define LATS_AOT_STATIC_ASSERT static_assert
#else
#define LATS_AOT_STATIC_ASSERT _Static_assert
#endif
LATS_AOT_STATIC_ASSERT(sizeof(uintptr_t) == 8, "AOT requires a 64-bit host");
LATS_AOT_STATIC_ASSERT(sizeof(aot_rel) == 32, "AOT relocation layout");
LATS_AOT_STATIC_ASSERT(sizeof(aot_tu_head) == 40, "AOT TU layout");
LATS_AOT_STATIC_ASSERT(sizeof(aot_tail) == 2072, "AOT tail layout");
#if defined(CONFIG_LATX_TU) || defined(LATS_AOT_DISK_TU)
LATS_AOT_STATIC_ASSERT(sizeof(aot_block) == 176, "AOT member layout");
#endif
#undef LATS_AOT_STATIC_ASSERT

#endif
