/*
 * Capstone disassembler engine bindings for OCaml
 *
 * By Sam L. Thomas (xorpse) <st@xv.ax>, 2019 --
 * Based on bindings by Nguyen Anh Quynh <aquynh@gmail.com>, 2013
 *
 */

#include <string.h>

#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/version.h>

#include <capstone/arm.h>
#include <capstone/arm64.h>
#include <capstone/capstone.h>
#include <capstone/m680x.h>
#include <capstone/m68k.h>
#include <capstone/mips.h>
#include <capstone/ppc.h>
#include <capstone/sparc.h>
#include <capstone/systemz.h>
#include <capstone/tms320c64x.h>
#include <capstone/x86.h>
#include <capstone/xcore.h>

#include "arm64_const_stubs.h"
#include "arm_const_stubs.h"
#include "evm_const_stubs.h"
#include "m680x_const_stubs.h"
#include "m68k_const_stubs.h"
#include "mips_const_stubs.h"
#include "ppc_const_stubs.h"
#include "sparc_const_stubs.h"
#include "sysz_const_stubs.h"
#include "tms320c64x_const_stubs.h"
#include "x86_const_stubs.h"
#include "xcore_const_stubs.h"

#include "capstone_poly_var_syms.h"
#include "cs_const_stubs.h"

#define Val_none Val_int(0)
#define Some_val(v) Field(v, 0)
#define Val_emptyarray Atom(0)

static CAMLprim value Val_some(value v) {
  CAMLparam1(v);
  CAMLlocal1(some);
  some = caml_alloc(1, 0);
  Store_field(some, 0, v);
  CAMLreturn(some);
}

static CAMLprim value caml_copy_uint8_array(uint8_t *array, size_t len) {
  CAMLparam0();
  CAMLlocal1(a);

  a = caml_alloc(len, 0);

  for (size_t i = 0; i < len; i++) {
    Store_field(a, i, Val_int(array[i]));
  }

  CAMLreturn(a);
}

CAMLprim value ml_capstone_cs_ac_type(cs_ac_type t) {
  CAMLparam0();
  CAMLlocal1(v);

  switch ((int)t) {
  case CS_AC_READ:
    v = caml_hash_variant("R");
    break;
  case CS_AC_WRITE:
    v = caml_hash_variant("W");
    break;
  case CS_AC_READ | CS_AC_WRITE:
    v = caml_hash_variant("RW");
    break;
  default:
    caml_failwith("capstone: unknown access type");
    break;
  }

  CAMLreturn(v);
}

// NOTE(xorpse): convert Xflag mask
// let i=0 | g/$/s//\=' -> Int64.shift_left 1L '.i/ | let i=i+1

#define ARR_SIZE(a) (sizeof(a) / sizeof(*a))
#define Capstone_handle_val(v) ((csh *)Data_custom_val(v))

static void ml_capstone_finalise_handle(value h) {
  CAMLparam1(h);
  cs_close(Capstone_handle_val(h));
  CAMLreturn0;
}

static struct custom_operations ml_capstone_handle_custom_ops = {
    (char *)"ml_capstone_handle_custom_ops",
    ml_capstone_finalise_handle,
    custom_compare_default,
    custom_compare_ext_default,
    custom_hash_default,
    custom_serialize_default,
    custom_deserialize_default,
#if OCAML_VERSION_MAJOR >= 4 && OCAML_VERSION_MINOR >= 8
    NULL, // custom_fixed_length
#endif
};

static value ml_capstone_alloc_handle(const csh *handle) {
  CAMLparam0();
  CAMLlocal1(h);
  h = caml_alloc_custom(&ml_capstone_handle_custom_ops, sizeof(*handle), 0, 1);
  memcpy(Capstone_handle_val(h), handle, sizeof(*handle));
  CAMLreturn(h);
}

CAMLprim value ml_capstone_create(value arch, value mode) {
  CAMLparam2(arch, mode);
  csh handle;

  if (cs_open(Int_val(arch), Int_val(mode), &handle) != 0) {
    CAMLreturn(Val_none);
  }

  CAMLreturn(Val_some(ml_capstone_alloc_handle(&handle)));
}

CAMLprim value ml_capstone_set_option(value handle, value opt, value val) {
  CAMLparam3(handle, opt, val);

  int err = cs_option(*Capstone_handle_val(handle), Int_val(opt), Int_val(val));

  if (err != CS_ERR_OK) {
    caml_raise_with_arg(*caml_named_value("Capstone_error"),
                        ml_cs_err_to_capstone(err));
  }

  CAMLreturn(Val_unit);
}

CAMLprim value ml_capstone_disassemble_inner(cs_arch arch, csh handle,
                                             const uint8_t *code,
                                             size_t code_len, uint64_t addr,
                                             size_t count) {
  CAMLparam0();
  CAMLlocal5(list, cons, rec_insn, array, tmp);
  CAMLlocal4(detail_opt, op_info_val, tmp2, tmp3);
  cs_insn *insn;
  size_t c;

  list = Val_emptylist;

  c = cs_disasm(handle, code, code_len, addr, count, &insn);
  if (c) {
    uint64_t j;
    for (j = c; j > 0; j--) {
      unsigned int lcount, i;
      cons = caml_alloc(2, 0);

#define INSN(LOWER_PREFIX, HAS_REG, GRP_TYPE)                                  \
  rec_insn = caml_alloc(HAS_REG ? 10 : 8, 0);                                  \
  Store_field(rec_insn, 0, Val_int(insn[j - 1].id));                           \
  Store_field(rec_insn, 1, caml_copy_int64(insn[j - 1].address));              \
  Store_field(rec_insn, 2, Val_int(insn[j - 1].size));                         \
  tmp = caml_alloc_string(insn[j - 1].size);                                   \
  memcpy(Bytes_val(tmp), insn[j - 1].bytes, insn[j - 1].size);                 \
  Store_field(rec_insn, 3, tmp);                                               \
  Store_field(rec_insn, 4, caml_copy_string(insn[j - 1].mnemonic));            \
  Store_field(rec_insn, 5, caml_copy_string(insn[j - 1].op_str));              \
  if (HAS_REG) {                                                               \
    if (insn[0].detail) {                                                      \
      lcount = (insn[j - 1]).detail->regs_read_count;                          \
      if (lcount) {                                                            \
        array = caml_alloc(lcount, 0);                                         \
        for (i = 0; i < lcount; i++) {                                         \
          Store_field(array, i, Val_int(insn[j - 1].detail->regs_read[i]));    \
        }                                                                      \
      } else {                                                                 \
        array = Val_emptyarray;                                                \
      }                                                                        \
    } else {                                                                   \
      array = Val_emptyarray;                                                  \
    }                                                                          \
    Store_field(rec_insn, 6, array);                                           \
    if (insn[0].detail) {                                                      \
      lcount = (insn[j - 1]).detail->regs_write_count;                         \
      if (lcount) {                                                            \
        array = caml_alloc(lcount, 0);                                         \
        for (i = 0; i < lcount; i++) {                                         \
          Store_field(array, i, Val_int(insn[j - 1].detail->regs_write[i]));   \
        }                                                                      \
      } else {                                                                 \
        array = Val_emptyarray;                                                \
      }                                                                        \
    } else {                                                                   \
      array = Val_emptyarray;                                                  \
    }                                                                          \
    Store_field(rec_insn, 7, array);                                           \
  }                                                                            \
  if (insn[0].detail) {                                                        \
    lcount = (insn[j - 1]).detail->groups_count;                               \
    if (lcount) {                                                              \
      array = caml_alloc(lcount, 0);                                           \
      for (i = 0; i < lcount; i++) {                                           \
        if (insn[j - 1].detail->groups[i] <= CS_GRP_BRANCH_RELATIVE) {         \
          Store_field(                                                         \
              array, i,                                                        \
              ml_capstone_to_cs_group_type(insn[j - 1].detail->groups[i]));    \
        } else {                                                               \
          Store_field(array, i,                                                \
                      ml_capstone_to_##LOWER_PREFIX##_##GRP_TYPE(              \
                          insn[j - 1].detail->groups[i]));                     \
        }                                                                      \
      }                                                                        \
    } else {                                                                   \
      array = Val_emptyarray;                                                  \
    }                                                                          \
  } else {                                                                     \
    array = Val_emptyarray;                                                    \
  }                                                                            \
  Store_field(rec_insn, HAS_REG ? 8 : 6, array)

      switch (arch) {
      case CS_ARCH_ARM: {
        INSN(arm, true, insn_group);
        if (insn[j - 1].detail) {
          op_info_val = caml_alloc(10, 0);

          cs_arm *detail = &insn[j - 1].detail->arm;

          Store_field(op_info_val, 0, Val_bool(detail->usermode));
          Store_field(op_info_val, 1, Val_int(detail->vector_size));
          Store_field(op_info_val, 2,
                      detail->vector_data
                          ? Val_some(Val_int(detail->vector_data))
                          : Val_none);
          Store_field(op_info_val, 3,
                      detail->cps_mode ? Val_some(Val_int(detail->cps_mode))
                                       : Val_none);
          Store_field(op_info_val, 4,
                      detail->cps_flag ? Val_some(Val_int(detail->cps_flag))
                                       : Val_none);
          Store_field(op_info_val, 5,
                      detail->cc ? Val_some(Val_int(detail->cc)) : Val_none);
          Store_field(op_info_val, 6, Val_bool(detail->update_flags));
          Store_field(op_info_val, 7, Val_bool(detail->writeback));
          Store_field(op_info_val, 8, Val_int(detail->mem_barrier));

          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              tmp2 = caml_alloc(6, 0);
              switch (detail->operands[i].type) {
              case ARM_OP_REG:
                tmp = caml_alloc(1, 0);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case ARM_OP_CIMM:
                tmp = caml_alloc(1, 1);
                Store_field(tmp, 0, caml_copy_int32(detail->operands[i].imm));
                break;
              case ARM_OP_PIMM:
                tmp = caml_alloc(1, 2);
                Store_field(tmp, 0, caml_copy_int32(detail->operands[i].imm));
                break;
              case ARM_OP_IMM:
                tmp = caml_alloc(1, 3);
                Store_field(tmp, 0, caml_copy_int32(detail->operands[i].imm));
                break;
              case ARM_OP_FP:
                tmp = caml_alloc(1, 4);
                Store_field(tmp, 0, caml_copy_double(detail->operands[i].fp));
                break;
              case ARM_OP_MEM:
                tmp = caml_alloc(1, 5);
                tmp3 = caml_alloc(4, 0);
                Store_field(
                    tmp3, 0,
                    detail->operands[i].mem.base != ARM_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.base))
                        : Val_none);
                Store_field(
                    tmp3, 1,
                    detail->operands[i].mem.base != ARM_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.index))
                        : Val_none);
                Store_field(tmp3, 2, Val_int(detail->operands[i].mem.scale));
                Store_field(tmp3, 3, Val_int(detail->operands[i].mem.disp));
                Store_field(tmp, 0, tmp3);
                break;
              case ARM_OP_SETEND:
                tmp = caml_alloc(1, 6);
                Store_field(tmp, 0, Val_int(detail->operands[i].setend));
                break;
              case ARM_OP_SYSREG:
                tmp = caml_alloc(1, 6);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              default:
                break;
              }
              // operand.vector_index
              Store_field(
                  tmp2, 0,
                  detail->operands[i].vector_index == -1
                      ? Val_some(Val_int(detail->operands[i].vector_index))
                      : Val_none);
              // operand.shift
              if (detail->operands[i].shift.type != ARM_SFT_INVALID) {
                tmp3 = caml_alloc(2, 0);
                Store_field(tmp3, 0, Val_int(detail->operands[i].shift.type));
                Store_field(tmp3, 1, Val_int(detail->operands[i].shift.value));
                Store_field(tmp2, 1, Val_some(tmp3));
              } else {
                Store_field(tmp2, 1, Val_none);
              }
              // operand.value
              Store_field(tmp2, 2, tmp);
              // operand.subtracted
              Store_field(tmp2, 3, Val_bool(detail->operands[i].subtracted));
              // operand.access
              Store_field(tmp2, 4,
                          ml_capstone_cs_ac_type(detail->operands[i].access));
              // operand.neon_lane
              Store_field(tmp2, 5,
                          detail->operands[i].neon_lane == -1
                              ? Val_some(Val_int(detail->operands[i].neon_lane))
                              : Val_none);
              Store_field(array, i, tmp2);
            }
          } else {
            array = Val_emptyarray;
          }

          Store_field(op_info_val, 9, array);
          Store_field(rec_insn, 9, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      case CS_ARCH_ARM64: {
        INSN(arm64, true, insn_group);
        if (insn[j - 1].detail) {
          cs_arm64 *detail = &insn[j - 1].detail->arm64;
          op_info_val = caml_alloc(4, 0);

          Store_field(op_info_val, 0,
                      detail->cc != ARM64_CC_INVALID
                          ? Val_some(Val_int(detail->cc))
                          : Val_none);
          Store_field(op_info_val, 1, Val_bool(detail->update_flags));
          Store_field(op_info_val, 2, Val_bool(detail->writeback));

          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              tmp2 = caml_alloc(7, 0);
              switch (detail->operands[i].type) {
              case ARM64_OP_REG:
                tmp = caml_alloc(1, 0);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case ARM64_OP_IMM:
                tmp = caml_alloc(1, 1);
                Store_field(tmp, 0, caml_copy_int64(detail->operands[i].imm));
                break;
              case ARM64_OP_CIMM:
                tmp = caml_alloc(1, 2);
                Store_field(tmp, 0, caml_copy_int64(detail->operands[i].imm));
                break;
              case ARM64_OP_FP:
                tmp = caml_alloc(1, 3);
                Store_field(tmp, 0, caml_copy_double(detail->operands[i].fp));
                break;
              case ARM64_OP_MEM:
                tmp = caml_alloc(1, 4);
                tmp3 = caml_alloc(3, 0);
                Store_field(
                    tmp3, 0,
                    detail->operands[i].mem.base != ARM64_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.base))
                        : Val_none);
                Store_field(
                    tmp3, 1,
                    detail->operands[i].mem.index != ARM64_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.index))
                        : Val_none);
                Store_field(tmp3, 2,
                            caml_copy_int32(detail->operands[i].mem.disp));
                Store_field(tmp, 0, tmp3);
                break;
              case ARM64_OP_REG_MRS:
                tmp = caml_alloc(1, 5);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case ARM64_OP_REG_MSR:
                tmp = caml_alloc(1, 6);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case ARM64_OP_PSTATE:
                tmp = caml_alloc(1, 7);
                Store_field(tmp, 0, Val_int(detail->operands[i].pstate));
                break;
              case ARM64_OP_SYS: {
                switch (insn[j - 1].id) {
                case ARM64_INS_AT:
                  tmp = caml_alloc(1, 8);
                  Store_field(tmp, 0, Val_int(detail->operands[i].sys));
                  break;
                case ARM64_INS_DC:
                  tmp = caml_alloc(1, 9);
                  Store_field(tmp, 0, Val_int(detail->operands[i].sys));
                  break;
                case ARM64_INS_IC:
                  tmp = caml_alloc(1, 10);
                  Store_field(tmp, 0, Val_int(detail->operands[i].sys));
                  break;
                case ARM64_INS_TLBI:
                  tmp = caml_alloc(1, 11);
                  Store_field(tmp, 0, Val_int(detail->operands[i].sys));
                  break;
                default:
                  tmp = caml_alloc(1, 12);
                  Store_field(tmp, 0, Val_int(detail->operands[i].sys));
                  break;
                }
                break;
              }
              case ARM64_OP_PREFETCH:
                tmp = caml_alloc(1, 13);
                Store_field(tmp, 0, Val_int(detail->operands[i].prefetch));
                break;
              case ARM64_OP_BARRIER:
                tmp = caml_alloc(1, 14);
                Store_field(tmp, 0, Val_int(detail->operands[i].barrier));
                break;
              default:
                caml_failwith("arm64: unknown operand type");
                break;
              }
              Store_field(
                  tmp2, 0,
                  detail->operands[i].vector_index != -1
                      ? Val_some(Val_int(detail->operands[i].vector_index))
                      : Val_none);
              Store_field(tmp2, 1,
                          detail->operands[i].vas != ARM64_VAS_INVALID
                              ? Val_some(Val_int(detail->operands[i].vas))
                              : Val_none);
              Store_field(tmp2, 2,
                          detail->operands[i].vess != ARM64_VESS_INVALID
                              ? Val_some(Val_int(detail->operands[i].vess))
                              : Val_none);

              if (detail->operands[i].shift.type != ARM64_SFT_INVALID) {
                tmp3 = caml_alloc(2, 0);
                Store_field(tmp3, 0, Val_int(detail->operands[i].shift.type));
                Store_field(tmp3, 1, Val_int(detail->operands[i].shift.value));

                Store_field(tmp2, 3, Val_some(tmp3));
              } else {
                Store_field(tmp2, 3, Val_none);
              }

              Store_field(tmp2, 4,
                          detail->operands[i].ext != ARM64_EXT_INVALID
                              ? Val_some(Val_int(detail->operands[i].ext))
                              : Val_none);
              Store_field(tmp2, 5, tmp);
              Store_field(tmp2, 6,
                          ml_capstone_cs_ac_type(detail->operands[i].access));
              Store_field(array, i, tmp2);
            }
          } else {
            array = Val_emptyarray;
          }

          Store_field(op_info_val, 3, array);
          Store_field(rec_insn, 9, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      case CS_ARCH_EVM: {
        INSN(evm, false, insn_group);
        if (insn[j - 1].detail) {
          cs_evm *detail = &insn[j - 1].detail->evm;
          op_info_val = caml_alloc(3, 0);
          Store_field(op_info_val, 0, Val_int(detail->pop));
          Store_field(op_info_val, 1, Val_int(detail->push));
          Store_field(op_info_val, 2, Val_int(detail->fee));
          Store_field(rec_insn, 7, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 7, Val_none);
        }
        break;
      }
      case CS_ARCH_M680X: {
        INSN(m680x, true, group_type);
        if (insn[j - 1].detail) {
          cs_m680x *detail = &insn[j - 1].detail->m680x;
          op_info_val = caml_alloc(2, 0);

          Store_field(op_info_val, 0, Val_int(detail->flags));
          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              switch (detail->operands[i].type) {
              case M680X_OP_REGISTER:
                tmp = caml_alloc(1, 0);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case M680X_OP_IMMEDIATE:
                tmp = caml_alloc(1, 1);
                Store_field(tmp, 0, caml_copy_int32(detail->operands[i].imm));
                break;
              case M680X_OP_INDEXED:
                tmp = caml_alloc(1, 2);
                tmp2 = caml_alloc(7, 0);
                Store_field(
                    tmp2, 0,
                    detail->operands[i].idx.base_reg != M680X_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].idx.base_reg))
                        : Val_none);
                Store_field(
                    tmp2, 1,
                    detail->operands[i].idx.offset_reg != M680X_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].idx.offset_reg))
                        : Val_none);
                Store_field(tmp2, 2, Val_int(detail->operands[i].idx.offset));
                Store_field(tmp2, 3,
                            Val_int(detail->operands[i].idx.offset_addr));
                Store_field(tmp2, 4,
                            Val_int(detail->operands[i].idx.offset_bits));
                Store_field(
                    tmp2, 5,
                    detail->operands[i].idx.inc_dec != 0
                        ? Val_some(Val_int(detail->operands[i].idx.inc_dec))
                        : Val_none);
                Store_field(tmp2, 6, Val_int(detail->operands[i].idx.flags));
                Store_field(tmp, 0, tmp2);
                break;
              case M680X_OP_RELATIVE:
                tmp = caml_alloc(1, 3);
                tmp2 = caml_alloc(2, 0);
                Store_field(tmp2, 0, Val_int(detail->operands[i].rel.address));
                Store_field(tmp2, 1, Val_int(detail->operands[i].rel.offset));
                Store_field(tmp, 0, tmp2);
                break;
              case M680X_OP_EXTENDED:
                tmp = caml_alloc(1, 4);
                tmp2 = caml_alloc(2, 0);
                Store_field(tmp2, 0, Val_int(detail->operands[i].ext.address));
                Store_field(tmp2, 1,
                            Val_bool(detail->operands[i].ext.indirect));
                Store_field(tmp, 0, tmp2);
                break;
              case M680X_OP_DIRECT:
                tmp = caml_alloc(1, 5);
                Store_field(tmp, 0, Val_int(detail->operands[i].direct_addr));
                break;
              case M680X_OP_CONSTANT:
                tmp = caml_alloc(1, 6);
                Store_field(tmp, 0, Val_int(detail->operands[i].const_val));
                break;
              default:
                caml_failwith("m680x: unknown operand type");
                break;
              }
              tmp2 = caml_alloc(3, 0);
              Store_field(tmp2, 0, tmp);
              Store_field(tmp2, 1, Val_int(detail->operands[i].size));
              Store_field(tmp2, 2,
                          ml_capstone_cs_ac_type(detail->operands[i].access));
              Store_field(array, i, tmp2);
            }
            Store_field(op_info_val, 1, array);
          } else {
            Store_field(op_info_val, 1, Val_emptyarray);
          }
          Store_field(rec_insn, 9, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      case CS_ARCH_M68K: {
        INSN(m68k, true, group_type);
        if (insn[j - 1].detail) {
          op_info_val = caml_alloc(2, 0);
          cs_m68k *detail = &insn[j - 1].detail->m68k;

          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              switch (detail->operands[i].type) {
              case M68K_OP_REG:
                tmp2 = caml_alloc(1, 0);
                Store_field(tmp2, 0, Val_int(detail->operands[i].reg));
                break;
              case M68K_OP_REG_BITS:
                tmp2 = caml_alloc(1, 1);
                Store_field(tmp2, 0,
                            caml_copy_int32(
                                (int32_t)detail->operands[i].register_bits));
                break;
              case M68K_OP_REG_PAIR:
                tmp2 = caml_alloc(1, 2);
                tmp3 = caml_alloc(2, 0);
                Store_field(tmp3, 0,
                            Val_int(detail->operands[i].reg_pair.reg_0));
                Store_field(tmp3, 1,
                            Val_int(detail->operands[i].reg_pair.reg_1));
                Store_field(tmp2, 0, tmp3);
                break;
              case M68K_OP_IMM:
                tmp2 = caml_alloc(1, 3);
                Store_field(tmp2, 0, caml_copy_int64(detail->operands[i].imm));
                break;
              case M68K_OP_MEM:
                tmp3 = caml_alloc(8, 0);
                Store_field(
                    tmp3, 0,
                    detail->operands[i].mem.base_reg != M68K_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.base_reg))
                        : Val_none);
                Store_field(
                    tmp3, 1,
                    detail->operands[i].mem.index_reg != M68K_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.index_reg))
                        : Val_none);
                Store_field(
                    tmp3, 2,
                    detail->operands[i].mem.in_base_reg != M68K_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.in_base_reg))
                        : Val_none);
                Store_field(tmp3, 3,
                            caml_copy_int32(detail->operands[i].mem.in_disp));
                Store_field(tmp3, 4,
                            caml_copy_int32(detail->operands[i].mem.out_disp));
                Store_field(tmp3, 5, Val_int(detail->operands[i].mem.disp));
                if (detail->operands[i].mem.bitfield) {
                  tmp2 = caml_alloc(2, 0);
                  Store_field(tmp2, 0, Val_int(detail->operands[i].mem.width));
                  Store_field(tmp2, 1, Val_int(detail->operands[i].mem.offset));
                  Store_field(tmp3, 6, Val_some(tmp2));
                } else {
                  Store_field(tmp3, 6, Val_none);
                }
                Store_field(tmp3, 7,
                            Val_int(detail->operands[i].mem.index_size));
                tmp2 = caml_alloc(1, 4);
                Store_field(tmp2, 0, tmp3);
                break;
              case M68K_OP_BR_DISP:
                tmp2 = caml_alloc(1, 5);
                tmp3 = caml_alloc(2, 0);
                Store_field(tmp3, 0,
                            caml_copy_int32(detail->operands[i].br_disp.disp));
                Store_field(tmp3, 1,
                            Val_int(detail->operands[i].br_disp.disp_size));
                Store_field(tmp2, 0, tmp3);
                break;
              case M68K_OP_FP_DOUBLE:
                tmp2 = caml_alloc(1, 6);
                Store_field(tmp2, 0,
                            caml_copy_double(detail->operands[i].dimm));
                break;
              case M68K_OP_FP_SINGLE:
                tmp2 = caml_alloc(1, 7);
                Store_field(tmp2, 0,
                            caml_copy_double(detail->operands[i].simm));
                break;
              default:
                caml_failwith("m68k: unknown operand type");
                break;
              }
              tmp = caml_alloc(2, 0);
              Store_field(tmp, 0, tmp2);
              Store_field(tmp, 1, Val_int(detail->operands[i].address_mode));
              Store_field(array, i, tmp);
            }
            Store_field(op_info_val, 0, array);
          } else {
            Store_field(op_info_val, 0, Val_emptyarray);
          }

          switch (detail->op_size.type) {
          case M68K_SIZE_TYPE_CPU:
            tmp = caml_alloc(1, 0);
            Store_field(tmp, 0, Val_int(detail->op_size.cpu_size));
            Store_field(op_info_val, 1, Val_some(tmp));
            break;
          case M68K_SIZE_TYPE_FPU:
            tmp = caml_alloc(1, 1);
            Store_field(tmp, 0, Val_int(detail->op_size.fpu_size));
            Store_field(op_info_val, 1, Val_some(tmp));
            break;
          default:
            Store_field(op_info_val, 1, Val_none);
            break;
          }

          Store_field(rec_insn, 9, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      case CS_ARCH_MIPS: {
        INSN(mips, true, insn_group);
        if (insn[j - 1].detail) {
          cs_mips *detail = &insn[j - 1].detail->mips;
          op_info_val = caml_alloc(1, 0);

          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              switch (detail->operands[i].type) {
              case MIPS_OP_REG:
                tmp = caml_alloc(1, 0);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case MIPS_OP_IMM:
                tmp = caml_alloc(1, 1);
                Store_field(tmp, 0, caml_copy_int64(detail->operands[i].imm));
                break;
              case MIPS_OP_MEM:
                tmp = caml_alloc(1, 2);
                tmp3 = caml_alloc(2, 0);
                Store_field(
                    tmp3, 0,
                    detail->operands[i].mem.base != MIPS_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.base))
                        : Val_none);
                Store_field(tmp3, 1,
                            caml_copy_int64(detail->operands[i].mem.disp));
                Store_field(tmp, 0, tmp3);
                break;
              default:
                caml_failwith("mips: unknown operand type");
                break;
              }
              Store_field(array, i, tmp);
            }
          } else {
            array = Val_emptyarray;
          }

          Store_field(op_info_val, 0, array);
          Store_field(rec_insn, 9, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      case CS_ARCH_PPC: {
        INSN(ppc, true, insn_group);
        if (insn[j - 1].detail) {
          cs_ppc *detail = &insn[j - 1].detail->ppc;
          op_info_val = caml_alloc(4, 0);

          Store_field(op_info_val, 0,
                      detail->bc != PPC_BC_INVALID
                          ? Val_some(Val_int(detail->bc))
                          : Val_none);
          Store_field(op_info_val, 1,
                      detail->bh != PPC_BH_INVALID
                          ? Val_some(Val_int(detail->bh))
                          : Val_none);
          Store_field(op_info_val, 2, Val_bool(detail->update_cr0));

          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              switch (detail->operands[i].type) {
              case PPC_OP_REG:
                tmp = caml_alloc(1, 0);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case PPC_OP_IMM:
                tmp = caml_alloc(1, 1);
                Store_field(tmp, 0, caml_copy_int64(detail->operands[i].imm));
                break;
              case PPC_OP_MEM:
                tmp = caml_alloc(1, 2);
                tmp3 = caml_alloc(2, 0);
                Store_field(
                    tmp3, 0,
                    detail->operands[i].mem.base != PPC_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.base))
                        : Val_none);
                Store_field(tmp3, 1,
                            caml_copy_int32(detail->operands[i].mem.disp));
                Store_field(tmp, 0, tmp3);
                break;
              case PPC_OP_CRX:
                tmp = caml_alloc(1, 3);
                tmp3 = caml_alloc(3, 0);
                Store_field(tmp3, 0, Val_int(detail->operands[i].crx.scale));
                Store_field(tmp3, 1, Val_int(detail->operands[i].crx.reg));
                Store_field(tmp3, 2, Val_int(detail->operands[i].crx.cond));
                Store_field(tmp, 0, tmp3);
                break;
              default:
                caml_failwith("ppc: unknown operand type");
                break;
              }
              Store_field(array, i, tmp);
            }
          } else {
            array = Val_emptyarray;
          }

          Store_field(op_info_val, 3, array);
          Store_field(rec_insn, 9, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      case CS_ARCH_SPARC: {
        INSN(sparc, true, insn_group);
        if (insn[j - 1].detail) {
          cs_sparc *detail = &insn[j - 1].detail->sparc;
          op_info_val = caml_alloc(3, 0);

          Store_field(op_info_val, 0,
                      detail->cc != SPARC_CC_INVALID
                          ? Val_some(Val_int(detail->cc))
                          : Val_none);
          Store_field(op_info_val, 1,
                      detail->hint != SPARC_HINT_INVALID
                          ? Val_some(Val_int(detail->hint))
                          : Val_none);

          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              switch (detail->operands[i].type) {
              case SPARC_OP_REG:
                tmp = caml_alloc(1, 0);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case SPARC_OP_IMM:
                tmp = caml_alloc(1, 1);
                Store_field(tmp, 0, caml_copy_int64(detail->operands[i].imm));
                break;
              case SPARC_OP_MEM:
                tmp = caml_alloc(1, 2);
                tmp2 = caml_alloc(3, 0);
                Store_field(
                    tmp2, 0,
                    detail->operands[i].mem.base != SPARC_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.base))
                        : Val_none);
                Store_field(
                    tmp2, 1,
                    detail->operands[i].mem.index != SPARC_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.index))
                        : Val_none);
                Store_field(tmp2, 2,
                            caml_copy_int32(detail->operands[i].mem.disp));
                Store_field(tmp, 0, tmp2);
                break;
              default:
                caml_failwith("sparc: unknown operand type");
                break;
              }
              Store_field(array, i, tmp);
            }
          } else {
            array = Val_emptyarray;
          }

          Store_field(op_info_val, 2, array);
          Store_field(rec_insn, 9, Val_some(detail_opt));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      case CS_ARCH_SYSZ: {
        INSN(sysz, true, insn_group);
        if (insn[j - 1].detail) {
          cs_sysz *detail = &insn[j - 1].detail->sysz;
          op_info_val = caml_alloc(2, 0);

          Store_field(op_info_val, 0,
                      detail->cc != SYSZ_CC_INVALID
                          ? Val_some(Val_int(detail->cc))
                          : Val_none);

          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              switch (detail->operands[i].type) {
              case SYSZ_OP_REG:
                tmp = caml_alloc(1, 0);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case SYSZ_OP_ACREG:
                tmp = caml_alloc(1, 1);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case SYSZ_OP_IMM:
                tmp = caml_alloc(1, 2);
                Store_field(tmp, 0, caml_copy_int64(detail->operands[i].imm));
                break;
              case SYSZ_OP_MEM:
                tmp = caml_alloc(1, 3);
                tmp2 = caml_alloc(4, 0);
                Store_field(
                    tmp2, 0,
                    detail->operands[i].mem.base != SYSZ_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.base))
                        : Val_none);
                Store_field(
                    tmp2, 1,
                    detail->operands[i].mem.index != SYSZ_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.index))
                        : Val_none);
                Store_field(tmp2, 2,
                            caml_copy_int64(detail->operands[i].mem.length));
                Store_field(tmp2, 3,
                            caml_copy_int64(detail->operands[i].mem.disp));
                Store_field(tmp, 0, tmp2);
                break;
              default:
                caml_failwith("systemz: unknown operand type");
                break;
              }
              Store_field(array, i, tmp);
            }
          } else {
            array = Val_emptyarray;
          }

          Store_field(op_info_val, 1, array);
          Store_field(rec_insn, 9, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      case CS_ARCH_TMS320C64X: {
        INSN(tms320c64x, true, insn_group);
        if (insn[j - 1].detail) {
          cs_tms320c64x *detail = &insn[j - 1].detail->tms320c64x;
          op_info_val = caml_alloc(4, 0);

          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              switch (detail->operands[i].type) {
              case TMS320C64X_OP_REG:
                tmp = caml_alloc(1, 0);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case TMS320C64X_OP_REGPAIR:
                // based on cstool/cstool_tms320c64x.c
                tmp = caml_alloc(1, 1);
                tmp2 = caml_alloc(2, 0);
                Store_field(tmp2, 0, Val_int(detail->operands[i].reg + 1));
                Store_field(tmp2, 1, Val_int(detail->operands[i].reg));
                Store_field(tmp, 0, tmp2);
                break;
              case TMS320C64X_OP_IMM:
                tmp = caml_alloc(1, 2);
                Store_field(tmp, 0, caml_copy_int32(detail->operands[i].imm));
                break;
              case TMS320C64X_OP_MEM:
                tmp = caml_alloc(1, 3);
                tmp2 = caml_alloc(6, 0);

                Store_field(
                    tmp2, 0,
                    detail->operands[i].mem.base != TMS320C64X_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.base))
                        : Val_none);

                switch (detail->operands[i].mem.disptype) {
                case TMS320C64X_MEM_DISP_REGISTER:
                  tmp3 = caml_alloc(1, 0);
                  Store_field(tmp3, 0, Val_int(detail->operands[i].mem.disp));
                  Store_field(tmp2, 1, Val_some(tmp3));
                  break;
                case TMS320C64X_MEM_DISP_CONSTANT:
                  tmp3 = caml_alloc(1, 1);
                  Store_field(tmp3, 0, Val_int(detail->operands[i].mem.disp));
                  Store_field(tmp2, 1, Val_some(tmp3));
                  break;
                default:
                  Store_field(tmp2, 1, Val_none);
                }

                Store_field(
                    tmp2, 2,
                    detail->operands[i].mem.unit != TMS320C64X_FUNIT_INVALID &&
                            detail->operands[i].mem.unit != TMS320C64X_FUNIT_NO
                        ? Val_some(Val_int(detail->operands[i].mem.unit))
                        : Val_none);
                Store_field(tmp2, 3, Val_bool(detail->operands[i].mem.scaled));
                Store_field(
                    tmp2, 4,
                    detail->operands[i].mem.direction !=
                            TMS320C64X_MEM_DIR_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.direction))
                        : Val_none);
                Store_field(
                    tmp2, 5,
                    detail->operands[i].mem.modify != TMS320C64X_MEM_MOD_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.modify))
                        : Val_none);
                Store_field(tmp, 0, tmp2);
                break;
              default:
                caml_failwith("tms320c64x: unknown operand type");
                break;
              }
              Store_field(array, i, tmp);
            }
            Store_field(op_info_val, 0, array);
          } else {
            Store_field(op_info_val, 0, Val_emptyarray);
          }

          if (detail->condition.reg != TMS320C64X_REG_INVALID) {
            tmp = caml_alloc(2, 0);
            Store_field(tmp, 0, Val_int(detail->condition.reg));
            Store_field(tmp, 1, Val_bool(detail->condition.zero));
            Store_field(op_info_val, 1, Val_some(tmp));
          } else {
            Store_field(op_info_val, 1, Val_none);
          }

          if (detail->funit.unit != TMS320C64X_FUNIT_NO &&
              detail->funit.unit != TMS320C64X_FUNIT_INVALID) {
            tmp = caml_alloc(3, 0);
            Store_field(tmp, 0, Val_int(detail->funit.unit));
            Store_field(tmp, 1, Val_int(detail->funit.side));
            // is crosspath meaningful if there is no unit?
            Store_field(tmp, 2, Val_bool(detail->funit.crosspath));
            Store_field(op_info_val, 2, Val_some(tmp));
          } else {
            Store_field(op_info_val, 2, Val_none);
          }
          Store_field(op_info_val, 3, Val_bool(detail->parallel));

          Store_field(rec_insn, 9, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      case CS_ARCH_X86: {
        INSN(x86, true, insn_group);
        if (insn[j - 1].detail) {
          cs_x86 *detail = &insn[j - 1].detail->x86;
          op_info_val = caml_alloc(22, 0);

          // detail.prefix
          Store_field(
              op_info_val, 0,
              detail->prefix[0] == 0
                  ? Val_none
                  : Val_some(Val_int(detail->prefix[0] - X86_PREFIX_LOCK)));

          // detail.segment_override
          switch (detail->prefix[1]) {
          case X86_PREFIX_CS:
            Store_field(op_info_val, 1, Val_some(Val_int(0)));
            break;
          case X86_PREFIX_SS:
            Store_field(op_info_val, 1, Val_some(Val_int(1)));
            break;
          case X86_PREFIX_DS:
            Store_field(op_info_val, 1, Val_some(Val_int(2)));
            break;
          case X86_PREFIX_ES:
            Store_field(op_info_val, 1, Val_some(Val_int(3)));
            break;
          case X86_PREFIX_FS:
            Store_field(op_info_val, 1, Val_some(Val_int(4)));
            break;
          case X86_PREFIX_GS:
            Store_field(op_info_val, 1, Val_some(Val_int(5)));
            break;
          default:
            Store_field(op_info_val, 1, Val_none);
            break;
          }

          // detail.op_size_override
          Store_field(op_info_val, 2,
                      Val_bool(detail->prefix[2] == X86_PREFIX_OPSIZE));

          // detail.addr_size_override
          Store_field(op_info_val, 3,
                      Val_bool(detail->prefix[3] == X86_PREFIX_ADDRSIZE));

          // detail.opcode
          Store_field(
              op_info_val, 4,
              caml_copy_uint8_array(detail->opcode, ARR_SIZE(detail->opcode)));

          // detail.rex
          Store_field(op_info_val, 5, Val_int(detail->rex));

          // detail.addr_size
          Store_field(op_info_val, 6, Val_int(detail->addr_size));

          // detail.modrm
          Store_field(op_info_val, 7, Val_int(detail->modrm));

          // detail.disp
          Store_field(op_info_val, 8,
                      detail->encoding.disp_offset != 0
                          ? Val_some(caml_copy_int64(detail->disp))
                          : Val_none);
          // detail.sib
          // detail.sib_index
          // detail.sib_scale
          // detail.sib_base
          if (detail->sib != 0) {
            Store_field(op_info_val, 9, Val_some(detail->sib));
            Store_field(op_info_val, 10, Val_some(Val_int(detail->sib_index)));
            Store_field(op_info_val, 11, Val_some(Val_int(detail->sib_scale)));
            Store_field(op_info_val, 12, Val_some(Val_int(detail->sib_base)));
          } else {
            Store_field(op_info_val, 9, Val_none);
            Store_field(op_info_val, 10, Val_none);
            Store_field(op_info_val, 11, Val_none);
            Store_field(op_info_val, 12, Val_none);
          }

          // detail.xop_cc
          Store_field(op_info_val, 13,
                      detail->xop_cc != X86_XOP_CC_INVALID
                          ? Val_some(Val_int(detail->xop_cc))
                          : Val_none);
          // detail.sse_cc
          Store_field(op_info_val, 14,
                      detail->sse_cc != X86_SSE_CC_INVALID
                          ? Val_some(Val_int(detail->sse_cc))
                          : Val_none);
          // detail.avx_cc
          Store_field(op_info_val, 15,
                      detail->avx_cc != X86_AVX_CC_INVALID
                          ? Val_some(Val_int(detail->avx_cc))
                          : Val_none);
          // detail.avx_sae
          Store_field(op_info_val, 16, Val_bool(detail->avx_sae));
          // detail.avx_rm
          Store_field(op_info_val, 17,
                      detail->avx_rm != X86_AVX_RM_INVALID
                          ? Val_some(Val_int(detail->avx_rm))
                          : Val_none);

          bool is_eflags = true;
          for (int grpn = 0; grpn < insn[j - 1].detail->groups_count; grpn++) {
            if (insn[j - 1].detail->groups[grpn] == X86_GRP_FPU) {
              Store_field(op_info_val, 18, Val_none);
              Store_field(op_info_val, 19,
                          detail->fpu_flags != 0
                              ? Val_some(caml_copy_int64(detail->fpu_flags))
                              : Val_none);
              is_eflags = false;
              break;
            }
          }
          if (is_eflags) {
            Store_field(op_info_val, 18,
                        detail->eflags != 0
                            ? Val_some(caml_copy_int64(detail->eflags))
                            : Val_none);
            Store_field(op_info_val, 19, Val_none);
          }

          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              switch (detail->operands[i].type) {
              case X86_OP_IMM:
                tmp = caml_alloc(1, 0);
                Store_field(tmp, 0, caml_copy_int64(detail->operands[i].imm));
                break;
              case X86_OP_MEM:
                tmp = caml_alloc(1, 1);
                tmp2 = caml_alloc(5, 0);
                // x86_op_mem.segment
                Store_field(
                    tmp2, 0,
                    detail->operands[i].mem.segment == X86_REG_INVALID
                        ? Val_none
                        : Val_some(Val_int(detail->operands[i].mem.segment)));
                // x86_op_mem.base
                Store_field(
                    tmp2, 1,
                    detail->operands[i].mem.base == X86_REG_INVALID
                        ? Val_none
                        : Val_some(Val_int(detail->operands[i].mem.base)));
                // x86_op_mem.index
                Store_field(
                    tmp2, 2,
                    detail->operands[i].mem.index == X86_REG_INVALID
                        ? Val_none
                        : Val_some(Val_int(detail->operands[i].mem.index)));
                // x86_op_mem.scale
                Store_field(
                    tmp2, 3,
                    detail->operands[i].mem.segment == X86_REG_INVALID
                        ? Val_none
                        : Val_some(Val_int(detail->operands[i].mem.scale)));
                // x86_op_mem.disp
                Store_field(tmp2, 4,
                            caml_copy_int64(detail->operands[i].mem.disp));
                Store_field(tmp, 0, tmp2);
                break;
              case X86_OP_REG:
                tmp = caml_alloc(1, 2);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              default:
                caml_failwith("x86: unknown operand type");
                break;
              }

              tmp2 = caml_alloc(5, 0);
              Store_field(tmp2, 0, tmp);
              Store_field(tmp2, 1, Val_int(detail->operands[i].size));
              Store_field(tmp2, 2,
                          ml_capstone_cs_ac_type(detail->operands[i].access));
              Store_field(tmp2, 3,
                          detail->operands[i].avx_bcast != X86_AVX_BCAST_INVALID
                              ? Val_some(Val_int(detail->operands[i].avx_bcast))
                              : Val_none);
              Store_field(tmp2, 4,
                          Val_int(detail->operands[i].avx_zero_opmask));

              Store_field(array, i, tmp2);
            }
          } else {
            array = Val_emptyarray;
          }
          Store_field(op_info_val, 20, array);

          tmp = caml_alloc(5, 0);
          Store_field(tmp, 0, Val_int(detail->encoding.modrm_offset));
          Store_field(tmp, 1, Val_int(detail->encoding.disp_offset));
          Store_field(tmp, 2, Val_int(detail->encoding.disp_size));
          Store_field(tmp, 3, Val_int(detail->encoding.imm_offset));
          Store_field(tmp, 4, Val_int(detail->encoding.imm_size));

          // detail.encoding
          Store_field(op_info_val, 21, tmp);

          Store_field(rec_insn, 9, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      case CS_ARCH_XCORE: {
        INSN(xcore, true, insn_group);
        if (insn[j - 1].detail) {
          cs_xcore *detail = &insn[j - 1].detail->xcore;
          op_info_val = caml_alloc(1, 0);

          if (detail->op_count > 0) {
            array = caml_alloc(detail->op_count, 0);
            for (i = 0; i < detail->op_count; i++) {
              switch (detail->operands[i].type) {
              case XCORE_OP_REG:
                tmp = caml_alloc(1, 0);
                Store_field(tmp, 0, Val_int(detail->operands[i].reg));
                break;
              case XCORE_OP_IMM:
                tmp = caml_alloc(1, 1);
                Store_field(tmp, 0, caml_copy_int32(detail->operands[i].imm));
                break;
              case XCORE_OP_MEM:
                tmp = caml_alloc(1, 2);
                tmp2 = caml_alloc(4, 0);
                Store_field(
                    tmp2, 0,
                    detail->operands[i].mem.base != XCORE_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.base))
                        : Val_none);
                Store_field(
                    tmp2, 1,
                    detail->operands[i].mem.index != XCORE_REG_INVALID
                        ? Val_some(Val_int(detail->operands[i].mem.index))
                        : Val_none);
                Store_field(tmp2, 2,
                            caml_copy_int32(detail->operands[i].mem.disp));
                Store_field(tmp2, 3, Val_int(detail->operands[i].mem.direct));
                Store_field(tmp, 0, tmp2);
                break;
              default:
                caml_failwith("xcore: unknown operand type");
                break;
              }
              Store_field(array, i, tmp);
            }
          } else {
            array = Val_emptyarray;
          }

          Store_field(op_info_val, 0, array);
          Store_field(rec_insn, 9, Val_some(op_info_val));
        } else {
          Store_field(rec_insn, 9, Val_none);
        }
        break;
      }
      default:
        caml_failwith("capstone: unsupported architecture");
        break;
      }

      Store_field(cons, 0, rec_insn);
      Store_field(cons, 1, list);
      list = cons;
    }
    cs_free(insn, c);
  }
  CAMLreturn(list);
}

CAMLprim value ml_capstone_disassemble(value _arch, value _handle, value _code,
                                       value _addr, value _count) {
  CAMLparam5(_arch, _handle, _code, _addr, _count);
  csh handle;
  cs_arch arch;
  const uint8_t *code;
  uint64_t addr, count, code_len;

  handle = *Capstone_handle_val(_handle);
  arch = Int_val(_arch);
  code = Bytes_val(_code);
  code_len = caml_string_length(_code);
  addr = Int64_val(_addr);
  count = Int64_val(_count);

  CAMLreturn(
      ml_capstone_disassemble_inner(arch, handle, code, code_len, addr, count));
}

CAMLprim value ml_capstone_version(void) {
  CAMLparam0();
  CAMLreturn(Val_int(cs_version(NULL, NULL)));
}
