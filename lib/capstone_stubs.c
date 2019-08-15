/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>		// debug
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>

#include <capstone/capstone.h>

#include "arm_const_stubs.h"
#include "arm64_const_stubs.h"
#include "mips_const_stubs.h"
#include "ppc_const_stubs.h"
#include "sparc_const_stubs.h"
#include "sysz_const_stubs.h"
#include "x86_const_stubs.h"
#include "xcore_const_stubs.h"

#include "cs_const_stubs.h"
#include "capstone_poly_var_syms.h"

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
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

static value ml_capstone_alloc_handle(const csh *handle) {
  CAMLparam0();
  CAMLlocal1(h);
  h = caml_alloc_custom(&ml_capstone_handle_custom_ops, sizeof(*handle), 0, 1);
  memcpy(Capstone_handle_val(h), handle, sizeof(*handle));
  CAMLreturn(h);
}

// count the number of positive members in @list
static unsigned int list_count(uint8_t *list, unsigned int max)
{
	unsigned int i;

	for(i = 0; i < max; i++)
		if (list[i] == 0)
			return i;

	return max;
}

CAMLprim value ml_capstone_create(value _arch, value _mode)
{
	CAMLparam2(_arch, _mode);
	CAMLlocal2(head, result);
	csh handle;
	cs_arch arch;
	cs_mode mode = 0;

  arch = ml_cs_arch_to_capstone(_arch);

  while (_mode != Val_emptylist) {
    head = Field(_mode, 0);
    mode |= ml_cs_mode_to_capstone(head);
    _mode = Field(_mode, 1);
  }

	if (cs_open(arch, mode, &handle) != 0) {
    CAMLreturn(Val_int(0)); // None
  }

	result = caml_alloc(1, 0);
	Store_field(result, 0, ml_capstone_alloc_handle(&handle)); // Some handle 
	CAMLreturn(result);
}

CAMLprim value ml_capstone_set_option(value _handle, value _opt, value _val)
{
	CAMLparam3(_handle, _opt, _val);

  cs_opt_type opt = ml_cs_opt_type_to_capstone(_opt);
  int val = (opt == CS_OPT_MODE) ? ml_cs_mode_to_capstone(_val) : ml_cs_opt_value_to_capstone(_val);
  int err = cs_option(*Capstone_handle_val(_handle), opt, val);

  if (err != CS_ERR_OK) {
    caml_raise_with_arg(*caml_named_value("Capstone_error"), ml_cs_err_to_capstone(err));
  }

	CAMLreturn(Val_unit);
}

CAMLprim value ml_capstone_disassemble_inner(cs_arch arch, csh handle, const uint8_t * code, size_t code_len, uint64_t addr, size_t count)
{
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

#define INSN(LOWER_PREFIX, TAG) \
			rec_insn = caml_alloc(10, TAG); \
			Store_field(rec_insn, 0, ml_capstone_to_##LOWER_PREFIX##_insn(insn[j-1].id)); \
			Store_field(rec_insn, 1, Val_int(insn[j-1].address)); \
			Store_field(rec_insn, 2, Val_int(insn[j-1].size)); \
      tmp = caml_alloc_string(insn[j-1].size); \
      memcpy(String_val(tmp), insn[j-1].bytes, insn[j-1].size); \
			Store_field(rec_insn, 3, tmp);  \
			Store_field(rec_insn, 4, caml_copy_string(insn[j-1].mnemonic)); \
			Store_field(rec_insn, 5, caml_copy_string(insn[j-1].op_str)); \
			if (insn[0].detail) { \
				lcount = (insn[j-1]).detail->regs_read_count; \
				if (lcount) { \
					array = caml_alloc(lcount, 0); \
					for (i = 0; i < lcount; i++) { \
						Store_field(array, i, ml_capstone_to_##LOWER_PREFIX##_reg(insn[j-1].detail->regs_read[i])); \
					} \
				} else \
					array = Atom(0); \
			} else \
				array = Atom(0); \
			Store_field(rec_insn, 6, array); \
			if (insn[0].detail) { \
				lcount = (insn[j-1]).detail->regs_write_count; \
				if (lcount) { \
					array = caml_alloc(lcount, 0); \
					for (i = 0; i < lcount; i++) { \
            Store_field(array, i, ml_capstone_to_##LOWER_PREFIX##_reg(insn[j-1].detail->regs_write[i])); \
					} \
				} else \
					array = Atom(0); \
			} else \
				array = Atom(0); \
			Store_field(rec_insn, 7, array); \
			if (insn[0].detail) { \
				lcount = (insn[j-1]).detail->groups_count; \
				if (lcount) { \
					array = caml_alloc(lcount, 0); \
					for (i = 0; i < lcount; i++) { \
						Store_field(array, i, Val_int(insn[j-1].detail->groups[i])); \
					} \
				} else \
					array = Atom(0); \
			} else \
				array = Atom(0); \
			Store_field(rec_insn, 8, array);

      switch(arch) {
      case CS_ARCH_ARM: {
        INSN(arm, 0)
        if (insn[j-1].detail) {
          detail_opt = caml_alloc(1, 0); // Some
          op_info_val = caml_alloc(10, 0);
          Store_field(op_info_val, 0, Val_bool(insn[j-1].detail->arm.usermode));
          Store_field(op_info_val, 1, Val_int(insn[j-1].detail->arm.vector_size));
          Store_field(op_info_val, 2, Val_int(insn[j-1].detail->arm.vector_data));
          Store_field(op_info_val, 3, Val_int(insn[j-1].detail->arm.cps_mode));
          Store_field(op_info_val, 4, Val_int(insn[j-1].detail->arm.cps_flag));
          Store_field(op_info_val, 5, Val_int(insn[j-1].detail->arm.cc));
          Store_field(op_info_val, 6, Val_bool(insn[j-1].detail->arm.update_flags));
          Store_field(op_info_val, 7, Val_bool(insn[j-1].detail->arm.writeback));
          Store_field(op_info_val, 8, Val_int(insn[j-1].detail->arm.mem_barrier));

          lcount = insn[j-1].detail->arm.op_count;
          if (lcount > 0) {
            array = caml_alloc(lcount, 0);
            for (i = 0; i < lcount; i++) {
              tmp2 = caml_alloc(4, 0);
              switch(insn[j-1].detail->arm.operands[i].type) {
                case ARM_OP_REG:
                case ARM_OP_SYSREG:
                  tmp = caml_alloc(1, 1);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm.operands[i].reg));
                  break;
                case ARM_OP_CIMM:
                  tmp = caml_alloc(1, 2);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm.operands[i].imm));
                  break;
                case ARM_OP_PIMM:
                  tmp = caml_alloc(1, 3);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm.operands[i].imm));
                  break;
                case ARM_OP_IMM:
                  tmp = caml_alloc(1, 4);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm.operands[i].imm));
                  break;
                case ARM_OP_FP:
                  tmp = caml_alloc(1, 5);
                  Store_field(tmp, 0, caml_copy_double(insn[j-1].detail->arm.operands[i].fp));
                  break;
                case ARM_OP_MEM:
                  tmp = caml_alloc(1, 6);
                  tmp3 = caml_alloc(4, 0);
                  Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm.operands[i].mem.base));
                  Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm.operands[i].mem.index));
                  Store_field(tmp3, 2, Val_int(insn[j-1].detail->arm.operands[i].mem.scale));
                  Store_field(tmp3, 3, Val_int(insn[j-1].detail->arm.operands[i].mem.disp));
                  Store_field(tmp, 0, tmp3);
                  break;
                case ARM_OP_SETEND:
                  tmp = caml_alloc(1, 7);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm.operands[i].setend));
                  break;
                default: break;
              }
              tmp3 = caml_alloc(2, 0);
              Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm.operands[i].shift.type));
              Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm.operands[i].shift.value));
              Store_field(tmp2, 0, Val_int(insn[j-1].detail->arm.operands[i].vector_index));
              Store_field(tmp2, 1, tmp3);
              Store_field(tmp2, 2, tmp);
              Store_field(tmp2, 3, Val_bool(insn[j-1].detail->arm.operands[i].subtracted));
              Store_field(array, i, tmp2);
            }
          } else	// empty list
            array = Atom(0);

          Store_field(op_info_val, 9, array);

          Store_field(detail_opt, 0, op_info_val);
          Store_field(rec_insn, 9, detail_opt);
        } else {
          Store_field(rec_insn, 9, Val_int(0)); // None
        }
        break;
      }
      case CS_ARCH_ARM64: {
        INSN(arm64, 0)
        if (insn[j-1].detail) {
          detail_opt = caml_alloc(1, 0); // Some
          op_info_val = caml_alloc(4, 0);
          Store_field(op_info_val, 0, Val_int(insn[j-1].detail->arm64.cc));
          Store_field(op_info_val, 1, Val_bool(insn[j-1].detail->arm64.update_flags));
          Store_field(op_info_val, 2, Val_bool(insn[j-1].detail->arm64.writeback));

          lcount = insn[j-1].detail->arm64.op_count;
          if (lcount > 0) {
            array = caml_alloc(lcount, 0);
            for (i = 0; i < lcount; i++) {
              tmp2 = caml_alloc(6, 0);
              switch(insn[j-1].detail->arm64.operands[i].type) {
                case ARM64_OP_REG:
                  tmp = caml_alloc(1, 1);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].reg));
                  break;
                case ARM64_OP_CIMM:
                  tmp = caml_alloc(1, 2);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].imm));
                  break;
                case ARM64_OP_IMM:
                  tmp = caml_alloc(1, 3);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].imm));
                  break;
                case ARM64_OP_FP:
                  tmp = caml_alloc(1, 4);
                  Store_field(tmp, 0, caml_copy_double(insn[j-1].detail->arm64.operands[i].fp));
                  break;
                case ARM64_OP_MEM:
                  tmp = caml_alloc(1, 5);
                  tmp3 = caml_alloc(3, 0);
                  Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm64.operands[i].mem.base));
                  Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm64.operands[i].mem.index));
                  Store_field(tmp3, 2, Val_int(insn[j-1].detail->arm64.operands[i].mem.disp));
                  Store_field(tmp, 0, tmp3);
                  break;
                case ARM64_OP_REG_MRS:
                  tmp = caml_alloc(1, 6);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].reg));
                  break;
                case ARM64_OP_REG_MSR:
                  tmp = caml_alloc(1, 7);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].reg));
                  break;
                case ARM64_OP_PSTATE:
                  tmp = caml_alloc(1, 8);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].pstate));
                  break;
                case ARM64_OP_SYS:
                  tmp = caml_alloc(1, 9);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].sys));
                  break;
                case ARM64_OP_PREFETCH:
                  tmp = caml_alloc(1, 10);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].prefetch));
                  break;
                case ARM64_OP_BARRIER:
                  tmp = caml_alloc(1, 11);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->arm64.operands[i].barrier));
                  break;
                default: break;
              }
              tmp3 = caml_alloc(2, 0);
              Store_field(tmp3, 0, Val_int(insn[j-1].detail->arm64.operands[i].shift.type));
              Store_field(tmp3, 1, Val_int(insn[j-1].detail->arm64.operands[i].shift.value));

              Store_field(tmp2, 0, Val_int(insn[j-1].detail->arm64.operands[i].vector_index));
              Store_field(tmp2, 1, Val_int(insn[j-1].detail->arm64.operands[i].vas));
              Store_field(tmp2, 2, Val_int(insn[j-1].detail->arm64.operands[i].vess));
              Store_field(tmp2, 3, tmp3);
              Store_field(tmp2, 4, Val_int(insn[j-1].detail->arm64.operands[i].ext));
              Store_field(tmp2, 5, tmp);

              Store_field(array, i, tmp2);
            }
          } else	// empty array
            array = Atom(0);

          Store_field(op_info_val, 3, array);

          Store_field(detail_opt, 0, op_info_val);
          Store_field(rec_insn, 9, detail_opt);
        } else {
          Store_field(rec_insn, 9, Val_int(0)); // None
        }
        break;
      }
      case CS_ARCH_MIPS: {
        INSN(mips, 0)
        if (insn[j-1].detail) {
          detail_opt = caml_alloc(1, 0); // Some
          op_info_val = caml_alloc(1, 0);

          lcount = insn[j-1].detail->mips.op_count;
          if (lcount > 0) {
            array = caml_alloc(lcount, 0);
            for (i = 0; i < lcount; i++) {
              tmp2 = caml_alloc(1, 0);
              switch(insn[j-1].detail->mips.operands[i].type) {
              case MIPS_OP_REG:
                tmp = caml_alloc(1, 1);
                Store_field(tmp, 0, Val_int(insn[j-1].detail->mips.operands[i].reg));
                break;
              case MIPS_OP_IMM:
                tmp = caml_alloc(1, 2);
                Store_field(tmp, 0, Val_int(insn[j-1].detail->mips.operands[i].imm));
                break;
              case MIPS_OP_MEM:
                tmp = caml_alloc(1, 3);
                tmp3 = caml_alloc(2, 0);
                Store_field(tmp3, 0, Val_int(insn[j-1].detail->mips.operands[i].mem.base));
                Store_field(tmp3, 1, Val_int(insn[j-1].detail->mips.operands[i].mem.disp));
                Store_field(tmp, 0, tmp3);
                break;
              default: break;
              }
              Store_field(tmp2, 0, tmp);
              Store_field(array, i, tmp2);
            }
          } else	// empty array
            array = Atom(0);

          Store_field(op_info_val, 0, array);

          Store_field(detail_opt, 0, op_info_val);
          Store_field(rec_insn, 9, detail_opt);
        } else {
          Store_field(rec_insn, 9, Val_int(0)); // None
        }
        break;
      }
      case CS_ARCH_PPC: {
        INSN(ppc, 0)
        if (insn[j-1].detail) {
          detail_opt = caml_alloc(1, 0); // Some
          op_info_val = caml_alloc(4, 0);

          Store_field(op_info_val, 0, Val_int(insn[j-1].detail->ppc.bc));
          Store_field(op_info_val, 1, Val_int(insn[j-1].detail->ppc.bh));
          Store_field(op_info_val, 2, Val_bool(insn[j-1].detail->ppc.update_cr0));

          lcount = insn[j-1].detail->ppc.op_count;
          if (lcount > 0) {
            array = caml_alloc(lcount, 0);
            for (i = 0; i < lcount; i++) {
              tmp2 = caml_alloc(1, 0);
              switch(insn[j-1].detail->ppc.operands[i].type) {
                case PPC_OP_REG:
                  tmp = caml_alloc(1, 1);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->ppc.operands[i].reg));
                  break;
                case PPC_OP_IMM:
                  tmp = caml_alloc(1, 2);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->ppc.operands[i].imm));
                  break;
                case PPC_OP_MEM:
                  tmp = caml_alloc(1, 3);
                  tmp3 = caml_alloc(2, 0);
                  Store_field(tmp3, 0, Val_int(insn[j-1].detail->ppc.operands[i].mem.base));
                  Store_field(tmp3, 1, Val_int(insn[j-1].detail->ppc.operands[i].mem.disp));
                  Store_field(tmp, 0, tmp3);
                  break;
                case PPC_OP_CRX:
                  tmp = caml_alloc(1, 4);
                  tmp3 = caml_alloc(3, 0);
                  Store_field(tmp3, 0, Val_int(insn[j-1].detail->ppc.operands[i].crx.scale));
                  Store_field(tmp3, 1, Val_int(insn[j-1].detail->ppc.operands[i].crx.reg));
                  Store_field(tmp3, 2, Val_int(insn[j-1].detail->ppc.operands[i].crx.cond));
                  Store_field(tmp, 0, tmp3);
                  break;
                default: break;
              }
              Store_field(tmp2, 0, tmp);
              Store_field(array, i, tmp2);
            }
          } else	// empty array
            array = Atom(0);

          Store_field(op_info_val, 3, array);

          Store_field(detail_opt, 0, op_info_val);
          Store_field(rec_insn, 9, detail_opt);
        } else {
          Store_field(rec_insn, 9, Val_int(0)); // None
        }
        break;
      }
      case CS_ARCH_SPARC: {
        INSN(sparc, 0)
        if (insn[j-1].detail) {
          detail_opt = caml_alloc(1, 0); // Some
          op_info_val = caml_alloc(3, 0);

          Store_field(op_info_val, 0, Val_int(insn[j-1].detail->sparc.cc));
          Store_field(op_info_val, 1, Val_int(insn[j-1].detail->sparc.hint));

          lcount = insn[j-1].detail->sparc.op_count;
          if (lcount > 0) {
            array = caml_alloc(lcount, 0);
            for (i = 0; i < lcount; i++) {
              tmp2 = caml_alloc(1, 0);
              switch(insn[j-1].detail->sparc.operands[i].type) {
                case SPARC_OP_REG:
                  tmp = caml_alloc(1, 1);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->sparc.operands[i].reg));
                  break;
                case SPARC_OP_IMM:
                  tmp = caml_alloc(1, 2);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->sparc.operands[i].imm));
                  break;
                case SPARC_OP_MEM:
                  tmp = caml_alloc(1, 3);
                  tmp3 = caml_alloc(3, 0);
                  Store_field(tmp3, 0, Val_int(insn[j-1].detail->sparc.operands[i].mem.base));
                  Store_field(tmp3, 1, Val_int(insn[j-1].detail->sparc.operands[i].mem.index));
                  Store_field(tmp3, 2, Val_int(insn[j-1].detail->sparc.operands[i].mem.disp));
                  Store_field(tmp, 0, tmp3);
                  break;
                default: break;
              }
              Store_field(tmp2, 0, tmp);
              Store_field(array, i, tmp2);
            }
          } else	// empty array
            array = Atom(0);

          Store_field(op_info_val, 2, array);

          Store_field(detail_opt, 0, op_info_val);
          Store_field(rec_insn, 9, detail_opt);
        } else {
          Store_field(rec_insn, 9, Val_int(0)); // None
        }
        break;
      }
      case CS_ARCH_SYSZ: {
        INSN(sysz, 0)
        if (insn[j-1].detail) {
          detail_opt = caml_alloc(1, 0); // Some
          op_info_val = caml_alloc(2, 0);

          Store_field(op_info_val, 0, Val_int(insn[j-1].detail->sysz.cc));

          lcount = insn[j-1].detail->sysz.op_count;
          if (lcount > 0) {
            array = caml_alloc(lcount, 0);
            for (i = 0; i < lcount; i++) {
              tmp2 = caml_alloc(1, 0);
              switch(insn[j-1].detail->sysz.operands[i].type) {
                case SYSZ_OP_REG:
                  tmp = caml_alloc(1, 1);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->sysz.operands[i].reg));
                  break;
                case SYSZ_OP_ACREG:
                  tmp = caml_alloc(1, 2);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->sysz.operands[i].reg));
                  break;
                case SYSZ_OP_IMM:
                  tmp = caml_alloc(1, 3);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->sysz.operands[i].imm));
                  break;
                case SYSZ_OP_MEM:
                  tmp = caml_alloc(1, 4);
                  tmp3 = caml_alloc(4, 0);
                  Store_field(tmp3, 0, Val_int(insn[j-1].detail->sysz.operands[i].mem.base));
                  Store_field(tmp3, 1, Val_int(insn[j-1].detail->sysz.operands[i].mem.index));
                  Store_field(tmp3, 2, caml_copy_int64(insn[j-1].detail->sysz.operands[i].mem.length));
                  Store_field(tmp3, 3, caml_copy_int64(insn[j-1].detail->sysz.operands[i].mem.disp));
                  Store_field(tmp, 0, tmp3);
                  break;
                default: break;
              }
              Store_field(tmp2, 0, tmp);
              Store_field(array, i, tmp2);
            }
          } else	// empty array
            array = Atom(0);

          Store_field(op_info_val, 1, array);

          Store_field(detail_opt, 0, op_info_val);
          Store_field(rec_insn, 9, detail_opt);
        } else {
          Store_field(rec_insn, 9, Val_int(0)); // None
        }
        break;
      }
      case CS_ARCH_X86: {
        INSN(x86, 0)
        if (insn[j-1].detail) {
          detail_opt = caml_alloc(1, 0); // Some
          op_info_val = caml_alloc(15, 0);

          // fill prefix
          lcount = list_count(insn[j-1].detail->x86.prefix, ARR_SIZE(insn[j-1].detail->x86.prefix));
          if (lcount) {
            array = caml_alloc(lcount, 0);
            for (i = 0; i < lcount; i++) {
              Store_field(array, i, Val_int(insn[j-1].detail->x86.prefix[i]));
            }
          } else
            array = Atom(0);
          Store_field(op_info_val, 0, array);

          // fill opcode
          lcount = list_count(insn[j-1].detail->x86.opcode, ARR_SIZE(insn[j-1].detail->x86.opcode));
          if (lcount) {
            array = caml_alloc(lcount, 0);
            for (i = 0; i < lcount; i++) {
              Store_field(array, i, Val_int(insn[j-1].detail->x86.opcode[i]));
            }
          } else
            array = Atom(0);
          Store_field(op_info_val, 1, array);

          Store_field(op_info_val, 2, Val_int(insn[j-1].detail->x86.rex));

          Store_field(op_info_val, 3, Val_int(insn[j-1].detail->x86.addr_size));

          Store_field(op_info_val, 4, Val_int(insn[j-1].detail->x86.modrm));

          Store_field(op_info_val, 5, Val_int(insn[j-1].detail->x86.sib));

          Store_field(op_info_val, 6, Val_int(insn[j-1].detail->x86.disp));

          Store_field(op_info_val, 7, Val_int(insn[j-1].detail->x86.sib_index));

          Store_field(op_info_val, 8, Val_int(insn[j-1].detail->x86.sib_scale));

          Store_field(op_info_val, 9, ml_capstone_to_x86_reg(insn[j-1].detail->x86.sib_base));

          Store_field(op_info_val, 10, Val_int(insn[j-1].detail->x86.sse_cc));
          Store_field(op_info_val, 11, Val_int(insn[j-1].detail->x86.avx_cc));
          Store_field(op_info_val, 12, Val_int(insn[j-1].detail->x86.avx_sae));
          Store_field(op_info_val, 13, Val_int(insn[j-1].detail->x86.avx_rm));

          lcount = insn[j-1].detail->x86.op_count;
          if (lcount > 0) {
            array = caml_alloc(lcount, 0);
            for (i = 0; i < lcount; i++) {
              switch(insn[j-1].detail->x86.operands[i].type) {
                case X86_OP_REG:
                  tmp = ml_capstone_to_x86_reg(insn[j-1].detail->x86.operands[i].reg);
                  break;
                case X86_OP_IMM:
                  tmp = caml_alloc(2, 0);
                  Store_field(tmp, 0, caml_hash_variant("IMM"));
                  Store_field(tmp, 1, caml_copy_int64(insn[j-1].detail->x86.operands[i].imm));
                  break;
                case X86_OP_MEM:
                  tmp = caml_alloc(2, 0);
                  tmp2 = caml_alloc(5, 0);
                  Store_field(tmp2, 0, ml_capstone_to_x86_reg(insn[j-1].detail->x86.operands[i].mem.segment));
                  Store_field(tmp2, 1, ml_capstone_to_x86_reg(insn[j-1].detail->x86.operands[i].mem.base));
                  Store_field(tmp2, 2, ml_capstone_to_x86_reg(insn[j-1].detail->x86.operands[i].mem.index));
                  Store_field(tmp2, 3, Val_int(insn[j-1].detail->x86.operands[i].mem.scale));
                  Store_field(tmp2, 4, caml_copy_int64(insn[j-1].detail->x86.operands[i].mem.disp));

                  Store_field(tmp, 0, caml_hash_variant("MEM"));
                  Store_field(tmp, 1, tmp2);
                  break;
                default:
                  tmp = caml_hash_variant("INVALID");
              }

              tmp2 = caml_alloc(4, 0);
              Store_field(tmp2, 0, tmp);
              Store_field(tmp2, 1, Val_int(insn[j-1].detail->x86.operands[i].size));
              Store_field(tmp2, 2, ml_capstone_to_x86_avx_bcast(insn[j-1].detail->x86.operands[i].avx_bcast));
              Store_field(tmp2, 3, Val_int(insn[j-1].detail->x86.operands[i].avx_zero_opmask));

              Store_field(array, i, tmp2);
            }
          } else	// empty array
            array = Atom(0);
          Store_field(op_info_val, 14, array);

          Store_field(detail_opt, 0, op_info_val);
          Store_field(rec_insn, 9, detail_opt);
        } else {
          Store_field(rec_insn, 9, Val_int(0)); // None
        }
        break;
      }
      case CS_ARCH_XCORE: {
        INSN(xcore, 0)
        if (insn[j-1].detail) {
          detail_opt = caml_alloc(1, 0); // Some
          op_info_val = caml_alloc(1, 0);

          lcount = insn[j-1].detail->xcore.op_count;
          if (lcount > 0) {
            array = caml_alloc(lcount, 0);
            for (i = 0; i < lcount; i++) {
              tmp2 = caml_alloc(1, 0);
              switch(insn[j-1].detail->xcore.operands[i].type) {
                case XCORE_OP_REG:
                  tmp = caml_alloc(1, 1);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->xcore.operands[i].reg));
                  break;
                case XCORE_OP_IMM:
                  tmp = caml_alloc(1, 2);
                  Store_field(tmp, 0, Val_int(insn[j-1].detail->xcore.operands[i].imm));
                  break;
                case XCORE_OP_MEM:
                  tmp = caml_alloc(1, 3);
                  tmp3 = caml_alloc(4, 0);
                  Store_field(tmp3, 0, Val_int(insn[j-1].detail->xcore.operands[i].mem.base));
                  Store_field(tmp3, 1, Val_int(insn[j-1].detail->xcore.operands[i].mem.index));
                  Store_field(tmp3, 2, caml_copy_int64(insn[j-1].detail->xcore.operands[i].mem.disp));
                  Store_field(tmp3, 3, caml_copy_int64(insn[j-1].detail->xcore.operands[i].mem.direct));
                  Store_field(tmp, 0, tmp3);
                  break;
                default: break;
              }
              Store_field(tmp2, 0, tmp);
              Store_field(array, i, tmp2);
            }
          } else	// empty array
            array = Atom(0);

          Store_field(op_info_val, 0, array);

          Store_field(detail_opt, 0, op_info_val);
          Store_field(rec_insn, 9, detail_opt);
        } else {
          Store_field(rec_insn, 9, Val_int(0)); // None
        }
        break;
      }
      default:
        caml_invalid_argument("impossible architecture");
      }

			Store_field(cons, 0, rec_insn);	// head
			Store_field(cons, 1, list);		// tail
			list = cons;
		}
		cs_free(insn, c);
	}

	CAMLreturn(list);
}

CAMLprim value ml_capstone_disassemble(value _arch, value _handle, value _code, value _addr, value _count)
{
	CAMLparam5(_arch, _handle, _code, _addr, _count);
	csh handle;
	cs_arch arch;
	const uint8_t *code;
	uint64_t addr, count, code_len;

	handle = *Capstone_handle_val(_handle);
  arch = ml_cs_arch_to_capstone(_arch);
	code = (uint8_t *)String_val(_code);
	code_len = caml_string_length(_code);
	addr = Int64_val(_addr);
	count = Int64_val(_count);

	CAMLreturn(ml_capstone_disassemble_inner(arch, handle, code, code_len, addr, count));
}


CAMLprim value ml_capstone_version(void)
{
	CAMLparam0();
	CAMLreturn(Val_int(cs_version(NULL, NULL)));
}
