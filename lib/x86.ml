module Const = struct
  module AvxBcast = X86_const.AvxBcast
  module AvxCc = X86_const.AvxCc
  module AvxRm = X86_const.AvxRm
  module Insn = X86_const.Insn
  module InsnGroup = X86_const.InsnGroup
  module OpType = X86_const.OpType
  module Reg = X86_const.Reg
  module SseCc = X86_const.SseCc
  module XopCc = X86_const.XopCc

  module Prefix = struct
    type t = private int
    type id = [ `LOCK
              | `REP
              | `REPE
              | `REPNE
              ]

    external of_id : id -> t = "ml_x86_prefix_to_capstone_int"
    external to_id : t -> id = "ml_int_capstone_to_x86_prefix"

    let lock = of_id `LOCK
    let rep = of_id `REP
    let repe = of_id `REP
    let repne = of_id `REPNE
  end

  module SegmentReg = struct
    type t = private int
    type id = [ `CS
              | `DS
              | `ES
              | `FS
              | `GS
              | `SS
              ]

    external of_id : id -> t = "ml_x86_prefix_to_capstone_int"
    external to_id : t -> id = "ml_int_capstone_to_x86_prefix"

    let cs = of_id `CS
    let ds = of_id `DS
    let es = of_id `ES
    let fs = of_id `FS
    let gs = of_id `GS
    let ss = of_id `SS
  end

  module EFlags = struct
    type t = private int
    type id = [ `MODIFY_AF
              | `MODIFY_CF
              | `MODIFY_SF
              | `MODIFY_ZF
              | `MODIFY_PF
              | `MODIFY_OF
              | `MODIFY_TF
              | `MODIFY_IF
              | `MODIFY_DF
              | `MODIFY_NT
              | `MODIFY_RF
              | `PRIOR_OF
              | `PRIOR_SF
              | `PRIOR_ZF
              | `PRIOR_AF
              | `PRIOR_PF
              | `PRIOR_CF
              | `PRIOR_TF
              | `PRIOR_IF
              | `PRIOR_DF
              | `PRIOR_NT
              | `RESET_OF
              | `RESET_CF
              | `RESET_DF
              | `RESET_IF
              | `RESET_SF
              | `RESET_AF
              | `RESET_TF
              | `RESET_NT
              | `RESET_PF
              | `SET_CF
              | `SET_DF
              | `SET_IF
              | `TEST_OF
              | `TEST_SF
              | `TEST_ZF
              | `TEST_PF
              | `TEST_CF
              | `TEST_NT
              | `TEST_DF
              | `UNDEFINED_OF
              | `UNDEFINED_SF
              | `UNDEFINED_ZF
              | `UNDEFINED_PF
              | `UNDEFINED_AF
              | `UNDEFINED_CF
              | `RESET_RF
              | `TEST_RF
              | `TEST_IF
              | `TEST_TF
              | `TEST_AF
              | `RESET_ZF
              | `SET_OF
              | `SET_SF
              | `SET_ZF
              | `SET_AF
              | `SET_PF
              | `RESET_0F
              | `RESET_AC ]

    let of_id = function
      | `MODIFY_AF -> Int64.shift_left 1L 0
      | `MODIFY_CF -> Int64.shift_left 1L 1
      | `MODIFY_SF -> Int64.shift_left 1L 2
      | `MODIFY_ZF -> Int64.shift_left 1L 3
      | `MODIFY_PF -> Int64.shift_left 1L 4
      | `MODIFY_OF -> Int64.shift_left 1L 5
      | `MODIFY_TF -> Int64.shift_left 1L 6
      | `MODIFY_IF -> Int64.shift_left 1L 7
      | `MODIFY_DF -> Int64.shift_left 1L 8
      | `MODIFY_NT -> Int64.shift_left 1L 9
      | `MODIFY_RF -> Int64.shift_left 1L 10
      | `PRIOR_OF -> Int64.shift_left 1L 11
      | `PRIOR_SF -> Int64.shift_left 1L 12
      | `PRIOR_ZF -> Int64.shift_left 1L 13
      | `PRIOR_AF -> Int64.shift_left 1L 14
      | `PRIOR_PF -> Int64.shift_left 1L 15
      | `PRIOR_CF -> Int64.shift_left 1L 16
      | `PRIOR_TF -> Int64.shift_left 1L 17
      | `PRIOR_IF -> Int64.shift_left 1L 18
      | `PRIOR_DF -> Int64.shift_left 1L 19
      | `PRIOR_NT -> Int64.shift_left 1L 20
      | `RESET_OF -> Int64.shift_left 1L 21
      | `RESET_CF -> Int64.shift_left 1L 22
      | `RESET_DF -> Int64.shift_left 1L 23
      | `RESET_IF -> Int64.shift_left 1L 24
      | `RESET_SF -> Int64.shift_left 1L 25
      | `RESET_AF -> Int64.shift_left 1L 26
      | `RESET_TF -> Int64.shift_left 1L 27
      | `RESET_NT -> Int64.shift_left 1L 28
      | `RESET_PF -> Int64.shift_left 1L 29
      | `SET_CF -> Int64.shift_left 1L 30
      | `SET_DF -> Int64.shift_left 1L 31
      | `SET_IF -> Int64.shift_left 1L 32
      | `TEST_OF -> Int64.shift_left 1L 33
      | `TEST_SF -> Int64.shift_left 1L 34
      | `TEST_ZF -> Int64.shift_left 1L 35
      | `TEST_PF -> Int64.shift_left 1L 36
      | `TEST_CF -> Int64.shift_left 1L 37
      | `TEST_NT -> Int64.shift_left 1L 38
      | `TEST_DF -> Int64.shift_left 1L 39
      | `UNDEFINED_OF -> Int64.shift_left 1L 40
      | `UNDEFINED_SF -> Int64.shift_left 1L 41
      | `UNDEFINED_ZF -> Int64.shift_left 1L 42
      | `UNDEFINED_PF -> Int64.shift_left 1L 43
      | `UNDEFINED_AF -> Int64.shift_left 1L 44
      | `UNDEFINED_CF -> Int64.shift_left 1L 45
      | `RESET_RF -> Int64.shift_left 1L 46
      | `TEST_RF -> Int64.shift_left 1L 47
      | `TEST_IF -> Int64.shift_left 1L 48
      | `TEST_TF -> Int64.shift_left 1L 49
      | `TEST_AF -> Int64.shift_left 1L 50
      | `RESET_ZF -> Int64.shift_left 1L 51
      | `SET_OF -> Int64.shift_left 1L 52
      | `SET_SF -> Int64.shift_left 1L 53
      | `SET_ZF -> Int64.shift_left 1L 54
      | `SET_AF -> Int64.shift_left 1L 55
      | `SET_PF -> Int64.shift_left 1L 56
      | `RESET_0F -> Int64.shift_left 1L 57
      | `RESET_AC -> Int64.shift_left 1L 58

    let modify_af = of_id `MODIFY_AF
    let modify_cf = of_id `MODIFY_CF
    let modify_sf = of_id `MODIFY_SF
    let modify_zf = of_id `MODIFY_ZF
    let modify_pf = of_id `MODIFY_PF
    let modify_of = of_id `MODIFY_OF
    let modify_tf = of_id `MODIFY_TF
    let modify_if = of_id `MODIFY_IF
    let modify_df = of_id `MODIFY_DF
    let modify_nt = of_id `MODIFY_NT
    let modify_rf = of_id `MODIFY_RF
    let prior_of = of_id `PRIOR_OF
    let prior_sf = of_id `PRIOR_SF
    let prior_zf = of_id `PRIOR_ZF
    let prior_af = of_id `PRIOR_AF
    let prior_pf = of_id `PRIOR_PF
    let prior_cf = of_id `PRIOR_CF
    let prior_tf = of_id `PRIOR_TF
    let prior_if = of_id `PRIOR_IF
    let prior_df = of_id `PRIOR_DF
    let prior_nt = of_id `PRIOR_NT
    let reset_of = of_id `RESET_OF
    let reset_cf = of_id `RESET_CF
    let reset_df = of_id `RESET_DF
    let reset_if = of_id `RESET_IF
    let reset_sf = of_id `RESET_SF
    let reset_af = of_id `RESET_AF
    let reset_tf = of_id `RESET_TF
    let reset_nt = of_id `RESET_NT
    let reset_pf = of_id `RESET_PF
    let set_cf = of_id `SET_CF
    let set_df = of_id `SET_DF
    let set_if = of_id `SET_IF
    let test_of = of_id `TEST_OF
    let test_sf = of_id `TEST_SF
    let test_zf = of_id `TEST_ZF
    let test_pf = of_id `TEST_PF
    let test_cf = of_id `TEST_CF
    let test_nt = of_id `TEST_NT
    let test_df = of_id `TEST_DF
    let undefined_of = of_id `UNDEFINED_OF
    let undefined_sf = of_id `UNDEFINED_SF
    let undefined_zf = of_id `UNDEFINED_ZF
    let undefined_pf = of_id `UNDEFINED_PF
    let undefined_af = of_id `UNDEFINED_AF
    let undefined_cf = of_id `UNDEFINED_CF
    let reset_rf = of_id `RESET_RF
    let test_rf = of_id `TEST_RF
    let test_if = of_id `TEST_IF
    let test_tf = of_id `TEST_TF
    let test_af = of_id `TEST_AF
    let reset_zf = of_id `RESET_ZF
    let set_of = of_id `SET_OF
    let set_sf = of_id `SET_SF
    let set_zf = of_id `SET_ZF
    let set_af = of_id `SET_AF
    let set_pf = of_id `SET_PF
    let reset_0f = of_id `RESET_0F
    let reset_ac = of_id `RESET_AC

    let test t v = Int64.logand t v <> 0L
    let test_id t id = test t (of_id id)
  end

  module FPUFlags = struct
    type t = private int64
    type id = [ `MODIFY_C0
              | `MODIFY_C1
              | `MODIFY_C2
              | `MODIFY_C3
              | `RESET_C0
              | `RESET_C1
              | `RESET_C2
              | `RESET_C3
              | `SET_C0
              | `SET_C1
              | `SET_C2
              | `SET_C3
              | `UNDEFINED_C0
              | `UNDEFINED_C1
              | `UNDEFINED_C2
              | `UNDEFINED_C3
              | `TEST_C0
              | `TEST_C1
              | `TEST_C2
              | `TEST_C3 ]

    let of_id = function
      | `MODIFY_C0 -> Int64.shift_left 1L 0
      | `MODIFY_C1 -> Int64.shift_left 1L 1
      | `MODIFY_C2 -> Int64.shift_left 1L 2
      | `MODIFY_C3 -> Int64.shift_left 1L 3
      | `RESET_C0 -> Int64.shift_left 1L 4
      | `RESET_C1 -> Int64.shift_left 1L 5
      | `RESET_C2 -> Int64.shift_left 1L 6
      | `RESET_C3 -> Int64.shift_left 1L 7
      | `SET_C0 -> Int64.shift_left 1L 8
      | `SET_C1 -> Int64.shift_left 1L 9
      | `SET_C2 -> Int64.shift_left 1L 10
      | `SET_C3 -> Int64.shift_left 1L 11
      | `UNDEFINED_C0 -> Int64.shift_left 1L 12
      | `UNDEFINED_C1 -> Int64.shift_left 1L 13
      | `UNDEFINED_C2 -> Int64.shift_left 1L 14
      | `UNDEFINED_C3 -> Int64.shift_left 1L 15
      | `TEST_C0 -> Int64.shift_left 1L 16
      | `TEST_C1 -> Int64.shift_left 1L 17
      | `TEST_C2 -> Int64.shift_left 1L 18
      | `TEST_C3 -> Int64.shift_left 1L 19

    let modify_c0 = of_id `MODIFY_C0
    let modify_c1 = of_id `MODIFY_C1
    let modify_c2 = of_id `MODIFY_C2
    let modify_c3 = of_id `MODIFY_C3
    let reset_c0 = of_id `RESET_C0
    let reset_c1 = of_id `RESET_C1
    let reset_c2 = of_id `RESET_C2
    let reset_c3 = of_id `RESET_C3
    let set_c0 = of_id `SET_C0
    let set_c1 = of_id `SET_C1
    let set_c2 = of_id `SET_C2
    let set_c3 = of_id `SET_C3
    let undefined_c0 = of_id `UNDEFINED_C0
    let undefined_c1 = of_id `UNDEFINED_C1
    let undefined_c2 = of_id `UNDEFINED_C2
    let undefined_c3 = of_id `UNDEFINED_C3
    let test_c0 = of_id `TEST_C0
    let test_c1 = of_id `TEST_C1
    let test_c2 = of_id `TEST_C2
    let test_c3 = of_id `TEST_C3

    let test t v = Int64.logand t v <> 0L
    let test_id t id = test t (of_id id)
  end
end

type operand_mem_val = {
	segment : Const.Reg.t option;
	base    : Const.Reg.t option;
	index   : Const.Reg.t option;
	scale   : int option;
	disp    : int64;
}

type operand_val = Imm of int64
                 | Mem of operand_mem_val
                 | Reg of Const.Reg.t

type operand = {
	value           : operand_val;
  size            : int;
  access          : [ `R | `W | `RW ];
	avx_bcast       : Const.AvxBcast.t option;
	avx_zero_opmask : int;
}

type encoding = {
  modrm_offset : int;
  disp_offset  : int;
  disp_size    : int;
  imm_offset   : int;
  imm_size     : int;
}

type detail = {
	prefix             : Const.Prefix.t option;
  segment_override   : Const.SegmentReg.t option;
  op_size_override   : bool;
  addr_size_override : bool;
  opcode             : int array;
	rex                : int;
	addr_size          : int;
	modrm              : int;
	disp               : int64 option;
  sib                : int option;
	sib_index          : Const.Reg.t option;
	sib_scale          : int option;
	sib_base           : Const.Reg.t option;
  xop_cc             : Const.XopCc.t option;
  sse_cc             : Const.SseCc.t option;
	avx_cc             : Const.AvxCc.t option;
	avx_sae            : bool;
	avx_rm             : Const.AvxRm.t option;
  eflags             : Const.EFlags.t option;
  fpu_flags          : Const.FPUFlags.t option;
  operands           : operand array;
  encoding           : encoding;
}
