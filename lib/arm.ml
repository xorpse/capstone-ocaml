(* Capstone Disassembly Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

module Const = Arm_const

type operand_shift = {
	shift_type  : Const.Shifter.t;
	shift_value : int;
}

type operand_mem = {
	base   : Const.Reg.t option;
	index  : Const.Reg.t option;
	scale  : int;
	disp   : int;
}

type operand_val =
	| Reg of Const.Reg.t
	| CImm of int32
	| PImm of int32
	| Imm of int32
	| Fp of float
	| Mem of operand_mem
	| Setend of Const.SetendType.t
  | SysReg of Const.Sysreg.t

type operand = {
	vector_index : int option;
	shift        : operand_shift option;
	value        : operand_val option;
	subtracted   : bool;
  access       : [ `R | `W | `RW ];
  neon_lane    : int option;
}

type detail = {
	usermode     : bool;
	vector_size  : int;
	vector_data  : Const.VectordataType.t option;
	cps_mode     : Const.CpsmodeType.t option;
	cps_flag     : Const.CpsflagType.t option;
	cc           : Const.Cc.t option;
	update_flags : bool;
	writeback    : bool;
	mem_barrier  : Const.MemBarrier.t option;
	operands     : operand array;
}
