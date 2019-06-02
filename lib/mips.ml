(* Capstone Disassembly Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

module Const = Mips_const

(* architecture specific info of instruction *)
type mips_op_mem = {
	base: int;
	disp: int
}

type mips_op_value =
	| MIPS_OP_INVALID of int
	| MIPS_OP_REG of int
	| MIPS_OP_IMM of int
	| MIPS_OP_MEM of mips_op_mem

type mips_op = {
	value: mips_op_value;
}

type mips_insn_detail = {
	operands: mips_op array;
}
