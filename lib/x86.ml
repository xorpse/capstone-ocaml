(* Capstone Disassembly Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

module Const = X86_const

(* architecture specific info of instruction *)
type x86_op_mem = {
	segment: Const.x86_reg;
	base: Const.x86_reg;
	index: Const.x86_reg;
	scale: int;
	disp: int64;
}

type x86_op_value = [ `INVALID
                    | `IMM of int64
                    | `MEM of x86_op_mem
                    | Const.x86_reg
                    ]

type x86_op = {
	value: x86_op_value;
	size: int;
	avx_bcast: Const.x86_avx_bcast;
	avx_zero_opmask: int;
}

type x86_insn_detail = {
	prefix: int array;
	opcode: int array;
	rex: int;
	addr_size: int;
	modrm: int;
	sib: int;
	disp: int;
	sib_index: int;
	sib_scale: int;
	sib_base: Const.x86_reg;
	sse_cc: int;
	avx_cc: int;
	avx_sae: int;
	avx_rm: int;
	operands: x86_op array;
}
