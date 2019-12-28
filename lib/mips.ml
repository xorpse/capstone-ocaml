(* Capstone Disassembly Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

module Const = Mips_const

type operand_mem = {
	base : Const.Reg.t option;
	disp : int64;
}

type operand = Reg of Const.Reg.t
             | Imm of int64
             | Mem of operand_mem

type detail = {
	operands: operand array;
}
