(* Capstone Disassembly Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

module Const = Sysz_const

type operand_mem = {
  base   : Const.Reg.t option;
  index  : Const.Reg.t option;
  length : int64;
  disp   : int64;
}

type operand = Reg of Const.Reg.t
             | AcReg of Const.Reg.t
             | Imm of int64
             | Mem of operand_mem

type detail = {
  cc       : Const.Cc.t option;
  operands : operand array;
}
