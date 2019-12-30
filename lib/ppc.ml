module Const = Ppc_const

type operand_mem = {
  base : Const.Reg.t option;
  disp : int32;
}

type operand_crx = {
  scale : int;
  reg   : Const.Reg.t;
  cond  : Const.Bc.t;
}

type operand =
  | Reg of Const.Reg.t
  | Imm of int64
  | Mem of operand_mem
  | Crx of operand_crx

type detail = {
  bc         : Const.Bc.t option;
  bh         : Const.Bh.t option;
  update_cr0 : bool;
  operands   : operand array;
}
