(* Capstone Disassembly Engine
 * By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 *)

module Const = Arm64_const

type operand_shift = {
  shift_type  : Const.Shifter.t;
  shift_value : int;
}

type operand_mem = {
  base  : Const.Reg.t option;
  index : Const.Reg.t option;
  disp  : int32;
}

type operand_val =
  | Reg of Const.Reg.t
  | Imm of int64
  | CImm of int64
  | Fp of float
  | Mem of operand_mem
  | RegMRS of int
  | RegMSR of int
  | PState of Const.Pstate.t
  | SysAt of Const.AtOp.t
  | SysDc of Const.DcOp.t
  | SysIc of Const.IcOp.t
  | SysTlbi of Const.TlbiOp.t
  | Sys of int
  | Prefetch of Const.PrefetchOp.t
  | Barrier of Const.BarrierOp.t

type operand = {
  vector_index : int option;
  vas          : Const.Vas.t option;
  vess         : Const.Vess.t option;
  shift        : operand_shift option;
  ext          : Const.Extender.t option;
  value        : operand_val;
  access       : [ `R | `W | `RW ];
}

type detail = {
  cc           : Const.Cc.t option;
  update_flags : bool;
  writeback    : bool;
  operands     : operand array;
}
