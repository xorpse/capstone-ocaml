module Const = Tms320c64x_const

type operand_mem_disp = Reg of Const.Reg.t
                      | Const of int

type operand_mem = {
  base      : Const.Reg.t option;
  disp      : operand_mem_disp option;
  unit      : Const.Funit.t option;
  scaled    : bool;
  direction : Const.MemDir.t option;
  modify    : Const.MemMod.t option;
}

type operand = Reg of Const.Reg.t
             | RegPair of Const.Reg.t * Const.Reg.t
             | Imm of int32
             | Mem of operand_mem

type funit = {
  unit      : Const.Funit.t;
  side      : int;
  crosspath : bool;
}

type condition = {
  reg     : Const.Reg.t;
  is_zero : bool;
}

type detail = {
  operands  : operand array;
  condition : condition option;
  funit     : funit option; (* None if Const.Funit.no or invalid *)
  parallel  : bool;
}
