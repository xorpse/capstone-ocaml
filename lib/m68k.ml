module Const = M68k_const

type operand_size = Cpu of Const.CpuSize.t
                  | Fpu of Const.FpuSize.t

type operand_br_disp = {
  disp      : int32;
  disp_size : Const.OpBrDispSize.t;
}

type operand_bitfield = {
  width  : int;
  offset : int;
}

type operand_mem = {
  base_reg    : Const.Reg.t option;
  index_reg   : Const.Reg.t option;
  in_base_reg : Const.Reg.t option;
  in_disp     : int32;
  out_disp    : int32;
  disp        : int;
  bitfield    : operand_bitfield option;
  index_size  : int;
}

type operand_value = Reg of Const.Reg.t
                   | RegBits of int32
                   | RegPair of Const.Reg.t * Const.Reg.t
                   | Imm of int64
                   | Mem of operand_mem
                   | BranchDisp of operand_br_disp
                   | FpDouble of float
                   | FpSingle of float

type operand = {
  value        : operand_value;
  address_mode : Const.AddressMode.t;
}

type detail = {
  operands : operand array;
  size     : operand_size option;
}
