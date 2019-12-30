module Const = struct
  module AddressMode = M68k_const.AddressMode
  module CpuSize = M68k_const.CpuSize
  module FpuSize = M68k_const.FpuSize
  module OpBrDispSize = M68k_const.OpBrDispSize
  module Insn = M68k_const.Insn
  module InsnGroup = M68k_const.GroupType
  module Reg = M68k_const.Reg
end

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
