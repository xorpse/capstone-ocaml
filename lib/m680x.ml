module Const = struct
  include M680x_const

  module Flags = struct
    type t = private int

    type id = [ `FstOpInMnem
              | `SndOpInMnem
              ]

    let of_id = function
      | `FstOpInMnem -> 1
      | `SndOpInMnem -> 2

    let to_id = function
      | 1 -> `FstOpInMnem
      | 2 -> `SndOpInMnem
      | _ -> invalid_arg "unexpected m680x instruction flag"

    let fst_op_in_mnem = of_id `FstOpInMnem
    let snd_op_in_mnem = of_id `SndOpInMnem
  end

  module IdxFlags = struct
    type t = private int
    type id = [ `Indirect
              | `NoComma
              | `PostIncDec
              ]

    let of_id = function
      | `Indirect -> 1
      | `NoComma -> 2
      | `PostIncDec -> 4

    let indirect = of_id `Indirect
    let no_comma = of_id `NoComma
    let post_ind_dec = of_id `PostIncDec

    let test t v = (t land v) <> 0
    let test_id t id = test t (of_id id)
  end
end

type operand_ext = {
  address  : int;
  indirect : bool;
}

type operand_rel = {
  address : int;
  offset  : int;
}

type operand_idx = {
  base_reg    : Const.Reg.t option;
  offset_reg  : Const.Reg.t option;
  offset      : int;
  offset_addr : int;
  offset_bits : int;
  inc_dec     : int option;
  flags       : Const.IdxFlags.t;
}

type operand_val = Reg of Const.Reg.t
                 | Imm of int32
                 | IdxAddr of operand_idx
                 | RelAddr of operand_rel
                 | ExtAddr of operand_ext
                 | DirAddr of int
                 | Const of int

type operand = {
  value  : operand_val;
  size   : int;
  access : [ `R | `W | `RW ]
}

type detail = {
  flags    : Const.Flags.t;
  operands : operand array;
}
