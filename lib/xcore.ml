(* Capstone Disassembly Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

module Const = struct
  include Xcore_const

  module Direction = struct
    type t = private int
    type id = [ `Forward
              | `Backward
              ]

    let of_id = function
      | `Forward -> 1
      | `Backward -> -1

    let to_id = function
      | 1 -> `Forward
      | -1 -> `Backward
      | _ -> invalid_arg "Xcore.Const.Direction.to_id: invalid value"

    let forward = of_id `Forward
    let backward = of_id `Backward
  end
end

type operand_mem = {
  base      : Const.Reg.t option;
  index     : Const.Reg.t option;
  disp      : int32;
  direction : Const.Direction.t;
}

type operand = Reg of Const.Reg.t
             | Imm of int32
             | Mem of operand_mem

type detail = {
  operands : operand array;
}
