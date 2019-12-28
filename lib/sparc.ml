(* Capstone Disassembly Engine
 * By Guillaume Jeanne <guillaume.jeanne@ensimag.fr>, 2014> *)

module Const = Sparc_const
module Const = struct
  module Cc = Sparc_const.Cc

  module Hint = struct
    type t = private int
    type id = [ `A
              | `Pt
              | `Pn
              ]

    external of_id : id -> t = "ml_sparc_hint_to_capstone_int"

    let a = of_id `A
    let pt = of_id `Pt
    let pn = of_id `Pn

    let test t v = (t land v) <> 0
    let test_id t id = test t (of_id id :> int)
  end

  module Insn = Sparc_const.Insn
  module InsnGroup = Sparc_const.InsnGroup
  module Reg = Sparc_const.Reg

end

type operand_mem = {
	base  : Const.Reg.t option;
	index : Const.Reg.t option;
	disp  : int32;
}

type operand = Reg of Const.Reg.t
             | Imm of int64
             | Mem of operand_mem

type detail = {
	cc       : Const.Cc.t option;
	hint     : Const.Hint.t option;
	operands : operand array;
}

