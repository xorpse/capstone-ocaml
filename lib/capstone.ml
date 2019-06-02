module Arm = Arm
module Arm64 = Arm64
module Mips = Mips
module Ppc = Ppc
module Sparc = Sparc
module Systemz = Systemz
module X86 = X86
module Xcore = Xcore

exception Capstone_error of Cs_const.cs_err

type arch = [ `Arm | `Arm64 | `Mips | `Ppc | `Sparc | `Sysz | `X86 | `Xcore ]

type mode = Cs_const.cs_mode

type opt = [ `Syntax of [ `Default | `Intel | `Att | `Noregname ]
           | `Detail of [ `On | `Off ]
           | `Mode of mode
           | `Skipdata of [ `On | `Off ] ]

type operand = Cs_const.cs_op_type

type group = Cs_const.cs_group_type

type handle

type t = {
  handle : handle;
  arch   : arch;
}

type arm_insn = {
  id         : Arm.Const.arm_insn;
  address    : int;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Arm.Const.arm_reg array;
  regs_write : Arm.Const.arm_reg array;
  groups     : group array;
  detail     : Arm.arm_insn_detail option;
}

type arm64_insn = {
  id         : Arm64.Const.arm64_insn;
  address    : int;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Arm64.Const.arm64_reg array;
  regs_write : Arm64.Const.arm64_reg array;
  groups     : group array;
  detail     : Arm64.arm64_insn_detail option;
}

type mips_insn = {
  id         : Mips.Const.mips_insn;
  address    : int;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Mips.Const.mips_reg array;
  regs_write : Mips.Const.mips_reg array;
  groups     : group array;
  detail     : Mips.mips_insn_detail option;
}

type ppc_insn = {
  id         : Ppc.Const.ppc_insn;
  address    : int;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Ppc.Const.ppc_reg array;
  regs_write : Ppc.Const.ppc_reg array;
  groups     : group array;
  detail     : Ppc.ppc_insn_detail option;
}

type sparc_insn = {
  id         : Sparc.Const.sparc_insn;
  address    : int;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Sparc.Const.sparc_reg array;
  regs_write : Sparc.Const.sparc_reg array;
  groups     : group array;
  detail     : Sparc.sparc_insn_detail option;
}

type sysz_insn = {
  id         : Systemz.Const.sysz_insn;
  address    : int;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Systemz.Const.sysz_reg array;
  regs_write : Systemz.Const.sysz_reg array;
  groups     : group array;
  detail     : Systemz.sysz_insn_detail option;
}

type x86_insn = {
  id         : X86.Const.x86_insn;
  address    : int;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : X86.Const.x86_reg array;
  regs_write : X86.Const.x86_reg array;
  groups     : group array;
  detail     : X86.x86_insn_detail option;
}

type xcore_insn = {
  id         : Xcore.Const.xcore_insn;
  address    : int;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Xcore.Const.xcore_reg array;
  regs_write : Xcore.Const.xcore_reg array;
  groups     : group array;
  detail     : Xcore.xcore_insn_detail option;
}

type reg = [ Arm.Const.arm_reg
           | Arm64.Const.arm64_reg
           | Mips.Const.mips_reg
           | Ppc.Const.ppc_reg
           | Sparc.Const.sparc_reg
           | Systemz.Const.sysz_reg
           | X86.Const.x86_reg
           | Xcore.Const.xcore_reg ]

type insn =
  | ARM_INS of arm_insn
  | ARM64_INS of arm64_insn
  | MIPS_INS of mips_insn
  | PPC_INS of ppc_insn
  | SPARC_INS of sparc_insn
  | SYSZ_INS of sysz_insn
  | X86_INS of x86_insn
  | XCORE_INS of xcore_insn

external create' : arch:arch -> mode:(mode list) -> handle option = "ml_capstone_create"
external disasm_quick' : arch:arch -> mode:(mode list) -> bytes -> Int64.t -> Int64.t -> insn list = "ml_capstone_disasm"
external disasm' : arch -> handle -> bytes -> Int64.t -> Int64.t -> insn list = "ml_capstone_diasm_internal"
(*  external _cs_disasm_internal: arch -> Int64.t -> string -> Int64.t -> Int64.t -> cs_insn0 list = "ocaml_cs_disasm_internal" *)
(*
external reg_name: handle ->  -> string = "ml_capstone_register_name"
external insn_name: Int64.t -> int -> string = "ml_capstone_instruction_name"
external group_name: Int64.t -> int -> string = "ml_capstone_group_name"
*)
external version: unit -> int = "ml_capstone_version"

external set_option: handle -> opt -> unit = "ml_capstone_option"
(*
external _cs_close: Int64.t -> int = "ocaml_close"
*)


let create ?(mode = []) ~arch = match create' ~arch ~mode with
  | None -> None
  | Some h -> Some { handle = h; arch }


let disasm ~handle ~addr ?(count = -1L) buf =
  disasm' handle.arch handle.handle buf addr count

let disasm_quick ~arch ~mode ~addr ?(count = -1L) buf =
  disasm_quick' ~arch ~mode buf addr count
