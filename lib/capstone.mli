module Arm        : module type of Arm
module Arm64      : module type of Arm64
module Evm        : module type of Evm
module M680x      : module type of M680x
module M68k       : module type of M68k
module Mips       : module type of Mips
module Ppc        : module type of Ppc
module Sparc      : module type of Sparc
module Systemz    : module type of Systemz
module Tms320c64x : module type of Tms320c64x
module X86        : module type of X86
module Xcore      : module type of Xcore

module Const : sig
  type err  = Cs_const.cs_err

  module Err       : module type of Cs_const.Err
  module InsnGroup : module type of Cs_const.GroupType
end

exception Capstone_error of Const.err

type arm_insn = {
  id         : Arm.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Arm.Const.Reg.t array;
  regs_write : Arm.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | Arm.Const.InsnGroup.id ] array;
  detail     : Arm.detail option;
}

type arm64_insn = {
  id         : Arm64.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Arm64.Const.Reg.t array;
  regs_write : Arm64.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | Arm64.Const.InsnGroup.id ] array;
  detail     : Arm64.detail option;
}

type evm_insn = {
  id         : Evm.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  groups     : [ Const.InsnGroup.id | Mips.Const.InsnGroup.id ] array;
  detail     : Evm.detail option;
}

type m680x_insn = {
  id         : M680x.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Mips.Const.Reg.t array;
  regs_write : Mips.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | M680x.Const.InsnGroup.id ] array;
  detail     : M680x.detail option;
}

type m68k_insn = {
  id         : M68k.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : M68k.Const.Reg.t array;
  regs_write : M68k.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | M68k.Const.InsnGroup.id ] array;
  detail     : M68k.detail option;
}
type mips_insn = {
  id         : Mips.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Mips.Const.Reg.t array;
  regs_write : Mips.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | Mips.Const.InsnGroup.id ] array;
  detail     : Mips.detail option;
}

type ppc_insn = {
  id         : Ppc.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Ppc.Const.Reg.t array;
  regs_write : Ppc.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | Ppc.Const.InsnGroup.id ] array;
  detail     : Ppc.detail option;
}

type sparc_insn = {
  id         : Sparc.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Sparc.Const.Reg.t array;
  regs_write : Sparc.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | Sparc.Const.InsnGroup.id ] array;
  detail     : Sparc.detail option;
}

type systemz_insn = {
  id         : Systemz.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Systemz.Const.Reg.t array;
  regs_write : Systemz.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | Systemz.Const.InsnGroup.id ] array;
  detail     : Systemz.detail option;
}

type tms320c64x_insn = {
  id         : X86.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : X86.Const.Reg.t array;
  regs_write : X86.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | X86.Const.InsnGroup.id ] array;
  detail     : X86.detail option;
}

type x86_insn = {
  id         : X86.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : X86.Const.Reg.t array;
  regs_write : X86.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | X86.Const.InsnGroup.id ] array;
  detail     : X86.detail option;
}

type xcore_insn = {
  id         : Xcore.Const.Insn.t;
  address    : int;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Xcore.Const.Reg.t array;
  regs_write : Xcore.Const.Reg.t array;
  groups     : [ Const.InsnGroup.id | Xcore.Const.InsnGroup.id ] array;
  detail     : Xcore.detail option;
}

module Arch : sig
  type id  = [ `ARM
             | `ARM64
             | `EVM
             | `M680X
             | `M68K
             | `MIPS
             | `PPC
             | `SPARC
             | `SYSTEMZ
             | `TMS320C64X
             | `X86
             | `XCORE ]
  type any = id
  type ('a, 'b) t =
    | ARM        : ([ `ARM ], arm_insn) t
    | ARM64      : ([ `ARM64 ], arm64_insn) t
    | EVM        : ([ `EVM ], evm_insn) t
    | M680X      : ([ `M680X ], m680x_insn) t
    | M68K       : ([ `M68K ], m68k_insn) t
    | MIPS       : ([ `MIPS ], mips_insn) t
    | PPC        : ([ `PPC ], ppc_insn) t
    | SPARC      : ([ `SPARC ], sparc_insn) t
    | SYSTEMZ    : ([ `SYSTEMZ ], systemz_insn) t
    | TMS320C64X : ([ `TMS320C64X ], tms320c64x_insn) t
    | X86        : ([ `X86 ], x86_insn) t
    | XCORE      : ([ `XCORE ], xcore_insn) t
end

module Mode : sig
  type 'arch t

  val little_endian : [< Arch.any ] t
  val arm           : [< `ARM ] t
  val mode_16       : [< `X86 ] t
  val mode_32       : [< `MIPS | `X86 ] t
  val mode_64       : [< `MIPS | `PPC | `X86 ] t
  val thumb         : [< `ARM ] t
  val mclass        : [< `ARM ] t
  val v8            : [< `ARM ] t
  val micro         : [< `MIPS ] t
  val mips3         : [< `MIPS ] t
  val mips32r6      : [< `MIPS ] t
  val mips2         : [< `MIPS ] t
  val v9            : [< `SPARC ] t
  val qpx           : [< `PPC ] t
  val m68k_000      : [< `M68K ] t
  val m68k_010      : [< `M68K ] t
  val m68k_020      : [< `M68K ] t
  val m68k_030      : [< `M68K ] t
  val m68k_040      : [< `M68K ] t
  val m68k_060      : [< `M68K ] t
  val big_endian    : [< Arch.any] t
  val mips32        : [< `MIPS ] t
  val mips64        : [< `MIPS ] t
  val m680x_6301    : [< `M680X ] t
  val m680x_6309    : [< `M680X ] t
  val m680x_6800    : [< `M680X ] t
  val m680x_6801    : [< `M680X ] t
  val m680x_6805    : [< `M680X ] t
  val m680x_6808    : [< `M680X ] t
  val m680x_6809    : [< `M680X ] t
  val m680x_6811    : [< `M680X ] t
  val m680x_cpu12   : [< `M680X ] t
  val m680x_hcs08   : [< `M680X ] t
  val (&)           : 'arch t -> 'arch t -> 'arch t
end

module Opt : sig
  type 'arch k
  type 'value v

  val on        : [> `On ] v
  val off       : [> `Off ] v
  val att       : [> `Att ] v
  val default   : [> `Default ] v
  val intel     : [> `Intel ] v
  val noregname : [> `NoRegName ] v
  val masm      : [> `Masm ] v

  val detail   : [ `On | `Off ] v -> [< Arch.any ] k
  val syntax   : [ `Att | `Default | `Intel | `NoRegName | `Masm ] v -> [< Arch.any ] k
  val skipdata : [ `On | `Off ] v -> [< Arch.any ] k
  val unsigned : [ `On | `Off ] v -> [< Arch.any ] k
  val mode     : 'a Mode.t -> 'a k
end

type ('arch, 'insn) t

val create           : ?mode:'arch Mode.t -> ('arch, 'insn) Arch.t -> ('arch, 'insn) t option
val disassemble      : ?count:int64 -> addr:int64 -> ('arch, 'insn) t -> bytes -> 'insn list
val disassemble_only : ?count:int64 -> ?mode:'arch Mode.t -> arch:('arch, 'insn) Arch.t -> addr:int64 -> bytes -> 'insn list option
val set_option       : ('arch, 'insn) t -> 'arch Opt.k -> unit
val version          : unit -> int
