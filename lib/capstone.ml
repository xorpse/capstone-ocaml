module Arm = Arm
module Arm64 = Arm64
module Evm = Evm
module M680x = M680x
module M68k = M68k
module Mips = Mips
module Ppc = Ppc
module Sparc = Sparc
module Systemz = Systemz
module Tms320c64x = Tms320c64x
module X86 = X86
module Xcore = Xcore

(*
   TODO(xorpse):
     - cs_ac_type -> redo implementation from Cs_const
     - implement mode -> Cs_const.Mode.t
     - implement insn_group as int -> make test / test_id
*)

exception Capstone_error of Cs_const.cs_err

type arch = [ `ARM
            | `ARM64
            | `EVM
            | `M680
            | `M68K
            | `MIPS
            | `PPC
            | `SPARC
            | `SYSTEMZ
            | `TMS320C64X
            | `X86
            | `XCORE ]

type operand = Cs_const.cs_op_type

type group = Cs_const.cs_group_type

type handle

type arm_insn = {
  id         : Arm.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Arm.Const.Reg.t array;
  regs_write : Arm.Const.Reg.t array;
  groups     : [ Cs_const.GroupType.id | Arm.Const.InsnGroup.id ] array;
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
  groups     : [ Cs_const.GroupType.id | Arm64.Const.InsnGroup.id ] array;
  detail     : Arm64.detail option;
}

type evm_insn = {
  id         : Evm.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  groups     : [ Cs_const.GroupType.id | Mips.Const.InsnGroup.id ] array;
  detail     : Evm.detail option;
}

type m680x_insn = {
  id         : Mips.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Mips.Const.Reg.t array;
  regs_write : Mips.Const.Reg.t array;
  groups     : [ Cs_const.GroupType.id | Mips.Const.InsnGroup.id ] array;
  detail     : Mips.detail option;
}

type m68k_insn = {
  id         : Mips.Const.Insn.t;
  address    : int64;
  size       : int;
  bytes      : bytes;
  mnemonic   : string;
  op_str     : string;
  regs_read  : Mips.Const.Reg.t array;
  regs_write : Mips.Const.Reg.t array;
  groups     : [ Cs_const.GroupType.id | Mips.Const.InsnGroup.id ] array;
  detail     : Mips.detail option;
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
  groups     : [ Cs_const.GroupType.id | Mips.Const.InsnGroup.id ] array;
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
  groups     : [ Cs_const.GroupType.id | Ppc.Const.InsnGroup.id ] array;
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
  groups     : [ Cs_const.GroupType.id | Sparc.Const.InsnGroup.id ] array;
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
  groups     : [ Cs_const.GroupType.id | Systemz.Const.InsnGroup.id ] array;
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
  groups     : [ Cs_const.GroupType.id | X86.Const.InsnGroup.id ] array;
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
  groups     : [ Cs_const.GroupType.id | X86.Const.InsnGroup.id ] array;
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
  groups     : [ Cs_const.GroupType.id | Xcore.Const.InsnGroup.id ] array;
  detail     : Xcore.detail option;
}

type reg = [ Arm.Const.Reg.id
           | Arm64.Const.Reg.id
           | Mips.Const.Reg.id
           | Ppc.Const.Reg.id
           | Sparc.Const.Reg.id
           | Systemz.Const.Reg.id
           | X86.Const.Reg.id
           | Xcore.Const.Reg.id ]

external create_ffi : arch:Cs_const.Arch.t -> mode:(Cs_const.cs_mode list) -> handle option = "ml_capstone_create"

external disasm_arm_ffi : Cs_const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> arm_insn list = "ml_capstone_disassemble"
external disasm_arm64_ffi : Cs_const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> arm64_insn list = "ml_capstone_disassemble"
external disasm_mips_ffi : Cs_const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> mips_insn list = "ml_capstone_disassemble"
external disasm_ppc_ffi : Cs_const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> ppc_insn list = "ml_capstone_disassemble"
external disasm_sparc_ffi : Cs_const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> sparc_insn list = "ml_capstone_disassemble"
external disasm_sysz_ffi : Cs_const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> systemz_insn list = "ml_capstone_disassemble"
external disasm_x86_ffi : Cs_const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> x86_insn list = "ml_capstone_disassemble"
external disasm_xcore_ffi : Cs_const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> xcore_insn list = "ml_capstone_disassemble"

external set_option_ffi: handle -> Cs_const.OptType.t -> int -> unit = "ml_capstone_set_option"
external version: unit -> int = "ml_capstone_version"

module Arch = struct
  type ('a, 'b) t =
    | ARM   : ([ `ARM ], arm_insn) t
    | ARM64 : ([ `ARM64 ], arm64_insn) t
    | MIPS  : ([ `MIPS ], mips_insn) t
    | PPC   : ([ `PPC ], ppc_insn) t
    | SPARC : ([ `SPARC ], sparc_insn) t
    | SYSZ  : ([ `SYSZ ], systemz_insn) t
    | X86   : ([ `X86 ], x86_insn) t
    | XCORE : ([ `XCORE ], xcore_insn) t
end

type ('a, 'b) t = T : ('a, 'b) Arch.t * handle -> ('a, 'b) t

let arch : type a b. (a, b) t -> (a, b) Arch.t =
  function T (arch, _) -> arch

let handle = function T (_, h) -> h

let disassemble (type a) (type b) (t : (a, b) t) ~(addr : int64) ?(count : int64 = -1L) (buf : bytes)
  : b list = match t with
  | T (Arch.ARM, h) -> disasm_arm_ffi Cs_const.Arch.arm h buf addr count
  | T (Arch.ARM64, h) -> disasm_arm64_ffi Cs_const.Arch.arm64 h buf addr count
  | T (Arch.MIPS, h) -> disasm_mips_ffi Cs_const.Arch.mips h buf addr count
  | T (Arch.PPC, h) -> disasm_ppc_ffi Cs_const.Arch.ppc h buf addr count
  | T (Arch.SPARC, h) -> disasm_sparc_ffi Cs_const.Arch.sparc h buf addr count
  | T (Arch.SYSZ, h) -> disasm_sysz_ffi Cs_const.Arch.sysz h buf addr count
  | T (Arch.X86, h) -> disasm_x86_ffi Cs_const.Arch.x86 h buf addr count
  | T (Arch.XCORE, h) -> disasm_xcore_ffi Cs_const.Arch.xcore h buf addr count

type any_arch = arch

type 'a mode =
  | M_LITTLE_ENDIAN : [< any_arch ] mode
  | M_ARM           : [< `ARM ] mode
  | M_MODE_16       : [< `X86 ] mode
  | M_MODE_32       : [< `MIPS | `X86 ] mode
  | M_MODE_64       : [< `MIPS | `PPC | `X86 ] mode
  | M_THUMB         : [< `ARM ] mode
  | M_MCLASS        : [< `ARM ] mode
  | M_V8            : [< `ARM ] mode
  | M_MICRO         : [< `MIPS ] mode
  | M_MIPS3         : [< `MIPS ] mode
  | M_MIPS3R6       : [< `MIPS ] mode
  | M_MIPS2         : [< `MIPS ] mode
  | M_V9            : [< `SPARC ] mode
  | M_QPX           : [< `PPC ] mode
  | M_M68K_000      : [< `M68K ] mode
  | M_M68K_010      : [< `M68K ] mode
  | M_M68K_020      : [< `M68K ] mode
  | M_M68K_030      : [< `M68K ] mode
  | M_M68K_040      : [< `M68K ] mode
  | M_M68K_060      : [< `M68K ] mode
  | M_BIG_ENDIAN    : [< any_arch] mode
  | M_MIPS32        : [< `MIPS ] mode
  | M_MIPS64        : [< `MIPS ] mode
  | M_M680X_6301    : [< `M680X ] mode
  | M_M680X_6309    : [< `M680X ] mode
  | M_M680X_6800    : [< `M680X ] mode
  | M_M680X_6801    : [< `M680X ] mode
  | M_M680X_6805    : [< `M680X ] mode
  | M_M680X_6808    : [< `M680X ] mode
  | M_M680X_6809    : [< `M680X ] mode
  | M_M680X_6811    : [< `M680X ] mode
  | M_M680X_CPU12   : [< `M680X ] mode
  | M_M680X_HCS08   : [< `M680X ] mode
  | M_PLUS          : 'a mode * 'a mode -> 'a mode

let create (type a) (type b) ?(_mode : a mode option) (arch : (a, b) Arch.t) : (a, b) t option =
  let arch' = match arch with
    | Arch.ARM -> Cs_const.Arch.arm
    | Arch.ARM64 -> Cs_const.Arch.arm64
    | Arch.MIPS -> Cs_const.Arch.mips
    | Arch.PPC -> Cs_const.Arch.ppc
    | Arch.SPARC -> Cs_const.Arch.sparc
    | Arch.SYSZ -> Cs_const.Arch.sysz
    | Arch.X86 -> Cs_const.Arch.x86
    | Arch.XCORE -> Cs_const.Arch.xcore
  in
  match create_ffi ~arch:arch' ~mode:[] with
  | Some h -> Some (T (arch, h))
  | None -> None

type 'a opt_val =
  | On        : [> `On ] opt_val
  | Off       : [> `Off ] opt_val
  | Att       : [> `Att ] opt_val
  | Default   : [> `Default ] opt_val
  | Intel     : [> `Intel ] opt_val
  | NoRegName : [> `NoRegName ] opt_val
  | Masm      : [> `Masm ] opt_val

type 'a opt =
  | Detail   : [ `On | `Off ] opt_val -> [< any_arch ] opt
  | Syntax   : [ `Att | `Default | `Intel | `NoRegName | `Masm ] opt_val -> [< any_arch ] opt
  | Skipdata : [ `On | `Off ] opt_val -> [< any_arch ] opt
  | Unsigned : [ `On | `Off ] opt_val -> [< any_arch ] opt
  | Mode     : 'a mode -> 'a opt

let set_option (type a) (type b) (t : (a, b) t) (opt : a opt) =
  let open Cs_const in
  let (opt, value) = match opt with
    | Detail v ->
      (OptType.detail, match v with
        | On -> OptValue.on
        | Off -> OptValue.off)
    | Mode _ -> failwith "TODO"
    | Skipdata v ->
      (OptType.skipdata, match v with
        | On -> OptValue.on
        | Off -> OptValue.off)
    | Syntax v ->
      (OptType.syntax, match v with
        | Att -> OptValue.syntax_att
        | Default -> OptValue.syntax_default
        | Intel -> OptValue.syntax_intel
        | NoRegName -> OptValue.syntax_noregname
        | Masm -> OptValue.syntax_masm)
    | Unsigned v ->
      (OptType.skipdata, match v with
        | On -> OptValue.on
        | Off -> OptValue.off)
  in set_option_ffi (handle t) opt (value :> int)

let disassemble_only ~arch ~_mode ~addr ?(count = -1L) buf =
  match create ~_mode arch with
  | None -> None
  | Some ctx -> Some (disassemble ctx ~addr ~count buf)
