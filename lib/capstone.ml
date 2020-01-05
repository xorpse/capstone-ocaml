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

module Const = struct
  type err = Cs_const.cs_err

  module Arch = Cs_const.Arch
  module Err = Cs_const.Err
  module InsnGroup = Cs_const.GroupType
  module OptType = Cs_const.OptType
  module OptValue = Cs_const.OptValue
end

(*
   TODO(xorpse):
     - cs_ac_type -> redo implementation from Const
     - implement mode -> Const.Mode.t
     - implement insn_group as int -> make test / test_id
*)

exception Capstone_error of Const.err
let _ = Callback.register_exception (Capstone_error Const.Err.ok)

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

external create_ffi : arch:Const.Arch.t -> mode:int -> handle option = "ml_capstone_create"

external disasm_arm_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> arm_insn list = "ml_capstone_disassemble"
external disasm_arm64_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> arm64_insn list = "ml_capstone_disassemble"
external disasm_evm_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> evm_insn list = "ml_capstone_disassemble"
external disasm_m680x_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> m680x_insn list = "ml_capstone_disassemble"
external disasm_m68k_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> m68k_insn list = "ml_capstone_disassemble"
external disasm_mips_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> mips_insn list = "ml_capstone_disassemble"
external disasm_ppc_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> ppc_insn list = "ml_capstone_disassemble"
external disasm_sparc_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> sparc_insn list = "ml_capstone_disassemble"
external disasm_sysz_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> systemz_insn list = "ml_capstone_disassemble"
external disasm_tms320c64x_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> tms320c64x_insn list = "ml_capstone_disassemble"
external disasm_x86_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> x86_insn list = "ml_capstone_disassemble"
external disasm_xcore_ffi : Const.Arch.t -> handle -> bytes -> Int64.t -> Int64.t -> xcore_insn list = "ml_capstone_disassemble"

external set_option_ffi: handle -> Const.OptType.t -> int -> unit = "ml_capstone_set_option"
external version: unit -> int = "ml_capstone_version"

module Arch = struct
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

  type id = [ `ARM
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
            | `XCORE
            ]
  type any = id
end

type ('a, 'b) t = T : ('a, 'b) Arch.t * handle -> ('a, 'b) t

let handle = function T (_, h) -> h

let disassemble (type a) (type b) ?(count : int64 = -1L) ~(addr : int64) (t : (a, b) t) (buf : bytes)
  : b list = match t with
  | T (Arch.ARM, h) -> disasm_arm_ffi Const.Arch.arm h buf addr count
  | T (Arch.ARM64, h) -> disasm_arm64_ffi Const.Arch.arm64 h buf addr count
  | T (Arch.EVM, h) -> disasm_evm_ffi Const.Arch.evm h buf addr count
  | T (Arch.M680X, h) -> disasm_m680x_ffi Const.Arch.m680x h buf addr count
  | T (Arch.M68K, h) -> disasm_m68k_ffi Const.Arch.m68k h buf addr count
  | T (Arch.MIPS, h) -> disasm_mips_ffi Const.Arch.mips h buf addr count
  | T (Arch.PPC, h) -> disasm_ppc_ffi Const.Arch.ppc h buf addr count
  | T (Arch.SPARC, h) -> disasm_sparc_ffi Const.Arch.sparc h buf addr count
  | T (Arch.SYSTEMZ, h) -> disasm_sysz_ffi Const.Arch.sysz h buf addr count
  | T (Arch.TMS320C64X, h) -> disasm_tms320c64x_ffi Const.Arch.tms320c64x h buf addr count
  | T (Arch.X86, h) -> disasm_x86_ffi Const.Arch.x86 h buf addr count
  | T (Arch.XCORE, h) -> disasm_xcore_ffi Const.Arch.xcore h buf addr count


module Mode = struct
  type 'a t =
    | M_LITTLE_ENDIAN : [< Arch.any ] t
    | M_ARM           : [< `ARM ] t
    | M_MODE_16       : [< `X86 ] t
    | M_MODE_32       : [< `MIPS | `X86 ] t
    | M_MODE_64       : [< `MIPS | `PPC | `X86 ] t
    | M_THUMB         : [< `ARM ] t
    | M_MCLASS        : [< `ARM ] t
    | M_V8            : [< `ARM ] t
    | M_MICRO         : [< `MIPS ] t
    | M_MIPS3         : [< `MIPS ] t
    | M_MIPS32R6      : [< `MIPS ] t
    | M_MIPS2         : [< `MIPS ] t
    | M_V9            : [< `SPARC ] t
    | M_QPX           : [< `PPC ] t
    | M_M68K_000      : [< `M68K ] t
    | M_M68K_010      : [< `M68K ] t
    | M_M68K_020      : [< `M68K ] t
    | M_M68K_030      : [< `M68K ] t
    | M_M68K_040      : [< `M68K ] t
    | M_M68K_060      : [< `M68K ] t
    | M_BIG_ENDIAN    : [< Arch.any] t
    | M_MIPS32        : [< `MIPS ] t
    | M_MIPS64        : [< `MIPS ] t
    | M_M680X_6301    : [< `M680X ] t
    | M_M680X_6309    : [< `M680X ] t
    | M_M680X_6800    : [< `M680X ] t
    | M_M680X_6801    : [< `M680X ] t
    | M_M680X_6805    : [< `M680X ] t
    | M_M680X_6808    : [< `M680X ] t
    | M_M680X_6809    : [< `M680X ] t
    | M_M680X_6811    : [< `M680X ] t
    | M_M680X_CPU12   : [< `M680X ] t
    | M_M680X_HCS08   : [< `M680X ] t
    | M_PLUS          : 'a t * 'a t -> 'a t

  let little_endian = M_LITTLE_ENDIAN
  let arm = M_ARM
  let mode_16 = M_MODE_16
  let mode_32 = M_MODE_32
  let mode_64 = M_MODE_64
  let thumb = M_THUMB
  let mclass = M_MCLASS
  let v8 = M_V8
  let micro = M_MICRO
  let mips3 = M_MIPS3
  let mips32r6 = M_MIPS32R6
  let mips2 = M_MIPS2
  let v9 = M_V9
  let qpx = M_QPX
  let m68k_000 = M_M68K_000
  let m68k_010 = M_M68K_010
  let m68k_020 = M_M68K_020
  let m68k_030 = M_M68K_030
  let m68k_040 = M_M68K_040
  let m68k_060 = M_M68K_060
  let big_endian = M_BIG_ENDIAN
  let mips32 = M_MIPS32
  let mips64 = M_MIPS64
  let m680x_6301 = M_M680X_6301
  let m680x_6309 = M_M680X_6309
  let m680x_6800 = M_M680X_6800
  let m680x_6801 = M_M680X_6801
  let m680x_6805 = M_M680X_6805
  let m680x_6808 = M_M680X_6808
  let m680x_6809 = M_M680X_6809
  let m680x_6811 = M_M680X_6811
  let m680x_cpu12 = M_M680X_CPU12
  let m680x_hcs08 = M_M680X_HCS08
  let (&) v v' = M_PLUS (v, v')

  let rec to_int_mode : 'a. 'a t -> int =
    let aux (type a) (m : a t) : int = match m with
      | M_LITTLE_ENDIAN -> (Cs_const.Mode.little_endian :> int)
      | M_ARM -> (Cs_const.Mode.arm :> int)
      | M_MODE_16 -> (Cs_const.Mode.mode_16 :> int)
      | M_MODE_32 -> (Cs_const.Mode.mode_32 :> int)
      | M_MODE_64 -> (Cs_const.Mode.mode_64 :> int)
      | M_THUMB -> (Cs_const.Mode.thumb :> int)
      | M_MCLASS -> (Cs_const.Mode.mclass :> int)
      | M_V8 -> (Cs_const.Mode.v8 :> int)
      | M_MICRO -> (Cs_const.Mode.micro :> int)
      | M_MIPS3 -> (Cs_const.Mode.mips3 :> int)
      | M_MIPS32R6 -> (Cs_const.Mode.mips32r6 :> int)
      | M_MIPS2 -> (Cs_const.Mode.mips2 :> int)
      | M_V9 -> (Cs_const.Mode.v9 :> int)
      | M_QPX -> (Cs_const.Mode.qpx :> int)
      | M_M68K_000 -> (Cs_const.Mode.m68k_000 :> int)
      | M_M68K_010 -> (Cs_const.Mode.m68k_010 :> int)
      | M_M68K_020 -> (Cs_const.Mode.m68k_020 :> int)
      | M_M68K_030 -> (Cs_const.Mode.m68k_030 :> int)
      | M_M68K_040 -> (Cs_const.Mode.m68k_040 :> int)
      | M_M68K_060 -> (Cs_const.Mode.m68k_060 :> int)
      | M_BIG_ENDIAN -> (Cs_const.Mode.big_endian :> int)
      | M_MIPS32 -> (Cs_const.Mode.mips32 :> int)
      | M_MIPS64 -> (Cs_const.Mode.mips64 :> int)
      | M_M680X_6301 -> (Cs_const.Mode.m680x_6301 :> int)
      | M_M680X_6309 -> (Cs_const.Mode.m680x_6309 :> int)
      | M_M680X_6800 -> (Cs_const.Mode.m680x_6800 :> int)
      | M_M680X_6801 -> (Cs_const.Mode.m680x_6801 :> int)
      | M_M680X_6805 -> (Cs_const.Mode.m680x_6805 :> int)
      | M_M680X_6808 -> (Cs_const.Mode.m680x_6808 :> int)
      | M_M680X_6809 -> (Cs_const.Mode.m680x_6809 :> int)
      | M_M680X_6811 -> (Cs_const.Mode.m680x_6811 :> int)
      | M_M680X_CPU12 -> (Cs_const.Mode.m680x_cpu12 :> int)
      | M_M680X_HCS08 -> (Cs_const.Mode.m680x_hcs08 :> int)
      | M_PLUS (v, v') -> to_int_mode v land to_int_mode v'
    in aux
end

let create (type a) (type b) ?(mode : a Mode.t option) (arch : (a, b) Arch.t) : (a, b) t option =
  let arch' = match arch with
    | Arch.ARM -> Const.Arch.arm
    | Arch.ARM64 -> Const.Arch.arm64
    | Arch.EVM -> Const.Arch.evm
    | Arch.M680X -> Const.Arch.m680x
    | Arch.M68K -> Const.Arch.m68k
    | Arch.MIPS -> Const.Arch.mips
    | Arch.PPC -> Const.Arch.ppc
    | Arch.SPARC -> Const.Arch.sparc
    | Arch.SYSTEMZ -> Const.Arch.sysz
    | Arch.TMS320C64X -> Const.Arch.tms320c64x
    | Arch.X86 -> Const.Arch.x86
    | Arch.XCORE -> Const.Arch.xcore
  in
  let mode' = match mode with None -> 0 | Some v -> Mode.to_int_mode v in
  match create_ffi ~arch:arch' ~mode:mode' with
  | Some h -> Some (T (arch, h))
  | None -> None

module Opt = struct
  type 'a v =
    | On        : [> `On ] v
    | Off       : [> `Off ] v
    | Att       : [> `Att ] v
    | Default   : [> `Default ] v
    | Intel     : [> `Intel ] v
    | NoRegName : [> `NoRegName ] v
    | Masm      : [> `Masm ] v

  let on = On
  let off = Off
  let att = Att
  let default = Default
  let intel = Intel
  let noregname = NoRegName
  let masm = Masm

  type 'a k =
    | Detail   : [ `On | `Off ] v -> [< Arch.any ] k
    | Syntax   : [ `Att | `Default | `Intel | `NoRegName | `Masm ] v -> [< Arch.any ] k
    | Skipdata : [ `On | `Off ] v -> [< Arch.any ] k
    | Unsigned : [ `On | `Off ] v -> [< Arch.any ] k
    | Mode     : 'a Mode.t -> 'a k

  let detail v = Detail v
  let syntax v = Syntax v
  let skipdata v = Skipdata v
  let unsigned v = Unsigned v
  let mode v = Mode v
end

let set_option (type a) (type b) (t : (a, b) t) (opt : a Opt.k) =
  let open Const in
  let (opt, value) = match opt with
    | Opt.Detail v ->
      (OptType.detail, match v with
        | On -> (OptValue.on :> int)
        | Off -> (OptValue.off :> int))
    | Opt.Mode v -> OptType.mode, Mode.to_int_mode v
    | Opt.Skipdata v ->
      (OptType.skipdata, match v with
        | On -> (OptValue.on :> int)
        | Off -> (OptValue.off :> int))
    | Opt.Syntax v ->
      (OptType.syntax, match v with
        | Att -> (OptValue.syntax_att :> int)
        | Default -> (OptValue.syntax_default :> int)
        | Intel -> (OptValue.syntax_intel :> int)
        | NoRegName -> (OptValue.syntax_noregname :> int)
        | Masm -> (OptValue.syntax_masm :> int))
    | Opt.Unsigned v ->
      (OptType.unsigned, match v with
        | On -> (OptValue.on :> int)
        | Off -> (OptValue.off :> int))
  in set_option_ffi (handle t) opt value

let disassemble_only ?(count = -1L) ?mode ~arch ~addr buf =
  match create ?mode arch with
  | None -> None
  | Some ctx -> Some (disassemble ctx ~addr ~count buf)
