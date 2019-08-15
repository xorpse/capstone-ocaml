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

type operand = Cs_const.cs_op_type

type group = Cs_const.cs_group_type

type handle

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

type mode =
  [ `LITTLE_ENDIAN
  | `ARM
  | `MODE_16
  | `M68K_000
  | `M680X_6301
  | `MODE_32
  | `M68K_010
  | `MIPS32
  | `M680X_6309
  | `MODE_64
  | `M68K_020
  | `MIPS64
  | `M680X_6800
  | `THUMB
  | `MICRO
  | `V9
  | `QPX
  | `M68K_030
  | `M680X_6801
  | `MCLASS
  | `MIPS3
  | `M68K_040
  | `M680X_6805
  | `V8
  | `MIPS32R6
  | `M68K_060
  | `M680X_6808
  | `MIPS2
  | `M680X_6809 ]

type opt = [ `Syntax of [ `Default | `Intel | `Att | `Noregname ]
           | `Detail of [ `On | `Off ]
           | `Mode of mode
           | `Skipdata of [ `On | `Off ] ]

let mode_to_cs_mode = function
  | `LITTLE_ENDIAN -> `LITTLE_ENDIAN_ARM
  | `ARM -> `LITTLE_ENDIAN_ARM
  | `MODE_16 -> `MODE_16_M68K_000_M680X_6301
  | `M68K_000 -> `MODE_16_M68K_000_M680X_6301
  | `M680X_6301 -> `MODE_16_M68K_000_M680X_6301
  | `MODE_32 -> `MODE_32_M68K_010_MIPS32_M680X_6309
  | `M68K_010 -> `MODE_32_M68K_010_MIPS32_M680X_6309
  | `MIPS32 -> `MODE_32_M68K_010_MIPS32_M680X_6309
  | `M680X_6309 -> `MODE_32_M68K_010_MIPS32_M680X_6309
  | `MODE_64 -> `MODE_64_M68K_020_MIPS64_M680X_6800
  | `M68K_020 -> `MODE_64_M68K_020_MIPS64_M680X_6800
  | `MIPS64 -> `MODE_64_M68K_020_MIPS64_M680X_6800
  | `M680X_6800 -> `MODE_64_M68K_020_MIPS64_M680X_6800
  | `THUMB -> `THUMB_MICRO_V9_QPX_M68K_030_M680X_6801
  | `MICRO -> `THUMB_MICRO_V9_QPX_M68K_030_M680X_6801
  | `V9 -> `THUMB_MICRO_V9_QPX_M68K_030_M680X_6801
  | `QPX -> `THUMB_MICRO_V9_QPX_M68K_030_M680X_6801
  | `M68K_030 -> `THUMB_MICRO_V9_QPX_M68K_030_M680X_6801
  | `M680X_6801 -> `THUMB_MICRO_V9_QPX_M68K_030_M680X_6801
  | `MCLASS -> `MCLASS_MIPS3_M68K_040_M680X_6805
  | `MIPS3 -> `MCLASS_MIPS3_M68K_040_M680X_6805
  | `M68K_040 -> `MCLASS_MIPS3_M68K_040_M680X_6805
  | `M680X_6805 -> `MCLASS_MIPS3_M68K_040_M680X_6805
  | `V8 -> `V8_MIPS32R6_M68K_060_M680X_6808
  | `MIPS32R6 -> `V8_MIPS32R6_M68K_060_M680X_6808
  | `M68K_060 -> `V8_MIPS32R6_M68K_060_M680X_6808
  | `M680X_6808 -> `V8_MIPS32R6_M68K_060_M680X_6808
  | `MIPS2 -> `MIPS2_M680X_6809
  | `M680X_6809 -> `MIPS2_M680X_6809

external create_ffi : arch:Cs_const.cs_arch -> mode:(Cs_const.cs_mode list) -> handle option = "ml_capstone_create"

external disasm_arm_ffi : Cs_const.cs_arch -> handle -> bytes -> Int64.t -> Int64.t -> arm_insn list = "ml_capstone_disassemble"
external disasm_arm64_ffi : Cs_const.cs_arch -> handle -> bytes -> Int64.t -> Int64.t -> arm64_insn list = "ml_capstone_disassemble"
external disasm_mips_ffi : Cs_const.cs_arch -> handle -> bytes -> Int64.t -> Int64.t -> mips_insn list = "ml_capstone_disassemble"
external disasm_ppc_ffi : Cs_const.cs_arch -> handle -> bytes -> Int64.t -> Int64.t -> ppc_insn list = "ml_capstone_disassemble"
external disasm_sparc_ffi : Cs_const.cs_arch -> handle -> bytes -> Int64.t -> Int64.t -> sparc_insn list = "ml_capstone_disassemble"
external disasm_sysz_ffi : Cs_const.cs_arch -> handle -> bytes -> Int64.t -> Int64.t -> sysz_insn list = "ml_capstone_disassemble"
external disasm_x86_ffi : Cs_const.cs_arch -> handle -> bytes -> Int64.t -> Int64.t -> x86_insn list = "ml_capstone_disassemble"
external disasm_xcore_ffi : Cs_const.cs_arch -> handle -> bytes -> Int64.t -> Int64.t -> xcore_insn list = "ml_capstone_disassemble"

external set_option_ffi: handle -> Cs_const.cs_opt_type -> [ Cs_const.cs_opt_value | Cs_const.cs_mode ] -> unit = "ml_capstone_set_option"
external version: unit -> int = "ml_capstone_version"

module Arch = struct
  type 'a t =
    | Arm     : arm_insn t
    | Arm64   : arm64_insn t
    | Mips    : mips_insn t
    | Ppc     : ppc_insn t
    | Sparc   : sparc_insn t
    | SystemZ : sysz_insn t
    | X86     : x86_insn t
    | Xcore   : xcore_insn t
end

type 'a t = T : 'a Arch.t * handle -> 'a t

let arch : type a. a t -> a Arch.t =
  function T (arch, _) -> arch

let handle = function T (_, h) -> h

let disassemble (type a) (t : a t) ~(addr : int64) ?(count : int64 = -1L) (buf : bytes)
  : a list = match t with
  | T (Arch.Arm, h) -> disasm_arm_ffi `ARM h buf addr count
  | T (Arch.Arm64, h) -> disasm_arm64_ffi `ARM64 h buf addr count
  | T (Arch.Mips, h) -> disasm_mips_ffi `MIPS h buf addr count
  | T (Arch.Ppc, h) -> disasm_ppc_ffi `PPC h buf addr count
  | T (Arch.Sparc, h) -> disasm_sparc_ffi `SPARC h buf addr count
  | T (Arch.SystemZ, h) -> disasm_sysz_ffi `SYSZ h buf addr count
  | T (Arch.X86, h) -> disasm_x86_ffi `X86 h buf addr count
  | T (Arch.Xcore, h) -> disasm_xcore_ffi `XCORE h buf addr count

(* TODO: can we make this not require the conversion *)
let create (type a) ?(mode : mode list = []) (arch : a Arch.t) : a t option =
  let arch' = match arch with
    | Arch.Arm -> `ARM
    | Arch.Arm64 -> `ARM64
    | Arch.Mips -> `MIPS
    | Arch.Ppc -> `PPC
    | Arch.Sparc -> `SPARC
    | Arch.SystemZ -> `SYSZ
    | Arch.X86 -> `X86
    | Arch.Xcore -> `XCORE
  in
  match create_ffi ~arch:arch' ~mode:(List.map mode_to_cs_mode mode) with
  | Some h -> Some (T (arch, h))
  | None -> None

let set_option t opt =
  let (opt, value) = match opt with
    | `Syntax v ->
      (`SYNTAX, match v with
        | `Default -> `OFF_SYNTAX_DEFAULT
        | `Intel -> `SYNTAX_INTEL
        | `Att -> `SYNTAX_ATT
        | `Noregname -> `ON_SYNTAX_NOREGNAME)
    | `Detail v ->
      (`DETAIL, match v with
        | `On -> `ON_SYNTAX_NOREGNAME
        | `Off -> `OFF_SYNTAX_DEFAULT)
    | `Mode m -> (`MODE, mode_to_cs_mode m)
    | `Skipdata v ->
      (`SKIPDATA, match v with
        | `On -> `ON_SYNTAX_NOREGNAME
        | `Off -> `OFF_SYNTAX_DEFAULT)
  in
  set_option_ffi (handle t) opt value

let disassemble_only ~arch ~mode ~addr ?(count = -1L) buf =
  match create ~mode arch with
  | None -> None
  | Some ctx -> Some (disassemble ctx ~addr ~count buf)
