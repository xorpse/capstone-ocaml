let includes = [
    "capstone.h"; "arm.h"; "arm64.h"; "mips.h"; "ppc.h";
    "sparc.h"; "systemz.h"; "x86.h"; "xcore.h"
]

let template = Hashtbl.of_seq @@ List.to_seq [
    (* filename templates *)
    "ml_suffix",  "_const.ml";
    "c_suffix",   "_const_stubs.c";
    "h_suffix",   "_const_stubs.h";
    (* header to module mapping *)
    "capstone.h", "cs";
    "arm.h",      "arm";
    "arm64.h",    "arm64";
    "mips.h",     "mips";
    "ppc.h",      "ppc";
    "sparc.h",    "sparc";
    "systemz.h",  "sysz";
    "x86.h",      "x86";
    "xcore.h",    "xcore";
]

let variant_mapping = Hashtbl.of_seq @@ List.to_seq [
    "cs_mode", Hashtbl.of_seq @@ List.to_seq [
      "LITTLE_ENDIAN", "LITTLE_ENDIAN_ARM";
      "ARM",           "LITTLE_ENDIAN_ARM";
      "MODE_16",       "MODE_16_M68K_000_M680X_6301";
      "M68K_000",      "MODE_16_M68K_000_M680X_6301";
      "M680X_6301",    "MODE_16_M68K_000_M680X_6301";
      "MODE_32",       "MODE_32_M68K_010_MIPS32_M680X_6309";
      "M68K_010",      "MODE_32_M68K_010_MIPS32_M680X_6309";
      "MIPS32",        "MODE_32_M68K_010_MIPS32_M680X_6309";
      "M680X_6309",    "MODE_32_M68K_010_MIPS32_M680X_6309";
      "MODE_64",       "MODE_64_M68K_020_MIPS64_M680X_6800";
      "M68K_020",      "MODE_64_M68K_020_MIPS64_M680X_6800";
      "MIPS64",        "MODE_64_M68K_020_MIPS64_M680X_6800";
      "M680X_6800",    "MODE_64_M68K_020_MIPS64_M680X_6800";
      "THUMB",         "THUMB_MICRO_V9_QPX_M68K_030_M680X_6801";
      "MICRO",         "THUMB_MICRO_V9_QPX_M68K_030_M680X_6801";
      "V9",            "THUMB_MICRO_V9_QPX_M68K_030_M680X_6801";
      "QPX",           "THUMB_MICRO_V9_QPX_M68K_030_M680X_6801";
      "M68K_030",      "THUMB_MICRO_V9_QPX_M68K_030_M680X_6801";
      "M680X_6801",    "THUMB_MICRO_V9_QPX_M68K_030_M680X_6801";
      "MCLASS",        "MCLASS_MIPS3_M68K_040_M680X_6805";
      "MIPS3",         "MCLASS_MIPS3_M68K_040_M680X_6805";
      "M68K_040",      "MCLASS_MIPS3_M68K_040_M680X_6805";
      "M680X_6805",    "MCLASS_MIPS3_M68K_040_M680X_6805";
      "V8",            "V8_MIPS32R6_M68K_060_M680X_6808";
      "MIPS32R6",      "V8_MIPS32R6_M68K_060_M680X_6808";
      "M68K_060",      "V8_MIPS32R6_M68K_060_M680X_6808";
      "M680X_6808",    "V8_MIPS32R6_M68K_060_M680X_6808";
      "MIPS2",         "MIPS2_M680X_6809";
      "M680X_6809",    "MIPS2_M680X_6809";
    ];
    "cs_opt_value", Hashtbl.of_seq @@ List.to_seq [
      "OFF",              "OFF_SYNTAX_DEFAULT";
      "SYNTAX_DEFAULT",   "OFF_SYNTAX_DEFAULT";
      "ON",               "ON_SYNTAX_NOREGNAME";
      "SYNTAX_NOREGNAME", "ON_SYNTAX_NOREGNAME";
    ];
    "arm_reg", Hashtbl.of_seq @@ List.to_seq [
      "R13", "SP_R13";
      "SP",  "SP_R13";
      "R14", "LR_R14";
      "LR",  "LR_R14";
      "PC",  "PC_R15";
      "R15", "PC_R15";
      "R9",  "SB_R9";
      "SB",  "SB_R9";
      "R10", "SL_R10";
      "SL",  "SL_R10";
      "R11", "FP_R11";
      "FP",  "FP_R11";
      "R12", "IP_R12";
      "IP",  "IP_R12";
    ];
    "arm64_reg", Hashtbl.of_seq @@ List.to_seq [
      "IP0", "IP0_X16";
      "X16", "IP0_X16";
      "IP1", "IP1_X17";
      "X17", "IP1_X17";
      "FP",  "FP_X29";
      "X29", "FP_X29";
      "LR",  "LR_X30";
      "X30", "LR_X30";
    ];
    "mips_reg", Hashtbl.of_seq @@ List.to_seq [
     "REG_0",  "ZERO_R0";     "ZERO", "ZERO_R0";
     "REG_1",  "AT_R1";       "AT",   "AT_R1";
     "REG_2",  "V0_R2";       "V0",   "V0_R2";
     "REG_3",  "V1_R3";       "V1",   "V1_R3";
     "REG_4",  "A0_R4";       "A0",   "A0_R4";
     "REG_5",  "A1_R5";       "A1",   "A1_R5";
     "REG_6",  "A2_R6";       "A2",   "A2_R6";
     "REG_7",  "A3_R7";       "A3",   "A3_R7";
     "REG_8",  "T0_R8";       "T0",   "T0_R8";
     "REG_9",  "T1_R9";       "T1",   "T1_R9";
     "REG_10", "T2_R10";      "T2",   "T2_R10";
     "REG_11", "T3_R11";      "T3",   "T3_R11";
     "REG_12", "T4_R12";      "T4",   "T4_R12";
     "REG_13", "T5_R13";      "T5",   "T5_R13";
     "REG_14", "T6_R14";      "T6",   "T6_R14";
     "REG_15", "T7_R15";      "T7",   "T7_R15";
     "REG_16", "S0_R16";      "S0",   "S0_R16";
     "REG_17", "S1_R17";      "S1",   "S1_R17";
     "REG_18", "S2_R18";      "S2",   "S2_R18";
     "REG_19", "S3_R19";      "S3",   "S3_R19";
     "REG_20", "S4_R20";      "S4",   "S4_R20";
     "REG_21", "S5_R21";      "S5",   "S5_R21";
     "REG_22", "S6_R22";      "S6",   "S6_R22";
     "REG_23", "S7_R23";      "S7",   "S7_R23";
     "REG_24", "T8_R24";      "T8",   "T8_R24";
     "REG_25", "T9_R25";      "T9",   "T9_R25";
     "REG_26", "K0_R26";      "K0",   "K0_R26";
     "REG_27", "K1_R27";      "K1",   "K1_R27";
     "REG_28", "GP_R28";      "GP",   "GP_R28";
     "REG_29", "SP_R29";      "SP",   "SP_R29";
     "REG_30", "FP_S8_R30";   "FP",   "FP_S8_R30";   "S8", "FP_S8_R30";
     "REG_31", "RA_R31";      "RA",   "RA_R31";
     "AC0",    "LO0_HI0_AC0"; "HI0",  "LO0_HI0_AC0";
     "AC1",    "LO1_HI1_AC1"; "HI1",  "LO1_HI1_AC1";
     "AC2",    "LO2_HI2_AC2"; "HI2",  "LO2_HI2_AC2";
     "AC3",    "LO3_HI3_AC3"; "HI3",  "LO3_HI3_AC3";
     "HI0",    "LO0_HI0_AC0"; "LO0",  "LO0_HI0_AC0";
     "HI1",    "LO1_HI1_AC1"; "LO1",  "LO1_HI1_AC1";
     "HI2",    "LO2_HI2_AC2"; "LO2",  "LO2_HI2_AC2";
     "HI3",    "LO3_HI3_AC3"; "LO3",  "LO3_HI3_AC3";
    ];
    "sparc_reg", Hashtbl.of_seq @@ List.to_seq [
      "I6", "FP_I6";
      "FP", "FP_I6";
      "O6", "SP_O6";
      "SP", "SP_O6";
    ];
    "x86_prefix", Hashtbl.of_seq @@ List.to_seq [
      "REPE", "REP_REPE";
      "REP",  "REP_REPE";
    ];
]

module Syms = struct
  module T = struct
    type t = string * string

    let compare x y = compare (fst x) (fst y)
  end

  include T
  module Set = Set.Make(T)
  module Map = Map.Make(T)
end

(* Utility functions *)

let val_int x =
  let open Int32 in succ @@ shift_left x 1

let caml_hash_variant tag =
  let open Int32 in
  let acc = ref 0l in
  for i = 0 to String.length tag - 1 do
    acc := add (mul 223l !acc) (of_int @@ Char.code tag.[i])
  done;
  acc := logand !acc (pred (shift_left 1l 31));
  val_int @@ if !acc > 0x3fffffffl then sub !acc (shift_left 1l 31) else !acc

(* Standard library extras to avoid extra build dependencies *)

module Option = struct
  let return v = Some v
  let (>>=) v f = match v with None -> None | Some v' -> f v'
  let (>>|) v f = v >>= (fun v' -> Some (f v'))

  let value ~default = function None -> default | Some v -> v
  let value_exn = function None -> failwith "no value" | Some v -> v
end

module List = struct
  include ListLabels

  let rec drop n xs =
    if n > 0 then match xs with
      | [] -> xs
      | _ :: xs' -> drop (pred n) xs'
    else
      xs

  let hd_ex = hd
  let hd = function [] -> None | x :: _ -> Some x

  let rec last_exn = function
    | [] -> failwith "empty list"
    | [x] -> x
    | _ :: xs -> last_exn xs
end

module String = struct
  include StringLabels

  let starts_with s v =
    Str.string_match (Str.regexp_string s) v 0

  let ends_with s v =
    let slen = String.length s in
    let vlen = String.length v in
    if slen > vlen then false
    else Str.string_match (Str.regexp_string s) v (vlen - slen)
end

(* Other utility functions *)

let is_digit = function '0' .. '9' -> true | _ -> false

(* Trim whitespace, parenthesis, comments *)
let trim =
  let aux_l = Str.split (Str.regexp "^[ \r\n\t(]+") in
  let aux_r = Str.split (Str.regexp "[ \r\n\t)]+$") in
  let aux_c = Str.split (Str.regexp "//.*$") in
  let open Option in
  fun v ->
    value ~default: "" (
      aux_l v |> List.hd >>= fun v ->
      aux_c v |> List.hd >>= fun v ->
      aux_r v |> List.hd
    )

(* Split on whitespace and parenthesis *)
let split_wsbr =
  let aux = Str.split (Str.regexp "[ \t\r\n()]+") in
  fun v -> aux v

let with_file_in p ~f =
  let op = open_in p in
  let v = f op in
  ignore @@ close_in op;
  v

(* Open file for given arch [suffix_key] *)
let open_out_file prefix suffix_key =
  open_out @@ prefix ^ Hashtbl.find template suffix_key

(* Get type name from enum definition *)
let get_typename line =
  if String.starts_with "typedef" line then (
    match split_wsbr line with
    | _ :: "enum" :: typ :: _ -> Some typ
    | _ -> None
  ) else if String.starts_with "enum" line then (
    match split_wsbr line with
    | _ :: typ :: _ -> Some typ
    | _ -> None
  ) else
    None

(* Update syms and mapper based on current line part [t] *)
let get_syms ~mapper ~typ ~prefix syms t =
  let open Option in
  if t == "" || String.starts_with "//" t then syms
  else match split_wsbr t with
    | _ :: sep :: _ when sep <> "=" -> syms
    | name :: _ when String.starts_with (String.uppercase_ascii prefix) name -> begin
      let sym = String.split_on_char ~sep:'_' name |>
        List.drop 2 |>
        String.concat ~sep:"_" |>
        String.uppercase_ascii
      in

      let sym = if is_digit sym.[0] then
          let pr = String.split_on_char ~sep:'_' typ |>
                   List.last_exn |>
                   String.uppercase_ascii
          in
          pr ^ "_" ^ sym
        else
          sym
      in

      let sym = value ~default:sym @@ (Hashtbl.find_opt variant_mapping typ >>= fun tm ->
        Hashtbl.find_opt tm sym)
      in

      let sym_name = "CAPSTONE_ML_SYM_" ^ (String.uppercase_ascii sym) in
      let lhs = trim name in

      if String.ends_with "_ENDING" lhs then
        syms
      else match Hashtbl.find_opt mapper typ with
        | None ->
          Syms.Map.singleton (sym_name, sym) lhs |> Hashtbl.add mapper typ;
          Syms.Set.add (sym_name, sym) syms
        | Some mt ->
          if Syms.Map.mem (sym_name, sym) mt then
            syms
          else (
            Syms.Map.add (sym_name, sym) lhs mt |> Hashtbl.replace mapper typ;
            Syms.Set.add (sym_name, sym) syms
          )
    end
    | _ -> syms

(* Perform the .ml/.c/.h file generation *)
let generate () =
  let syms = List.fold_left includes ~init:Syms.Set.empty ~f:(fun syms target ->
      let prefix  = Hashtbl.find template target in
      let ml_file = open_out_file prefix "ml_suffix" in
      let c_file  = open_out_file prefix "c_suffix" in
      let h_file  = open_out_file prefix "h_suffix" in

      let mapper = Hashtbl.create 100 in

      let syms' = with_file_in ("/usr/include/capstone/" ^ target) ~f:(fun p ->
          let rec process_lines ?typ syms =
            match try Some (trim @@ input_line p) with End_of_file -> None with
            | None -> syms
            | Some line ->
              if line = "" || String.starts_with "//" line then
                process_lines ?typ syms
              else
                match get_typename line with
                | Some typ -> process_lines ~typ syms
                | _ ->
                  if not @@ String.starts_with (String.uppercase_ascii prefix) line then
                    process_lines ?typ syms
                  else
                    List.fold_left (List.map ~f:trim @@ String.split_on_char ~sep:',' line)
                      ~init:syms
                      ~f:(get_syms ~mapper ~typ:(Option.value_exn typ) ~prefix)
                    |> process_lines ?typ
          in
          process_lines syms
        )
      in

      let h_file_name = prefix ^ Hashtbl.find template "h_suffix" in

      Printf.fprintf c_file {|
#include <math.h>
#include <capstone/capstone.h>
#include "capstone_poly_var_syms.h"
#include "%s"

|} h_file_name;

      let prefix_upper = String.uppercase_ascii prefix in

      Printf.fprintf h_file {|
#ifndef _ML_CAPSTONE_%s_STUBS_H_
#define _ML_CAPSTONE_%s_STUBS_H_

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/callback.h>

|} prefix_upper prefix_upper;

      let c2ml = Buffer.create 100 in
      let ml2c = Buffer.create 100 in
      let mlty = Buffer.create 100 in
      let mlcmp = Buffer.create 100 in

      Hashtbl.iter (fun k v ->
          let k_lower = String.lowercase_ascii k in
          Printf.fprintf h_file {|extern value ml_capstone_to_%s(int v);
extern int ml_%s_to_capstone(value v);
|} k_lower k_lower;

          Printf.bprintf c2ml {|value ml_capstone_to_%s(int v) {
  CAMLparam0();
  switch (v) {
|} k_lower;

          Printf.bprintf ml2c {|int ml_%s_to_capstone(value v) {
  CAMLparam1(v);
  switch (v) {
|} k_lower;

          Printf.bprintf mlty {|type %s = [
|} k_lower;

          Printf.bprintf mlcmp {|int ml_%s_compare(value u, value v) {
  CAMLparam2(u, v);
  int x = ml_%s_to_capstone(u) - ml_%s_to_capstone(v);
  CAMLreturn(Val_int(x==0 ? 0 : x/abs(x)));
}
|} k_lower k_lower k_lower;

          Syms.Map.iter (fun (sym_name, sym) vv ->
              Printf.bprintf c2ml {|  case %s:
    CAMLreturn(%s);
|} vv sym_name;
              Printf.bprintf ml2c {|  case %s:
    CAMLreturn(%s);
|} sym_name vv;
              Printf.bprintf mlty {|  | `%s
|} sym;
            ) v;

          Printf.bprintf c2ml {|  default:
    caml_invalid_argument("ml_capstone_%s: impossible value");
  }
}

|} k_lower;

          Printf.bprintf ml2c {|  default:
    caml_invalid_argument("ml_capstone_%s: impossible value");
  }
}

|} k_lower;

          Printf.bprintf mlty "]\n\n";
      ) mapper;

      Printf.fprintf h_file {|#endif|};

      Buffer.output_buffer c_file c2ml;
      Buffer.output_buffer c_file ml2c;
      Buffer.output_buffer c_file mlcmp;

      Buffer.output_buffer ml_file mlty;

      close_out ml_file;
      close_out c_file;
      close_out h_file;
      syms'
    )
  in
  let ph_file = open_out "capstone_poly_var_syms.h" in

  Printf.fprintf ph_file {|#ifndef _CAPSTONE_POLY_VAR_SYMS_H_
#define _CAPSTONE_POLY_VAR_SYMS_H_
|};

  Syms.Set.iter (fun (name, sym) ->
      Printf.fprintf ph_file {|#define %s (%ld)
|} name (caml_hash_variant sym)
    ) syms;

  Printf.fprintf ph_file "\n#endif\n";
  close_out ph_file

let () =
  try generate () with _ -> print_endline "error generating bindings"
