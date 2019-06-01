module List = ListLabels
module String = StringLabels

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
    "arm_reg", Hashtbl.of_seq @@ List.to_seq [
      "r13", "sp_r13";
      "sp",  "sp_r13";
      "r14", "lr_r14";
      "lr",  "lr_r14";
      "pc",  "pc_r15";
      "r15", "pc_r15";
      "r9",  "sb_r9";
      "sb",  "sb_r9";
      "r10", "sl_r10";
      "sl",  "sl_r10";
      "r12", "ip_r12";
      "ip",  "ip_r12";
    ];
    "arm64_reg", Hashtbl.of_seq @@ List.to_seq [
      "ip0", "ip0_x16";
      "x16", "ip0_x16";
      "ip1", "ip1_x17";
      "x17", "ip1_x17";
      "lr",  "lr_x30";
      "x30", "lr_x30";
    ];
    "mips_reg", Hashtbl.of_seq @@ List.to_seq [
     "reg_0",  "zero_r0";     "zero", "zero_r0";
     "reg_1",  "at_r1";       "at",   "at_r1";
     "reg_2",  "v0_r2";       "v0",   "v0_r2";
     "reg_3",  "v1_r3";       "v1",   "v1_r3";
     "reg_4",  "a0_r4";       "a0",   "a0_r4";
     "reg_5",  "a1_r5";       "a1",   "a1_r5";
     "reg_6",  "a2_r6";       "a2",   "a2_r6";
     "reg_7",  "a3_r7";       "a3",   "a3_r7";
     "reg_8",  "t0_r8";       "t0",   "t0_r8";
     "reg_9",  "t1_r9";       "t1",   "t1_r9";
     "reg_10", "t2_r10";      "t2",   "t2_r10";
     "reg_11", "t3_r11";      "t3",   "t3_r11";
     "reg_12", "t4_r12";      "t4",   "t4_r12";
     "reg_13", "t5_r13";      "t5",   "t5_r13";
     "reg_14", "t6_r14";      "t6",   "t6_r14";
     "reg_15", "t7_r15";      "t7",   "t7_r15";
     "reg_16", "s0_r16";      "s0",   "s0_r16";
     "reg_17", "s1_r17";      "s1",   "s1_r17";
     "reg_18", "s2_r18";      "s2",   "s2_r18";
     "reg_19", "s3_r19";      "s3",   "s3_r19";
     "reg_20", "s4_r20";      "s4",   "s4_r20";
     "reg_21", "s5_r21";      "s5",   "s5_r21";
     "reg_22", "s6_r22";      "s6",   "s6_r22";
     "reg_23", "s7_r23";      "s7",   "s7_r23";
     "reg_24", "t8_r24";      "t8",   "t8_r24";
     "reg_25", "t9_r25";      "t9",   "t9_r25";
     "reg_26", "k0_r26";      "k0",   "k0_r26";
     "reg_27", "k1_r27";      "k1",   "k1_r27";
     "reg_28", "gp_r28";      "gp",   "gp_r28";
     "reg_29", "sp_r29";      "sp",   "sp_r29";
     "reg_30", "fp_s8_r30";   "fp",   "fp_s8_r30";   "s8", "fp_s8_r30";
     "reg_31", "ra_r31";      "ra",   "ra_r31";
     "ac0",    "lo0_hi0_ac0"; "hi0",  "lo0_hi0_ac0";
     "ac1",    "lo1_hi1_ac1"; "hi1",  "lo1_hi1_ac1";
     "ac2",    "lo2_hi2_ac2"; "hi2",  "lo2_hi2_ac2";
     "ac3",    "lo3_hi3_ac3"; "hi3",  "lo3_hi3_ac3";
     "hi0",    "lo0_hi0_ac0"; "lo0",  "lo0_hi0_ac0";
     "hi1",    "lo1_hi1_ac1"; "lo1",  "lo1_hi1_ac1";
     "hi2",    "lo2_hi2_ac2"; "lo2",  "lo2_hi2_ac2";
     "hi3",    "lo3_hi3_ac3"; "lo3",  "lo3_hi3_ac3";
    ];
    "x86_reg", Hashtbl.of_seq @@ List.to_seq [
      "repe", "rep_repe";
      "rep",  "rep_repe";
    ];
]

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

module Syms = struct
  module T = struct
    type t = string * string

    let compare = compare
  end

  include T
  module Set = Set.Make(T)
end

module Option = struct
  let return v = Some v
  let (>>=) v f = match v with None -> None | Some v' -> f v'
  let (>>|) v f = v >>= (fun v' -> Some (f v'))

  let value ~default = function None -> default | Some v -> v
  let value_exn = function None -> failwith "no value" | Some v -> v
end

(* Utility functions *)

let rec drop n xs =
  if n > 0 then match xs with
    | [] -> xs
    | _ :: xs' -> drop (pred n) xs'
  else
    xs

let rec last_exn = function
  | [] -> failwith "empty list"
  | [x] -> x
  | _ :: xs -> last_exn xs

let is_digit = function '0' .. '9' -> true | _ -> false

let trim =
  let aux_l = Str.split (Str.regexp "^[ \r\n\t]+") in
  let aux_r = Str.split (Str.regexp "[ \r\n\t]+$") in
  fun v -> match aux_l v with
    | [] -> ""
    | x :: _ -> List.hd @@ aux_r x

let starts_with s v =
  Str.string_match (Str.regexp_string s) v 0

let ends_with s v =
  let slen = String.length s in
  let vlen = String.length v in
  if slen > vlen then false
  else Str.string_match (Str.regexp_string s) v (vlen - slen)

let split_ws =
  let aux = Str.split (Str.regexp "[ \t\r\n]+") in
  fun v -> aux v

let open_out_file prefix suffix_key =
  open_out @@ prefix ^ Hashtbl.find template suffix_key

let with_process_in p ~f =
  let op = Unix.open_process_in p in
  let v = f op in
  ignore @@ Unix.close_process_in op;
  v

(* Get type name from enum definition *)
let get_typename line =
  if starts_with "typedef" line then (
    match split_ws line with
    | _ :: "enum" :: typ :: _ -> Some typ
    | _ -> None
  ) else if starts_with "enum" line then (
    match split_ws line with
    | _ :: typ :: _ -> Some typ
    | _ -> None
  ) else
    None

(* Update syms and mapper based on current line part [t] *)
let get_syms ~mapper ~typ ~prefix syms t =
  let open Option in
  if t == "" || starts_with "//" t then syms
  else match split_ws t with
    | _ :: sep :: _ when not @@ List.mem sep ~set:["="; "/"; "//"] -> syms
    | name :: _ when starts_with (String.uppercase_ascii prefix) name -> begin
      let sym = String.split_on_char ~sep:'_' name |>
        drop 2 |>
        String.concat ~sep:"_" |>
        String.uppercase_ascii
      in

      let sym = if is_digit sym.[0] then
          let pr = String.split_on_char ~sep:'_' typ |>
                   last_exn |>
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

      if Syms.Set.mem (sym_name, sym) syms && Hashtbl.mem mapper typ then
        syms
      else
        let syms = Syms.Set.add (sym_name, sym) syms in
        if ends_with "_ENDING" lhs then
          syms
        else match Hashtbl.find_opt mapper typ with
          | None ->
            Hashtbl.add mapper typ [(lhs, sym_name, sym)];
            syms
          | Some mt ->
            Hashtbl.replace mapper typ ((lhs, sym_name, sym) :: mt);
            syms
    end
    | _ -> syms

let generate () =
  let syms = List.fold_left includes ~init:Syms.Set.empty ~f:(fun syms target ->
      let prefix  = Hashtbl.find template target in
      let ml_file = open_out_file prefix "ml_suffix" in
      let c_file  = open_out_file prefix "c_suffix" in
      let h_file  = open_out_file prefix "h_suffix" in

      let mapper = Hashtbl.create 100 in

      let syms' = with_process_in ("cpp /usr/include/capstone/" ^ target) ~f:(fun p ->
          let rec process_lines ?typ syms =
            match try Some (trim @@ input_line p) with End_of_file -> None with
            | None -> syms
            | Some line ->
              if line = "" || starts_with "//" line then
                process_lines ?typ syms
              else
                match get_typename line with
                | Some typ -> process_lines ~typ syms
                | _ ->
                  if not @@ starts_with (String.uppercase_ascii prefix) line then
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

          Printf.bprintf c2ml {|value ml_capstone_to_%s(unsigned int v) {
  CAMLparam0();
  switch (v) {
|} k_lower;

          Printf.bprintf ml2c {|value ml_capstone_to_%s(int v) {
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

          List.iter (List.rev v) ~f:(fun (vv, sym_name, sym) ->
              Printf.bprintf c2ml {|  case %s:
    CAMLreturn(%s);
|} vv sym_name;
              Printf.bprintf ml2c {|  case %s:
    CAMLreturn(%s);
|} sym_name vv;
              Printf.bprintf mlty {|  | `%s
|} sym;
            );

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
#ifndef _CAPSTONE_POLY_VAR_SYMS_H_
|};

  Syms.Set.iter (fun (name, sym) ->
      Printf.fprintf ph_file {|#define %s (%ld)
|} name (caml_hash_variant sym)
    ) syms;

  Printf.fprintf ph_file "\n#endif\n";
  close_out ph_file

let () =
  try generate () with _ -> print_endline "error generating bindings"
