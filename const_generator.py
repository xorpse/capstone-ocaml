# Capstone Disassembler Engine
# By Dang Hoang Vu, 2013
from __future__ import print_function
from io import StringIO
import sys, re, subprocess

include = [ 'capstone.h', 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'ppc.h', 'sparc.h', 'systemz.h', 'xcore.h' ]

template = {
    'header': "(* For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.ml] *)\n",
    'footer': "",
    'ml_out_file': '%s_const.ml',
    'c_out_file': '%s_const_stubs.c',
    'h_out_file': '%s_const_stubs.h',
    # prefixes for constant filenames of all archs - case sensitive
    'capstone.h': 'cs',
    'arm.h': 'arm',
    'arm64.h': 'arm64',
    'mips.h': 'mips',
    'x86.h': 'x86',
    'ppc.h': 'ppc',
    'sparc.h': 'sparc',
    'systemz.h': 'sysz',
    'xcore.h': 'xcore',
    'comment_open': '(*',
    'comment_close': ' *)',
}

# markup for comments to be added to autogen files
MARKUP = '//>'

remap_syms = {'syntax_default': 'default',
              'syntax_intel': 'intel',
              'syntax_att': 'att',
              'syntax_noregname': 'noregname'}
#              'asr': 'asr_imm',
#              'lsl': 'lsl_imm',
#              'lsr': 'lsr_imm',
#              'ror': 'ror_imm',
#              'rrx': 'rrx_imm'}

skip_fns = ('ml_capstone_to_cs_mode', 'ml_capstone_to_cs_arch', 'ml_capstone_to_cs_opt')


def val_int(x):
    return (x << 1) + 1


def caml_hash_variant(tag):
    accu = 0
    for c in tag.encode('latin1'):
        accu = 223 * accu + c
    accu = accu & ((1 << 31) - 1)
    return val_int(accu - (1 << 31) if accu > 0x3FFFFFFF else accu)


def gen():
    global include, template
    incl_dir = subprocess.check_output(['pkg-config', '--cflags', 'capstone'])[2:].decode("ascii").strip() + '/'
    # initalise with (nicer) defaults not found in capstone.h but in stubs.ml
    syms = set()
    for target in include:
        mapper = dict()
        local_vars = dict()
        prefix = template[target]
        ml_outfile = open(template['ml_out_file'] %(prefix), 'wb')   # open as binary prevents windows newlines
        c_outfile = open(template['c_out_file'] %(prefix), 'wb')   # open as binary prevents windows newlines
        h_outfile = open(template['h_out_file'] %(prefix), 'wb')   # open as binary prevents windows newlines

        ml_outfile.write((template['header'] % (prefix)).encode("utf-8"))

        # Make cpp process trivial substitutions
        lines = subprocess.check_output(['cpp', incl_dir + target]).decode('utf-8').splitlines()

        count = 0
        for line in lines:
            line = line.strip()

            if line.startswith(MARKUP):  # markup for comments
                ml_outfile.write(("\n%s%s%s\n" %(template['comment_open'], \
                                                 line.replace(MARKUP, ''), \
                                                 template['comment_close']) ).encode("utf-8"))
                continue

            if line == '' or line.startswith('//'):
                continue

            if not line.startswith(prefix.upper()):
                continue

            tmp = line.strip().split(',')
            for t in tmp:
                t = t.strip()
                if not t or t.startswith('//'): continue
                f = re.split('\s+', t)

                if f[0].startswith(prefix.upper()):
                    if len(f) > 1 and f[1] not in '//=':
                        print("Error: Unable to convert %s" % f)
                        continue
                    #elif len(f) > 1 and f[1] == '=':
                    #    rhs = ''.join(f[2:])
                    #else:
                    #    rhs = str(count)
                    #    count += 1

                    # really bad...
                    #rhs = str(eval(rhs, local_vars))
                    #local_vars[f[0].strip()] = rhs

                    # ocaml uses lsl for '<<', lor for '|'
                    #rhs = rhs.replace('<<', ' lsl ')
                    #rhs = rhs.replace('|', ' lor ')

                    typ = f[0].split('_')[1]
                    sym = '_'.join(f[0].split('_')[2:]).lower()

                    if sym[0].isdigit():
                        sym = '_'.join([typ.lower(), sym])

                    sym = remap_syms.get(sym, sym).title()

                    sym_name = 'CAPSTONE_ML_SYM_' + sym.upper()
                    lhs = f[0].strip()

                    syms.add((sym_name, sym))

                    if lhs.endswith('_ENDING'):
                        continue

                    if mapper.get(typ, None) is None:
                        mapper[typ] = [(lhs, sym_name, sym)]
                    else:
                        mapper[typ].append((lhs, sym_name, sym))
                    #if mapper.get(typ, None) is None:
                    #    mapper[typ] = [(lhs, rhs)]
                    #else:
                    #    mapper[typ].append((lhs, rhs))


        c2ml = StringIO()
        ml2c = StringIO()
        mlty = StringIO()
        mlcmp = StringIO()
        hstr = StringIO()

        c_outfile.write("#include <math.h>\n".encode('utf-8'))
        c_outfile.write("#include <capstone/capstone.h>\n".encode('utf-8'))
        c_outfile.write((('#include "' + template['h_out_file'] + '"\n\n') %(prefix)).encode('utf-8'))
        c_outfile.write('#include "capstone_poly_var_syms.h"\n'.encode('utf-8'))

        hstr.write('#ifndef _ML_CAPSTONE_%s_STUBS_H_\n' %(prefix.upper()))
        hstr.write('#define _ML_CAPSTONE_%s_STUBS_H_\n\n' %(prefix.upper()))

        hstr.write("#include <caml/mlvalues.h>\n")
        hstr.write("#include <caml/memory.h>\n")
        hstr.write("#include <caml/alloc.h>\n")
        hstr.write("#include <caml/custom.h>\n")
        hstr.write("#include <caml/fail.h>\n")
        hstr.write("#include <caml/callback.h>\n\n")

        for k, v in mapper.items():
            hstr.write("extern value ml_capstone_to_%s_%s(unsigned int v);\n" %(prefix, k.lower()))
            hstr.write("extern unsigned int ml_%s_%s_to_capstone(value v);\n\n" %(prefix, k.lower()))

            if 'ml_capstone_to_%s_%s' %(prefix, k.lower()) not in skip_fns:
                c2ml.write("value ml_capstone_to_%s_%s(unsigned int v) {\n" %(prefix, k.lower()))
                c2ml.write("  CAMLparam0();\n")
                c2ml.write("  switch (v) {\n")

            ml2c.write("unsigned int ml_%s_%s_to_capstone(value v) {\n" %(prefix, k.lower()))
            ml2c.write("  CAMLparam1(v);\n")
            ml2c.write("  switch (v) {\n")

            mlty.write("type %s_%s = [\n" %(prefix, k.lower()))

            mlcmp.write("int ml_%s_%s_compare(value u, value v) {\n" %(prefix, k.lower()))
            mlcmp.write("  CAMLparam2(u, v);\n")
            mlcmp.write("  int x = ml_{0}_{1}_to_capstone(u) - ml_{0}_{1}_to_capstone(v);\n".format(prefix, k.lower()))
            mlcmp.write("  CAMLreturn(Val_int(x==0 ? 0 : x/abs(x)));\n")
            mlcmp.write("}\n\n")

            for (vv, sym_name, sym) in v:
                if 'ml_capstone_to_%s_%s' %(prefix, k.lower()) not in skip_fns:
                    c2ml.write("  case %s:\n" %(vv))
                    c2ml.write("    CAMLreturn(%s);\n" %(sym_name))
                ml2c.write("  case %s:\n" %(sym_name))
                ml2c.write("    CAMLreturn(%s);\n" %(vv))
                mlty.write("  | `%s\n" %(sym))

            if 'ml_capstone_to_%s_%s' %(prefix, k.lower()) not in skip_fns:
                c2ml.write("  default:\n")
                c2ml.write("    caml_invalid_argument(\"ml_capstone_to_%s_%s: impossible value\");\n" %(prefix, k.lower()))
                c2ml.write("  }\n")
                c2ml.write("}\n")

            ml2c.write("  default:\n")
            ml2c.write("    caml_invalid_argument(\"ml_%s_%s_to_capstone: impossible value\");\n" %(prefix, k.lower()))
            ml2c.write("  }\n")
            ml2c.write("}\n")

            mlty.write("]\n")

            if 'ml_%s_%s_to_capstone' %(prefix, k.lower()) not in skip_fns:
                c2ml.write('\n')
            ml2c.write('\n')
            mlty.write('\n')


        hstr.write('#endif')

        c_outfile.write(c2ml.getvalue().encode('utf-8'))
        c_outfile.write(ml2c.getvalue().encode('utf-8'))
        c_outfile.write(mlcmp.getvalue().encode('utf-8'))

        h_outfile.write(hstr.getvalue().encode('utf-8'))

        ml_outfile.write(mlty.getvalue().encode('utf-8'))

        c2ml.close()
        ml2c.close()
        mlty.close()
        mlcmp.close()

        ml_outfile.close()
        c_outfile.close()

    poly_hf = open("capstone_poly_var_syms.h", "wb")
    poly_h = StringIO()

    poly_h.write("#ifndef _CAPSTONE_POLY_VAR_SYMS_H_\n")
    poly_h.write("#define _CAPSTONE_POLY_VAR_SYMS_H_\n\n")
    for (name, sym) in syms:
        poly_h.write("#define {} ({})\n".format(name, caml_hash_variant(sym)))
    poly_h.write("\n#endif\n");

    poly_hf.write(poly_h.getvalue().encode('utf-8'))
    poly_hf.close()

def main():
    try:
        gen()
    except:
        raise RuntimeError("Error generating bindings")

if __name__ == "__main__":
    main()
