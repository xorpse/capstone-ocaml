# Capstone Disassembler Engine
# By Dang Hoang Vu, 2013
from __future__ import print_function
import sys, re, subprocess

include = [ 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'ppc.h', 'sparc.h', 'systemz.h', 'xcore.h' ]

template = {
    'header': "(* For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.ml] *)\n",
    'footer': "",
    'line_format': 'let _%s = %s;;\n',
    'out_file': '%s_const.ml',
    # prefixes for constant filenames of all archs - case sensitive
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

def gen():
    global include, template
    incl_dir = subprocess.check_output(['pkg-config', '--cflags', 'capstone'])[2:].decode("ascii").strip() + '/'
    for target in include:
        prefix = template[target]
        outfile = open(template['out_file'] %(prefix), 'wb')   # open as binary prevents windows newlines
        outfile.write((template['header'] % (prefix)).encode("utf-8"))

        lines = open(incl_dir + target).readlines()

        count = 0
        for line in lines:
            line = line.strip()

            if line.startswith(MARKUP):  # markup for comments
                outfile.write(("\n%s%s%s\n" %(template['comment_open'], \
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
                    elif len(f) > 1 and f[1] == '=':
                        rhs = ''.join(f[2:])
                    else:
                        rhs = str(count)
                        count += 1

                    try:
                        count = int(rhs) + 1
                        if (count == 1):
                            outfile.write(("\n").encode("utf-8"))
                    except ValueError:
                        # ocaml uses lsl for '<<', lor for '|'
                        rhs = rhs.replace('<<', ' lsl ')
                        rhs = rhs.replace('|', ' lor ')
                        # ocaml variable has _ as prefix
                        if rhs[0].isalpha():
                            rhs = '_' + rhs

                    outfile.write((template['line_format'] %(f[0].strip(), rhs)).encode("utf-8"))

        outfile.write((template['footer']).encode("utf-8"))
        outfile.close()

def main():
    try:
        gen()
    except:
        raise RuntimeError("Error generating bindings")

if __name__ == "__main__":
    main()
