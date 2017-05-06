#!/usr/bin/env python


import os
import argparse

import shutil
import r2pipe as r2p


def get_args():
    parser = argparse.ArgumentParser(description=("Analysis of decrypted crackme"))
    parser.add_argument("-f", "--crackme-file", help="Path to crackme")

    args = parser.parse_args()

    return args


def bytes2str(bytes):
    return "".join([chr(i) for i in bytes])


def analysis(crackme_file):
    print "Open %s with Radare2..\n" % crackme_file
    r = r2p.open(crackme_file, flags=["-w"])

    def cmd(c):
        print
        print "[r2]> %s" % c
        print
        print r.cmd(c)
        print

    base = 0x00400000
    payload_offset = 0x400570
    main_offset = 0x40074c
    var_offset = 0x00400754
    xor_val = 0xc

    print
    print "Now we have everything decrypted."
    print "Lets go to see the address in 'rax' - 0x%08x" % payload_offset

    cmd("s 0x%08x" % payload_offset)
    print "Analyse function at current offset.."
    cmd("af")
    print "And dissasemble it.."
    cmd("pdf")
    print "We can see this is the standard entry code of a ELF executable"
    print "linked to the standard library libc."
    print
    print "What we know for certain is that the call holds the address of main as"
    print "first argument - 0x%08x. So lets go check it.." % main_offset
    cmd("s 0x%08x" % main_offset)
    cmd("af")
    cmd("pdf")

    patch_cmds = ["s 0x%08x" % (var_offset - base + 0x3), "wx %02x" % xor_val]

    print "What we can see is that the local variable at 0x%08x is 0x1" % var_offset
    print "and it is compared with 0x0 at 0x%08x. The jump must not be taken in order to" % 0x004007a5
    print "to print 'cracked'. So we must patch the byte at 0x%08x + 0x3 with 0x0." % var_offset
    print "0x0 XORed with anything is 'anything' so it is the easiest patch possible and we can apply"
    print "it to the original (don't forget the base calculation):"
    print
    print "abrams_crackme_2017-patch.r2:"
    print
    print "\n".join(patch_cmds)

    patch_file = os.path.join(os.path.dirname(crackme_file), "crack-patch.r2")
    open(patch_file, "w").write("\n".join(patch_cmds))

    print
    print "Apply patch as:"
    print
    print "   $> r2 -w -i ./%s ./abrams_crackme_2017" % (os.path.basename(patch_file))
    print


def main():
    args = get_args()

    crackme_fl = os.path.abspath(args.crackme_file)
    analysis(crackme_fl)


if __name__ == "__main__":
    main()
