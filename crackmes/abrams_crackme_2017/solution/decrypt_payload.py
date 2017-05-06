#!/usr/bin/env python


import os
import argparse

import shutil
import r2pipe as r2p


def get_args():
    parser = argparse.ArgumentParser(description=("Decrypt XORed part of executable code "
                                                  "then substitues it the a copy of the exec "
                                                  "and changes the key for XOR to 0x0"))
    parser.add_argument("-f", "--crackme-file", help="Path to crackme")

    args = parser.parse_args()

    return args


def bytes2str(bytes):
    return "".join([chr(i) for i in bytes])


def decryptor(crackme_file):
    crackme_file_copy = crackme_file + ".decrypted"

    print "Make copy of %s to %s\n" % (crackme_file, crackme_file_copy)
    shutil.copyfile(crackme_file, crackme_file_copy)

    print "Open %s with Radare2..\n" % crackme_file_copy
    r = r2p.open(crackme_file_copy, flags=["-w"])

    def cmd(c):
        print
        print "[r2]> %s" % c
        print
        print r.cmd(c)
        print

    def cmdj(c):
        return r.cmdj(c)

    print "Ensure we are at entrypoint"
    cmd("s entry0")
    print "Analyse current function"
    cmd("af")
    cmd("pdf")

    print "Hm, a syscall:"
    print "   syscall no: rax=0xa (__NR_unlink)"
    print "   param1: rdi=sym.imp.__gmon_start__"
    print "   param2: rsi=0x842"
    print "   param3: rdx=7"
    print
    print "This syscall does not make sense!"
    print "Probably it is used as NOP."
    print "I think the analysis has missed a few bytes. Lets print the blcok .."
    print

    cmd("px")

    print "So, the analysis has missed 4 bytes. Lets include them too.."

    cmd("pD 0x44")
    # e0f = cmdj("pDj 0x44")

    base = 0x00400000
    loop_start = 0x004009e0
    loop_end = 0x004009f5
    base_offset = 0x400570
    xor_inst_offset = 0x004009e7
    xor_val = 0xc
    end_count = 0x2d2

    print "From offset 0x%08x to offset 0x%08x we see a loop.\n" % (loop_start, loop_end)
    print ("It uses 'eax' to store a base offset (0x%08x which is inside loaded .text section)\n"
           "and 'edx' as counter.\n"
           "At offset 0x%08x there is a byte XOR with 0x%x.\n"
           "The source and destination used are at the [base+counter] offset.\n"
           "Obviously this is a decryption cycle. The loop ends when 'edx' reaches 0x%x") %\
          (base_offset, xor_inst_offset, xor_val, end_count)

    # def get_inst(start, end):
    #     return filter(lambda b: b["offset"] >= start and b["offset"] <= end, e0f)

    print ("Next we write a simple decryption routine in Python with r2pipe\n"
           "and write it down to the executable..\n")

    payload_file = os.path.join(os.path.dirname(crackme_file_copy), "payload.decr.bin")
    print "Use %s file for decrypted payload.." % payload_file

    payload = cmdj("pcj 0x%x @ 0x%x" % (end_count, base_offset))
    open(payload_file, "w").write(bytes2str(map(lambda a: a ^ xor_val,
                                  payload)))

    print ("Write down the decrypted paload in executable. Mind that when writing,\n"
           "you write with 0x0 base offseet not 0x%08x so we have to fix it..") % base

    cmd("s 0x%x" % (base_offset - base))
    cmd("wf %s" % payload_file)

    print ("Now we can nop the XOR in order to have a\n"
           "working executable ready for analysis.")

    cmd("s 0x%x" % (xor_inst_offset - base))
    cmd('"wa nop;nop;nop;nop;nop"')

    print "Now we continue with analysis of decrypted executable."


def main():
    args = get_args()

    crackme_fl = os.path.abspath(args.crackme_file)
    decryptor(crackme_fl)


if __name__ == "__main__":
    main()
