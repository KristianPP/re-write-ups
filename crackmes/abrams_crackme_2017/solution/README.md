# abrams_crackme_2017 solution

## Scripts

```bash
./decrypt_payload.py -f ./abrams_crackme_2017
./analysis.py -f abrams_crackme_2017.decrypted
r2 -w -i ./crack-patch.r2 ./abrams_crackme_2017
```

## Detailed analysis

### Decrypting

Load the executable in Radare2 with:

```
r2 -w ./abrams_crackme_2017
```

Ensure we are at entrypoint

```
[r2]> s entry0
```

Analyse current function

```
[r2]> af
[r2]> pdf


/ (fcn) entry0 57
|   entry0 ();
|           0x004009be      52             push rdx
|           0x004009bf      54             push rsp
|           0x004009c0      48c7c7000040.  mov rdi, sym.imp.__gmon_start__ ; loc.imp.__gmon_start__ ; 0x400000
|           0x004009c7  ~   48c7c6420800.  mov rsi, 0x842
|           ;-- section_end..eh_frame:
|           ;-- section_end.LOAD0:
|           0x004009cc      0000           add byte [rax], al
|           0x004009ce      48c7c2070000.  mov rdx, 7
|           0x004009d5      48c7c00a0000.  mov rax, 0xa
|           0x004009dc      0f05           syscall
|           0x004009de      31d2           xor edx, edx
|       .-> 0x004009e0      8d0425700540.  lea eax, [0x400570]         ; section..text ; "=.E..RD..D...\XE..L.L.D....L.D..@.L...Z.,....H...S.l.YD!T.l.D...D..z......D..x.Q.T.l...j........Q...L.j".........T.l.YD..T.l.D...D..D..D..3D..D..x......D..x.Q.T.l......Q.j..H...1=.,..y.YD...b...Q....,......L....l.D.3.y...........D..x.YD....Q.v...YD..D.............D.........X.L......D............D...........D..."
|       |   0x004009e7      678034100c     xor byte [eax + edx], 0xc
|       |   0x004009ec      83c201         add edx, 1
|       |   0x004009ef      81fad2020000   cmp edx, 0x2d2
\       `=< 0x004009f5      75e9           jne 0x4009e0
```

Hm, a syscall:
* syscall no: rax=0xa (__NR_unlink)
* param1: rdi=sym.imp.__gmon_start__
* param2: rsi=0x842
* param3: rdx=7

This syscall does not make sense, cause there is no string at the offset!
Probably it is used as NOP.
I think the analysis has missed a few bytes. Lets print the blcok:

```
[r2]> px

- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x004009be  5254 48c7 c700 0040 0048 c7c6 4208 0000  RTH....@.H..B...
0x004009ce  48c7 c207 0000 0048 c7c0 0a00 0000 0f05  H......H........
0x004009de  31d2 8d04 2570 0540 0067 8034 100c 83c2  1...%p.@.g.4....
0x004009ee  0181 fad2 0200 0075 e948 c7c0 7005 4000  .......u.H..p.@.
0x004009fe  5c5a ffe0 0000 0000 0000 0000 0000 0000  \Z..............
0x00400a0e  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x00400a1e  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x00400a2e  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x00400a3e  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x00400a4e  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x00400a5e  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x00400a6e  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x00400a7e  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x00400a8e  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x00400a9e  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x00400aae  0000 0000 0000 0000 0000 0000 0000 0000  ................
```

So, the analysis has missed 4 bytes. Lets include them too:

```
[r2]> pD 0x44

/ (fcn) entry0 57
|           0x004009be      52             push rdx
|           0x004009bf      54             push rsp
|           0x004009c0      48c7c7000040.  mov rdi, sym.imp.__gmon_start__ ; loc.imp.__gmon_start__ ; 0x400000
|           0x004009c7  ~   48c7c6420800.  mov rsi, 0x842
|           ;-- section_end..eh_frame:
|           ;-- section_end.LOAD0:
|           0x004009cc      0000           add byte [rax], al
|           0x004009ce      48c7c2070000.  mov rdx, 7
|           0x004009d5      48c7c00a0000.  mov rax, 0xa
|           0x004009dc      0f05           syscall
|           0x004009de      31d2           xor edx, edx
|       .-> 0x004009e0      8d0425700540.  lea eax, [0x400570]         ; section..text ; "=.E..RD..D...\XE..L.L.D....L.D..@.L...Z.,....H...S.l.YD!T.l.D...D..z......D..x.Q.T.l...j........Q...L.j".........T.l.YD..T.l.D...D..D..D..3D..D..x......D..x.Q.T.l......Q.j..H...1=.,..y.YD...b...Q....,......L....l.D.3.y...........D..x.YD....Q.v...YD..D.............D.........X.L......D............D...........D.............I"
|       |   0x004009e7      678034100c     xor byte [eax + edx], 0xc
|       |   0x004009ec      83c201         add edx, 1
|       |   0x004009ef      81fad2020000   cmp edx, 0x2d2
\       `=< 0x004009f5      75e9           jne 0x4009e0
            0x004009f7      48c7c0700540.  mov rax, 0x400570           ; section..text ; "=.E..RD..D...\XE..L.L.D....L.D..@.L...Z.,....H...S.l.YD!T.l.D...D..z......D..x.Q.T.l...j........Q...L.j".........T.l.YD..T.l.D...D..D..D..3D..D..x......D..x.Q.T.l......Q.j..H...1=.,..y.YD...b...Q....,......L....l.D.3.y...........D..x.YD....Q.v...YD..D.............D.........X.L......D............D...........D.............I"
            0x004009fe      5c             pop rsp
            0x004009ff      5a             pop rdx
            0x00400a00      ffe0           jmp rax
```

From offset 0x004009e0 to offset 0x004009f5 we see a loop.

It uses 'eax' to store a base offset (0x00400570 which is inside loaded .text section)
and 'edx' as counter.
At offset 0x004009e7 there is a byte XOR with 0xc.
The source and destination used are at the [base+counter] offset.
Obviously this is a decryption cycle. The loop ends when 'edx' reaches 0x2d2
Next we write a simple decryption routine in Python with r2pipe
and write it down to the executable..

I use payload.decr.bin file for decrypted payload to write down
the decrypted paload in executable. Mind that when writing,
you write with 0x0 base offseet not 0x00400000 - when we write to a file we use the
file offset which in ELF can be calculated just by substracting the vaddr base.

```
[r2]> s 0x570
[r2]> wf ./payload.decr.bin

```

Now we can nop the XOR in order to have a
working executable ready for analysis.

```
[r2]> s 0x9e7
[r2]> "wa nop;nop;nop;nop;nop"
```

We can continue with the analysis of the decrypted payload. This trick to decrypt
the payload inside the executable is used to ease the later analysis in order to 
preserve references and symbols.

### Analysis of payload
