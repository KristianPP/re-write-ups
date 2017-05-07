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

Now we have everything decrypted. We open the decrypted executable with:

```
r2 -w ./abrams_crackme_2017.decrypted
```

We saw previously that there is a decryption loop that stores a payload base address
at 'eax'. Lets go to see the address (0x00400570):

```
[r2]> s 0x00400570
```

Analyse function at current offset:

```
[r2]> af
```

and dissasemble it:

```
[r2]> pdf

          ;-- section_end..plt:
            ;-- section..text:
/ (fcn) fcn.00400570 43
|   fcn.00400570 ();
|           0x00400570      31ed           xor ebp, ebp                ; section 13 va=0x00400570 pa=0x00000570 sz=722 vsz=722 rwx=--rwx .text
|           0x00400572      4989d1         mov r9, rdx
|           0x00400575      5e             pop rsi
|           0x00400576      4889e2         mov rdx, rsp
|           0x00400579      4883e4f0       and rsp, 0xfffffffffffffff0
|           0x0040057d      50             push rax
|           0x0040057e      54             push rsp
|           0x0040057f      49c7c0400840.  mov r8, 0x400840
|           0x00400586      48c7c1d00740.  mov rcx, 0x4007d0
|           0x0040058d      48c7c74c0740.  mov rdi, 0x40074c
|           0x00400594      ff15560a2000   call qword [reloc.__gmon_start___240] ; [0x600ff0:8]=0
\           0x0040059a      f4             hlt
```

We can see this is the standard entry code of an ELF executable
linked to the standard library libc. Linked to libc libraries does not execute
the 'main()' function right at the program's entrypoint. This [article](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)
describes in detail how the linker calls our 'main()' funciton.

Knowing how the linker works, we can see that the call to __gmon_start___240 has a pointer
to the 'main()' function. In x64 under Linux the function arguments are passed through the
registers rdi, rsi, rdx, rcx, r8, r9, <stack> in the same order. So 'rdi' has our pointer - 0x40074c.

```
[r2]> s 0x0040074c
[r2]> af
[r2]> pdf

/ (fcn) fcn.0040074c 124
|   fcn.0040074c ();
|           ; var int local_4h @ rbp-0x4
|           ; var int local_0h @ rbp-0x0
|              ; DATA XREF from 0x0040058d (fcn.00400570)
|           0x0040074c      55             push rbp
|           0x0040074d      4889e5         mov rbp, rsp
|           0x00400750      4883ec10       sub rsp, 0x10
|           0x00400754      c745fc010000.  mov dword [local_4h], 1
|           0x0040075b      b900000000     mov ecx, 0
|           0x00400760      ba00000000     mov edx, 0
|           0x00400765      be00000000     mov esi, 0
|           0x0040076a      bf00000000     mov edi, 0
|           0x0040076f      b800000000     mov eax, 0
|           0x00400774      e8c7fdffff     call sym.imp.ptrace
|           0x00400779      4883f8ff       cmp rax, -1
|       ,=< 0x0040077d      7507           jne 0x400786
|       |   0x0040077f      b8ffffffff     mov eax, 0xffffffff         ; -1
|      ,==< 0x00400784      eb40           jmp 0x4007c6
|      |`-> 0x00400786      b800000000     mov eax, 0
|      |    0x0040078b      e8d6feffff     call 0x400666
|      |    0x00400790      85c0           test eax, eax
|      |,=< 0x00400792      7407           je 0x40079b
|      ||   0x00400794      b8ffffffff     mov eax, 0xffffffff         ; -1
|     ,===< 0x00400799      eb2b           jmp 0x4007c6
|     ||`-> 0x0040079b      b800000000     mov eax, 0
|     ||    0x004007a0      e8c1feffff     call 0x400666
|     ||    0x004007a5      837dfc00       cmp dword [local_4h], 0
|     ||,=< 0x004007a9      750c           jne 0x4007b7
|     |||   0x004007ab      bf65084000     mov edi, str.cracked        ; 0x400865 ; "cracked"
|     |||   0x004007b0      e85bfdffff     call sym.imp.puts
|    ,====< 0x004007b5      eb0a           jmp 0x4007c1
|    |||`-> 0x004007b7      bf6d084000     mov edi, str.not_cracked    ; 0x40086d ; "not cracked"
|    |||    0x004007bc      e84ffdffff     call sym.imp.puts
|    |||       ; JMP XREF from 0x004007b5 (fcn.0040074c)
|    `----> 0x004007c1      b800000000     mov eax, 0
|     ||       ; JMP XREF from 0x00400799 (fcn.0040074c)
|     ||       ; JMP XREF from 0x00400784 (fcn.0040074c)
|     ``--> 0x004007c6      c9             leave
\           0x004007c7      c3             ret
```

There is Linux anti-debugging logic in this function. The call to ptrace is used
for self-tracing which is a well known trick to prevent a debugger from attaching.

What we can see at 0x00400754 is a local variable equal to 0x1
and it is compared with 0x0 at 0x004007a5. The jump must not be taken in order to
to print 'cracked'. So we must patch the byte at 0x00400754 + 0x3 with 0x0.
0x0 XORed with anything is 'anything' so it is the easiest patch possible and we can apply
it to the original (don't forget the base calculation). Our initial XOR key was 0xc 
(from offset 0x004009e7):

abrams_crackme_2017-patch.r2:

```
s 0x00000757
wx 0c
```

Apply patch as:

```
$> r2 -w -i ./crack-patch.r2 ./abrams_crackme_2017
```

## References

* http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html
* http://stackoverflow.com/a/4266083/713289