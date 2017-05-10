# Run the main analysis
. ./analysis.r2

ood+

# Break after init of "password"
db important.after_password_init

# Break on flag
db importand.flag

# I need 7 bytes that turn init "password" into increment "password"
wx `!rasm2 -b 64 -a x86 "add dword [rbp-0x34], 0x1; nop; nop; nop"` @ important.password_init

# Try a relative jump to "important.after_password_init"
# TO-DO: Fix this relative jmp
wx `!rasm2 -b 64 -a x86 'xor eax, eax; jmp [rip-0x16f+0x5]'` @ 

# Must break on "important.flag"
dc

# Print password
?vi `pxW 0x4~[1] @ rbp-0x34`
