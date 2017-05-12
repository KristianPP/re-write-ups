!echo
!echo 'Run the main analysis'
!echo
. ./analysis.r2

!echo
!echo
!echo

!echo 'Load the file in debug mode with write permissions'
!echo 'The changes are made at the vaddr offset so there are no file changes (at 0x0 offset)'
!echo
ood+

!echo
!echo 'Break after init of "password"'
db important.after_password_init
!echo

!echo 'Stop at important.after_password_init'
!echo 'We have the password initialised to 0 by the program'
!echo
dc
!echo

!echo 'Break on flag'
db important.flag_passwd_eax

!echo
!echo 'Rewrite init password into increment'
!echo 'I need 7 bytes that turn init "password" into increment "password"'
wx `!rasm2 -b 64 -a x86 'add dword [rbp-0x34], 0x1; nop; nop; nop'` @ important.password_init

!echo

!echo 'NOP the 1st print'
wx 9090909090 @ important.first_printf

!echo

!echo 'NOP the scanf'
wx 9090909090 @ important.get_password_scanf

!echo

!echo 'NOP the false flag print'
wx 9090909090 @ important.false_flag_printf

!echo

!echo 'NOP the no cookies print'
wx 9090909090 @ important.no_cookies_printf

!echo

!echo 'Try a relative jump to "important.after_password_init"'
!echo 'abs(-372) = 0x174 = offset to important.password_init with 2 bytes for prev instruction'
wx `!rasm2 -b 64 -a x86 'xor eax, eax; jmp -372'` @ important.main_exit

!echo

!echo 'Remove initial breakpoint'
!echo
db -important.after_password_init

!echo 'Must break on flag goodboy'
!echo
dc

!echo
!echo 'One step further :)'
!echo
ds
!echo
!echo

!echo "The password is: "
?vi `dr?eax`
!echo
!echo