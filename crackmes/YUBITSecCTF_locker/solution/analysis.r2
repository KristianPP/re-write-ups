aaa
# GNU MP library used https://gmplib.org/
s main

f important.flag @ main + 0x14e
f important.password_init @ main + 0x8
f important.after_password_init @ main + 0xf
f important.main_exit @ main + 0x17c

afvn local_34h password
afvn local_30h no_flag_for_you
pdf
