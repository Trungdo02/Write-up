# Babygame01

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+1h] [ebp-AA5h]
  int v5[2]; // [esp+2h] [ebp-AA4h] BYREF
  char v6; // [esp+Ah] [ebp-A9Ch]
  char v7[2700]; // [esp+Eh] [ebp-A98h] BYREF
  unsigned int v8; // [esp+A9Ah] [ebp-Ch]
  int *v9; // [esp+A9Eh] [ebp-8h]

  v9 = &argc;
  v8 = __readgsdword(0x14u);
  init_player((int)v5);
  init_map((int)v7, v5);
  print_map((int)v7, (int)v5);
  signal(2, (__sighandler_t)sigint_handler);
  do
  {
    do
    {
      v4 = getchar();
      move_player(v5, v4, (int)v7);
      print_map((int)v7, (int)v5);
    }
    while ( v5[0] != 29 );
  }
  while ( v5[1] != 'Y' );
  puts("You win!");
  if ( v6 )
  {
    puts("flage");
    win();
    fflush(stdout);
  }
  return 0;
}
}
```
Con game này sẽ tạo ra cái 1 map dạng mảng 2 chiều với vị trí của mình trong đấy, nhiệm vụ của mình là phải dùng 4 nút `asdw` để di chuyển tới đích thì sẽ thắng, tiếp theo chương trình sẽ kiểm tra biến `v6` và gọi hàm `win` để in ra `flag`, chỉ cần `v6` khác 0 là câu `if` sẽ trả về `true` và ta có `flag`. Tuy nhiên biến `v6` chỉ được gọi vào đúng một lần duy nhất ở câu điều kiện trong xuyên suốt chương trình vì vậy hiếm có cơ hội để `overwrite`. 

May thay trong hàm `move_player` có thứ tận dụng được :

```c
_BYTE *__cdecl move_player(int *v5, char v4, int v7)
{
  _BYTE *result; // eax

  if ( v4 == 'l' )
    player_tile = getchar();
  if ( v4 == 'p' )
    solve_round(v7, v5);
  *(_BYTE *)(v5[1] + v7 + 90 * *v5) = 46;
  switch ( v4 )
  {
    case 'w':
      --*v5;
      break;
    case 's':
      ++*v5;
      break;
    case 'a':
      --v5[1];
      break;
    case 'd':
      ++v5[1];
      break;
  }
  result = (_BYTE *)(v5[1] + v7 + 90 * *v5);
  *result = player_tile;
  return result;
}
```
Tóm lược chức năng của hàm này chỉ là di chuyển giá trị các con trỏ phù hợp với chữ cái mà ta nhập vào và `v5` sẽ chứa cặp chỉ số của map lưu trong `v7` với `v5[1]` là cột còn `v5[0]` là hàng, nhưng cách nó di chuyển thì tạo ra bug =)). Ngoài ra còn có 2 tính năng: Nếu ta gõ `'l'` đi kèm với 1 ký tự thì `player` của ta sẽ là ký tự đó =)), phím `'p'` để chương trình tự hoàn thành trò chơi. Ngay dưới câu lệnh gọi hàm `solve_round`: 

    *(_BYTE *)(v5[1] + v7 + 90 * *v5) = 46;

Câu lệnh này sẽ set `1byte` giá trị của địa chỉ được tính như trên thành `46 ('.')`. Chỉ cần giá trị này là địa chỉ của `v6` thì coi như thành công.

Nhiệm vụ bây giờ là cần phải tìm cặp vị trí phù hợp của `v5[0]` và `v5[1]` để phép tính trên trỏ đến chính xác địa chỉ của `v6` với điều kiện `v5[1] < 89` và `v5[0] < 29`. 

```c
char v4; // [esp+1h] [ebp-AA5h]
int v5[2]; // [esp+2h] [ebp-AA4h] BYREF
char v6; // [esp+Ah] [ebp-A9Ch]
char v7[2700]; // [esp+Eh] [ebp-A98h] BYREF
unsigned int v8; // [esp+A9Ah] [ebp-Ch]
int *v9; // [esp+A9Eh] [ebp-8h]
```
Ta có phép tính đơn giản: `v5[1] + v7 + 90 * v5[0] = v7 - 4`. Lúc đầu tớ cho `v5[0] = -1` và `v5[1] = 81` (cột 81 hàng -1) tuy nhiên lúc chạy thì gặp lỗi `SIGSEGV` chắc là do truy cập vào vùng nhớ k hợp lệ và đã không thỏa mãn điều kiện. Nếu hàng không được thì thử out of bound cột với `v5[1] = 0`, `v5[0] = -4` (hàng 0 cột -4) nghĩa là phải di chuyển lên hàng thứ 0 và cho chạy lùi 4 lần ra khỏi map vì chỉ có hàng 0 thì mới có thể di chuyển ra ngoài map được. Các phím lần lượt phải bấm là `'wwwwaaaaaaaa'`. Chạy thử thì k còn bị crash và xuất hiện thông báo có flag

```java
End tile position: 29 89
Player has flag: 64
..........................................................................................
..........................................................................................
```
Bây giờ chỉ cần hoàn thành đưa về hàng cuối cột cuối hoàn thành trò chơi là có `flag`. Ta dùng phím `'p'` để nó tự chạy.

```java
..........................................................................................
.........................................................................................@
You win!
flage
flag.txt not found in current directory
```
Chạy trên local ok rồi giờ remote để lấy flag

```java
..........................................................................................
..........................................................................................
.........................................................................................@
You win!
flage
picoCTF{gamer_m0d3_enabled_0a880baf}
```
`flag: picoCTF{gamer_m0d3_enabled_0a880baf}`