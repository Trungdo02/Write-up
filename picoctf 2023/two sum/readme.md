# Two sum

## Source code

```c
#include <stdio.h>
#include <stdlib.h>

static int addIntOvf(int result, int a, int b) {
    result = a + b;
    if(a > 0 && b > 0 && result < 0)
        return -1;
    if(a < 0 && b < 0 && result > 0)
        return -1;
    return 0;
}

int main() {
    int num1, num2, sum;
    FILE *flag;
    char c;

    printf("n1 > n1 + n2 OR n2 > n1 + n2 \n");
    fflush(stdout);
    printf("What two positive numbers can make this possible: \n");
    fflush(stdout);
    
    if (scanf("%d", &num1) && scanf("%d", &num2)) {
        printf("You entered %d and %d\n", num1, num2);
        fflush(stdout);
        sum = num1 + num2;
        if (addIntOvf(sum, num1, num2) == 0) {
            printf("No overflow\n");
            fflush(stdout);
            exit(0);
        } else if (addIntOvf(sum, num1, num2) == -1) {
            printf("You have an integer overflow\n");
            fflush(stdout);
        }

        if (num1 > 0 || num2 > 0) {
            flag = fopen("flag.txt","r");
            if(flag == NULL){
                printf("flag not found: please run this on the server\n");
                fflush(stdout);
                exit(0);
            }
            char buf[60];
            fgets(buf, 59, flag);
            printf("YOUR FLAG IS: %s\n", buf);
            fflush(stdout);
            exit(0);
        }
    }
    return 0;
}

```
Đại khái chương trình sẽ yêu cầu ta nhập 2 số và sau đó cộng 2 số lại với nhau rồi gọi hàm `addIntOvf` để so sánh, nếu `n1, n2 > 0` và `sum < 0` hoặc `n1, n2 < 0` và `sum >0` thì sẽ `return 0` ngược lại `return -1`. 

Nếu `return -1` thì chương trình sẽ dừng lại, nếu ngược lại nó sẽ kiểm tra `num1` hoặc `num2 > 0` để in ra `flag`.

Bug ở đây là `integer overflow` khi 2 số dương cộng lại lại thành một số âm. Kiểu `int` có 4 byte và qui định byte đầu tiên từ trái sang sẽ quyết định dấu (1 là âm, 0 là dương). Để tận dụng bug này thì ta cần 2 số có bit đầu tiên là 0 mà khi cộng lại sẽ thành một số có bit đầu là 1

Theo wikipedia =))

    32-bit: maximum representable value 232 − 1 = 4,294,967,295 (the most common width for personal computers as of 2005),
    64-bit: maximum representable value 264 − 1 = 18,446,744,073,709,551,615 (the most common width for personal computer central processing units (CPUs), as of 2021)

Tớ sẽ chọn số 4,294,967,294 làm target. Khi chia đôi số này ta được 2 số bé hơn 2,147,483,647 với : 

    4,294,967,294 = 11111111 11111111 11111111 11111110
    2,147,483,647 = 01111111 11111111 11111111 11111111

Remote rồi lấy flag thôi =))
## Exploit

```java
trungdo@TEFO:$ nc saturn.picoctf.net 52601
n1 > n1 + n2 OR n2 > n1 + n2
What two positive numbers can make this possible:
2147483647
2147483647
You entered 2147483647 and 2147483647
You have an integer overflow
YOUR FLAG IS: picoCTF{Tw0_Sum_Integer_Bu773R_0v3rfl0w_fe14e9e9}
```
`flag: picoCTF{Tw0_Sum_Integer_Bu773R_0v3rfl0w_fe14e9e9}`

*chall đầu tiên của giải khá nhẹ nhàng :');