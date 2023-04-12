def hash_string(str):
    hash = 0
    l = len(str)
    if (l > 16):
        return 0
    for i in range(l):
        hash += ord(str[i]) * 31
    return hash

str = input("input : ")
print(hash_string(str) % 10)