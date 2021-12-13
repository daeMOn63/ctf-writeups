
from pwn import *
import string

def roll(i): # actually fibo
    if (i  > 1):
        tmp = roll(i-1)
        i = roll(i-2)
        i = i + tmp
    return i


# let's try to encrypt know plaintext see what happen
s = b"idek{"
out = b''
for i in range(0, len(s)):
    mod = roll(i)
    c = mod + s[i]
    enc_char = c + ((c // 6 + (c >> 0x1f) >> 4) - (c >> 0x1f)) * -0x60 + 0x22
    out += bytes([enc_char])
print(out.hex()) # 2b27282f40, looks like flag1 content in big endian, we're on good track


# extracted from binary, most probably the flag
flag1 = 0x455d35402f28272b
flag2 = 0x43277c222d58366a
flag3 = 0x5650324666795152
flag4 = 0x5f472c67575b6353

# flag = p64(flag1) + p64(flag2) + p64(flag3) + p64(flag4)
flag = p64(flag1) + p64(flag2) + p64(flag3) + p64(flag4)


out = b''
for i in range(0, len(flag)):
    mod = roll(i)
    
    expected = flag[i] 
    for char in string.printable:
        c = mod + ord(char)
        enc_char = c + ((c // 6 + (c >> 0x1f) >> 4) - (c >> 0x1f)) * -0x60 + 0x22    
        if enc_char == expected:
            out += bytes([ord(char)])
print(out) 
