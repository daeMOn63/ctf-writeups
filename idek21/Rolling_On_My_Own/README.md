
# Rolling on my own


We start opening the binary in ghidra, and get a nice dissassembled main:

```c
void main(void)

{
  int iVar1;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  char local_38 [36];
  int local_14;
  int local_10;
  int local_c;
  
  puts("I can\'t just let anyone in, what\'s the password?");
  __isoc99_scanf(&DAT_00102039);
  local_58 = 0x455d35402f28272b;
  local_50 = 0x43277c222d58366a;
  local_48 = 0x5650324666795152;
  local_40 = 0x5f472c67575b6353;
  local_c = 0;
  while( true ) {
    if (0x1f < local_c) {
      printf("https://www.youtube.com/watch?v=TeSRoEjevHI");
      return;
    }
    local_10 = (int)local_38[local_c];
    iVar1 = roll(local_c);
    iVar1 = iVar1 + local_10;
    local_14 = iVar1 + ((iVar1 / 6 + (iVar1 >> 0x1f) >> 4) - (iVar1 >> 0x1f)) * -0x60 + 0x22;
    if (local_14 != *(char *)((long)&local_58 + (long)local_c)) break;
    local_c = local_c + 1;
  }
  printf("Imposter!!");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

We also have a `roll` function that is generating Fibonacci numbers:

```c
int roll(int param_1)

{
  int iVar1;
  
  if (1 < param_1) {
    iVar1 = roll(param_1 + -1);
    param_1 = roll(param_1 + -2);
    param_1 = param_1 + iVar1;
  }
  return param_1;
}
```


the `local_58`, `local_50`, `local_48` and `local_40` could be our flag, we can try to confirm this trying to encrypt some known plaintext with the function:

```python
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
print(out.hex()) # 2b27282f40, looks like local_58 content in big endian, we're on good track
```

From here we can just bruteforce every printable characters until we find a match in the `local_xx`:

```python
from pwn import *
import string

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
    for char in string.printable: # iterate on all printable chars
        c = mod + ord(char)
        enc_char = c + ((c // 6 + (c >> 0x1f) >> 4) - (c >> 0x1f)) * -0x60 + 0x22    
        if enc_char == expected: # if it matches the encrypted flag byte, we know that `char` is the clear byte.
            out += bytes([ord(char)])
print(out)
```