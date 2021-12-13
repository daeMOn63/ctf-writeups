# I love Snowy Stegausaurus

When looking at chall.txt, we see weird whitespace charaters on the first few lines:

```
 $ head chall.txt | hexdump -C
00000000  73 6e 6f 77 62 61 6c 6c  09 20 20 20 20 20 09 20  |snowball.     . |
00000010  20 20 20 09 20 20 20 20  20 20 20 09 09 09 20 09  |   .       ... .|
00000020  20 20 20 09 20 20 20 0a  73 6e 6f 77 66 6c 61 6b  |   .   .snowflak|
00000030  65 20 20 20 20 09 20 20  20 20 09 20 20 20 20 20  |e    .    .     |
00000040  20 09 20 20 20 20 20 09  09 20 20 20 20 20 20 09  | .     ..      .|
00000050  20 20 20 20 20 09 20 20  20 09 20 20 0a 73 6e 6f  |     .   .  .sno|
00000060  77 6d 61 6e 20 20 09 20  20 20 20 09 20 20 20 20  |wman  .    .    |
00000070  20 09 20 20 20 20 09 20  09 20 20 20 09 20 20 20  | .    . .   .   |
00000080  20 20 20 20 09 20 20 20  20 20 0a 73 6e 6f 77 77  |    .     .snoww|
00000090  68 69 74 65 09 20 20 20  20 20 20 20 09 20 20 20  |hite.       .   |
000000a0  20 09 20 20 20 20 09 20  09 20 09 20 20 20 20 20  | .    . . .     |
000000b0  09 09 20 20 20 20 20 20  0a 73 6e 6f 77 62 61 6c  |..      .snowbal|
```

Mostly spaces (0x20) and tabs (0x09).

Googling a bit on whitespace steganography, we land on https://www.carta.tech/man-pages/man1/stegsnow.1.html

And another tool allowing to bruteforce the password given a wordlist: https://github.com/0xMohammed/SnowCracker

```
# install stegsnow first
python3 stegsnow.py -f chall.txt -w chall.txt -c
```
