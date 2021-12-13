
# Strings

We know that idek write in hex like so:
```
echo idek | xxd
00000000: 6964 656b 0a                             idek.
```

Looking at the main function in ghidra we see:

```
        0010113d 48 c7 45        MOV        qword ptr [RBP + local_10], 0x0
        00101145 c7 45 f4        MOV        dword ptr [RBP + local_14], 0x656469
        0010114c c7 45 f0        MOV        dword ptr [RBP + local_18], 0x737b6b
        00101153 c7 45 ec        MOV        dword ptr [RBP + local_1c], 0x315274
        0010115a c7 45 e8        MOV        dword ptr [RBP + local_20], 0x73346e
        00101161 c7 45 e4        MOV        dword ptr [RBP + local_24], 0x54375f
        00101168 c7 45 e0        MOV        dword ptr [RBP + local_28], 0x212157
        0010116f c7 45 dc        MOV        dword ptr [RBP + local_2c], 0x7d
```

Those hex numbers looks like the flag written backward:
```
0x656469 #  edi
0x737b6b #  s{k
0x315274
0x73346e
0x54375f
0x212157
0x7d
```

So we just decode it:

```
echo 6964656b7b737452316e34735f37545721217d | xxd -r -p
idek{stR1n4s_7TW!!}
```
