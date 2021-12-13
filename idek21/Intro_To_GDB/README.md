# Intro to GDB

gdb ./Intro_to_GDB
b main
next until call puts
enter AAAAAAAA
next until main+183 (cmp input buffer)
-> read flag in RSP (RSP: 0x7fffffffd890 ("idek{m0m_g3t_th3_c4m3rA!}"))