# 堆利用简介

[glibc3.8](https://elixir.bootlin.com/linux/v3.8/source)

# 堆概述

## 什么是堆

## 堆的基本操作

### malloc

### free

### 内存分配后的系统调用

#### (s)brk

[man sbrk(2)](http://man7.org/linux/man-pages/man2/sbrk.2.html)

#### mmap

### 多线程支持

arena

# 堆相关数据结构

## 微观结构

### malloc_chunk

```c
/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/
struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

要求：理解相关概念



size的三个比特位：

> - NON_MAIN_ARENA，记录当前 chunk 是否不属于主线程，1表示不属于，0表示属于。
> - IS_MAPPED，记录当前 chunk 是否是由 mmap 分配的。
> - PREV_INUSE，记录前一个 chunk 块是否被分配。一般来说，堆中第一个被分配的内存块的 size 字段的P位都会被设置为1，以便于防止访问前面的非法内存。当一个 chunk 的 size 的 P 位为 0 时，我们能通过 prev_size 字段来获取上一个 chunk 的大小以及地址。这也方便进行空闲chunk之间的合并。

