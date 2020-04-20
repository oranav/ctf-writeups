# PlaidCTF 2020 - Sandybox writeup

Written by @oranav on behalf of @pastenctf.

## Overview

We are presented with a single binary `sandybox`. After some setting up, it forks [1], waits for a ptrace tracer to attach [2], stops [3], and finally calls an inner function [4]:

```c
child_pid = fork();                                         // [1]
...
if ( !child_pid )
{
  prctl(PR_SET_PDEATHSIG, SIGKILL);
  if ( getppid() != 1 )
  {
    if ( ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL) )            // [2]
    {
      ...
    }
    myself = getpid();
    kill(myself, SIGSTOP);                                  // [3]
    child();                                                // [4]
    _exit(0);
  }
...
}
```

Inside the inner function, an RWX space of size 10 bytes is allocated, then a shellcode (of exactly 10 bytes) is read, and finally executed:

```c
char *buf, *ptr;
ptr = buf = (char *)mmap(0LL, 10uLL, 7, 34, -1, 0LL);
...
do
{
  if ( read(0, ptr, 1uLL) != 1 )
    _exit(0);
  ++ptr;
}
while ( ptr != buf + 10 );
((void (*)(void))buf)();
```

Note that at the time our shellcode is run, the tracer is already attached to us. Now what does it do? Basically, it sandboxes our shellcode. In short, it sanitizes the syscalls we are making by repeatedly using `PTRACE_SYSCALL`; what follows is essentially what the sanitizer does (by inspecting the registers, especially the syscall number - `rax`):

1. `read`, `write`, `close`, `fstat`, `lseek`, `getpid` `exit`, `exit_group` (0, 1, 3, 5, 8, 39, 60, 231 respectively) are unconditionally allowed.
2. `alarm` (37) is allowed only if `rdi` is at most 20.
3. `mmap`, `mprotect`, `munmap` (9, 10, 11 respectively) are allowed only if `rsi` (len) is at most 0x1000.
4. `open` (2) is allowed only if `rsi` is 0, `rdi` points to a valid address with a string of size at most 15, that does not contain the substrings "flag", "proc" or "sys".

## 32-bit syscalls to the rescue!

There are multiple solutions possible. However, the easiest I could come up with is just using 32-bit syscalls.

You see, Linux syscall numbers differ among different architectures. x86 and amd64 are no exceptions; they have different syscall tables. However, the interesting situation is that Linux on amd64 (usually) supports running x86 binaries. This means you can issue 32-bit syscalls from a 64-bit process, using **32-bit syscall numbers** (by hitting `int 0x80`). However, you are limited to 32-bit registers, so it's highly unlikely that you'll be able to pass pointers unless you mapped specific addresses.

However, note that while `rax=2` represents `open` under 64-bit, it represents `fork` under 32-bit. By setting up the correct register structure, we are able to issue syscall number 2! By using `int 0x80` instead of `syscall`, Linux runs fork().

After we forked, the newly created child is not traced by anyone, and it is free to do whatever it wants. Now we can just `open`, `read`, and `write` the flag.

## All this in 10 bytes?!

Huh? No way.

Well, Linux `mmap`s with a page granularity. Even though 10 bytes are requested for our RWX section, the generous kernel provides us no less than 4096 bytes!

Hence, we split the shellcode into two parts. The first (small) shellcode just `read`s the second (larger) shellcode into the RWX section, and right after `read` returns - the second shellcode runs.

## Wrap up

The flag is `PCTF{bonus_round:_did_you_spot_the_other_2_solutions?}`.

Well, can you?
