# MD15 writeup

_Difficulty estimate: medium_
--hxp, 2019

Written by @oranav on behalf of @pastenctf.

If you just want the solution, [skip to attempt #4](#attempt-4-reverse-every-byte-in-the-binary).

## Overview

We were presented with an abstract for a paper:
![MD15 paper](https://2019.ctf.link/assets/files/md15-8ea9df9e3f601d35.png)

Obviously, we should implement the mentioned attack, huh?

We were also presented with a binary though. Let me save you the hassle of reverse engineering:

1. It's taking an input through `argv[1]`.
2. Make sure its format is  `hxp{XXXXXXXXXXXXXXXX}`, where the `X`s are 16 printable characters (`0x20 <= X < 0x7F`).
3. Take the `X`s (a total of 16 bytes), and let's call them `buf`:
   1. Make sure `MD5(buf ^ "hhhhhhhhhhhhhhhh") = O_h` where `O_h` is given.
   2. Make sure `MD5(buf ^ "xxxxxxxxxxxxxxxx") = O_x` where `O_x` is given.
   3. Make sure `MD5(buf ^ "pppppppppppppppp") = O_p` where `O_p` is given.
4. Print ":)" if it all checks out, otherwise ":(".

So we should find such `buf` that satisfies (3). Should be easy given the paper, right? Only if this was the intended solution, it should have been in the "zahjebischte" category. To clarify: there is no known practical preimage attack on MD5, and if somebody found one during a CTF, it would be very stupid to waste it ;)

## What we've been through

### Attempt #1: find a bug in the MD5 library

The code appears to be using [an SSE implementation found in a library called simd_md5](https://github.com/krisprice/simd_md5/blob/master/simd_md5/md5_sse.c), which is not very popular (1 watch, 8 stars, 5 forks). So obviously our first attempt was to find a bug in the library.

It appears that the library supports digesting 4 buffers in parallel (hence SSE), however the code passes the identical input to all the 4 buffers. There's a bug with the last 2 outputs, but the code is taking the first one, which seems to be behaving correctly.

To make sure, we tested some test vectors and made sure the output is correct with this library. I even compiled a program which tested 1 billion random inputs against OpenSSL's implementation, and they all checked out. We also debugged the binary itself and made sure the outputs from the MD5 function are as expected.

Even if we did find such a bug, it's highly unlikely that it'll let us mount a preimage attack. We figured that it might be that the author deliberately chose the buffer to be the very one that fails the implementation; however it's very unlikely that it'll be printable (xor 'h', 'x' and 'p'). Even so, we did not find such a bug. So we ditched this train of thought.

### Attempt #2: take a closer look at the paper

We were pretty clueless at this point, so we looked everywhere. The paper mentions that their algorithm should run in
$$
2^{128/(n-\pi/4)^2}
$$
Since `n=3`, we get that the exponent is roughly equivalent to 26. We tried to guess what would give us 26 degrees of freedom (spoiler: nothing), and maybe brute force such a space. But that's no reversing challenge, so we didn't hope for much.

### Attempt #3: SSE returns

Then we figured out: what if this was run on a processor which does not support SSE? Sure, it should receive a SIGILL signal, but maybe something interesting happens?

We tried to simulate such a situation, only to find out that SSE was introduced in Pentium III, while amd64 was introduced in Pentium 4; meaning there is no (sane) processor supporting the amd64 architecture but not SSE.

### Attempt #4: reverse every byte in the binary!

At this point we were seriously frustrated. Some of us claimed that the challenge is unsolvable.

Then hxp released a hint: _Remember, md15 is a reversing challenge. hxp recommends you stop reading crypto papers._

It must be something that we did not reverse engineer correctly then. We declared that there should not be a single byte in the binary which was not reverse engineered!

My friend [Matan](https://ctftime.org/user/4749) then discovered a very strange NOP, which IDA willingly classifies as an "alignment" directive, and Ghidra just doesn't decode on its own:

```assembly
        00101405 0f 1f 80         NOP       dword ptr [0x92f3e9 + RAX]
                 e9 f3 92 00
```

Hmm... x86 has variable length instructions. Maybe in a different alignment it'll make more sense?

```assembly
        00101408 e9 f3 92         JMP       LAB_0010a700
                 00 00
```

Aha! but `0xA700` is outside our text segment according to IDA/Ghidra... Or is it?

ELF files have sections and segments. Sections describe what the bytes inside the binary mean. Segments describe what the loader should load into memory while loading the ELF. IDA/Ghidra use segments to load and display the ELF file which is being disassembled. However, the loader has a granularity of page size (0x1000 bytes); hence when a segment does not nicely end at the end of a page, the rest is also `mmap()`ed and, in the case of the TEXT segment, is also executable.

Our text segment is `0xFD96` bytes long; meaning the rest `0x26A` bytes are also mapped and executable. That's exactly what lies in `0xA700`. In addition, the `__libc_csu_init` function (which runs before `main`) appears to be patched -- instead of jumping into the `frame_dummy` function, it jumps 8 bytes ahead, which is conveniently the dreaded `JMP`.

By reverse engineering the newly discovered init code, it appears to be checking some additional conditions on the input (it has to satisfy some LFSR condition for instance). If it passes the checks, the MD5 transform function **is patched in memory** and modified in such way that only the first 12 operations of the first round are run: as soon as the 12th operation is completed, the stack frame pointer is shifted away such that all operations are done on unused stack variables. Right before returning the stack frame is shifted back and the original variables are returned, as they were left by the 12th operation.

The reason we did not see this patching happening is plainly because we haven't tried enough inputs **to the binary itself** to trigger the right conditions.

A single round of MD5 is reversible. Let me explain why.

The `transform` function is called only once (since the input being digested is only 16 bytes / 4 words long). There is a padding of 12 words which is completely known, making the digest block being passed into `transform` a total of 16 words: 4 unknown and 12 known. The first (and only) round operates on the words one by one, in order; we know the final state, and we do know words 4-15, so we can reverse the last 12 operations quite easily. Coming next are the first 4 operations which operate on the (unknown) words 0-3; however, we do know the initial state here, so we can just write the equations a bit differently and solve for `words[0:3]` given the initial and final state. `words[0:3]` are exactly what we're looking for.

A Python solution is attached to this repository.

## Closing words

This challenge proved to be much more difficult that initial thought. It used not-so-uncommon tricks, but since we're used to believe everything IDA spits out, we missed the key part of this challenge for the majority of the CTF, wasting many hours. Always doubt what you see.
