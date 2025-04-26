# CSGY 9223 Intro to Offensive Security
# Week 9 Challenges
# nam10102

## Challenge - Sneaky Heap Leak
```
Can you leak the heap base address? nc offsec-chalbroker.osiris.cyber.nyu.edu 1220
```
Inspect the binary:
```aiignore
$ checksec sneaky_heap_leak
[*] '/mnt/csgy9223_IntroOffSec/week_9/sneaky_heap_leak'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Run the binary:

```aiignore
What do you want to do?
1. Free an index
2. Read an index
3. Allocate an index
4. Guess the heap's base address
> 3

What index would you like to (re)allocate?
> 0
Index 0 is already allocated!
What do you want to do?
1. Free an index
2. Read an index
3. Allocate an index
4. Guess the heap's base address
>
```
Looks like some data is pre-allocated. Inspecting binary using binja.

This works just like the week 8 "sneaky_leak" challenge. However, this week we are working with glibc 2.35, so the address will need to be manipulated to get the base address. Instead of getting the address of system, we need to leak the address of the heap. So we won't need unsorted bins this time.

Creating solver...

Plan of attack:
- Free index 0
- Allocate index 0
- Read index 0
- Left bitshift 12 the value returned
- Send the value

Results:
```aiignore
That's it!

Here's your flag, friend: flag{s4f3_l1nk1nG_n07_s0_s4f3__!_56ac734613749d58}
```
## Challenge - Keymaker
```
Can you use this keymaker to leak the tcache_key?? nc offsec-chalbroker.osiris.cyber.nyu.edu 1223

Note: there is a ~2.75% chance there is a null byte in the key that would prevent leaking it. If this occurs, simply retry and the odds should be in your favor.
```
Inspecting binary:

```aiignore
$ checksec keymaker
[*] '/mnt/csgy9223_IntroOffSec/week_9/keymaker'
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
 ./keymaker
Welcome to the OffSec Keymaking machine!
We have a special going on where you can get
ONE FREE KEY with a custom message!

Choose an option:
1. Make key
2. Review key
3. Edit key
4. Delete key
```
The options seem pretty clear. The free key is stored 0x8 bytes into the memory location. The plan of attack is:
- Make a key
- Delete key
- Edit key, using first 0x8 bytes of address space "AAAAAAAA"
- Review the key which should provide all the first 0x8 bytes and as many non-zero bytes in the 2nd 0x8 bytes (the tcache key)
- Repeat if unsuccessful (~2.75% chance, restart the solver)

And that would have worked had the binary not wanted to free the address space after guessing correctly. This resulted in a double free error. I now need to adjust my script to store  the free key and use it after making another key to reallocate the space.

Results:

```aiignore
Here's your flag, friend: flag{Fr33_tc@ch3_k3y5_4_3v3ry1_!_1bd450319c799104}
```

## Challenge - Useful (and FUN) Message Server v2.0
```
Can you make the message server, running modern mitigations, cough up the flag?? nc offsec-chalbroker.osiris.cyber.nyu.edu 1221
```
Inspecting the binary:

```aiignore
9$ checksec useful_and_fun_message_server_v2.0
[*] '/mnt/csgy9223_IntroOffSec/week_9/useful_and_fun_message_server_v2.0'
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
$ ./useful_and_fun_message_server_v2.0
Welcome to the OffSec queue!
We store all your feedback in a fancy queue until
you're ready to send.                                                                                                                                         But this time, we're using modern mitigations!
Let's start out by giving you a helpful message: _
While we're feeling generous, here is another helpful message: R
Choose an option:
1. Add message
2. Review message
3. Edit message
4. Send messages
>
```
Same UI as the first useful_and_fun_message_server. Let's look at the binary to see what's different.

Looks like they leaked the address of printf and of __environ. We can make use of these.

The messages are upto 0x40 bytes, 0x48 are malloced for them and the 0x40 byte is set to 0. I'm guessing this is to prevent any message printing from being able to leak into the next message space. 

I started a solver script that pulls:
- printf_address: 0x7ffff7deb6f0
- __environ_address: 0x7fffffffe078

And computes:
- libc.address: 0x7ffff7d8b000
- bin/sh address: 0x7ffff7f63678
- system: 0x7ffff7ddbd70

Now using environment address, I need to compute the offset to the add() function RIP.
- (remote) gef➤ p 0x7fffffffe078 - 0x7fffffffdf28 = 0x150

The offset for the RIP pointer will be 0x158.
- add_rip_address: 0x7fffffffdf20

All address variables aer verified. Next we need to leak the address of the heap. To do this, we'll create a message, delete the message, then read the contents of that address space. I'll compute the addresses of the first 2 chunks (hopefully the only ones we'll need):
```aiignore
chunk_size = 0x48
tcache_size = 0x290 + 0x10
chunk_1 = heap_leak + tcache_size
print(f'chunk_1: {hex(chunk_1)}')
chunk_2 = chunk_1 + chunk_size + 0x8
print(f'chunk_2: {hex(chunk_2)}')
```
The addresses of the chunks have been verified in GDB:
- heap base address: 0x555555559000
- chunk_1: 0x5555555592a0 [Chunk(addr=0x5555555592a0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)]
- chunk_2: 0x5555555592f0 [Chunk(addr=0x5555555592f0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)]

This will allow me to poison the tcache by using the (address >> 12) ^ target_address computation.

Plan of attack:
- Use the creation and deletion of messages to poison tcache. Since we are using glibc 2.35, we'll have to leak the address of the heap, then determine the address of each message so that we can put a (address >> 12) ~forward address. The current plan is to use a single freed message at the top of the heap after tcache so that we get the heap base address.
- Use this starting message address, knowing that each subsequent address is 0x48 + 0x8 bytes beyond to get the address of each message we enter. We'll do this by reading the address and bit shift left by 12 (address << 12).
- Get the offset of one of the functions stack (not sure which one yet) to take over the return with our own ROP chain.
  - I ended up using an addition 8 bytes of offset into the stack. This was purely by accident as my original calculation was off, but if I tried to point directly to the RIP, I would get a malloc error. 
  - What I ended up doing was adding 8 bytes to the offset 0x158, and this cleared the malloc(). I'm not sure why malloc() didn't like pointing direction to the RIP. Something kept showing up as a corrupted tcache chunk.
  - With the additional 8 bytes, I sent in 0x8 "A"s, prior to my rop chain, which required an extra ret to align.
  - After some discussion with the professor in slack, I noted that the original address probably was not 0x10 byte aligned. That something I need to check for in the future.
- Use ROP to pop a shell.

First we need a solver script.

Results:

```aiignore
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x2c bytes:
    b'flag.txt\n'
    b'useful_and_fun_message_server_v2.0\n'
flag.txt
useful_and_fun_message_server_v2.0
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x34 bytes:
    b'flag{Unw4v3r1ng_AND_fl0ur1shinG_!_12219d1be9e76b32}\n'
flag{Unw4v3r1ng_AND_fl0ur1shinG_!_12219d1be9e76b32}
```

## Challenge - Biiiiig Message Server v2.0
```
Can you make the message server cough up the flag?? This server is using the most modern mitigations. 

nc offsec-chalbroker.osiris.cyber.nyu.edu 1222
```
Inspecting the binary:

```aiignore
$ checksec big_message_server_v2.0
[*] '/mnt/csgy9223_IntroOffSec/week_9/big_message_server_v2.0'
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
./big_message_server_v2.0
Welcome to the OffSec queue!
We store all your feedback in a fancy queue until
you're ready to send.
Let's start out by giving you a helpful message: b
While we're feeling generous, here is another helpful message: x.
Choose an option:
1. Add message
2. Review message
3. Edit message
4. Send messages
>
```
This looks a lot like the first one. Opening in binja to see what's different. Like the first one, this one stores the forward link in the first 8 bytes.

This one is providing the address of printf() and __environ. We'll work on getting those first.

- printf_address: 0x7ffff7deb6f0 
- __environ_address: 0x7fffffffe088
- libc.address: 0x7ffff7d8b000
- bin sh address: 0x7ffff7f63678
- system: 0x7ffff7ddbd70
- edit_rip_address: 0x7fffffffdf30 
  - rbp at 0x7fffffffdf30, rip at 0x7fffffffdf38 
  - p/x 0x7fffffffe088 - 0x7fffffffdf38 = 0x150 (make sure this is 16 byte aligned when used)

All addresses are verified using GDB.

One thing different is that the messages are limited to 0x40 bytes in length. The first one gave us a much larger option, to create an unsorted bins entry. When editing a message, 0x60 bytes can be entered. Perhaps we can do a heap overflow to poison tcache. Or maybe even just use the binary against itself.

Since the binary traverses each message by looking at the first 8 bytes and grabbing that address, and it continues doing that until it reaches the message number requested.

My first plan of attack will be to send 3 messages. Use editing of the first message to overwrite the next pointer of the 2nd message with a pointer to the stack. Then edit the 3rd message to send the rop chain over to hijack the return pointer of edit(). Let's see how it works out...

And the results are:

```aiignore
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x21 bytes:
    b'big_message_server_v2.0\n'
    b'flag.txt\n'
big_message_server_v2.0
flag.txt
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x33 bytes:
    b'flag{UN570ppabl3_&_Uny13ld1ng!_!_e6ea087d8e82deec}\n'
flag{UN570ppabl3_&_Uny13ld1ng!_!_e6ea087d8e82deec}
```
## Challenge - Comics v2.0
```
Another opportunity to make your own Cyanide and Happiness comic! Poison tcache and circumvent modern mitigations to get the flag! 

nc offsec-chalbroker.osiris.cyber.nyu.edu 1224
```
Inspecting:
```aiignore
$ checksec comics_v2.0
[*] '/mnt/csgy9223_IntroOffSec/week_9/comics_v2.0'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Running:
```aiignore
Please select an option?
1. Create a new comic
2. Print a comic
3. Edit a comic                                                                                                                               
4. Delete a comic
5. Quit
>
```
This one will be tough. No leak of __environ.


Glibc address from main_arena
-  p/x (0x7ffff7fa5ce0 & ~0xfff) - 0x00007ffff7d8b000 = 0x21a000

May punt on this one.