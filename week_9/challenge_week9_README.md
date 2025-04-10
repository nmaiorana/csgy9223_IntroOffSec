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
- Review the key which should provide all the first 0x8 bytes and as many non-zero bytes in the 2nd 0x8 bytes (the free key)
- Repeat if unsuccessful (~2.75% chance, restart the solver)

And that would have worked had the binary not wanted to free the address space after guessing correctly. This resulted in a double free error. I now need to adjust my script to store  the free key and use it after making another key to reallocate the space.

Results:

```aiignore
Here's your flag, friend: flag{Fr33_tc@ch3_k3y5_4_3v3ry1_!_1bd450319c799104}
```


