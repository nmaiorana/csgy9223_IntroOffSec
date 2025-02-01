# Week 1 CTF


## Challenge - Directions

### Evaluate the process
My first step was to execute the process to find out what it was looking for:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_1$ ./directions

Let's practice finding addresses again!

I found the raw bytes address of main() written somewhere: #x?RV
can you tell me the address of the call to the really_important_function?
>

Address 0x7ffd3c711d0a doesn't look right... Try again, friend!
(Did you send raw bytes?)
```
Looks like it is asking us to find addresses again. This time it's the address of where the function is being called. 

Let's look at the ELF header information:


```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_1$ readelf -Wh directions
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x1120
  Start of program headers:          64 (bytes into file)
  Start of section headers:          14448 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```

And let's look for interesting symbols:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_1$ readelf -Ws directions | grep main
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (2)
    19: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34
    38: 0000000000001223   282 FUNC    GLOBAL DEFAULT   16 main
    
    (csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_1$ readelf -Ws directions | grep really_important
    18: 0000000000001209    26 FUNC    GLOBAL DEFAULT   16 really_important_function
```

This appears to be similar to "vault4", except the address is not of the function, but where it's being called. So I'll try to run that solver script with the new names. I will use Ghidra to manually look up the address of where the function "really_important_function" is being called:

```aiignore
                             LAB_00101245                                    XREF[1]:     001012d3(*)  
        00101245 e8 bf ff        CALL       really_important_function                        undefined really_important_funct
                 ff ff
```
With this information, I will hardcode the address 0x1245 into the new "directions.py" solver script:


```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_1$ python ./directions.py
[+] Starting local process './directions': pid 505593

Let's practice finding addresses again!

I found the raw bytes address of main() written somewhere:
can you tell me the address of the call to the really_important_function?
>
main            raw         : b'#r\xc5\xb0xU\x00\x00'
main            address     : 0x5578b0c57223
[*] '/mnt/csgy9223_IntroOffSec/week_1/directions'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
main            offset      : 0x1223
base address                : 0x5578b0c56000
really_important_function offset      : 0x1245
really_important_function address     : 0x5578b0c57245
really_important_function address raw : b'Er\xc5\xb0xU\x00\x00\x00\x00\x00\x00\x00'
 You're right! The call to the really_important_function is at 0x5578b0c57245!
```

That was it, I found the flag. Now to see how this address can be derived from using pwntools.

I added the following logic to pull the data using pwntools and ELF:

```python
# Get the  calling address for the target
# Get the size of the .text section
text_section = e.get_section_by_name('.text')
text_section_size = text_section.header.sh_size
# Disassemble the binary
disassembly = e.disasm(e.entry, text_section_size)

# Find call instructions to the target function
target_calling_address_offset = 0x0
for line in disassembly.split('\n'):
    if f'call   {hex(target_address_offset)}' in line:
        target_calling_address_offset = int(line.split(':')[0], 16)
        break

print_address(target_address_name, 'function call offset', target_calling_address_offset)
```

### Script Flow

Updates to the scrip include adding a "print_address()" function for consistent formatting of the output.

The basic flow of the script is the following:
- Start the process
  - Local is using "./directions"
  - Remote is using "offsec-chalbroker.osiris.cyber.nyu.edu on port 1244"
- Extract the raw source address from the process output
- Get the byte order from ELF
- Convert the raw source address to an integer
- Use ELF to get the source address offset
- Compute the base address using base = address - offset
- Use ELF to get the target address offset
- Use ELF disassembly to get the target address calling address
- Compute the target calling address using address = base + offset
- Convert the target calling address to raw bytes
- Submit the raw bytes to the process

Here are the results of running the solver script:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_1$ python ./directions.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1244: Done
[*] '/mnt/csgy9223_IntroOffSec/week_1/directions'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
 hello, nam10102. Please wait a moment...

Let's practice finding addresses again!

I found the raw bytes address of main() written somewhere:
can you tell me the address of the call to the really_important_function?
>
main                          raw                           : b"#\x92\xfd'\xbaU\x00\x00"
main                          address                       : 0x55ba27fd9223
main                          offset                        : 0x1223
base                          address                       : 0x55ba27fd8000
really_important_function     offset                        : 0x1209
really_important_function     function call offset          : 0x1245
really_important_function     call address                  : 0x55ba27fd9245
really_important_function     call address raw              : b"E\x92\xfd'\xbaU\x00\x00\x00\x00\x00\x00\x00"
 You're right! The call to the really_important_function is at 0x55ba27fd9245!



Here's your flag, friend: flag{st4t1c_4n4lys1s_g1v3s_us_s0_much_1nf0_4b0ut_4_b1n4ry!_58b217f5846f46c3}
```
## Challenge - GDB 0
This challenge appears to be only available remotely. It starts with the following message:

```aiignore
Good evening Agent Phelps.


         Your mission, should you choose to accept it,
         is to step through the code, find the place
         where the password is hiding and use that
         password to rescue the flag.
         As always, should you or any of your IM Force
         be caught or killed, the Secretary will disavow
         any knowledge of your actions.


         This tape will self-destruct in 5 seconds.
         Good luck!
```
Then continues:

```aiignore
------   Welcome to GDB 0   ------


         This time you will have access to the source code!

------------------------------------------------------------------------------

[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".


        HEEEELP! My password is somewhere around here, but I can't find it.
        Can you tell me my password?
        >
```

Entering a value drops me into gdb:

```aiignore
        >

        That's nice, but it doesn't look like my password!
        Try again friend!


[Inferior 1 (process 64) exited with code 01]


------------------------------------------------------------------------------

         Remember, you can type the command `run` to run the program
         or type `break main` and then `run` to start debugging!


pwndbg> 
```

My first step was to setup a breakpoint for main and run:

```aiignore
pwndbg> b main
Breakpoint 1 at 0x5639e71ac245: file gdb0.c, line 19.
pwndbg> r
Starting program: /home/ctf/gdb0
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main (argc=1, argv=0x7ffc27be3958) at gdb0.c:19
19          set_buffering_mode();
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
 RAX  0x562e20fe5229 (main) ◂— endbr64
 RBX  0
 RCX  0x562e20fe7d88 (__do_global_dtors_aux_fini_array_entry) —▸ 0x562e20fe51e0 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x7ffc27be3968 —▸ 0x7ffc27be4e7a ◂— 'LANGUAGE=en_US:en'
 RDI  1
 RSI  0x7ffc27be3958 —▸ 0x7ffc27be4e6b ◂— '/home/ctf/gdb0'
 R8   0x7f654c0b8f10 (initial+16) ◂— 4
 R9   0x7f654c0d2040 (_dl_fini) ◂— endbr64
 R10  0x7f654c0cc908 ◂— 0xd00120000000e
 R11  0x7f654c0e7660 (_dl_audit_preinit) ◂— endbr64
 R12  0x7ffc27be3958 —▸ 0x7ffc27be4e6b ◂— '/home/ctf/gdb0'
 R13  0x562e20fe5229 (main) ◂— endbr64
 R14  0x562e20fe7d88 (__do_global_dtors_aux_fini_array_entry) —▸ 0x562e20fe51e0 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7f654c106040 (_rtld_global) —▸ 0x7f654c1072e0 —▸ 0x562e20fe4000 ◂— 0x10102464c457f
 RBP  0x7ffc27be3840 ◂— 1
 RSP  0x7ffc27be3790 —▸ 0x7ffc27be3958 —▸ 0x7ffc27be4e6b ◂— '/home/ctf/gdb0'
 RIP  0x562e20fe5245 (main+28) ◂— mov eax, 0
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp 0x7ffc27be3790 —▸ 0x7ffc27be3958 —▸ 0x7ffc27be4e6b ◂— '/home/ctf/gdb0'
01:0008│-0a8 0x7ffc27be3798 ◂— 0x100000000
02:0010│-0a0 0x7ffc27be37a0 ◂— 0
... ↓        5 skipped
───────────────────────────────[ SOURCE (CODE) ]────────────────────────────────
In file: /home/ctf/gdb0.c:19
   15 int main(int argc, char** argv) {
   16     char flag[0x80];
   17     char buffer[0x20];
   18
 ► 19     set_buffering_mode();
   20     puts("\n\n\tHEEEELP! My password is somewhere around here, but I can't find it.");
   21     puts("\tCan you tell me my password?");
   22
   23     printf("\t> ");
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x562e20fe5245 <main+28>    mov    eax, 0
   0x562e20fe524a <main+33>    call   set_buffering_mode          <set_buffering_mode>

   0x562e20fe524f <main+38>    lea    rax, [rip + 0xdb2]
   0x562e20fe5256 <main+45>    mov    rdi, rax
   0x562e20fe5259 <main+48>    call   puts@plt                    <puts@plt>

   0x562e20fe525e <main+53>    lea    rax, [rip + 0xdea]
   0x562e20fe5265 <main+60>    mov    rdi, rax
   0x562e20fe5268 <main+63>    call   puts@plt                    <puts@plt>

   0x562e20fe526d <main+68>    lea    rax, [rip + 0xdf9]
   0x562e20fe5274 <main+75>    mov    rdi, rax
   0x562e20fe5277 <main+78>    mov    eax, 0
────────────────────────────────────────────────────────────────────────────────
pwndbg>
```
Next I'll step through the code to find anything interesting:

````aiignore
In file: /home/ctf/gdb0.c:24
   20     puts("\n\n\tHEEEELP! My password is somewhere around here, but I can't find it.");
   21     puts("\tCan you tell me my password?");
   22
   23     printf("\t> ");
 ► 24     fgets(buffer, sizeof(buffer), stdin);
   25     buffer[strcspn(buffer, "\n")] = '\0';
   26
   27     if (strcmp(buffer, get_password()) == 0) {
   28         puts("\tYou did it! You found my password!");
````
So I found a function called get_password(). I'll set a breakpoint for it and continue:

```aiignore
In file: /home/ctf/gdb0.c:41
   37 }
   38
   39
   40 char* get_password() {
 ► 41     return password;
   42 }
   43
```

There is variable called password. Next I need to print the string stored in password:

```aiignore
pwndbg> x/s password
0x562e20fe8010 <password>:      "4_v3ry_1337_s3cr3t_p4ssw0rd"
```

Using this value to answer the prompt:

```aiignore
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".


        HEEEELP! My password is somewhere around here, but I can't find it.
        Can you tell me my password?
        > 4_v3ry_1337_s3cr3t_p4ssw0rd
        You did it! You found my password!

Here's your flag, friend: flag{34sy_3n0ugh_wh3n_y0u_g3t_d3bug_symb0ls!_23bce8f0f5d80f82}
```
## Challenge GDB 1

The challenge command is:

```aiignore
nc offsec-chalbroker.osiris.cyber.nyu.edu 1242
```
And produced the following message:

```aiignore
         ------   Welcome to GDB 1   ------


 Use the command `run` to run the program
 use `break main` and then `run` to start debugging
 use `disass` to disassemble the current function
 add a break after a 'read command' and look for the flag!


pwndbg> run
Starting program: /home/ctf/gdb1
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
        What is the address of the buffer the flag is read into?
        (hint: it is zeroed out at the beginning of the function)
        >

        Oops, I forgot to tell you I can only read hex!

[Inferior 1 (process 94) exited with code 01]
```
After entering a value, I was dropped into GDB did the following.
- Set a break point at 'main' and ran the program
- Ran the disassemble command.
- Looked for a "read" command and found:
```
   0x000055bbbaba9322 <+121>:   call   0x55bbbaba9381 <read_input>
   0x000055bbbaba9327 <+126>:   mov    QWORD PTR [rbp-0x68],rax
```

- Set a breakpoint: b *(0x000055bbbaba9327)
- I looked for the buffer memory address that is set to 0 at the beginning of the function
  - I did some research on how "memset" works and which registers are used. The following set of instructions set the memory address space, number of bytes and value to set

````aiignore
   0x000055bbbaba92c9 <+32>:    xor    eax,eax
   0x000055bbbaba92cb <+34>:    lea    rax,[rbp-0x60]
   0x000055bbbaba92cf <+38>:    mov    edx,0x50
   0x000055bbbaba92d4 <+43>:    mov    esi,0x0
   0x000055bbbaba92d9 <+48>:    mov    rdi,rax
   0x000055bbbaba92dc <+51>:    call   0x55bbbaba9140 <memset@plt>
````
- The buffer memory address is the rbp register - 0x60.
- RBP: 0x7fffc0bd3a00
- pwndbg> x/h 0x7fffc0bd3a00 - 0x60 = 0x7fffc0bd39a0
- Stepping through the instructions "ni"
```aiignore
 0x55bbbaba92dc <main+51>    call   memset@plt                  <memset@plt>
        s: 0x7fffc0bd39a0 ◂— 0
        c: 0
        n: 0x50
```
- The address of the buffer is 0x7fffc0bd39a0
- Continue process
```aiignore
Continuing.
        What is the address of the buffer the flag is read into?
        (hint: it is zeroed out at the beginning of the function)
        > 0x7fffc0bd39a0
        ....
           0x55bbbaba9335 <main+140>    lea    rax, [rip + 0xd4b]              RAX => 0x55bbbabaa087 ◂— "\tThat's the right address!"
        ....
```
- Continue stepping through "ni"
```aiignore
03:0018│-068     0x7fffc0bd3998 —▸ 0x7fffc0bd39a0 ◂— 'flag{s331ng_wh4t_is_g01ng_0n_1ns1d3_4_pr0gr4m_1s_s00_1337!_388d64490778ee71}'
```
The flag is: flag{s331ng_wh4t_is_g01ng_0n_1ns1d3_4_pr0gr4m_1s_s00_1337!_388d64490778ee71}

## Challenge Basic Math
This one looks a lot like "directions" where the address of a function is provided in the hint, and it needs to be read in an unpacked to compute the base address.

One different twist is that instead of looking for the address of another symbol or function, it was asking for the address of an add instruction:

```aiignore
I found the raw bytes address of `totally_uninteresting_function` written somewhere:
can you tell me the address of the ADD instruction in basic_math?
```

First thing to do was look at the file and see what it has to offer us:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_1$ file basic_math
basic_math: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f2109b5789a5419058a79b0f701f5217972d0edf, for GNU/Linux 3.2.0, not stripped

(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_1$ readelf -Wh basic_math
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x1160
  Start of program headers:          64 (bytes into file)
  Start of section headers:          14584 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
  
 (csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_1$ readelf -Ws basic_math | grep totally_uninteresting_function
    33: 0000000000001249    26 FUNC    GLOBAL DEFAULT   16 totally_uninteresting_function
```

My first mistake, as you will see later, was not to also do a lookup for the "basic_math" symbol.

I copied the "directions.py" solver script into "basic_math.py" and modified the source and target names.

The first time I ran it, I got an error that the symbol for "add" could not be found.

```aiignore
    target_address_offset = e.symbols[target_address_name]
                            ~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^
  File "/home/nmaiorana/csgy9223py/lib/python3.12/site-packages/pwnlib/elf/elf.py", line 164, in __missing__
    raise KeyError(name)
```
It was then I realized I was not looking for a function "add", but an "add" instruction. Running gdb on the file, I thought I could pull the instruction from there. However, I made a mistake in thinking the "add" instruction was from basic_math main routine. My thought was to pull the address from the run, and pass it into the using gbr. I'm not sure if this could have worked, because my next hurdle was to convert  it to raw bytes. 

I tried using gbr match functions to do a conversion, but my answers all got rejected.

My next thought was to hardcode the offset into my solver script and compute the address from the acquired base address. Using Ghidra, I opend the file, found the offset to the "add" instruction and plugged it in. This of course was rejected as well.

I decided to check the math on computing the address by checking the address for "totally_uninteresting_function":
```aiignore
base address                                : 0x5566815ea000
totally_uninteresting_function address      : 0x5566815eb249
```
I used the Memory Map tool in Ghidra, set the base address to my computed one and verified that it matched the one I read in.
```aiignore
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined totally_uninteresting_function()
             undefined         AL:1           <RETURN>
                             totally_uninteresting_function                  XREF[5]:     Entry Point(*), 
                                                                                          main:5566815eb2d4(*), 
                                                                                          main:5566815eb2db(*), 
                                                                                          5566815ec28c, 5566815ec348(*)  
    5566815eb249 f3 0f 1e fa     ENDBR64
```
A match. My math was good.

While scrolling around in Ghidra, I noticed that there was a function called "basic_math" and I noticed an "add" instruction there. Light bulb comes on!

```aiignore
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined basic_math()
             undefined         AL:1           <RETURN>
             undefined4        Stack[-0xc]:4  local_c                                 XREF[1]:     00101287(W)  
             undefined4        Stack[-0x10]:4 local_10                                XREF[2]:     0010127c(W), 
                                                                                                   00101282(R)  
             undefined4        Stack[-0x14]:4 local_14                                XREF[2]:     00101274(W), 
                                                                                                   0010127f(R)  
                             basic_math                                      XREF[4]:     Entry Point(*), main:0010134a(*), 
                                                                                          00102294, 00102368(*)  
        00101263 f3 0f 1e fa     ENDBR64
        00101267 55              PUSH       RBP
        00101268 48 89 e5        MOV        RBP,RSP
        0010126b 48 83 ec 10     SUB        RSP,0x10
        0010126f e8 dc fe        CALL       <EXTERNAL>::rand                                 int rand(void)
                 ff ff
        00101274 89 45 f4        MOV        dword ptr [RBP + local_14],EAX
        00101277 e8 d4 fe        CALL       <EXTERNAL>::rand                                 int rand(void)
                 ff ff
        0010127c 89 45 f8        MOV        dword ptr [RBP + local_10],EAX
        0010127f 8b 55 f4        MOV        EDX,dword ptr [RBP + local_14]
        00101282 8b 45 f8        MOV        EAX,dword ptr [RBP + local_10]
        00101285 01 d0           ADD        EAX,EDX
```

I hardcoded the offset to this "add" instruction and ran the script. Bingo. I got the flag.

```aiignore
add             offset      : 0x1285
add             address     : 0x5566815eb285

You're right! The call to the add instruction is at 0x5566815eb285!

Here's your flag, friend: flag{R34d1ng_4ss3mbly_l4ngu4ge_w4snt_th4t_h4rd!_b8cf360b6c1a89ad}
```
#### *Footnote* ####
After completing the challenge, I realized that I could have used gdb to disassemble the "basic_math" function and find the address of the "add" instruction. I could have then used the same logic as I did for the "totally_uninteresting_function" to compute the base address and then the target address. I will try this in the future. My guess is that I could have used pwntools with gdb to automate this process.

```aiignore
gef➤  disass basic_math
Dump of assembler code for function basic_math:
   0x0000000000001263 <+0>:     endbr64
   0x0000000000001267 <+4>:     push   rbp
   0x0000000000001268 <+5>:     mov    rbp,rsp
   0x000000000000126b <+8>:     sub    rsp,0x10
   0x000000000000126f <+12>:    call   0x1150 <rand@plt>
   0x0000000000001274 <+17>:    mov    DWORD PTR [rbp-0xc],eax
   0x0000000000001277 <+20>:    call   0x1150 <rand@plt>
   0x000000000000127c <+25>:    mov    DWORD PTR [rbp-0x8],eax
   0x000000000000127f <+28>:    mov    edx,DWORD PTR [rbp-0xc]
   0x0000000000001282 <+31>:    mov    eax,DWORD PTR [rbp-0x8]
   0x0000000000001285 <+34>:    add    eax,edx
   0x0000000000001287 <+36>:    mov    DWORD PTR [rbp-0x4],eax
   0x000000000000128a <+39>:    nop
   0x000000000000128b <+40>:    leave
   0x000000000000128c <+41>:    ret
End of assembler dump.
```
## Challenge GDB 2
Starting the challenge:
```aiignore
                 ------   Welcome to GDB 2   ------


 Let's start debugging!
```
This one also dropped me into "gdb". My first step was to run the process:
```aiignore
Starting program: /home/ctf/gdb2
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".


                The flag is somewhere around here!
                Can you find it?
```

Next I set a breakpoint for "main" and ran the program and perform a "disassemble":

```aiignore
   0x000055bf7a0ae209 <+0>:     endbr64
   0x000055bf7a0ae20d <+4>:     push   rbp
   0x000055bf7a0ae20e <+5>:     mov    rbp,rsp
=> 0x000055bf7a0ae211 <+8>:     sub    rsp,0x10
   0x000055bf7a0ae215 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x000055bf7a0ae218 <+15>:    mov    QWORD PTR [rbp-0x10],rsi
   0x000055bf7a0ae21c <+19>:    mov    eax,0x0
   0x000055bf7a0ae221 <+24>:    call   0x55bf7a0ae2c7 <set_buffering_mode>
   0x000055bf7a0ae226 <+29>:    mov    eax,0x0
   0x000055bf7a0ae22b <+34>:    call   0x55bf7a0ae250 <read_file>
   0x000055bf7a0ae230 <+39>:    lea    rax,[rip+0xdd1]        # 0x55bf7a0af008
   0x000055bf7a0ae237 <+46>:    mov    rdi,rax
   0x000055bf7a0ae23a <+49>:    call   0x55bf7a0ae0b0 <puts@plt>
   0x000055bf7a0ae23f <+54>:    mov    edi,0x3
   0x000055bf7a0ae244 <+59>:    call   0x55bf7a0ae110 <sleep@plt>
   0x000055bf7a0ae249 <+64>:    mov    eax,0x0
   0x000055bf7a0ae24e <+69>:    leave
   0x000055bf7a0ae24f <+70>:    ret
```
A short program indeed.

Looking over the instructions, I decided to put in a breakpoint at read_file. I didn't see anything interesting there, so I started stepping through the instructions. I got to a read_file function and stepped inside.
```aiignore
=> 0x00005571f0c20250 <+0>:     endbr64
   0x00005571f0c20254 <+4>:     push   rbp
   0x00005571f0c20255 <+5>:     mov    rbp,rsp
   0x00005571f0c20258 <+8>:     sub    rsp,0x10
   0x00005571f0c2025c <+12>:    mov    esi,0x0
   0x00005571f0c20261 <+17>:    lea    rax,[rip+0xddb]        # 0x5571f0c21043
   0x00005571f0c20268 <+24>:    mov    rdi,rax
   0x00005571f0c2026b <+27>:    mov    eax,0x0
   0x00005571f0c20270 <+32>:    call   0x5571f0c200f0 <open@plt>
   0x00005571f0c20275 <+37>:    mov    DWORD PTR [rbp-0x4],eax
   0x00005571f0c20278 <+40>:    cmp    DWORD PTR [rbp-0x4],0xffffffff
   0x00005571f0c2027c <+44>:    jne    0x5571f0c2029c <read_file+76>
   0x00005571f0c2027e <+46>:    lea    rax,[rip+0xdcb]        # 0x5571f0c21050
   0x00005571f0c20285 <+53>:    mov    rdi,rax
   0x00005571f0c20288 <+56>:    mov    eax,0x0
   0x00005571f0c2028d <+61>:    call   0x5571f0c200c0 <printf@plt>
   0x00005571f0c20292 <+66>:    mov    edi,0x1
   0x00005571f0c20297 <+71>:    call   0x5571f0c20100 <exit@plt>
   0x00005571f0c2029c <+76>:    mov    eax,DWORD PTR [rbp-0x4]
   0x00005571f0c2029f <+79>:    mov    edx,0x80
   0x00005571f0c202a4 <+84>:    lea    rcx,[rip+0x2d95]        # 0x5571f0c23040 <flag>
   0x00005571f0c202ab <+91>:    mov    rsi,rcx
   0x00005571f0c202ae <+94>:    mov    edi,eax
   0x00005571f0c202b0 <+96>:    call   0x5571f0c200d0 <read@plt>
   0x00005571f0c202b5 <+101>:   lea    rax,[rip+0xdc3]        # 0x5571f0c2107f
   0x00005571f0c202bc <+108>:   mov    rdi,rax
   0x00005571f0c202bf <+111>:   call   0x5571f0c200b0 <puts@plt>
   0x00005571f0c202c4 <+116>:   nop
   0x00005571f0c202c5 <+117>:   leave
   0x00005571f0c202c6 <+118>:   ret
```
Stepping through I noticed this:
```aiignore
0x5571f0c202b0 <read_file+96>     call   read@plt                    <read@plt>
        fd: 6 (/home/ctf/flag.txt)
        buf: 0x5571f0c23040 (flag) ◂— 0
        nbytes: 0x80
```
Could "0x5571f0c23040" be the buffer where the flag is read in? A quick print of the address showed an empty string "". Stepping over read@plt gave me what I was looking for:

```aiignore
pwndbg> x/s 0x5571f0c23040
0x5571f0c23040 <flag>:  "flag{gl4d_y0u_f1gur3d_0ut_h0w_t0_f1nd_th3_fl4g!_619b18c6f1e2c254}\n"
```











