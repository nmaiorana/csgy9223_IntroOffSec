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

Using GDB, I will load the libthread_db and step through it.

## Challenge - GDB 1
## Challenge - Basic Math
## Challenge - GDB 2
