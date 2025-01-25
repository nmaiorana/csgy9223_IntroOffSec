# Week 0 CTF

This week of challenges were mainly centered around extracting address values for various functions. The tools I used for this week were:

- pwntools
- readelf

A majority of the time was spent getting my environment setup. For this I upgraded my WSL version of Ubuntu to Ubuntu 24.04.1 LTS. I also had to install python (Python 3.12.3) into a new python env. From here I installed pwntools.

Most, if not all of my script editing is done by using PyCharm on my native Windows machine, with the project directory mounted into my WSL environment.

There are only 5 solver scripts. The rest were scratchpad Python scripts to perform calculations and print the results. The names of the solver scripts coincide with the challenge name:
- are_you_alive.py
- baby_glibc.py
- secret_vault_3.py
- glibc.py
- secret_vault_4.py
### Learnings
From the 1st challenge to the last I learned quite a few things. Aside from the various tools needed to complete the challenges, I learned how to use them effectively to gain information quicker. For instance, using readelf to gain information about the target process and how to get the interesting information.

I also learned that being more generic in an approach, from a solver script perspective, can minimize the changes for scripts created later. For instance, using specific variable names like "sleep_address" are better suited using something like "target_address".

Using variables to store the names of source and target symbols also makes it quicker to alter a script looking for different symbols and minimizes the amount of code needing to be changed. This also is useful for providing output from the script to show meaningful information like:

```aiignore
fake_vault      offset      : 0x4030
base address                : 0x556ef84ce000
secret_vault    offset      : 0x4038
secret_vault    address     : 0x556ef84d2038
secret_vault    address raw : b'8 M\xf8nU\x00\x00\x00\x00\x00\x00\x00'
```
For this, I only needed to change the variable names for the source and target symbols.

The biggest learning was from getting information from the challenge prompt. I'm pretty new to CTF challenges and the second challenge was presenting me with vital information (the address of a function) that would be needed to solve the challenge. I struggled for quite sometime until Professor Dupont focused my attention on the challenge prompt.

Overall I think my write-ups got better. When I review this document, I see that the last challenge had the best presentation of my work. I will use this as an example going forward.

To follow are the list of challenges I completed for the week:

## Challenge - Are You Alive: Server Edition

This is a simple challenge to get us started to use Osiris. The goal is to submit a message to the server and get a response back.
The message is will be sent using the following command line syntax:

```nc offsec-chalbroker.osiriris.cyber.nyu.edu 1237```

### Host Server Setup
I first started by launching the Ubuntu server on my Surface Pro 6. I decided to update my Ubuntu server to the latest version.

In WSL Ubuntu:

```
sudo apt update && sudo apt full-upgrade
```

In Windows:

```  
wsl -l -v
wsl --terminate Ubuntu
```

Restart Ubuntu and then:

```sudo do-release-upgrade```

### Attempt 1
For this attempt I started the VPN on my Windows machine, thinking it would transfer over to the WSL Ubuntu. I was wrong. I had to start the VPN on the Ubuntu server.
I executed the command:

```
nc offsec-chalbroker.osiriris.cyber.nyu.edu 1237
```

And the command hung. I had to CTL+C to exit.

### Attempt 2
For this attempt I installed the Open Connect VPN server on my Ubuntu server. If first had to turn off the VPN on Windows.

On Ubuntu:

```
sudo apt-get update
sudo apt-get install openconnect network-manager-openconnect network-manager-openconnect-gnome
```
I then connected to the VPN server:

```
sudo openconnect --background --user nam10102 vpnsec.nyu.edu
```

I was prompted for my password and then prompted again. For the 2nd prompt I entered "push" and Duo prompted me on my phone.

I entered the command:

```
nc offsec-chalbroker.osiriris.cyber.nyu.edu 1237
```

and was prompted by the server:

```
Please input your NetID (something like abc123):
```

I entered my NetID and was greeted with:

```
Here's your flag, friend: flag{n0w_y0u_kn0w_wh4t_t0_d0_t0_w1n!_6f07d51a7d15ab78}
```

Success!

### Attempt 3 using Python and pwntools

I created a script using pwntools to capture this flag:

```
from pwn import *

p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1237)
p.recvuntil(b"abc123):")
p.sendline(b"nam10102")
p.recvuntil(b"moment...")
p.recvline()
p.recvline()
print(p.recvline())
```
The results were: 

```aiignore
 python are_you_alive.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1237: Done
b"Here's your flag, friend: flag{n0w_y0u_kn0w_wh4t_t0_d0_t0_w1n!_6f07d51a7d15ab78}\n"
[*] Closed connection to offsec-chalbroker.osiris.cyber.nyu.edu port 1237
```

## Challenge - Baby glibc

This challenge was bit tricky. The goal was to find the address of the sleep() function. The prompt generated by the challenge included the address of the printf() function.

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ ./baby_glibc
Enough of PIEs 🥧 for today! What about some practice with ASLR and GLIBC?
I found glibc's `printf` function address written on a post-it note: ����
Agh! raw bytes again!

Can you tell me the address of the sleep() function?
```
The value for the address was encoded and was displayed as "����". characters. By using pwntools, I was able to decode the address.

```python
print(p.recvuntil(b"note: "))
printf_address = int.from_bytes(p.recvline().strip(), byteorder="little")
```

Using this address from the clue, I was able to use ELF to read the libc.so.6 file and find the offset address values for sleep() and printf() functions. With the address of the printf() function, I was able to compute the base address:
```python
base_address = printf_address - printf_offset
```
With the base address computed, I was able to calculate the address of the sleep() function:

```python
sleep_address = base_address + sleep_offset
```

I received my flag on both the local and remote versions.

```aiignore
Here's your flag, friend: flag{y0ur_g0nna_g3t_re4lly_fam1li4r_w1th_Gl1bC!_ea052dd573375523}
```

## Secret Vault 0

For this one we were given a file called "vault0". The file is an ELF 64-bit executable. I used readelf to get the symbol information from the file:

```
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ readelf -Ws vault0 | grep secret_vault
    38: 0000000000401236    21 FUNC    GLOBAL DEFAULT   15 secret_vault
```

Using python to convert the hex address 0x0000000000401236 to decimal I got 4198966. And this gave me my flag:

```python
address_of_vault = 0x0000000000401236
print(address_of_vault)

4198966
```

The result of running the script with the right answer was:
```
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1230
Please input your NetID (something like abc123): nam10102
hello, nam10102. Please wait a moment...
Can you tell me the address of the secret vault?

> 4198966
Lucky me! that's my favorite vault!

Here's your flag, friend: flag{Th3_g00d_0ld_d4ys_0f_N0_PIE!_16557334d461883a}
```

## Challenge - Secret Vault 1
For this challenge it was similar to secret vault 0, except PIE ws involved to randomize the address space. A hint was provided with the base address.

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ ./vault1
Can you still find the address of the secret vault?
I was told this time it's protected by some 'PIE' 🥧
But I found this base address 0x563a0df10000 on a post-it note!
```
Using readelf, I discovered the offset for the symbol for "secret_vault" is 0x0000000000001249.

By adding the base address to the offset I was able to produce the address of "secret_vault" as 0x563a0df11249.

address = base address + offset

```python
address_of_vault = 0x0000000000001249
base_address = 0x5563d5647000

print(hex(base_address + address_of_vault))

0x5563d5648249
```
0x563a0df11249 = 0x563a0df10000 + 0x0000000000001249

The result was:
```aiignore
> 0x5563d5648249
Lucky me, that's my favorite vault!

Here's your flag, friend: flag{n0t_s00_PIE_1f_w3_g3t_th3_BASE!_d8c6d7a669a99b58}
```

## Challenge - Secret Vault 2
This was similar to Secret Vault 1, except they provided an address for a fake_vault. Using readelf I was able to get the offsets for both the secret_vault and the fake_vault:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ readelf -Ws vault2 | grep vault
    11: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS vault2.c
    12: 0000000000004029     1 OBJECT  LOCAL  DEFAULT   26 fake_vault
    40: 0000000000001269    26 FUNC    GLOBAL DEFAULT   16 secret_vault
```

Using the address provided for the fake_vault (0x55baab5bf029), I was able to compute the base address. Once this was determined, the address of the secret_vault was computed:

```python
fake_vault_offset = 0x0000000000004029
fake_vault_address = 0x55baab5bf029
base_address = fake_vault_address - fake_vault_offset
secret_vault_offset = 0x0000000000001269
secret_vault_address = base_address + secret_vault_offset
print(hex(secret_vault_address))

0x55baab5bc269
```
Once entered, the flag was provided:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1232
Please input your NetID (something like abc123): nam10102
hello, nam10102. Please wait a moment...
Can you still find the address of the secret vault?
I found this fake vault at 0x55baab5bf029, but it doesn't appear to be the right one!

> 0x55baab5bc269
Lucky me, that's my favorite vault!

Here's your flag, friend: flag{wh0_n33ds_th3_BASE_1f_w3_h4v3_4_lEaK!_4962a0805bfc8305}
```

## Challenge - Secret Vault 3
This challenge was similar to Baby glibc and Secret Vault 1 in that the base address was sent and an encoded string in the challenge message.

```aiignore
b' hello, nam10102. Please wait a moment...\nCan you still find the address of the secret vault?\n\nI found this base address written on a post-it note: '
```

Using the following code, I was able to decode the base address:

```python
print(p.recvuntil(b"note: "))
base_address = int.from_bytes(p.recvline().strip(), byteorder="little")
print("base address", hex(base_address))

base address 0x55ccc7dfb000
```
Using the ELF I was able to get the offset of the "secret_vault" symbol:

```python
e = ELF(libc)
secret_vault_offset = e.symbols['secret_vault']
print("secret_vault offset", hex(secret_vault_offset))

secret_vault offset 0x1269
```

By adding the base address to the offset, I computed the address of the "secret_vault" symbol:

```python
secret_vault_address = base_address + secret_vault_offset
print("secret_vault address", hex(secret_vault_address))

secret_vault address 0x55ccc7dfc269
```

Here is the full output from the run:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ python secret_vault_3.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1233: Done
[*] '/mnt/csgy9223_IntroOffSec/challenge0/vault3'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
b' hello, nam10102. Please wait a moment...\nCan you still find the address of the secret vault?\n\nI found this base address written on a post-it note: '
secret_vault offset 0x1269
base address 0x55ccc7dfb000
secret_vault address 0x55ccc7dfc269
/mnt/csgy9223_IntroOffSec/challenge0/secret_vault_3.py:41: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(hex(secret_vault_address))
b" Lucky me, that's my favorite vault!\n"
b"Here's your flag, friend: flag{th3_l34st_s1gn1f1c4nt_byt3_c0m3s_f1rst!_9fdb98c7fff7d55b}\n"
```

## Challenge - Glibc
This challenge was similar to Baby glibc in that it was requesting an address for "_IO_2_1_stdout_" symbol and provided the address for _IO_2_1_stdin_ which needed to be read and converted to an int value:

```aiignore
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1236: Done
 hello, nam10102. Please wait a moment...
Let's practice one more time finding GLIBC symbols! You know the drill 😎

I found glibc's `_IO_2_1_stdin_` address written on a post-it note:
Can you tell me the address of glibc's `_IO_2_1_stdout_` variable?
```
For this we pulled in the given address and used ELF to pull the offset addresses:

```python
_IO_2_1_stdin__address_raw = p.recvline().strip()
print(p.recvuntil(b">").decode())
print("_IO_2_1_stdin__address raw", _IO_2_1_stdin__address_raw)
_IO_2_1_stdin__address = int.from_bytes(_IO_2_1_stdin__address_raw, byteorder="little")
print("_IO_2_1_stdin_ address", hex(_IO_2_1_stdin__address))

# Open Shared library to get offset addresses
e = ELF(libc)

# Get source offset
_IO_2_1_stdin__offset = e.symbols["_IO_2_1_stdin_"]
print("_IO_2_1_stdin_ offset", hex(_IO_2_1_stdin__offset))

# Get the offset for the target address
_IO_2_1_stdout__offset = e.symbols["_IO_2_1_stdout_"]
print("_IO_2_1_stdout_ offset", hex(_IO_2_1_stdout__offset))

_IO_2_1_stdin__address raw b'\xa0\xba\x1d\xf2\xfa\x7f\x00\x00'
_IO_2_1_stdin_ address 0x7ffaf21dbaa0
_IO_2_1_stdin_ offset 0x21aaa0
_IO_2_1_stdout_ offset 0x21b780
```
With the source address and offset I computed the base address:

```python
# Compute the base address from the offset and the given address (base = address - offset)
base_address = _IO_2_1_stdin__address - _IO_2_1_stdin__offset
print("base address", hex(base_address))

base address 0x7ffaf1fc1000
```

And now we have enough information to compute the target address:

```python
# Compute the target address (address = base + offset)
_IO_2_1_stdout__address = base_address + _IO_2_1_stdout__offset
print("_IO_2_1_stdout_ address", hex(_IO_2_1_stdout__address))

_IO_2_1_stdout_ address 0x7ffaf21dc780
```

This challenge requires raw bytes for the answer, so I needed to convert the decimal value to byte values.

```python
# This challenge required raw bytes
_IO_2_1_stdout__address_raw = _IO_2_1_stdout__address.to_bytes((_IO_2_1_stdout__address.bit_length() + 7) // 4,
                                                               byteorder='little')
print("_IO_2_1_stdout_ address raw", _IO_2_1_stdout__address_raw)

_IO_2_1_stdout_ address raw b'\x80\xc7\x1d\xf2\xfa\x7f\x00\x00\x00\x00\x00\x00\x00'
```

The script was able to compute the right address and I was able to capture the flag:


```aiignore
You are right! 0x7ffaf21dc780 is the correct address!





Here's your flag, friend: flag{3v3n_th3_st4nd4rd_1nput_and_0utput_4r3_d3f1n3d_1n_GLIBC!_eb5064c95c79db18}
```
## Challenge - Vault 4
This will be similar where they are asking to find the address of a secret vault and we are given the address of a fake vault. For this I run the vault4 process locally:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ ./vault4
Can you still find the address of the secret vault?

I found this fake vault at: 0��i�U
But it doesn't appear to be the right one.
Agh! and the vault coordinates are in raw bytes!
```
A quick test of the input tells me they are looking for raw bytes:

```aiignore
> 55555

Address 0xa3535353535 doesn't look right... Try again, friend!
(now I only read addresses in raw bytes!)
```
Using readelf, I extracted the header information to find out more about the file:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ readelf -Wh vault4
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
  Entry point address:               0x1140
  Start of program headers:          64 (bytes into file)
  Start of section headers:          14520 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```
Notice the data is in "little endian" byte order. This is important to know how to convert the raw source address into an integer.

Performing a quick readelf to see which symbols are available. I found 2 interesting symbols containing the word "vault":

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ readelf -Ws vault4 | grep vault
    11: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS vault4.c
    12: 0000000000004030     1 OBJECT  LOCAL  DEFAULT   26 fake_vault
    13: 0000000000004038     8 OBJECT  LOCAL  DEFAULT   26 secret_vault
```

### Challenge Summary
For this challenge I will use pwntools to start a conversation with the process and to extract the offset values of the vault symbols.

Once I have the address of "fake_vault" and it's offset, I can compute the base address using: base = address - offset. Using the offset for the "secret_vault" I can compute the address of the "secret_vault" with address = base + offset formula.

Once I have obtained the address for "secret_vault" I will convert it to raw byts and submit.

### Coding up the script
I'll start by copying the script for the Glibc challenge, since it has all the same components. I'll call this "secret_vault4.py". At this point I think I'm going to make the variable names a bit more generic so that if I have to use the code again I won't have to have specific variable names.

As in other scripts, I'll use a variable called LOCAL to do a majority of my testing local before hitting the challenge server. I'm also adding variable names for the source and target addresses. These will be used in my print statements to provide clarity of the information derived throughout the script. This will also allow me to use the name values in my elf symbol lookup.

With this in mind, I'm also going to format the output so it looks cleaner. 

### Script Flow
The basic flow of the script is the following:
- Start the process
  - Local is using "./vault4"
  - Remote is using "offsec-chalbroker.osiris.cyber.nyu.edu on port 1234"
- Extract the raw source address from the process output
  - Reading the ELF I noticed the data is stored in "little endian" format.
- Convert the raw source address to an integer
- Use ELF to get the source address offset
- Compute the base address using base = address - offset
- Use ELF to get the target address offset
- Compute the target address using address = base + offset
- Convert the target address to raw byts
- Submit the raw byts to the process

### Execution
After refactoring the code it solved the challenge on the first try! I changed the LOCAL to False and re-ran against the challenge server:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/challenge0$ python secret_vault4.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1234: Done
 hello, nam10102. Please wait a moment...
Can you still find the address of the secret vault?

I found this fake vault at:
But it doesn't appear to be the right one.
Agh! and the vault coordinates are in raw bytes!

>
fake_vault      raw         : b'0 M\xf8nU\x00\x00'
fake_vault      address     : 0x556ef84d2030
[*] '/mnt/csgy9223_IntroOffSec/challenge0/vault4'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
fake_vault      offset      : 0x4030
base address                : 0x556ef84ce000
secret_vault    offset      : 0x4038
secret_vault    address     : 0x556ef84d2038
secret_vault    address raw : b'8 M\xf8nU\x00\x00\x00\x00\x00\x00\x00'
 Lucky me! The vault at 0x556ef84d2038 is my favorite vault!



Here's your flag, friend: flag{b4ckw4rds_byt3_0rd3r_1s_n0t_s0_b4d!_9b1ca04eb6b55ba2}
```
