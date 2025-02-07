# Week 2 CTF

---
## Challenge - Quasar

```aiignore
nc offsec-chalbroker.osiris.cyber.nyu.edu 1250
```
For this challenge we are given a binary file named 'quasar'.

Inspecting the file we find:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ file quasar
quasar: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d9bf3db4988b1bf8267a09552df5caf5d0d0593b, for GNU/Linux 3.2.0, not stripped

(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ readelf -Ws quasar

Symbol table '.dynsym' contains 20 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (2)
     2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (3)
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strlen@GLIBC_2.2.5 (3)
    .
    .
    .
    32: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    33: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strtol@GLIBC_2.2.5
    34: 0000000000004008     0 OBJECT  GLOBAL HIDDEN    25 __dso_handle
    35: 0000000000002000     4 OBJECT  GLOBAL DEFAULT   18 _IO_stdin_used
    36: 0000000000004050     0 NOTYPE  GLOBAL DEFAULT   26 _end
    37: 00000000000011a0    38 FUNC    GLOBAL DEFAULT   16 _start
    38: 0000000000004010     0 NOTYPE  GLOBAL DEFAULT   26 __bss_start
    39: 0000000000001289   163 FUNC    GLOBAL DEFAULT   16 main
    40: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND setvbuf@GLIBC_2.2.5
    41: 00000000000014ba    71 FUNC    GLOBAL DEFAULT   16 set_buffering_mode
    42: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fopen@GLIBC_2.2.5
    43: 00000000000013fd   189 FUNC    GLOBAL DEFAULT   16 print_flag
    44: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND exit@GLIBC_2.2.5
    45: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fwrite@GLIBC_2.2.5
    46: 0000000000004010     0 OBJECT  GLOBAL HIDDEN    25 __TMC_END__
    47: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
    48: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5
    49: 0000000000001000     0 FUNC    GLOBAL HIDDEN    12 _init
    50: 000000000000132c   209 FUNC    GLOBAL DEFAULT   16 read_input
    51: 0000000000004040     8 OBJECT  GLOBAL DEFAULT   26 stderr@GLIBC_2.2.5
```
When I run the process I get:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ ./quasar

        This quasar is the brightest object in the universe.
        Can you guess the mass of the black hole at its center?

        >
```

Let's look at the file using binja. One interesting line is:
```aiignore
000012f4        if (read_input() != 0x3f5476a00)
```
It looks like the value it's looking for is hardcoded into the program in main. I'll plug the value '0x3f5476a00' into the prompt:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ ./quasar

        This quasar is the brightest object in the universe.
        Can you guess the mass of the black hole at its center?

        > 0x3f5476a00

        Yeah! You're right!
```
Well that was easy. Let's run the function on the server:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1250
Please input your NetID (something like abc123): nam10102
hello, nam10102. Please wait a moment...

        This quasar is the brightest object in the universe.
        Can you guess the mass of the black hole at its center?

        > 0x3f5476a00

        Yeah! You're right!

        Here's your flag, friend: flag{sc4la4r_v4lu3s_h1dd3n_1n_pl41ns1ght!_e6a08914501c6b58}
```

---
## Challenge - Secrets

```aiignore
I know you can't read my message! It's hidden using my Next Gen Ultra Secret process!

nc offsec-chalbroker.osiris.cyber.nyu.edu 1254
```

For this we are given a binary 'secrets': Let's explore:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ file secrets
secrets: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d06011928fc516c1de805541c60a07c2687e1f87, for GNU/Linux 3.2.0, not stripped

(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ readelf -Ws secrets
.
.
.
    35: 0000000000004020   169 OBJECT  GLOBAL DEFAULT   25 secret
.
.
.
```
Let's run it and see what it's asking for:  
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ ./secrets

ERROR: no message file found.


Can you guess the key?
>
```

Hmm, it was looking for a message file. Let's see what that file name is using binja.

The file name is 'message.txt'

There is a function called read_key(). Looking at that function, it's looking for a number between 0 and 255 (inclusive). A key might imply some sort of encryption.

Let's investigate main to see the conditional statements around getting that response:

```aiignore
00001348        while (true)
00001348        {
00001348            if ((int64_t)accumulator >= strlen(&message_buffer))
00001350            {
0000135c                puts("\nGood job! that's the right key…");
00001366                read_flag();
0000136b                result = 0;
0000136b                break;
00001350            }
00001350            
00001316            if (((uint32_t)*(uint8_t*)((int64_t)accumulator + &secret) ^ key) != (int32_t)*(uint8_t*)(&message_buffer + (int64_t)accumulator))
00001316            {
00001322                puts("\nTry again!\n\n");
00001327                result = 1;
0000132c                break;
00001316            }
00001316            
0000132e            accumulator += 1;
00001348        }

```
 It looks like there is a while loop that does a comparison between the data at the secret address and the data in the message_buffer. This looks to be doing a character by character comparison. This is controlled by an accumulatore that is initialized to 0 and incremented each time through the loop The while loop breaks when the accumulator is the size of the message string.
 
The value at the current character address for secret, is cast to an 8 bit unsigned int, dereferenced and returned as a 32 bit unsigned int.

The value for the current character of message_buffer is also cast to an 8 bit unsigned int, then dereferenced and cast to a 32 bit unsigned int. 

The comparison is not done directly on the value stored at the offset to the secret address. That value is XORed with the key value. Aha! They key is used for decryption. Which means the values stored at &secret have been encrypted with the key. A quick search tells me that XOR is its own inverse. So now I just need to determine any of the original values and run XOR against its original value to produce the key value.

So how to determine what the original characters were. My first attempt will be to look for repeating values that might be a space " " or 32 (0x20).

This is the memory map of &secret:

```aiignore
00004020  secret:
00004020  a0 87 9a 86 8f 8c 9b 87 c9 9a 80 8a 81 c9 8d 80  ................
00004030  8c c9 ba 0d 9d 93 8c c9 8d 8c 9b c9 a4 88 9d 81  ................
00004040  8c 84 88 9d 80 82 c9 88 9c 8f c9 8d 80 8c c9 be  ................
00004050  80 9b 82 85 80 8a 81 82 8c 80 9d c9 8b 8c 93 80  ................
00004060  8c 81 8c 87 c5 c9 9a 80 87 8d c9 9a 80 8c c9 87  ................
00004070  80 8a 9d c9 9a 80 8a 81 8c 9b c5 c9 9c 87 8d c9  ................
00004080  80 87 9a 86 8f 8c 9b 87 c9 9a 80 8c c9 9a 80 8a  ................
00004090  81 8c 9b c9 9a 80 87 8d c5 c9 8b 8c 93 80 8c 81  ................
000040a0  8c 87 c9 9a 80 8c c9 9a 80 8a 81 c9 87 80 8a 81  ................
000040b0  9d c9 88 9c 8f c9 8d 80 8c c9 be 80 9b 82 85 80  ................
000040c0  8a 81 82 8c 80 9d c7 e3 00                       .........
```
I'll try 0xc9 since it comes up quite frequently:

```aiignore
0xc9 = 11001001
0x20 = 00100000
key  = 11101001

11101001 = 233
```
And when hitting the server I get:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1254
Please input your NetID (something like abc123): nam10102
hello, nam10102. Please wait a moment...

Can you guess the key?
> 233

Good job! that's the right key!


        Here's your flag, friend: flag{4_0n3_byt3_k3y_g1v3s_4_v3ry_sm4ll_k3y_sp4c3!_b5871977d363c350}
```

---
## Challenge - StrS

```aiignore
nc offsec-chalbroker.osiris.cyber.nyu.edu 1253
```
For this challenge we are given a binary file named 'strs'.

```aiignore
file strs
strs: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=041b9b6eed41113d88dcf0d47c4bd343757b503c, for GNU/Linux 3.2.0, not stripped
```

Running the executable:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ ./strs

        Give me the right answer and I'll give you the flag!

        >
```
No clues here, let's open the file in binja.

Looking in main I see a comparison of 2 buffers. If they match byte for byte, then the process continues and you get the flag. Here is the code, I have updated the variable names to be more descriptive:

```aiignore
000012e6        if (strcmp(&input_buffer, &comparison_buffer))
000012e6        {
00001312            puts("\n\tThat's not the correct answe…");
00001317            return 1;
000012e6        }
```
With the variable named, I see it's getting set in the init() function:

```aiignore


0000131e    int64_t init()

0000131e    {
0000131e        setvbuf(stdout, nullptr, 2, 0);
0000135d        int64_t result = setvbuf(stdin, nullptr, 2, 0);
00001376        __builtin_strncpy(&comparison_buffer, " SMSS J052915.80", 0x10);
0000138e        data_40b0 = 0x35313533349288e2;
00001395        __builtin_strncpy(&data_40b8, "2.0 ", 5);
000013a8        return result;
0000131e    }


```

I tried this string value at 00001376 " SMSS J052915.80", and that was not the answer. Some trickery must be going on. Time to run in gdb. The address of the comparison buffer is at offset 0x40a0. The name of the next address spaced used by the process is data_40b0, exactly 10 bytes, the length of the string pushed into the comparison address space. A large number is set at offset 0x40b0 (0x35313533349288e2). Since the termination value would be starting at 0x04b0, a string comparison would now go into this address space. 

One other observation is that 8 bytes after 0x40b0, the string "2.0 " is copied in. 

I started in gdb, put a breakpoint at main and init. When executing the init function, I checked the comparison variable value. Here is a disassembly of init:

```aiignore
   0x000055555555531e <+0>:     endbr64
   0x0000555555555322 <+4>:     push   rbp
   0x0000555555555323 <+5>:     mov    rbp,rsp
=> 0x0000555555555326 <+8>:     mov    rax,QWORD PTR [rip+0x2cf3]        # 0x555555558020 <stdout@GLIBC_2.2.5>
   0x000055555555532d <+15>:    mov    ecx,0x0
   0x0000555555555332 <+20>:    mov    edx,0x2
   0x0000555555555337 <+25>:    mov    esi,0x0
   0x000055555555533c <+30>:    mov    rdi,rax
   0x000055555555533f <+33>:    call   0x555555555130 <setvbuf@plt>
   0x0000555555555344 <+38>:    mov    rax,QWORD PTR [rip+0x2ce5]        # 0x555555558030 <stdin@GLIBC_2.2.5>
   0x000055555555534b <+45>:    mov    ecx,0x0
   0x0000555555555350 <+50>:    mov    edx,0x2
   0x0000555555555355 <+55>:    mov    esi,0x0
   0x000055555555535a <+60>:    mov    rdi,rax
   0x000055555555535d <+63>:    call   0x555555555130 <setvbuf@plt>
   0x0000555555555362 <+68>:    movabs rax,0x304a2053534d5320
   0x000055555555536c <+78>:    movabs rdx,0x30382e3531393235
   0x0000555555555376 <+88>:    mov    QWORD PTR [rip+0x2d23],rax        # 0x5555555580a0 <var2>
   0x000055555555537d <+95>:    mov    QWORD PTR [rip+0x2d24],rdx        # 0x5555555580a8 <var2+8>
   0x0000555555555384 <+102>:   movabs rax,0x35313533349288e2
   0x000055555555538e <+112>:   mov    QWORD PTR [rip+0x2d1b],rax        # 0x5555555580b0 <var2+16>
   0x0000555555555395 <+119>:   mov    DWORD PTR [rip+0x2d19],0x20302e32        # 0x5555555580b8 <var2+24>
   0x000055555555539f <+129>:   mov    BYTE PTR [rip+0x2d16],0x0        # 0x5555555580bc <var2+28>
   0x00005555555553a6 <+136>:   nop
   0x00005555555553a7 <+137>:   pop    rbp
   0x00005555555553a8 <+138>:   ret
```

Stepping through the code, just before exiting and checking the value of the comparison buffer:

```aiignore
 x/s 0x5555555580a0
0x5555555580a0 <var2>:  " SMSS J052915.80−435152.0 "
```
The string at the comparison buffer offset was indeed extended to add the first 8 byts of the value plus the additional string. Using this value I got the flag:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1253
Please input your NetID (something like abc123): nam10102
hello, nam10102. Please wait a moment...

        Give me the right answer and I'll give you the flag!

        >  SMSS J052915.80−435152.0

        Yep, that's the right answer!

        Here's your flag, friend: flag{str1ng_c0mp4r1s0n_ch3cks_3v3ry_ch4r!_41949d77d5749d9e}
```
