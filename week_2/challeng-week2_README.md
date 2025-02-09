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
 It looks like there is a while loop that does a comparison between the data at the secret address and the data in the message_buffer. This looks to be doing a character by character comparison. This is controlled by an accumulator that is initialized to 0 and incremented each time through the loop. The while loop breaks when the accumulator is the size of the message string.
 
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

## Challenge - Cosmic Distance
```aiignore
I lost my measuring tape! Can you help me find the distance?

nc offsec-chalbroker.osiris.cyber.nyu.edu 1252
```
We also have binary called cosmic_distance:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ file cosmic_distance
cosmic_distance: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7a51d945beeff2132d37fb86b3e30439ab551637, for GNU/Linux 3.2.0, not stripped
```

Running the binary:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ ./cosmic_distance
        Can you tell me the distance from this quasar to Earth?
```

Using binja to explor the logic. This looks pretty straight forward. There is a variable where a distance is stored:
````aiignore
000012c4    void init()

000012c4    {
000012c4        distance = 0x2cb417800;
000012c4    }
````
And in main the input is compared to this value:
```aiignore
00001229    int32_t main(int32_t argc, char** argv, char** envp)

00001229    {
00001229        int32_t argc_1 = argc;
00001238        char** argv_1 = argv;
00001241        set_buffering_mode();
0000124b        init();
0000125a        puts("\tCan you tell me the distance f…");
0000126e        printf("\t: ");
0000126e        
0000128c        if (read_input() != distance)
0000128c        {
000012b8            puts("\n\tThat's not the correct dista…");
000012bd            return 1;
0000128c        }
0000128c        
00001298        puts("\n\tYeah! You got the right dist…");
000012a2        read_flag();
000012a7        return 0;
00001229    }
```
Lets try giving it this value (0x2cb417800):
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ ./cosmic_distance
        Can you tell me the distance from this quasar to Earth?


        : 0x2cb417800

        Yeah! You got the right distance!
```
I was expecting to have to convert that value to an integer, but it took it.
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1252
Please input your NetID (something like abc123): nam10102
hello, nam10102. Please wait a moment...
        Can you tell me the distance from this quasar to Earth?


        : 0x2cb417800

        Yeah! You got the right distance!

        Here's your flag, friend: flag{0nly_tw3lv3_b1ll10n_l1ght_y34rs_4w4y!_0cb22a91b31f6080}
```
## Challenge - Favorite
```aiignore
Can you help me out? I'm trying to figure out where's my favorite drink.

nc offsec-chalbroker.osiris.cyber.nyu.edu 1251
```
We also are provided a binary called fave:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ file fave
fave: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2d3390ff02ce2c9ec122457009b56de0f42de0fa, for GNU/Linux 3.2.0, not stripped
```
Running the binary:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ ./fave

        FYI, this is the address of function `hint`: ���U

        Can you tell me where is my favorite beverage?
        >
```
Looks like we have to interpret some input. Let's see where it gets it from and how it's used with binja.

I started looking at the available information:
- We are given the address of a function called hint() - offset 0x12a9
- Using binja, I see there is a variable called beverage that has an offset of 0x4850
- beverage is set to 0xc01dc0ffee
- The if statement in main() compares the input to 0xc01dc0ffee
- The read_input() function only takes integers from 0-9

My first attempt was to convert 0xc01dc0ffee to decimal (825132908526). This produced a segmentation fault. Hmm, what part of memory was being accessed?

Stepping through the code, the segment fault definitely came from the if statement. Let's examine further.

```*(uint64_t*)*(uint64_t*)read_input() != 0xc01dc0ffee```

The pointer arithmatic is being compared to the hex value 0xc01dc0ffee, which is stored in the variable beverage. My next step was to use one of my solver scripts to pass in the address for beverage. I copied one of my old scripts, replaced the source name with "hint" and the target name to "beverage". Getting the input from the process, I computed the base address for beverage and passed the decimal representation for my input...segmentation fault.

Let's break down the pointer logic a bit:
- read_input() returns an integer that was entered
- The value is cast to a unsigned 64-bit integer
- That is dereferenced so the content of that address is used
- The content at that address is then cast to a unsigned 64-bit integer

So the value entered represents a location where the address of the content is stored. Looking at init() again:
```aiignore
000013d1    void init()

000013d1    {
000013d1        data_43f8 = &beverage;
000013f1        beverage = 0xc01dc0ffee;
000013d1    }

```
The if condition is not looking for the address of beverage, it's looking for the address where the beverage address is stored data_43f8, which has an offset of 0x43f8. I plugged that value into the solver script and bingo!

I updated the script to run remotely:

```aiignore
        You did it! Thanks for finding my drink!

        Here's your flag, friend: flag{l34ks_d0ubl3_p01nt3rs_4nd_0ffs3ts_t0_w1n!_0b5e1482f4ef7536}
```

## Challenge - Numbers
```aiignore
Heeelp!! Can you find my 5 numbers?

nc offsec-chalbroker.osiris.cyber.nyu.edu 1255
```
We are provided a binary called numbers:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ file numbers
numbers: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e4ce9dd862e102971a48e2b157b3798deabdaa35, for GNU/Linux 3.2.0, not stripped
```
Running the process we get:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_2$ ./numbers

Answer 5 questions to get the flag.


        1. What are the the first two decimals of the Golden Ratio?

                From address:
```
5 Questions. "From address:" Huh?

Hit enter: " Naah, I don't like that address!"
From Decimal
Run again this time put in a number, same thing.

Trying hex: 

```aiignore
Answer 5 questions to get the flag.


        1. What are the the first two decimals of the Golden Ratio?

                From address: 0x20

                The size to dereference is:
```
Open the file with binja.

This one turns out to be pretty strait forward. Each question starts by asking for an address, then the size to dereference the value from that address in response to the question.

The valid answers for dereferencing can be found in the input_answer() function. They are:
- char 
- short
- long
- long long
- void*

So if you know for instance the answer to the question was compared using a 8 bit register (AL, DL), then the answer would be "char". 

For question 1:
```aiignore
004012b6    uint64_t question1()

004012b6    {
004012b6        puts("\n\t1. What are the the first tw…");
004012cd        input_answer();
004012eb        return (uint64_t)((int8_t)data_404730 == var1);
004012b6    }

```
The address we are looking for is 0x404730 and var1 is an unsigned int 8, so char. The value for the question is 61.

For question 2:
```aiignore
004012ec    uint64_t question2()

004012ec    {
004012ec        puts("\n\t2. Just give me a really big…");
00401303        input_answer();
00401319        uint64_t rax_1;
00401319        rax_1 = data_4042a0 == var4;
00401320        return (uint64_t)rax_1;
004012ec    }

```
The address we are looking for is 0x4042a0 and var4 is an unsigned int 64, so long long

For question 3:
```aiignore
00401321    uint64_t question3()

00401321    {
00401321        printf("\n\t3. When was it proved that %…", &pi);
00401342        input_answer();
0040135a        uint16_t rax_3;
0040135a        rax_3 = (int16_t)data_404730 == var2;
00401361        return (uint64_t)rax_3;
00401321    }
```
The address we are looking for is 0x404730, same as question 1, but since we are looking for a date, 1761 so this will take a short or 2 bytes. var2 is an unsigned int 16 or short.

For question 4:
```aiignore
00401362    uint64_t question4()

00401362    {
00401362        printf("\n\t4. The address of %s?\n", 0x4020a0);
00401383        input_answer();
0040139c        uint64_t rax_3;
0040139c        rax_3 = (*(uint64_t*)data_4043c0) == var5;
004013a3        return (uint64_t)rax_3;
00401362    }
```
The address we are looking for is 0x4043c0 and var5 is an unsigned int 64. Since it holds an irrational number like pi, you could use this to store a reference to it via an intermediary pointer, then cast it to a double. So the dereference size is void*.

For question 5:
```aiignore
004013a4    uint64_t question5()

004013a4    {
004013a4        puts("\n\t5. Last one!");
004013bb        input_answer();
004013d1        uint64_t rax_1;
004013d1        rax_1 = data_4044c8 == var3;
004013d8        return (uint64_t)rax_1;
004013a4    }
```
The address we are looking for is 0x4044c8 and var3 is defined as an unsigned int 64 so to dereference would be long.

Running correct answers:
```aiignore
Continuing.

        1. What are the the first two decimals of the Golden Ratio?

                From address: 0x404730

                The size to dereference is: char

        2. Just give me a really big number!

                From address: 0x4042a0

                The size to dereference is: long long
 
        3. When was it proved that 𝜋 is irrational?

                From address: 0x404730
                
                The size to dereference is: short
        4. The address of 𝜋?

                From address: 0x4043c0

                The size to dereference is: void*
                
        5. Last one!

                From address: 0x4044c8

                The size to dereference is: long 
                
You did it!
You've mastered the secret arts of casting!

Here's your flag, friend: flag{w1th_c4st1ng_w3_c4n_tr34t_4ny_m3m0ry_4s_4ny_d4t4_typ3!_b78d3f2dd313f901}       
```



