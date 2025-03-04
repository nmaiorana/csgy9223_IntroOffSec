# CSGY 9223 Intro to Offensive Security
# Week 4 Challenges
# nam10102

## Challenge - Stripped
I got rid of all symbols. Let's see what you can do!

nc offsec-chalbroker.osiris.cyber.nyu.edu 1270

We are given the file 'stripped':

```
stripped: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=12c60274e8a8e3aeeed1de7cfca9eddacc122446, for GNU/Linux 3.2.0, stripped
```

Running the program we get:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_4$ ./stripped

Hey friend, can you tell me your favorite fruit? Apples
Highly illogical.
```

This is definitely a stripped file. Using binja to see how much information we can get.

At first glance this does look different. The function names are all non-descript "sub_xxx" values. Binja did a nice job of getting me to main(). A high level overview shows me the original question from the process. I'm guessing there is an input somewhere. I also see another question asking for the location of the flag: "Any idea where to get the flag?". My initial thoughts are it's looking for a file name. But let's investigate how to get to this point.

The first function that is called appears to be an init() function. It also has what I believe to be the answer to the main question. I'll rename it init and name some of the variables inside. Even though I think I have the answer, I'm going to go through all the function calls and rename them to get some practice around working with stripped files.

I went through and named all the functions properly. I did this with help from [Chromium OS Docs](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit). If found this page extremely valuable to know which syscalls were being made. Here are a list of functions I came up with:

- read() - syscall 0
- write() - syscall 1
- file_open() - syscall 2
- file_close() - syscall 3
- fill_buff() - fill a buffer of size with a value
- len() - length of buffer
- strcmp() - String comparison where 0 are matching strings
- init() - set the value of target answer "Golana Melon"

Getting all those functions named really helped. The main() function now is easily understood. Having the information to solve the challenge I gave it a shot.

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_4$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1270
Please input your NetID (something like abc123): nam10102
hello, nam10102. Please wait a moment...

Hey friend, can you tell me your favorite fruit? Golana Melon

Fascinating.

Any idea where to get the flag? flag.txt


Here's your flag, friend: flag{4ll_w3_n33d_1s_kn0wl3dg3_0f_th3_sysc4ll_API!_564a0dadccc3c907}
```

## Challenge - Rudimentary Data Protocol
```aiignore
This protocol doesn't use fancy words. Can you speak its language?

nc offsec-chalbroker.osiris.cyber.nyu.edu 1272
```

Checking file:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_4$ file rdp
rdp: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7d12ee8e03586d9ce1a3753635ea84d22b80ccb3, for GNU/Linux 3.2.0, not stripped
```
This is not a stripped file.

Let's dive into binja:

### Goal
The main() function appears to loop through a function process_packet() until the value returned from the function XOR with 1 is 0. So my thought is that the function needs to return a 1.

Let's dig into the process_packet() function.

The goal of this challenge is to get the process_packet() to send a value of 1 back (valid_message). The input takes in a packet with the following attributes:

A packet consists of the following:
 - 1 byte length
 - 1 byte op code (0, 1 or 2)
 - 1 to 8 byte message

The function will keep accepting packets as long as they meet the following criteria:
- The packet is 3 bytes long
- The length value is the length of the packet
- The op codes are 0, 1 or 2

The only way to get the process_packet() function to return a 1 is to send in a valid message (55), after a connection has been established. Once a valid message is passed in, and the connection is closed, the valid message indicator (1) is passed back. To do this the following sequence is required:

- Send an opcode 0 to establish a connection
- Send an opcode 1, with the 2nd byte of the message = 55 (sets valid message to 1)
- Send an opcode 2 to close the connection

I created a solver script (rdp_solver.py) using pwntools to process this challenge.

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_4$ python rdp_solver.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1272: Done
 hello, nam10102. Please wait a moment...
Send me the right data and I'll give you the flag!

Connection Established!

That's a nice message!

Disconnected!

[*] Switching to interactive mode

        Here's your flag, friend: flag{w3_r34lly_l1k3_s3r14l1z3d_d4t4!_9a734ad4222cbcd4}
```

## Challenge - Hand Rolled Cryptex
```
I found this weird cryptex asking for input, can you help me reverse the gadgets and open it?? Be careful, a mistake will ruin the parchment inside!

nc offsec-chalbroker.osiris.cyber.nyu.edu 1273```

Checking the file:
```
$ file hand_rolled_cryptex
hand_rolled_cryptex: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=750642551ebf934ca1d6718bcf2f900deccc7689, for GNU/Linux 3.2.0, stripped

Welp, it looks like it's stripped. 

```
readelf -Wh hand_rolled_cryptex
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
  Entry point address:               0x1080
  Start of program headers:          64 (bytes into file)
  Start of section headers:          16720 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         29
  Section header string table index: 28
```
We have a starting address. Let's run the program to see what it asks for:

```aiignore
$ ./hand_rolled_cryptex
I found this weird cryptex...
...it seems to take some weird series of operations...
...but all the symbols are obscured...
...could you crack it for me??

The first round requires two inputs...
 > 2 2

 > 2

Oh no! That input broke the vial of vinegar, ruining
the papyrus scroll with the flag!
```

Okay, this looks like fun. Breaking out Binja. I'm going to go through and figure out what most if not all of the functions do. Here is what I have:
- write
- rev
- itoa
- strncpy
- read
- open
- close
- memset
- atoi
- strlen
- round1
- round2
- round3

So the first set of user inputs are the name of a file and the flags to open. The flags is only one value and the open flags that are 9 or less are:
```aiignore
#define CEPH_O_RDONLY		00000000
#define CEPH_O_WRONLY		00000001
#define CEPH_O_RDWR		    00000002
#define CEPH_O_CREAT		00000100
```
So 0, 1 or 2. Since I don't think I can create the file, I'll have to put in a test file. I'll use flags.txt??? with a read only flag of 0:
```aiignore
I found this weird cryptex...
...it seems to take some weird series of operations...
...but all the symbols are obscured...
...could you crack it for me??

The first round requires two inputs...
 > flags.txt

 > 0
*The first chamber opened! There is some weird carved into                   the interior...

The second phase requires a single input...
 >
```
So why all those spaces? It also writes 4 bytes of the value of the file descriptor opened in round1, followed by a line feed. Could this be used later? These are not visible characters.

So it reads the value of what is input, gets the bitwise compliment and XORs with 0xc9 (201). My guess is that the user input, XORed with 0xc9, needs to equal the file descriptor. The 256 bytes are stored in memory at 0x5040. The number of bytes read is returned.

I think I need to turn to pwntools to start manipulating the following inputs.

I was right. I read in the value, XORed the result with 201, then took the compliment. I send in the result as a packed32 signed integer:
```aiignore
Nice, the second chamber opened! Ok, the final level requires another single input...
```

At this point the flag is stored at address 0x5040, I'll call this "flag". 

So round 3 has to return a value 0 or greater. Looks like I'm going to have to jump through hoops to figure out how...

For function round3() an input values is read.
- if nothing was entered, then return -1
- if the value is 1, return -1
- if the value is less than 0, return -1
- if the value is equal to 2, return the string length of the input read, 1
- if the value is greater than 2, return result of itoa()
- if the value is 0, return -1 due to a failed atoi() call
- if the value is less than 0, return the result of itoa()

So only the value of 2, for certain, will get me past the 3rd round. I may have to dig into itoa() if this does not pan out. 

Looking at where the flag is being printed shows that the value returned by round 3 determines the fd where it is written to. Since a value of 1 (stdout) will return a -1 from round3(), then the only other option to get the flag to display is 2 (stderr). 

I made sure my local flag.txt file had data in it ("flag-----------------------------------------------------------").

And sent in a 2 for round 3:
```aiignore
The final chamber opened, but a flaw in the design
popped a vinegar vial which started to eat away at the papyrus
scroll inside. You hold it up, trying to decipher the text... flag-----------------------------------------------------------
```

I'll try against the server and see what happens:
```aiignore
The final chamber opened, but a flaw in the design
popped a vinegar vial which started to eat away at the papyrus
scroll inside. You hold it up, trying to decipher the text... flag{str1PP3d_B1N4R135_4r3_S0o0_much_FUN!_efaaf4fb44853578}
```
Indeed, soo much FUN!

## Challenge - Heterograms
```aiignore
This protocol asks for fancy words and weird command sequences. Speak its language for the flag.

nc offsec-chalbroker.osiris.cyber.nyu.edu 1271
```

What is a heterogram?

A heterogram is a word, phrase, or sentence in which no letter of the alphabet occurs more than once. In other words, each letter appears exactly once in the word or phrase. Heterograms are a fun way to challenge one's vocabulary and creativity in using letters without repetition.

Okay...

In inspecting the binary 'heterograms':
```aiignore
$ file heterograms
heterograms: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a0a0b8c73b764c067aad5ce9d6d96033b267ddde, for GNU/Linux 3.2.0, not stripped
```
Not stripped. This will help a bunch...
Running the binary:
```aiignore
./heterograms
Send me some data to get the flag!
```
Going to binja to see what the goal is.

The main() function is pretty tight. It prints the opening message, calls process() and if process() returns a 1, print the flag. Next is to discover how to get a one back from process().

There are two return options from the process() function. The first is a failed attempt, displays a message and returns a 0. The second is from the return value of handle(). The handle() fuction is called when the entire packet is processed.

The handle() function has 3 return options. One is a fail where a reset() function is called and a 0 is returned. The second looks into a global state and a buffer position. The buffer needs to equal a global state value. If the buffer value is equal to 2, an erase() function is called, a message is displayed "Copy that!", and a 0 is returned.

The third option is our target. This time the buffer value has to be less than or equal to 2 and not equal to 0. Interesting since if it's equal to 2, we fail with that last return. Since it also can't equal 0, then the only option is 1 since the value is an unsigned integer. If the right conditions are met, then the return is the result of a check() function. 

This function has 3 return options, 2 that are 0 and one where a 1 is returned if the global state count is 7. There is a strs variable referenced. Let's dig into that.

This appears to have a series of words that are each heterograms. The global state value is used to select one of the values from strs. Let's look at the strs memory location. This appears to be a structure. Here is what I came up with:

```aiignore
struct strings
{
    char word[0xf];
};
```
There are 7 (interesting) words that look like they can be upto 15 characters each. Applying my struct I get:

```aiignore
00004020  struct strings strs[0x7] = 
00004020  {
00004020      [0x0] = 
00004020      {
00004020          char word[0xf] = "unforgivable\x00\x00", 0
0000402f      }
0000402f      [0x1] = 
0000402f      {
0000402f          char word[0xf] = "troublemakings", 0
0000403e      }
0000403e      [0x2] = 
0000403e      {
0000403e          char word[0xf] = "computerizably", 0
0000404d      }
0000404d      [0x3] = 
0000404d      {
0000404d          char word[0xf] = "hydromagnetics", 0
0000405c      }
0000405c      [0x4] = 
0000405c      {
0000405c          char word[0xf] = "flamethrowing\x00", 0
0000406b      }
0000406b      [0x5] = 
0000406b      {
0000406b          char word[0xf] = "copyrightable\x00", 0
0000407a      }
0000407a      [0x6] = 
0000407a      {
0000407a          char word[0xf] = "undiscoverably", 0
00004089      }
00004089  }

```
Now I know what words to use. Let's look at globalstate. This looks like another structure. This one has what I'll call a count along with 26 integers. My guess is this counts the occurrences of each letter. I'll create a structure:

```aiignore
struct global_state_struct __packed
{
    char count;
    char letter[0x1a];
};
```

Now to dig into getting all the words through.

Digging into process(), the first thing it does is get user input. This is stored in an 80 byte character array.

I think we are dealing with a structure. The first byte appears to be a length, and the size of has to be more than 3. After some effort, I came up with a structure for the input packet. It actually is made up of 2 structures:


So far my packet looks like:
```aiignore
struct packet
{
    uint8_t packet_len;
    uint8_t checksum_val;
    struct operation_struct operation[0x1f];
};
```
The second byte appears to be a checksum value which is the compliment of the sum of rest of the packet, including the line feed. After some experimentation, I discovered an oddity. The linefeed is part of the checksum(), but not part of the length.

Another structure is being used. This is a fixed 36 bytes with the first byte being the length, and the last 4 bytes being the checksum.
```aiignore
struct operation_struct
{
    enum op_codes op_code;
    uint8_t len;
    char word[0xf];
};

enum op_codes : uint32_t
{
    WORDINDEX = 0x0,
    LETTERCOUNT = 0x1,
    CHECK = 0x2
};
```
Looking at how process uses these structures, I think we have an enum. The valid values are 0,1 & 2. I'm not entirely sure what 0 and 2 do, but 1 counts each letter in the current word and stores it in the globalstate.

So I know op code 1 counts letter. Op code 2 puts the value (what I called len) in the operation_struct in position 27 in a new structure I'll call current operation:
```aiignore
struct current_op
{
    char packet_len;
    char word[0x1f];
    int32_t checksum;
};
```
This is a 36 byte structure with the packet length (incoming packet) at the first byte and checksum at the last 4 bytes.

I'm going to play with a solver to see how to get the packets properly arranged.

For the incoming packet, the checksum value which is the compliment of the sum of rest of the packet, including the line feed. After some experimentation, I discovered an oddity. The linefeed is part of the checksum(), but not part of the length. I discovered this by attaching a GDB session to my solver and using tmux to view what was going on.

Now that I have a partially working solver where I can send in an op code 1, with a word. Now I need to start playing with op codes 2 and 0. The only thing that makes sense so far is that op code 2 puts a value in the 27th position. So I'll try something like:
```aiignore
len
checksum
op code 2
1
op code 1
len
word
```
I worked through this using a solver and some c struct definitions in pwntools+gdb. The program had 4 operations with the 3 operation code. 

- Opcode 0 with the index of the number of words that were checked correctly
- Opcode 1 with the word to check
- Opcode 2 with a 0 to run the check
- Opcode 2 with a 2 to clear the current state

I put all words in a list and ran them through. I was messed up for a while due to used sendline() instead of send(). This messed up my length computation. My solver looked like this:
```aiignore
p.recvuntil(b" flag!\n")

packet_erase = build_packet_erase()
packet_check = build_packet_check()

# send_packet(p, build_packet_idx(0) + packet_erase)
for i, heterogram in enumerate(heterograms):
    send_packet(p, build_packet_count(heterogram) + build_packet_idx(i) + packet_check)
    p.recvuntil(b"That's a nice word!\n")
    send_packet(p, build_packet_idx(i+1) + packet_erase )
    p.recvuntil(b"Copy that!\n")

p.interactive()
```
and when everything was correctly coded:
```aiignore
[DEBUG] Received 0x3b bytes:
    b'flag{s3r1aL1z3d_d4t4_and_ST4T3_m4ch1n3s_3e61f080a22f70d9}\n'
    b'\n'
```