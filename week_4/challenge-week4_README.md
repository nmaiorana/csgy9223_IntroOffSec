# CSGY 9223 Intro to Offensive Security
# Week 4 Challenges

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




