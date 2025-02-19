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


