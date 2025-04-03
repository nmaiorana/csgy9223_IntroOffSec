# CSGY 9223 Intro to Offensive Security
# Week 8 Challenges
# nam10102

## Challenge - Thread and Needle
```aiignore
Can you leak tcache_perthread_struct's address??

nc offsec-chalbroker.osiris.cyber.nyu.edu 1211
```
Looking at the binary:
```aiignore
$ checksec --file=./thread_and_needle
[*] '/mnt/csgy9223_IntroOffSec/week_8/thread_and_needle'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Opening the binary in binja, There are a series of menu items:
```aiignore
 ./thread_and_needle
Welcome to the OffSec Sewing Machine!
In this challenge you must leak the address of `tcache_perthread_struct`
to calculate the heap base address using the vulnerabilities included
in the binary.

But first, we sew!
What do you want to do?
1. Set up sewing machine
2. Edit setup
3. Make item
4. Quit
>
```
Going into option 1, runs the setup() function which allocates some memory space, then proceeds to get user input to fill the space:

```aiignore
What do you want to do?
1. Set up sewing machine
2. Edit setup
3. Make item
4. Quit
> 1
                                                                                                                                                                                                     What item are you making (max 8 characters, e.g., quilt, dress, etc.)?
> aaa                                                                                                                                                                                                Nice! That will be cool.                                                                                                                                                                             
Now, set up your stitch length
> aaa
Solid settings.                                                                                                                                                                                      
Now, what stitch type did you land on (max 8 characters, e.g., blind hem, ladder, etc.)?
> aaa
Oh, that is a great choice!                                                                                                                                                                          
What is the heap base? Do you have any guesses?
```
When returning to main(), the user is prompted for the heap base address. Since we don't have one we will just hit enter and move on.

Next we select to view data using the edit option 2. This runs the edit() function which asks which item to view, then proceeds to get input from the user:
```aiignore
Would you like to reivew any of the prior settings for reference?
1. Item
2. Stitch length
3. Stitch type
4. Not necessary
> 1
Item: aaa

What item are you making (max 8 characters, e.g., quilt, dress, etc.)?
> aaa
Nice! That will be cool.                                                                                                                                                                             
Now, set up your stitch length
> aaa
Solid settings.                                                                                                                                                                                      
Now, what stitch type did you land on (max 8 characters, e.g., blind hem, ladder, etc.)?
> aaa
Oh, that is a great choice!                                                                                                                                                                          
What is the heap base? Do you have any guesses?
  
```
The interesting thing here is that we want to leak the heap address once we free the memory space. This can be done by selecting option 2, the Stitch Length which will display the contents of the memory allocation + 8 bytes. Once the memory is freed. This will point to the tcache per thread structure. 

But first we have to free the memory, this can be done by selecting option 3, Make Item from the main menu. This runs the make() function that frees the memory.

```aiignore
What do you want to do?
1. Set up sewing machine
2. Edit setup
3. Make item
4. Quit
> 3

One moment please...
Success! You made one aaa
!

What is the heap base? Do you have any guesses?
```
So the game plan here is to:
- Run the setup() function to allocate the memory, 
- followed by the make() function to free the memory
- and finally the edit() function to leak the address of tcache thread structure

We'll have to adjust the returned value by & ~0xff.

- For this we'll build a solver script.

The results:
```aiignore
That's it!
Before we leave, let's clean up our workshop
(hint: we cannot free two identical addresses into tcache, nor can we
 free an address which has *(address + 8) == &tcache_perthread_struct)
Double check that the global allocation does not have this set

Here's your flag, friend: flag{Sew1ng_2gethr_3xpl017s!_943bac622edb1aab}
```

## Challenge - Sneaky Leak
```
Can you leak the address of sytem?

nc offsec-chalbroker.osiris.cyber.nyu.edu 1210
```
 Inpsecting the binary:

```aiignore
$ checksec --file sneaky_leak
[*] '/mnt/csgy9223_IntroOffSec/week_8/sneaky_leak'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

A little bit of everything here. Running the binary:

```
 ./sneaky_leak
I need your help leaking the address of system!
And all i have to offer is this array of random character buffers :/
Can you find it and get the flag??
What do you want to do?
1. Free an index
2. Read an index
3. Allocate an index
4. Guess the address of system
> 
```

My first intuition is that I will have to allocate some data, free up some data, read a freed portion of the data and get some information to guess the address of system.

Looking at code using Binja.

main() calls a function populate_arr() which will be an array of 0x7f (127) pointers to allocated memory for each index. Each index will be allocated the index left shifted by 4 bytes of heap space. Smallest 0x0 and largest 0x7e0 (2016). The space will contain a random value using the /dev/urandom system function.

Allocation:
- The index allocation is 0-126
- The allocation size is dependent on the 4 bit shift left of the index
  - 0x7e (126) = 0x7e0 (2016 bytes) so can be larger than tcache if selected properly

Reading: Reads the value at an index if the pointer points to > 0x0 value.

Freeing: Frees the allocated memory for that index as long as it has not been freed yet.

I'm going to run in GDB, to get a better feel for what is going on.

My plan of attack will be to work with the larger indexes to utilize the unsorted bins. This would give me a pointer to the main arena. I also need to keep a guard between the freed space and the top chunk. My plan of attack will be:

- Free index 124
- Free index 125
- Allocate index 125 (should point back to original memory allocation)
- Read the data at index 125 (should point to head in the main arena)

Found the offset from main_arena to libc
-  p/x 0x7ffff7fba1f0 - 0x00007ffff7dcd000 = 0x1ed1f0

And the script produced:

```aiignore
That's it!                                                                                                                                                                                                                                  
Here's your flag, friend: flag{S1LLY_malloc_U_shuld_m3ms3t!_74ad88e5fba05bb6}
```