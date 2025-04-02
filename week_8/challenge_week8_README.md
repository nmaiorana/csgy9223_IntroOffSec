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

