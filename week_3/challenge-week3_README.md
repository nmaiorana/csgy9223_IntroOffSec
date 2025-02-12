# Week 3 CTF

---
## Challenge - Rewards

```aiignore
Rewards

I don't quite understand this rewards program. Can you help me out? 

nc offsec-chalbroker.osiris.cyber.nyu.edu 1263
```
We are provided with a binary called rewards:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_3$ file rewards
rewards: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b00ec8ecd10f5a056bcf9da20327d56adb75ce9f, for GNU/Linux 3.2.0, not stripped
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_3$
```
Let's run it and see what it asks for:

```aiignore
Please select one option:
 1. Enter a store
 2. List stores
 3. Enter a customer
 4. Process rewards
 5. Quit

 > 1

Enter the city where the store is located
 >
```
I get various options until I try option 4, then I get a segmentation fault. Let's crack open the binary to see what it wants.

Looking at main, there is a while true loop that displays the menu, gets a single digit entry from the user and does a number of comparisons. Let's dig into get_number.

This only allows a single digit entry between 0-9. It returns the integer value of the number entered.

Back to main, lets examine the menu() function. This is pretty strait forward. It looks to be clearing the screen, putting the cursor to the top, printing 2 lines, then the menu. It does print an empty string after "5. Quit", then the characters "> ". The empty string comes from an address 0x21e4. Nothing special here except the empty string. A quick guess is telling me that this is a sub menu question. Like above, "Enter the city where the store is located". 

Option "5. Quit" is not checked so it drops to a return 0.

After cleaning up the file a bit in binja, the process() function is looking for these conditions:

- 2 store entries
  - store numbers: array of uint64_t (2 X 8 bytes)
  - store names: array of uint64_t* to the buffers (2 X 8 bytes)
- 3 customer entries
  - This is an array of structures (40 bytes)
    - uint64_t - number
    - unit64_t* to name buffer
    - unit64_t* to city buffer
    - unit64_t - total
    - unit64_t - rewards level
- The customer[1] city must equal the 2nd city entered city[1]. This is due to the 2nd city entered aligning with the address that is being used to do the comparison.
- Update rewards for customer[1] if the above 2 are met using update_rewards() function.
  - this function updates the total for the customer by multiplying it by 4919
  - this function also sets the customer rewards level to 3
- customer[1] total rewards after the update is (255620754 / 4919) or 51966, so the 2nd customer has to be entered as 51966.

```aiignore
Please select one option:
 1. Enter a store
 2. List stores
 3. Enter a customer
 4. Process rewards
 5. Quit

 > 4

        Nice Job!

        Here's your flag, friend: flag{n1c3_j0b_r3c0v3r1ng_th3s3_d4t4_structur3s!_a8a14a1efae086a3}
```



