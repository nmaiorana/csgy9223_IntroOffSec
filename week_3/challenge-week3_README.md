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

After cleaning up the file a bit in binja, the process() function is looking for a number of conditions. My first attempts at creating structures produced some weird code interpretations from binja. But after determining the proper sizes, I got some easy to interpret code:

```aiignore
00004060  struct store stores[0x2] = 
00004060  {
00004060      [0x0] = 
00004060      {
00004060          int32_t number = 0x0
00004064              00 00 00 00                                                                              ....
00004068          char* city = nullptr
00004070      }
00004070      [0x1] = 
00004070      {
00004070          int32_t number = 0x0
00004074                                                              00 00 00 00                                              ....
00004078          char* city = nullptr
00004080      }
00004080  }
00004080  struct customer customers[0x3] = 
00004080  {
00004080      [0x0] = 
00004080      {
00004080          uint64_t number = 0x0
00004088          char* name = nullptr
00004090          char* city = nullptr
00004098          uint64_t total = 0x0
000040a0          uint64_t rewards_level = 0x0
000040a8      }
000040a8      [0x1] = 
000040a8      {
000040a8          uint64_t number = 0x0
000040b0          char* name = nullptr
000040b8          char* city = nullptr
000040c0          uint64_t total = 0x0
000040c8          uint64_t rewards_level = 0x0
000040d0      }
000040d0      [0x2] = 
000040d0      {
000040d0          uint64_t number = 0x0
000040d8          char* name = nullptr
000040e0          char* city = nullptr
000040e8          uint64_t total = 0x0
000040f0          uint64_t rewards_level = 0x0
000040f8      }
000040f8  }
```

One thing that made things easy was the pre-defined limits on the number of stores and customers. This allowed me to map those memory locations with a specific layout for the structures and the conditional logic was easy to understand:
```aiignore
000015e0    int64_t update_rewards(int64_t customer_number)

0000162f        customers[customer_number].total *= 4919
0000164f        customers[customer_number].rewards_level.b = 3
00001655        return customer_number * 0x28


00001656    int64_t process()

00001672        if (num_customers == 3 || num_stores == 2)
000016a5            if (strcmp(customers[1].city, stores[1].city) == 0)
000016ac                update_rewards(customer_number: 1)
000016ac            
000016be            if (customers[1].total == 255620754)
000016ca                puts(str: "\n\tNice Job!")
000016d4                read_flag()
000016de                exit(status: 0)
000016de                noreturn
000016de            
000016ed            puts(str: "Try again, friend!\n\n")
00001672        else
0000167e            puts(str: "That doesn't look right!")
0000167e        
000016f8        return 1
```

- 2 store entries
  - 16 byte structure
  - store numbers: array of uint64_t (8 bytes)
  - store city: array of uint64_t* to the buffers (8 bytes)
- 3 customer entries
  - This is an array of structures (40 bytes)
    - uint64_t - number
    - unit64_t* to name buffer
    - unit64_t* to city buffer
    - unit64_t - total
    - unit64_t - rewards level
- The customer[1] city must equal the 2nd city entered city[1]. 
- Update rewards for customer[1] if the above 2 are met using update_rewards() function.
  - this function updates the total for the customer by multiplying it by 4919
  - this function also sets the customer rewards level to 3
- customer[1] total rewards after the update is 255620754 which means the original reward X 4919 = 255620754, x = 255620754 / 4919 = 51966, so the 2nd customer has to be entered as 51966.

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
## Challenge - Knapsack

```aiignore
Can you help me find the best way to spend my entire allowance?

nc offsec-chalbroker.osiris.cyber.nyu.edu 1260
```
Exploring the file:

```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_3$ file knapsack
knapsack: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cc1aa38b718932d2a7c1655568d7808e2546985e, for GNU/Linux 3.2.0, not stripped
```
Running the process:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_3$ ./knapsack


        Let's go shopping!

        How many of each would you like?
        3
4
        Nah, that's not how we count around here!
```
This appears to be a problem that can be solved with a Z3 solver in python. Cracking open the binary in binja the process takes in 6 numbers and does a single computation which has to match a predefined value.

The predefined values are:

```aiignore
00004010  uint32_t var_0 = 1605
00004014  uint32_t var_1 = 215
00004018  uint32_t var_2 = 275
0000401c  uint32_t var_3 = 335
00004020  uint32_t var_4 = 355
00004024  uint32_t var_5 = 420
00004028  uint32_t var_6 = 580
```
I have named the input values to be num1-num6.

The computation is:

```aiignore
000012a6        if (var_6 * num6 + var_1 * num1 + var_2 * num2 + var_3 * num3 + var_4 * num4 + var_5 * num5 != var_0)
000012af            return 0;

```
So the result of the computation needs to equal 1605. For this I'll create a python solver using Z3.
```python
from z3 import Int, Solver, sat

# declare the predefined integers

var_0 = 1605
var_1 = 215
var_2 = 275
var_3 = 335
var_4 = 355
var_5 = 420
var_6 = 580

# declare the variables
num1 = Int('num1')
num2 = Int('num2')
num3 = Int('num3')
num4 = Int('num4')
num5 = Int('num5')
num6 = Int('num6')

# create solver and enforce constraints per the program control flow
s = Solver()
s.add(num1 >= 0)
s.add(num2 >= 0)
s.add(num3 >= 0)
s.add(num4 >= 0)
s.add(num5 >= 0)
s.add(num6 >= 0)
s.add(var_6 * num6 + var_1 * num1 + var_2 * num2 + var_3 * num3 + var_4 * num4 + var_5 * num5 == var_0)

# solve!
assert s.check() == sat, "Error, not satisfiable!"
print(s.model())
```
Running the sovler we get:
```aiignore
[num5 = 0, num6 = 1, num2 = 0, num3 = 2, num1 = 0, num4 = 1]
```
So my input string is: "0 - 0 - 2 - 1 - 0 - 1"

And the results are:
```aiignore
(csgy9223py) nmaiorana@Nicks-Surface-6:~/csgy9223/csgy9223_IntroOffSec/week_3$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1260
Please input your NetID (something like abc123): nam10102
hello, nam10102. Please wait a moment...


        Let's go shopping!

        How many of each would you like?
        0 - 0 - 2 - 1 - 0 - 1

        You made great choices!

        Here's your flag, friend: flag{1ts_n0t_t0_b4d_s0lv1ng_pr0bl3ms_w1th_Z3!_b761131001a43a40}
```
## Challenge - Disks Game
```aiignore
This old game is asking for input. Can you help me figure out the correct answer?

nc offsec-chalbroker.osiris.cyber.nyu.edu 1261
```
