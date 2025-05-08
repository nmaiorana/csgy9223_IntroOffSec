from pwn import *
import binascii


import ctypes

libc = ctypes.CDLL("libc.so.6")

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./pseudo_rand"

LOCAL = False
if LOCAL:
    p = process(target_file)
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1514)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

# Define the time function
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]  # time returns a long
libc.srand.argtypes = [ctypes.c_uint]  # srand takes an unsigned int

# Call time(NULL) to get the current time
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
print(f"Current time: {current_time.value}")

print(p.recvuntil(b"Can you guess my number?\n"))

adjust = 0

# Seed the random number generator with the current time
current_time.value = current_time.value + adjust
seed = current_time.value + 25
libc.srand(ctypes.c_uint(seed))

libc.rand.restype = ctypes.c_int

random_number = libc.rand()
print(f"Random number: {random_number}")
p.sendline(str(random_number))

p.interactive()
