from pwn import *

import ctypes
import time

libc = ctypes.CDLL("libc.so.6")

# Define the time function
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]  # time returns a long
libc.srand.argtypes = [ctypes.c_uint]  # srand takes an unsigned int

# Call time(NULL) to get the current time
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))

# Seed the random number generator with the current time
libc.srand(ctypes.c_uint(current_time.value*current_time.value))

libc.rand.restype = ctypes.c_int32 # rand returns an int

flag = b"flag{this_is_a_fake_flag}"
for m_char in flag:
    print(f"Original character: {hex(m_char)}({chr(m_char)})")
    random_number = libc.rand()
    print(f"Random number: {hex(random_number)}")
    c_char = random_number ^ m_char
    print(f"XORed character: {hex(c_char)}")
    print(f"Inverse XORed character: {chr(random_number ^ c_char)}")

