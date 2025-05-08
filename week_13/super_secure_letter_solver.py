from pwn import *
import binascii


import ctypes

libc = ctypes.CDLL("libc.so.6")

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./super_secure_letter"

LOCAL = False
if LOCAL:
    p = process(target_file)
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1517)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

# Define the time function
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]  # time returns a long
libc.srand.argtypes = [ctypes.c_uint]  # srand takes an unsigned int

# Call time(NULL) to get the current time
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
print(f"Current time: {current_time.value}")

print(p.recvuntil(b"luck reading it :)!\n"))
letter = p.recvline().strip()
print(letter)
assert len(letter) % 2 == 0, "Bytestring length must be even"

flag = ''
adjust = 0

# Seed the random number generator with the current time
current_time.value = current_time.value + adjust
seed = current_time.value * current_time.value
libc.srand(ctypes.c_uint(seed))

libc.rand.restype = ctypes.c_int
flag = ''
for i in range(0, len(letter), 2):
    byte_pair = letter[i:i + 2]
    print(f'Byte pair: {byte_pair}')
    character = int(byte_pair.decode(), 16)
    print(f'Character {i}: int: {character} hex: {hex(character)}')
    # print(f"Cyphertext character: {hex(c_char)}({chr(c_char)})")
    random_number = libc.rand() & 0xFF
    print(f"Random number: {hex(random_number)}")
    m_char = (random_number ^ character)
    print(f"XORed character: {hex(m_char)}")
    flag += chr(m_char)

print(f"Flag: {flag}")
p.interactive()
