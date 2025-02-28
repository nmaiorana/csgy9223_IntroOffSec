from pwn import *

context.log_level = "debug"

LOCAL = True

if LOCAL:
    p = process("./hand_rolled_cryptex")
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1273)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

# Round 1
file_name = "flag.txt"
flag = "2"
print(p.recvuntil(b" > ").decode())
p.sendline(bytes(file_name, "utf-8"))
print(p.recvuntil(b" > ").decode())
p.sendline(bytes(flag, "utf-8"))

# Round 2
print(p.recvuntil(b"...\n").decode())
fd = u32(p.recvuntil(b"\n").decode().strip())
print(fd)
xor_fd = fd ^ 201
print(xor_fd)
comp_fd = ~xor_fd
print(comp_fd)
p.sendline(p32(comp_fd, sign="yes"))



print(p.recvuntil(b" > ").decode())



p.interactive()
