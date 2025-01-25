from pwn import *

context.log_level = "debug"

p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1237)
p.recvuntil(b"abc123):")
p.sendline(b"nam10102")
print(p.recvuntil(b"moment...").decoded())
print(p.recvline().decoded())
print(p.recvline().decoded())
print(p.recvline().decoded())
p.interactive()
