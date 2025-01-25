from pwn import *

context.log_level = "debug"

p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1237)
p.recvuntil(b"abc123):")
p.sendline(b"nam10102")
p.recvuntil(b"moment...")
p.recvline()
p.recvline()
print(p.recvline())
p.interactive()
