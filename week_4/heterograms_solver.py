from pwn import *
import ctypes

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-f", "-h"]

heterograms = [
    "unforgivable",
    "troublemakings",
    "computerizably",
    "hydromagnetics",
    "flamethrowing",
    "copyrightable",
    "undiscoverably"
]

def encode_word(word:str) -> bytearray:
    encoded = bytearray()
    for char in word:
        encoded += p8(ord(char) - ord('a'))
    return encoded

def checksum(byte_string:bytes) -> ctypes.c_int8:
    sum = ctypes.c_int8(0)
    for byte in byte_string:
        sum.value += byte
    return ~sum.value

def build_packet_count(word: str = None) -> bytearray:
    encoded = encode_word(word)
    encoded = p8(1) + p8(len(encoded)) + encoded
    return encoded

def build_packet_erase() -> bytearray:
    return p8(2) + p8(2)

def build_packet_check() -> bytearray:
    return p8(2) + p8(0)

def build_packet_idx(index: int) -> bytearray:
    return p8(0) + p8(index)

def send_packet(p: remote, pkt: bytearray) -> None:
    packet_len = len(pkt) + 1
    packet_checksum = checksum(pkt)
    p.send(p8(packet_len) + p8(packet_checksum, sign="signed")  + pkt)

LOCAL = False

if LOCAL:
    p = process("./heterograms")
    # p = gdb.debug( "./heterograms",'''
    #     set disable-randomization on
    #     b checksum
    #     b check
    #     add-symbol-file packet.o
    #     c
    # ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1271)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

p.recvuntil(b" flag!\n")

packet_erase = build_packet_erase()
packet_check = build_packet_check()

# send_packet(p, build_packet_idx(0) + packet_erase)
for i, heterogram in enumerate(heterograms):
    send_packet(p, build_packet_count(heterogram) + build_packet_idx(i) + packet_check)
    p.recvuntil(b"That's a nice word!\n")
    send_packet(p, build_packet_idx(i+1) + packet_erase )
    p.recvuntil(b"Copy that!\n")

p.interactive()
