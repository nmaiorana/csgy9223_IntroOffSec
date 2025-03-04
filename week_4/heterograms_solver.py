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
    # encoded += p8(0xa)
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
    pktlen = len(pkt) + 2
    print (pktlen)
    pktchk = checksum(pkt +p8(0) + p8(0))
    p.send(p8(pktlen) + p8(pktchk, sign="signed")  + pkt)

LOCAL = True

if LOCAL:
    p = process("./heterograms")
    # g = gdb.attach(p, '''
    # set disable-randomization off
    # b check
    # add-symbol-file packet.o
    # # ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1271)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

p.recvuntil(b" flag!\n")

for i, heterogram in enumerate(heterograms):
    packet = build_packet_erase()
    packet += build_packet_idx(i)
    packet += build_packet_count(heterogram)
    packet += build_packet_check()
    send_packet(p, packet)

p.interactive()
