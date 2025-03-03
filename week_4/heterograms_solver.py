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

def build_op_packet(op_code: int, word: str = None) -> bytearray:
    if op_code == 0:
        encoded = p8(op_code) + p8(0)
        return encoded
    elif op_code == 1:
        encoded = encode_word(word)
        encoded = p8(op_code) + p8(len(encoded)) + encoded
        return encoded
    else: # op_code == 2
        encoded = p8(op_code) + p8(0)
        return encoded

def send_packet(p: remote, pkt: bytearray) -> None:
    pkt += p8(1) + p8(1)
    pktlen = len(pkt) + 2
    pkt += p8(0xa)
    pktchk = checksum(pkt)
    p.send(bytes(p8(pktlen)) + bytes(p8(pktchk, sign="signed"))  + pkt)

LOCAL = True

if LOCAL:
    p = process("./heterograms")
    # g = gdb.attach(p, '''
    # set disable-randomization off
    # b check
    # add-symbol-file packet.o
    # ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1271)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

p.recvuntil(b" flag!\n")
for i, heterogram in enumerate(heterograms):

    send_packet(p, build_op_packet(1, heterogram))
    # send_packet(p, p8(0) + p8(0) + p8(2) + p8(0))
    send_packet(p, p8(2) + p8(2))



    # packet_len = len(packet) + 2
    # packet += p8(0xa)
    # check_sum = checksum(packet)
    # packet = bytes(p8(packet_len)) + bytes(p8(check_sum, sign="signed"))  + packet
    #
    # p.send(packet)

p.interactive()
