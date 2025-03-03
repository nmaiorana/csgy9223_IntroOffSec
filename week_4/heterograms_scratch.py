from pwn import *
import ctypes

def encode_word(word:str) -> bytearray:
    encoded = bytearray(len(word))
    for char in word:
        encoded += struct.pack('B', ord(char) - ord('a'))
    return encoded

def checksum(byte_string:bytes) -> ctypes.c_int8:
    sum = ctypes.c_int8(0)
    for byte in byte_string:
        sum.value += byte
    return ~sum.value

heterogram = "unforgivable"
heterogram_encoded = encode_word(heterogram)
byte_string = bytes([0x1]) + heterogram_encoded + bytes([0xa])
print(byte_string)
print (len(byte_string))
check_sum = checksum(byte_string)
print(hex(check_sum))

packed8 = p8(~check_sum, sign="signed")
print(packed8)

# unforgivable\x00\x00\x00
# troublemakings\x00
# computerizably\x00
# hydromagnetics\x00
# flamethrowing\x00\x00
# copyrightable\x00\x00
# undiscoverably\x00
# \x00
# \x00
# \x00

print(len('unforgivable'))