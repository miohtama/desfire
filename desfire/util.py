"""Misc. utility functions."""


def byte_array_to_byte_string(bytes):
    s = "".join([chr(b) for b in bytes])
    return s


def byte_array_to_human_readable_hex(bytes):
    return " ".join(["{:02X}".format(ord(c)) for c in byte_array_to_byte_string(bytes)])


def byte_string_to_byte_array(s):
    return [ord(c) for c in s]


def hex_array_to_byte_string(hex_array):
    return "".join(chr(c) for c in hex_array)


def dword_to_byte_array(value):
    return [(value & 0xff), (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24), ]


def word_to_byte_array(value):
    return [(value & 0xff), (value >> 8) & 0xff]
