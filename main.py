"""This module implements the Pocket AES Decryption algorithm."""

inverse_substitution_box = {
    "0000": "1010",
    "0001": "0000",
    "0010": "1001",
    "0011": "1110",
    "0100": "0110",
    "0101": "0011",
    "0110": "1111",
    "0111": "0101",
    "1000": "0001",
    "1001": "1101",
    "1010": "1100",
    "1011": "0111",
    "1100": "1011",
    "1101": "0100",
    "1110": "0010",
    "1111": "1000",
}


inverse_constant_matrix = [
    [9, 2],
    [2, 9],
]

inverse_constant_matrix_binary = [
    [0x9, 0x2],
    [0x2, 0x9],
]
