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


def main():
    """This is the main function."""
    sub_nibbles = []
    shifted_row = []
    mixed_column = []

    text_block = input("Enter a text block: ")
    if len(text_block) > 4:
        print("Text Block invalid. It should have exactly 4 characters.")
        return
    text_block = text_block.zfill(4)

    # Convert the hexadecimal to binary and remove the '0b' prefix and make the string 16 bit
    text_binary_value = bin(int(text_block, 16))[2:].zfill(16)

    sub_nibbles = sub_nibbles_func(text_binary_value)
    sub_nibbles_string = "".join(sub_nibbles)
    sub_nibbles_binary_value = bin(int("".join(sub_nibbles), 16))[2:]
    print(f"SubNibbles({text_block}) = ", sub_nibbles_string)

    shifted_row = shift_rows(text_binary_value)
    shifted_row_string = "".join(shifted_row)
    print(f"ShiftRows({text_block}) = ", shifted_row_string)

    mixed_column = mix_columns(text_block)
    mixed_column_string = "".join(mixed_column)
    print(f"MixColumns({text_block}) = ", mixed_column_string)

    key = input("Enter a key: ")
    if len(key) > 4:
        print("Key invalid. It should have exactly 4 characters.")
        return
    key = key.zfill(4)
    # Convert the hexadecimal to binary and remove the '0b' prefix
    key_binary_value = bin(int(key, 16))[2:]
    key_binary_value = key_binary_value.zfill(16)
    round_key_one, round_key_two = generate_round_keys(key_binary_value)
    round_key_one_string = "".join(
        [hex(int(binary, 2))[2:] for binary in round_key_one]
    )
    round_key_two_string = "".join(
        [hex(int(binary, 2))[2:] for binary in round_key_two]
    )

    print(
        f"GenerateRoundKets({key}) = ({round_key_one_string}, {round_key_two_string})"
    )
