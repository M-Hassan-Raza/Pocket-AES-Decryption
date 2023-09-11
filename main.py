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

Rcon_1 = "1110"
Rcon_2 = "1010"


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

    mixed_column = mix_columns(text_block)
    mixed_column_string = "".join(mixed_column)

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

    decrypted_block = ""
    print(f"Decrypted Block: {decrypted_block}")


def sub_nibbles_func(binary_value):
    """This function performs the substitution of nibbles."""
    sub_nibbles_data = []

    # Check if the input is 4 bits or 16 bits
    if len(binary_value) == 4:
        # Input is already a 4-bit nibble
        sub_nibbles_data.append(substitution_box[binary_value])
    elif len(binary_value) == 16:
        # Input is a 16-bit binary value, split it into 4-bit nibbles
        for i in range(0, 16, 4):
            sub_nibbles_data.append(substitution_box[binary_value[i : i + 4]])
    else:
        raise ValueError("Input length must be either 4 or 16 bits")

    hexadecimal_values = []

    for binary_value in sub_nibbles_data:
        # Convert the binary to an integer and then to a hexadecimal nibble
        hex_value = hex(int(binary_value, 2))[2:]

        # Append the hexadecimal nibble to the list
        hexadecimal_values.append(hex_value)

    return hexadecimal_values


def shift_rows(binary_value):
    """This function performs the shift rows operation."""
    nibbles = [binary_value[i : i + 4] for i in range(0, len(binary_value), 4)]
    nibbles[0], nibbles[2] = nibbles[2], nibbles[0]
    shifted_binary_value = []
    for binary_value in nibbles:
        hex_value = hex(int(binary_value, 2))[2:]
        shifted_binary_value.append(hex_value)

    binary_value = "".join(shifted_binary_value)
    return shifted_binary_value


def mix_columns(hex_input_value):
    """This function performs the mix columns operation."""
    binary_value = bin(int(hex_input_value, 16))[2:]
    nibbles = [binary_value[i : i + 4] for i in range(0, len(binary_value), 4)]
    processed_nibbles = []

    d0 = finite_field_multiply(
        int(nibbles[0], 2), inverse_constant_matrix_binary[0][0]
    ) ^ finite_field_multiply(
        int(nibbles[1], 2), inverse_constant_matrix_binary[0][1]
    )
    d1 = finite_field_multiply(
        int(nibbles[0], 2), inverse_constant_matrix_binary[1][0]
    ) ^ finite_field_multiply(
        int(nibbles[1], 2), inverse_constant_matrix_binary[1][1]
    )
    d2 = finite_field_multiply(
        int(nibbles[2], 2), inverse_constant_matrix_binary[0][0]
    ) ^ finite_field_multiply(
        int(nibbles[3], 2), inverse_constant_matrix_binary[0][1]
    )
    d3 = finite_field_multiply(
        int(nibbles[2], 2), inverse_constant_matrix_binary[1][0]
    ) ^ finite_field_multiply(
        int(nibbles[3], 2), inverse_constant_matrix_binary[1][1]
    )

    processed_nibbles.append(hex(d0)[2:])
    processed_nibbles.append(hex(d1)[2:])
    processed_nibbles.append(hex(d2)[2:])
    processed_nibbles.append(hex(d3)[2:])

    return processed_nibbles


def generate_round_keys(binary_key):
    """This function generates the round keys for Pocket AES encryption method."""
    round_key_one = []
    round_key_two = []
    binary_key_chunks = [
        binary_key[i : i + 4] for i in range(0, len(binary_key), 4)
    ]
    round_key_one.append(
        bitwise_xor(
            bitwise_xor(
                binary_key_chunks[0],
                bin(int(sub_nibbles_func(binary_key_chunks[3])[0], 16))[
                    2:
                ].zfill(4),
            ),
            Rcon_1,
        )
    )
    round_key_one.append(bitwise_xor(binary_key_chunks[1], round_key_one[0]))
    round_key_one.append(bitwise_xor(binary_key_chunks[2], round_key_one[1]))
    round_key_one.append(bitwise_xor(binary_key_chunks[3], round_key_one[2]))

    round_key_two.append(
        bitwise_xor(
            bitwise_xor(
                round_key_one[0],
                bin(int(sub_nibbles_func(round_key_one[3])[0], 16))[2:].zfill(
                    4
                ),
            ),
            Rcon_2,
        )
    )
    round_key_two.append(bitwise_xor(round_key_one[1], round_key_two[0]))
    round_key_two.append(bitwise_xor(round_key_one[2], round_key_two[1]))
    round_key_two.append(bitwise_xor(round_key_one[3], round_key_two[2]))

    return round_key_one, round_key_two


def bitwise_xor(bin_str1, bin_str2):
    """Perform bitwise XOR between two binary strings of equal length."""
    if len(bin_str1) != len(bin_str2):
        raise ValueError("Binary strings must have the same length")

    result = ""
    for bit1, bit2 in zip(bin_str1, bin_str2):
        result += "1" if bit1 != bit2 else "0"

    return result


def finite_field_multiply(first_number, second_number):
    """Perform multiplication in the finite field GF(2^4) modulo 𝒙^4 + 𝒙 + 𝟏."""
    # Initialize m to 0 to store the result
    multiplication_result = 0

    while second_number > 0:
        # Check if the LSB of b is 1
        if second_number & 1 == 1:
            # Perform bitwise XOR to accumulate the product
            multiplication_result ^= first_number

        # Left-shift a by 1 bit (equivalent to multiplying by 2 in the field)
        first_number <<= 1

        # Check if the fourth bit of a is set
        if first_number & 0b10000:
            # Perform reduction modulo the irreducible polynomial
            first_number ^= 0b10011  # Irreducible polynomial 𝒙^4 + 𝒙 + 𝟏

        # Right-shift b by 1 bit (equivalent to dividing by 2 in the field)
        second_number >>= 1

    return multiplication_result


if __name__ == "__main__":
    main()
