"""This module implements the Pocket AES Decryption algorithm."""

INVERSE_SUBSTITUTION_BOX = {
    "1010": "0000",
    "0000": "0001",
    "1001": "0010",
    "1110": "0011",
    "0110": "0100",
    "0011": "0101",
    "1111": "0110",
    "0101": "0111",
    "0001": "1000",
    "1101": "1001",
    "1100": "1010",
    "0111": "1011",
    "1011": "1100",
    "0100": "1101",
    "0010": "1110",
    "1000": "1111",
}

SUBSTITUTION_BOX = {
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


INVERSE_CONSTANT_MATRIX = [
    [9, 2],
    [2, 9],
]

INVERSE_CONSTANT_MATRIX_BINARY = [
    [0x9, 0x2],
    [0x2, 0x9],
]

RCON_1 = "1110"
RCON_2 = "1010"


def main():
    """This is the main function."""

    cipher_text_block = input("Enter the ciphertext block = ")
    if len(cipher_text_block) > 4:
        print("Text Block invalid. It should have exactly 4 characters.")
        return
    cipher_text_block = cipher_text_block.zfill(4)

    decryption_key = input("Enter the decryption key = ")
    if len(decryption_key) > 4:
        print("Key invalid. It should have exactly 4 characters.")
        return
    decryption_key = decryption_key.zfill(4)
    decryption_key_binary_value = bin(int(decryption_key, 16))[2:].zfill(16)
    cipher_text_binary_value = bin(int(cipher_text_block, 16))[2:].zfill(16)

    print(f"Cipher Binary Value: {cipher_text_binary_value}")
    print(f"Decryption Key Binary Value: {decryption_key_binary_value}")

    decrypted_block = decrypt_data(
        cipher_text_binary_value, decryption_key_binary_value
    )
    print(f"Decrypted Block: {decrypted_block}")


def decrypt_data(cipher_text_binary_value, decryption_key):
    """This function decrypts the cipher text using the decryption key."""

    round_key_one, round_key_two = generate_round_keys(decryption_key)
    round_key_one = "".join(round_key_one)
    round_key_two = "".join(round_key_two)

    # Round 1
    print(f"Round Key 2: {round_key_two}")
    shifted_rows_data = shift_rows(cipher_text_binary_value)
    shifted_rows_data = "".join(shifted_rows_data)
    shifted_rows_data = bin(int(shifted_rows_data, 16))[2:].zfill(16)
    print(f"Shifted Rows Data: {shifted_rows_data}")
    after_round_key_xor_data = bitwise_xor(shifted_rows_data, round_key_two)
    print(f"After Round Key XOR Data: {after_round_key_xor_data}")
    sub_nibbles_data = sub_nibbles_func(after_round_key_xor_data)
    sub_nibbles_data = "".join(sub_nibbles_data)
    sub_nibbles_data = bin(int(sub_nibbles_data, 16))[2:].zfill(16)
    print(f"Sub Nibbles Data: {sub_nibbles_data}")

    # Round 2
    print(f"Round Key 1: {round_key_one}")
    shifted_rows_data = shift_rows(sub_nibbles_data)
    shifted_rows_data = "".join(shifted_rows_data)
    print(f"Shifted Rows Data: {shifted_rows_data}")
    mixed_columns_data = mix_columns(shifted_rows_data)
    mixed_columns_data = "".join(mixed_columns_data)
    mixed_columns_data = bin(int(mixed_columns_data, 16))[2:].zfill(16)
    print(f"Mixed Columns Data: {mixed_columns_data}")
    after_round_key_xor_data = bitwise_xor(mixed_columns_data, round_key_one)
    print(f"After Round Key XOR Data: {after_round_key_xor_data}")
    sub_nibbles_data = sub_nibbles_func(after_round_key_xor_data)
    print(f"Sub Nibbles Data: {sub_nibbles_data}")

    decrypted_data = []
    for hex_value in sub_nibbles_data:
        decrypted_data.append(hex_value)

    return "".join(decrypted_data)


def sub_nibbles_func(binary_value):
    """This function performs the substitution of nibbles."""
    sub_nibbles_data = []
    # Check if the input is 4 bits or 16 bits
    if len(binary_value) == 4:
        # Input is already a 4-bit nibble
        sub_nibbles_data.append(INVERSE_SUBSTITUTION_BOX[binary_value])
    elif len(binary_value) == 16:
        # Input is a 16-bit binary value, split it into 4-bit nibbles
        for i in range(0, 16, 4):
            sub_nibbles_data.append(
                INVERSE_SUBSTITUTION_BOX[binary_value[i : i + 4]]
            )
    else:
        raise ValueError("Input length must be either 4 or 16 bits")

    hexadecimal_values = []

    for binary_value in sub_nibbles_data:
        # Convert the binary to an integer and then to a hexadecimal nibble
        hex_value = hex(int(binary_value, 2))[2:]

        # Append the hexadecimal nibble to the list
        hexadecimal_values.append(hex_value)

    return hexadecimal_values


def sub_nibbles_func_decrypted(binary_value):
    """This function performs the substitution of nibbles."""
    sub_nibbles_data = []
    # Check if the input is 4 bits or 16 bits
    if len(binary_value) == 4:
        # Input is already a 4-bit nibble
        sub_nibbles_data.append(SUBSTITUTION_BOX[binary_value])
    elif len(binary_value) == 16:
        # Input is a 16-bit binary value, split it into 4-bit nibbles
        for i in range(0, 16, 4):
            sub_nibbles_data.append(SUBSTITUTION_BOX[binary_value[i : i + 4]])
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
        int(nibbles[0], 2), INVERSE_CONSTANT_MATRIX_BINARY[0][0]
    ) ^ finite_field_multiply(
        int(nibbles[1], 2), INVERSE_CONSTANT_MATRIX_BINARY[0][1]
    )
    d1 = finite_field_multiply(
        int(nibbles[0], 2), INVERSE_CONSTANT_MATRIX_BINARY[1][0]
    ) ^ finite_field_multiply(
        int(nibbles[1], 2), INVERSE_CONSTANT_MATRIX_BINARY[1][1]
    )
    d2 = finite_field_multiply(
        int(nibbles[2], 2), INVERSE_CONSTANT_MATRIX_BINARY[0][0]
    ) ^ finite_field_multiply(
        int(nibbles[3], 2), INVERSE_CONSTANT_MATRIX_BINARY[0][1]
    )
    d3 = finite_field_multiply(
        int(nibbles[2], 2), INVERSE_CONSTANT_MATRIX_BINARY[1][0]
    ) ^ finite_field_multiply(
        int(nibbles[3], 2), INVERSE_CONSTANT_MATRIX_BINARY[1][1]
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
                bin(
                    int(
                        sub_nibbles_func_decrypted(binary_key_chunks[3])[0], 16
                    )
                )[2:].zfill(4),
            ),
            RCON_1,
        )
    )
    round_key_one.append(bitwise_xor(binary_key_chunks[1], round_key_one[0]))
    round_key_one.append(bitwise_xor(binary_key_chunks[2], round_key_one[1]))
    round_key_one.append(bitwise_xor(binary_key_chunks[3], round_key_one[2]))

    round_key_two.append(
        bitwise_xor(
            bitwise_xor(
                round_key_one[0],
                bin(int(sub_nibbles_func_decrypted(round_key_one[3])[0], 16))[
                    2:
                ].zfill(4),
            ),
            RCON_2,
        )
    )
    round_key_two.append(bitwise_xor(round_key_one[1], round_key_two[0]))
    round_key_two.append(bitwise_xor(round_key_one[2], round_key_two[1]))
    round_key_two.append(bitwise_xor(round_key_one[3], round_key_two[2]))

    hex_value_one = "".join(round_key_one)
    hex_value_two = "".join(round_key_two)
    hex_values_one_hexa = hex(int(hex_value_one, 2))[2:].zfill(4)
    hex_values_two_hexa = hex(int(hex_value_two, 2))[2:].zfill(4)

    print(f"Round Key 1: {hex_values_one_hexa}")
    print(f"Round Key 2: {hex_values_two_hexa}")

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
