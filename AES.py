import numpy as np
from BitVector import BitVector


def xor_hex_string_with_int(a: str, b: int):
    return hex(int(a, 16) ^ b)


def xor_hex_string_with_xor_hex_string(a: str, b: str):
    return hex(int(a, 16) ^ int(b, 16))


def s_box_substitution(hex_str: str):
    if int(hex_str, 16) < 16:
        idx = int(hex_str, 16)
    else:
        idx = int(hex_str[-2], 16) * 16 + int(hex_str[-1], 16)
    return hex(AES.S_BOX[idx])


def inv_s_box_substitution(hex_str: str):
    if int(hex_str, 16) < 16:
        idx = int(hex_str, 16)
    else:
        idx = int(hex_str[-2], 16) * 16 + int(hex_str[-1], 16)
    return hex(AES.INV_S_BOX[idx])


def matrix4x4_gf_multiplication(mat_a_bs, mat_b_hex):
    output = mat_b_hex.copy()
    for i in range(4):
        for j in range(4):
            row = mat_a_bs[i]
            col = mat_b_hex[:, j]
            temp_val = 0
            for k in range(4):
                temp_val ^= row[k].gf_multiply_modular(BitVector(hexstring=col[k][2:]),
                                                       BitVector(bitstring='100011011'), 8).int_val()
            output[i][j] = hex(temp_val)
    return output


class AES:
    S_BOX = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )

    INV_S_BOX = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    )

    MIXER = [
        [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
        [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
        [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
        [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
    ]

    INV_MIXER = [
        [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
        [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
        [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
        [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
    ]

    ROUND_CONST = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    def __init__(self, key: str) -> None:
        super().__init__()
        self.key_plaintext = key[:16] if len(key) > 16 else key + '0' * (16 - len(key))
        self.round_key = []
        self.round_key.append(np.array([
            hex(ord(char)) for char in key
        ]).reshape((4, 4), order='F'))
        for round_no in range(10):
            self.round_key.append(self.generate_round_key(round_no))

    def generate_round_key(self, round_no: int):
        temp_round_key = self.round_key[round_no].copy()
        temp_round_sub_key = temp_round_key[:, -1].copy()
        # rotation
        temp_round_sub_key = np.roll(temp_round_sub_key, -1)
        # substitution
        for i in range(len(temp_round_sub_key)):
            temp_round_sub_key[i] = s_box_substitution(temp_round_sub_key[i])
        # add round constant
        temp_round_sub_key[0] = xor_hex_string_with_int(temp_round_sub_key[0], AES.ROUND_CONST[round_no])

        for i in range(4):
            temp_round_key[i, 0] = xor_hex_string_with_xor_hex_string(temp_round_key[i, 0], temp_round_sub_key[i])
        for col_no in range(1, 4):
            for row_no in range(4):
                temp_round_key[row_no, col_no] = xor_hex_string_with_xor_hex_string(temp_round_key[row_no, col_no - 1],
                                                                                    temp_round_key[row_no, col_no])
        return temp_round_key

    def add_round_key(self, round_key_no: int, state_matrix):
        for i in range(4):
            for j in range(4):
                state_matrix[i][j] = xor_hex_string_with_xor_hex_string(
                    state_matrix[i][j], self.round_key[round_key_no][i][j]
                )

    def encrypt(self, plain_text: str) -> str:
        updated_plain_text = plain_text[:16] if len(plain_text) > 16 else plain_text + ' ' * (16 - len(plain_text))
        state_matrix = np.array([
            hex(ord(char)) for char in updated_plain_text
        ]).reshape((4, 4), order='F')

        # Round 0
        self.add_round_key(0, state_matrix)
        # Round 1-10
        for round_no in range(1, 11):
            # Substitution
            for i in range(4):
                for j in range(4):
                    state_matrix[i][j] = s_box_substitution(state_matrix[i][j])
            # Shift Row
            for i in range(1, 4):
                state_matrix[i, :] = np.roll(state_matrix[i, :], -i)
            # Mix Column (For round 1-9)
            if round_no != 10:
                state_matrix = matrix4x4_gf_multiplication(AES.MIXER, state_matrix)
            # Add Round Key
            self.add_round_key(round_no, state_matrix)

        cipher_text = ""
        for col in range(4):
            for row in range(4):
                cipher_text += (state_matrix[row][col] + ' ')
        return cipher_text.strip()

    def decrypt(self, cipher_text: str) -> str:
        cipher_state_matrix = np.array(
            cipher_text.split(" ")
        ).reshape((4, 4), order='F')
        # Round 0-9
        for round_no in range(0, 10):
            # Add Round Key
            self.add_round_key(10 - round_no, cipher_state_matrix)
            # Mix Column (For round 1-9)
            if round_no != 0:
                cipher_state_matrix = matrix4x4_gf_multiplication(AES.INV_MIXER, cipher_state_matrix)
            # Shift Row
            for i in range(1, 4):
                cipher_state_matrix[i, :] = np.roll(cipher_state_matrix[i, :], i)
            # Substitution
            for i in range(4):
                for j in range(4):
                    cipher_state_matrix[i][j] = inv_s_box_substitution(cipher_state_matrix[i][j])
        # Round 10
        self.add_round_key(0, cipher_state_matrix)

        plain_text = ""
        for col in range(4):
            for row in range(4):
                plain_text += chr(int(cipher_state_matrix[row][col], 16))
        return plain_text


if __name__ == '__main__':
    x = 'Thats my Kung Fu'
    aes = AES(x)
    pt = "Two One Nine Two"
    ct = aes.encrypt(pt)
    dpt = aes.decrypt(ct)
