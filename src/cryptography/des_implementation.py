from typing import Callable, List

from .feistel_net import FeistelNet
from .interfaces import (
        IRoundKeyGen,
        IRoundKeyEncryption,
        ISymmetricBlockEncryption
    )

from .utils import (
        permutate_bits,
        bits_to_bytes,
        bytes_to_bits
    )
IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

DES_PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

DES_E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
]

DES_P = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
]

DES_S = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

class DesRoundKeyEncryption(IRoundKeyEncryption):
    @staticmethod
    def encrypt(value: bytes, round_key: bytes) -> bytes:
        # Expand 32-bit R to 48-bit using E table
        expanded = permutate_bits(value, DES_E, least_bit_first=False)
        
        # XOR with round key
        xor_result = bytes(a ^ b for a, b in zip(expanded, round_key))
        
        # Convert to bits for S-box processing
        xor_bits = bytes_to_bits(xor_result, least_bit_first=False)
        
        # Apply S-boxes (8 groups of 6 bits -> 8 groups of 4 bits)
        sbox_output_bits = []
        for i in range(8):
            # Extract 6 bits for this S-box
            start_bit = i * 6
            six_bits = xor_bits[start_bit:start_bit + 6]
            
            # S-box lookup: row = bits[0]<<1 | bits[5], col = bits[1:5]
            # Note: six_bits[0] is bit 1, six_bits[5] is bit 6 (1-based)
            row = (six_bits[0] << 1) | six_bits[5]
            col = (six_bits[1] << 3) | (six_bits[2] << 2) | (six_bits[3] << 1) | six_bits[4]
            
            # Get 4-bit output from S-box
            sbox_value = DES_S[i][row][col]
            
            # Convert to 4 bits (MSB first)
            sbox_output_bits.extend([(sbox_value >> 3) & 1, (sbox_value >> 2) & 1,
                                   (sbox_value >> 1) & 1, sbox_value & 1])
        
        # Convert S-box output to bytes
        sbox_output_bytes = bits_to_bytes(sbox_output_bits, least_bit_first=False)
        
        # Apply P-permutation
        return permutate_bits(sbox_output_bytes, DES_P, least_bit_first=False)


class DesRoundKeysGen(IRoundKeyGen):
    @staticmethod
    def expand_key(input_key: bytes) -> List[bytes]:
        first_permutation = int.from_bytes(
            permutate_bits(input_key, DES_PC1, least_bit_first=False),
            "big"
        ) #56 bits
        
        keys = []
        C, D = first_permutation >> 28, first_permutation & ((1 << 28) - 1)
        
        for i in range(16):
            C = DesRoundKeysGen._left_shift(C, DES_SHIFTS[i])
            D = DesRoundKeysGen._left_shift(D, DES_SHIFTS[i])
            
            key = DesRoundKeysGen._permutation_2(C, D)
            keys.append(key)
            
        return keys
        
    @staticmethod
    def _permutation_2(C: int, D: int) -> bytes: # 48 bits
        # Combine C and D into 56-bit value
        combined = (C << 28) | D
        combined_bytes = combined.to_bytes(7, 'big')
        return permutate_bits(combined_bytes, DES_PC2, least_bit_first=False)

    @staticmethod
    def _left_shift(value: int, num: int) -> int:
        """cycle shift to the left for 28-bit values"""
        mask = (1 << 28) - 1
        value &= mask
        return ((value << num) | (value >> (28 - num))) & mask
        
        
class Des(ISymmetricBlockEncryption):
    """
    Implementation of Data Encryption Standard symmetrical
    encryption algorithm
    """
    def __init__(self) -> None:
        self._feistel_net = FeistelNet(DesRoundKeysGen, DesRoundKeyEncryption)
        self._feistel_net._n_rounds = 16
        self._feistel_net.block_size = 8 #bytes
        self._key = None
    
    def encrypt(self, value: bytes, result: bytearray) -> bytes:
        if len(value) != 8:
            raise ValueError("DES operates on 8-byte blocks")
            
        # Initial permutation
        permuted = self._init_permutation(value, inverse=False)
        
        # 16 rounds of Feistel
        encrypted = self._feistel_net.encrypt(permuted)
        
        # Final permutation
        final = self._init_permutation(encrypted, inverse=True)
        
        result[:] = final
        return final
    
    def decrypt(self, value: bytes, result: bytearray) -> bytes:
        if len(value) != 8:
            raise ValueError("DES operates on 8-byte blocks")
            
        # Initial permutation
        permuted = self._init_permutation(value, inverse=False)
        
        # 16 rounds of Feistel (reversed keys)
        decrypted = self._feistel_net.decrypt(permuted)
        
        # Final permutation
        final = self._init_permutation(decrypted, inverse=True)
        
        result[:] = final
        return final
    
    def _init_permutation(self, value: bytes, inverse=False):
        if inverse:
            return permutate_bits(value, FP_TABLE, least_bit_first=False)
        else:
            return permutate_bits(value, IP_TABLE, least_bit_first=False)
    
    @property
    def key(self):
        return self._key
    
    @key.setter
    def key(self, value: bytes):
        if len(value) != 8:
            raise ValueError("DES key must be 8 bytes")
        self._key = value
        self._feistel_net.key = value

if __name__ == '__main__':
    pass