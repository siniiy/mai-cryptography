from typing import Callable, List

from feistel_net import FeistelNet
from interfaces import (
        IRoundKeyGen,
        IRoundKeyEncryption,
        ISymmetricBlockEncryption
    )

from utils import (
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

class DesRoundKeyEncryption(IRoundKeyEncryption):
    @staticmethod
    def encrypt(value: bytes, round_key: bytes) -> bytes:
        ...


class DesRoundKeysGen(IRoundKeyGen):
    @staticmethod
    def expand_key(self, input_key: bytes) -> List[bytes]:
        first_permutation = int.from_bytes(
            permutate_bits(input_key, DES_PC1, least_bit_first=False, first_bit_index=1),
            "big"
        ) #56 bytes
        
        a = bytes()
        
        keys = []
        C, D = first_permutation >> 28, first_permutation & ((1 << 28) - 1)
        for i in range(16):
            C = self._left_shift(C, DES_SHIFTS[i]) 
            D = self._left_shift(D, DES_SHIFTS[i])
            
            keys.append(self._permutation_2(C, D))
            
        return keys
        
    @staticmethod
    def _permutation_2(C: bytes, D: bytes) -> bytes: # 48 bits
        value = C + D
        return bytes(
            permutate_bits(value, DES_PC2, least_bit_first=False, first_bit_index=1)
        )

    @staticmethod
    def _left_shift(value: bytes, num: int) -> bytes:
        """cycle shift to the left"""
        bits_of_value = bytes_to_bits(value, least_bit_first=False)
        
        result = bits_of_value[num::] + bits_of_value[:num:]
        
        return bits_to_bytes(result, least_bit_first=False)
        
        
class Des:
    """
    Implementation of Data Encryption Standard symmetrical 
    encryption algorithm  
    """
    def __init__(self, feistel_net: FeistelNet) -> None:
        self._feisetl_net = FeistelNet(DesRoundKeysGen, DesRoundKeyEncryption)
        self._feisetl_net._n_rounds = 16 
        self._feisetl_net.block_size = 8 #bytes
    
    def encrypt(self, value: bytes) -> bytes:
        ...
    
    def decrypt(self, value: bytes) -> bytes:
        ...
    
    def _init_permutation(self, value: bytes, inverse=False):
        ...

if __name__ == '__main'