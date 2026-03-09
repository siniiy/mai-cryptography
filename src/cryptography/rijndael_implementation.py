from typing import List, Optional

from .interfaces import ISymmetricBlockEncryption
from .gf2n_service import GF2NService, ReductionPolynomialError, AES_MODULUS


RIJNDAEL_PARAMETERS = {
    (16, 16): {'nb': 4, 'nk': 4, 'nr': 10},
    (16, 24): {'nb': 4, 'nk': 6, 'nr': 12},
    (16, 32): {'nb': 4, 'nk': 8, 'nr': 14},
    (24, 16): {'nb': 6, 'nk': 4, 'nr': 12},
    (24, 24): {'nb': 6, 'nk': 6, 'nr': 12},
    (24, 32): {'nb': 6, 'nk': 8, 'nr': 14},
    (32, 16): {'nb': 8, 'nk': 4, 'nr': 14},
    (32, 24): {'nb': 8, 'nk': 6, 'nr': 14},
    (32, 32): {'nb': 8, 'nk': 8, 'nr': 14},
}


class Rijndael(ISymmetricBlockEncryption):
    
    def __init__(self, block_size: int = 16, modulus: int = AES_MODULUS):
        if block_size not in (16, 24, 32):
            raise ValueError(f"Block size must be 16, 24, or 32 bytes, got {block_size}")
        
        if not GF2NService.is_irreducible(modulus):
            raise ReductionPolynomialError(
                f"Modulus 0x{modulus:03X} is not an irreducible polynomial of degree 8"
            )
        
        self._block_size = block_size
        self._modulus = modulus
        self._key = None
        self._key_size = None
        self._round_keys = None
        self._nr = None
        self._nb = None
        self._nk = None
        
        self._sbox: Optional[List[int]] = None
        self._inv_sbox: Optional[List[int]] = None
        
        self._init_sboxes()
    
    def _init_sboxes(self):
        self._sbox = self._get_standard_sbox()
        self._inv_sbox = self._compute_inv_sbox()
    
    def _get_standard_sbox(self) -> List[int]:
        return list(bytes([
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
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]))
        
        for i in range(256):
            inv = GF2NService.inverse_by_exponentiation(i, self._modulus)
            
            b = inv
            result = 0
            
            result ^= (GF2NService.add((inv >> 0) & 1, (inv >> 4) & 1))
            result ^= GF2NService.add((inv >> 5) & 1, (inv >> 6) & 1)
            result ^= GF2NService.add((inv >> 7) & 1, 1)
            b0 = result & 1
            
            result = 0
            result ^= (GF2NService.add((inv >> 0) & 1, (inv >> 1) & 1))
            result ^= GF2NService.add((inv >> 5) & 1, (inv >> 7) & 1)
            result ^= 1
            b1 = result & 1
            
            result = 0
            result ^= (GF2NService.add((inv >> 0) & 1, (inv >> 1) & 1))
            result ^= GF2NService.add((inv >> 2) & 1, (inv >> 6) & 1)
            result ^= GF2NService.add((inv >> 7) & 1, 0)
            b2 = result & 1
            
            result = 0
            result ^= (GF2NService.add((inv >> 0) & 1, (inv >> 1) & 1))
            result ^= GF2NService.add((inv >> 2) & 1, (inv >> 3) & 1)
            result ^= GF2NService.add((inv >> 7) & 1, 0)
            b3 = result & 1
            
            result = 0
            result ^= (GF2NService.add((inv >> 0) & 1, (inv >> 1) & 1))
            result ^= GF2NService.add((inv >> 2) & 1, (inv >> 3) & 1)
            result ^= GF2NService.add((inv >> 4) & 1, 0)
            b4 = result & 1
            
            result = 0
            result ^= (GF2NService.add((inv >> 1) & 1, (inv >> 2) & 1))
            result ^= GF2NService.add((inv >> 3) & 1, (inv >> 4) & 1)
            result ^= GF2NService.add((inv >> 5) & 1, 1)
            b5 = result & 1
            
            result = 0
            result ^= (GF2NService.add((inv >> 2) & 1, (inv >> 3) & 1))
            result ^= GF2NService.add((inv >> 4) & 1, (inv >> 5) & 1)
            result ^= GF2NService.add((inv >> 6) & 1, 1)
            b6 = result & 1
            
            result = 0
            result ^= (GF2NService.add((inv >> 3) & 1, (inv >> 4) & 1))
            result ^= GF2NService.add((inv >> 5) & 1, (inv >> 6) & 1)
            result ^= GF2NService.add((inv >> 7) & 1, 0)
            b7 = result & 1
            
            sbox[i] = (b7 << 7) | (b6 << 6) | (b5 << 5) | (b4 << 4) | (b3 << 3) | (b2 << 2) | (b1 << 1) | b0
        
        return sbox
    
    def _compute_inv_sbox(self) -> List[int]:
        inv_sbox = [0] * 256
        for i in range(256):
            inv_sbox[self._sbox[i]] = i
        return inv_sbox
    
    @property
    def key(self):
        return self._key
    
    @key.setter
    def key(self, key: bytes):
        key_len = len(key)
        
        if key_len not in (16, 24, 32):
            raise ValueError(f"Key must be 16, 24, or 32 bytes, got {key_len}")
        
        params = RIJNDAEL_PARAMETERS.get((self._block_size, key_len))
        if params is None:
            raise ValueError(
                f"Invalid combination: block_size={self._block_size}, key_size={key_len}"
            )
        
        self._key = key
        self._key_size = key_len
        self._nb = params['nb']
        self._nk = params['nk']
        self._nr = params['nr']
        
        self._round_keys = self._expand_key(key)
    
    def _expand_key(self, key: bytes) -> List[List[int]]:
        w = []
        
        for i in range(self._nk):
            word = list(key[4*i:4*i+4])
            w.append(word)
        
        rcon = self._compute_rcon()
        
        for i in range(self._nk, self._nb * (self._nr + 1)):
            temp = w[i - 1].copy()
            
            if i % self._nk == 0:
                temp = self._rot_word(temp)
                temp = self._sub_word(temp)
                temp[0] ^= rcon[i // self._nk - 1]
            elif self._nk > 6 and i % self._nk == 4:
                temp = self._sub_word(temp)
            
            new_word = []
            for j in range(4):
                new_word.append(w[i - self._nk][j] ^ temp[j])
            w.append(new_word)
        
        return w
    
    def _compute_rcon(self) -> List[int]:
        rcon = []
        max_rcon = max(10, self._nr)
        
        c = 1
        for _ in range(max_rcon):
            rcon.append(c)
            c = GF2NService.xtime(c, self._modulus)
        
        return rcon
    
    def _rot_word(self, word: List[int]) -> List[int]:
        return [word[1], word[2], word[3], word[0]]
    
    def _sub_word(self, word: List[int]) -> List[int]:
        return [self._sbox[b] for b in word]
    
    def encrypt(self, value: bytes, result: bytearray):
        if self._key is None:
            raise RuntimeError("Key must be set before encryption")
        
        if len(value) != self._block_size:
            raise ValueError(f"Input must be {self._block_size} bytes, got {len(value)}")
        
        if len(result) != self._block_size:
            raise ValueError(f"Result must be {self._block_size} bytes, got {len(result)}")
        
        state = self._bytes_to_state(value)
        
        state = self._add_round_key(state, 0)
        
        for round_num in range(1, self._nr):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, round_num)
        
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self._nr)
        
        output = self._state_to_bytes(state)
        result[:] = output
    
    def decrypt(self, value: bytes, result: bytearray):
        if self._key is None:
            raise RuntimeError("Key must be set before decryption")
        
        if len(value) != self._block_size:
            raise ValueError(f"Input must be {self._block_size} bytes, got {len(value)}")
        
        if len(result) != self._block_size:
            raise ValueError(f"Result must be {self._block_size} bytes, got {len(result)}")
        
        state = self._bytes_to_state(value)
        
        state = self._add_round_key(state, self._nr)
        
        for round_num in range(self._nr - 1, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, round_num)
            state = self._inv_mix_columns(state)
        
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, 0)
        
        output = self._state_to_bytes(state)
        result[:] = output
    
    def _bytes_to_state(self, data: bytes) -> List[List[int]]:
        state = [[0] * self._nb for _ in range(4)]
        
        for c in range(self._nb):
            for r in range(4):
                state[r][c] = data[r + 4 * c]
        
        return state
    
    def _state_to_bytes(self, state: List[List[int]]) -> bytes:
        output = bytearray()
        
        for c in range(self._nb):
            for r in range(4):
                output.append(state[r][c])
        
        return bytes(output)
    
    def _add_round_key(self, state: List[List[int]], round_num: int) -> List[List[int]]:
        for c in range(self._nb):
            word_idx = round_num * 4 + c
            if word_idx < len(self._round_keys):
                word = self._round_keys[word_idx]
                for r in range(4):
                    state[r][c] ^= word[r]
        
        return state
    
    def _sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        for c in range(self._nb):
            for r in range(4):
                state[r][c] = self._sbox[state[r][c]]
        return state
    
    def _inv_sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        for c in range(self._nb):
            for r in range(4):
                state[r][c] = self._inv_sbox[state[r][c]]
        return state
    
    def _shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        new_state = [[0] * self._nb for _ in range(4)]
        
        for r in range(4):
            for c in range(self._nb):
                new_state[r][c] = state[r][(c + r) % self._nb]
        
        return new_state
    
    def _inv_shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        new_state = [[0] * self._nb for _ in range(4)]
        
        for r in range(4):
            for c in range(self._nb):
                new_state[r][c] = state[r][(c - r) % self._nb]
        
        return new_state
    
    def _mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        new_state = [[0] * self._nb for _ in range(4)]
        
        for c in range(self._nb):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
            
            new_state[0][c] = (
                GF2NService.multiply(0x02, s0, self._modulus) ^
                GF2NService.multiply(0x03, s1, self._modulus) ^
                s2 ^ s3
            )
            new_state[1][c] = (
                s0 ^
                GF2NService.multiply(0x02, s1, self._modulus) ^
                GF2NService.multiply(0x03, s2, self._modulus) ^
                s3
            )
            new_state[2][c] = (
                s0 ^ s1 ^
                GF2NService.multiply(0x02, s2, self._modulus) ^
                GF2NService.multiply(0x03, s3, self._modulus)
            )
            new_state[3][c] = (
                GF2NService.multiply(0x03, s0, self._modulus) ^
                s1 ^ s2 ^
                GF2NService.multiply(0x02, s3, self._modulus)
            )
        
        return new_state
    
    def _inv_mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        new_state = [[0] * self._nb for _ in range(4)]
        
        for c in range(self._nb):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
            
            new_state[0][c] = (
                GF2NService.multiply(0x0e, s0, self._modulus) ^
                GF2NService.multiply(0x0b, s1, self._modulus) ^
                GF2NService.multiply(0x0d, s2, self._modulus) ^
                GF2NService.multiply(0x09, s3, self._modulus)
            )
            new_state[1][c] = (
                GF2NService.multiply(0x09, s0, self._modulus) ^
                GF2NService.multiply(0x0e, s1, self._modulus) ^
                GF2NService.multiply(0x0b, s2, self._modulus) ^
                GF2NService.multiply(0x0d, s3, self._modulus)
            )
            new_state[2][c] = (
                GF2NService.multiply(0x0d, s0, self._modulus) ^
                GF2NService.multiply(0x09, s1, self._modulus) ^
                GF2NService.multiply(0x0e, s2, self._modulus) ^
                GF2NService.multiply(0x0b, s3, self._modulus)
            )
            new_state[3][c] = (
                GF2NService.multiply(0x0b, s0, self._modulus) ^
                GF2NService.multiply(0x0d, s1, self._modulus) ^
                GF2NService.multiply(0x09, s2, self._modulus) ^
                GF2NService.multiply(0x0e, s3, self._modulus)
            )
        
        return new_state
    
    @property
    def block_size(self) -> int:
        return self._block_size
    
    @property
    def modulus(self) -> int:
        return self._modulus
    
    @property
    def num_rounds(self) -> int:
        return self._nr
