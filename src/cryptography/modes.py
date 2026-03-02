from enum import Enum, auto

from .interfaces import ISymmetricBlockEncryption

class Cipher_Mode(Enum):
    ECB = auto()
    CBC = auto()
    PCBC = auto()
    CFB = auto()
    OFB = auto()
    CTR = auto()
    Random_Delta = auto()
    
        
class SymmetricBlockCipherAction(ISymmetricBlockEncryption):
    def __init__(
        self,
        cipher_mode: Cipher_Mode,
        init_vector: bytes,
        block_size: int,
        *args
    ) -> None:
        
        self._block_size = block_size
        self._key = None
        self._mode = cipher_mode
        self._encrypt_block = None # IsymmetricBlockENcryption
        self._decrypt_block = None
        #self._padding_mode = padding_mode
        self._iv = init_vector
        
        match self._mode:
            case Cipher_Mode.ECB:
                self._enc_mode = self._ecb_encrypt
                self._dec_mode = self._ecb_decrypt
            case Cipher_Mode.CBC:
                self._enc_mode = self._cbc_encrypt
                self._dec_mode = self._cbc_decrypt
            case Cipher_Mode.PCBC:
                self._enc_mode = self._pcbc_encrypt
                self._dec_mode = self._pcbc_decrypt
            case Cipher_Mode.CFB:
                self._enc_mode = self._cfb_encrypt
                self._dec_mode = self._cfb_decrypt
            case Cipher_Mode.OFB:
                self._enc_mode = self._ofb_xor
                self._dec_mode = self._ofb_xor
            case Cipher_Mode.CTR:
                self._enc_mode = self._ctr_xor
                self._dec_mode = self._ctr_xor
            case Cipher_Mode.Random_Delta:
                self._enc_mode = self._random_delta_xor
                self._dec_mode = self._random_delta_xor
            case _:
                raise ValueError(f"Unknown cipher mode: {self._mode}")

    def encrypt(self, value: bytes, result: bytearray) -> bytes:
        if self._key is None:
            raise RuntimeError
        result[:] = self._enc_mode(value)
        
    def decrypt(self, value: bytes, result: bytearray) -> bytes:
        if self._key is None:
            raise RuntimeError
        result[:] = self._dec_mode(value)
    
    @property
    def key(self): # геттер
        return "sosal"
    
    @key.setter
    def key(self, key: bytes):
        self._key = key
        
    def _ecb_encrypt(self, value: bytes):
        b = self._block_size
        output = bytearray(len(value))
        for i in range(0, len(value), b):
            output[i:i+b] = self._encrypt_block(value[i:i+b])
        return output
            
    def _ecb_decrypt(self, value: bytes):
        b = self._block_size
        output = bytearray(len(value))
        for i in range(0, len(value), b):
            output[i:i+b] = self._decrypt_block(value[i:i+b])
            
        return output
    
    def _cbc_encrypt(self, value: bytes):
        b = self._block_size
        output = bytearray(len(value))
        tmp_vec = self._iv
        for i in range(0, len(value), b):
            output[i:i+b] = self._encrypt_block(bytes(a ^ b for a, b in zip(value[i:i+b], tmp_vec)))
            tmp_vec = output[i:i+b]
            
        return output
    
    def _cbc_decrypt(self, value: bytes):
        b = self._block_size
        tmp_vec = self._iv
        output = bytearray(len(value))
        for i in range(0, len(value), b):
            tmp_decrypted = self._decrypt_block(value[i:i+b])
            
            output[i:i+b] = bytes(a ^ b for a, b in zip(tmp_decrypted, tmp_vec))
            
            tmp_vec = value[i:i+b]
            
        return output
    
    def _pcbc_encrypt(self, value: bytes):
        b = self._block_size
        output = bytearray(len(value))
        tmp_vec = bytearray(self._iv)
        for i in range(0, len(value), b):
            p = value[i:i+b]
            x = bytes(a ^ c for a, c in zip(p, tmp_vec))
            c = self._encrypt_block(x)
            output[i:i+b] = c
            tmp_vec[:] = bytes(a ^ c2 for a, c2 in zip(p, c))
        return output

    def _pcbc_decrypt(self, value: bytes):
        b = self._block_size
        output = bytearray(len(value))
        tmp_vec = bytearray(self._iv)
        for i in range(0, len(value), b):
            c = value[i:i+b]
            t = self._decrypt_block(c)
            p = bytes(a ^ c2 for a, c2 in zip(t, tmp_vec))
            output[i:i+b] = p
            tmp_vec[:] = bytes(a ^ c2 for a, c2 in zip(p, c))
        return output
    
    def _cfb_encrypt(self, value: bytes):
        b = self._block_size
        tmp_vec = bytearray(self._iv)
        output = bytearray(len(value))
        for i in range(0, len(value), b):
            encrypted_tmp_vec = self._encrypt_block(bytes(tmp_vec))
            c = bytes(a ^ k for a, k in zip(value[i:i+b], encrypted_tmp_vec))
            output[i:i+b] = c
            tmp_vec = c        
        return output

    def _cfb_decrypt(self, value: bytes):
        b = self._block_size
        tmp_vec = bytearray(self._iv)
        output = bytearray(len(value))
        for i in range(0, len(value), b):
            decrypted_tmp_vec = self._encrypt_block(bytes(tmp_vec))
            chunk = value[i:i+b]
            p = bytes(a ^ k for a, k in zip(chunk, decrypted_tmp_vec))
            output[i:i+len(chunk)] = p
            tmp_vec = value[i:i+b]         
        return output

    def _ofb_xor(self, value: bytes):
        b = self._block_size
        tmp_vec = bytearray(self._iv)
        output = bytearray(len(value))
        for i in range(0, len(value), b):
            tmp_vec[:] = self._encrypt_block(bytes(tmp_vec))
            output[i:i+b] = bytes(x ^ y for x, y in zip(tmp_vec, value[i:i+b]))
        return output
    
    def _ctr_xor(self, value: bytes):
        b = self._block_size
        output = bytearray(len(value))
        counter = bytearray(self._iv)
        for i in range(0, len(value), b):
            keystream = self._encrypt_block(bytes(counter))
            
            output[i:i+b] = bytes(a ^ k for a, k in zip(value[i:i+b], keystream[:b]))

            self._add_to_counter(counter, 1)

        return output

    def _add_to_counter(self, counter: bytearray, add: int) -> None:
        i = len(counter) - 1
        carry = add
        while i >= 0 and carry:
            val = counter[i] + (carry & 0xFF)
            counter[i] = val & 0xFF
            carry = val >> 8
            i -= 1
            
    def _random_delta_xor(self, value: bytes):
        b = self._block_size
        output = bytearray(len(value) + b)

        tmp_vec = bytearray(self._iv)

        rd_bytes = min(8, len(self._iv))
        delta = int.from_bytes(self._iv[-rd_bytes:], "big", signed=False)

        output[0:len(self._iv)] = self._encrypt_block(bytes(tmp_vec))

        out_off = len(self._iv)
        for i in range(0, len(value), b):
            keystream = self._encrypt_block(bytes(tmp_vec))
            output[out_off:out_off+b] = bytes(a ^ k for a, k in zip(value[i:i+b], keystream[:b]))
            out_off += b
            self._add_to_counter(tmp_vec, delta)

        return output
