from enum import Enum, auto
import random

class Padding_Mode(Enum):
    Zeros = auto()
    ANSI_X_923 = auto()
    PKCS7 = auto()
    ISO_10126 = auto()
    
class PaddingAction:
    def __init__(self, padding_mode: Padding_Mode, block_size: int):
        if block_size <= 0:
            raise ValueError("Block size should be > 1")
        
        self._padding_mode = padding_mode
        self._block_size = block_size
        
        match self._padding_mode:
            case Padding_Mode.Zeros:
                self._padding_action = self._pad_zeros
            case Padding_Mode.ANSI_X_923:
                self._padding_action = self._pad_ansi_x_923
            case Padding_Mode.PKCS7:
                self._padding_action = self._pad_pkcs7
            case Padding_Mode.ISO_10126:
                self._padding_action = self._pad_iso_10126
            case _:
                raise ValueError(f"Unknown padding mode: {self._padding_mode}")
            
    def pad(self, value: bytes) -> bytes:
        return self._padding_action(value, unpad=False)
        
    def unpad(self, value: bytes) -> bytes:
        return self._padding_action(value, unpad=True)
    
    def _pad_len(self, n: int) -> int:
        bs = self._block_size
        pad = bs - (n % bs)
        return pad if pad != 0 else bs

    def _pad_zeros(self, value: bytes, *, unpad: bool) -> bytes:
        if unpad:
            if not value:
                return value
            bs = self._block_size
            i = len(value) - 1
            removed = 0
            while i >= 0 and value[i] == 0 and removed < bs:
                i -= 1
                removed += 1
            return value[:i+1]
        else:
            p = self._pad_len(len(value))
            return value + (b"\x00" * p)

    def _pad_ansi_x_923(self, value: bytes, *, unpad: bool) -> bytes:
        if unpad:
            bs = self._block_size
            pad_len = value[-1]
            return value[:-pad_len]
        else:
            p = self._pad_len(len(value))
            return value + (b"\x00" * (p - 1)) + bytes([p])

    def _pad_pkcs7(self, value: bytes, *, unpad: bool) -> bytes:
        if unpad:
            pad_len = value[-1]
            return value[:-pad_len]
        else:
            p = self._pad_len(len(value))
            return value + bytes([p]) * p
        
    def _pad_iso_10126(self, value: bytes, *, unpad: bool) -> bytes:
        if unpad:
            pad_len = value[-1]
            return value[:-pad_len]
        else:
            p = self._pad_len(len(value))
            if p == 1:
                return value + bytes([1])
            rnd = bytes(random.getrandbits(8) for _ in range(p - 1))
            return value + rnd + bytes([p])