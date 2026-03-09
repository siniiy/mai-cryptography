import os
from pathlib import Path
from typing import Optional

from .interfaces import ISymmetricBlockEncryption
from .modes import Cipher_Mode, SymmetricBlockCipherAction
from .paddings import Padding_Mode, PaddingAction

class FileCipher:
    def __init__(
        self,
        cipher: ISymmetricBlockEncryption,
        mode: Cipher_Mode,
        padding: Padding_Mode,
        iv: Optional[bytes] = None,
        block_size: int = 8
    ):
        if not isinstance(mode, Cipher_Mode):
            raise TypeError("mode must be a Cipher_Mode enum value")
        if not isinstance(padding, Padding_Mode):
            raise TypeError("padding must be a Padding_Mode enum value")
        
        self._cipher = cipher
        self._mode = mode
        self._padding_mode = padding
        self._block_size = block_size
        
        if iv is None:
            self._iv = os.urandom(self._block_size)
        else:
            if len(iv) != self._block_size:
                raise ValueError(f"IV must be {self._block_size} bytes")
            self._iv = iv
        
        self._padding_actor = PaddingAction(self._padding_mode, self._block_size)
        
        self._cipher_action = SymmetricBlockCipherAction(
            self._mode,
            self._iv,
            self._block_size
        )
        self._cipher_action._encrypt_block = self._encrypt_block
        self._cipher_action._decrypt_block = self._decrypt_block
        self._cipher_action._key = cipher.key
    
    def _encrypt_block(self, data: bytes) -> bytes:
        if len(data) != self._block_size:
            raise ValueError(f"Block must be {self._block_size} bytes")
        result = bytearray(self._block_size)
        self._cipher.encrypt(data, result)
        return bytes(result)
    
    def _decrypt_block(self, data: bytes) -> bytes:
        if len(data) != self._block_size:
            raise ValueError(f"Block must be {self._block_size} bytes")
        result = bytearray(self._block_size)
        self._cipher.decrypt(data, result)
        return bytes(result)
    
    @property
    def key(self):
        return self._cipher.key
    
    @key.setter
    def key(self, value: bytes):
        self._cipher.key = value
        self._cipher_action._key = value
    
    @property
    def iv(self) -> bytes:
        return self._iv
    
    def _is_padding_needed(self, data_length: int) -> bool:
        if self._mode not in {
            Cipher_Mode.ECB,
            Cipher_Mode.CBC,
            Cipher_Mode.PCBC
        }:
            return False
        
        if data_length % self._block_size == 0:
            if self._padding_mode in {
                Padding_Mode.PKCS7,
                Padding_Mode.ANSI_X_923,
                Padding_Mode.ISO_10126
            }:
                return True
            return False
        return True
    
    def encrypt_bytes(self, data: bytes) -> bytes:
        if self._is_padding_needed(len(data)):
            data = self._padding_actor.pad(data)
        
        result = bytearray(len(data))
        self._cipher_action.encrypt(data, result)
        return bytes(result)
    
    def decrypt_bytes(self, data: bytes) -> bytes:
        if self._mode in {
            Cipher_Mode.ECB,
            Cipher_Mode.CBC,
            Cipher_Mode.PCBC
        }:
            if len(data) % self._block_size != 0:
                raise ValueError(f"Encrypted data length must be a multiple of {self._block_size} bytes")
        
        result = bytearray(len(data))
        self._cipher_action.decrypt(data, result)
        
        if self._mode in {
            Cipher_Mode.ECB,
            Cipher_Mode.CBC,
            Cipher_Mode.PCBC
        }:
            result = self._padding_actor.unpad(bytes(result))
        
        return result
    
    def encrypt_file(self, input_path: Path, output_path: Path) -> None:
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        if not input_path.is_file():
            raise ValueError(f"Input path is not a file: {input_path}")
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = input_path.read_bytes()
        encrypted = self.encrypt_bytes(data)
        output_path.write_bytes(encrypted)
    
    def decrypt_file(self, input_path: Path, output_path: Path) -> None:
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        if not input_path.is_file():
            raise ValueError(f"Input path is not a file: {input_path}")
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = input_path.read_bytes()
        decrypted = self.decrypt_bytes(data)
        output_path.write_bytes(decrypted)
