#!/usr/bin/env python3
"""
DEAL Demo Script
Tests the DEAL implementation with various test vectors and modes
"""

import sys
import os
from pathlib import Path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from cryptography.deal_implementation import Deal
from cryptography.demonstrator import FileCipher
from cryptography.modes import Cipher_Mode
from cryptography.paddings import Padding_Mode


def test_deal_vectors():
    """Test DEAL with known test vectors"""
    
    test_cases = [
        {
            'name': '128-bit key, zero plaintext',
            'key': bytes.fromhex('00000000000000000000000000000000'),
            'plaintext': bytes.fromhex('00000000000000000000000000000000'),
            'expected_roundtrip': True
        },
        {
            'name': '128-bit key, all ones',
            'key': bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'),
            'plaintext': bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'),
            'expected_roundtrip': True
        },
        {
            'name': '192-bit key, mixed values',
            'key': bytes.fromhex('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF'),
            'plaintext': bytes.fromhex('0123456789ABCDEF0123456789ABCDEF'),
            'expected_roundtrip': True
        },
        {
            'name': '256-bit key, mixed values',
            'key': bytes.fromhex('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF'),
            'plaintext': bytes.fromhex('FEDCBA9876543210FEDCBA9876543210'),
            'expected_roundtrip': True
        },
        {
            'name': '128-bit key, sequential bytes',
            'key': bytes.fromhex('11111111111111112222222222222222'),
            'plaintext': bytes.fromhex('000102030405060708090A0B0C0D0E0F'),
            'expected_roundtrip': True
        },
    ]
    
    deal = Deal()
    
    print("DEAL Test Vectors")
    print("=" * 60)
    
    all_passed = True
    
    for i, test in enumerate(test_cases, 1):
        print(f"\nTest Case {i}: {test['name']}")
        print(f"Key:        {test['key'].hex().upper()}")
        print(f"Plaintext:  {test['plaintext'].hex().upper()}")
        
        try:
            deal.key = test['key']
            
            encrypted_result = bytearray(16)
            deal.encrypt(test['plaintext'], encrypted_result)
            encrypted = bytes(encrypted_result)
            
            print(f"Encrypted:  {encrypted.hex().upper()}")
            
            decrypted_result = bytearray(16)
            deal.decrypt(encrypted, decrypted_result)
            decrypted = bytes(decrypted_result)
            
            print(f"Decrypted:  {decrypted.hex().upper()}")
            
            if test['expected_roundtrip']:
                if decrypted == test['plaintext']:
                    print("✓ PASS - Round-trip successful")
                else:
                    print("✗ FAIL - Round-trip failed")
                    print(f"  Expected: {test['plaintext'].hex()}")
                    print(f"  Got:      {decrypted.hex()}")
                    all_passed = False
            else:
                print("✓ PASS - No exception raised")
                
        except Exception as e:
            print(f"✗ FAIL - Exception: {e}")
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("All tests PASSED! ✓")
    else:
        print("Some tests FAILED! ✗")
    
    return all_passed


def test_round_trip():
    """Test encrypt/decrypt round-trip with random data"""
    import random
    
    print("\nRound-trip Test")
    print("=" * 40)
    
    deal = Deal()
    
    key_sizes = [16, 24, 32]
    
    all_passed = True
    
    for key_size in key_sizes:
        print(f"\nTesting with {key_size * 8}-bit key:")
        
        for i in range(3):
            key = bytes([random.randint(0, 255) for _ in range(key_size)])
            plaintext = bytes([random.randint(0, 255) for _ in range(16)])
            
            deal.key = key
            
            encrypted_result = bytearray(16)
            deal.encrypt(plaintext, encrypted_result)
            encrypted = bytes(encrypted_result)
            
            decrypted_result = bytearray(16)
            deal.decrypt(encrypted, decrypted_result)
            decrypted = bytes(decrypted_result)
            
            if plaintext == decrypted:
                print(f"  Test {i+1}: ✓ PASS")
            else:
                print(f"  Test {i+1}: ✗ FAIL")
                print(f"    Original:  {plaintext.hex()}")
                print(f"    Decrypted: {decrypted.hex()}")
                all_passed = False
    
    if all_passed:
        print("\nAll round-trip tests PASSED! ✓")
    else:
        print("\nSome round-trip tests FAILED! ✗")
    
    return all_passed


def test_file_encryption():
    """Test file encryption/decryption with DEAL"""
    print("\nFile Encryption Test")
    print("=" * 60)
    
    project_root = Path(__file__).parent.parent
    input_file = project_root / "data" / "hamster.png"
    output_dir = project_root / "data" / "output"
    encrypted_file = output_dir / "hamster_deal_encrypted.bin"
    decrypted_file = output_dir / "hamster_deal_decrypted.png"
    
    if not input_file.exists():
        print(f"⚠ Test file not found: {input_file}")
        return False
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    key_128 = bytes.fromhex('0123456789ABCDEF0123456789ABCDEF')
    key_192 = bytes.fromhex('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF')
    key_256 = bytes.fromhex('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF')
    iv = bytes.fromhex('1234567890ABCDEF1234567890ABCDEF')
    
    test_configs = [
        ("128-bit key, ECB with PKCS7", key_128, Cipher_Mode.ECB, Padding_Mode.PKCS7),
        ("128-bit key, CBC with PKCS7", key_128, Cipher_Mode.CBC, Padding_Mode.PKCS7),
        ("192-bit key, CBC with PKCS7", key_192, Cipher_Mode.CBC, Padding_Mode.PKCS7),
        ("256-bit key, CBC with PKCS7", key_256, Cipher_Mode.CBC, Padding_Mode.PKCS7),
        ("128-bit key, PCBC with ANSI_X_923", key_128, Cipher_Mode.PCBC, Padding_Mode.ANSI_X_923),
        ("128-bit key, CFB (no padding)", key_128, Cipher_Mode.CFB, Padding_Mode.Zeros),
        ("128-bit key, OFB (no padding)", key_128, Cipher_Mode.OFB, Padding_Mode.Zeros),
        ("128-bit key, CTR (no padding)", key_128, Cipher_Mode.CTR, Padding_Mode.Zeros),
    ]
    
    all_passed = True
    original_data = input_file.read_bytes()
    
    for name, key, mode, padding in test_configs:
        print(f"\nTesting: {name}")
        
        try:
            deal = Deal()
            cipher = FileCipher(deal, mode, padding, iv, block_size=16)
            cipher.key = key
            
            cipher.encrypt_file(input_file, encrypted_file)
            
            cipher2 = FileCipher(Deal(), mode, padding, iv, block_size=16)
            cipher2.key = key
            cipher2.decrypt_file(encrypted_file, decrypted_file)
            
            decrypted_data = decrypted_file.read_bytes()
            
            if original_data == decrypted_data:
                print(f"  ✓ PASS - File integrity preserved")
                print(f"  Original size: {len(original_data)} bytes")
                print(f"  Encrypted size: {encrypted_file.stat().st_size} bytes")
            else:
                print(f"  ✗ FAIL - File corrupted")
                print(f"  Original size: {len(original_data)} bytes")
                print(f"  Decrypted size: {len(decrypted_data)} bytes")
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ FAIL - Exception: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False
    
    if all_passed:
        print("\n✓ All file encryption tests PASSED!")
    else:
        print("\n✗ Some file encryption tests FAILED!")
    
    return all_passed


def test_bytes_encryption():
    """Test bytes encryption/decryption with different modes"""
    print("\nBytes Encryption Test")
    print("=" * 60)
    
    key_128 = bytes.fromhex('FEDCBA9876543210FEDCBA9876543210')
    key_192 = bytes.fromhex('FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210')
    key_256 = bytes.fromhex('FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210')
    iv = bytes.fromhex('0F1E2D3C4B5A69780F1E2D3C4B5A6978')
    
    test_data = b"Hello, DEAL encryption! This is a test message for the 128-bit block cipher."
    
    test_configs = [
        ("128-bit key, ECB + PKCS7", key_128, Cipher_Mode.ECB, Padding_Mode.PKCS7),
        ("128-bit key, CBC + PKCS7", key_128, Cipher_Mode.CBC, Padding_Mode.PKCS7),
        ("192-bit key, CBC + PKCS7", key_192, Cipher_Mode.CBC, Padding_Mode.PKCS7),
        ("256-bit key, CBC + PKCS7", key_256, Cipher_Mode.CBC, Padding_Mode.PKCS7),
        ("128-bit key, OFB", key_128, Cipher_Mode.OFB, Padding_Mode.Zeros),
        ("128-bit key, CTR", key_128, Cipher_Mode.CTR, Padding_Mode.Zeros),
    ]
    
    all_passed = True
    
    for name, key, mode, padding in test_configs:
        print(f"\nTesting: {name}")
        
        try:
            deal = Deal()
            cipher = FileCipher(deal, mode, padding, iv, block_size=16)
            cipher.key = key
            
            encrypted = cipher.encrypt_bytes(test_data)
            decrypted = cipher.decrypt_bytes(encrypted)
            
            if test_data == decrypted:
                print(f"  ✓ PASS")
                print(f"  Original: {test_data[:40]}...")
                print(f"  Encrypted length: {len(encrypted)} bytes")
            else:
                print(f"  ✗ FAIL - Data mismatch")
                print(f"  Expected: {test_data}")
                print(f"  Got: {decrypted}")
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ FAIL - Exception: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False
    
    return all_passed


def test_key_validation():
    """Test key validation"""
    print("\nKey Validation Test")
    print("=" * 40)
    
    deal = Deal()
    
    valid_keys = [
        (16, "128-bit key"),
        (24, "192-bit key"),
        (32, "256-bit key"),
    ]
    
    invalid_keys = [
        (8, "64-bit key (too short)"),
        (12, "96-bit key (invalid)"),
        (40, "320-bit key (too long)"),
    ]
    
    all_passed = True
    
    print("\nValid key sizes:")
    for size, name in valid_keys:
        try:
            deal.key = bytes([0] * size)
            print(f"  {name}: ✓ PASS")
        except Exception as e:
            print(f"  {name}: ✗ FAIL - {e}")
            all_passed = False
    
    print("\nInvalid key sizes (should raise exceptions):")
    for size, name in invalid_keys:
        try:
            deal.key = bytes([0] * size)
            print(f"  {name}: ✗ FAIL - Should have raised exception")
            all_passed = False
        except ValueError as e:
            print(f"  {name}: ✓ PASS - Correctly rejected")
        except Exception as e:
            print(f"  {name}: ✗ FAIL - Wrong exception: {e}")
            all_passed = False
    
    return all_passed


def test_block_size_validation():
    """Test block size validation"""
    print("\nBlock Size Validation Test")
    print("=" * 40)
    
    deal = Deal()
    deal.key = bytes.fromhex('00000000000000000000000000000000')
    
    valid_block = bytes([0] * 16)
    invalid_blocks = [
        (8, "64-bit block (too small)"),
        (15, "120-bit block (too small)"),
        (17, "136-bit block (too large)"),
        (32, "256-bit block (too large)"),
    ]
    
    all_passed = True
    
    print("\nValid block size:")
    try:
        result = bytearray(16)
        deal.encrypt(valid_block, result)
        print(f"  128-bit block: ✓ PASS")
    except Exception as e:
        print(f"  128-bit block: ✗ FAIL - {e}")
        all_passed = False
    
    print("\nInvalid block sizes (should raise exceptions):")
    for size, name in invalid_blocks:
        try:
            result = bytearray(size)
            deal.encrypt(bytes([0] * size), result)
            print(f"  {name}: ✗ FAIL - Should have raised exception")
            all_passed = False
        except ValueError as e:
            print(f"  {name}: ✓ PASS - Correctly rejected")
        except Exception as e:
            print(f"  {name}: ✗ FAIL - Wrong exception: {e}")
            all_passed = False
    
    return all_passed


if __name__ == '__main__':
    try:
        vectors_passed = test_deal_vectors()
        
        roundtrip_passed = test_round_trip()
        
        key_validation_passed = test_key_validation()
        
        block_validation_passed = test_block_size_validation()
        
        file_passed = test_file_encryption()
        
        bytes_passed = test_bytes_encryption()
        
        all_passed = (
            vectors_passed and 
            roundtrip_passed and 
            key_validation_passed and 
            block_validation_passed and
            file_passed and 
            bytes_passed
        )
        
        print("\n" + "=" * 60)
        if all_passed:
            print(" All DEAL tests completed successfully!")
            sys.exit(0)
        else:
            print(" Some DEAL tests failed!")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n Error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
