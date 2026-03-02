#!/usr/bin/env python3
"""
DES Demo Script
Tests the DES implementation with known test vectors from FIPS 46-3
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from cryptography.des_implementation import Des

def test_des_vectors():
    """Test DES with known test vectors from FIPS 46-3"""
    
    # Test vectors from FIPS 46-3 Appendix A
    test_cases = [
        {
            'key': bytes.fromhex('0000000000000000'),
            'plaintext': bytes.fromhex('0000000000000000'),
            'ciphertext': bytes.fromhex('8CA64DE9C1B123A7')
        },
        {
            'key': bytes.fromhex('FFFFFFFFFFFFFFFF'),
            'plaintext': bytes.fromhex('FFFFFFFFFFFFFFFF'),
            'ciphertext': bytes.fromhex('7359B2163E4EDC58')
        },
        {
            'key': bytes.fromhex('3000000000000000'),
            'plaintext': bytes.fromhex('1000000000000001'),
            'ciphertext': bytes.fromhex('958E6E627A05557B')
        },
        {
            'key': bytes.fromhex('1111111111111111'),
            'plaintext': bytes.fromhex('1111111111111111'),
            'ciphertext': bytes.fromhex('F40379AB9E0EC533')
        },
        {
            'key': bytes.fromhex('0123456789ABCDEF'),
            'plaintext': bytes.fromhex('1111111111111111'),
            'ciphertext': bytes.fromhex('17668DFC7292532D')
        }
    ]
    
    des = Des()
    
    print("DES Test Vectors (FIPS 46-3)")
    print("=" * 50)
    
    all_passed = True
    
    for i, test in enumerate(test_cases, 1):
        print(f"\nTest Case {i}:")
        print(f"Key:        {test['key'].hex().upper()}")
        print(f"Plaintext:  {test['plaintext'].hex().upper()}")
        print(f"Expected:   {test['ciphertext'].hex().upper()}")
        
        # Test encryption
        des.key = test['key']
        encrypted_result = bytearray(8)
        des.encrypt(test['plaintext'], encrypted_result)
        encrypted = bytes(encrypted_result)
        
        print(f"Encrypted:  {encrypted.hex().upper()}")
        
        # Test decryption
        decrypted_result = bytearray(8)
        des.decrypt(encrypted, decrypted_result)
        decrypted = bytes(decrypted_result)
        
        print(f"Decrypted:  {decrypted.hex().upper()}")
        
        # Check results
        encrypt_ok = encrypted == test['ciphertext']
        decrypt_ok = decrypted == test['plaintext']
        
        if encrypt_ok and decrypt_ok:
            print("✓ PASS")
        else:
            print("✗ FAIL")
            if not encrypt_ok:
                print(f"  Encryption failed: expected {test['ciphertext'].hex()}, got {encrypted.hex()}")
            if not decrypt_ok:
                print(f"  Decryption failed: expected {test['plaintext'].hex()}, got {decrypted.hex()}")
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("All tests PASSED! ✓")
    else:
        print("Some tests FAILED! ✗")
    
    return all_passed

def test_round_trip():
    """Test encrypt/decrypt round-trip with random data"""
    import random
    
    print("\nRound-trip Test")
    print("=" * 30)
    
    des = Des()
    
    # Test with random keys and data
    for i in range(5):
        key = bytes([random.randint(0, 255) for _ in range(8)])
        plaintext = bytes([random.randint(0, 255) for _ in range(8)])
        
        des.key = key
        
        # Encrypt
        encrypted_result = bytearray(8)
        des.encrypt(plaintext, encrypted_result)
        encrypted = bytes(encrypted_result)
        
        # Decrypt
        decrypted_result = bytearray(8)
        des.decrypt(encrypted, decrypted_result)
        decrypted = bytes(decrypted_result)
        
        if plaintext == decrypted:
            print(f"Test {i+1}: ✓ PASS")
        else:
            print(f"Test {i+1}: ✗ FAIL")
            print(f"  Original: {plaintext.hex()}")
            print(f"  Decrypted: {decrypted.hex()}")
            return False
    
    print("All round-trip tests PASSED! ✓")
    return True

if __name__ == '__main__':
    try:
        # Run test vectors
        vectors_passed = test_des_vectors()
        
        # Run round-trip tests
        roundtrip_passed = test_round_trip()
        
        if vectors_passed and roundtrip_passed:
            print("\n🎉 All DES tests completed successfully!")
            sys.exit(0)
        else:
            print("\n❌ Some DES tests failed!")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n💥 Error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)