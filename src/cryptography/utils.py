#fuck me...
from typing import List

def bytes_to_bits(value: bytes, least_bit_first: bool = True) -> List[int]:
    bit_array = []
    
    if least_bit_first:
        for byte in value:
            for i in range(8):
                bit_array.append((byte >> i) & 1)
    else:
        for byte in value:
            for i in range(8):
                bit_array.append((byte >> (7 - i)) & 1)
                
    return bit_array

def bits_to_bytes(value: List[int], least_bit_first: bool = True) -> bytes:
    counter = 0
    number = 0
    result = bytearray()
    for i in value:
        if counter == 8:
            result.append(number)
            counter = 0
            number = 0
    
        if least_bit_first:
            number ^= (i << counter)
        else:
            number ^= (i << (7 - counter))

        counter += 1
        
    if counter != 0:
        result.append(number)
    
    return bytes(result)
    
# 1.1
def permutate_bits(value: bytes, bits_mapping: List[int], least_bit_first=True, first_bit_index=1) -> bytes:
    """
    Permutate bits in byte array according to bits_mapping
    
    bits_mapping: bits_mapping[i] corresponds to №i bit in new array
    first_bit_index: 1 for 1-based indexing (FIPS standard), 0 for 0-based indexing
    """

    if first_bit_index not in [0, 1]:
        raise ValueError("First bit index should be 1 or 0")
    
    bit_array = bytes_to_bits(value, least_bit_first=least_bit_first)
    
    permutated_bits = [0 for _ in bits_mapping]
    
    for output_index, input_index in enumerate(bits_mapping):
        actual_input_index = input_index - first_bit_index
        if actual_input_index < len(bit_array):
            permutated_bits[output_index] = bit_array[actual_input_index]
        else:
            permutated_bits[output_index] = 0
    
    result = bits_to_bytes(permutated_bits, least_bit_first=least_bit_first)
    
    return result
