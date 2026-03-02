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
def permutate_bits(value: bytes, bits_mapping: List[int], least_bit_first=True, first_bit_index=0) -> bytes:
    """
    Permutate bits in byte array according to bits_mapping
    
    bits_mapping: bits_mapping[i] corresponds to №i bit in new array
    """

    if first_bit_index not in [0, 1]:
        raise ValueError("First bit index should be 1 or 0")
    
    if first_bit_index:
        bits_mapping = map(lambda x: x - 1, bits_mapping)
    
    # bit_array = []
    
    # if least_bit_first:
    #     for byte in value:
    #         for i in range(8):
    #             bit_array.append((byte >> i) & 1)
    # else:
    #     for byte in value:
    #         for i in range(8):
    #             bit_array.append((byte >> (7 - i)) & 1)
    
    bit_array = bytes_to_bits(value, least_bit_first=least_bit_first)
    
    permutated_bits = [0 for _ in bit_array]
    
    for input_index, output_index in enumerate(bit_array):
        permutated_bits[output_index] = bit_array[input_index]

    # counter = 0
    # number = 0
    # result = bytearray()
    # for i in permutated_bits:
    #     if counter == 8:
    #         result.append(number)
    #         counter = 0
    #         number = 0
    
    #     if least_bit_first:
    #         number ^= (i << counter)
    #     else:
    #         number ^= (i << (7 - counter))

    #     counter += 1
        
    # if counter != 0:
    #     result.append(number)
    
    result = bits_to_bytes(permutated_bits, least_bit_first=least_bit_first)
    
    return result

[0x10101010, 0x10101010]

pblock = [i for i in range()]