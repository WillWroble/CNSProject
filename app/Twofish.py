import struct
from typing import List

# --- GF(256) Multiplication ---
def gf_mult(a: int, b: int, modulus: int = 0x14D) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        # Shift a left by one bit, keeping it 8-bit.
        a = (a << 1) & 0xFF
        # Instead of XORing with 0x14D (which is >255), XOR only with lower 8 bits (0x14D & 0xFF = 0x4D).
        if hi_bit:
            a ^= (modulus & 0xFF)
        b >>= 1
    return p
# --- RS Matrix from TwoFish Spec ---
RS = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]
]
# --- MDS Matrix for TwoFish ---
MDS = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B]
]
# --- Q-Permutation Tables ---
# Base nibble (4-bit) arrays from TwoFish specification.
q0_nibble = [0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4]
q1_nibble = [0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5]

def compute_q_table(q_nibble: list) -> list:
    table = []
    for x in range(256):
        a = x >> 4  # high nibble
        b = x & 0x0F  # low nibble
        y = (q_nibble[a] << 4) | q_nibble[b]
        table.append(y)
    return table

# Compute the full 256-entry Q tables.
q0_table = compute_q_table(q0_nibble)
q1_table = compute_q_table(q1_nibble)

def mds_mult(row: int, vec: list) -> int:
    result = 0
    for i in range(4):
        result ^= gf_mult(MDS[row][i], vec[i])
    return result
def rs_mds_encode(data: bytes) -> bytes:
    result = []
    # For each row of the RS matrix.
    for row in RS:
        acc = 0
        # Multiply each row element with the corresponding data byte and XOR accumulate.
        for r, d in zip(row, data):
            acc ^= gf_mult(r, d)
        result.append(acc)
    return bytes(result)

def simple_rs_encode(key: bytes) -> bytes:
    block_size = 8
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for RS encoding.")
    # Partition key into 4 blocks.
    blocks = [key[i*block_size:(i+1)*block_size] for i in range(4)]
    combined = bytearray(block_size)
    for i in range(block_size):
        combined[i] = blocks[0][i] ^ blocks[1][i] ^ blocks[2][i] ^ blocks[3][i]
    # Encode combined 8 bytes using the RS matrix.
    return rs_mds_encode(bytes(combined))
# --- TwoFish Implementation with Key-dependent S-boxes ---
class TwoFish:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits) for this implementation.")
        self.key = key
        self.NR = 16  # Number of rounds (Twofish typically uses 16 rounds)
        self.SBOX = self._generate_key_dependent_sbox(key)
        self.subkeys = self._key_schedule(key)
    def _generate_key_dependent_sbox(self, key: bytes):
        # Base S-box: reverse the numbers 0 to 255.
        base_sbox = list(range(256))
        base_sbox.reverse()
        # Compute 4 S-box key bytes using RS/MDS encoding.
        sbox_key = simple_rs_encode(key)  # returns 4 bytes
        # Modify the base S-box by XORing each entry with a key byte (cycling through).
        key_dependent_sbox = []
        for i in range(256):
            key_byte = sbox_key[i % 4]
            key_dependent_sbox.append(base_sbox[i] ^ key_byte)
        return key_dependent_sbox
    def _rotate_left(self, x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _h(self, x: int, L: List[int]) -> int:
        for word in L:
            x = self._g(x ^ word)
        return x
    def _key_schedule(self, key: bytes) -> List[int]:
        """
        Generate a full set of 40 subkeys (each 32 bits) using a RS‑MDS-based key schedule.
        
        Steps:
          - Split the 256-bit key into eight 32-bit words (little-endian).
          - Let Me = even-indexed words, Mo = odd-indexed words.
          - For i from 0 to 19, compute:
              A = _h(2*i, Me)
              B = _rotate_left( _h(2*i+1, Mo), 8 )
              Subkey[2*i]   = (A + B) mod 2^32
              Subkey[2*i+1] = _rotate_left( (A + 2*B) mod 2^32, 9 )
        
        This yields 40 subkeys in total:
          - Indices 0-3: input whitening keys.
          - Indices 4-7: output whitening keys.
          - Indices 8-39: round keys.
        """
        # Split key into 8 words (32 bits each), little-endian.
        words = list(struct.unpack("<8I", key))
        Me = [words[i] for i in range(0, len(words), 2)]
        Mo = [words[i] for i in range(1, len(words), 2)]
        subkeys = []
        for i in range(20):
            A = self._h(2 * i, Me)
            B = self._rotate_left(self._h(2 * i + 1, Mo), 8)
            K_even = (A + B) & 0xFFFFFFFF
            K_odd = self._rotate_left((A + 2 * B) & 0xFFFFFFFF, 9)
            subkeys.append(K_even)
            subkeys.append(K_odd)
        return subkeys


    def _g(self, x: int) -> int:
        b0 = (x >> 24) & 0xFF
        b1 = (x >> 16) & 0xFF
        b2 = (x >> 8) & 0xFF
        b3 = x & 0xFF

        # Apply Q-permutations.
        b0 = q0_table[b0]
        b1 = q0_table[b1]
        b2 = q1_table[b2]
        b3 = q1_table[b3]

        # Substitute each byte using the key dependent S-box.
        b0 = self.SBOX[b0]
        b1 = self.SBOX[b1]
        b2 = self.SBOX[b2]
        b3 = self.SBOX[b3]

        # Now apply the MDS multiplication:
        y0 = mds_mult(0, [b0, b1, b2, b3])
        y1 = mds_mult(1, [b0, b1, b2, b3])
        y2 = mds_mult(2, [b0, b1, b2, b3])
        y3 = mds_mult(3, [b0, b1, b2, b3])

        # Recombine the 4 bytes into a 32-bit word.
        return (y0 << 24) | (y1 << 16) | (y2 << 8) | y3
    
    def _PHT(self, x: int, y: int) -> (int,int):
        a = (x + y) & 0xFFFFFFFF
        b = (x + 2 * y) & 0xFFFFFFFF
        return a, b
    
    def _F(self, R0: int, R1: int, round: int) -> int:
        g0 = self._g(R0)
        g1 = self._g(R1)
        pht0, pht1 = self._PHT(g0, g1)
        # Assume subkeys for rounds start at offset 8 (indices 8 and upward are used for rounds).
        offset = 8
        F0 = (pht0 + self.subkeys[offset + 2 * round]) & 0xFFFFFFFF
        F1 = (pht1 + self.subkeys[offset + 2 * round + 1]) & 0xFFFFFFFF
        return F0, F1

    def encrypt_block(self, plaintext: bytes) -> bytes:
        if len(plaintext) != 16:
            raise ValueError("Plaintext block must be 16 bytes.")
        # Unpack the plaintext block into four 32-bit unsigned integers (big-endian).
        R = list(struct.unpack(">4I", plaintext))

        # Input whitening: XOR the plaintext words with the first 4 subkeys.
        R[0] ^= self.subkeys[0]
        R[1] ^= self.subkeys[1]
        R[2] ^= self.subkeys[2]
        R[3] ^= self.subkeys[3]

        # Perform 16 rounds of the encryption process.
        for r in range(self.NR):
            F0, F1 = self._F(R[0], R[1], r)
            R[2] ^= F0
            R[3] ^= F1
            R = R[2:] + R[:2] #rotate

    
        # Output whitening: XOR the words with the next 4 subkeys.
        R[0] ^= self.subkeys[4]
        R[1] ^= self.subkeys[5]
        R[2] ^= self.subkeys[6]
        R[3] ^= self.subkeys[7]

        # Pack the four 32-bit words back into a 16-byte block.
        ciphertext = struct.pack(">4I", *R)
        return ciphertext

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != 16:
            raise ValueError("Ciphertext block must be 16 bytes.")
        R = list(struct.unpack(">4I", ciphertext))

        # Reverse output whitening.
        R[0] ^= self.subkeys[4]
        R[1] ^= self.subkeys[5]
        R[2] ^= self.subkeys[6]
        R[3] ^= self.subkeys[7]

        # Reverse the rounds.
        for r in range(self.NR - 1, -1, -1):
            R = R[-2:] + R[:-2]  # reverse rotation.
            F0, F1 = self._F(R[0], R[1], r)
            R[2] ^= F0
            R[3] ^= F1
        # Reverse input whitening.
        R[0] ^= self.subkeys[0]
        R[1] ^= self.subkeys[1]
        R[2] ^= self.subkeys[2]
        R[3] ^= self.subkeys[3]

        plaintext = struct.pack(">4I", *R)
        return plaintext


# Example usage:
if __name__ == "__main__":
    key = b'LRIuntUbPf7Kd4uiyOzzcQKLRwknyUJW'  # Must be exactly 32 bytes (256 bits)
    cipher = TwoFish(key)

    # 16-byte block of plaintext
    plaintext = b'16 byte message.'
    ciphertext = cipher.encrypt_block(plaintext)
    decrypted = cipher.decrypt_block(ciphertext)

    print("Plaintext: ", plaintext)
    print("Ciphertext (hex): ", ciphertext.hex())
    print("Decrypted: ", decrypted)
