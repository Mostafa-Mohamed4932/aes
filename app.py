from flask import Flask, render_template, request, jsonify
import os
import base64

# Import all the necessary functions from your AES implementation
from functools import reduce

# === AES Constants ===
# S-box for the SubBytes step (256 elements)
s_box = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

# Inverse S-box for the InvSubBytes step (256 elements)
inv_s_box = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

# Round constant for key expansion (only first 10 needed for AES-128)
r_con = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# === Helper Functions for Block & Matrix Conversion ===

def bytes2matrix(text_bytes):
    """Converts a 16-byte array into a 4x4 matrix."""
    return [list(text_bytes[i:i + 4]) for i in range(0, 16, 4)]


def matrix2bytes(matrix):
    """Converts a 4x4 matrix back into a 16-byte array."""
    return bytes(sum(matrix, []))


def xor_bytes(a, b):
    """Returns a new byte array with the XOR of a and b."""
    return bytes(i ^ j for i, j in zip(a, b))


# === AES Core Transformations (Encryption) ===

def sub_bytes(state):
    """Apply the S-box substitution on each byte in the state matrix."""
    for i in range(4):
        for j in range(4):
            state[i][j] = s_box[state[i][j]]
    return state


def shift_rows(state):
    """Perform the ShiftRows transformation on the state matrix."""
    for i in range(4):
        state[i] = state[i][i:] + state[i][:i]
    return state


def xtime(a):
    """Multiply by x (i.e. {02}) in GF(2^8)."""
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def mix_single_column(column):
    """Mix one column for the MixColumns step."""
    t = column[0] ^ column[1] ^ column[2] ^ column[3]
    u = column[0]
    column[0] ^= t ^ xtime(column[0] ^ column[1])
    column[1] ^= t ^ xtime(column[1] ^ column[2])
    column[2] ^= t ^ xtime(column[2] ^ column[3])
    column[3] ^= t ^ xtime(column[3] ^ u)
    return column


def mix_columns(state):
    """Apply the MixColumns transformation on the state matrix."""
    for j in range(4):
        col = [state[i][j] for i in range(4)]
        col = mix_single_column(col)
        for i in range(4):
            state[i][j] = col[i]
    return state


def add_round_key(state, round_key):
    """XOR the state with the round key."""
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state


# === Key Expansion for AES-128 ===

def key_expansion(key):
    """
    Expands a 16-byte key into 11 round keys (each a 4x4 matrix).
    AES-128 uses 10 rounds, plus an initial AddRoundKey.
    """
    key_columns = bytes2matrix(key)
    columns = key_columns[:]  # start with original key columns
    i = 4
    while len(columns) < 44:
        temp = list(columns[-1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  # Rotate word
            temp = [s_box[b] for b in temp]  # Apply S-box
            temp[0] ^= r_con[i // 4]  # XOR with round constant
        new_col = [a ^ b for a, b in zip(columns[-4], temp)]
        columns.append(new_col)
        i += 1
    round_keys = [columns[4 * i:4 * (i + 1)] for i in range(11)]
    return round_keys


# === AES Single Block Encryption ===

def aes_encrypt_block(block, round_keys):
    """
    Encrypts a single 16-byte block using the provided round keys.
    Follows 10 rounds of AES for a 128-bit key.
    """
    state = bytes2matrix(block)
    state = add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return matrix2bytes(state)


# === PKCS#7 Padding (PKCS5Padding for AES block size) ===

def pad(plaintext_bytes):
    """
    Pads the plaintext using PKCS#7 padding so that its length is a multiple of 16 bytes.
    Each added byte is the number of bytes that are added.
    """
    pad_len = 16 - (len(plaintext_bytes) % 16)
    return plaintext_bytes + bytes([pad_len] * pad_len)


def unpad(padded_bytes):
    """
    Removes the PKCS#7 padding from the plaintext.
    """
    pad_len = padded_bytes[-1]
    return padded_bytes[:-pad_len]


# === AES CBC Mode Encryption ===

def encrypt_aes_cbc(plaintext, key, iv):
    """
    Encrypts an arbitrary-length plaintext using AES in CBC mode.

    Parameters:
      plaintext (str): The plaintext message to encrypt.
      key (str): The encryption key (must be 16 characters for 128-bit AES).
      iv (bytes): A 16-byte initialization vector.

    Returns:
      bytes: The resulting ciphertext.
    """
    plaintext_bytes = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("Key must be exactly 16 characters long.")
    round_keys = key_expansion(key_bytes)
    padded = pad(plaintext_bytes)
    blocks = [padded[i:i + 16] for i in range(0, len(padded), 16)]
    ciphertext = b""
    previous = iv  # Use IV for the first block
    for block in blocks:
        block = xor_bytes(block, previous)
        encrypted_block = aes_encrypt_block(block, round_keys)
        ciphertext += encrypted_block
        previous = encrypted_block  # Update IV for next block (CBC chaining)
    return ciphertext


# === Decryption Helper Functions ===

# Galois Field multiplication (used in inverse MixColumns)
def gmul(a, b):
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p


def inv_mix_single_column(column):
    """
    Applies the inverse MixColumns transformation to a single column.
    The multiplication coefficients are {0x0e, 0x0b, 0x0d, 0x09}.
    """
    c0 = gmul(column[0], 0x0e) ^ gmul(column[1], 0x0b) ^ gmul(column[2], 0x0d) ^ gmul(column[3], 0x09)
    c1 = gmul(column[0], 0x09) ^ gmul(column[1], 0x0e) ^ gmul(column[2], 0x0b) ^ gmul(column[3], 0x0d)
    c2 = gmul(column[0], 0x0d) ^ gmul(column[1], 0x09) ^ gmul(column[2], 0x0e) ^ gmul(column[3], 0x0b)
    c3 = gmul(column[0], 0x0b) ^ gmul(column[1], 0x0d) ^ gmul(column[2], 0x09) ^ gmul(column[3], 0x0e)
    return [c0, c1, c2, c3]


def inv_mix_columns(state):
    """Apply the inverse MixColumns transformation on the state matrix."""
    for j in range(4):
        col = [state[i][j] for i in range(4)]
        col = inv_mix_single_column(col)
        for i in range(4):
            state[i][j] = col[i]
    return state


def inv_shift_rows(state):
    """Perform the inverse ShiftRows transformation (right shift each row by its row index)."""
    for i in range(4):
        state[i] = state[i][-i:] + state[i][:-i]
    return state


def inv_sub_bytes(state):
    """Apply the inverse S-box substitution on each byte in the state matrix."""
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_s_box[state[i][j]]
    return state


# === AES Single Block Decryption ===

def aes_decrypt_block(block, round_keys):
    """
    Decrypts a single 16-byte block using the provided round keys.
    Inverse of the encryption process for AES-128.
    """
    state = bytes2matrix(block)
    state = add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return matrix2bytes(state)


# === AES CBC Mode Decryption ===

def decrypt_aes_cbc(ciphertext, key, iv):
    """
    Decrypts ciphertext encrypted with AES in CBC mode.

    Parameters:
      ciphertext (bytes): The ciphertext to decrypt.
      key (str): The encryption key (must be 16 characters for 128-bit AES).
      iv (bytes): The 16-byte initialization vector used during encryption.

    Returns:
      bytes: The resulting plaintext (unpadded).
    """
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("Key must be exactly 16 characters long.")
    round_keys = key_expansion(key_bytes)
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    plaintext = b""
    previous = iv
    for block in blocks:
        decrypted_block = aes_decrypt_block(block, round_keys)
        plaintext_block = xor_bytes(decrypted_block, previous)
        plaintext += plaintext_block
        previous = block  # update for CBC mode
    return unpad(plaintext)

# Initialize Flask app
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        plaintext = data.get('plaintext', '')
        key = data.get('key', '')
        
        # Validate inputs
        if not plaintext or not key:
            return jsonify({'error': 'Plaintext and key are required'}), 400
        
        if len(key) != 16:
            return jsonify({'error': 'Key must be exactly 16 characters long'}), 400
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Encrypt the plaintext
        ciphertext = encrypt_aes_cbc(plaintext, key, iv)
        
        # Convert binary data to base64 for safe transmission
        return jsonify({
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        ciphertext_b64 = data.get('ciphertext', '')
        iv_b64 = data.get('iv', '')
        key = data.get('key', '')
        
        # Validate inputs
        if not ciphertext_b64 or not iv_b64 or not key:
            return jsonify({'error': 'Ciphertext, IV, and key are required'}), 400
        
        if len(key) != 16:
            return jsonify({'error': 'Key must be exactly 16 characters long'}), 400
        
        # Convert from base64 to binary
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        
        # Decrypt the ciphertext
        plaintext = decrypt_aes_cbc(ciphertext, key, iv)
        
        return jsonify({
            'plaintext': plaintext.decode('utf-8')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)