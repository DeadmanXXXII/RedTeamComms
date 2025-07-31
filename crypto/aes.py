from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

BLOCK_SIZE = 16

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding] * padding)

def unpad(data):
    return data[:-data[-1]]

def generate_aes_key():
    return get_random_bytes(32)

def encrypt_aes(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))
    return base64.b64encode(iv + ciphertext)

def decrypt_aes(key, ciphertext):
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(raw[16:]))
