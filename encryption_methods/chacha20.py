from Crypto.Cipher import ChaCha20
import os

def encrypt(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    return nonce + ciphertext

def decrypt(data: bytes, key: bytes) -> bytes:
    nonce = data[:12]
    ciphertext = data[12:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)
