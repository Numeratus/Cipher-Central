from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import base64

def validate_blowfish_key(key: str) -> bool:
    key_bytes = key.encode('utf-8')
    return 4 <= len(key_bytes) <= 56

def encrypt(data: bytes, key: str) -> bytes:
    if not validate_blowfish_key(key):
        raise ValueError("Invalid Blowfish key length (must be 4-56 bytes)")

    cipher = Blowfish.new(key.encode('utf-8'), Blowfish.MODE_ECB)
    padded_data = pad(data, Blowfish.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted)

def decrypt(encrypted_data: bytes, key: str) -> bytes:
    if not validate_blowfish_key(key):
        raise ValueError("Invalid Blowfish key length (must be 4-56 bytes)")

    try:
        ciphertext = base64.b64decode(encrypted_data)
    except Exception as e:
        raise ValueError("Invalid base64 encoding") from e

    if len(ciphertext) % Blowfish.block_size != 0:
        raise ValueError(f"Ciphertext length must be multiple of {Blowfish.block_size} bytes")

    cipher = Blowfish.new(key.encode('utf-8'), Blowfish.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, Blowfish.block_size)
