import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import warnings

class AESHandler:
    def __init__(self):
        # Get key from environment variable or use default
        env_key = os.getenv('AES_SECRET_KEY')
        if env_key:
            self.default_key = env_key.encode('utf-8')
            key_length = len(self.default_key)
            if key_length not in [16, 24, 32]:
                from hashlib import sha256
                self.default_key = sha256(self.default_key).digest()[:32]  # Hash and truncate to 32 bytes

        else:
            # Fallback for development
            self.default_key = b"default_dev_key_16b"
            warnings.warn("Using development AES key - not secure for production!", UserWarning)

        self.block_size = AES.block_size

    def encrypt(self, data: bytes, key: bytes = None) -> str:
        """Encrypt data with provided key or default"""
        use_key = key or self.default_key
        cipher = AES.new(use_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, self.block_size))
        return b64encode(cipher.iv + ct_bytes).decode('utf-8')

    def decrypt(self, encrypted_data: str, key: bytes = None) -> bytes:
        """Decrypt data using provided key or default"""
        use_key = key or self.default_key
        try:
            raw = b64decode(encrypted_data)
            iv = raw[:self.block_size]
            ct = raw[self.block_size:]
            cipher = AES.new(use_key, AES.MODE_CBC, iv=iv)
            return unpad(cipher.decrypt(ct), self.block_size)
        except Exception as e:
            raise ValueError("Decryption failed") from e

aes_handler = AESHandler()
