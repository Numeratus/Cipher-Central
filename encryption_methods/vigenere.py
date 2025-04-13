def encrypt(text, key):
    key = key.upper()
    encrypted = []
    key_index = 0
    for char in text:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            key_char = ord(key[key_index % len(key)]) - ord('A')
            encrypted_char = chr((ord(char) - offset + key_char) % 26 + offset)
            encrypted.append(encrypted_char)
            key_index += 1
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def decrypt(text, key):
    key = key.upper()
    decrypted = []
    key_index = 0
    for char in text:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            key_char = ord(key[key_index % len(key)]) - ord('A')
            decrypted_char = chr((ord(char) - offset - key_char) % 26 + offset)
            decrypted.append(decrypted_char)
            key_index += 1
        else:
            decrypted.append(char)
    return ''.join(decrypted)
