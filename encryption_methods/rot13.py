import codecs

def encrypt(text):
    return codecs.encode(text, 'rot_13')

def decrypt(text):
    return encrypt(text)
