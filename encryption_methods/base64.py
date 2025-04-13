import base64

def encrypt(data):
    """Always returns base64 encoded string"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('utf-8')

def decrypt(data):
    """Accepts both bytes and string, returns bytes"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64decode(data)
