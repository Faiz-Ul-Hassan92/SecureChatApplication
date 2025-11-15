"""AES-128(ECB)+PKCS#7 helpers (use library).""" 


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_aes(plaintext, key):
    """
    Encrypt plaintext using AES-128 with PKCS#7 padding
    Returns: base64-encoded ciphertext
    """
    cipher = AES.new(key, AES.MODE_ECB)  
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes(ciphertext_b64, key):
    """
    Decrypt base64-encoded ciphertext using AES-128
    Returns: plaintext string
    """
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext_b64)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode('utf-8')
