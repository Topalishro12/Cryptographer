from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json

def generate_aes_key():
    return get_random_bytes(32)

def encrypt_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    nonce = cipher.nonce
    
    return {
        'key': base64.b64encode(key).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8')
    }

def decrypt_aes_from_file(file_path):
    with open(file_path, 'r') as f:
        loaded = json.load(f)
        key = base64.b64decode(loaded['key'])
        ciphertext = base64.b64decode(loaded['ciphertext'])
        nonce = base64.b64decode(loaded['nonce'])
        tag = base64.b64decode(loaded['tag'])
        
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode('utf-8')