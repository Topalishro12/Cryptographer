from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import json

def generate_rsa_keys():
    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    return private_key,public_key


def get_public_key_pem(public_key_bytes):
    return public_key_bytes.decode('utf-8')

def encrypt_rsa(public_key,plaintext):
    public_key_obj = RSA.import_key(public_key)
    data = plaintext.encode('utf-8')
    # Шифрование публичным ключом
    cipher_rsa = PKCS1_OAEP.new(public_key_obj)
    ciphertext_rsa = cipher_rsa.encrypt(data)

    return {'ciphertext_rsa':base64.b64encode(ciphertext_rsa).decode('utf-8')}

def decrypt(private_key, ciphertext_b64):
    private_key_obj = RSA.import_key(private_key)
    ciphertext = base64.b64decode(ciphertext_b64.encode('utf-8'))
    # Расшифрование приватным ключом
    cipher_rsa = PKCS1_OAEP.new(private_key_obj)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext.decode('utf-8')
        
