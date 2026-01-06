from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


def generate_rsa_keys():
    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    return public_key,private_key


def get_public_key_pem(public_key_bytes):
    return public_key_bytes.decode('utf-8')

def encrypt_rsa(private_key,public_key,plaintext):
    # Предполагаем, ключи уже сгенерированы
    private_key_obj = RSA.import_key(private_key)
    public_key_obj = RSA.import_key(public_key)
    data = plaintext.encode('utf-8')
    # Шифрование публичным ключом
    cipher_rsa = PKCS1_OAEP.new(public_key_obj)
    ciphertext_rsa = cipher_rsa.encrypt(data)

    return {
        'public_key_obj': public_key_obj,
        'private_key_obj': private_key_obj,
        'ciphertext_rsa': base64.b64encode(ciphertext_rsa).decode('utf-8'),
    }