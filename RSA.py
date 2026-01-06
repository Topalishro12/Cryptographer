from Crypto.PublicKey import RSA

def generate_rsa_keys():
    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    return public_key,private_key


def get_public_key_pem(public_key_bytes):
    return public_key_bytes.decode('utf-8')