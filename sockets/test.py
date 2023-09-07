import binascii
import requests
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


def generate_rsa_keys():
    key_pair = RSA.generate(2048)
    public_key = key_pair.publickey().exportKey()
    private_key = key_pair.exportKey()
    return public_key, private_key


def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)


def decrypt_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext


def encrypt_aes_key(rsa_public_key, msg):
    encryptor = PKCS1_OAEP.new(rsa_public_key)
    return encryptor.encrypt(msg)


keyPair = RSA.generate(3072)

pubKey = keyPair.publickey().export_key()
pubKey = RSA.import_key(pubKey)
print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPEM = pubKey.exportKey()
print(pubKeyPEM.decode('ascii'))

print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
privKeyPEM = keyPair.exportKey()
print(privKeyPEM.decode('ascii'))
# testkey = pubKey.export_key()
# newPub = RSA.import_key(pubKey)
msg = b'A message for encryption'
encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(msg)
print("Encrypted:", binascii.hexlify(encrypted))
