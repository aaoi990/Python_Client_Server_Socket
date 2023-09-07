import binascii
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import json


def generate_rsa_keys():
    key_pair = RSA.generate(2048)
    public_key = key_pair.publickey()
    return public_key, key_pair


def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    msg = json.dumps({'text': binascii.hexlify(ciphertext).decode(),
                      'iv': binascii.hexlify(aesCipher.nonce).decode(),
                      'tag': binascii.hexlify(authTag).decode()
                      })
    return msg


def decrypt_AES_GCM(msg, secretKey):
    (ciphertext, nonce, authTag) = json.loads(msg).values()
    aesCipher = AES.new(secretKey, AES.MODE_GCM, binascii.unhexlify(nonce))
    plaintext = aesCipher.decrypt_and_verify(
        binascii.unhexlify(ciphertext), binascii.unhexlify(authTag))
    return plaintext


def encrypt_aes_key(rsa_public_key, msg):
    encryptor = PKCS1_OAEP.new(rsa_public_key)
    return encryptor.encrypt(msg)


def decrypt_aes_key(rsa_key_pair, msg):
    decryptor = PKCS1_OAEP.new(rsa_key_pair)
    return decryptor.decrypt(msg)
