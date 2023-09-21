import binascii
import json
from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def generate_rsa_keys() -> Tuple[RSA.RsaKey, RSA.RsaKey]:
    key_pair = RSA.generate(2048)
    public_key = key_pair.publickey()
    return public_key, key_pair


def encrypt_AES_GCM(msg: bytes, secretKey: bytes) -> str:
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    msg = json.dumps({'text': binascii.hexlify(ciphertext).decode(),
                      'iv': binascii.hexlify(aesCipher.nonce).decode(),
                      'tag': binascii.hexlify(authTag).decode()
                      })
    return msg


def decrypt_AES_GCM(msg: str, secretKey: bytes) -> str:
    (ciphertext, nonce, authTag) = json.loads(msg).values()
    aesCipher = AES.new(secretKey, AES.MODE_GCM, binascii.unhexlify(nonce))
    plaintext = aesCipher.decrypt_and_verify(
        binascii.unhexlify(ciphertext), binascii.unhexlify(authTag))
    return plaintext


def encrypt_aes_key(rsa_public_key: RSA.RsaKey, msg: bytes) -> bytes:
    encryptor = PKCS1_OAEP.new(rsa_public_key)
    return encryptor.encrypt(msg)


def decrypt_aes_key(rsa_key_pair: RSA.RsaKey, msg: bytes) -> bytes:
    decryptor = PKCS1_OAEP.new(rsa_key_pair)
    return decryptor.decrypt(msg)
