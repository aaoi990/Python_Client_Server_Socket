import binascii
import logging
import socket
import uuid

import components.crypt as crypt
import components.protocol as protocol
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)

AES_KEY_SIZE = 32

class Host:
    def __init__(self, connection: socket.socket, name: str) -> None:
        self.friendly_name = name        
        self.connection = connection         
        self.count = 0     
        self.protocol = protocol.Protocol()        
        self.aes = get_random_bytes(AES_KEY_SIZE)
        self._uuid = uuid.uuid4()
        self._public_rsa, self._key_pair = crypt.generate_rsa_keys()
        self._client_public_rsa = None
        self._configure_crypt(connection)

    def __repr__(self) -> str:
        return f"Host({self.friendly_name}, {self._uuid})"

    def _configure_crypt(self, connection: socket.socket) -> None:
        logger.info("Configuring encryption")
        self.protocol.send(connection, self._public_rsa.export_key())
        try:
            self._client_public_rsa = RSA.import_key(
                self.protocol.receive(connection))
        except TypeError as key_error:
            logging.error("Error importing the clients RSA public key: %s", key_error)

        encrypted_aes_key = crypt.encrypt_aes_key(
            self._client_public_rsa, self.aes)
        self.protocol.send(
            connection, binascii.hexlify(encrypted_aes_key))
        logger.info("Encryption configured, remote host %s has AES key %s", self.friendly_name, self.aes)


