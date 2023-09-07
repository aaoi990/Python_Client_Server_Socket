import socket
import argparse
import logging
import components.protocol as protocol
import components.crypt as crypt
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import binascii

AES_KEY_SIZE = 32


class Server:
    def __init__(self, address: str, port: int) -> None:
        self.address = address
        self.port = port
        self.connections = []
        self.protocol = protocol.Protocol()
        self._public_rsa, self._key_pair = crypt.generate_rsa_keys()
        self._client_public_rsa = None
        self._aes = get_random_bytes(AES_KEY_SIZE)
        self._count = 0

    def _configure_crypt(self, connection: socket.socket) -> None:
        self.protocol.send(connection, self._public_rsa.export_key())
        try:
            self._client_public_rsa = RSA.import_key(
                self.protocol.receive(connection))
        except TypeError as key_error:
            logging.error("Error importing the clients RSA public key.")

        encrypted_aes_key = crypt.encrypt_aes_key(
            self._client_public_rsa, self._aes)
        self.protocol.send(
            connection, binascii.hexlify(encrypted_aes_key))

    def handle_user_connection(self, connection: socket.socket) -> None:
        while True:
            msg = None
            while not msg:
                msg = input("Send command to client: ").encode()
            try:
                if msg:
                    self.protocol.send(
                        connection, crypt.encrypt_AES_GCM(msg, self._aes).encode())
                    msg = self.protocol.receive(connection)
                    decrypted_msg = crypt.decrypt_AES_GCM(msg, self._aes)
                if decrypted_msg:
                    logging.info(
                        "Received message from client: %s", decrypted_msg.decode())
                    self._count += 1

            except socket.error as comms_error:
                logging.error("Transmission error: %s", comms_error)
                self.remove_connection(connection)
                break

    def remove_connection(self, connection: socket.socket) -> None:
        if connection in self.connections:
            connection.close()
            self.connections.remove(connection)

    def run(self) -> None:
        logging.info("Generating keys......")
        if self._public_rsa and self._key_pair:
            logging.info("Keys generated successfully")
        else:
            logging.error("Error generating keys")
            return
        try:
            socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as error_message:
            logging.error("Socket creation error: %s", error_message)

        socket_instance.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            socket_instance.bind(('', self.port))
            socket_instance.listen(5)
            logging.info("Server running")
        except socket.error as error_message:
            logging.error("Socket binding error: %s", error_message)
            socket_instance.close()

        while True:
            socket_connection, adddress = socket_instance.accept()
            logging.info("Client connected: %s", adddress)
            self.connections.append(socket_connection)
            self._configure_crypt(socket_connection)
            self.handle_user_connection(socket_connection)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Socket Server")
    parser.add_argument('-a', '--address', type=str,
                        default='localhost', help='Address to bind to')
    parser.add_argument('-p', '--port', type=int,
                        default=1060, help='Port to bind to')
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    server = Server(args.address, args.port)
    server.run()
