import socket
import components.crypt as crypt
import sys
import logging
import os
from components import protocol
import binascii


class Client:
    def __init__(self, ip_address: str, port: int) -> None:
        self.server_address = ip_address
        self.server_port = port
        self.running = True
        self.protocol = protocol.Protocol()
        self._server_public_rsa = None
        self._aes_key = None
        self._public_rsa, self._key_pair = crypt.generate_rsa_keys()
        self._commands = {
            "exit":  self.terminate_client,
            "whoami": self.whoami,
        }


    def whoami(self) -> str:
        return os.getuid()

    def terminate_client(self, connection: socket.socket) -> None:
        connection.close()
        self.running = False
        logging.warning("Client terminated")
        sys.exit(1)

    def _configure_crypt(self, connection: socket.socket) -> None:
        self._server_public_rsa = self.protocol.receive(connection)
        self.protocol.send(connection,
                           self._public_rsa.export_key())
        aes_key = binascii.unhexlify(self.protocol.receive(connection))
        self._aes_key = crypt.decrypt_aes_key(self._key_pair, aes_key)

    def handle_messages(self, connection: socket.socket) -> None:
        while self.running:
            try:
                msg = self.protocol.receive(connection).decode()
                if msg:
                    decrypted_msg = crypt.decrypt_AES_GCM(msg, self._aes_key).decode()
                    print(decrypted_msg)
                    if decrypted_msg == "exit":
                        self.terminate_client(connection)
                    else:
                        cmd_output = self._commands.get(decrypted_msg, lambda: 'Invalid')()
                        self.protocol.send(
                            connection, crypt.encrypt_AES_GCM(cmd_output.encode(), self._aes_key).encode())
                else:
                    logging.info("Unknown command: %s", msg)
            except socket.error as error_message:
                logging.error(
                    "Error handling message from server: %s", error_message)
                self.terminate_client(connection)

    def run(self) -> None:
        try:
            socket_instance = socket.socket()
            socket_instance.connect((self.server_address, self.server_port))
            socket_instance.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._configure_crypt(socket_instance)
        except socket.error as error_message:
            logging.error("Socket creation error: %s", error_message)
            socket_instance.close()
            sys.exit(1)

        self.handle_messages(socket_instance)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    client = Client('127.0.0.1', 12000)
    client.run()
