import argparse
import logging
import socket

import components.crypt as crypt
import components.host as remote_host

logger = logging.getLogger(__name__)

class Server:
    def __init__(self, address: str, port: int) -> None:
        self.address = address
        self.port = port
        self.connections = []
        self._remote_hosts = []

    def handle_user_connection(self, host: remote_host, connection: socket.socket) -> None:
        while True:
            msg = None
            while not msg:
                msg = input("Send command to client: ").encode()
            try:
                if msg:
                    host.protocol.send(
                        connection, crypt.encrypt_AES_GCM(msg, host.aes).encode())
                    msg = host.protocol.receive(connection)
                    decrypted_msg = crypt.decrypt_AES_GCM(msg, host.aes)
                if decrypted_msg:
                    logging.info(
                        "Received message from client: %s", decrypted_msg.decode())
                    host.count += 1

            except socket.error as comms_error:
                logging.error("Transmission error: %s", comms_error)
                self.remove_connection(connection)
                break

    def remove_connection(self, connection: socket.socket) -> None:
        if connection in self.connections:
            connection.close()
            self.connections.remove(connection)

    def run(self) -> None:
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
            logging.info("Client connected from: %s", adddress)
            logging.info("Storing new remote host data.")
            name = input("Input new remote host identifier: ")
            new_host = remote_host.Host(socket_connection, name)
            self._remote_hosts.append(new_host)          
            self.connections.append(socket_connection)
            logging.info("%s Added", repr(new_host))            
            if self.connections:
                print("You are already to connected to the first host")           
                self.handle_user_connection(new_host, socket_connection)
            else:
                logging.warning("A new remote host %s has connected", repr(new_host))


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