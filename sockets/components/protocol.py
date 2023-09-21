import struct
import logging
import socket
import sys

logger = logging.getLogger(__name__)


class Protocol:
    def __init__(self):
        self._header_len = 4

    def send(self, sock: socket.socket, msg: str) -> None:
        try:
            final_msg = struct.pack('>I', len(msg)) + msg
            sock.sendall(final_msg)
        except socket.error as error_message:
            logger.error("Error sending data: %s", error_message)
            sys.exit(1)

    def receive(self, sock: socket.socket) -> str:
        header = self._raw_receive(sock, self._header_len)
        logger.debug("Recieved message header: %s", header)
        msg_len = struct.unpack('>I', header)[0]
        logger.debug("Recieved message lenght: %s", msg_len)
        msg = self._raw_receive(sock, msg_len)
        return msg

    def _raw_receive(self, sock: socket.socket, msg_len: int) -> bytearray:
        data = bytearray()
        while len(data) < msg_len:
            try:
                chunk = sock.recv(msg_len - len(data))
                data.extend(chunk)
            except socket.error as error_message:
                logger.error("Error receiving data: %s", error_message)
                sys.exit(1)
        return data
