import socket

ETH_P_ALL = 0x0003


def open_capture(iface: str | None = None) -> socket.socket:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    if iface is not None:
        sock.bind((iface, 0))
    return sock


def capture(iface: str | None = None):
    sock = open_capture(iface)
    try:
        while True:
            frame, _ = sock.recvfrom(65535)
            yield frame
    finally:
        sock.close()
