"""Exercise the built DLL in an isolated process with a local SOCKS5 stub."""
import ctypes
import os
import socket
import struct
import sys
import threading


def receive_exact(connection, length):
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise RuntimeError("Unexpected EOF from SOCKS5 client")
        result.extend(chunk)
    return bytes(result)


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
listener.settimeout(10)
proxy_port = listener.getsockname()[1]
failures = []
observed = []
payload = b"force-proxy-build-smoke-test"


def serve_proxy():
    try:
        with listener.accept()[0] as connection:
            connection.settimeout(10)
            assert receive_exact(connection, 3) == b"\x05\x01\x00"
            connection.sendall(b"\x05\x00")
            request = receive_exact(connection, 10)
            assert request[:4] == b"\x05\x01\x00\x01"
            destination = socket.inet_ntoa(request[4:8])
            destination_port = struct.unpack("!H", request[8:10])[0]
            assert (destination, destination_port) == ("203.0.113.42", 443)
            observed.append(f"{destination}:{destination_port}")
            connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            assert receive_exact(connection, len(payload)) == payload
            connection.sendall(payload)
    except BaseException as error:
        failures.append(error)


worker = threading.Thread(target=serve_proxy, daemon=True)
worker.start()
os.environ.update(
    SOCKS5_PROXY_ADDRESS="127.0.0.1",
    SOCKS5_PROXY_PORT=str(proxy_port),
    SOCKS5_PROXY_LOGIN="",
    SOCKS5_PROXY_PASSWORD="",
    SOCKS5_PROXY_TIMEOUT="5",
)
loaded_library = ctypes.WinDLL(os.path.abspath(sys.argv[1]))
winsock = ctypes.WinDLL("ws2_32", use_last_error=True)
winsock.connect.argtypes = [ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
winsock.connect.restype = ctypes.c_int
winsock.WSAGetLastError.restype = ctypes.c_int


class SockAddrIn(ctypes.Structure):
    _fields_ = [
        ("family", ctypes.c_ushort),
        ("port", ctypes.c_ushort),
        ("address", ctypes.c_ubyte * 4),
        ("padding", ctypes.c_ubyte * 8),
    ]


target = SockAddrIn()
target.family = socket.AF_INET
target.port = socket.htons(443)
target.address[:] = socket.inet_aton("203.0.113.42")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    result = winsock.connect(client.fileno(), ctypes.byref(target), ctypes.sizeof(target))
    if result != 0:
        raise RuntimeError(f"Intercepted connect failed: {winsock.WSAGetLastError()}")
    client.settimeout(10)
    client.sendall(payload)
    assert receive_exact(client, len(payload)) == payload

worker.join(timeout=12)
listener.close()
assert not worker.is_alive(), "SOCKS5 stub did not finish"
if failures:
    raise failures[0]
assert observed
print(f"PASS: x64 DLL loaded; TCP {observed[0]} traversed local SOCKS5; payload echoed")
