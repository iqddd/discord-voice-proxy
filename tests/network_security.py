"""Integration tests, isolated from Discord. Run with Python x64 on Windows."""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
FORCE = ROOT / 'x64/Release/force-proxy.dll'
DWRITE = ROOT / 'x64/Release/DWrite.dll'

class Blob(c.Structure):
    _fields_ = [('size', w.DWORD), ('data', c.POINTER(c.c_ubyte))]

def protect(text):
    import base64
    data = text.encode('utf-8')
    raw = (c.c_ubyte * len(data)).from_buffer_copy(data)
    source, dest = Blob(len(data), raw), Blob()
    crypt = c.WinDLL('crypt32', use_last_error=True)
    assert crypt.CryptProtectData(c.byref(source), None, None, None, None, 1, c.byref(dest))
    try:
        return base64.b64encode(c.string_at(dest.data, dest.size)).decode()
    finally:
        kernel = c.WinDLL('kernel32')
        kernel.LocalFree.argtypes = [c.c_void_p]
        kernel.LocalFree(dest.data)

def exact(connection, count):
    data = b''
    while len(data) < count:
        chunk = connection.recv(count-len(data))
        if not chunk:
            raise RuntimeError('EOF')
        data += chunk
    return data

def run(mode):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    listener.settimeout(5)
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(('127.0.0.1', 0))
    relay.settimeout(1)
    port = listener.getsockname()[1]
    errors, received = [], []
    release = threading.Event()
    password = 'test-\u043f\u0430\u0440\u043e\u043b\u044c=123'
    def server():
        try:
            with listener.accept()[0] as connection:
                connection.settimeout(5)
                greeting = exact(connection, 3)
                assert greeting == (b'\x05\x01\x02' if mode == 'loader' else b'\x05\x01\x00')
                connection.sendall(b'\x05' + greeting[2:])
                if mode == 'loader':
                    version, length = exact(connection, 2)
                    assert version == 1 and exact(connection, length) == b'user'
                    length = exact(connection, 1)[0]
                    assert exact(connection, length) == password.encode()
                    connection.sendall(b'\x01\x00')
                request = exact(connection, 10)
                if mode == 'loader':
                    assert request == b'\x05\x01\x00\x01' + socket.inet_aton('203.0.113.42') + struct.pack('!H', 443)
                    response = b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00'
                else:
                    assert request[:4] == b'\x05\x03\x00\x01'
                    if mode == 'reject':
                        connection.sendall(b'\x05\x01\x00\x01')
                        return
                    if mode == 'truncated':
                        connection.sendall(b'\x05\x00')
                        return
                    response = b'\x05\x00\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', relay.getsockname()[1])
                # Fragmented responses exercise exact-length reads.
                for byte in response:
                    connection.sendall(bytes([byte]))
                    time.sleep(.002)
                if mode == 'loader':
                    assert exact(connection, 4) == b'ping'
                    connection.sendall(b'pong')
                else:
                    received.append(relay.recvfrom(1024)[0])
                    release.wait(5)
        except BaseException as error:
            errors.append(error)
    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    os.environ.update(SOCKS5_PROXY_ADDRESS='127.0.0.1', SOCKS5_PROXY_PORT=str(port),
                      SOCKS5_PROXY_LOGIN='', SOCKS5_PROXY_PASSWORD='', SOCKS5_PROXY_TIMEOUT='1')
    os.environ.pop('SOCKS5_PROXY_PASSWORD_DPAPI', None)
    library_path = FORCE
    if mode == 'loader':
        fixture = Path(tempfile.mkdtemp(prefix='discord-loader-test-'))
        own = fixture / 'own'; own.mkdir()
        hostile = fixture / 'cwd'; hostile.mkdir()
        shutil.copy2(DWRITE, own / 'DWrite.dll')
        shutil.copy2(FORCE, own / 'force-proxy.dll')
        (own / 'proxy.txt').write_text(f'SOCKS5_PROXY_ADDRESS=127.0.0.1\nSOCKS5_PROXY_PORT={port}\nSOCKS5_PROXY_LOGIN=user\nSOCKS5_PROXY_PASSWORD_DPAPI={protect(password)}\nSECURITY_TEST_SENTINEL=changed\n', encoding='utf-8')
        (hostile / 'proxy.txt').write_text('SOCKS5_PROXY_ADDRESS=192.0.2.1\nSOCKS5_PROXY_PORT=9\nSECURITY_TEST_SENTINEL=changed\n')
        (hostile / 'force-proxy.dll').write_bytes(b'invalid DLL')
        os.environ['SECURITY_TEST_SENTINEL'] = 'original'
        os.chdir(hostile)
        library_path = own / 'DWrite.dll'
    library = c.WinDLL(str(library_path))
    winsock = c.WinDLL('ws2_32')
    winsock.connect.argtypes = [c.c_size_t, c.c_void_p, c.c_int]
    winsock.bind.argtypes = [c.c_size_t, c.c_void_p, c.c_int]
    winsock.sendto.argtypes = [c.c_size_t, c.c_void_p, c.c_int, c.c_int, c.c_void_p, c.c_int]
    target = struct.pack('<H', socket.AF_INET) + struct.pack('!H', 443) + socket.inet_aton('203.0.113.42') + bytes(8)
    if mode == 'loader':
        kernel = c.WinDLL('kernel32')
        value = c.create_unicode_buffer(64)
        kernel.GetEnvironmentVariableW('SECURITY_TEST_SENTINEL', value, 64)
        assert value.value == 'original'
        with socket.socket() as client:
            assert winsock.connect(client.fileno(), target, len(target)) == 0
            client.sendall(b'ping'); assert exact(client, 4) == b'pong'
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            local = struct.pack('<H', socket.AF_INET) + bytes(14)
            result = winsock.bind(client.fileno(), local, len(local))
            if mode in ('reject', 'truncated'):
                assert result == -1
                # Even after a failed bind, a subsequent send must not escape.
                direct = struct.pack('<H', socket.AF_INET) + struct.pack('!H', relay.getsockname()[1]) + socket.inet_aton('127.0.0.1') + bytes(8)
                assert winsock.sendto(client.fileno(), b'leak', 4, 0, direct, len(direct)) == -1
                try:
                    relay.recvfrom(1024)
                    raise AssertionError('Direct UDP leak')
                except socket.timeout:
                    pass
            else:
                assert result == 0
                assert winsock.sendto(client.fileno(), b'voice', 5, 0, target, len(target)) == 5
                # Keep the association/socket alive until the relay receives it.
                deadline = time.monotonic() + 3
                while not received and not errors and time.monotonic() < deadline:
                    time.sleep(.01)
    release.set()
    worker.join(6)
    assert not worker.is_alive()
    if errors: raise errors[0]
    if mode == 'udp':
        assert received == [b'\0\0\0\x01' + socket.inet_aton('203.0.113.42') + struct.pack('!H', 443) + b'voice']
    print('PASS:', mode)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe_receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe_sender:
            probe_receiver.bind(('127.0.0.1', 0))
            probe_receiver.settimeout(1)
            probe_sender.sendto(b'probe', probe_receiver.getsockname())
            try:
                udp_available = probe_receiver.recvfrom(16)[0] == b'probe'
            except socket.timeout:
                udp_available = False
        if not udp_available:
            print('SKIP: successful UDP relay test; plain loopback UDP fails without the DLL', flush=True)
        for mode in ('loader', 'reject', 'truncated') + (('udp',) if udp_available else ()):
            subprocess.run([sys.executable, str(Path(__file__).resolve()), mode], check=True, timeout=20)
