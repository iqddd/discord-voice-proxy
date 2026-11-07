#include "stdafx.h"
#include <wincrypt.h>
#include <mutex>
#include <string>
#pragma comment(lib, "crypt32.lib")

namespace {
int Fail(int error) { WSASetLastError(error); return SOCKET_ERROR; }

bool WaitForSocket(SOCKET socket, bool write)
{
    fd_set ready, errors;
    FD_ZERO(&ready); FD_SET(socket, &ready);
    FD_ZERO(&errors); FD_SET(socket, &errors);
    timeval timeout{static_cast<long>(g_ProxyTimeout), 0};
    const int result = select(0, write ? nullptr : &ready, write ? &ready : nullptr, &errors, &timeout);
    if (result == SOCKET_ERROR) return false;
    if (!result) { Fail(WSAETIMEDOUT); return false; }
    if (FD_ISSET(socket, &errors)) {
        int error = 0, length = sizeof(error);
        if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) != 0)
            return false;
        Fail(error ? error : WSAECONNABORTED);
        return false;
    }
    return true;
}

bool SendAll(SOCKET socket, const void* buffer, int length, bool nonBlocking)
{
    const char* data = static_cast<const char*>(buffer);
    while (length) {
        if (nonBlocking && !WaitForSocket(socket, true)) return false;
        const int count = send(socket, data, length, 0);
        if (count == SOCKET_ERROR) return false;
        if (!count) { Fail(WSAECONNRESET); return false; }
        data += count; length -= count;
    }
    return true;
}

bool ReceiveExact(SOCKET socket, void* buffer, int length, bool nonBlocking)
{
    char* data = static_cast<char*>(buffer);
    while (length) {
        if (nonBlocking && !WaitForSocket(socket, false)) return false;
        const int count = recv(socket, data, length, 0);
        if (count == SOCKET_ERROR) return false;
        if (!count) { Fail(WSAECONNRESET); return false; }
        data += count; length -= count;
    }
    return true;
}

bool ReadReply(SOCKET socket, uint8_t (&response)[10], bool nonBlocking)
{
    if (!ReceiveExact(socket, response, 4, nonBlocking)) return false;
    if (response[0] != 5 || response[2] != 0) { Fail(WSAECONNABORTED); return false; }
    if (response[1] != 0) { Fail(WSAECONNREFUSED); return false; }
    if (response[3] != 1) { Fail(WSAEAFNOSUPPORT); return false; }
    return ReceiveExact(socket, response + 4, 6, nonBlocking);
}

bool LoadProtectedPassword()
{
    // DPAPI can load libraries and use RPC: defer it until the first handshake,
    // outside DllMain's loader lock. Encrypted configuration overrides plaintext.
    static std::once_flag once;
    static bool valid = false;
    std::call_once(once, [] {
        if (g_ProxyEncryptedPassword.empty()) { valid = true; return; }
        DWORD size = 0;
        if (!CryptStringToBinaryA(g_ProxyEncryptedPassword.c_str(), 0, CRYPT_STRING_BASE64,
            nullptr, &size, nullptr, nullptr)) return;
        std::vector<BYTE> encrypted(size);
        if (!CryptStringToBinaryA(g_ProxyEncryptedPassword.c_str(), 0, CRYPT_STRING_BASE64,
            encrypted.data(), &size, nullptr, nullptr)) return;
        DATA_BLOB input{size, encrypted.data()}, output{};
        if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &output)) return;
        if (output.cbData <= 255 && !memchr(output.pbData, 0, output.cbData)) {
            memcpy(g_ProxyPassword, output.pbData, output.cbData);
            g_ProxyPassword[output.cbData] = 0;
            valid = true;
        }
        SecureZeroMemory(output.pbData, output.cbData);
        LocalFree(output.pbData);
    });
    if (!valid) Fail(WSAEACCES);
    return valid;
}
}

int ConnectToProxy(SOCKET socket, bool nonBlocking)
{
    sockaddr_in proxy{};
    proxy.sin_family = AF_INET;
    proxy.sin_addr = g_ProxyAddress;
    proxy.sin_port = g_ProxyPort;
    const int result = Real_connect(socket, reinterpret_cast<const sockaddr*>(&proxy), sizeof(proxy));
    if (result == 0) return 0;
    if (!nonBlocking || WSAGetLastError() != WSAEWOULDBLOCK) return SOCKET_ERROR;
    if (!WaitForSocket(socket, true)) return SOCKET_ERROR;
    int error = 0, length = sizeof(error);
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) != 0)
        return SOCKET_ERROR;
    return error ? Fail(error) : 0;
}

int SendSocks5Handshake(SOCKET socket, bool nonBlocking)
{
    if (!LoadProtectedPassword()) return SOCKET_ERROR;
    const bool authenticate = g_ProxyLogin[0] || g_ProxyPassword[0];
    const uint8_t request[] = {5, 1, static_cast<uint8_t>(authenticate ? 2 : 0)};
    uint8_t response[2]{};
    if (!SendAll(socket, request, sizeof(request), nonBlocking) ||
        !ReceiveExact(socket, response, sizeof(response), nonBlocking)) return SOCKET_ERROR;
    // Do not allow a proxy to downgrade explicitly configured authentication.
    if (response[0] != 5 || response[1] != request[2]) return Fail(WSAEACCES);
    if (authenticate) {
        const size_t loginLength = strlen(g_ProxyLogin), passwordLength = strlen(g_ProxyPassword);
        uint8_t auth[513]{};
        size_t size = 0;
        auth[size++] = 1;
        auth[size++] = static_cast<uint8_t>(loginLength);
        memcpy(auth + size, g_ProxyLogin, loginLength); size += loginLength;
        auth[size++] = static_cast<uint8_t>(passwordLength);
        memcpy(auth + size, g_ProxyPassword, passwordLength); size += passwordLength;
        const bool sent = SendAll(socket, auth, static_cast<int>(size), nonBlocking);
        SecureZeroMemory(auth, sizeof(auth));
        if (!sent || !ReceiveExact(socket, response, sizeof(response), nonBlocking)) return SOCKET_ERROR;
        if (response[0] != 1 || response[1] != 0) return Fail(WSAEACCES);
    }
    return 0;
}

int ConnectThroughSocks5(SOCKET socket, const sockaddr_in* target, bool nonBlocking)
{
    if (ConnectToProxy(socket, nonBlocking) != 0 || SendSocks5Handshake(socket, nonBlocking) != 0)
        return SOCKET_ERROR;
    uint8_t request[10] = {5, 1, 0, 1}, response[10]{};
    memcpy(request + 4, &target->sin_addr, 4);
    memcpy(request + 8, &target->sin_port, 2);
    if (!SendAll(socket, request, sizeof(request), nonBlocking) || !ReadReply(socket, response, nonBlocking))
        return SOCKET_ERROR;
    return nonBlocking ? Fail(WSAEWOULDBLOCK) : 0;
}

bool InitializeSocks5UdpAssociation(udp_association_entry_t* entry)
{
    *entry = {};
    entry->proxySocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (entry->proxySocket == INVALID_SOCKET) return false;
    const auto fail = [&] {
        const int error = WSAGetLastError();
        Real_closesocket(entry->proxySocket);
        entry->proxySocket = INVALID_SOCKET;
        WSASetLastError(error);
        return false;
    };
    u_long nonBlocking = 1;
    if (Real_ioctlsocket(entry->proxySocket, FIONBIO, &nonBlocking) != 0 ||
        ConnectToProxy(entry->proxySocket, true) != 0 || SendSocks5Handshake(entry->proxySocket, true) != 0)
        return fail();
    const uint8_t request[10] = {5, 3, 0, 1};
    uint8_t response[10]{};
    if (!SendAll(entry->proxySocket, request, sizeof(request), true) ||
        !ReadReply(entry->proxySocket, response, true)) return fail();
    entry->udpProxyAddr.sin_family = AF_INET;
    memcpy(&entry->udpProxyAddr.sin_addr, response + 4, 4);
    memcpy(&entry->udpProxyAddr.sin_port, response + 8, 2);
    if (!entry->udpProxyAddr.sin_port) { Fail(WSAECONNABORTED); return fail(); }
    if (entry->udpProxyAddr.sin_addr.s_addr == INADDR_ANY)
        entry->udpProxyAddr.sin_addr = g_ProxyAddress;
    return true;
}

void ExtractSockAddr(char* buf, sockaddr* target)
{
    const struct sockaddr_in* addr = reinterpret_cast<const struct sockaddr_in*>(target);
    memcpy((void*)&addr->sin_addr.s_addr, &buf[4], sizeof(addr->sin_addr.s_addr)); //ip addr
    memcpy((void*)&addr->sin_port, &buf[8], sizeof(addr->sin_port)); // port
}