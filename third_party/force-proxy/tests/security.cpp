#include "../src/stdafx.h"
#include <cassert>
#include <iostream>
#include "../src/hooks.cpp"

IN_ADDR g_ProxyAddress{};
uint16_t g_ProxyPort = 0;
uint32_t g_ProxyTimeout = 1;
char g_ProxyLogin[256]{};
char g_ProxyPassword[256]{};
std::string g_ProxyEncryptedPassword;

std::vector<WSABUF> captured;
LPWSAOVERLAPPED capturedOverlapped;
LPWSAOVERLAPPED_COMPLETION_ROUTINE capturedCallback;
const sockaddr* capturedDestination;
int directCalls = 0;
int WINAPI CaptureSend(SOCKET, LPWSABUF buffers, DWORD count, LPDWORD, DWORD,
    const sockaddr* to, int, LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE callback)
{
    captured.assign(buffers, buffers + count);
    capturedOverlapped = overlapped;
    capturedCallback = callback;
    capturedDestination = to;
    WSASetLastError(WSA_IO_PENDING);
    return SOCKET_ERROR;
}
int WINAPI CountConnect(SOCKET, const sockaddr*, int) { ++directCalls; return 0; }
void CALLBACK Completed(DWORD, DWORD, LPWSAOVERLAPPED, DWORD) {}

int main()
{
    WSADATA data{};
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    auto tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    auto udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(443);
    inet_pton(AF_INET, "203.0.113.42", &destination.sin_addr);
    sockaddr_in6 ipv6{};
    ipv6.sin6_family = AF_INET6;
    auto originalConnect = Real_connect;
    Real_connect = CountConnect;
    assert(Mine_connect(tcp, reinterpret_cast<sockaddr*>(&ipv6), sizeof(ipv6)) == SOCKET_ERROR);
    assert(WSAGetLastError() == WSAEAFNOSUPPORT && directCalls == 0);
    assert(Mine_connect(udp, reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) == SOCKET_ERROR);
    assert(WSAGetLastError() == WSAEOPNOTSUPP && directCalls == 0);
    Real_connect = originalConnect;

    // Unassociated UDP must never invoke the real send, including zero payload.
    char first[] = "first", second[] = "second";
    WSABUF payloads[] = {{5, first}, {6, second}};
    assert(Mine_sendto(udp, first, 5, 0, reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) == SOCKET_ERROR);
    assert(WSAGetLastError() == WSAENETUNREACH);
    assert(Mine_WSASendTo(udp, payloads, 2, nullptr, 0,
        reinterpret_cast<sockaddr*>(&destination), sizeof(destination), nullptr, nullptr) == SOCKET_ERROR);
    assert(WSAGetLastError() == WSAENETUNREACH);

    udp_association_entry_t entry{};
    entry.udpProxyAddr.sin_family = AF_INET;
    entry.udpProxyAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    entry.udpProxyAddr.sin_port = htons(12345);
    g_UDPAssociateMap.emplace(udp, entry);
    Real_WSASendTo = CaptureSend;
    WSAOVERLAPPED overlapped{};
    assert(Mine_WSASendTo(udp, payloads, 2, nullptr, 0,
        reinterpret_cast<sockaddr*>(&destination), sizeof(destination), &overlapped, Completed) == SOCKET_ERROR);
    assert(WSAGetLastError() == WSA_IO_PENDING);
    assert(capturedOverlapped == &overlapped && capturedCallback == Completed);
    assert(captured.size() == 3 && captured[0].len == 10);
    assert(captured[1].buf == first && captured[2].buf == second);
    // Read only AFTER the hook returns and churn allocations to expose UAF.
    const char* retainedHeader = captured[0].buf;
    std::vector<std::vector<char>> churn(1000, std::vector<char>(256, 'X'));
    assert(retainedHeader[3] == 1);
    assert(memcmp(retainedHeader + 4, &destination.sin_addr, 4) == 0);
    assert(memcmp(retainedHeader + 8, &destination.sin_port, 2) == 0);
    assert(reinterpret_cast<const sockaddr_in*>(capturedDestination)->sin_port == htons(12345));
    assert(Mine_WSASendTo(udp, payloads, 2, nullptr, 0,
        reinterpret_cast<sockaddr*>(&destination), sizeof(destination), &overlapped, nullptr) == SOCKET_ERROR);
    assert(captured[0].buf == retainedHeader); // Reuses header rather than leaking per send.
    assert(capturedCallback == nullptr && capturedOverlapped == &overlapped);
    g_UDPAssociateMap.clear();
    closesocket(udp); closesocket(tcp);
    WSACleanup();
    std::cout << "PASS: IPv6/connected UDP blocked; no UDP fallback; pending scatter/gather buffers survive; event/IOCP/callback arguments preserved\n";
}
