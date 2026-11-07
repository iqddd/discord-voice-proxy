#include "stdafx.h"
#include <array>
#include <mutex>
#include <tuple>
#include <new>

#pragma region Detours definations

extern "C" {
	int (WINAPI* Real_connect)(SOCKET s, const sockaddr* name, int namelen) = connect;

	int (WINAPI* Real_bind)(SOCKET s, const sockaddr* addr, int namelen) = bind;

	int (WINAPI* Real_closesocket)(SOCKET s) = closesocket;

	int (WINAPI* Real_sendto)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) = sendto;

	int (WINAPI* Real_recvfrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) = recvfrom;

	int (WINAPI* Real_WSASendTo)(
		SOCKET s,
		LPWSABUF lpBuffers,
		DWORD dwBufferCount,
		LPDWORD lpNumberOfBytesSent,
		DWORD dwFlags,
		const sockaddr* lpTo,
		int iTolen,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSASendTo;

	int (WINAPI* Real_WSARecvFrom)(
		SOCKET s,
		LPWSABUF lpBuffers,
		DWORD dwBufferCount,
		LPDWORD lpNumberOfBytesRecvd,
		LPDWORD lpFlags,
		sockaddr* lpFrom,
		LPINT lpFromlen,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSARecvFrom;

	int (WSAAPI* Real_WSAEventSelect)(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents) = WSAEventSelect;
	int (WSAAPI* Real_ioctlsocket)(SOCKET s, long cmd, u_long* argp) = ioctlsocket;
}

#pragma endregion


std::shared_mutex g_SocketsMapsMutex;
std::map<SOCKET, udp_association_entry_t> g_UDPAssociateMap;
std::map<SOCKET, long> g_NonBlockingSockets;

bool IsUDPSocket(SOCKET s)
{
	int32_t sockOptVal;
	int32_t sockOptLen = sizeof(sockOptVal);

	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sockOptVal, &sockOptLen) != 0)
		return false;

	return sockOptVal == SOCK_DGRAM;
}

int SocketError(int error)
{
    WSASetLastError(error);
    return SOCKET_ERROR;
}

bool ValidateIPv4(const sockaddr* address, int length)
{
    if (!address || length < sizeof(address->sa_family)) {
        WSASetLastError(WSAEFAULT);
        return false;
    }
    if (address->sa_family != AF_INET) {
        WSASetLastError(WSAEAFNOSUPPORT);
        return false;
    }
    if (length < sizeof(sockaddr_in)) {
        WSASetLastError(WSAEFAULT);
        return false;
    }
    return true;
}

bool GetUdpRelay(SOCKET s, const sockaddr* destination, int length, udp_association_entry_t& entry)
{
    if (!ValidateIPv4(destination, length)) return false;
    const auto ip = ntohl(reinterpret_cast<const sockaddr_in*>(destination)->sin_addr.s_addr);
    if ((ip & 0xf0000000) == 0xe0000000 || ip == 0xffffffff) {
        WSASetLastError(WSAEACCES); // SOCKS5 does not provide multicast/broadcast.
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(g_SocketsMapsMutex);
    auto it = g_UDPAssociateMap.find(s);
    if (it == g_UDPAssociateMap.end()) {
        WSASetLastError(WSAENETUNREACH); // Never fall back to a direct datagram.
        return false;
    }
    entry = it->second;
    return true;
}

struct UdpSendTarget {
    std::array<char, 10> header{};
    sockaddr_in relay{};
};

const UdpSendTarget* GetUdpSendTarget(const sockaddr_in& destination, const sockaddr_in& relay)
{
    using Key = std::tuple<ULONG, USHORT, ULONG, USHORT>;
    struct Cache {
        std::mutex mutex;
        std::map<Key, UdpSendTarget> targets;
    };
    // One immutable 10-byte header per destination/relay, not per send. Keep
    // these nodes for the PROCESS lifetime, including DLL unload: an outstanding
    // send can still reference them. The OS reclaims them at process exit.
    // Payloads remain caller-owned, exactly as required by WSASendTo.
    static auto* cache = new Cache;
    std::lock_guard<std::mutex> lock(cache->mutex);
    const Key key{destination.sin_addr.s_addr, destination.sin_port,
        relay.sin_addr.s_addr, relay.sin_port};
    auto existing = cache->targets.find(key);
    if (existing != cache->targets.end()) return &existing->second;
    // Bound retained storage; exhaustion fails closed instead of growing forever.
    if (cache->targets.size() >= 4096) throw std::bad_alloc();
    auto result = cache->targets.try_emplace(key);
    auto& target = result.first->second;
    if (result.second) {
        target.header[3] = 1; // SOCKS5 IPv4 UDP header.
        memcpy(target.header.data() + 4, &destination.sin_addr, 4);
        memcpy(target.header.data() + 8, &destination.sin_port, 2);
        target.relay = relay;
    }
    return &target;
}

bool SocketExistsInUdpAssociationMap(SOCKET s)
{
	g_SocketsMapsMutex.lock_shared();
	bool exists = g_UDPAssociateMap.count(s);
	g_SocketsMapsMutex.unlock_shared();

	return exists;
}

bool SocketExistsInNonBlockingMap(SOCKET s)
{
	g_SocketsMapsMutex.lock_shared();
	bool exists = g_NonBlockingSockets.count(s);
	g_SocketsMapsMutex.unlock_shared();

	return exists;
}

int WSAAPI Mine_WSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents)
{

	g_SocketsMapsMutex.lock();
	if (hEventObject != NULL && lNetworkEvents != 0) {
		g_NonBlockingSockets.insert(std::pair<SOCKET, long>(s, lNetworkEvents));
	} else {
		g_NonBlockingSockets.erase(s);
	}
	g_SocketsMapsMutex.unlock();

	return Real_WSAEventSelect(s, hEventObject, lNetworkEvents);
}

int WSAAPI Mine_ioctlsocket(SOCKET s, long cmd, u_long* argp)
{
	if (cmd == FIONBIO) {
		g_SocketsMapsMutex.lock();
		if (*argp) {
			g_NonBlockingSockets.insert(std::pair<SOCKET, long>(s, *argp));
		} else {
			g_NonBlockingSockets.erase(s);
		}
		g_SocketsMapsMutex.unlock();
	}

	return Real_ioctlsocket(s, cmd, argp);
}

int WINAPI Mine_connect(SOCKET s, const sockaddr* name, int namelen)
{
    if (!ValidateIPv4(name, namelen)) return SOCKET_ERROR;
    const auto* address = reinterpret_cast<const sockaddr_in*>(name);
    const bool loopback = (ntohl(address->sin_addr.s_addr) >> 24) == 127;
    // Connected UDP can subsequently use send/WSASend, which are not hooked.
    // Reject it instead of allowing an unencapsulated path to the destination.
    if (IsUDPSocket(s)) return SocketError(WSAEOPNOTSUPP);
    if (loopback || (address->sin_addr.s_addr == g_ProxyAddress.s_addr &&
        address->sin_port == g_ProxyPort))
        return Real_connect(s, name, namelen);
    return ConnectThroughSocks5(s, address, SocketExistsInNonBlockingMap(s));
}

int WINAPI Mine_bind(SOCKET s, const sockaddr* addr, int namelen)
{
    if (!ValidateIPv4(addr, namelen)) return SOCKET_ERROR;
    if (!IsUDPSocket(s) || SocketExistsInUdpAssociationMap(s))
        return Real_bind(s, addr, namelen);

    udp_association_entry_t entry{};
    if (!InitializeSocks5UdpAssociation(&entry)) return SOCKET_ERROR;
    auto result = Real_bind(s, addr, namelen);
    if (result == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        Real_closesocket(entry.proxySocket);
        return SocketError(error);
    }
    std::unique_lock<std::shared_mutex> lock(g_SocketsMapsMutex);
    auto inserted = g_UDPAssociateMap.emplace(s, entry);
    if (!inserted.second) Real_closesocket(entry.proxySocket);
    return result;
}

int WINAPI Mine_closesocket(SOCKET s)
{
	g_SocketsMapsMutex.lock();
	if (g_UDPAssociateMap.count(s)) {
		Real_closesocket(g_UDPAssociateMap[s].proxySocket);
		g_UDPAssociateMap.erase(s);
	}
	g_NonBlockingSockets.erase(s);
	g_SocketsMapsMutex.unlock();

	return Real_closesocket(s);
}

int WINAPI Mine_sendto(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
    if (!IsUDPSocket(s)) return Real_sendto(s, buf, len, flags, to, tolen);
    udp_association_entry_t entry{};
    if (!GetUdpRelay(s, to, tolen, entry)) return SOCKET_ERROR;
    if (len < 0 || (len && !buf)) return SocketError(WSAEFAULT);
    if (len > 65507 - 10) return SocketError(WSAEMSGSIZE);
    try {
        const auto* target = GetUdpSendTarget(*reinterpret_cast<const sockaddr_in*>(to), entry.udpProxyAddr);
        std::vector<char> packet(target->header.begin(), target->header.end());
        if (len) packet.insert(packet.end(), buf, buf + len);
        const int sent = Real_sendto(s, packet.data(), static_cast<int>(packet.size()), flags,
            reinterpret_cast<const sockaddr*>(&target->relay), sizeof(target->relay));
        return sent == SOCKET_ERROR ? sent : sent - 10;
    } catch (const std::bad_alloc&) { return SocketError(WSAENOBUFS); }
}

int WINAPI Mine_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iTolen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (!IsUDPSocket(s))
        return Real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
            dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
    udp_association_entry_t entry{};
    if (!GetUdpRelay(s, lpTo, iTolen, entry)) return SOCKET_ERROR;
    if (!lpBuffers || !dwBufferCount) return SocketError(WSAEINVAL);
    if (dwBufferCount > 65536) return SocketError(WSAENOBUFS);
    size_t payloadLength = 0;
    for (DWORD i = 0; i < dwBufferCount; ++i) {
        if (lpBuffers[i].len && !lpBuffers[i].buf) return SocketError(WSAEFAULT);
        payloadLength += lpBuffers[i].len;
        if (payloadLength > 65507 - 10) return SocketError(WSAEMSGSIZE);
    }
    try {
        const auto* target = GetUdpSendTarget(*reinterpret_cast<const sockaddr_in*>(lpTo), entry.udpProxyAddr);
        // Winsock captures the WSABUF DESCRIPTORS before returning, even for
        // pending I/O. The header and caller-owned payload bytes outlive them.
        std::vector<WSABUF> buffers;
        buffers.reserve(static_cast<size_t>(dwBufferCount) + 1);
        buffers.push_back({10, const_cast<char*>(target->header.data())});
        buffers.insert(buffers.end(), lpBuffers, lpBuffers + dwBufferCount);
        const int result = Real_WSASendTo(s, buffers.data(), static_cast<DWORD>(buffers.size()),
            lpNumberOfBytesSent, dwFlags, reinterpret_cast<const sockaddr*>(&target->relay),
            sizeof(target->relay), lpOverlapped, lpCompletionRoutine);
        if (result == 0 && lpNumberOfBytesSent && *lpNumberOfBytesSent >= 10)
            *lpNumberOfBytesSent -= 10;
        return result;
    } catch (const std::bad_alloc&) { return SocketError(WSAENOBUFS); }
}

int WINAPI Mine_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
	auto received = Real_recvfrom(s, buf, len, flags, from, fromlen);

	if (received != SOCKET_ERROR && SocketExistsInUdpAssociationMap(s)) {
		//Encapsulated header is 10 bytes
		if (received < 10) {
			return SOCKET_ERROR;
		}

		ExtractSockAddr(buf, from);

		memmove(buf, &buf[10], received -= 10);
	};

	return received;
}

int WINAPI Mine_WSARecvFrom(SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
	sockaddr* lpFrom,
	LPINT lpFromlen,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	DWORD received = 0;
	if (lpNumberOfBytesRecvd == NULL)
		lpNumberOfBytesRecvd = &received;

	auto status = Real_WSARecvFrom(
		s,
		lpBuffers,
		dwBufferCount,
		lpNumberOfBytesRecvd,
		lpFlags,
		lpFrom,
		lpFromlen,
		lpOverlapped,
		lpCompletionRoutine
	);

	if (status == ERROR_SUCCESS && SocketExistsInUdpAssociationMap(s)) {
		//Encapsulated header is 10 bytes
		if (*lpNumberOfBytesRecvd < 10) {
			return SOCKET_ERROR;
		}

		ExtractSockAddr(lpBuffers->buf, lpFrom);

		memmove(lpBuffers->buf, &lpBuffers->buf[10], *lpNumberOfBytesRecvd -= 10);
	}

	return status;
}

void InitHooks()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)(&Real_WSAEventSelect), Mine_WSAEventSelect);
	DetourAttach((PVOID*)(&Real_ioctlsocket), Mine_ioctlsocket);
	DetourAttach((PVOID*)(&Real_connect), Mine_connect);
	DetourAttach((PVOID*)(&Real_bind), Mine_bind);
	DetourAttach((PVOID*)(&Real_closesocket), Mine_closesocket);
	DetourAttach((PVOID*)(&Real_sendto), Mine_sendto);
	DetourAttach((PVOID*)(&Real_recvfrom), Mine_recvfrom);
	DetourAttach((PVOID*)(&Real_WSASendTo), Mine_WSASendTo);
	DetourAttach((PVOID*)(&Real_WSARecvFrom), Mine_WSARecvFrom);
	DetourTransactionCommit();
}

void DestroyHooks()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach((PVOID*)(&Real_WSAEventSelect), Mine_WSAEventSelect);
	DetourDetach((PVOID*)(&Real_ioctlsocket), Mine_ioctlsocket);
	DetourDetach((PVOID*)(&Real_connect), Mine_connect);
	DetourDetach((PVOID*)(&Real_bind), Mine_bind);
	DetourDetach((PVOID*)(&Real_closesocket), Mine_closesocket);
	DetourDetach((PVOID*)(&Real_sendto), Mine_sendto);
	DetourDetach((PVOID*)(&Real_recvfrom), Mine_recvfrom);
	DetourDetach((PVOID*)(&Real_WSASendTo), Mine_WSASendTo);
	DetourDetach((PVOID*)(&Real_WSARecvFrom), Mine_WSARecvFrom);
	DetourTransactionCommit();
}
