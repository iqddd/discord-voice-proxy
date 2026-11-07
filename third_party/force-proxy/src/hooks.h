#pragma once

extern "C" {
	extern int (WINAPI* Real_connect)(SOCKET s, const sockaddr* name, int namelen);

	extern int (WINAPI* Real_bind)(SOCKET s, const sockaddr* addr, int namelen);

	extern int (WINAPI* Real_closesocket)(SOCKET s);

	extern int (WINAPI* Real_sendto)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);

	extern int (WINAPI* Real_recvfrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);

	extern int (WINAPI* Real_WSASendTo)(
		SOCKET s,
		LPWSABUF lpBuffers,
		DWORD dwBufferCount,
		LPDWORD lpNumberOfBytesSent,
		DWORD dwFlags,
		const sockaddr* lpTo,
		int iTolen,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

	extern int (WINAPI* Real_WSARecvFrom)(
		SOCKET s,
		LPWSABUF lpBuffers,
		DWORD dwBufferCount,
		LPDWORD lpNumberOfBytesRecvd,
		LPDWORD lpFlags,
		sockaddr* lpFrom,
		LPINT lpFromlen,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

	extern int (WSAAPI* Real_WSAEventSelect)(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents);

	extern int (WSAAPI* Real_ioctlsocket)(SOCKET s, long cmd, u_long* argp);
}


void InitHooks();
void DestroyHooks();