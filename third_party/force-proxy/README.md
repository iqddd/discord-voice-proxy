# Force-Proxy

This is a DLL that hooks a few [Winsock 2](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2) APIs to redirect TCP and UDP sockets to a SOCKS5 proxy.

Both blocking and non-blocking sockets are supported.

SOCKS5 login/password authentication are supported.

## Motivation

Sometimes there is a need to redirect traffic of some application to SOCKS5 proxy, which does not have such functionality. 

This is an attempt to provide a free and fully open source alternative to commercial solutions for process proxification.

## How it works

Once injected into the target process, this DLL hooks several Winsock 2 APIs using [Microsoft Detours](https://github.com/microsoft/Detours).

For TCP, just change the connection target to a proxy server and send a socks5 CONNECT request.

For UDP, socks5 UDP ASSOCIATE is requested during bind. All UDP packets are then encapsulated and sent to the associated port of the proxy server. For incoming packets, the correct sender is restored from the header and the packet is decapsulated.

Here is the list of Winsock 2 APIs that are hooked:

1. [connect](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect) - for TCP redirection
2. [bind](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-bind) - good time to request UDP ASSOCIATE
3. [sendto](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-sendto) and [WSASendTo](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-WSASendTo) - to encapsulate a UDP packet and redirect it to a proxy
4. [recvfrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom) and [WSARecvFrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-WSARecvFrom) - to decapsulate a UDP packet and restore the sender field
5. [ioctlsocket](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-ioctlsocket) and [WSAEventSelect](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-WSAEventSelect) - to determine that socket is set to non-blocking mode
6. [closesocket](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-closesocket) - to cleanup

## Limitations

Currently only IPv4 support is implemented.

## Real usage examples

[@runetfreedom/discord-voice-proxy](https://github.com/runetfreedom/discord-voice-proxy) - project that uses DLL Hijacking to load this DLL into Discord processes to redirect all traffic (including WebRTC) to the proxy.

## Be careful

**Do not try to inject this DLL into games protected by anti-cheat!** 

From an anti-cheat point of view, injecting an unsigned DLL and hooking system calls looks like typical cheat behavior, so you will most likely be banned.

## Getting started

Just find any of the thousands of DLL injectors and inject that DLL into the target process.

You can pass parameters using environment variables:

1. `SOCKS5_PROXY_ADDRESS` - proxy ip address
2. `SOCKS5_PROXY_PORT` - proxy port
3. `SOCKS5_PROXY_TIMEOUT` - proxy connection timeout (optional)
3. `SOCKS5_PROXY_LOGIN` - proxy login (optional)
3. `SOCKS5_PROXY_PASSWORD` - proxy password (optional)