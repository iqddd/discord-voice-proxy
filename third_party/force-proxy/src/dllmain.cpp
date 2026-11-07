#include "stdafx.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "detours.lib")

IN_ADDR g_ProxyAddress;
uint16_t g_ProxyPort;
uint32_t g_ProxyTimeout;
char g_ProxyLogin[256];
char g_ProxyPassword[256];
std::string g_ProxyEncryptedPassword;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        {

            char addressBuff[MAX_PATH] = "127.0.0.1";
            char portBuff[MAX_PATH] = "12334";
            char timeoutBuff[MAX_PATH];

            DisableThreadLibraryCalls(hModule);
            DetourRestoreAfterWith();

            GetEnvironmentVariableA("SOCKS5_PROXY_ADDRESS", addressBuff, sizeof(addressBuff));
            GetEnvironmentVariableA("SOCKS5_PROXY_PORT", portBuff, sizeof(portBuff));

            g_ProxyLogin[0] = '\0';
            g_ProxyPassword[0] = '\0';
            const auto readUtf8 = [](const wchar_t* key, char* output, int capacity) {
                wchar_t value[256]{};
                const DWORD length = GetEnvironmentVariableW(key, value, 256);
                if (length >= 256) return false;
                if (!length) { output[0] = 0; return true; }
                return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1,
                    output, capacity, nullptr, nullptr) != 0;
            };
            if (!readUtf8(L"SOCKS5_PROXY_LOGIN", g_ProxyLogin, sizeof(g_ProxyLogin)) ||
                !readUtf8(L"SOCKS5_PROXY_PASSWORD", g_ProxyPassword, sizeof(g_ProxyPassword))) return FALSE;
            char encrypted[8192]{};
            const DWORD encryptedLength = GetEnvironmentVariableA("SOCKS5_PROXY_PASSWORD_DPAPI", encrypted, sizeof(encrypted));
            if (encryptedLength >= sizeof(encrypted)) return FALSE;
            g_ProxyEncryptedPassword.assign(encrypted, encryptedLength);
            // The DLL owns these values now; don't expose the password to children.
            SetEnvironmentVariableA("SOCKS5_PROXY_PASSWORD", nullptr);
            SetEnvironmentVariableA("SOCKS5_PROXY_PASSWORD_DPAPI", nullptr);

            if (inet_pton(AF_INET, addressBuff, &g_ProxyAddress) != 1) return FALSE;
            char* portEnd = nullptr;
            const long port = strtol(portBuff, &portEnd, 10);
            if (portEnd == portBuff || *portEnd || port <= 0 || port > 65535) return FALSE;
            g_ProxyPort = htons(static_cast<uint16_t>(port));

            DWORD timeoutEnvLen = GetEnvironmentVariableA("SOCKS5_PROXY_TIMEOUT", timeoutBuff, sizeof(timeoutBuff) - 1);
            if (timeoutEnvLen == 0 || timeoutEnvLen >= (sizeof(timeoutBuff) - 1) ) {
                g_ProxyTimeout = 30;
            } else {
                timeoutBuff[timeoutEnvLen] = '\0';
                char* endPtr;
                long val = strtol(timeoutBuff, &endPtr, 10);
                if (endPtr == timeoutBuff || *endPtr != '\0' || val <= 0) {
                    g_ProxyTimeout = 30;
                } else {
                    g_ProxyTimeout = static_cast<uint32_t>(val);
                }
            }

            InitHooks();
        }
        break;

    case DLL_PROCESS_DETACH:
        DestroyHooks();
        break;
    }
    return TRUE;
}
