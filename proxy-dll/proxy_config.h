#pragma once
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

inline bool ApplyProxyConfig(const std::filesystem::path& directory)
{
    static const char* keys[] = {
        "SOCKS5_PROXY_ADDRESS", "SOCKS5_PROXY_PORT", "SOCKS5_PROXY_TIMEOUT",
        "SOCKS5_PROXY_LOGIN", "SOCKS5_PROXY_PASSWORD", "SOCKS5_PROXY_PASSWORD_DPAPI"
    };
    std::map<std::string, std::string> values;
    std::error_code error;
    const auto config = directory / L"proxy.txt";
    if (std::filesystem::file_size(config, error) > 65536 || error)
        return false;
    std::ifstream file(config);
    if (!file) return false;
    std::string line;
    bool first = true;
    while (std::getline(file, line)) {
        if (first && line.compare(0, 3, "\xef\xbb\xbf") == 0) line.erase(0, 3);
        first = false;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto equals = line.find('=');
        if (equals == std::string::npos) continue;
        const auto key = line.substr(0, equals);
        for (const auto allowed : keys) {
            if (key == allowed) {
                if (line.find('\0') != std::string::npos) return false;
                values[key] = line.substr(equals + 1);
                break;
            }
        }
    }
    if (file.bad() || values["SOCKS5_PROXY_ADDRESS"].empty() || values["SOCKS5_PROXY_PORT"].empty())
        return false;

    // Do not inherit credentials/options left by another installation or parent.
    for (const auto key : keys) SetEnvironmentVariableA(key, nullptr);
    for (const auto& pair : values) {
        std::wstring key(pair.first.begin(), pair.first.end());
        const auto& value = pair.second;
        const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            value.c_str(), -1, nullptr, 0);
        if (!length) return false;
        std::vector<wchar_t> wide(length);
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.c_str(), -1, wide.data(), length) ||
            !SetEnvironmentVariableW(key.c_str(), wide.data())) return false;
    }
    return true;
}
