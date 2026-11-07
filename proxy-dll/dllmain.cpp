#include <windows.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <vector>
#include <detours/detours.h>
#include "proxy.h"
#include "proxy_config.h"
#pragma comment(lib, "detours.lib")

namespace fs = std::filesystem;

extern "C" BOOL(__stdcall * Real_CreateProcessW)(LPCWSTR a0,
	LPWSTR a1,
	LPSECURITY_ATTRIBUTES a2,
	LPSECURITY_ATTRIBUTES a3,
	BOOL a4,
	DWORD a5,
	LPVOID a6,
	LPCWSTR a7,
	LPSTARTUPINFOW a8,
	LPPROCESS_INFORMATION a9) = CreateProcessW;

HMODULE OriginalDLL;
uintptr_t OrignalDWriteCreateFactory;
uintptr_t OrignalGetFileVersionInfoSizeW;
uintptr_t OrignalGetFileVersionInfoW;
uintptr_t OrignalVerQueryValueW;

bool EndsWith(const std::wstring& fullString, const std::wstring& ending)
{
	if (ending.size() > fullString.size())
		return false;

	return fullString.compare(fullString.size() - ending.size(), ending.size(), ending) == 0;
}

BOOL __stdcall Mine_CreateProcessW(LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	;
	WCHAR path[MAX_PATH];
	GetModuleFileNameW(NULL, path, MAX_PATH);

	std::vector<std::wstring> files = {
		L"proxy.txt",
		L"force-proxy.dll",
		L"DWrite.dll"
	};

	if (lpApplicationName != NULL) {
		auto targetAppName = std::wstring(lpApplicationName);
		auto currentPath = std::wstring(path);

		if (EndsWith(targetAppName, L"Discord.exe") && targetAppName != currentPath) {
			auto currentDir = fs::path(currentPath).parent_path();
			auto targetDir = fs::path(targetAppName).parent_path();

			for (const auto& file : files) {
				if (fs::exists(currentDir.wstring() + L"\\" + file)) {
					fs::copy(currentDir.wstring() + L"\\" + file, targetDir.wstring() + L"\\" + file, fs::copy_options::overwrite_existing);
				}
			}
		}
	}

	return Real_CreateProcessW(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);
}

bool LoadForceProxy(HMODULE module)
{
	std::vector<wchar_t> path(32768);
	const DWORD size = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
	if (!size || size >= path.size()) return false;
	const auto directory = fs::path(path.data()).parent_path();
	if (!ApplyProxyConfig(directory)) return false;
	return LoadLibraryExW((directory / L"force-proxy.dll").c_str(), nullptr,
		LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32) != nullptr;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	wchar_t path[MAX_PATH];
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
		const UINT length = GetSystemDirectoryW(path, MAX_PATH);
		if (!length || length >= MAX_PATH) return FALSE;
		OriginalDLL = LoadLibraryW((fs::path(path) / L"DWrite.dll").c_str());
		if (OriginalDLL == NULL)
		{
			return FALSE;
		}
		OrignalDWriteCreateFactory = (uintptr_t)GetProcAddress(OriginalDLL, "DWriteCreateFactory");

		if (!OrignalDWriteCreateFactory || !LoadForceProxy(hModule)) {
			FreeLibrary(OriginalDLL);
			OriginalDLL = nullptr;
			return FALSE;
		}
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach((PVOID *)(&Real_CreateProcessW), Mine_CreateProcessW);
		DetourTransactionCommit();

		break;
	}
	case DLL_PROCESS_DETACH:
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach((PVOID*)(&Real_CreateProcessW), Mine_CreateProcessW);
		DetourTransactionCommit();

		FreeLibrary(OriginalDLL);

		break;
	}
	}
	return TRUE;
}
