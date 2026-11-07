# Security fixes and local builds

The loader, installer and network changes are in this repository. The patched
network library is vendored in `third_party/force-proxy`, based on commit
`00ba992fc150f4ada7c4dccf7d2c49c9eab6ff83`. Both DLLs must be updated together.

## Behavior

- IPv6 calls intercepted by the library return `WSAEAFNOSUPPORT`. UDP without a
  successful SOCKS5 association fails instead of falling back to direct delivery.
  Connected UDP and multicast/broadcast are explicitly unsupported and rejected.
  This does not add coverage for other, previously unhooked Winsock APIs or DNS.
- SOCKS5 handshakes handle partial reads/writes and reject errors, truncated
  replies and unsupported reply address types. Failed associations close their
  control sockets.
- `WSASendTo` passes the application's original buffers plus an immutable SOCKS5
  header to Winsock. The caller must keep its payload buffers valid until I/O
  completion, as required by Winsock. Headers and relay addresses remain alive
  for the process lifetime; storage is capped at 4096 destination/relay pairs.
  Native completion paths are retained. As before, asynchronous completion byte
  counts include the 10-byte wire header; immediate return byte counts exclude it.
- The installer stores the password as `SOCKS5_PROXY_PASSWORD_DPAPI`, protected
  for the current Windows user. `force-proxy` decrypts it at the first handshake,
  outside the loader lock. Existing manual `SOCKS5_PROXY_PASSWORD` configs remain
  supported; reinstall to replace an existing plaintext config with DPAPI.
- Uninstall removes `proxy.txt`, `DWrite.dll` and `force-proxy.dll` from every
  version directory under `%LocalAppData%\Discord`. Junction directories are
  skipped. Other files are retained; deletion failures are reported.
- Config and dependency paths are relative to the loaded `DWrite.dll`, not the
  working directory. Only the six documented `SOCKS5_PROXY_*` keys are accepted
  (address, port, timeout, login, password, password_DPAPI). Unknown keys are
  ignored. Missing/invalid config or a missing dependency fails DLL loading.

## Local rebuild and checks

From PowerShell, run `./build.ps1 -Test` to compile Detours, both DLLs and the
installer, then run the regression checks. Use `./build.ps1` for compilation only.
The script finds Visual Studio 2022 using `vswhere`; no developer shell is needed.
Prerequisites: Visual Studio 2022 C++ tools and Windows SDK, .NET 8 SDK, and x64
Python 3 for tests. NuGet access is required for the first .NET package restore.

Build configuration is in `scripts/Release.props`: MSVC v143, x64 Release,
C++17 and static CRT. Detours 4.0.1 is built from its vendored source, without
vcpkg. Dependency provenance and licenses are recorded in `third_party/README.md`.
No adjacent checkouts or external build directories are used.

Outputs:

- `x64/Release/DWrite.dll` and `x64/Release/force-proxy.dll`.
- `installer/bin/Release/net8.0-windows/DiscordProxyInstaller.exe` and its runtime
  files; keep the entire output directory together when running the installer.
- `x64/Release/build.json` with build settings and binary SHA256 hashes.
- `.build/` with intermediate objects, the Detours static library and native tests.

Build outputs and caches are ignored by Git. The source, scripts and configuration
are tracked, so a fresh clone can be rebuilt at another location.

Tests use temporary directories and isolated processes, not the installed Discord.
The native tests simulate pending I/O and inspect the captured buffers after the
hook has returned. Integration tests cover DPAPI authentication, a hostile working
directory, fragmented SOCKS5 replies, proxy refusal and truncated responses.
The successful UDP relay integration test is skipped if ordinary loopback UDP
does not work before loading the DLL; it was unavailable on the build machine.
Discord voice calls have not been tested.
