# Vendored native dependencies

These source snapshots are checked in so building does not depend on adjacent
checkouts, prebuilt third-party DLLs, vcpkg or machine-specific absolute paths.

## force-proxy

- Upstream: https://github.com/runetfreedom/force-proxy
- Base commit: `00ba992fc150f4ada7c4dccf7d2c49c9eab6ff83`
- License: GPL-3.0, preserved in `force-proxy/LICENSE.txt`.
- Snapshot includes local security fixes described in `../SECURITY-FIXES.md` and
  the native regression test. Upstream vcpkg manifests are omitted because the
  top-level build uses the Detours sources included here.

## Microsoft Detours

- Upstream: https://github.com/microsoft/Detours
- Version: `v4.0.1`
- Source archive: https://github.com/microsoft/Detours/archive/v4.0.1.tar.gz
- Archive SHA512:
  `0a9c21b8222329add2de190d2e94d99195dfa55de5a914b75d380ffe0fb787b12e016d0723ca821001af0168fd1643ffd2455298bf3de5fdc155b3393a3ccc87`
- License: MIT, preserved in `detours/LICENSE.md`.
- `detours/src`, upstream README and credits are copied unchanged from the
  verified archive. `detours/detours.h` is a local include shim. The local
  `scripts/Detours.vcxproj` builds the library from source with static CRT.

The .NET installer additionally restores `System.Security.Cryptography.ProtectedData`
8.0.0 from NuGet using its project declaration.
