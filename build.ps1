[CmdletBinding()]
param([switch]$Test)

$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot
$vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswherePath)) {
    throw 'Install Visual Studio 2022 Build Tools with Desktop development with C++ and Windows SDK.'
}
$vsRoot = & $vswherePath -latest -products '*' -version '[17.0,18.0)' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsRoot) { throw 'Visual Studio 2022 C++ tools were not found.' }
$msbuildPath = Join-Path $vsRoot 'MSBuild\Current\Bin\MSBuild.exe'
$releaseDirectory = Join-Path $repoRoot 'x64\Release'
$intermediateDirectory = Join-Path $repoRoot '.build\obj'
$releaseProps = Join-Path $repoRoot 'scripts\Release.props'
$commonProperties = @('/nologo', '/m', '/v:minimal', '/p:Configuration=Release', '/p:Platform=x64',
    '/p:VcpkgEnabled=false', '/p:VcpkgEnableManifest=false', "/p:ForceImportBeforeCppTargets=$releaseProps")

function Build-Native([string]$Project, [string]$Name, [string]$Output) {
    $objectDirectory = Join-Path $intermediateDirectory $Name
    & $msbuildPath (Join-Path $repoRoot $Project) @commonProperties '/t:Build' "/p:OutDir=$Output\" "/p:IntDir=$objectDirectory\"
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $Name" }
}

Push-Location $repoRoot
try {
    Build-Native 'scripts\Detours.vcxproj' 'detours' (Join-Path $repoRoot '.build\lib')
    Build-Native 'third_party\force-proxy\src\force-proxy.vcxproj' 'force-proxy' $releaseDirectory
    Build-Native 'proxy-dll\discord-voice-proxy.vcxproj' 'DWrite' $releaseDirectory
    & dotnet build (Join-Path $repoRoot 'installer\DiscordProxyInstaller.csproj') -c Release --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Installer build failed.' }

    $binaries = foreach ($name in @('DWrite.dll', 'force-proxy.dll')) {
        $file = Join-Path $releaseDirectory $name
        [ordered]@{ file = "x64/Release/$name"; sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash }
    }
    $receipt = [ordered]@{
        forceProxyBaseCommit = '00ba992fc150f4ada7c4dccf7d2c49c9eab6ff83'
        forceProxySource = 'third_party/force-proxy (with local security fixes)'
        detoursVersion = '4.0.1'
        configuration = 'Release'
        architecture = 'x64'
        runtime = 'static CRT (/MT)'
        buildScript = 'build.ps1'
        binaries = @($binaries)
    }
    $receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $releaseDirectory 'build.json') -Encoding utf8

    if ($Test) {
        $pythonPath = (Get-Command python -ErrorAction Stop).Source
        & $pythonPath -c 'import struct; assert struct.calcsize("P") == 8, "Tests require x64 Python"'
        if ($LASTEXITCODE -ne 0) { throw 'Tests require x64 Python 3.' }
        Build-Native 'scripts\NativeTests.vcxproj' 'security-tests' (Join-Path $repoRoot '.build\tests')
        & (Join-Path $repoRoot '.build\tests\security-tests.exe')
        if ($LASTEXITCODE -ne 0) { throw 'Native security tests failed.' }
        & dotnet run --project (Join-Path $repoRoot 'tests\InstallerTests\InstallerTests.csproj') -c Release
        if ($LASTEXITCODE -ne 0) { throw 'Installer tests failed.' }
        # Bound isolated hook tests: a regression must not leave a hung process.
        & $pythonPath -c 'import subprocess,sys; subprocess.run([sys.executable, "tests/tcp_smoke.py", "x64/Release/force-proxy.dll"], timeout=30, check=True)'
        if ($LASTEXITCODE -ne 0) { throw 'TCP smoke test failed.' }
        & $pythonPath tests/network_security.py
        if ($LASTEXITCODE -ne 0) { throw 'Network security tests failed.' }
    }
    Write-Host "Built DLLs: $releaseDirectory"
    Write-Host ('Installer: ' + (Join-Path $repoRoot 'installer\bin\Release\net8.0-windows\DiscordProxyInstaller.exe'))
}
finally { Pop-Location }
