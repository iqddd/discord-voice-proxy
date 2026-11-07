using DiscordProxyInstaller;
using System.Security.Cryptography;
using System.Text;

static void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

const string password = "test-\u043f\u0430\u0440\u043e\u043b\u044c=123";
var config = Discord.CreateConfig("127.0.0.1", "10808", "user", password);
Check(!string.Join('\n', config).Contains(password), "Plaintext password leaked");
var encoded = config.Single(s => s.StartsWith("SOCKS5_PROXY_PASSWORD_DPAPI="))
    .Split('=', 2)[1];
var decoded = ProtectedData.Unprotect(Convert.FromBase64String(encoded), null, DataProtectionScope.CurrentUser);
Check(Encoding.UTF8.GetString(decoded) == password, "DPAPI roundtrip failed");
try { Discord.CreateConfig("host\nPATH=bad", "10808", "", ""); throw new Exception("Injection accepted"); }
catch (ArgumentException) { }

var root = Path.Combine(Path.GetTempPath(), "discord-proxy-tests-" + Guid.NewGuid());
Directory.CreateDirectory(root);
foreach (var version in new[] { "app-1.0.1", "app-1.0.2" })
{
    var dir = Directory.CreateDirectory(Path.Combine(root, version)).FullName;
    foreach (var file in new[] { "DWrite.dll", "force-proxy.dll", "proxy.txt", "Discord.exe", "keep.txt" })
        File.WriteAllText(Path.Combine(dir, file), "test");
}
var unrelated = Directory.CreateDirectory(Path.Combine(root, "app-backup")).FullName;
File.WriteAllText(Path.Combine(unrelated, "proxy.txt"), "keep");
Discord.RemoveProxyFiles(root);
Discord.RemoveProxyFiles(root); // Idempotent, including partial prior removal.
foreach (var dir in Discord.GetVersionDirectories(root))
{
    foreach (var file in new[] { "DWrite.dll", "force-proxy.dll", "proxy.txt" })
        Check(!File.Exists(Path.Combine(dir, file)), "Leftover proxy file");
    Check(File.Exists(Path.Combine(dir, "Discord.exe")) && File.Exists(Path.Combine(dir, "keep.txt")), "Unrelated file removed");
}
Check(File.Exists(Path.Combine(unrelated, "proxy.txt")), "Non-version directory changed");
var builtInstaller = Path.GetFullPath("installer/bin/Release/net8.0-windows/DiscordProxyInstaller.dll");
if (File.Exists(builtInstaller))
{
    var assembly = System.Reflection.Assembly.LoadFile(builtInstaller);
    foreach (var name in new[] { "DWrite.dll", "force-proxy.dll" })
    {
        using var stream = assembly.GetManifestResourceStream("DiscordProxyInstaller." + name)
            ?? throw new Exception("Missing resource: " + name);
        using var binary = File.OpenRead(Path.Combine("x64", "Release", name));
        Check(SHA256.HashData(stream).SequenceEqual(SHA256.HashData(binary)), "Stale embedded DLL: " + name);
    }
    Console.WriteLine("PASS: installer embeds both current DLLs byte-for-byte");
}
Console.WriteLine("PASS: DPAPI password roundtrip; config injection rejected; all versions cleaned; unrelated files preserved; uninstall idempotent");
Console.WriteLine("Fixture: " + root);
