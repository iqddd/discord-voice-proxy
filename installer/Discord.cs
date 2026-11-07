using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DiscordProxyInstaller
{
    internal class Discord
    {
        public static bool Exists()
        {
            return Directory.Exists(GetRootDirectory()) && Directory.Exists(GetAppDirectory());
        }

        public static string GetRootDirectory()
        {
            return Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Discord");
        }

        public static string GetAppDirectory()
        {
            var root = GetRootDirectory();
            var result = "";

            foreach (var item in Directory.GetDirectories(root))
            {
                var dir = Path.GetFileName(item);
                if (dir.StartsWith("app-"))
                {
                    var version = dir.Split("app-")[1];
                    if (result == "" || new Version(result).CompareTo(new Version(version)) < 0)
                    {
                        result = version;
                    }
                }
            }

            return Path.Join(root, "app-" + result);
        }

        public static void Install(string host, string port, string login = "", string password = "")
        {
            var appDir = GetAppDirectory();

            // Prepare the config before replacing files, so protection failures
            // cannot leave a partially installed proxy with stale credentials.
            var lines = CreateConfig(host, port, login, password);

            WriteResourceToFile("DWrite.dll", Path.Join(appDir, "DWrite.dll"));
            WriteResourceToFile("force-proxy.dll", Path.Join(appDir, "force-proxy.dll"));

            File.WriteAllLines(Path.Join(appDir, "proxy.txt"), lines);
        }

        internal static string[] CreateConfig(string host, string port, string login, string password)
        {
            foreach (var value in new[] { host, port, login, password })
                if (value.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
                    throw new ArgumentException("Proxy settings cannot contain line breaks or NUL.");

            var plaintext = Encoding.UTF8.GetBytes(password);
            string protectedPassword;
            try
            {
                protectedPassword = Convert.ToBase64String(ProtectedData.Protect(
                    plaintext, null, DataProtectionScope.CurrentUser));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }

            return new string[] {
                "SOCKS5_PROXY_ADDRESS=" + host,
                "SOCKS5_PROXY_PORT=" + port,
                "SOCKS5_PROXY_LOGIN=" + login,
                "SOCKS5_PROXY_PASSWORD_DPAPI=" + protectedPassword,
            };
        }

        public static void Run()
        {
            var appDir = GetAppDirectory();
            var exePath = Path.Combine(appDir, "Discord.exe");

            Process process = new Process();
            process.StartInfo.FileName = exePath;
            process.StartInfo.WorkingDirectory = appDir;
            process.Start();
        }

        public static void InstallAndRun(string host, string port, string login = "", string password = "")
        {
            Kill();
            Install(
              host,
              port,
              login,
              password
            );
            Run();
        }

        public static bool IsInstalled()
        {
            return GetVersionDirectories(GetRootDirectory()).Any(dir =>
                ProxyFiles.Any(file => File.Exists(Path.Join(dir, file))));
        }

        public static void Uninstall()
        {
            Kill();
            RemoveProxyFiles(GetRootDirectory());
        }

        private static readonly string[] ProxyFiles = { "proxy.txt", "DWrite.dll", "force-proxy.dll" };

        internal static IEnumerable<string> GetVersionDirectories(string root)
        {
            if (!Directory.Exists(root) ||
                (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
                yield break;

            foreach (var dir in Directory.EnumerateDirectories(root, "app-*"))
            {
                if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) == 0 &&
                    Version.TryParse(Path.GetFileName(dir)[4..], out _))
                    yield return dir;
            }
        }

        internal static void RemoveProxyFiles(string root)
        {
            var failures = new List<Exception>();
            foreach (var dir in GetVersionDirectories(root))
            {
                foreach (var file in ProxyFiles)
                {
                    try { File.Delete(Path.Join(dir, file)); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    { failures.Add(ex); }
                }
            }
            if (failures.Count != 0)
                throw new AggregateException("Some proxy files could not be removed.", failures);
        }

        public static void Kill()
        {
            foreach (var process in Process.GetProcessesByName("Discord"))
            {
                process.Kill();
            }

            Thread.Sleep(1000);
        }

        private static void WriteResourceToFile(string resourceName, string fileName)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using (var resource = assembly.GetManifestResourceStream(assembly.GetName().Name + "." + resourceName)
                ?? throw new InvalidOperationException("Missing embedded resource: " + resourceName))
            {
                using (var file = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                {
                    resource.CopyTo(file);
                }
            }
        }
    }
}
