<#
.SYNOPSIS
    Offline-Werkzeug zum Anonymisieren von Netzwerk-Logs, Show-Techs und Konfigurationen.
    Kompatibel mit Windows PowerShell 5.1+ und PowerShell 7+, ohne externe Module und ohne Netzwerkzugriffe.

.DESCRIPTION
    Ersetzt sensible Infrastruktur-Daten (IPv4/IPv6 inkl. netzerhaltendem Modus NET-x.Hy, MAC-Adressen,
    Hostnamen, FQDNs, E-Mail-Adressen, URLs, Benutzernamen, Seriennummern, Freitext-Felder sowie
    pflegbare Begriffe aus anon-regeln.json) konsistent über alle Dateien eines Laufs.
    Entfernt Geheimnisse (Passwörter, Hashes, Keys, SNMP-Communities, PEM-Zertifikate, Hex/Base64-Blobs)
    unwiderruflich durch *****.
    Speichert die Zuordnungstabelle strikt getrennt vom Ausgabeordner (Standard: %LOCALAPPDATA%\Anon\Tabellen\),
    geschützt per NTFS-ACL auf den aktuellen Benutzer und optional verschlüsselt (DPAPI oder AES-256).
    Freigegeben wird ausschließlich <Ausgabe>\anonym\. Archive werden unter %LOCALAPPDATA%\Anon\arbeit\<zufall>\
    entpackt (ACL nur Benutzer); dieser Ordner wird nach jedem Lauf gelöscht, auch bei Fehler oder Abbruch.

.PARAMETER Eingabe
    Pfad zu einer Datei, einem Ordner oder einem Archiv (.zip, .tar.gz, .tgz). Mehrfachangabe möglich.

.PARAMETER Ausgabe
    Zielordner. Die anonymisierten Dateien landen in <Ausgabe>\anonym\, der Bericht in <Ausgabe>\bericht.json.

.PARAMETER Regeln
    Pfad zur Regeldatei (Standard: anon-regeln.json im Skriptordner, sonst ..\regeln\anon-regeln.json).

.PARAMETER TabellenPfad
    Pfad zur Zuordnungstabelle zum Weiterverwenden oder Speichern.
    Standard: %LOCALAPPDATA%\Anon\Tabellen\tabelle-<Zeitstempel>.json
    Darf NIEMALS innerhalb des Ausgabeordners liegen!

.PARAMETER Tabelle
    Alias für -TabellenPfad (bestehende Zuordnungstabelle weiterverwenden).

.PARAMETER Dpapi
    Verschlüsselt die Zuordnungstabelle zusätzlich mit Windows DPAPI (CurrentUser).
    Unter Windows ist DPAPI für neue Tabellen standardmäßig aktiv, sofern nicht -MitPasswort oder -Unverschluesselt angegeben wird.

.PARAMETER MitPasswort
    Fragt ein Passwort (mindestens 12 Zeichen) sicher über Read-Host -AsSecureString ab (beim Verschlüsseln zweimal zur Bestätigung)
    und verschlüsselt die Zuordnungstabelle im Format ANON-AES256-2 (PBKDF2-SHA1 mit 600.000 Iterationen, getrennte AES/HMAC-Schlüssel).
    Kein Klartext-Passwort in der Befehlszeile oder PowerShell-Historie.

.PARAMETER Unverschluesselt
    Speichert die Zuordnungstabelle explizit unverschlüsselt im Klartext (nur mit NTFS-ACL/chmod-Schutz).
    Ohne diesen Schalter behalten geladene verschlüsselte Tabellen ihren Schutz bei und neue Tabellen werden unter Windows mit DPAPI geschützt.

.PARAMETER Zurueck
    Rückübersetzungs-Modus: Übersetzt eine Textdatei (z.B. KI-Antwort) mithilfe von -TabellenPfad wieder in echte Werte.
    Ziel: -Ausgabe (Datei; bei mehreren Eingaben Ordner) oder standardmäßig %LOCALAPPDATA%\Anon\klartext\ (ACL nur Benutzer).
    Der Klartext wird nie auf der Konsole ausgegeben und nie unterhalb von anonym\ oder in einem Ausgabeordner eines Laufs gespeichert.

.PARAMETER Pruefen
    Führt nur den Prüfmodus auf den angegebenen Dateien/Ordnern aus und gibt "SAUBER" bei 0 Treffern zurück.

.PARAMETER Probe
    Trockenlauf: Zeigt nur, was ersetzt würde (Anzahl je Kategorie), schreibt keine anonymisierten Dateien.

.PARAMETER Netzerhaltend
    Schalter: netzerhaltender Modus (NET-x.Hy) unabhängig von der Einstellung 'netzerhaltend' in anon-regeln.json.

.PARAMETER NichtNetzerhaltend
    Schalter: IPs als IP-PRIV-n / IP-PUB-n statt netzerhaltend. Nicht zusammen mit -Netzerhaltend verwendbar.

.PARAMETER Kategorien
    Kommagetrennte Liste aktiver Kategorien (z.B. "ip,mac,hostnamen,geheimnisseEntfernen").
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string[]]$Eingabe,

    [Parameter(Mandatory = $false)]
    [string]$Ausgabe,

    [Parameter(Mandatory = $false)]
    [string]$Regeln,

    [Parameter(Mandatory = $false)]
    [string]$LokaleRegeln,

    [Parameter(Mandatory = $false)]
    [Alias("Tabelle")]
    [string]$TabellenPfad,

    [Parameter(Mandatory = $false)]
    [switch]$Dpapi,

    [Parameter(Mandatory = $false)]
    [switch]$MitPasswort,

    [Parameter(Mandatory = $false)]
    [switch]$Unverschluesselt,

    [Parameter(Mandatory = $false, DontShow = $true)]
    [SecureString]$PasswortSecure,

    [Parameter(Mandatory = $false)]
    [switch]$Zurueck,

    [Parameter(Mandatory = $false)]
    [switch]$Pruefen,

    [Parameter(Mandatory = $false)]
    [switch]$Probe,

    [Parameter(Mandatory = $false)]
    [switch]$Netzerhaltend,

    [Parameter(Mandatory = $false)]
    [switch]$NichtNetzerhaltend,

    [Parameter(Mandatory = $false)]
    [string[]]$Kategorien
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# Eingebettete C#-Engine für hohe Performance (Dateien bis 50 MB / Show-Techs)
# ============================================================================
$csharpCode = @'
using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace AnonTool
{
    // Passwort-Behandlung ohne verwalteten Klartext-String: SecureString -> UTF-8-Bytes -> PBKDF2,
    // alle Zwischenpuffer werden danach mit Nullen überschrieben.
    public static class AnonCrypto
    {
        // PBKDF2 mit SHA256 gibt es ab .NET Framework 4.7.2 (Rfc2898DeriveBytes mit HashAlgorithmName)
        public static bool Sha256KdfAvailable()
        {
            return GetSha256Ctor() != null;
        }

        private static ConstructorInfo GetSha256Ctor()
        {
            Type han = typeof(Rfc2898DeriveBytes).Assembly.GetType("System.Security.Cryptography.HashAlgorithmName");
            if (han == null) return null;
            return typeof(Rfc2898DeriveBytes).GetConstructor(new Type[] { typeof(byte[]), typeof(byte[]), typeof(int), han });
        }

        public static void Zero(byte[] b)
        {
            if (b != null) Array.Clear(b, 0, b.Length);
        }

        public static byte[] SecureStringToUtf8(SecureString s)
        {
            if (s == null) return new byte[0];
            IntPtr ptr = IntPtr.Zero;
            char[] chars = new char[s.Length];
            try
            {
                ptr = Marshal.SecureStringToGlobalAllocUnicode(s);
                Marshal.Copy(ptr, chars, 0, chars.Length);
                return new UTF8Encoding(false).GetBytes(chars);
            }
            finally
            {
                Array.Clear(chars, 0, chars.Length);
                if (ptr != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        public static bool SecureStringEquals(SecureString a, SecureString b)
        {
            byte[] x = SecureStringToUtf8(a);
            byte[] y = SecureStringToUtf8(b);
            try
            {
                if (x.Length != y.Length) return false;
                int diff = 0;
                for (int i = 0; i < x.Length; i++) diff |= x[i] ^ y[i];
                return diff == 0;
            }
            finally
            {
                Zero(x);
                Zero(y);
            }
        }

        public static byte[] DeriveMasterKey(SecureString password, byte[] salt, int iterations, bool sha256)
        {
            byte[] pw = SecureStringToUtf8(password);
            try
            {
                DeriveBytes kdf;
                if (sha256)
                {
                    ConstructorInfo ci = GetSha256Ctor();
                    if (ci == null) throw new InvalidOperationException("PBKDF2-SHA256 benötigt .NET Framework 4.7.2 oder neuer.");
                    Type han = ci.GetParameters()[3].ParameterType;
                    object sha = han.GetProperty("SHA256").GetValue(null, null);
                    kdf = (DeriveBytes)ci.Invoke(new object[] { pw, salt, iterations, sha });
                }
                else
                {
                    // über Reflection: in .NET 9 (pwsh 7) ist der Konstruktor als veraltet markiert (SYSLIB0060)
                    kdf = (DeriveBytes)Activator.CreateInstance(typeof(Rfc2898DeriveBytes), new object[] { pw, salt, iterations });
                }
                using (kdf)
                {
                    return kdf.GetBytes(32);
                }
            }
            finally
            {
                Zero(pw);
            }
        }
    }

    public class AnonState
    {
        public Dictionary<string, string> Forward = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Reverse = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> Counters = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Dictionary<string, string>> NetHostForward = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> Stats = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public string LoadedProtection = "NONE";

        public int NextCounter(string prefix)
        {
            int val = 0;
            if (Counters.TryGetValue(prefix, out val))
            {
                val++;
                Counters[prefix] = val;
                return val;
            }
            Counters[prefix] = 1;
            return 1;
        }

        public void AddStat(string category, int count = 1)
        {
            if (count <= 0) return;
            int cur = 0;
            if (Stats.TryGetValue(category, out cur))
                Stats[category] = cur + count;
            else
                Stats[category] = count;
        }

        public string GetOrCreateToken(string categoryKey, string rawValue, string prefix, string reverseDisplayVal = null)
        {
            string lookupKey = categoryKey + "|" + rawValue.Trim().ToLowerInvariant();
            string existing;
            if (Forward.TryGetValue(lookupKey, out existing))
                return existing;

            int num = NextCounter(prefix);
            string token = prefix + "-" + num.ToString();
            Forward[lookupKey] = token;
            if (!Reverse.ContainsKey(token))
                Reverse[token] = string.IsNullOrEmpty(reverseDisplayVal) ? rawValue.Trim() : reverseDisplayVal.Trim();
            return token;
        }

        public void RegisterFixed(string rawValue, string token)
        {
            string lookupKey = "FIXED|" + rawValue.Trim().ToLowerInvariant();
            Forward[lookupKey] = token;
            if (!Reverse.ContainsKey(token))
                Reverse[token] = rawValue;
        }
    }

    public class SecretRule
    {
        public string Name;
        public string Pattern;
        public string Replacement;
        public Regex Compiled;
    }

    public class FreeTextRule
    {
        public string Name;
        public string Category;
        public string Pattern;
        public Regex Compiled;
    }

    public class TableColumnSpec
    {
        public string Name;
        public string Kategorie;
    }

    public class TableRule
    {
        public string Name;
        public List<string> Kopf = new List<string>();
        public List<TableColumnSpec> Spalten = new List<TableColumnSpec>();
    }

    public class TableField
    {
        public int Start;
        public int Length;
        public int Zeile;
        public string Kategorie;
        public string Wert;
    }

    public class AuditFinding
    {
        public string Datei;
        public int Zeile;
        public string Kategorie;
        public string Fund;
        public string Kontext;
    }

    public class EngineConfig
    {
        public bool Netzerhaltend = true;
        public bool IpPrivatOeffentlichTrennen = true;
        public bool SubnetzmaskenBehalten = true;
        public bool MacNormalisieren = true;

        public bool CatGeheimnisse = true;
        public bool CatIp = true;
        public bool CatMac = true;
        public bool CatHostnamen = true;
        public bool CatBenutzer = true;
        public bool CatSeriennummern = true;
        public bool CatFreitext = true;
        public bool CatEigeneBegriffe = true;

        public Dictionary<string, string> FesteZuordnung = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public List<string> FirmenUndStandorte = new List<string>();
        public List<string> InterneDomains = new List<string>();
        public HashSet<string> ExakteAusnahmen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public List<Regex> VersionKontextRegex = new List<Regex>();
        public List<Regex> AusnahmenRegex = new List<Regex>();
        public HashSet<string> PruefungErlaubtListe = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public List<Regex> PruefungErlaubtMuster = new List<Regex>();

        public List<SecretRule> GeheimnisMuster = new List<SecretRule>();
        public List<FreeTextRule> FreitextMuster = new List<FreeTextRule>();
        public List<Regex> SeriennummerMuster = new List<Regex>();
        public List<Regex> BenutzerMuster = new List<Regex>();
        public List<Regex> HostnamenMuster = new List<Regex>();
        public List<TableRule> TabellenSpalten = new List<TableRule>();
    }

    public static class TarGzHelper
    {
        public static bool IsBinaryContent(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return false;
            int checkLen = Math.Min(bytes.Length, 8192);
            // Check UTF-16 BOM
            if (bytes.Length >= 2 && ((bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == 0xFE && bytes[1] == 0xFF)))
                return false;
            int nullCount = 0;
            int controlCount = 0;
            for (int i = 0; i < checkLen; i++)
            {
                byte b = bytes[i];
                if (b == 0)
                {
                    nullCount++;
                    if (nullCount >= 2) return true;
                }
                else if (b < 7 || (b > 14 && b < 32 && b != 27))
                {
                    controlCount++;
                }
            }
            if (nullCount > 0) return true;
            if (checkLen > 32 && ((double)controlCount / checkLen) > 0.15) return true;
            return false;
        }

        public static string DecodeTextWithBom(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return string.Empty;
            using (MemoryStream ms = new MemoryStream(bytes))
            using (StreamReader sr = new StreamReader(ms, Encoding.UTF8, true))
            {
                return sr.ReadToEnd();
            }
        }

        public static void ExtractTarGz(string archivePath, string destDir)
        {
            using (FileStream fs = File.OpenRead(archivePath))
            using (GZipStream gz = new GZipStream(fs, CompressionMode.Decompress))
            {
                ExtractTarStream(gz, destDir);
            }
        }

        public static void ExtractTar(string archivePath, string destDir)
        {
            using (FileStream fs = File.OpenRead(archivePath))
            {
                ExtractTarStream(fs, destDir);
            }
        }

        private static int ReadExact(Stream s, byte[] buf, int offset, int count)
        {
            int total = 0;
            while (total < count)
            {
                int r = s.Read(buf, offset + total, count - total);
                if (r <= 0) break;
                total += r;
            }
            return total;
        }

        public static void ExtractTarStream(Stream stream, string destDir)
        {
            byte[] header = new byte[512];
            string fullDestRoot = Path.GetFullPath(destDir);
            if (!fullDestRoot.EndsWith(Path.DirectorySeparatorChar.ToString()))
                fullDestRoot += Path.DirectorySeparatorChar;

            while (true)
            {
                int read = ReadExact(stream, header, 0, 512);
                if (read < 512) break;

                bool allZero = true;
                for (int i = 0; i < 512; i++)
                {
                    if (header[i] != 0) { allZero = false; break; }
                }
                if (allZero) break;

                string name = Encoding.ASCII.GetString(header, 0, 100).TrimEnd('\0', ' ');
                string prefix = Encoding.ASCII.GetString(header, 345, 155).TrimEnd('\0', ' ');
                if (!string.IsNullOrEmpty(prefix))
                    name = prefix + "/" + name;

                string sizeOctal = Encoding.ASCII.GetString(header, 124, 12).Trim('\0', ' ');
                long size = 0;
                if (!string.IsNullOrEmpty(sizeOctal))
                {
                    try { size = Convert.ToInt64(sizeOctal, 8); }
                    catch { size = 0; }
                }

                byte typeFlag = header[156];
                string relPath = name.Replace('/', Path.DirectorySeparatorChar).TrimStart(Path.DirectorySeparatorChar);

                if (!string.IsNullOrEmpty(relPath))
                {
                    string targetPath = Path.GetFullPath(Path.Combine(destDir, relPath));
                    // Zip-Slip Schutz: Ziel muss in destDir liegen
                    if (targetPath.StartsWith(fullDestRoot, StringComparison.OrdinalIgnoreCase))
                    {
                        if (typeFlag == (byte)'5' || name.EndsWith("/"))
                        {
                            Directory.CreateDirectory(targetPath);
                        }
                        else if (typeFlag == 0 || typeFlag == (byte)'0')
                        {
                            string parent = Path.GetDirectoryName(targetPath);
                            if (!string.IsNullOrEmpty(parent))
                                Directory.CreateDirectory(parent);

                            using (FileStream outFs = File.Create(targetPath))
                            {
                                long remaining = size;
                                byte[] buf = new byte[8192];
                                while (remaining > 0)
                                {
                                    int toRead = (int)Math.Min(buf.Length, remaining);
                                    int r = ReadExact(stream, buf, 0, toRead);
                                    if (r <= 0) break;
                                    outFs.Write(buf, 0, r);
                                    remaining -= r;
                                }
                            }
                        }
                        else
                        {
                            SkipBytes(stream, size);
                        }
                    }
                    else
                    {
                        SkipBytes(stream, size);
                    }
                }
                else
                {
                    SkipBytes(stream, size);
                }

                long pad = (512 - (size % 512)) % 512;
                if (pad > 0) SkipBytes(stream, pad);
            }
        }

        private static void SkipBytes(Stream s, long count)
        {
            byte[] dummy = new byte[4096];
            long rem = count;
            while (rem > 0)
            {
                int r = ReadExact(s, dummy, 0, (int)Math.Min(dummy.Length, rem));
                if (r <= 0) break;
                rem -= r;
            }
        }
    }

    public static class AnonEngine
    {
        public static readonly TimeSpan RxTimeout = TimeSpan.FromSeconds(5);

        // Vorkompilierte Kern-Muster mit 5s Timeout
        private static readonly Regex RxEmail = new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b", RegexOptions.Compiled, RxTimeout);
        private static readonly Regex RxUrl = new Regex(@"\b(?:https?|ftp|tftp|scp|sftp|ldap|ldaps)://[^\s""'<>]+", RegexOptions.Compiled | RegexOptions.IgnoreCase, RxTimeout);

        // MAC-Formate:
        // 1. aa:bb:cc:dd:ee:ff oder aa-bb-cc-dd-ee-ff (nicht Teil von IPv6 oder Zeitstempel)
        //    Ein Doppelpunkt direkt davor ist erlaubt (z.B. "Address:0a:1b:2c:3d:4e:5f"), nicht aber als Teil einer längeren Hex-Kette (IPv6)
        private static readonly Regex RxMacColonDash = new Regex(@"(?<![0-9A-Fa-f.])(?<!::)(?<!:[0-9A-Fa-f]{1,4}:)(?<!(?<![A-Za-z0-9])[0-9A-Fa-f]{1,4}:)(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f.])(?!:[0-9A-Fa-f])|(?<![0-9A-Fa-f.-])(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f.-])", RegexOptions.Compiled, RxTimeout);
        // 2. Cisco/Aruba Punktformat: aabb.ccdd.eeff
        private static readonly Regex RxMacDot = new Regex(@"(?<![0-9A-Fa-f.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![0-9A-Fa-f.])", RegexOptions.Compiled, RxTimeout);
        // 3. 12 Hex-Zeichen am Stück mit MAC-Kontext davor
        private static readonly Regex RxMacRawContext = new Regex(@"(?i)((?<![A-Za-z0-9_])(?:mac(?:-address|_address|[ \t]+address)?|hwaddr|lladdr|station|client-id|bssid|chassis-id|peer-mac)(?![A-Za-z0-9_])[ \t"":=]{1,6})([0-9A-Fa-f]{6}-?[0-9A-Fa-f]{6})(""?)(?![0-9A-Fa-f])", RegexOptions.Compiled, RxTimeout);
        // 4. Aruba-Format aabbcc-ddeeff (nur mit mindestens einem Hex-Buchstaben, reine Ziffern nur mit MAC-Kontext)
        private static readonly Regex RxMacAruba = new Regex(@"(?<![0-9A-Za-z_.:-])[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}(?![0-9A-Za-z_.:-])", RegexOptions.Compiled, RxTimeout);

        // IPv4 inkl. Direktangrenzung an _ oder Buchstaben (z.B. WAN_192.0.2.0-27 oder 192.0.2.0/24) und Satzende (z.B. "von 192.0.2.40.")
        private static readonly Regex RxIpv4 = new Regex(@"(?<![0-9.])(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:(?:/|-)(?:3[0-2]|[12]?[0-9])(?![0-9]))?(?![0-9]|\.[0-9\u0002])", RegexOptions.Compiled, RxTimeout);

        // IPv6 (Standard, komprimiert ::, fe80::, 2001:db8:: usw., keine einfachen Uhrzeiten wie 12:34:56)
        private static readonly Regex RxIpv6 = new Regex(@"(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))(?:/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9]))?(?![0-9A-Fa-f:])", RegexOptions.Compiled, RxTimeout);

        // CLI-Prompt am Zeilenanfang (z.B. dc1-sw-core01# oder fw-edge01(config-if)#)
        private static readonly Regex RxCliPrompt = new Regex(@"(?m)^([A-Za-z][A-Za-z0-9_-]{2,48})(\([A-Za-z0-9_-]+\))?([#>])[ \t]+", RegexOptions.Compiled, RxTimeout);

        // Schutz-Marker-Auflösung in einem einzigen Durchlauf pro Schachtelungsebene
        private static readonly Regex RxUnprotect = new Regex("\u0002PROT_(\\d+)\u0003", RegexOptions.Compiled, RxTimeout);

        // Dateiendungen und Präfixe für Pfad-Anonymisierung
        private static readonly Regex RxPathExt = new Regex(@"(?i)(\.(?:tar\.gz|tgz|zip|tar|txt|log|json|cfg|conf|xml|csv|out|bin|dump|bak|old))$", RegexOptions.Compiled, RxTimeout);
        private static readonly Regex RxPathPrefix = new Regex(@"(?i)^((?:show-tech-|show_tech_|showtech-|running-config-|startup-config-|config-|backup-|support-|tech-support-|firmware-|dump-|log-|syslog-|eventlog-)+)(.+)$", RegexOptions.Compiled, RxTimeout);

        public static bool IsSubnetMaskOrSpecialIpv4(int o1, int o2, int o3, int o4, bool keepMasks)
        {
            if (o1 == 0 && o2 == 0 && o3 == 0 && o4 == 0) return true;
            if (o1 == 255 && o2 == 255 && o3 == 255 && o4 == 255) return true;
            if (o1 == 127 && o2 == 0 && o3 == 0 && o4 == 1) return true;
            if (!keepMasks) return false;

            // Gültige Subnetzmasken oder Wildcard-Masken
            if (o1 == 255 && (o2 == 255 || o2 == 254 || o2 == 252 || o2 == 248 || o2 == 240 || o2 == 224 || o2 == 192 || o2 == 128 || o2 == 0))
            {
                uint mask = ((uint)o1 << 24) | ((uint)o2 << 16) | ((uint)o3 << 8) | (uint)o4;
                uint inv = ~mask;
                if ((inv & (inv + 1)) == 0) return true;
            }
            if (o1 == 0 && (o4 == 255 || o4 == 127 || o4 == 63 || o4 == 31 || o4 == 15 || o4 == 7 || o4 == 3 || o4 == 1))
            {
                uint wc = ((uint)o1 << 24) | ((uint)o2 << 16) | ((uint)o3 << 8) | (uint)o4;
                if ((wc & (wc + 1)) == 0) return true;
            }
            return false;
        }

        public static bool IsPrivateIpv4(int o1, int o2, int o3, int o4)
        {
            if (o1 == 10) return true;
            if (o1 == 172 && o2 >= 16 && o2 <= 31) return true;
            if (o1 == 192 && o2 == 168) return true;
            if (o1 == 169 && o2 == 254) return true;
            if (o1 == 100 && o2 >= 64 && o2 <= 127) return true; // CGNAT
            return false;
        }

        public static string NormalizeMac(string rawMac)
        {
            StringBuilder sb = new StringBuilder(12);
            for (int i = 0; i < rawMac.Length; i++)
            {
                char c = rawMac[i];
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                    sb.Append(char.ToLowerInvariant(c));
            }
            return sb.ToString();
        }

        public static string FormatIpv4Token(string rawMatch, EngineConfig cfg, AnonState state)
        {
            string ipPart = rawMatch;
            string suffix = "";
            int slashIdx = rawMatch.IndexOf('/');
            int dashIdx = rawMatch.IndexOf('-');
            if (slashIdx > 0)
            {
                ipPart = rawMatch.Substring(0, slashIdx);
                suffix = rawMatch.Substring(slashIdx);
            }
            else if (dashIdx > 0)
            {
                ipPart = rawMatch.Substring(0, dashIdx);
                suffix = rawMatch.Substring(dashIdx);
            }

            string[] parts = ipPart.Split('.');
            if (parts.Length != 4) return rawMatch;

            // Keine führenden Nullen wie 01.02.03.04 (oft Version/Build)
            for (int i = 0; i < 4; i++)
            {
                if (parts[i].Length > 1 && parts[i][0] == '0')
                    return rawMatch;
            }

            int o1, o2, o3, o4;
            if (!int.TryParse(parts[0], out o1) || !int.TryParse(parts[1], out o2) ||
                !int.TryParse(parts[2], out o3) || !int.TryParse(parts[3], out o4))
                return rawMatch;

            if (IsSubnetMaskOrSpecialIpv4(o1, o2, o3, o4, cfg.SubnetzmaskenBehalten))
                return rawMatch;

            if (cfg.ExakteAusnahmen.Contains(ipPart) || cfg.ExakteAusnahmen.Contains(rawMatch))
                return rawMatch;

            state.AddStat("ip", 1);

            string existingIpTok;
            if (state.Forward.TryGetValue("IPV4|" + ipPart, out existingIpTok) && !string.IsNullOrEmpty(existingIpTok))
            {
                return existingIpTok + suffix;
            }

            if (cfg.Netzerhaltend)
            {
                string netKey = o1.ToString() + "." + o2.ToString() + "." + o3.ToString();
                string netToken = state.GetOrCreateToken("IPV4NET", netKey, "NET");
                string hostPart;
                if (o4 == 0)
                {
                    hostPart = "H0";
                }
                else if (o4 == 255)
                {
                    hostPart = "H255";
                }
                else
                {
                    Dictionary<string, string> hostMap;
                    if (!state.NetHostForward.TryGetValue(netToken, out hostMap))
                    {
                        hostMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        state.NetHostForward[netToken] = hostMap;
                    }
                    string hKey = o4.ToString();
                    if (!hostMap.TryGetValue(hKey, out hostPart))
                    {
                        int hNum = state.NextCounter("HOST_IN_" + netToken);
                        hostPart = "H" + hNum.ToString();
                        hostMap[hKey] = hostPart;
                    }
                }
                string fullToken = netToken + "." + hostPart;
                state.Forward["IPV4|" + ipPart] = fullToken;
                if (!state.Reverse.ContainsKey(fullToken))
                    state.Reverse[fullToken] = ipPart;
                if (!state.Reverse.ContainsKey(netToken))
                    state.Reverse[netToken] = netKey;
                return fullToken + suffix;
            }
            else
            {
                string prefix = "IP";
                if (cfg.IpPrivatOeffentlichTrennen)
                    prefix = IsPrivateIpv4(o1, o2, o3, o4) ? "IP-PRIV" : "IP-PUB";
                string token = state.GetOrCreateToken("IPV4", ipPart, prefix);
                return token + suffix;
            }
        }

        public static string FormatIpv6Token(string rawMatch, EngineConfig cfg, AnonState state)
        {
            string ipPart = rawMatch;
            string suffix = "";
            int slashIdx = rawMatch.IndexOf('/');
            if (slashIdx > 0)
            {
                ipPart = rawMatch.Substring(0, slashIdx);
                suffix = rawMatch.Substring(slashIdx);
            }

            string lower = ipPart.ToLowerInvariant();
            if (lower == "::" || lower == "::1" || lower == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
                return rawMatch;

            if (cfg.ExakteAusnahmen.Contains(lower) || cfg.ExakteAusnahmen.Contains(rawMatch))
                return rawMatch;

            // Schutz vor Uhrzeiten / Timestamps wie 12:34:56 (genau 2 Doppelpunkte, keine :: und alle Blöcke <= 2 Ziffern dezimal)
            if (!lower.Contains("::"))
            {
                string[] segs = lower.Split(':');
                if (segs.Length < 6)
                    return rawMatch;
            }

            state.AddStat("ip", 1);
            bool isPriv = lower.StartsWith("fe80:") || lower.StartsWith("fc") || lower.StartsWith("fd");
            string prefix = cfg.IpPrivatOeffentlichTrennen ? (isPriv ? "IP6-PRIV" : "IP6-PUB") : "IP6";
            string token = state.GetOrCreateToken("IPV6", lower, prefix);
            return token + suffix;
        }

        // ----------------------------------------------------------------
        // Tabellenspalten (z.B. letzte Spalte "show interface brief", LLDP PORT-DESC / SYS-NAME)
        // Spaltengrenzen werden aus der Kopfzeile bestimmt; die Tabelle endet an einer Leerzeile.
        // ----------------------------------------------------------------
        private static bool IsBlank(char c)
        {
            return c == ' ' || c == '\t';
        }

        private static int FindHeaderWord(string line, string word)
        {
            if (string.IsNullOrEmpty(word)) return -1;
            int from = 0;
            while (from <= line.Length - word.Length)
            {
                int i = line.IndexOf(word, from, StringComparison.Ordinal);
                if (i < 0) return -1;
                int e = i + word.Length;
                bool okLeft = (i == 0) || IsBlank(line[i - 1]);
                bool okRight = (e == line.Length) || IsBlank(line[e]);
                if (okLeft && okRight) return i;
                from = i + 1;
            }
            return -1;
        }

        private static bool IsTableSeparatorLine(string line)
        {
            bool any = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '-' || c == '=' || c == '+' || c == '|') any = true;
                else if (!IsBlank(c)) return false;
            }
            return any;
        }

        public static List<TableField> FindTableFields(string text, EngineConfig cfg)
        {
            List<TableField> result = new List<TableField>();
            if (string.IsNullOrEmpty(text) || cfg.TabellenSpalten.Count == 0) return result;

            List<int[]> cols = null;
            List<string> kats = null;
            int pos = 0;
            int lineNo = 0;
            while (pos <= text.Length)
            {
                int nl = text.IndexOf('\n', pos);
                int lineEnd = nl < 0 ? text.Length : nl;
                int contentEnd = lineEnd;
                if (contentEnd > pos && text[contentEnd - 1] == '\r') contentEnd--;
                string line = text.Substring(pos, contentEnd - pos);
                lineNo++;

                bool isHeader = false;
                foreach (TableRule rule in cfg.TabellenSpalten)
                {
                    if (rule.Kopf.Count == 0 || rule.Spalten.Count == 0) continue;
                    bool all = true;
                    foreach (string w in rule.Kopf)
                    {
                        if (FindHeaderWord(line, w) < 0) { all = false; break; }
                    }
                    if (!all) continue;

                    List<int[]> newCols = new List<int[]>();
                    List<string> newKats = new List<string>();
                    foreach (TableColumnSpec sp in rule.Spalten)
                    {
                        int s = FindHeaderWord(line, sp.Name);
                        if (s < 0) continue;
                        int e = -1;
                        for (int p = s + sp.Name.Length; p < line.Length; p++)
                        {
                            if (!IsBlank(line[p]) && IsBlank(line[p - 1])) { e = p; break; }
                        }
                        // aufsteigend nach Spaltenbeginn einsortieren
                        int ins = 0;
                        while (ins < newCols.Count && newCols[ins][0] <= s) ins++;
                        newCols.Insert(ins, new int[] { s, e });
                        newKats.Insert(ins, sp.Kategorie);
                    }
                    cols = newCols;
                    kats = newKats;
                    isHeader = true;
                    break;
                }

                if (!isHeader && cols != null)
                {
                    string trimmed = line.Trim();
                    if (trimmed.Length == 0 || trimmed.StartsWith("Total", StringComparison.OrdinalIgnoreCase))
                    {
                        cols = null;
                        kats = null;
                    }
                    else if (!IsTableSeparatorLine(line))
                    {
                        int lastEnd = 0;
                        for (int ci = 0; ci < cols.Count; ci++)
                        {
                            int s = cols[ci][0];
                            if (s < lastEnd) s = lastEnd;
                            if (s >= line.Length) continue;
                            // Wert der vorigen Spalte ragt hinein: bis zum nächsten Leerraum weiterrücken
                            while (s > 0 && s < line.Length && !IsBlank(line[s - 1])) s++;
                            while (s < line.Length && IsBlank(line[s])) s++;
                            int limit = cols[ci][1] < 0 ? line.Length : Math.Min(cols[ci][1], line.Length);
                            if (s >= limit) continue;
                            int e = limit;
                            if (cols[ci][1] >= 0)
                            {
                                // Wert ragt in die nächste Spalte: bis zum nächsten Leerraum verlängern
                                while (e < line.Length && !IsBlank(line[e]) && !IsBlank(line[e - 1])) e++;
                            }
                            while (e > s && IsBlank(line[e - 1])) e--;
                            if (e <= s) continue;
                            TableField f = new TableField();
                            f.Start = pos + s;
                            f.Length = e - s;
                            f.Zeile = lineNo;
                            f.Kategorie = string.IsNullOrEmpty(kats[ci]) ? "TEXT" : kats[ci];
                            f.Wert = line.Substring(s, e - s);
                            result.Add(f);
                            lastEnd = e;
                        }
                    }
                }

                if (nl < 0) break;
                pos = nl + 1;
            }
            return result;
        }

        private static bool IsFullMatch(Regex r, string val)
        {
            Match m = r.Match(val);
            return m.Success && m.Index == 0 && m.Length == val.Length;
        }

        // Nur Ziffern und Portnotation (z.B. 1/1/49, 120, --)
        private static bool IsTrivialTableValue(string val)
        {
            if (string.IsNullOrEmpty(val)) return false;
            for (int i = 0; i < val.Length; i++)
            {
                char c = val[i];
                if (!((c >= '0' && c <= '9') || c == '/' || c == ':' || c == '.' || c == '-')) return false;
            }
            return true;
        }

        // Tabellenwerte, die keine Information tragen (Portnummern, "--") oder ausdrücklich erlaubt sind
        public static bool IsTableValueExempt(string val, EngineConfig cfg)
        {
            if (string.IsNullOrEmpty(val)) return true;
            if (IsTrivialTableValue(val)) return true;
            if (cfg.ExakteAusnahmen.Contains(val)) return true;
            foreach (Regex r in cfg.VersionKontextRegex) { if (IsFullMatch(r, val)) return true; }
            foreach (Regex r in cfg.AusnahmenRegex) { if (IsFullMatch(r, val)) return true; }
            string[] parts = val.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string p in parts)
            {
                if (!cfg.ExakteAusnahmen.Contains(p)) return false;
            }
            return true;
        }

        private static bool IsLineRestBlank(string text, int from)
        {
            for (int i = from; i < text.Length; i++)
            {
                char c = text[i];
                if (c == '\n' || c == '\r') return true;
                if (!IsBlank(c)) return false;
            }
            return true;
        }

        private static bool HasHexLetter(string val)
        {
            for (int i = 0; i < val.Length; i++)
            {
                char c = val[i];
                if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) return true;
            }
            return false;
        }

        // Bekannte Hostnamen eines Laufs (Schlüssel "HOST|wert" in der Zuordnungstabelle)
        public static SortedDictionary<string, string> CollectKnownHosts(AnonState state, IEnumerable<string> extra, EngineConfig cfg)
        {
            Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.Ordinal);
            if (extra != null)
            {
                foreach (string h in extra)
                {
                    if (string.IsNullOrEmpty(h) || h.Length < 3) continue;
                    string k = h.ToLowerInvariant();
                    if (!map.ContainsKey(k)) map[k] = state.GetOrCreateToken("HOST", h, "HOST");
                }
            }
            foreach (KeyValuePair<string, string> kv in state.Forward)
            {
                if (!kv.Key.StartsWith("HOST|", StringComparison.OrdinalIgnoreCase)) continue;
                string v = kv.Key.Substring(5).Trim().ToLowerInvariant();
                if (v.Length < 3 || cfg.ExakteAusnahmen.Contains(v)) continue;
                if (!map.ContainsKey(v)) map[v] = kv.Value;
            }
            SortedDictionary<string, string> sorted = new SortedDictionary<string, string>(new LengthDescOrdinal());
            foreach (KeyValuePair<string, string> kv in map) sorted[kv.Key] = kv.Value;
            return sorted;
        }

        public class LengthDescOrdinal : IComparer<string>
        {
            public int Compare(string a, string b)
            {
                if (a.Length != b.Length) return b.Length - a.Length;
                return string.CompareOrdinal(a, b);
            }
        }

        public static string ProcessText(string input, EngineConfig cfg, AnonState state)
        {
            if (string.IsNullOrEmpty(input)) return input;

            string text = input;

            // Schutz-Speicher für temporäre Maskierungen (__ANON_PROT_0__ usw.)
            List<string> protectedValues = new List<string>();
            Func<string, string> protect = (string val) =>
            {
                int idx = protectedValues.Count;
                protectedValues.Add(val);
                return "\u0002PROT_" + idx.ToString() + "\u0003";
            };
            Func<string, string> unprotect = (string val) =>
            {
                if (string.IsNullOrEmpty(val) || val.IndexOf('\u0002') < 0) return val;
                return Regex.Replace(val, @"\u0002PROT_(\d+)\u0003", (Match pm) =>
                {
                    int idx;
                    if (int.TryParse(pm.Groups[1].Value, out idx) && idx >= 0 && idx < protectedValues.Count)
                        return protectedValues[idx];
                    return pm.Value;
                }, RegexOptions.None, RxTimeout);
            };
            Func<string, bool> isOnlyProtectedOrExempt = (string bodyVal) =>
            {
                if (string.IsNullOrWhiteSpace(bodyVal) || bodyVal == "*****") return true;
                string rawUnprot = unprotect(bodyVal).Trim();
                if (cfg.ExakteAusnahmen.Contains(rawUnprot)) return true;
                string stripped = Regex.Replace(bodyVal, @"\u0002PROT_\d+\u0003", " ", RegexOptions.None, RxTimeout).Trim();
                if (string.IsNullOrEmpty(stripped)) return true;
                if (cfg.ExakteAusnahmen.Contains(stripped)) return true;
                string[] parts = Regex.Split(stripped, @"\s+", RegexOptions.None, RxTimeout);
                foreach (string p in parts)
                {
                    if (string.IsNullOrEmpty(p)) continue;
                    if (!cfg.ExakteAusnahmen.Contains(p))
                        return false;
                }
                return true;
            };

            // ----------------------------------------------------------------
            // STUFE 0: Tabellenspalten (Beschreibungen, LLDP-Nachbarn) über Spaltenpositionen der Kopfzeile
            // ----------------------------------------------------------------
            if ((cfg.CatFreitext || cfg.CatHostnamen) && cfg.TabellenSpalten.Count > 0)
            {
                List<TableField> fields = FindTableFields(text, cfg);
                if (fields.Count > 0)
                {
                    StringBuilder sbTab = new StringBuilder(text.Length);
                    int lastPos = 0;
                    foreach (TableField f in fields)
                    {
                        if (IsTableValueExempt(f.Wert, cfg)) continue;
                        string rep = null;
                        if (f.Kategorie == "HOST")
                        {
                            if (!cfg.CatHostnamen) continue;
                            state.AddStat("hostnamen", 1);
                            rep = state.GetOrCreateToken("HOST", f.Wert, "HOST");
                        }
                        else
                        {
                            if (!cfg.CatFreitext) continue;
                            state.AddStat("freitext", 1);
                            rep = state.GetOrCreateToken("FREITEXT_" + f.Kategorie, f.Wert, f.Kategorie);
                        }
                        int fEnd = f.Start + f.Length;
                        // Spaltenausrichtung erhalten, außer am Zeilenende
                        if (rep.Length < f.Length && !IsLineRestBlank(text, fEnd))
                            rep = rep + new string(' ', f.Length - rep.Length);
                        sbTab.Append(text, lastPos, f.Start - lastPos);
                        sbTab.Append(protect(rep));
                        lastPos = fEnd;
                    }
                    sbTab.Append(text, lastPos, text.Length - lastPos);
                    text = sbTab.ToString();
                }
            }

            // ----------------------------------------------------------------
            // STUFE 1: Geheimnisse ENTFERNEN (*****)
            // ----------------------------------------------------------------
            if (cfg.CatGeheimnisse)
            {
                foreach (SecretRule rule in cfg.GeheimnisMuster)
                {
                    text = rule.Compiled.Replace(text, (Match m) =>
                    {
                        state.AddStat("geheimnisseEntfernen", 1);
                        string rep = m.Result(rule.Replacement);
                        return protect(rep);
                    });
                }
            }

            // ----------------------------------------------------------------
            // STUFE 2: Ausnahmen & Version-Kontext schützen
            // ----------------------------------------------------------------
            foreach (Regex vr in cfg.VersionKontextRegex)
            {
                text = vr.Replace(text, (Match m) => protect(m.Value));
            }
            foreach (Regex ar in cfg.AusnahmenRegex)
            {
                text = ar.Replace(text, (Match m) => protect(m.Value));
            }

            // ----------------------------------------------------------------
            // STUFE 3: Freitext-Felder (description, location, contact, banner, alias)
            // ----------------------------------------------------------------
            if (cfg.CatFreitext)
            {
                foreach (FreeTextRule fRule in cfg.FreitextMuster)
                {
                    text = fRule.Compiled.Replace(text, (Match m) =>
                    {
                        if (m.Groups.Count >= 5 && fRule.Category == "BANNER")
                        {
                            string body = m.Groups[3].Value.Trim();
                            string cleanBody = unprotect(body);
                            if (cfg.ExakteAusnahmen.Contains(cleanBody.Trim())) return protect(m.Value);
                            if (isOnlyProtectedOrExempt(body)) return m.Value;
                            state.AddStat("freitext", 1);
                            string tok = state.GetOrCreateToken("FREITEXT_" + fRule.Category, cleanBody, fRule.Category);
                            return protect(m.Groups[1].Value + m.Groups[2].Value + tok + m.Groups[4].Value);
                        }
                        else if (m.Groups.Count >= 4)
                        {
                            string body = m.Groups[2].Value.Trim();
                            string cleanBody = unprotect(body);
                            if (cfg.ExakteAusnahmen.Contains(cleanBody.Trim())) return protect(m.Value);
                            if (isOnlyProtectedOrExempt(body)) return m.Value;
                            state.AddStat("freitext", 1);
                            string tok = state.GetOrCreateToken("FREITEXT_" + fRule.Category, cleanBody, fRule.Category);
                            return protect(m.Groups[1].Value + tok + m.Groups[3].Value);
                        }
                        else if (m.Groups.Count >= 3)
                        {
                            string body = m.Groups[2].Value.Trim();
                            string cleanBody = unprotect(body);
                            if (cfg.ExakteAusnahmen.Contains(cleanBody.Trim())) return protect(m.Value);
                            if (isOnlyProtectedOrExempt(body)) return m.Value;
                            state.AddStat("freitext", 1);
                            string tok = state.GetOrCreateToken("FREITEXT_" + fRule.Category, cleanBody, fRule.Category);
                            return protect(m.Groups[1].Value + tok);
                        }
                        return m.Value;
                    });
                }
            }

            // ----------------------------------------------------------------
            // STUFE 4: Eigene Begriffe & Feste Zuordnungen (aus anon-regeln.json)
            // ----------------------------------------------------------------
            if (cfg.CatEigeneBegriffe)
            {
                // Feste Zuordnungen (längste zuerst, mit Wort-/Token-Grenzen (?<![A-Za-z0-9-])...(?![A-Za-z0-9-]))
                var sortedFixed = cfg.FesteZuordnung.OrderByDescending(kv => kv.Key.Length).ToList();
                foreach (var kv in sortedFixed)
                {
                    if (string.IsNullOrEmpty(kv.Key) || cfg.ExakteAusnahmen.Contains(kv.Key.Trim())) continue;
                    state.RegisterFixed(kv.Key, kv.Value);
                    string pat = "(?<![A-Za-z0-9-])" + Regex.Escape(kv.Key) + "(?![A-Za-z0-9-])";
                    text = Regex.Replace(text, pat, (Match m) =>
                    {
                        state.AddStat("eigeneBegriffe", 1);
                        return protect(kv.Value);
                    }, RegexOptions.IgnoreCase, RxTimeout);
                }

                // Firmen-, Standort- und Personennamen (mit Wort-/Token-Grenzen (?<![A-Za-z0-9-])...(?![A-Za-z0-9-]))
                var validTerms = cfg.FirmenUndStandorte.Where(s => !string.IsNullOrWhiteSpace(s) && !cfg.ExakteAusnahmen.Contains(s.Trim())).Select(s => s.Trim()).ToList();
                if (validTerms.Count > 0)
                {
                    var sortedByLen = validTerms.OrderByDescending(s => s.Length).Select(s => Regex.Escape(s)).ToArray();
                    string combinedPat = "(?<![A-Za-z0-9-])(?:" + string.Join("|", sortedByLen) + ")(?![A-Za-z0-9-])";
                    text = Regex.Replace(text, combinedPat, (Match m) =>
                    {
                        if (cfg.ExakteAusnahmen.Contains(m.Value.Trim())) return m.Value;
                        state.AddStat("eigeneBegriffe", 1);
                        // Kanonischen Namen aus Liste suchen
                        string matchedCanonical = validTerms.FirstOrDefault(t => string.Equals(t, m.Value, StringComparison.OrdinalIgnoreCase)) ?? m.Value;
                        string tok = state.GetOrCreateToken("FIRMA", matchedCanonical, "FIRMA");
                        return protect(tok);
                    }, RegexOptions.IgnoreCase, RxTimeout);
                }
            }

            // ----------------------------------------------------------------
            // STUFE 5: Seriennummern / Service-Tags / Asset-Tags
            // ----------------------------------------------------------------
            if (cfg.CatSeriennummern)
            {
                foreach (Regex sRx in cfg.SeriennummerMuster)
                {
                    text = sRx.Replace(text, (Match m) =>
                    {
                        string val = m.Groups[2].Value.Trim();
                        if (string.IsNullOrEmpty(val) || cfg.ExakteAusnahmen.Contains(val) || val == "*****")
                            return m.Value;
                        state.AddStat("seriennummern", 1);
                        string tok = state.GetOrCreateToken("SERIAL", val, "SERIAL");
                        string suffix = m.Groups.Count >= 4 ? m.Groups[3].Value : "";
                        return protect(m.Groups[1].Value + tok + suffix);
                    });
                }
            }

            // ----------------------------------------------------------------
            // STUFE 6: Benutzernamen
            // ----------------------------------------------------------------
            if (cfg.CatBenutzer)
            {
                foreach (Regex uRx in cfg.BenutzerMuster)
                {
                    text = uRx.Replace(text, (Match m) =>
                    {
                        string val = m.Groups[2].Value.Trim();
                        if (string.IsNullOrEmpty(val) || cfg.ExakteAusnahmen.Contains(val) || val == "*****")
                            return m.Value;
                        state.AddStat("benutzer", 1);
                        string tok = state.GetOrCreateToken("USER", val, "USER");
                        string suffix = m.Groups.Count >= 4 ? m.Groups[3].Value : "";
                        return protect(m.Groups[1].Value + tok + suffix);
                    });
                }
            }

            // ----------------------------------------------------------------
            // STUFE 7: E-Mail-Adressen & URLs (unter Hostnamen/Domains gesteuert)
            // ----------------------------------------------------------------
            if (cfg.CatHostnamen)
            {
                text = RxEmail.Replace(text, (Match m) =>
                {
                    if (cfg.ExakteAusnahmen.Contains(m.Value)) return m.Value;
                    state.AddStat("hostnamen", 1);
                    string tok = state.GetOrCreateToken("MAIL", m.Value, "MAIL");
                    return protect(tok);
                });

                text = RxUrl.Replace(text, (Match m) =>
                {
                    if (cfg.ExakteAusnahmen.Contains(m.Value)) return m.Value;
                    state.AddStat("hostnamen", 1);
                    string tok = state.GetOrCreateToken("URL", m.Value, "URL");
                    return protect(tok);
                });
            }

            // ----------------------------------------------------------------
            // STUFE 8: MAC-Adressen (in allen 4 Schreibweisen, normalisiert)
            // ----------------------------------------------------------------
            if (cfg.CatMac)
            {
                // 8a: Doppelpunkt- und Bindestrichnotation aa:bb:cc:dd:ee:ff / aa-bb-cc-dd-ee-ff
                text = RxMacColonDash.Replace(text, (Match m) =>
                {
                    string norm = NormalizeMac(m.Value);
                    if (norm == "000000000000" || norm == "ffffffffffff") return m.Value;
                    if (cfg.ExakteAusnahmen.Contains(m.Value) || cfg.ExakteAusnahmen.Contains(norm)) return m.Value;
                    state.AddStat("mac", 1);
                    string key = cfg.MacNormalisieren ? norm : m.Value.ToLowerInvariant();
                    string tok = state.GetOrCreateToken("MAC", key, "MAC", m.Value);
                    return protect(tok);
                });

                // 8b: Punktnotation aabb.ccdd.eeff
                text = RxMacDot.Replace(text, (Match m) =>
                {
                    string norm = NormalizeMac(m.Value);
                    if (norm == "000000000000" || norm == "ffffffffffff") return m.Value;
                    if (cfg.ExakteAusnahmen.Contains(m.Value) || cfg.ExakteAusnahmen.Contains(norm)) return m.Value;
                    state.AddStat("mac", 1);
                    string key = cfg.MacNormalisieren ? norm : m.Value.ToLowerInvariant();
                    string tok = state.GetOrCreateToken("MAC", key, "MAC", m.Value);
                    return protect(tok);
                });

                // 8c: Aruba-Format aabbcc-ddeeff (mindestens ein Hex-Buchstabe, sonst Datum/Zahlenbereich)
                text = RxMacAruba.Replace(text, (Match m) =>
                {
                    if (!HasHexLetter(m.Value)) return m.Value;
                    string norm = NormalizeMac(m.Value);
                    if (norm == "000000000000" || norm == "ffffffffffff") return m.Value;
                    if (cfg.ExakteAusnahmen.Contains(m.Value) || cfg.ExakteAusnahmen.Contains(norm)) return m.Value;
                    state.AddStat("mac", 1);
                    string key = cfg.MacNormalisieren ? norm : m.Value.ToLowerInvariant();
                    string tok = state.GetOrCreateToken("MAC", key, "MAC", m.Value);
                    return protect(tok);
                });

                // 8d: 12 Hex-Zeichen mit Kontext (z.B. mac=001122334455 oder mac 001122-334455)
                text = RxMacRawContext.Replace(text, (Match m) =>
                {
                    string rawHex = m.Groups[2].Value;
                    string norm = NormalizeMac(rawHex);
                    if (norm == "000000000000" || norm == "ffffffffffff") return m.Value;
                    if (cfg.ExakteAusnahmen.Contains(rawHex) || cfg.ExakteAusnahmen.Contains(norm)) return m.Value;
                    state.AddStat("mac", 1);
                    string key = cfg.MacNormalisieren ? norm : rawHex.ToLowerInvariant();
                    string tok = state.GetOrCreateToken("MAC", key, "MAC", rawHex);
                    return protect(m.Groups[1].Value + tok + m.Groups[3].Value);
                });
            }

            // ----------------------------------------------------------------
            // STUFE 9: IPv4 und IPv6 inkl. Netze/Masken
            // ----------------------------------------------------------------
            if (cfg.CatIp)
            {
                text = RxIpv6.Replace(text, (Match m) =>
                {
                    string replaced = FormatIpv6Token(m.Value, cfg, state);
                    if (replaced == m.Value) return m.Value;
                    return protect(replaced);
                });

                text = RxIpv4.Replace(text, (Match m) =>
                {
                    string replaced = FormatIpv4Token(m.Value, cfg, state);
                    if (replaced == m.Value) return m.Value;
                    return protect(replaced);
                });
            }

            // ----------------------------------------------------------------
            // STUFE 10: Hostnamen, FQDNs und interne Domains
            // ----------------------------------------------------------------
            if (cfg.CatHostnamen)
            {
                // Explizite Hostnamen-Zeilen (hostname X, System Name: X, JSON "hostname": "X", sowie Namensschema-Muster)
                List<string> discoveredHosts = new List<string>();
                foreach (Regex hRx in cfg.HostnamenMuster)
                {
                    text = hRx.Replace(text, (Match m) =>
                    {
                        if (m.Groups.Count >= 3 && m.Groups[2].Success)
                        {
                            string hVal = m.Groups[2].Value.Trim();
                            if (string.IsNullOrEmpty(hVal) || cfg.ExakteAusnahmen.Contains(hVal) || hVal.StartsWith("\u0002PROT_"))
                                return m.Value;
                            state.AddStat("hostnamen", 1);
                            string tok = state.GetOrCreateToken("HOST", hVal, "HOST");
                            if (!discoveredHosts.Contains(hVal)) discoveredHosts.Add(hVal);
                            string sfx = m.Groups.Count >= 4 ? m.Groups[3].Value : "";
                            return protect(m.Groups[1].Value + tok + sfx);
                        }
                        else
                        {
                            string hVal = (m.Groups.Count >= 2 && m.Groups[1].Success) ? m.Groups[1].Value.Trim() : m.Value.Trim();
                            if (string.IsNullOrEmpty(hVal) || cfg.ExakteAusnahmen.Contains(hVal) || hVal.StartsWith("\u0002PROT_"))
                                return m.Value;
                            state.AddStat("hostnamen", 1);
                            string tok = state.GetOrCreateToken("HOST", hVal, "HOST");
                            if (!discoveredHosts.Contains(hVal)) discoveredHosts.Add(hVal);
                            return protect(tok);
                        }
                    });
                }

                // CLI-Prompts (z.B. sw-access-01(config)#)
                text = RxCliPrompt.Replace(text, (Match m) =>
                {
                    string hVal = m.Groups[1].Value.Trim();
                    if (cfg.ExakteAusnahmen.Contains(hVal) || hVal.StartsWith("\u0002PROT_"))
                        return m.Value;
                    state.AddStat("hostnamen", 1);
                    string tok = state.GetOrCreateToken("HOST", hVal, "HOST");
                    if (!discoveredHosts.Contains(hVal)) discoveredHosts.Add(hVal);
                    return protect(tok) + m.Groups[2].Value + m.Groups[3].Value + " ";
                });

                // Entdeckte und im Lauf bereits bekannte Hostnamen überall im restlichen Text in einem Durchlauf ersetzen
                // (Grenzen: kein Buchstabe, keine Ziffer und kein "-" direkt davor oder danach; "_" trennt wie in Beschreibungen üblich)
                SortedDictionary<string, string> knownHosts = CollectKnownHosts(state, discoveredHosts, cfg);
                if (knownHosts.Count > 0)
                {
                    List<string> escapedHosts = new List<string>(knownHosts.Count);
                    foreach (string kh in knownHosts.Keys) escapedHosts.Add(Regex.Escape(kh));
                    string combinedHostPat = "(?<![A-Za-z0-9-])(?:" + string.Join("|", escapedHosts.ToArray()) + ")(?![A-Za-z0-9-])";
                    text = Regex.Replace(text, combinedHostPat, (Match m) =>
                    {
                        string tok;
                        if (knownHosts.TryGetValue(m.Value.ToLowerInvariant(), out tok))
                        {
                            state.AddStat("hostnamen", 1);
                            return protect(tok);
                        }
                        return m.Value;
                    }, RegexOptions.IgnoreCase, RxTimeout);
                }

                // FQDNs und Subdomains auf Basis von interneDomains (z.B. srv01.intern.example.invalid)
                var sortedDomains = cfg.InterneDomains.Where(d => !string.IsNullOrWhiteSpace(d)).OrderByDescending(d => d.Length).ToList();
                foreach (string dom in sortedDomains)
                {
                    string cleanDom = dom.Trim();
                    // Erst FQDNs unterhalb dieser Domain (z.B. host.sub.domain.example.net)
                    string fqdnPat = @"\b([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)\." + Regex.Escape(cleanDom) + @"\b";
                    text = Regex.Replace(text, fqdnPat, (Match m) =>
                    {
                        string hostPart = m.Groups[1].Value;
                        if (cfg.ExakteAusnahmen.Contains(m.Value) || cfg.ExakteAusnahmen.Contains(hostPart)) return m.Value;
                        state.AddStat("hostnamen", 1);
                        string hTok = state.GetOrCreateToken("HOST", m.Value, "HOST");
                        return protect(hTok);
                    }, RegexOptions.IgnoreCase, RxTimeout);

                    // Dann die nackte Domain selbst
                    string domPat = @"\b" + Regex.Escape(cleanDom) + @"\b";
                    text = Regex.Replace(text, domPat, (Match m) =>
                    {
                        if (cfg.ExakteAusnahmen.Contains(cleanDom)) return m.Value;
                        state.AddStat("hostnamen", 1);
                        string dTok = state.GetOrCreateToken("DOMAIN", cleanDom, "DOMAIN");
                        return protect(dTok);
                    }, RegexOptions.IgnoreCase, RxTimeout);
                }
            }

            // ----------------------------------------------------------------
            // Schutz-Maskierungen in wenigen linearen Durchläufen wieder auflösen
            // (verhindert O(K * Dateigröße) bei großen Show-Tech-Dateien)
            // ----------------------------------------------------------------
            int guard = 0;
            while (text.IndexOf('\u0002') >= 0 && guard < 8)
            {
                text = RxUnprotect.Replace(text, (Match m) =>
                {
                    int idx;
                    if (int.TryParse(m.Groups[1].Value, out idx) && idx >= 0 && idx < protectedValues.Count)
                        return protectedValues[idx];
                    return m.Value;
                });
                guard++;
            }

            return text;
        }

        public static string ProcessPath(string relPath, EngineConfig cfg, AnonState state)
        {
            if (string.IsNullOrEmpty(relPath)) return relPath;

            // Statistiken vor Pfad-Anonymisierung sichern, damit Dateiinhalts-Zähler unverfälscht bleiben
            Dictionary<string, int> savedStats = new Dictionary<string, int>(state.Stats, StringComparer.OrdinalIgnoreCase);

            string norm = relPath.Replace('\\', '/');
            string[] parts = norm.Split(new char[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            List<string> outParts = new List<string>(parts.Length);

            foreach (string seg in parts)
            {
                string basePart = seg;
                string extPart = "";
                Match mExt = RxPathExt.Match(basePart);
                if (mExt.Success && mExt.Index > 0)
                {
                    extPart = mExt.Value;
                    basePart = basePart.Substring(0, mExt.Index);
                }

                string prefixPart = "";
                string corePart = basePart;
                Match mPref = RxPathPrefix.Match(basePart);
                if (mPref.Success)
                {
                    prefixPart = mPref.Groups[1].Value;
                    corePart = mPref.Groups[2].Value;
                }

                string[] subParts = corePart.Split('_');
                for (int sp = 0; sp < subParts.Length; sp++)
                {
                    if (!string.IsNullOrEmpty(subParts[sp]))
                    {
                        subParts[sp] = ProcessText(subParts[sp], cfg, state);
                    }
                }
                string anonCore = string.Join("_", subParts);
                string combined = prefixPart + anonCore + extPart;

                // Ungültige Dateinamen-Zeichen (z.B. aus *****) bereinigen
                char[] invalidChars = new char[] { '*', '?', '"', '<', '>', '|', ':' };
                for (int i = 0; i < invalidChars.Length; i++)
                {
                    combined = combined.Replace(invalidChars[i], '_');
                }
                outParts.Add(combined);
            }

            state.Stats = savedStats;
            return string.Join("/", outParts.ToArray());
        }

        public static string DeanonymizeText(string input, Dictionary<string, string> reverseMap)
        {
            if (string.IsNullOrEmpty(input) || reverseMap == null || reverseMap.Count == 0)
                return input;

            string text = input;
            // Längste Platzhalter zuerst ersetzen (damit NET-1.H12 vor NET-1 und IP-PRIV-10 vor IP-PRIV-1 ersetzt wird!)
            var sortedTokens = reverseMap.Keys.Where(k => !string.IsNullOrEmpty(k)).OrderByDescending(k => k.Length).ToList();
            if (sortedTokens.Count == 0) return text;

            var escapedTokens = sortedTokens.Select(t => Regex.Escape(t)).ToArray();
            string combinedPat = @"(?<![A-Za-z0-9])(?:" + string.Join("|", escapedTokens) + @")(?![0-9])";
            Dictionary<string, string> ciLookup = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string k in sortedTokens)
                ciLookup[k] = reverseMap[k];

            text = Regex.Replace(text, combinedPat, (Match m) =>
            {
                string orig;
                if (ciLookup.TryGetValue(m.Value, out orig))
                    return orig;
                return m.Value;
            }, RegexOptions.IgnoreCase, RxTimeout);
            return text;
        }

        private static bool IsAllowedInAudit(string candidate, EngineConfig cfg)
        {
            if (string.IsNullOrEmpty(candidate)) return true;
            if (candidate == "*****") return true;
            if (cfg.PruefungErlaubtListe.Contains(candidate)) return true;
            if (cfg.ExakteAusnahmen.Contains(candidate)) return true;
            foreach (KeyValuePair<string, string> kv in cfg.FesteZuordnung)
            {
                if (string.Equals(kv.Value, candidate, StringComparison.OrdinalIgnoreCase)) return true;
            }
            foreach (Regex r in cfg.PruefungErlaubtMuster)
            {
                if (r.IsMatch(candidate)) return true;
            }
            return false;
        }

        // Alle durch Leerraum getrennten Teile sind erlaubt (Platzhalter, Ausnahmen, *****)
        private static bool AreAllPartsAllowed(string val, EngineConfig cfg)
        {
            string[] parts = val.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string p in parts)
            {
                if (!IsAllowedAuditPart(p, cfg)) return false;
            }
            return true;
        }

        // Ein Teil ist unkritisch, wenn er erlaubt ist, keine Buchstaben/Ziffern enthält
        // oder aus mit "." verbundenen erlaubten Platzhaltern besteht (z.B. HOST-3.DOMAIN-1)
        private static bool IsAllowedAuditPart(string p, EngineConfig cfg)
        {
            if (IsAllowedInAudit(p, cfg)) return true;
            bool hasAlnum = false;
            for (int i = 0; i < p.Length; i++)
            {
                char c = p[i];
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) { hasAlnum = true; break; }
            }
            if (!hasAlnum) return true;
            if (p.IndexOf('.') > 0)
            {
                string[] segs = p.Split('.');
                foreach (string sg in segs)
                {
                    if (sg.Length == 0 || !IsAllowedInAudit(sg, cfg)) return false;
                }
                return true;
            }
            return false;
        }

        private static string PickGroupValue(Match m)
        {
            if (m.Groups.Count >= 3 && m.Groups[2].Success) return m.Groups[2].Value.Trim();
            if (m.Groups.Count >= 2 && m.Groups[1].Success) return m.Groups[1].Value.Trim();
            return m.Value.Trim();
        }

        // Platzhalter in der Ausgabe (für die Suche nach bekannten Originalwerten ausblenden)
        private static readonly Regex RxPlaceholder = new Regex(@"(?<![A-Za-z0-9_-])(?:NET-[0-9]+(?:\.H[0-9]+)?|IP6?(?:-PRIV|-PUB)?-[0-9]+|(?:MAC|HOST|DOMAIN|USER|SERIAL|TEXT|MAIL|URL|ORT|KONTAKT|BANNER|FIRMA|PERSON)-[0-9]+)(?![A-Za-z0-9_])", RegexOptions.Compiled, RxTimeout);
        private static readonly string[] KnownValueCategories = new string[] { "HOST|", "SERIAL|", "USER|", "MAIL|", "URL|", "FIRMA|", "DOMAIN|", "FIXED|" };

        private static int GetLineNumber(List<int> lineStarts, int charIndex)
        {
            int pos = lineStarts.BinarySearch(charIndex);
            return (pos >= 0) ? (pos + 1) : (~pos);
        }

        public static List<AuditFinding> AuditText(string text, string fileName, EngineConfig cfg)
        {
            return AuditText(text, fileName, cfg, null);
        }

        // state != null: zusätzlich alle im Lauf erkannten Originalwerte (Hosts, Seriennummern, Benutzer, ...) suchen
        public static List<AuditFinding> AuditText(string text, string fileName, EngineConfig cfg, AnonState state)
        {
            List<AuditFinding> findings = new List<AuditFinding>();

            // Vorab Sperrbegriffe und interne Domains kompilieren (für Pfad- und Inhaltsprüfung)
            List<string> blockTerms = new List<string>();
            Dictionary<string, string> canonicalTerms = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in cfg.FesteZuordnung)
            {
                if (!string.IsNullOrWhiteSpace(kv.Key))
                {
                    string k = kv.Key.Trim();
                    if (!canonicalTerms.ContainsKey(k))
                    {
                        canonicalTerms[k] = k;
                        blockTerms.Add(Regex.Escape(k));
                    }
                }
            }
            foreach (string term in cfg.FirmenUndStandorte)
            {
                if (!string.IsNullOrWhiteSpace(term))
                {
                    string t = term.Trim();
                    if (!canonicalTerms.ContainsKey(t))
                    {
                        canonicalTerms[t] = t;
                        blockTerms.Add(Regex.Escape(t));
                    }
                }
            }
            Regex rxBlock = blockTerms.Count > 0
                ? new Regex("(?<![A-Za-z0-9-])(?:" + string.Join("|", blockTerms.OrderByDescending(s => s.Length).ToArray()) + ")(?![A-Za-z0-9-])", RegexOptions.IgnoreCase, RxTimeout)
                : null;

            List<string> blockDoms = new List<string>();
            Dictionary<string, string> canonicalDoms = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string dom in cfg.InterneDomains)
            {
                if (!string.IsNullOrWhiteSpace(dom))
                {
                    string d = dom.Trim();
                    if (!canonicalDoms.ContainsKey(d))
                    {
                        canonicalDoms[d] = d;
                        blockDoms.Add(Regex.Escape(d));
                    }
                }
            }
            Regex rxDom = blockDoms.Count > 0
                ? new Regex(@"\b(?:" + string.Join("|", blockDoms.OrderByDescending(s => s.Length).ToArray()) + @")\b", RegexOptions.IgnoreCase, RxTimeout)
                : null;

            // 0. Prüfe Dateipfad / Dateiname auf nicht anonymisierte Bestandteile
            if (!string.IsNullOrEmpty(fileName))
            {
                string[] pathSegs = fileName.Replace('\\', '/').Split(new char[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
                List<string> normSegs = new List<string>(pathSegs.Length);
                foreach (string ps in pathSegs)
                {
                    string s = ps;
                    Match mPref = RxPathPrefix.Match(s);
                    if (mPref.Success) s = mPref.Groups[1].Value + " " + mPref.Groups[2].Value;
                    s = s.Replace('_', ' ');
                    normSegs.Add(s);
                }
                string pathCheck = string.Join(" / ", normSegs.ToArray());

                foreach (Match m in RxIpv4.Matches(pathCheck))
                {
                    string val = m.Value;
                    string ipOnly = val.Split('/', '-')[0];
                    if (IsAllowedInAudit(ipOnly, cfg)) continue;
                    string[] p = ipOnly.Split('.');
                    int o1, o2, o3, o4;
                    if (p.Length == 4 && int.TryParse(p[0], out o1) && int.TryParse(p[1], out o2) && int.TryParse(p[2], out o3) && int.TryParse(p[3], out o4))
                    {
                        if (IsSubnetMaskOrSpecialIpv4(o1, o2, o3, o4, true)) continue;
                    }
                    findings.Add(new AuditFinding { Datei = fileName, Zeile = 0, Kategorie = "Pfad-IPv4", Fund = val, Kontext = "Dateipfad: " + fileName });
                }
                if (rxBlock != null)
                {
                    foreach (Match m in rxBlock.Matches(pathCheck))
                    {
                        if (IsAllowedInAudit(m.Value, cfg)) continue;
                        string fund = canonicalTerms.ContainsKey(m.Value) ? canonicalTerms[m.Value] : m.Value;
                        findings.Add(new AuditFinding { Datei = fileName, Zeile = 0, Kategorie = "Pfad-Sperrbegriff", Fund = fund, Kontext = "Dateipfad: " + fileName });
                    }
                }
                if (rxDom != null)
                {
                    foreach (Match m in rxDom.Matches(pathCheck))
                    {
                        if (IsAllowedInAudit(m.Value, cfg)) continue;
                        string fund = canonicalDoms.ContainsKey(m.Value) ? canonicalDoms[m.Value] : m.Value;
                        findings.Add(new AuditFinding { Datei = fileName, Zeile = 0, Kategorie = "Pfad-Domain", Fund = fund, Kontext = "Dateipfad: " + fileName });
                    }
                }
                foreach (Regex hRx in cfg.HostnamenMuster)
                {
                    foreach (Match m in hRx.Matches(pathCheck))
                    {
                        string hVal = (m.Groups.Count >= 3 && m.Groups[2].Success) ? m.Groups[2].Value.Trim() : m.Value.Trim();
                        if (string.IsNullOrEmpty(hVal) || IsAllowedInAudit(hVal, cfg)) continue;
                        findings.Add(new AuditFinding { Datei = fileName, Zeile = 0, Kategorie = "Pfad-Hostname", Fund = hVal, Kontext = "Dateipfad: " + fileName });
                    }
                }
            }

            if (string.IsNullOrEmpty(text)) return findings;

            string[] rawLines = text.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.None);
            List<int> lineStarts = new List<int>(rawLines.Length + 1);
            lineStarts.Add(0);
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] == '\n')
                    lineStarts.Add(i + 1);
            }

            Func<int, string> getLineCtx = (int lineNo) =>
            {
                if (lineNo >= 1 && lineNo <= rawLines.Length)
                    return rawLines[lineNo - 1].Trim();
                return "";
            };

            // Maskiere erlaubte Versionskontexte und Ausnahmen längengleich mit Leerzeichen (Zeilenumbrüche bleiben erhalten)
            MatchEvaluator spaceMasker = (Match m) =>
            {
                char[] arr = m.Value.ToCharArray();
                for (int i = 0; i < arr.Length; i++)
                {
                    if (arr[i] != '\r' && arr[i] != '\n') arr[i] = ' ';
                }
                return new string(arr);
            };

            // Für die IPv4-Prüfung wird mit \u0002 maskiert (wie die Schutz-Marker der Engine), damit z.B.
            // "1.3.6.1.<Version>" nicht als IPv4 am Satzende gilt; alle anderen Prüfungen sehen Leerzeichen.
            MatchEvaluator markMasker = (Match m) =>
            {
                char[] arr = m.Value.ToCharArray();
                for (int i = 0; i < arr.Length; i++)
                {
                    if (arr[i] != '\r' && arr[i] != '\n') arr[i] = '\u0002';
                }
                return new string(arr);
            };

            string ipCleanText = text;
            foreach (Regex vr in cfg.VersionKontextRegex)
                ipCleanText = vr.Replace(ipCleanText, markMasker);
            foreach (Regex ar in cfg.AusnahmenRegex)
                ipCleanText = ar.Replace(ipCleanText, markMasker);
            var multiWordExempt = cfg.ExakteAusnahmen.Where(w => !string.IsNullOrWhiteSpace(w) && w.Trim().IndexOf(' ') >= 0).OrderByDescending(w => w.Length).ToList();
            foreach (string mw in multiWordExempt)
            {
                Regex mwRx = new Regex("(?<![A-Za-z0-9-])" + Regex.Escape(mw.Trim()) + "(?![A-Za-z0-9-])", RegexOptions.IgnoreCase, RxTimeout);
                ipCleanText = mwRx.Replace(ipCleanText, markMasker);
            }
            string cleanText = ipCleanText.Replace('\u0002', ' ');

            Regex rxSuspiciousLongHexOrB64 = new Regex(@"\b(?:[A-Fa-f0-9]{32,}|[A-Za-z0-9+/]{40,}={1,2})\b", RegexOptions.Compiled, RxTimeout);
            Regex rxCryptHash = new Regex(@"\$(?:1|2[abxy]|5|6|8|9|y)\$[a-zA-Z0-9./=$]{10,128}", RegexOptions.Compiled, RxTimeout);

            // 1. Prüfe auf verbliebene IPv4
            foreach (Match m in RxIpv4.Matches(ipCleanText))
            {
                string val = m.Value;
                string ipOnly = val.Split('/', '-')[0];
                if (IsAllowedInAudit(ipOnly, cfg)) continue;
                string[] p = ipOnly.Split('.');
                int o1, o2, o3, o4;
                if (p.Length == 4 && int.TryParse(p[0], out o1) && int.TryParse(p[1], out o2) && int.TryParse(p[2], out o3) && int.TryParse(p[3], out o4))
                {
                    if (IsSubnetMaskOrSpecialIpv4(o1, o2, o3, o4, true)) continue;
                }
                int ln = GetLineNumber(lineStarts, m.Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-IPv4", Fund = val, Kontext = getLineCtx(ln) });
            }

            // 2. Prüfe auf verbliebene IPv6
            foreach (Match m in RxIpv6.Matches(cleanText))
            {
                string val = m.Value.Split('/')[0];
                if (IsAllowedInAudit(val, cfg)) continue;
                if (!val.Contains("::") && val.Split(':').Length < 6) continue;
                int ln = GetLineNumber(lineStarts, m.Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-IPv6", Fund = m.Value, Kontext = getLineCtx(ln) });
            }

            // 3. Prüfe auf verbliebene MAC-Adressen
            foreach (Match m in RxMacColonDash.Matches(cleanText))
            {
                if (IsAllowedInAudit(m.Value, cfg)) continue;
                int ln = GetLineNumber(lineStarts, m.Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-MAC", Fund = m.Value, Kontext = getLineCtx(ln) });
            }
            foreach (Match m in RxMacDot.Matches(cleanText))
            {
                if (IsAllowedInAudit(m.Value, cfg)) continue;
                int ln = GetLineNumber(lineStarts, m.Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-MAC", Fund = m.Value, Kontext = getLineCtx(ln) });
            }
            foreach (Match m in RxMacAruba.Matches(cleanText))
            {
                if (!HasHexLetter(m.Value) || IsAllowedInAudit(m.Value, cfg)) continue;
                int ln = GetLineNumber(lineStarts, m.Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-MAC", Fund = m.Value, Kontext = getLineCtx(ln) });
            }
            foreach (Match m in RxMacRawContext.Matches(cleanText))
            {
                string rawHex = m.Groups[2].Value;
                string norm = NormalizeMac(rawHex);
                if (norm == "000000000000" || norm == "ffffffffffff" || IsAllowedInAudit(rawHex, cfg)) continue;
                int ln = GetLineNumber(lineStarts, m.Groups[2].Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-MAC", Fund = rawHex, Kontext = getLineCtx(ln) });
            }

            // 4. Prüfe auf verbliebene E-Mail-Adressen
            foreach (Match m in RxEmail.Matches(cleanText))
            {
                if (IsAllowedInAudit(m.Value, cfg)) continue;
                int ln = GetLineNumber(lineStarts, m.Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-EMail", Fund = m.Value, Kontext = getLineCtx(ln) });
            }

            // 5. Prüfe auf eigene Begriffe / Sperrliste (Firmen, Standorte, Feste Zuordnung Keys)
            if (rxBlock != null)
            {
                foreach (Match m in rxBlock.Matches(cleanText))
                {
                    if (IsAllowedInAudit(m.Value, cfg)) continue;
                    int ln = GetLineNumber(lineStarts, m.Index);
                    string fund = canonicalTerms.ContainsKey(m.Value) ? canonicalTerms[m.Value] : m.Value;
                    findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Sperrbegriff", Fund = fund, Kontext = getLineCtx(ln) });
                }
            }

            if (rxDom != null)
            {
                foreach (Match m in rxDom.Matches(cleanText))
                {
                    if (IsAllowedInAudit(m.Value, cfg)) continue;
                    int ln = GetLineNumber(lineStarts, m.Index);
                    string fund = canonicalDoms.ContainsKey(m.Value) ? canonicalDoms[m.Value] : m.Value;
                    findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Interne-Domain", Fund = fund, Kontext = getLineCtx(ln) });
                }
            }

            // 6. Prüfe auf Passwort-Hashes oder lange Geheimnis-Blobs
            foreach (Match m in rxCryptHash.Matches(cleanText))
            {
                int ln = GetLineNumber(lineStarts, m.Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Verdacht-Hash", Fund = m.Value, Kontext = getLineCtx(ln) });
            }
            foreach (Match m in rxSuspiciousLongHexOrB64.Matches(cleanText))
            {
                if (IsAllowedInAudit(m.Value, cfg)) continue;
                int ln = GetLineNumber(lineStarts, m.Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Verdacht-Geheimnis-Blob", Fund = m.Value, Kontext = getLineCtx(ln) });
            }

            // 6b. Geheimnismuster: Fundstellen, an denen die Ersetzung noch etwas ändern würde, sind nicht entfernte Geheimnisse
            foreach (SecretRule sRule in cfg.GeheimnisMuster)
            {
                foreach (Match m in sRule.Compiled.Matches(cleanText))
                {
                    if (m.Result(sRule.Replacement) == m.Value) continue;
                    int ln = GetLineNumber(lineStarts, m.Index);
                    findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-Geheimnis", Fund = m.Value, Kontext = getLineCtx(ln) });
                }
            }

            // 7. Hostnamen, Seriennummern und Benutzer anhand der Erkennungsmuster auch im Inhalt prüfen
            List<KeyValuePair<string, List<Regex>>> patternGroups = new List<KeyValuePair<string, List<Regex>>>();
            patternGroups.Add(new KeyValuePair<string, List<Regex>>("Rest-Hostname", cfg.HostnamenMuster));
            patternGroups.Add(new KeyValuePair<string, List<Regex>>("Rest-Seriennummer", cfg.SeriennummerMuster));
            patternGroups.Add(new KeyValuePair<string, List<Regex>>("Rest-Benutzer", cfg.BenutzerMuster));
            foreach (KeyValuePair<string, List<Regex>> pg in patternGroups)
            {
                foreach (Regex rx in pg.Value)
                {
                    foreach (Match m in rx.Matches(cleanText))
                    {
                        string val = PickGroupValue(m);
                        if (string.IsNullOrEmpty(val) || val.IndexOf('\u0002') >= 0 || IsAllowedInAudit(val, cfg) || AreAllPartsAllowed(val, cfg)) continue;
                        int ln = GetLineNumber(lineStarts, m.Index);
                        findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = pg.Key, Fund = val, Kontext = getLineCtx(ln) });
                    }
                }
            }

            // 8. Freitext-Felder (description, location, ...) müssen ersetzt oder vollständig erlaubt sein
            foreach (FreeTextRule fRule in cfg.FreitextMuster)
            {
                foreach (Match m in fRule.Compiled.Matches(cleanText))
                {
                    int gIdx = (fRule.Category == "BANNER" && m.Groups.Count >= 5) ? 3 : 2;
                    if (m.Groups.Count <= gIdx || !m.Groups[gIdx].Success) continue;
                    string body = m.Groups[gIdx].Value.Trim();
                    if (string.IsNullOrEmpty(body) || IsAllowedInAudit(body, cfg) || AreAllPartsAllowed(body, cfg)) continue;
                    int ln = GetLineNumber(lineStarts, m.Groups[gIdx].Index);
                    findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-Freitext", Fund = body, Kontext = getLineCtx(ln) });
                }
            }

            // 9. Tabellenspalten (Beschreibungen, LLDP-Nachbarn)
            foreach (TableField f in FindTableFields(cleanText, cfg))
            {
                string val = f.Wert.Trim();
                if (IsTableValueExempt(val, cfg) || IsAllowedInAudit(val, cfg)) continue;
                // Nach Ersetzungen verschobene Spalten: Zahlen/Portnotation neben Platzhaltern sind unkritisch
                bool allOk = true;
                foreach (string part in val.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!IsTrivialTableValue(part) && !IsAllowedAuditPart(part, cfg)) { allOk = false; break; }
                }
                if (allOk) continue;
                findings.Add(new AuditFinding { Datei = fileName, Zeile = f.Zeile, Kategorie = "Rest-Tabellenfeld", Fund = val, Kontext = getLineCtx(f.Zeile) });
            }

            // 10. Im Lauf erkannte Originalwerte (aus der Zuordnungstabelle) dürfen nirgends mehr vorkommen
            if (state != null)
            {
                List<string> known = new List<string>();
                HashSet<string> seenKnown = new HashSet<string>(StringComparer.Ordinal);
                foreach (KeyValuePair<string, string> kv in state.Forward)
                {
                    foreach (string cat in KnownValueCategories)
                    {
                        if (!kv.Key.StartsWith(cat, StringComparison.OrdinalIgnoreCase)) continue;
                        string v = kv.Key.Substring(cat.Length).Trim().ToLowerInvariant();
                        if (v.Length >= 3 && !IsAllowedInAudit(v, cfg) && seenKnown.Add(v)) known.Add(v);
                        break;
                    }
                }
                if (known.Count > 0)
                {
                    known.Sort(new LengthDescOrdinal());
                    List<string> esc = new List<string>(known.Count);
                    foreach (string k in known) esc.Add(Regex.Escape(k));
                    Regex rxKnown = new Regex("(?<![A-Za-z0-9])(?:" + string.Join("|", esc.ToArray()) + ")(?![A-Za-z0-9])", RegexOptions.IgnoreCase, RxTimeout);
                    string knownText = RxPlaceholder.Replace(cleanText, spaceMasker);
                    foreach (KeyValuePair<string, string> kv in cfg.FesteZuordnung)
                    {
                        if (string.IsNullOrWhiteSpace(kv.Value)) continue;
                        knownText = Regex.Replace(knownText, "(?<![A-Za-z0-9_-])" + Regex.Escape(kv.Value.Trim()) + "(?![A-Za-z0-9_-])", spaceMasker, RegexOptions.IgnoreCase, RxTimeout);
                    }
                    foreach (Match m in rxKnown.Matches(knownText))
                    {
                        int ln = GetLineNumber(lineStarts, m.Index);
                        findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-Bekannt", Fund = m.Value, Kontext = getLineCtx(ln) });
                    }
                }
            }

            if (findings.Count > 1)
                findings = findings.OrderBy(f => f.Zeile).ToList();

            return findings;
        }
    }
}
'@

if (-not ("AnonTool.AnonEngine" -as [type])) {
    if ($PSVersionTable.PSEdition -eq "Desktop") {
        # Windows PowerShell 5.1: System.Linq liegt in System.Core (GZipStream, Regex, Kryptografie in System/mscorlib)
        Add-Type -TypeDefinition $csharpCode -ReferencedAssemblies @("System.Core") -ErrorAction Stop
    } else {
        Add-Type -TypeDefinition $csharpCode -ErrorAction Stop
    }
}

# ZIP-Unterstützung sofort laden und bei Fehler abbrechen (nicht erst beim Entpacken)
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
} catch {
    throw "System.IO.Compression.FileSystem konnte nicht geladen werden (.NET Framework 4.5 oder neuer erforderlich)."
}
# DPAPI (ProtectedData) ist nur unter Windows vorhanden und optional
try {
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
} catch {}

# ============================================================================
# Hilfsfunktionen für Regeln, Zuordnungstabelle, ACL & Verschlüsselung
# ============================================================================

function Get-JsonProp {
    param($Obj, [string]$PropName)
    if ($null -eq $Obj) { return $null }
    $prop = $Obj.PSObject.Properties[$PropName]
    if ($null -ne $prop) { return $prop.Value }
    return $null
}

# Liste aus Basisregeln, danach dieselbe Liste aus der lokalen Regeldatei (gleiche Reihenfolge wie anonymisierer.html)
function Get-MergedRuleList {
    param($BaseObj, $LokalObj, [string]$Section, [string]$Name)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($src in @($BaseObj, $LokalObj)) {
        if ($null -eq $src) { continue }
        $container = $src
        if (-not [string]::IsNullOrEmpty($Section)) { $container = Get-JsonProp $src $Section }
        $list = Get-JsonProp $container $Name
        if ($null -eq $list) { continue }
        foreach ($item in @($list)) {
            if ($null -ne $item) { $out.Add($item) }
        }
    }
    return $out.ToArray()
}

function Load-EngineConfig {
    param(
        [string]$RegelDatei,
        [string]$LokaleRegelDatei,
        [Nullable[bool]]$OverrideNetzerhaltend,
        [string[]]$AktivKategorien
    )
    if (-not (Test-Path -LiteralPath $RegelDatei)) {
        throw "Regeldatei nicht gefunden: $RegelDatei"
    }
    $rawJson = [AnonTool.TarGzHelper]::DecodeTextWithBom([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $RegelDatei).Path))
    $jsonObj = ConvertFrom-Json -InputObject $rawJson

    # Optional: Lokale Regeldatei (anon-regeln.lokal.json) früh einlesen; Begriffe UND Muster werden übernommen
    $lokalObj = $null
    if (-not [string]::IsNullOrEmpty($LokaleRegelDatei)) {
        if (-not (Test-Path -LiteralPath $LokaleRegelDatei)) {
            throw "Lokale Regeldatei nicht gefunden (Parameter -LokaleRegeln)."
        }
        $rawLokal = [AnonTool.TarGzHelper]::DecodeTextWithBom([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $LokaleRegelDatei).Path))
        $lokalObj = ConvertFrom-Json -InputObject $rawLokal
    }

    $cfg = New-Object AnonTool.EngineConfig
    $rxTimeout = [TimeSpan]::FromSeconds(5)
    $rxCompiled = [System.Text.RegularExpressions.RegexOptions]::Compiled

    $opt = Get-JsonProp $jsonObj "optionen"
    if ($null -ne $opt) {
        $vNetz = Get-JsonProp $opt "netzerhaltend"
        if ($null -ne $vNetz) { $cfg.Netzerhaltend = [bool]$vNetz }
        $vPriv = Get-JsonProp $opt "ipPrivatOeffentlichTrennen"
        if ($null -ne $vPriv) { $cfg.IpPrivatOeffentlichTrennen = [bool]$vPriv }
        $vMask = Get-JsonProp $opt "subnetzmaskenBehalten"
        if ($null -ne $vMask) { $cfg.SubnetzmaskenBehalten = [bool]$vMask }
        $vMac  = Get-JsonProp $opt "macNormalisieren"
        if ($null -ne $vMac)  { $cfg.MacNormalisieren = [bool]$vMac }

        $k = Get-JsonProp $opt "kategorien"
        if ($null -ne $k) {
            $kGeh = Get-JsonProp $k "geheimnisseEntfernen"
            if ($null -ne $kGeh) { $cfg.CatGeheimnisse = [bool]$kGeh }
            $kIp = Get-JsonProp $k "ip"
            if ($null -ne $kIp) { $cfg.CatIp = [bool]$kIp }
            $kMac = Get-JsonProp $k "mac"
            if ($null -ne $kMac) { $cfg.CatMac = [bool]$kMac }
            $kHost = Get-JsonProp $k "hostnamen"
            if ($null -ne $kHost) { $cfg.CatHostnamen = [bool]$kHost }
            $kBen = Get-JsonProp $k "benutzer"
            if ($null -ne $kBen) { $cfg.CatBenutzer = [bool]$kBen }
            $kSer = Get-JsonProp $k "seriennummern"
            if ($null -ne $kSer) { $cfg.CatSeriennummern = [bool]$kSer }
            $kFrei = Get-JsonProp $k "freitext"
            if ($null -ne $kFrei) { $cfg.CatFreitext = [bool]$kFrei }
            $kEig = Get-JsonProp $k "eigeneBegriffe"
            if ($null -ne $kEig) { $cfg.CatEigeneBegriffe = [bool]$kEig }
        }
    }

    if ($null -ne $OverrideNetzerhaltend) {
        $cfg.Netzerhaltend = [bool]$OverrideNetzerhaltend
    }

    if ($null -ne $AktivKategorien -and $AktivKategorien.Count -gt 0) {
        $allCats = $AktivKategorien -join ","
        $catSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($part in ($allCats -split ",")) {
            if (-not [string]::IsNullOrWhiteSpace($part)) {
                [void]$catSet.Add($part.Trim())
            }
        }
        $cfg.CatGeheimnisse = $catSet.Contains("geheimnisseEntfernen") -or $catSet.Contains("geheimnisse")
        $cfg.CatIp = $catSet.Contains("ip")
        $cfg.CatMac = $catSet.Contains("mac")
        $cfg.CatHostnamen = $catSet.Contains("hostnamen")
        $cfg.CatBenutzer = $catSet.Contains("benutzer")
        $cfg.CatSeriennummern = $catSet.Contains("seriennummern")
        $cfg.CatFreitext = $catSet.Contains("freitext")
        $cfg.CatEigeneBegriffe = $catSet.Contains("eigeneBegriffe")
    }

    $eig = Get-JsonProp $jsonObj "eigeneBegriffe"
    if ($null -ne $eig) {
        $feste = Get-JsonProp $eig "festeZuordnung"
        if ($null -ne $feste) {
            foreach ($prop in $feste.PSObject.Properties) {
                $cfg.FesteZuordnung[$prop.Name] = [string]$prop.Value
            }
        }
        $firmen = Get-JsonProp $eig "firmenUndStandorte"
        if ($null -ne $firmen) {
            foreach ($item in $firmen) {
                $cfg.FirmenUndStandorte.Add([string]$item)
            }
        }
        $doms = Get-JsonProp $eig "interneDomains"
        if ($null -ne $doms) {
            foreach ($item in $doms) {
                $cfg.InterneDomains.Add([string]$item)
            }
        }
    }

    $aus = Get-JsonProp $jsonObj "ausnahmen"
    if ($null -ne $aus) {
        $exW = Get-JsonProp $aus "exakteWoerter"
        if ($null -ne $exW) {
            foreach ($w in $exW) {
                [void]$cfg.ExakteAusnahmen.Add([string]$w)
            }
        }
    }
    foreach ($pat in (Get-MergedRuleList $jsonObj $lokalObj "ausnahmen" "versionKontext")) {
        $cfg.VersionKontextRegex.Add((New-Object System.Text.RegularExpressions.Regex ([string]$pat, $rxCompiled, $rxTimeout)))
    }
    foreach ($pat in (Get-MergedRuleList $jsonObj $lokalObj "ausnahmen" "musterRegex")) {
        $cfg.AusnahmenRegex.Add((New-Object System.Text.RegularExpressions.Regex ([string]$pat, $rxCompiled, $rxTimeout)))
    }

    # Lokale Regeldatei: eigeneBegriffe + ausnahmen.exakteWoerter zusammenführen (Muster siehe Get-MergedRuleList)
    if ($null -ne $lokalObj) {
        $lokEig = Get-JsonProp $lokalObj "eigeneBegriffe"
        if ($null -eq $lokEig) { $lokEig = $lokalObj }
        if ($null -ne $lokEig) {
            $lFeste = Get-JsonProp $lokEig "festeZuordnung"
            if ($null -ne $lFeste) {
                foreach ($prop in $lFeste.PSObject.Properties) {
                    $origKey = ([string]$prop.Name).Trim()
                    $phVal = ([string]$prop.Value).Trim()
                    if (-not [string]::IsNullOrEmpty($origKey) -and -not [string]::IsNullOrEmpty($phVal)) {
                        $cfg.FesteZuordnung[$origKey] = $phVal
                    }
                }
            }
            $lFirmen = Get-JsonProp $lokEig "firmenUndStandorte"
            if ($null -ne $lFirmen) {
                foreach ($item in $lFirmen) {
                    $sItem = ([string]$item).Trim()
                    if (-not [string]::IsNullOrEmpty($sItem) -and -not ($cfg.FirmenUndStandorte | Where-Object { $_ -ieq $sItem })) {
                        $cfg.FirmenUndStandorte.Add($sItem)
                    }
                }
            }
            $lDoms = Get-JsonProp $lokEig "interneDomains"
            if ($null -ne $lDoms) {
                foreach ($item in $lDoms) {
                    $sDom = ([string]$item).Trim()
                    if (-not [string]::IsNullOrEmpty($sDom) -and -not ($cfg.InterneDomains | Where-Object { $_ -ieq $sDom })) {
                        $cfg.InterneDomains.Add($sDom)
                    }
                }
            }
        }
        $lokAus = Get-JsonProp $lokalObj "ausnahmen"
        if ($null -ne $lokAus) {
            $lokExW = Get-JsonProp $lokAus "exakteWoerter"
            if ($null -ne $lokExW) {
                foreach ($w in $lokExW) {
                    $sw = ([string]$w).Trim()
                    if (-not [string]::IsNullOrEmpty($sw)) {
                        [void]$cfg.ExakteAusnahmen.Add($sw)
                    }
                }
            }
        }
    }

    foreach ($w in (Get-MergedRuleList $jsonObj $lokalObj "pruefung" "erlaubtListe")) {
        [void]$cfg.PruefungErlaubtListe.Add([string]$w)
    }
    foreach ($pat in (Get-MergedRuleList $jsonObj $lokalObj "pruefung" "erlaubtMuster")) {
        $cfg.PruefungErlaubtMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$pat, $rxCompiled, $rxTimeout)))
    }

    foreach ($gm in (Get-MergedRuleList $jsonObj $lokalObj "" "geheimnisMuster")) {
        $sr = New-Object AnonTool.SecretRule
        $sr.Name = [string](Get-JsonProp $gm "name")
        $sr.Pattern = [string](Get-JsonProp $gm "suche")
        $sr.Replacement = [string](Get-JsonProp $gm "ersetzen")
        $sr.Compiled = New-Object System.Text.RegularExpressions.Regex ($sr.Pattern, $rxCompiled, $rxTimeout)
        $cfg.GeheimnisMuster.Add($sr)
    }

    foreach ($fm in (Get-MergedRuleList $jsonObj $lokalObj "" "freitextMuster")) {
        $fr = New-Object AnonTool.FreeTextRule
        $fr.Name = [string](Get-JsonProp $fm "name")
        $fr.Category = [string](Get-JsonProp $fm "kategorie")
        $fr.Pattern = [string](Get-JsonProp $fm "suche")
        $fr.Compiled = New-Object System.Text.RegularExpressions.Regex ($fr.Pattern, $rxCompiled, $rxTimeout)
        $cfg.FreitextMuster.Add($fr)
    }

    foreach ($pat in (Get-MergedRuleList $jsonObj $lokalObj "" "seriennummerMuster")) {
        $cfg.SeriennummerMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$pat, $rxCompiled, $rxTimeout)))
    }

    foreach ($pat in (Get-MergedRuleList $jsonObj $lokalObj "" "benutzerMuster")) {
        $cfg.BenutzerMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$pat, $rxCompiled, $rxTimeout)))
    }

    # Reihenfolge wie in anonymisierer.html: hostnamenMuster (Basis, lokal), danach eigeneHostnamenMuster (Basis, lokal)
    $hostPats = @(Get-MergedRuleList $jsonObj $lokalObj "" "hostnamenMuster") + @(Get-MergedRuleList $jsonObj $lokalObj "" "eigeneHostnamenMuster")
    foreach ($pat in $hostPats) {
        $cfg.HostnamenMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$pat, $rxCompiled, $rxTimeout)))
    }

    foreach ($tr in (Get-MergedRuleList $jsonObj $lokalObj "" "tabellenSpalten")) {
        $rule = New-Object AnonTool.TableRule
        $rule.Name = [string](Get-JsonProp $tr "name")
        foreach ($k in @(Get-JsonProp $tr "kopf")) {
            if ($null -ne $k) { $rule.Kopf.Add([string]$k) }
        }
        foreach ($sp in @(Get-JsonProp $tr "spalten")) {
            if ($null -eq $sp) { continue }
            $col = New-Object AnonTool.TableColumnSpec
            $col.Name = [string](Get-JsonProp $sp "name")
            $col.Kategorie = [string](Get-JsonProp $sp "kategorie")
            $rule.Spalten.Add($col)
        }
        $cfg.TabellenSpalten.Add($rule)
    }

    return $cfg
}

function Set-RestrictedUserAcl {
    param([string]$TargetPath)
    $isWindowsOs = ($env:OS -eq "Windows_NT") -or ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
    if ($isWindowsOs) {
        try {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $acl = Get-Acl -LiteralPath $TargetPath
            $acl.SetAccessRuleProtection($true, $false)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $currentUser,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.SetAccessRule($rule)
            Set-Acl -LiteralPath $TargetPath -AclObject $acl
        } catch {
            Write-Warning "Konnte Windows-ACL auf '$TargetPath' nicht einschränken: $($_.Exception.Message)"
        }
    } else {
        # Fallback für Unix/macOS Testläufe: chmod 600 / 700
        try {
            if (Test-Path -LiteralPath $TargetPath -PathType Container) {
                & chmod 700 $TargetPath 2>$null
            } else {
                & chmod 600 $TargetPath 2>$null
            }
        } catch {}
    }
}

$script:PBKDF2_DEFAULT_ITERATIONS = 600000
$script:PBKDF2_LEGACY_ITERATIONS  = 100000
$script:MIN_PASSWORD_LENGTH       = 12
$script:LastLoadedProtection      = "NONE"
$script:LastLoadedPasswordSecure  = $null

$script:PBKDF2_MAX_ITERATIONS      = 5000000

function Read-TablePasswordInteractive {
    param([switch]$ConfirmTwice)
    if ($ConfirmTwice) {
        $s1 = Read-Host -Prompt "Passwort zum Verschlüsseln der Zuordnungstabelle eingeben (mind. 12 Zeichen)" -AsSecureString
        $s2 = Read-Host -Prompt "Passwort zur Bestätigung erneut eingeben" -AsSecureString
        if ($null -eq $s1 -or $s1.Length -lt $script:MIN_PASSWORD_LENGTH) {
            throw "Das Passwort muss mindestens $($script:MIN_PASSWORD_LENGTH) Zeichen lang sein."
        }
        if (-not [AnonTool.AnonCrypto]::SecureStringEquals($s1, $s2)) {
            throw "Die eingegebenen Passwörter stimmen nicht überein."
        }
        $s2.Dispose()
        return $s1
    } else {
        $s1 = Read-Host -Prompt "Passwort zum Entschlüsseln der Zuordnungstabelle eingeben" -AsSecureString
        return $s1
    }
}

# Hauptschlüssel ableiten und daraus getrennte Schlüssel für AES ("enc") und HMAC ("mac") bilden
function Get-TableSubKeys {
    param([SecureString]$PasswordSecure, [byte[]]$Salt, [int]$Iterations, [bool]$Sha256)
    $masterKey = [AnonTool.AnonCrypto]::DeriveMasterKey($PasswordSecure, $Salt, $Iterations, $Sha256)
    try {
        $hmacDerive = New-Object System.Security.Cryptography.HMACSHA256(,$masterKey)
        $encKey = $hmacDerive.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("enc"))
        $macKey = $hmacDerive.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("mac"))
        $hmacDerive.Dispose()
        return @{ Enc = $encKey; Mac = $macKey }
    } finally {
        [AnonTool.AnonCrypto]::Zero($masterKey)
    }
}

function Test-TableIterations {
    param($Value, [string]$Format)
    if ($null -eq $Value) {
        throw "Manipulierte oder ungültige $Format Zuordnungstabelle: Feld 'iterations' fehlt."
    }
    $iter = 0
    if (-not [int]::TryParse([string]$Value, [ref]$iter) -or $iter -le 0) {
        throw "Manipulierte oder ungültige $Format Zuordnungstabelle: Ungültige Iterationszahl."
    }
    if ($iter -gt $script:PBKDF2_MAX_ITERATIONS) {
        throw "Zuordnungstabelle abgelehnt: Iterationszahl über dem Höchstwert von 5.000.000."
    }
    return $iter
}

function Protect-TableContent {
    param(
        [string]$PlainJson,
        [switch]$UseDpapi,
        [SecureString]$PasswordSecure,
        [int]$Iterations = $script:PBKDF2_DEFAULT_ITERATIONS
    )
    if ($UseDpapi) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainJson)
        if ("System.Security.Cryptography.ProtectedData" -as [type]) {
            $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            $wrapper = [ordered]@{
                format = "ANON-DPAPI-1"
                daten  = [Convert]::ToBase64String($enc)
            }
            return ($wrapper | ConvertTo-Json -Depth 5)
        } else {
            throw "DPAPI (ProtectedData) ist nur unter Windows verfügbar. Nutzen Sie alternativ -MitPasswort oder -Unverschluesselt."
        }
    }
    elseif ($null -ne $PasswordSecure) {
        if ($PasswordSecure.Length -lt $script:MIN_PASSWORD_LENGTH) {
            throw "Das Passwort für die Tabellenverschlüsselung muss mindestens $($script:MIN_PASSWORD_LENGTH) Zeichen lang sein."
        }
        $effIter = if ($Iterations -gt 0) { $Iterations } else { $script:PBKDF2_DEFAULT_ITERATIONS }
        $salt = New-Object byte[] 16
        $iv = New-Object byte[] 16
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($salt)
        $rng.GetBytes($iv)

        # ANON-AES256-2: PBKDF2-SHA256 ab .NET 4.7.2, sonst PBKDF2-SHA1; getrennte Schlüssel für AES und HMAC
        $useSha256 = [AnonTool.AnonCrypto]::Sha256KdfAvailable()
        $kdfName = if ($useSha256) { "PBKDF2-SHA256" } else { "PBKDF2-SHA1" }
        $keys = Get-TableSubKeys -PasswordSecure $PasswordSecure -Salt $salt -Iterations $effIter -Sha256 $useSha256

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $keys.Enc
        $aes.IV = $iv

        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainJson)
        $encryptor = $aes.CreateEncryptor()
        $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        $aes.Dispose()

        $macInput = Get-Aes256V2MacInput -Iterations $effIter -Salt $salt -Iv $iv -Cipher $cipherBytes
        $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$keys.Mac)
        $macBytes = $hmac.ComputeHash($macInput)
        $hmac.Dispose()
        [AnonTool.AnonCrypto]::Zero($keys.Enc)
        [AnonTool.AnonCrypto]::Zero($keys.Mac)

        $wrapper = [ordered]@{
            format     = "ANON-AES256-2"
            kdf        = $kdfName
            iterations = $effIter
            salt       = [Convert]::ToBase64String($salt)
            iv         = [Convert]::ToBase64String($iv)
            hmac       = [Convert]::ToBase64String($macBytes)
            daten      = [Convert]::ToBase64String($cipherBytes)
        }
        return ($wrapper | ConvertTo-Json -Depth 5)
    }
    return $PlainJson
}

# MAC über UTF8("ANON-AES256-2|" + iter) + salt + iv + ciphertext
function Get-Aes256V2MacInput {
    param([int]$Iterations, [byte[]]$Salt, [byte[]]$Iv, [byte[]]$Cipher)
    $prefixBytes = [System.Text.Encoding]::UTF8.GetBytes("ANON-AES256-2|" + $Iterations.ToString())
    $macInput = New-Object byte[] ($prefixBytes.Length + $Salt.Length + $Iv.Length + $Cipher.Length)
    [System.Buffer]::BlockCopy($prefixBytes, 0, $macInput, 0, $prefixBytes.Length)
    [System.Buffer]::BlockCopy($Salt, 0, $macInput, $prefixBytes.Length, $Salt.Length)
    [System.Buffer]::BlockCopy($Iv, 0, $macInput, $prefixBytes.Length + $Salt.Length, $Iv.Length)
    [System.Buffer]::BlockCopy($Cipher, 0, $macInput, $prefixBytes.Length + $Salt.Length + $Iv.Length, $Cipher.Length)
    return ,$macInput
}

function Test-HmacConstantTime32 {
    param([byte[]]$ExpectedMac, [byte[]]$ActualMac)
    if ($null -eq $ExpectedMac -or $null -eq $ActualMac) { return $false }
    if ($ExpectedMac.Length -ne 32 -or $ActualMac.Length -ne 32) { return $false }
    $diff = 0
    for ($i = 0; $i -lt 32; $i++) {
        $diff = $diff -bor ($ExpectedMac[$i] -bxor $ActualMac[$i])
    }
    return ($diff -eq 0)
}

function Unprotect-TableContent {
    param(
        [string]$RawFileContent,
        [SecureString]$PasswordSecure
    )
    try {
        $obj = ConvertFrom-Json -InputObject $RawFileContent
    } catch {
        throw "Zuordnungstabelle ist kein gültiges JSON. Die Datei wird nicht verwendet und nicht überschrieben."
    }
    if ($null -eq $obj -or $obj -is [System.Array]) {
        throw "Unbekanntes Tabellenformat. Die Datei wird nicht verwendet und nicht überschrieben."
    }
    $fmt = Get-JsonProp $obj "format"
    if ($fmt -eq "ANON-DPAPI-1") {
        $script:LastLoadedProtection = "DPAPI"
        $enc = [Convert]::FromBase64String([string](Get-JsonProp $obj "daten"))
        $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($dec)
    }
    elseif ($fmt -eq "ANON-AES256-2") {
        if ($null -eq $PasswordSecure) {
            $PasswordSecure = Read-TablePasswordInteractive -ConfirmTwice:$false
        }
        if ($null -eq $PasswordSecure -or $PasswordSecure.Length -eq 0) {
            throw "Die Zuordnungstabelle ist passwortgeschützt. Bitte -MitPasswort angeben."
        }
        $iterations = Test-TableIterations -Value (Get-JsonProp $obj "iterations") -Format "ANON-AES256-2"

        $kdfName = [string](Get-JsonProp $obj "kdf")
        if ([string]::IsNullOrEmpty($kdfName)) { $kdfName = "PBKDF2-SHA1" }
        if ($kdfName -ne "PBKDF2-SHA1" -and $kdfName -ne "PBKDF2-SHA256") {
            throw "Unbekanntes Ableitungsverfahren '$kdfName' in der Zuordnungstabelle. Die Datei wird nicht verwendet und nicht überschrieben."
        }
        $useSha256 = ($kdfName -eq "PBKDF2-SHA256")
        if ($useSha256 -and -not [AnonTool.AnonCrypto]::Sha256KdfAvailable()) {
            throw "Die Zuordnungstabelle nutzt PBKDF2-SHA256; dafür wird .NET Framework 4.7.2 oder neuer benötigt."
        }

        $saltStr = [string](Get-JsonProp $obj "salt")
        $ivStr   = [string](Get-JsonProp $obj "iv")
        $hmacStr = [string](Get-JsonProp $obj "hmac")
        $datStr  = [string](Get-JsonProp $obj "daten")
        if ([string]::IsNullOrEmpty($saltStr) -or [string]::IsNullOrEmpty($ivStr) -or [string]::IsNullOrEmpty($hmacStr) -or [string]::IsNullOrEmpty($datStr)) {
            throw "Manipulierte Zuordnungstabelle: Pflichtfelder (salt/iv/hmac/daten) fehlen oder sind leer."
        }

        $salt = [Convert]::FromBase64String($saltStr)
        $iv = [Convert]::FromBase64String($ivStr)
        $expectedMac = [Convert]::FromBase64String($hmacStr)
        $cipherBytes = [Convert]::FromBase64String($datStr)

        if ($salt.Length -lt 8 -or $iv.Length -ne 16 -or $expectedMac.Length -ne 32 -or $cipherBytes.Length -le 0) {
            throw "Manipulierte Zuordnungstabelle: Ungültige Länge von Salt, IV, HMAC (muss exakt 32 Byte sein) oder Ciphertext."
        }

        $keys = Get-TableSubKeys -PasswordSecure $PasswordSecure -Salt $salt -Iterations $iterations -Sha256 $useSha256
        try {
            $macInput = Get-Aes256V2MacInput -Iterations $iterations -Salt $salt -Iv $iv -Cipher $cipherBytes
            $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$keys.Mac)
            $actualMac = $hmac.ComputeHash($macInput)
            $hmac.Dispose()

            if (-not (Test-HmacConstantTime32 -ExpectedMac $expectedMac -ActualMac $actualMac)) {
                throw "Falsches Passwort oder manipulierte Zuordnungstabelle (HMAC-Prüfung fehlgeschlagen)."
            }

            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.Key = $keys.Enc
            $aes.IV = $iv
            $decryptor = $aes.CreateDecryptor()
            $plainBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
            $aes.Dispose()
        } finally {
            [AnonTool.AnonCrypto]::Zero($keys.Enc)
            [AnonTool.AnonCrypto]::Zero($keys.Mac)
        }
        $script:LastLoadedProtection = "PASSWORD"
        $script:LastLoadedPasswordSecure = $PasswordSecure
        return [System.Text.Encoding]::UTF8.GetString($plainBytes)
    }
    elseif ($fmt -eq "ANON-AES256-1") {
        Write-Warning "Veraltetes Tabellenformat ANON-AES256-1 geladen. Beim Speichern wird die Tabelle automatisch auf ANON-AES256-2 gehoben."
        if ($null -eq $PasswordSecure) {
            $PasswordSecure = Read-TablePasswordInteractive -ConfirmTwice:$false
        }
        if ($null -eq $PasswordSecure -or $PasswordSecure.Length -eq 0) {
            throw "Die Zuordnungstabelle ist passwortgeschützt. Bitte -MitPasswort angeben."
        }
        # Iterationszahl aus dem Tabellenkopf lesen; Fallback auf 100.000 für ältere Tabellen ohne Feld
        $iterRaw = Get-JsonProp $obj "iterations"
        if ($null -eq $iterRaw) { $iterRaw = Get-JsonProp $obj "iterationen" }
        if ($null -eq $iterRaw) { $iterRaw = $script:PBKDF2_LEGACY_ITERATIONS }
        $iterations = Test-TableIterations -Value $iterRaw -Format "ANON-AES256-1"

        $salt = [Convert]::FromBase64String([string](Get-JsonProp $obj "salt"))
        $iv = [Convert]::FromBase64String([string](Get-JsonProp $obj "iv"))
        $expectedMac = [Convert]::FromBase64String([string](Get-JsonProp $obj "hmac"))
        $cipherBytes = [Convert]::FromBase64String([string](Get-JsonProp $obj "daten"))

        if ($expectedMac.Length -ne 32) {
            throw "Manipulierte Zuordnungstabelle: HMAC-Länge ungültig."
        }

        $key = [AnonTool.AnonCrypto]::DeriveMasterKey($PasswordSecure, $salt, $iterations, $false)
        try {
            $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$key)
            $actualMac = $hmac.ComputeHash($cipherBytes)
            $hmac.Dispose()
            if (-not (Test-HmacConstantTime32 -ExpectedMac $expectedMac -ActualMac $actualMac)) {
                throw "Falsches Passwort oder manipulierte Zuordnungstabelle (HMAC-Prüfung fehlgeschlagen)."
            }
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.Key = $key
            $aes.IV = $iv
            $decryptor = $aes.CreateDecryptor()
            $plainBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
            $aes.Dispose()
        } finally {
            [AnonTool.AnonCrypto]::Zero($key)
        }
        $script:LastLoadedProtection = "PASSWORD"
        $script:LastLoadedPasswordSecure = $PasswordSecure
        return [System.Text.Encoding]::UTF8.GetString($plainBytes)
    }
    elseif ($null -ne $fmt) {
        if ([string]$fmt -eq "ANON-WEBCRYPTO-AESGCM-1") {
            throw "Tabellenformat ANON-WEBCRYPTO-AESGCM-1 (ältere Browser-Tabelle) wird von anon.ps1 nicht unterstützt. Bitte in anonymisierer.html laden und neu speichern (ANON-AES256-2). Die Datei wird nicht überschrieben."
        }
        throw "Unbekanntes Tabellenformat. Die Datei wird nicht verwendet und nicht überschrieben."
    }
    # Unverschlüsselte Tabelle: muss die erwartete Struktur haben
    if ($null -eq (Get-JsonProp $obj "vorwaerts") -and $null -eq (Get-JsonProp $obj "rueckwaerts")) {
        throw "Unbekanntes Tabellenformat (weder verschlüsselt noch Zuordnungstabelle). Die Datei wird nicht verwendet und nicht überschrieben."
    }
    $script:LastLoadedProtection = "PLAIN"
    return $RawFileContent
}

function Import-AnonState {
    param(
        [string]$TablePath,
        [SecureString]$PasswordSecure
    )
    $state = New-Object AnonTool.AnonState
    $script:LastLoadedProtection = "NONE"
    if ([string]::IsNullOrEmpty($TablePath) -or -not (Test-Path -LiteralPath $TablePath)) {
        return $state
    }
    $raw = [AnonTool.TarGzHelper]::DecodeTextWithBom([System.IO.File]::ReadAllBytes($TablePath))
    $jsonText = Unprotect-TableContent -RawFileContent $raw -PasswordSecure $PasswordSecure
    $state.LoadedProtection = $script:LastLoadedProtection
    $tObj = ConvertFrom-Json -InputObject $jsonText

    $vorw = Get-JsonProp $tObj "vorwaerts"
    if ($null -ne $vorw) {
        foreach ($p in $vorw.PSObject.Properties) {
            $state.Forward[$p.Name] = [string]$p.Value
        }
    }
    $rueck = Get-JsonProp $tObj "rueckwaerts"
    if ($null -ne $rueck) {
        foreach ($p in $rueck.PSObject.Properties) {
            $state.Reverse[$p.Name] = [string]$p.Value
        }
    }
    $zaehl = Get-JsonProp $tObj "zaehler"
    if ($null -ne $zaehl) {
        foreach ($p in $zaehl.PSObject.Properties) {
            $state.Counters[$p.Name] = [int]$p.Value
        }
    }
    $nHosts = Get-JsonProp $tObj "netzHosts"
    if ($null -ne $nHosts) {
        foreach ($netProp in $nHosts.PSObject.Properties) {
            $dict = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($hProp in $netProp.Value.PSObject.Properties) {
                $dict[$hProp.Name] = [string]$hProp.Value
            }
            $state.NetHostForward[$netProp.Name] = $dict
        }
    }
    $als = Get-JsonProp $tObj "aliase"
    if ($null -ne $als) {
        foreach ($p in $als.PSObject.Properties) {
            $state.Aliases[$p.Name] = [string]$p.Value
        }
    }
    return $state
}

function Export-AnonState {
    param(
        [AnonTool.AnonState]$State,
        [string]$TablePath,
        [switch]$UseDpapi,
        [SecureString]$PasswordSecure,
        [switch]$Unverschluesselt
    )
    $fwd = [ordered]@{}
    foreach ($k in ($State.Forward.Keys | Sort-Object)) { $fwd[$k] = $State.Forward[$k] }
    $rev = [ordered]@{}
    foreach ($k in ($State.Reverse.Keys | Sort-Object)) { $rev[$k] = $State.Reverse[$k] }
    $cnt = [ordered]@{}
    foreach ($k in ($State.Counters.Keys | Sort-Object)) { $cnt[$k] = $State.Counters[$k] }
    $nh = [ordered]@{}
    foreach ($nk in ($State.NetHostForward.Keys | Sort-Object)) {
        $sub = [ordered]@{}
        foreach ($hk in ($State.NetHostForward[$nk].Keys | Sort-Object)) {
            $sub[$hk] = $State.NetHostForward[$nk][$hk]
        }
        $nh[$nk] = $sub
    }
    $als = [ordered]@{}
    if ($null -ne $State.Aliases) {
        foreach ($ak in ($State.Aliases.Keys | Sort-Object)) { $als[$ak] = $State.Aliases[$ak] }
    }

    $payload = [ordered]@{
        version     = "1.0"
        erstelltAm  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
        vorwaerts   = $fwd
        rueckwaerts = $rev
        zaehler     = $cnt
        netzHosts   = $nh
        aliase      = $als
    }
    $plainJson = $payload | ConvertTo-Json -Depth 8

    # Keine stille Herabstufung:
    # 1. Klartext nur wenn explizit -Unverschluesselt gesetzt wurde.
    # 2. Geladene Schutzart (PASSWORD oder DPAPI) bleibt beim Wiederspeichern erhalten.
    # 3. Neue Tabellen werden unter Windows standardmäßig mit DPAPI geschützt.
    $effDpapi = [bool]$UseDpapi
    $effPass  = $PasswordSecure

    if ($Unverschluesselt) {
        $effDpapi = $false
        $effPass  = $null
    } else {
        if ($null -eq $effPass -and -not $effDpapi) {
            if ($State.LoadedProtection -eq "PASSWORD") {
                $effPass = $script:LastLoadedPasswordSecure
                if ($null -eq $effPass) {
                    $effPass = Read-TablePasswordInteractive -ConfirmTwice:$true
                }
            } elseif ($State.LoadedProtection -eq "DPAPI") {
                $effDpapi = $true
            } else {
                $isWindowsOs = ($env:OS -eq "Windows_NT") -or ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
                if ($isWindowsOs -and ("System.Security.Cryptography.ProtectedData" -as [type])) {
                    $effDpapi = $true
                } else {
                    throw "Tabellenschutz erforderlich: Bitte -MitPasswort angeben oder für unverschlüsselte Klartext-Ablage explizit -Unverschluesselt setzen."
                }
            }
        }
    }

    $finalText = Protect-TableContent -PlainJson $plainJson -UseDpapi:$effDpapi -PasswordSecure $effPass

    $parentDir = Split-Path -Parent $TablePath
    if (-not [string]::IsNullOrEmpty($parentDir) -and -not (Test-Path -LiteralPath $parentDir)) {
        [void](New-Item -ItemType Directory -Path $parentDir -Force)
        Set-RestrictedUserAcl -TargetPath $parentDir
    }
    [System.IO.File]::WriteAllText($TablePath, $finalText, (New-Object System.Text.UTF8Encoding($false)))
    Set-RestrictedUserAcl -TargetPath $TablePath
}

# ============================================================================
# Hauptablauf
# ============================================================================

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($Regeln)) {
    # Admin-VM: anon-regeln.json liegt neben anon.ps1; im Repository unter ..\regeln\
    $Regeln = Join-Path $scriptDir "anon-regeln.json"
    $repoRegeln = Join-Path (Join-Path (Split-Path -Parent $scriptDir) "regeln") "anon-regeln.json"
    if (-not (Test-Path -LiteralPath $Regeln) -and (Test-Path -LiteralPath $repoRegeln)) {
        $Regeln = $repoRegeln
    }
}

if ($Netzerhaltend -and $NichtNetzerhaltend) {
    throw "-Netzerhaltend und -NichtNetzerhaltend schließen sich aus."
}
$netzOverride = $null
if ($Netzerhaltend) { $netzOverride = $true }
if ($NichtNetzerhaltend) { $netzOverride = $false }

$cfg = Load-EngineConfig -RegelDatei $Regeln -LokaleRegelDatei $LokaleRegeln -OverrideNetzerhaltend $netzOverride -AktivKategorien $Kategorien

# Konsolenausgabe von Prüftreffern: nur Kategorie, Datei und Zeile, nie der gefundene Wert
function Write-PruefFunde {
    param($Funde)
    foreach ($fd in $Funde) {
        Write-Host ("  [{0}] {1}:{2}" -f $fd.Kategorie, $fd.Datei, $fd.Zeile) -ForegroundColor Yellow
    }
}

# Fehlermeldungen ohne Datei- oder Pfadnamen: nur laufende Nummer, Schritt und Fehlerart
function Stop-MitNummer {
    param([int]$Nummer, [string]$Schritt, $Fehler)
    $art = "Fehler"
    if ($null -ne $Fehler -and $null -ne $Fehler.Exception) { $art = $Fehler.Exception.GetType().Name }
    throw ("Abbruch bei Datei Nr. {0} (Schritt: {1}, Fehlerart: {2})." -f $Nummer, $Schritt, $art)
}

# Rückübersetzter Klartext darf NIE unterhalb von anonym\ oder in einem Ausgabeordner eines Laufs liegen
# (erkennbar an den Geschwistern anonym\ und bericht.json)
function Assert-KlartextZiel {
    param([string]$Pfad)
    $dir = Split-Path -Parent ([System.IO.Path]::GetFullPath($Pfad))
    while (-not [string]::IsNullOrEmpty($dir)) {
        $leaf = Split-Path -Leaf $dir
        if ($leaf -ieq "anonym") {
            throw "SICHERHEITSFEHLER: Rückübersetzter Klartext darf nicht unterhalb eines Ordners 'anonym' gespeichert werden."
        }
        if ((Test-Path -LiteralPath (Join-Path $dir "anonym") -PathType Container) -and (Test-Path -LiteralPath (Join-Path $dir "bericht.json") -PathType Leaf)) {
            throw "SICHERHEITSFEHLER: Rückübersetzter Klartext darf nicht in einem Ausgabeordner eines Anonymisierungslaufs gespeichert werden."
        }
        $parent = Split-Path -Parent $dir
        if ($parent -eq $dir) { break }
        $dir = $parent
    }
}

# Basisordner %LOCALAPPDATA%\Anon (unter macOS/Linux: ~/.local/share/Anon)
function Get-AnonBaseDir {
    $localAppData = $env:LOCALAPPDATA
    if ([string]::IsNullOrEmpty($localAppData)) {
        $localAppData = Join-Path $HOME ".local/share"
    }
    return (Join-Path $localAppData "Anon")
}

# Arbeitsordner für entpackte Archive: %LOCALAPPDATA%\Anon\arbeit\<zufall>, ACL nur Benutzer.
# Eine offene Sperrdatei markiert den laufenden Lauf; verwaiste Ordner früherer Abbrüche werden beim Start entfernt.
function New-ArbeitsOrdner {
    $root = Join-Path (Get-AnonBaseDir) "arbeit"
    if (-not (Test-Path -LiteralPath $root)) {
        [void](New-Item -ItemType Directory -Path $root -Force)
        Set-RestrictedUserAcl -TargetPath $root
    }
    $isWindowsOs = ($env:OS -eq "Windows_NT") -or ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
    foreach ($alt in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
        $frei = $true
        $sperre = Join-Path $alt.FullName "lauf.lock"
        if (Test-Path -LiteralPath $sperre) {
            try {
                $fs = [System.IO.File]::Open($sperre, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                $fs.Dispose()
            } catch {
                $frei = $false
            }
        }
        # Ohne Windows-Dateisperren: nur Ordner entfernen, die älter als 24 Stunden sind
        if ($frei -and -not $isWindowsOs -and $alt.LastWriteTime -gt (Get-Date).AddHours(-24)) { $frei = $false }
        if ($frei) { Remove-Item -LiteralPath $alt.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $dir = Join-Path $root ([Guid]::NewGuid().ToString("N"))
    [void](New-Item -ItemType Directory -Path $dir -Force)
    Set-RestrictedUserAcl -TargetPath $dir
    $lockStream = [System.IO.File]::Open((Join-Path $dir "lauf.lock"), [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    return [pscustomobject]@{ Pfad = $dir; Sperre = $lockStream }
}

function Remove-ArbeitsOrdner {
    param($Arbeit)
    if ($null -eq $Arbeit) { return }
    try { $Arbeit.Sperre.Dispose() } catch {}
    if (Test-Path -LiteralPath $Arbeit.Pfad) {
        Remove-Item -LiteralPath $Arbeit.Pfad -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ----------------------------------------------------------------------------
# MODUS 1: Nur Prüfmodus (-Pruefen ohne Anonymisierungslauf)
# ----------------------------------------------------------------------------
if ($Pruefen -and [string]::IsNullOrEmpty($Ausgabe)) {
    if ($null -eq $Eingabe -or $Eingabe.Count -eq 0) {
        throw "Bitte -Eingabe für den Prüfmodus (-Pruefen) angeben."
    }
    $alleFunde = New-Object 'System.Collections.Generic.List[AnonTool.AuditFinding]'
    $einNr = 0
    $dateiNr = 0
    foreach ($ein in $Eingabe) {
        $einNr++
        if (-not (Test-Path -LiteralPath $ein)) {
            throw "Eingabe Nr. $einNr existiert nicht."
        }
        $item = Get-Item -LiteralPath $ein
        $files = @()
        if ($item.PSIsContainer) {
            $files = Get-ChildItem -LiteralPath $item.FullName -Recurse -File
        } else {
            $files = @($item)
        }
        foreach ($f in $files) {
            $dateiNr++
            try {
                $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                if ([AnonTool.TarGzHelper]::IsBinaryContent($bytes)) { continue }
                $txt = [AnonTool.TarGzHelper]::DecodeTextWithBom($bytes)
                $relAuditPath = if ($item.PSIsContainer) {
                    $f.FullName.Substring($item.FullName.Length).TrimStart('\', '/')
                } else {
                    $f.Name
                }
                $funde = [AnonTool.AnonEngine]::AuditText($txt, $relAuditPath, $cfg)
            } catch {
                Stop-MitNummer -Nummer $dateiNr -Schritt "Prüfen" -Fehler $_
            }
            foreach ($fd in $funde) { $alleFunde.Add($fd) }
        }
    }

    if ($alleFunde.Count -eq 0) {
        Write-Host "Prüfergebnis: SAUBER (0 Treffer)" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "Prüfergebnis: NICHT SAUBER ($($alleFunde.Count) Treffer gefunden)" -ForegroundColor Red
        Write-PruefFunde $alleFunde
        exit 2
    }
}

# ----------------------------------------------------------------------------
# MODUS 2: Rückübersetzung (-Zurueck)
# ----------------------------------------------------------------------------
if ($Zurueck) {
    if ($null -eq $Eingabe -or $Eingabe.Count -eq 0) {
        throw "Bitte mit -Eingabe die zu übersetzende Datei (z.B. KI-Antwort) angeben."
    }
    if ([string]::IsNullOrEmpty($TabellenPfad) -or -not (Test-Path -LiteralPath $TabellenPfad)) {
        throw "Für -Zurueck muss eine gültige Zuordnungstabelle über -TabellenPfad (oder -Tabelle) angegeben werden."
    }
    $activeSecPass = $PasswortSecure
    if ($MitPasswort -and $null -eq $activeSecPass) {
        $activeSecPass = Read-TablePasswordInteractive -ConfirmTwice:$false
    }
    $state = Import-AnonState -TablePath $TabellenPfad -PasswordSecure $activeSecPass
    $einNr = 0
    foreach ($ein in $Eingabe) {
        $einNr++
        try {
            $inBytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $ein).Path)
        } catch {
            Stop-MitNummer -Nummer $einNr -Schritt "Lesen" -Fehler $_
        }
        $rawText = [AnonTool.TarGzHelper]::DecodeTextWithBom($inBytes)
        $restored = [AnonTool.AnonEngine]::DeanonymizeText($rawText, $state.Reverse)

        # Zielpfad: -Ausgabe (eine Eingabe = Datei, mehrere Eingaben = Ordner) oder <Basis>\klartext\
        if (-not [string]::IsNullOrEmpty($Ausgabe)) {
            if ($Eingabe.Count -gt 1) {
                $zielPfad = Join-Path $Ausgabe ("rueck-{0:D3}.txt" -f $einNr)
            } else {
                $zielPfad = $Ausgabe
            }
        } else {
            $klartextDir = Join-Path (Get-AnonBaseDir) "klartext"
            $zielPfad = Join-Path $klartextDir ("rueck-{0}-{1:D3}.txt" -f (Get-Date).ToString("yyyyMMdd-HHmmss"), $einNr)
        }
        Assert-KlartextZiel -Pfad $zielPfad
        $zielDir = Split-Path -Parent ([System.IO.Path]::GetFullPath($zielPfad))
        if (-not (Test-Path -LiteralPath $zielDir)) {
            [void](New-Item -ItemType Directory -Path $zielDir -Force)
            Set-RestrictedUserAcl -TargetPath $zielDir
        }
        try {
            [System.IO.File]::WriteAllText($zielPfad, $restored, (New-Object System.Text.UTF8Encoding($false)))
        } catch {
            Stop-MitNummer -Nummer $einNr -Schritt "Schreiben" -Fehler $_
        }
        Set-RestrictedUserAcl -TargetPath $zielPfad
        Write-Host "Rückübersetzung gespeichert in: $zielPfad" -ForegroundColor Green
    }
    exit 0
}

# ----------------------------------------------------------------------------
# MODUS 3: Regulärer Anonymisierungslauf (bzw. -Probe Trockenlauf)
# ----------------------------------------------------------------------------
if ($null -eq $Eingabe -or $Eingabe.Count -eq 0) {
    throw "Bitte -Eingabe angeben (Datei, Ordner oder .zip/.tar.gz Archiv)."
}
if (-not $Probe -and [string]::IsNullOrEmpty($Ausgabe)) {
    throw "Bitte -Ausgabe angeben (Zielordner für anonymisierte Daten)."
}

# Tabellenpfad bestimmen und Sicherheitsprüfung durchführen (NIE im Ausgabeordner!)
if ([string]::IsNullOrEmpty($TabellenPfad)) {
    $defaultTabDir = Join-Path (Get-AnonBaseDir) "Tabellen"
    $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $TabellenPfad = Join-Path $defaultTabDir "tabelle-$stamp.json"
}

if (-not [string]::IsNullOrEmpty($Ausgabe)) {
    if (-not (Test-Path -LiteralPath $Ausgabe)) {
        [void](New-Item -ItemType Directory -Path $Ausgabe -Force)
    }
    $fullOut = [System.IO.Path]::GetFullPath($Ausgabe).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $fullTab = [System.IO.Path]::GetFullPath($TabellenPfad)
    if ($fullTab.StartsWith($fullOut, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SICHERHEITSFEHLER: Die Zuordnungstabelle (-TabellenPfad) darf NIEMALS innerhalb des Ausgabeordners (-Ausgabe) gespeichert werden!"
    }
}

$activeSecPass = $PasswortSecure
$tableExistsOnDisk = (-not [string]::IsNullOrEmpty($TabellenPfad)) -and (Test-Path -LiteralPath $TabellenPfad)
if ($MitPasswort -and $null -eq $activeSecPass) {
    # Beim Verschlüsseln einer neuen Tabelle wird das Passwort zweimal abgefragt, beim Laden einer bestehenden einmal
    $activeSecPass = Read-TablePasswordInteractive -ConfirmTwice:((-not $Probe) -and (-not $tableExistsOnDisk))
}

$state = Import-AnonState -TablePath $TabellenPfad -PasswordSecure $activeSecPass

$arbeit = $null
$arbeitOrdner = $null
$anonymOrdner = $null
if (-not $Probe) {
    $anonymOrdner = Join-Path $Ausgabe "anonym"
    if (Test-Path -LiteralPath $anonymOrdner) { Remove-Item -LiteralPath $anonymOrdner -Recurse -Force }
    [void](New-Item -ItemType Directory -Path $anonymOrdner -Force)
}
# Alter Arbeitsordner früherer Versionen im Ausgabeordner wird entfernt
if (-not [string]::IsNullOrEmpty($Ausgabe)) {
    $altArbeit = Join-Path $Ausgabe "_arbeit"
    if (Test-Path -LiteralPath $altArbeit) { Remove-Item -LiteralPath $altArbeit -Recurse -Force }
}

# Sammle alle zu verarbeitenden Dateien (inkl. rekursivem Entpacken von .zip / .tar.gz / .tgz im Arbeitsordner)
$dateiListe = New-Object 'System.Collections.Generic.List[psobject]'
$uebersprungeneDateien = New-Object 'System.Collections.Generic.List[string]'

function Expand-InputItem {
    param(
        [string]$ItemPath,
        [string]$RelPrefix,
        [string]$WorkRoot
    )
    $resolved = Get-Item -LiteralPath $ItemPath
    if ($resolved.PSIsContainer) {
        $children = Get-ChildItem -LiteralPath $resolved.FullName -Recurse -File
        foreach ($ch in $children) {
            $rel = $ch.FullName.Substring($resolved.FullName.Length).TrimStart('\', '/')
            if (-not [string]::IsNullOrEmpty($RelPrefix)) {
                $rel = Join-Path $RelPrefix $rel
            }
            Expand-InputItem -ItemPath $ch.FullName -RelPrefix $rel -WorkRoot $WorkRoot
        }
        return
    }

    $lowerName = $resolved.Name.ToLowerInvariant()
    $isZip = $lowerName.EndsWith(".zip")
    $isTarGz = $lowerName.EndsWith(".tar.gz") -or $lowerName.EndsWith(".tgz")
    $isTar = $lowerName.EndsWith(".tar")

    if (($isZip -or $isTarGz -or $isTar) -and -not [string]::IsNullOrEmpty($WorkRoot)) {
        $extractSub = Join-Path $WorkRoot ("ext_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
        [void](New-Item -ItemType Directory -Path $extractSub -Force)
        $archRelBase = if ([string]::IsNullOrEmpty($RelPrefix)) {
            ($resolved.Name -replace '(\.tar\.gz|\.tgz|\.zip|\.tar)$', '')
        } else {
            ($RelPrefix -replace '(\.tar\.gz|\.tgz|\.zip|\.tar)$', '')
        }

        if ($isZip) {
            [System.IO.Compression.ZipFile]::ExtractToDirectory($resolved.FullName, $extractSub)
        } elseif ($isTarGz) {
            [AnonTool.TarGzHelper]::ExtractTarGz($resolved.FullName, $extractSub)
        } elseif ($isTar) {
            [AnonTool.TarGzHelper]::ExtractTar($resolved.FullName, $extractSub)
        }

        $extractedFiles = Get-ChildItem -LiteralPath $extractSub -Recurse -File
        foreach ($ef in $extractedFiles) {
            $subRel = $ef.FullName.Substring($extractSub.Length).TrimStart('\', '/')
            $combinedRel = Join-Path $archRelBase $subRel
            Expand-InputItem -ItemPath $ef.FullName -RelPrefix $combinedRel -WorkRoot $WorkRoot
        }
        return
    }

    $finalRel = if ([string]::IsNullOrEmpty($RelPrefix)) { $resolved.Name } else { $RelPrefix }
    $dateiListe.Add([pscustomobject]@{
        QuellPfad = $resolved.FullName
        RelPfad   = $finalRel
    })
}

try {
    # Entpacken nie im Ausgabeordner, sondern unter %LOCALAPPDATA%\Anon\arbeit\<zufall>
    $arbeit = New-ArbeitsOrdner
    $arbeitOrdner = $arbeit.Pfad

    $einNr = 0
    foreach ($ein in $Eingabe) {
        $einNr++
        if (-not (Test-Path -LiteralPath $ein)) {
            throw "Eingabe Nr. $einNr nicht gefunden."
        }
        try {
            Expand-InputItem -ItemPath $ein -RelPrefix "" -WorkRoot $arbeitOrdner
        } catch {
            throw ("Abbruch bei Eingabe Nr. {0} (Schritt: Einlesen/Entpacken, Fehlerart: {1})." -f $einNr, $_.Exception.GetType().Name)
        }
    }

    $dateiBerichte = New-Object 'System.Collections.Generic.List[psobject]'
    $allePruefFunde = New-Object 'System.Collections.Generic.List[AnonTool.AuditFinding]'

    # Durchlauf 1: Alle Dateien einmal verarbeiten, damit Hostnamen aus späteren Dateien
    # (z.B. "hostname X" in Datei 3) auch in früheren Dateien ersetzt werden. Ausgabe wird verworfen.
    $dateiNr = 0
    foreach ($eintrag in $dateiListe) {
        $dateiNr++
        try {
            [void][AnonTool.AnonEngine]::ProcessPath($eintrag.RelPfad, $cfg, $state)
            $bytes = [System.IO.File]::ReadAllBytes($eintrag.QuellPfad)
            if ([AnonTool.TarGzHelper]::IsBinaryContent($bytes)) { continue }
            [void][AnonTool.AnonEngine]::ProcessText([AnonTool.TarGzHelper]::DecodeTextWithBom($bytes), $cfg, $state)
        } catch {
            Stop-MitNummer -Nummer $dateiNr -Schritt "Durchlauf 1" -Fehler $_
        }
    }
    $state.Stats = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)

    # Durchlauf 2: Endgültige Ausgabe mit vollständiger Zuordnungstabelle
    $anonErgebnisse = New-Object 'System.Collections.Generic.List[psobject]'
    $dateiNr = 0
    foreach ($eintrag in $dateiListe) {
        $dateiNr++
        try {
            $anonRelPfad = [AnonTool.AnonEngine]::ProcessPath($eintrag.RelPfad, $cfg, $state)
            $bytes = [System.IO.File]::ReadAllBytes($eintrag.QuellPfad)
        } catch {
            Stop-MitNummer -Nummer $dateiNr -Schritt "Lesen" -Fehler $_
        }
        if ([AnonTool.TarGzHelper]::IsBinaryContent($bytes)) {
            $uebersprungeneDateien.Add($anonRelPfad)
            continue
        }

        $vorherStats = @{}
        foreach ($k in $state.Stats.Keys) { $vorherStats[$k] = $state.Stats[$k] }

        try {
            $text = [AnonTool.TarGzHelper]::DecodeTextWithBom($bytes)
            $anonText = [AnonTool.AnonEngine]::ProcessText($text, $cfg, $state)
        } catch {
            Stop-MitNummer -Nummer $dateiNr -Schritt "Anonymisieren" -Fehler $_
        }

        $dateiStat = [ordered]@{}
        $gesamtInDatei = 0
        foreach ($k in $state.Stats.Keys) {
            $vorher = if ($vorherStats.ContainsKey($k)) { $vorherStats[$k] } else { 0 }
            $diff = $state.Stats[$k] - $vorher
            if ($diff -gt 0) {
                $dateiStat[$k] = $diff
                $gesamtInDatei += $diff
            }
        }

        if (-not $Probe) {
            $osRelPath = $anonRelPfad -replace '/', [System.IO.Path]::DirectorySeparatorChar
            $zielDatei = Join-Path $anonymOrdner $osRelPath
            $zielDir = Split-Path -Parent $zielDatei
            if (-not [string]::IsNullOrEmpty($zielDir) -and -not (Test-Path -LiteralPath $zielDir)) {
                [void](New-Item -ItemType Directory -Path $zielDir -Force)
            }
            try {
                [System.IO.File]::WriteAllText($zielDatei, $anonText, (New-Object System.Text.UTF8Encoding($false)))
            } catch {
                Stop-MitNummer -Nummer $dateiNr -Schritt "Schreiben" -Fehler $_
            }
        }

        $anonErgebnisse.Add([pscustomobject]@{
            Pfad      = $anonRelPfad
            Text      = $anonText
            DateiStat = $dateiStat
            Gesamt    = $gesamtInDatei
        })
    }

    # Automatische Nachprüfung jeder anonymisierten Datei inkl. Dateipfad, mit allen im Lauf erkannten Werten
    foreach ($erg in $anonErgebnisse) {
        $funde = [AnonTool.AnonEngine]::AuditText($erg.Text, $erg.Pfad, $cfg, $state)
        foreach ($fd in $funde) { $allePruefFunde.Add($fd) }
        $dateiBerichte.Add([pscustomobject][ordered]@{
            datei        = ($erg.Pfad -replace '\\', '/')
            ersetzungen  = $erg.Gesamt
            kategorien   = $erg.DateiStat
            pruefTreffer = $funde.Count
        })
    }
}
finally {
    # Arbeitsordner wird IMMER gelöscht, auch bei Fehler oder Abbruch (Strg+C)
    Remove-ArbeitsOrdner $arbeit
}

# Zuordnungstabelle speichern (nur wenn nicht -Probe)
if (-not $Probe) {
    Export-AnonState -State $state -TablePath $TabellenPfad -UseDpapi:$Dpapi -PasswordSecure $activeSecPass -Unverschluesselt:$Unverschluesselt
}

$pruefStatus = if ($allePruefFunde.Count -eq 0) { "SAUBER" } else { "RESTFUNDE_VORHANDEN" }

$gesamtKategorien = [ordered]@{}
foreach ($k in ($state.Stats.Keys | Sort-Object)) {
    $gesamtKategorien[$k] = $state.Stats[$k]
}

$pruefListe = @()
foreach ($fd in $allePruefFunde) {
    # Im gespeicherten Bericht keine echten Geheimnisse ablegen, nur Kategorie & Zeilennummer
    $pruefListe += [ordered]@{
        datei     = ($fd.Datei -replace '\\', '/')
        zeile     = $fd.Zeile
        kategorie = $fd.Kategorie
    }
}

$berichtObj = [ordered]@{
    zeitstempel          = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    modus                = if ($Probe) { "PROBE" } else { "ANONYMISIERUNG" }
    netzerhaltend        = $cfg.Netzerhaltend
    verarbeiteteDateien  = $dateiBerichte.Count
    uebersprungeneBinaer = @($uebersprungeneDateien | ForEach-Object { $_ -replace '\\', '/' })
    kategorienGesamt     = $gesamtKategorien
    dateien              = $dateiBerichte
    pruefergebnis        = $pruefStatus
    pruefTrefferAnzahl   = $allePruefFunde.Count
    pruefDetails         = $pruefListe
}

if (-not $Probe -and -not [string]::IsNullOrEmpty($Ausgabe)) {
    $berichtPfad = Join-Path $Ausgabe "bericht.json"
    $berichtJson = $berichtObj | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($berichtPfad, $berichtJson, (New-Object System.Text.UTF8Encoding($false)))
}

# Deutsche Konsolenausgabe
Write-Host "============================================================" -ForegroundColor Cyan
if ($Probe) {
    Write-Host " TROCKENLAUF (-Probe) - Es wurden keine Dateien geschrieben" -ForegroundColor Yellow
} else {
    Write-Host " ANONYMISIERUNG ABGESCHLOSSEN" -ForegroundColor Cyan
    Write-Host " Freigegebener Ordner : $anonymOrdner"
    Write-Host " Zuordnungstabelle    : $TabellenPfad (geschützt)"
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ("Verarbeitete Textdateien : {0}" -f $dateiBerichte.Count)
Write-Host ("Übersprungene Binärdat.  : {0}" -f $uebersprungeneDateien.Count)
if ($uebersprungeneDateien.Count -gt 0) {
    Write-Host ("  -> {0}" -f ($uebersprungeneDateien -join ", "))
}
Write-Host "Ersetzungen je Kategorie :"
foreach ($k in $gesamtKategorien.Keys) {
    Write-Host ("  - {0,-22}: {1}" -f $k, $gesamtKategorien[$k])
}
if ($pruefStatus -eq "SAUBER") {
    Write-Host "Prüfergebnis (-Pruefen)  : SAUBER (0 Treffer)" -ForegroundColor Green
    exit 0
} else {
    Write-Host ("Prüfergebnis (-Pruefen)  : {0} ({1} Treffer)" -f $pruefStatus, $allePruefFunde.Count) -ForegroundColor Red
    Write-PruefFunde $allePruefFunde
    exit 2
}
