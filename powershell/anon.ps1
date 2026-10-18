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
    Führt nur den Prüfmodus auf den angegebenen Dateien/Ordnern aus und gibt "KEINE_RESTFUNDE" (Keine Restfunde nach aktivem Regelwerk) bei 0 Treffern zurück.

.PARAMETER Probe
    Trockenlauf: Zeigt nur, was ersetzt würde (Anzahl je Kategorie), schreibt keine anonymisierten Dateien.

.PARAMETER Strukturvorlage
    Erzeugt aus den Eingabedateien Kopien, in denen alle Werte durch ihre Form ersetzt sind
    (Großbuchstabe -> A, Kleinbuchstabe -> a, Ziffer -> 9, Sonderzeichen bleiben). Bekannte CLI-Schlüsselwörter
    und Tabellenköpfe (feste Liste regeln\strukturvorlage.json) bleiben, Freitextfelder werden <FREITEXT>,
    Geheimnisse *****. Zweck: Regeln für reale Formate entwickeln. Vor Weitergabe sichten!
    Ziel: -Ausgabe (Ordner) oder %LOCALAPPDATA%\Anon\struktur\<Zeitstempel>\.

.PARAMETER Strukturwoerter
    Pfad zur Schlüsselwortliste (Standard: strukturvorlage.json neben anon.ps1, sonst ..\regeln\).

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
    [switch]$Strukturvorlage,

    [Parameter(Mandatory = $false)]
    [string]$Strukturwoerter,

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

            // Zentrale Vergabe: nie einen Platzhalter, der schon vergeben, fest zugeordnet oder als Alias reserviert ist
            string token;
            do
            {
                int num = NextCounter(prefix);
                token = prefix + "-" + num.ToString();
            } while (Reverse.ContainsKey(token) || Aliases.ContainsKey(token));
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
        public int ValueGroup = -1; // Gruppe mit dem Geheimnis (höchste nicht im Ersetzungstext verwendete Gruppe)
        public bool NurWertSchuetzen; // nur ***** schützen, Rest bleibt für spätere Stufen erkennbar (z.B. URL)
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
        public int Vorkommen = 1; // n-tes Vorkommen des Spaltennamens in der Kopfzeile
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
        public List<Regex> BenutzerMusterSchwach = new List<Regex>();
        public List<Regex> HostnamenMuster = new List<Regex>();
        public List<TableRule> TabellenSpalten = new List<TableRule>();
        // CLI-Schlüsselwörter und Tabellenköpfe (regeln/strukturvorlage.json): werden nie als Host/Benutzer/Seriennummer gelernt
        public HashSet<string> LernStoppwoerter = new HashSet<string>(StringComparer.Ordinal);
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

        private static int FindHeaderWordNth(string line, string word, int n)
        {
            int pos = -1;
            int start = 0;
            for (int k = 0; k < Math.Max(1, n); k++)
            {
                string rest = line.Substring(start);
                int i = FindHeaderWord(rest, word);
                if (i < 0) return -1;
                pos = start + i;
                start = pos + word.Length;
                if (start > line.Length) return -1;
            }
            return pos;
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
                        int s = FindHeaderWordNth(line, sp.Name, sp.Vorkommen);
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

        // ----------------------------------------------------------------
        // Paket A: JSON-Escapes, Lernregeln, Geheimnisse in Tabellenwerten, bekannte Werte, Kollisionen
        // ----------------------------------------------------------------
        private static readonly Regex RxJsonString = new Regex("\"(?:[^\"\\\\\\r\\n]|\\\\.)*\"", RegexOptions.Compiled, RxTimeout);
        private static readonly Regex RxJsonEscape = new Regex("\\\\(u[0-9A-Fa-f]{4}|.)", RegexOptions.Compiled, RxTimeout);

        // \uXXXX (druckbar, kein " oder \) und \/ in JSON-Strings dekodieren: gleiche Bedeutung, gültiges JSON, Werte erkennbar
        public static string DecodeJsonStringEscapes(string text)
        {
            if (string.IsNullOrEmpty(text) || text.IndexOf('\\') < 0) return text;
            return RxJsonString.Replace(text, (Match lit) =>
            {
                if (lit.Value.IndexOf('\\') < 0) return lit.Value;
                return RxJsonEscape.Replace(lit.Value, (Match e) =>
                {
                    string t = e.Groups[1].Value;
                    if (t == "/") return "/";
                    if (t.Length == 5 && (t[0] == 'u'))
                    {
                        int code = Convert.ToInt32(t.Substring(1), 16);
                        if (code >= 0x20 && code != 0x22 && code != 0x5C && code != 0x7F && (code < 0xD800 || code > 0xDFFF))
                            return ((char)code).ToString();
                    }
                    return e.Value;
                });
            });
        }

        // Gelernte Werte: keine CLI-Schlüsselwörter/Tabellenköpfe; Hosts und Seriennummern brauchen Ziffer oder Bindestrich
        // kontextgebunden = Wert steht in einem eindeutig bezeichneten Feld (hostname X, Serial Number: X, user X ...):
        // dann gilt nur die Stoppliste. Kontextfreie Heuristik (CLI-Prompt, Tabellenspalten) verlangt zusätzlich Ziffer oder Bindestrich.
        public static bool IsLearnable(string category, string value, EngineConfig cfg)
        {
            return IsLearnable(category, value, cfg, false);
        }

        public static bool IsLearnable(string category, string value, EngineConfig cfg, bool kontextgebunden)
        {
            string v = (value ?? "").Trim();
            if (v.Length == 0) return false;
            if (cfg.LernStoppwoerter.Contains(v.ToLowerInvariant())) return false;
            // Nur aus Schlüsselwörtern mit "-" oder Leerzeichen zusammengesetzt (z.B. PORT-DESC, Local Intf): Tabellenkopf
            bool allStop = true;
            bool anyPart = false;
            bool onlyDashOrSpace = true;
            StringBuilder part = new StringBuilder();
            foreach (char c in v + " ")
            {
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) { part.Append(c); continue; }
                if (c != '-' && c != ' ' && c != '\t') onlyDashOrSpace = false;
                if (part.Length > 0)
                {
                    anyPart = true;
                    if (!cfg.LernStoppwoerter.Contains(part.ToString().ToLowerInvariant())) allStop = false;
                    part.Length = 0;
                }
            }
            if (anyPart && allStop && onlyDashOrSpace) return false;
            if (!kontextgebunden && (category == "HOST" || category == "SERIAL"))
            {
                bool digitOrDash = false;
                foreach (char c in v) { if ((c >= '0' && c <= '9') || c == '-') { digitOrDash = true; break; } }
                if (!digitOrDash) return false;
            }
            return true;
        }

        // Ersetzung eines Geheimnisses; war der Wert in Anführungszeichen, bleiben sie um ***** erhalten
        public static string SecretReplacement(SecretRule rule, Match m)
        {
            string rep = m.Result(rule.Replacement);
            if (rule.ValueGroup < 0)
            {
                int[] nums = rule.Compiled.GetGroupNumbers();
                int vg = 0;
                foreach (int g in nums)
                {
                    if (g == 0 || g > 9) continue;
                    if (rule.Replacement.IndexOf("$" + g.ToString(), StringComparison.Ordinal) < 0 && g > vg) vg = g;
                }
                rule.ValueGroup = vg;
            }
            if (rule.ValueGroup > 0 && rule.ValueGroup < m.Groups.Count && m.Groups[rule.ValueGroup].Success)
            {
                string v = m.Groups[rule.ValueGroup].Value;
                int star = rep.IndexOf("*****", StringComparison.Ordinal);
                if (star >= 0 && v.Length >= 2 && (v[0] == '"' || v[0] == '\'') && v[v.Length - 1] == v[0])
                    rep = rep.Substring(0, star) + v[0] + "*****" + v[0] + rep.Substring(star + 5);
            }
            return rep;
        }

        // Geheimnisse in einem Wert entfernen, bevor er als Original in die Zuordnungstabelle gelangt
        private static string RemoveSecretsPlain(string value, EngineConfig cfg)
        {
            if (!cfg.CatGeheimnisse || string.IsNullOrEmpty(value)) return value;
            string v = value;
            foreach (SecretRule rule in cfg.GeheimnisMuster)
            {
                v = rule.Compiled.Replace(v, (Match m) => SecretReplacement(rule, m));
            }
            return v;
        }

        // Allgemeine Wörter, die als Benutzername vorkommen, aber auch im normalen Text stehen (identisch zu anonymisierer.html)
        private static readonly HashSet<string> AllgemeineBenutzerwoerter = new HashSet<string>(new string[] { "admin", "administrator", "anonymous", "audit", "backup", "default", "demo", "ftp", "guest",
            "manager", "monitor", "monitoring", "network", "nobody", "operator", "readonly", "readwrite", "root", "security", "service",
            "support", "system", "test", "tester", "user" }, StringComparer.Ordinal);
        // Wörter, die nach einem Feldnamen stehen können, aber kein Wert sind ("for user from ...")
        private static readonly HashSet<string> KeinFeldwert = new HashSet<string>(new string[] { "from", "to", "on", "at", "with", "via", "in", "by", "for", "is", "was", "has", "the", "a", "an", "of", "and", "or", "not", "name", "id" }, StringComparer.Ordinal);

        // Mehrdeutiger Benutzer: CLI-Schlüsselwort oder allgemeines Wort; wird nur im Feldkontext ersetzt, nie als freies Wort
        public static bool IsAmbiguousUser(string value, EngineConfig cfg)
        {
            string v = (value ?? "").Trim();
            return AllgemeineBenutzerwoerter.Contains(v.ToLowerInvariant()) || !IsLearnable("USER", v, cfg, true);
        }

        // Bekannte Originalwerte bestimmter Kategorien (Schlüssel "PREFIX|wert") -> Platzhalter
        public static SortedDictionary<string, string> CollectKnownValues(AnonState state, string[] prefixes, EngineConfig cfg)
        {
            SortedDictionary<string, string> sorted = new SortedDictionary<string, string>(new LengthDescOrdinal());
            foreach (KeyValuePair<string, string> kv in state.Forward)
            {
                foreach (string pf in prefixes)
                {
                    if (!kv.Key.StartsWith(pf, StringComparison.OrdinalIgnoreCase)) continue;
                    string v = kv.Key.Substring(pf.Length).Trim().ToLowerInvariant();
                    if (string.Equals(pf, "USER|", StringComparison.OrdinalIgnoreCase) && IsAmbiguousUser(v, cfg)) break;
                    if (v.Length >= 3 && !cfg.ExakteAusnahmen.Contains(v) && !sorted.ContainsKey(v)) sorted[v] = kv.Value;
                    break;
                }
            }
            return sorted;
        }

        private static readonly string[] PathKnownCategories = new string[] { "HOST|", "SERIAL|", "USER|", "MAIL|", "URL|", "FIRMA|", "DOMAIN|", "FIXED|" };

        // Dateinamen: bekannte Originalwerte auch an "-", "_" und "." grenzend ersetzen
        private static string ReplaceKnownInPathPart(string part, AnonState state, EngineConfig cfg)
        {
            SortedDictionary<string, string> known = CollectKnownValues(state, PathKnownCategories, cfg);
            if (known.Count == 0 || string.IsNullOrEmpty(part)) return part;
            List<string> esc = new List<string>(known.Count);
            foreach (string k in known.Keys) esc.Add(Regex.Escape(k));
            string pat = "(?<=^|[-_.])(?:" + string.Join("|", esc.ToArray()) + ")(?=$|[-_.])";
            return Regex.Replace(part, pat, (Match m) =>
            {
                string tok;
                return known.TryGetValue(m.Value.ToLowerInvariant(), out tok) ? tok : m.Value;
            }, RegexOptions.IgnoreCase, RxTimeout);
        }

        // Beide Richtungen einer importierten Tabelle passen zusammen (zulässig: MAC-Normalisierung, Groß-/Kleinschreibung)
        public static List<string> ValidateStateConsistency(AnonState state)
        {
            List<string> fehler = new List<string>();
            List<string> keys = new List<string>(state.Forward.Keys);
            keys.Sort(StringComparer.Ordinal);
            foreach (string fk in keys)
            {
                string tok = state.Forward[fk];
                if (string.IsNullOrWhiteSpace(tok)) { fehler.Add("Leerer Platzhalter in der Vorwärtsrichtung"); continue; }
                int bar = fk.IndexOf('|');
                string kat = bar >= 0 ? fk.Substring(0, bar).ToUpperInvariant() : "";
                string raw = (bar >= 0 ? fk.Substring(bar + 1) : fk).Trim().ToLowerInvariant();
                string rv;
                if (!state.Reverse.TryGetValue(tok, out rv))
                {
                    fehler.Add("Platzhalter " + tok.ToUpperInvariant() + " fehlt in der Rückrichtung");
                    continue;
                }
                string rvNorm = (rv ?? "").Trim().ToLowerInvariant();
                if (kat == "MAC") rvNorm = NormalizeMac(rvNorm);
                if (rvNorm != raw)
                    fehler.Add("Platzhalter " + tok.ToUpperInvariant() + ": Vorwärts- und Rückrichtung widersprechen sich");
            }
            return fehler;
        }

        // Eindeutigkeit der Platzhalter: ein Platzhalter darf nur für einen Originalwert stehen
        public static List<string> FindPlaceholderCollisions(AnonState state, Dictionary<string, string> festeZuordnung)
        {
            Dictionary<string, HashSet<string>> byToken = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            Action<string, string> add = (string tok, string raw) =>
            {
                if (string.IsNullOrEmpty(tok)) return;
                HashSet<string> set;
                if (!byToken.TryGetValue(tok, out set)) { set = new HashSet<string>(StringComparer.Ordinal); byToken[tok] = set; }
                set.Add((raw ?? "").Trim().ToLowerInvariant());
            };
            foreach (KeyValuePair<string, string> kv in state.Forward)
            {
                int bar = kv.Key.IndexOf('|');
                add(kv.Value, bar >= 0 ? kv.Key.Substring(bar + 1) : kv.Key);
            }
            if (festeZuordnung != null)
            {
                foreach (KeyValuePair<string, string> kv in festeZuordnung)
                {
                    if (string.IsNullOrWhiteSpace(kv.Key) || string.IsNullOrWhiteSpace(kv.Value)) continue;
                    add(kv.Value.Trim(), kv.Key);
                    string vorhanden;
                    if (state.Reverse.TryGetValue(kv.Value.Trim(), out vorhanden)) add(kv.Value.Trim(), vorhanden);
                }
            }
            List<string> result = new List<string>();
            List<string> tokens = new List<string>(byToken.Keys);
            tokens.Sort(StringComparer.Ordinal);
            foreach (string tok in tokens)
            {
                if (byToken[tok].Count > 1)
                    result.Add("Platzhalter " + tok.ToUpperInvariant() + " steht für " + byToken[tok].Count.ToString() + " verschiedene Originalwerte");
            }
            return result;
        }

        public static string ProcessText(string input, EngineConfig cfg, AnonState state)
        {
            if (string.IsNullOrEmpty(input)) return input;

            // JSON-Escapes für die Erkennung dekodieren (Ergebnis bleibt gültiges JSON)
            string text = DecodeJsonStringEscapes(input);

            // Feste Zuordnungen vorab reservieren, damit automatische Platzhalter nie kollidieren
            if (cfg.CatEigeneBegriffe)
            {
                foreach (KeyValuePair<string, string> kvFix in cfg.FesteZuordnung)
                {
                    if (!string.IsNullOrEmpty(kvFix.Key) && !string.IsNullOrEmpty(kvFix.Value) && !cfg.ExakteAusnahmen.Contains(kvFix.Key.Trim()))
                        state.RegisterFixed(kvFix.Key, kvFix.Value);
                }
            }

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
                        // Geheimnisse zuerst entfernen: das Original in der Tabelle darf kein Geheimnis enthalten
                        string wert = RemoveSecretsPlain(f.Wert, cfg);
                        string rep = null;
                        if (f.Kategorie == "HOST")
                        {
                            if (!cfg.CatHostnamen || !IsLearnable("HOST", wert, cfg)) continue;
                            state.AddStat("hostnamen", 1);
                            rep = state.GetOrCreateToken("HOST", wert, "HOST");
                        }
                        else if (f.Kategorie == "SERIAL")
                        {
                            if (!cfg.CatSeriennummern || !IsLearnable("SERIAL", wert, cfg)) continue;
                            state.AddStat("seriennummern", 1);
                            rep = state.GetOrCreateToken("SERIAL", wert, "SERIAL");
                        }
                        else
                        {
                            if (!cfg.CatFreitext) continue;
                            state.AddStat("freitext", 1);
                            rep = state.GetOrCreateToken("FREITEXT_" + f.Kategorie, wert, f.Kategorie);
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
                        string rep = SecretReplacement(rule, m);
                        return rule.NurWertSchuetzen ? rep.Replace("*****", protect("*****")) : protect(rep);
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
                        if (string.IsNullOrEmpty(val) || cfg.ExakteAusnahmen.Contains(val) || val == "*****" || !IsLearnable("SERIAL", val, cfg, true))
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
                // Starke Feldmuster (user X password ..., for user X, [user: X]): Stoppliste blockiert nicht.
                // Schwache Muster (user X am Zeilenende, User X logged in): keine CLI-Wörter, keine allgemeinen Wörter.
                List<KeyValuePair<Regex, bool>> userRules = new List<KeyValuePair<Regex, bool>>();
                foreach (Regex r in cfg.BenutzerMuster) userRules.Add(new KeyValuePair<Regex, bool>(r, true));
                foreach (Regex r in cfg.BenutzerMusterSchwach) userRules.Add(new KeyValuePair<Regex, bool>(r, false));
                foreach (KeyValuePair<Regex, bool> ur in userRules)
                {
                    Regex uRx = ur.Key;
                    bool stark = ur.Value;
                    text = uRx.Replace(text, (Match m) =>
                    {
                        string val = m.Groups[2].Value.Trim();
                        if (string.IsNullOrEmpty(val) || cfg.ExakteAusnahmen.Contains(val) || val == "*****" || KeinFeldwert.Contains(val.ToLowerInvariant()))
                            return m.Value;
                        if (!stark && IsAmbiguousUser(val, cfg)) return m.Value;
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
                    string tok = state.GetOrCreateToken("MAIL", unprotect(m.Value), "MAIL");
                    return protect(tok);
                });

                text = RxUrl.Replace(text, (Match m) =>
                {
                    if (cfg.ExakteAusnahmen.Contains(m.Value)) return m.Value;
                    state.AddStat("hostnamen", 1);
                    // Original ohne Schutz-Marker speichern (enthaltene Zugangsdaten sind bereits *****)
                    string tok = state.GetOrCreateToken("URL", unprotect(m.Value), "URL");
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
                            if (string.IsNullOrEmpty(hVal) || cfg.ExakteAusnahmen.Contains(hVal) || hVal.StartsWith("\u0002PROT_") || !IsLearnable("HOST", hVal, cfg, true))
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
                            if (string.IsNullOrEmpty(hVal) || cfg.ExakteAusnahmen.Contains(hVal) || hVal.StartsWith("\u0002PROT_") || !IsLearnable("HOST", hVal, cfg, true))
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
                    if (cfg.ExakteAusnahmen.Contains(hVal) || hVal.StartsWith("\u0002PROT_") || !IsLearnable("HOST", hVal, cfg))
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
            // STUFE 11: Einmal gelernte Seriennummern und Benutzer im ganzen Lauf ersetzen
            // ----------------------------------------------------------------
            List<string> otherPrefixes = new List<string>();
            if (cfg.CatSeriennummern) otherPrefixes.Add("SERIAL|");
            if (cfg.CatBenutzer) otherPrefixes.Add("USER|");
            if (otherPrefixes.Count > 0)
            {
                SortedDictionary<string, string> knownOther = CollectKnownValues(state, otherPrefixes.ToArray(), cfg);
                if (knownOther.Count > 0)
                {
                    List<string> escOther = new List<string>(knownOther.Count);
                    foreach (string ko in knownOther.Keys) escOther.Add(Regex.Escape(ko));
                    string otherPat = "(?<![A-Za-z0-9-])(?:" + string.Join("|", escOther.ToArray()) + ")(?![A-Za-z0-9-])";
                    text = Regex.Replace(text, otherPat, (Match m) =>
                    {
                        string tok;
                        if (knownOther.TryGetValue(m.Value.ToLowerInvariant(), out tok))
                        {
                            state.AddStat(tok.StartsWith("SERIAL", StringComparison.OrdinalIgnoreCase) ? "seriennummern" : "benutzer", 1);
                            return protect(tok);
                        }
                        return m.Value;
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

        // ----------------------------------------------------------------
        // Strukturvorlage: Form der Daten ohne Werte (A = Großbuchstabe, a = Kleinbuchstabe, 9 = Ziffer).
        // Bekannte Schlüsselwörter (feste Liste) bleiben, Freitextfelder werden <FREITEXT>, Geheimnisse *****.
        // ----------------------------------------------------------------
        public static HashSet<string> BuildKeywordSet(IEnumerable<string> words)
        {
            HashSet<string> set = new HashSet<string>(StringComparer.Ordinal);
            foreach (string w in words)
            {
                if (string.IsNullOrEmpty(w)) continue;
                StringBuilder part = new StringBuilder();
                foreach (char c in w + " ")
                {
                    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) { part.Append(c); continue; }
                    if (part.Length > 0) { set.Add(part.ToString().ToLowerInvariant()); part.Length = 0; }
                }
            }
            return set;
        }

        private static bool IsShapeWordChar(char c)
        {
            return char.IsLetter(c) || (c >= '0' && c <= '9');
        }

        private static string ShapeSegment(string seg, HashSet<string> keywords)
        {
            StringBuilder sb = new StringBuilder(seg.Length);
            int i = 0;
            while (i < seg.Length)
            {
                if (!IsShapeWordChar(seg[i])) { sb.Append(seg[i]); i++; continue; }
                int j = i;
                while (j < seg.Length && IsShapeWordChar(seg[j])) j++;
                string run = seg.Substring(i, j - i);
                if (keywords.Contains(run.ToLowerInvariant())) { sb.Append(run); i = j; continue; }
                int k = i;
                while (k < j)
                {
                    int e = k;
                    bool digit = seg[k] >= '0' && seg[k] <= '9';
                    while (e < j && ((seg[e] >= '0' && seg[e] <= '9') == digit)) e++;
                    string part = seg.Substring(k, e - k);
                    if (digit) sb.Append('9', part.Length);
                    else if (keywords.Contains(part.ToLowerInvariant())) sb.Append(part);
                    else
                    {
                        foreach (char c in part) sb.Append(char.IsUpper(c) ? 'A' : 'a');
                    }
                    k = e;
                }
                i = j;
            }
            return sb.ToString();
        }

        public static string BuildStructureTemplate(string input, EngineConfig cfg, HashSet<string> keywords, string freitextPlatzhalter)
        {
            if (string.IsNullOrEmpty(input)) return input;
            string text = DecodeJsonStringEscapes(input);
            List<string> protectedValues = new List<string>();
            Func<string, string> protect = (string val) =>
            {
                int idx = protectedValues.Count;
                protectedValues.Add(val);
                return "\u0002PROT_" + idx.ToString() + "\u0003";
            };

            // 1. Tabellenspalten: Text-Spalten werden Freitext, Host-Spalten werden später geformt
            List<TableField> fields = FindTableFields(text, cfg);
            if (fields.Count > 0)
            {
                StringBuilder sbTab = new StringBuilder(text.Length);
                int lastPos = 0;
                foreach (TableField f in fields)
                {
                    if (f.Kategorie == "HOST" || f.Kategorie == "SERIAL" || IsTableValueExempt(f.Wert, cfg)) continue;
                    string rep = freitextPlatzhalter;
                    int fEnd = f.Start + f.Length;
                    if (rep.Length < f.Length && !IsLineRestBlank(text, fEnd)) rep = rep + new string(' ', f.Length - rep.Length);
                    sbTab.Append(text, lastPos, f.Start - lastPos);
                    sbTab.Append(protect(rep));
                    lastPos = fEnd;
                }
                sbTab.Append(text, lastPos, text.Length - lastPos);
                text = sbTab.ToString();
            }

            // 2. Geheimnisse: nur "*****" wird geschützt, Präfixe (Schlüsselwörter) werden geformt
            foreach (SecretRule rule in cfg.GeheimnisMuster)
            {
                text = rule.Compiled.Replace(text, (Match m) =>
                {
                    string rep = SecretReplacement(rule, m);
                    return rep.Replace("*****", protect("*****"));
                });
            }

            // 3. Freitext-Felder komplett ersetzen (ohne Ausnahmen)
            foreach (FreeTextRule fRule in cfg.FreitextMuster)
            {
                text = fRule.Compiled.Replace(text, (Match m) =>
                {
                    if (m.Groups.Count >= 5 && fRule.Category == "BANNER")
                    {
                        if (m.Groups[3].Value.Trim().Length == 0) return m.Value;
                        return m.Groups[1].Value + m.Groups[2].Value + protect(freitextPlatzhalter) + m.Groups[4].Value;
                    }
                    else if (m.Groups.Count >= 4)
                    {
                        if (m.Groups[2].Value.Trim().Length == 0) return m.Value;
                        return m.Groups[1].Value + protect(freitextPlatzhalter) + m.Groups[3].Value;
                    }
                    else if (m.Groups.Count >= 3)
                    {
                        if (m.Groups[2].Value.Trim().Length == 0) return m.Value;
                        return m.Groups[1].Value + protect(freitextPlatzhalter);
                    }
                    return m.Value;
                });
            }

            // 4. Alles außerhalb der Schutz-Marker formen
            StringBuilder sbOut = new StringBuilder(text.Length);
            int pos = 0;
            foreach (Match mk in RxUnprotect.Matches(text))
            {
                sbOut.Append(ShapeSegment(text.Substring(pos, mk.Index - pos), keywords));
                sbOut.Append(mk.Value);
                pos = mk.Index + mk.Length;
            }
            sbOut.Append(ShapeSegment(text.Substring(pos), keywords));
            text = sbOut.ToString();

            // 5. Schutz-Marker auflösen (geschützte Werte enthalten selbst Marker der Präfixe nicht)
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
                string anonCore = ReplaceKnownInPathPart(string.Join("_", subParts), state, cfg);
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

        private static bool IsTokenChar(char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        }

        // Wort um eine Fundstelle: Buchstaben, Ziffern, ".", "_" und "-", ohne abschließenden Punkt
        public static string SurroundingToken(string text, int start, int length)
        {
            int a = start;
            int b = start + length;
            while (a > 0 && IsTokenChar(text[a - 1])) a--;
            while (b < text.Length && IsTokenChar(text[b])) b++;
            while (b > a && text[b - 1] == '.') b--;
            return text.Substring(a, b - a);
        }

        private static string PickGroupValue(Match m)
        {
            if (m.Groups.Count >= 3 && m.Groups[2].Success) return m.Groups[2].Value.Trim();
            if (m.Groups.Count >= 2 && m.Groups[1].Success) return m.Groups[1].Value.Trim();
            return m.Value.Trim();
        }

        // Platzhalter in der Ausgabe (für die Suche nach bekannten Originalwerten ausblenden)
        private static readonly Regex RxPlaceholder = new Regex(@"(?<![A-Za-z0-9_-])(?:NET-[0-9]+(?:\.H[0-9]+)?|IP6?(?:-PRIV|-PUB)?-[0-9]+|(?:MAC|HOST|DOMAIN|USER|SERIAL|TEXT|MAIL|URL|ORT|KONTAKT|BANNER|FIRMA|PERSON)-[0-9]+)(?![A-Za-z0-9_])", RegexOptions.Compiled, RxTimeout);
        private static readonly Regex RxCredentialSuspect = new Regex("(?i)(?<![A-Za-z0-9_-])(password|passwd|passwort|kennwort|pwd|secret|api[_-]?key|token|authorization)(?:[ \\t]*[:=][ \\t]*|[ \\t]+)\"?([^ \\t\\r\\n\"',;]+)", RegexOptions.Compiled, RxTimeout);
        private static readonly HashSet<string> CredentialStopWords = new HashSet<string>(new string[] {
            "for", "from", "is", "was", "has", "of", "to", "required", "expired", "changed", "incorrect", "invalid", "accepted", "failed",
            "authentication", "policy", "prompt", "plaintext", "ciphertext", "cipher", "simple", "hash", "encrypted", "level", "basic", "bearer",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" }, StringComparer.Ordinal);
        private static readonly Regex RxPartialMask = new Regex("\"[^\"\\r\\n]*\\*{5}[^\"\\r\\n]*\"|'[^'\\r\\n]*\\*{5}[^'\\r\\n]*'|[A-Za-z0-9]\\*{5}|\\*{5}[A-Za-z0-9]", RegexOptions.Compiled, RxTimeout);
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

            // 0b. Im Lauf erkannte Originalwerte im Dateipfad (Grenzen: alles außer Buchstabe/Ziffer)
            if (state != null && !string.IsNullOrEmpty(fileName))
            {
                SortedDictionary<string, string> knownPath = CollectKnownValues(state, PathKnownCategories, cfg);
                List<string> escPath = new List<string>();
                foreach (string k in knownPath.Keys) { if (!IsAllowedInAudit(k, cfg)) escPath.Add(Regex.Escape(k)); }
                if (escPath.Count > 0)
                {
                    Regex rxKnownPath = new Regex("(?<![A-Za-z0-9])(?:" + string.Join("|", escPath.ToArray()) + ")(?![A-Za-z0-9])", RegexOptions.IgnoreCase, RxTimeout);
                    string pathMasked = RxPlaceholder.Replace(fileName.Replace('\\', '/'), (Match pm) => new string(' ', pm.Length));
                    foreach (Match m in rxKnownPath.Matches(pathMasked))
                    {
                        findings.Add(new AuditFinding { Datei = fileName, Zeile = 0, Kategorie = "Pfad-Bekannt", Fund = m.Value, Kontext = "Dateipfad: " + fileName });
                    }
                }
            }

            if (string.IsNullOrEmpty(text)) return findings;
            text = DecodeJsonStringEscapes(text);

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
                    if (SecretReplacement(sRule, m) == m.Value) continue;
                    int ln = GetLineNumber(lineStarts, m.Index);
                    findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-Geheimnis", Fund = m.Value, Kontext = getLineCtx(ln) });
                }
            }

            // 6c. Verdacht-Zugangsdaten: Zugangsdaten-Schlüsselwort mit nicht maskiertem Wert
            foreach (Match m in RxCredentialSuspect.Matches(cleanText))
            {
                string val = m.Groups[2].Value;
                if (val.StartsWith("*****") || CredentialStopWords.Contains(val.ToLowerInvariant()) || IsAllowedAuditPart(val, cfg)) continue;
                // Modifikator vor einem bereits maskierten Wert (z.B. "password ENC *****")
                if (Regex.IsMatch(cleanText.Substring(m.Index + m.Length), "^[ \t]+\\*{5}", RegexOptions.None, RxTimeout)) continue;
                int ln = GetLineNumber(lineStarts, m.Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Verdacht-Zugangsdaten", Fund = m.Value, Kontext = getLineCtx(ln) });
            }

            // 6d. Teilweise maskierte Werte ("***** Rest", "*****x", "x*****")
            foreach (Match m in RxPartialMask.Matches(cleanText))
            {
                string inner = m.Value.Trim('"', '\'');
                if (inner == "*****") continue;
                int ln = GetLineNumber(lineStarts, m.Index);
                findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Verdacht-Teilmaskierung", Fund = m.Value, Kontext = getLineCtx(ln) });
            }

            // 7. Hostnamen, Seriennummern und Benutzer anhand der Erkennungsmuster auch im Inhalt prüfen
            List<KeyValuePair<string, List<Regex>>> patternGroups = new List<KeyValuePair<string, List<Regex>>>();
            Dictionary<string, string> lernKategorie = new Dictionary<string, string>();
            lernKategorie["Rest-Hostname"] = "HOST";
            lernKategorie["Rest-Seriennummer"] = "SERIAL";
            lernKategorie["Rest-Benutzer"] = "USER";
            patternGroups.Add(new KeyValuePair<string, List<Regex>>("Rest-Hostname", cfg.HostnamenMuster));
            patternGroups.Add(new KeyValuePair<string, List<Regex>>("Rest-Seriennummer", cfg.SeriennummerMuster));
            patternGroups.Add(new KeyValuePair<string, List<Regex>>("Rest-Benutzer", cfg.BenutzerMuster));
            patternGroups.Add(new KeyValuePair<string, List<Regex>>("Rest-Benutzer-Schwach", cfg.BenutzerMusterSchwach));
            foreach (KeyValuePair<string, List<Regex>> pg in patternGroups)
            {
                string kat = pg.Key == "Rest-Benutzer-Schwach" ? "Rest-Benutzer" : pg.Key;
                foreach (Regex rx in pg.Value)
                {
                    foreach (Match m in rx.Matches(cleanText))
                    {
                        string val = PickGroupValue(m);
                        if (string.IsNullOrEmpty(val) || val.IndexOf('\u0002') >= 0 || IsAllowedInAudit(val, cfg) || AreAllPartsAllowed(val, cfg)) continue;
                        // Gleiche Regel wie bei der Ersetzung: CLI-Wörter sind kein Restfund (starke Benutzerfelder: nur Nicht-Werte)
                        if (pg.Key == "Rest-Benutzer") { if (KeinFeldwert.Contains(val.ToLowerInvariant())) continue; }
                        else if (pg.Key == "Rest-Benutzer-Schwach") { if (IsAmbiguousUser(val, cfg)) continue; }
                        else if (!IsLearnable(lernKategorie[kat], val, cfg, true)) continue;
                        int ln = GetLineNumber(lineStarts, m.Index);
                        findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = kat, Fund = val, Kontext = getLineCtx(ln) });
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
                if ((f.Kategorie == "HOST" || f.Kategorie == "SERIAL") && !IsLearnable(f.Kategorie, val, cfg)) continue;
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
                        if (string.Equals(cat, "USER|", StringComparison.OrdinalIgnoreCase) && IsAmbiguousUser(v, cfg)) break;
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
                        // Umgebendes Wort (z.B. "edge7-alt") als Ausnahme eingetragen: kein Fund ("Fehlalarm")
                        if (cfg.ExakteAusnahmen.Contains(SurroundingToken(knownText, m.Index, m.Length))) continue;
                        int ln = GetLineNumber(lineStarts, m.Index);
                        findings.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = "Rest-Bekannt", Fund = m.Value, Kontext = getLineCtx(ln) });
                    }
                }
            }

            // 11. Unabhängige Nachprüfung (eigene Feldregeln, keine Lernregel)
            findings.AddRange(Nachpruefen(text, fileName, cfg));

            if (findings.Count > 1)
                findings = findings.OrderBy(f => f.Zeile).ToList();

            return findings;
        }

        // ----------------------------------------------------------------
        // Unabhängige Nachprüfung: eigene Entscheidungen über verdächtige Werte nach eindeutigen Feldnamen.
        // Nutzt keine Lernregel und keine Ausschlussfilter der Engine; erlaubt sind nur Platzhalter, *****,
        // Werte der festen Zuordnung und ausdrücklich eingetragene Ausnahmen (exakteWoerter, erlaubtListe).
        // Identisch zu nachpruefen() in anonymisierer.html.
        // ----------------------------------------------------------------
        private const RegexOptions NachOpt = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
        private static readonly Regex RxNachPlatzhalter = new Regex("^(?:NET-[0-9]+(?:\\.H[0-9]+)?(?:/[0-9]{1,3})?|IP6?(?:-PRIV|-PUB)?-[0-9]+|(?:MAC|HOST|DOMAIN|USER|SERIAL|TEXT|MAIL|URL|ORT|KONTAKT|BANNER|FIRMA|PERSON|SW-EIGEN)-[0-9]+)$", RegexOptions.CultureInvariant, RxTimeout);
        private static readonly Regex RxNachFeldFrei = new Regex("(?<![A-Za-z0-9_./-])\"?(hostname|sysname|switchname|host-name|user[ _-]?name|user|local-user|domain-name|password|passwd|secret|key|community|auth-pass|priv-pass|authentication-key|pre-shared-key|api[_-]?key|token)\"?(?![A-Za-z0-9_-])(?:[ \\t]*[:=][ \\t]*|[ \\t]+)", NachOpt, RxTimeout);
        private static readonly Regex RxNachFeldDoppelpunkt = new Regex("(?<![A-Za-z0-9_./-])\"?(System[ \\t]+Name|Device[ \\t]+ID|Computer(?:[ _]?Name)?|Workstation[ _]?Name|[A-Za-z]*UserName|[A-Za-z]*DomainName|(?:Chassis[ \\t]+|System[ \\t]+|Board[ \\t]+)?Serial(?:[ \\t_-]*(?:Number|Nbr|No|Num)\\.?)?|SN|Service[ \\t]+Tag|Asset[ \\t]+Tag|Authorization)\"?(?![A-Za-z0-9_-])[ \\t]*[:=][ \\t]*", NachOpt, RxTimeout);
        private static readonly HashSet<string> NachTypwoerter = new HashSet<string>(new string[] { "0", "5", "6", "7", "8", "9", "ciphertext", "plaintext", "encrypted", "unencrypted", "cipher", "simple", "enc", "hash", "sha", "sha256", "sha512", "md5", "basic", "bearer", "invalid", "illegal", "secure" }, StringComparer.Ordinal);
        private static readonly HashSet<string> NachStrukturwoerter = new HashSet<string>(new string[] { "chain", "generate", "zeroize", "rsa", "ecdsa", "dsa", "ed25519", "exchange", "config-key", "string", "id", "lifetime", "timeout", "recovery", "encryption", "length", "min-length", "minimum-length", "policy", "complexity", "aging", "history", "change", "prompt", "required", "attempts", "lockout", "add", "set", "remove", "print", "group", "profile", "role", "privilege", "level", "view", "mode", "type", "auth", "priv", "none", "no", "yes", "true", "false", "null", "on", "off", "enable", "disable", "enabled", "disabled", "read", "write", "read-only", "read-write", "ro", "rw", "authentication" }, StringComparer.Ordinal);
        private static readonly Regex RxNachSid = new Regex("(?<![A-Za-z0-9-])S-1-5-21(?:-[0-9]+){3,4}(?![A-Za-z0-9-])", RegexOptions.CultureInvariant, RxTimeout);
        private static readonly Regex RxNachUrlZugang = new Regex("(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9+.-]*://([^\\s/:@\"'<>]+):([^\\s/@\"'<>]+)@", RegexOptions.CultureInvariant, RxTimeout);
        private static readonly Regex RxNachSnmpHost = new Regex("(?<![A-Za-z0-9-])snmp-server[ \\t]+host[ \\t]+[^ \\t\\r\\n]+(?:[ \\t]+(?:informs|traps))?(?:[ \\t]+version[ \\t]+(?:1|2c|3(?:[ \\t]+(?:auth|noauth|priv))?))?[ \\t]+([^ \\t\\r\\n]+)", NachOpt, RxTimeout);
        private static readonly Regex RxNachXmlData = new Regex("<Data[ \\t]+Name=\"([A-Za-z]+)\">([^<\\r\\n]*)</Data>", RegexOptions.CultureInvariant, RxTimeout);
        private static readonly Regex RxNachXmlComputer = new Regex("<Computer>([^<\\r\\n]*)</Computer>", RegexOptions.CultureInvariant, RxTimeout);
        private static readonly Regex RxNachWert = new Regex("^(?:\"((?:[^\"\\\\\\r\\n]|\\\\.)*)\"|'([^'\\r\\n]*)'|([^\\s\"',;\\])<>{}]+))", RegexOptions.CultureInvariant, RxTimeout);
        private static readonly Regex RxNachSerialKopf = new Regex("(?<![A-Za-z0-9-])(?:Serial|SERIAL|serial)(?![A-Za-z0-9-])", RegexOptions.CultureInvariant, RxTimeout);
        private static readonly Regex RxNachTrennlinie = new Regex("^[ \\t]*[-=+]{3,}[-=+ \\t]*$", RegexOptions.CultureInvariant, RxTimeout);

        private static string NachFeldart(string name)
        {
            string n = Regex.Replace(name.ToLowerInvariant(), "[ \\t_-]+", "");
            if (n.EndsWith("username", StringComparison.Ordinal) || n == "user" || n == "localuser") return "B";
            if (n.EndsWith("domainname", StringComparison.Ordinal)) return "D";
            if (n == "hostname" || n == "sysname" || n == "switchname" || n == "systemname" || n == "deviceid" || Regex.IsMatch(n, "^(computer|workstation)(name)?$")) return "H";
            if (Regex.IsMatch(n, "^(chassis|system|board)?serial") || n == "sn" || n == "servicetag" || n == "assettag") return "S";
            return "G";
        }

        private static string NachKategorie(string art)
        {
            switch (art)
            {
                case "B": return "Nachpruefung-Benutzer";
                case "H": return "Nachpruefung-Hostname";
                case "D": return "Nachpruefung-Domaene";
                case "S": return "Nachpruefung-Seriennummer";
                default: return "Nachpruefung-Geheimnis";
            }
        }

        private static bool NachErlaubt(string v, EngineConfig cfg, HashSet<string> fest)
        {
            if (string.IsNullOrEmpty(v) || v == "*****") return true;
            string low = v.ToLowerInvariant();
            if (cfg.ExakteAusnahmen.Contains(low) || cfg.PruefungErlaubtListe.Contains(low)) return true;
            if (fest.Contains(low)) return true;
            // Aus Platzhaltern zusammengesetzt (HOST-1.DOMAIN-2, DOMAIN-1\USER-3, USER-1@DOMAIN-1)
            foreach (string t in v.Split('.', '\\', '@'))
            {
                if (t.Length == 0 || !(RxNachPlatzhalter.IsMatch(t) || fest.Contains(t.ToLowerInvariant()))) return false;
            }
            return true;
        }

        public static List<AuditFinding> Nachpruefen(string text, string fileName, EngineConfig cfg)
        {
            List<AuditFinding> funde = new List<AuditFinding>();
            if (string.IsNullOrEmpty(text)) return funde;
            text = DecodeJsonStringEscapes(text);
            string[] zeilen = Regex.Split(text, "\\r?\\n");
            HashSet<string> gesehen = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> fest = new HashSet<string>(StringComparer.Ordinal);
            foreach (string fv in cfg.FesteZuordnung.Values) fest.Add((fv ?? "").ToLowerInvariant());

            Action<int, string, string, string> melde = (ln, art, wert, kategorie) =>
            {
                string kat = kategorie ?? ((art == "G" && wert != "*****" && wert.IndexOf("*****", StringComparison.Ordinal) >= 0) ? "Nachpruefung-Teilmaskierung" : NachKategorie(art));
                if (!gesehen.Add(ln + "|" + kat + "|" + wert)) return;
                funde.Add(new AuditFinding { Datei = fileName, Zeile = ln, Kategorie = kat, Fund = wert, Kontext = zeilen[ln - 1].Trim() });
            };
            Action<int, string, string, string> pruefeWert = (ln, art, wert, feld) =>
            {
                if (string.IsNullOrEmpty(wert)) return;
                if (art == "G")
                {
                    if (wert == "*****") return;
                    if (wert.IndexOf("*****", StringComparison.Ordinal) < 0 && NachErlaubt(wert, cfg, fest)) return;
                    // BGP-Communities (65000:100, no-export) sind keine Geheimnisse
                    if (feld == "community" && (Regex.IsMatch(wert, "^[0-9]+:[0-9]+$") || Regex.IsMatch(wert, "^(?:no-export|no-advertise|internet|local-as|additive)$", RegexOptions.IgnoreCase))) return;
                }
                else if (NachErlaubt(wert, cfg, fest)) return;
                melde(ln, art, wert, null);
            };
            Action<int, string, int, string, string> feldWert = (ln, zeile, ab, art, name) =>
            {
                string rest = zeile.Substring(ab);
                for (int i = 0; i < 4; i++)
                {
                    Match w = RxNachWert.Match(rest);
                    if (!w.Success) return;
                    bool zitiert = !w.Groups[3].Success;
                    string wert = w.Groups[1].Success ? Regex.Replace(w.Groups[1].Value, "\\\\([\"\\\\])", "$1") : (w.Groups[2].Success ? w.Groups[2].Value : w.Groups[3].Value.TrimEnd('.', ':'));
                    string low = wert.ToLowerInvariant();
                    if (!zitiert && KeinFeldwert.Contains(low)) return;
                    if (!zitiert && art == "G" && NachStrukturwoerter.Contains(low)) return;
                    if (!zitiert && art == "B" && NachStrukturwoerter.Contains(low)) return;
                    // Schlüsselnummer ("key 1", "authentication-key 1 md5 ...") ist kein Wert
                    bool istSchluesselNr = art == "G" && Regex.IsMatch(name, "^(?:key|authentication-key)$", RegexOptions.IgnoreCase) && Regex.IsMatch(wert, "^[0-9]{1,5}$") && !NachTypwoerter.Contains(low);
                    if (!zitiert && (istSchluesselNr || (NachTypwoerter.Contains(low) && (art == "G" || art == "B"))))
                    {
                        rest = rest.Substring(w.Length).TrimStart(' ', '\t');
                        continue;
                    }
                    // MikroTik-Form "user add name=X"
                    Match nv = Regex.Match(wert, "^name=(.+)$", RegexOptions.IgnoreCase);
                    pruefeWert(ln, art, nv.Success ? Regex.Replace(nv.Groups[1].Value, "^\"|\"$", "") : wert, name.ToLowerInvariant());
                    return;
                }
            };

            for (int i = 0; i < zeilen.Length; i++)
            {
                string zeile = zeilen[i];
                int ln = i + 1;
                foreach (Regex rx in new Regex[] { RxNachFeldFrei, RxNachFeldDoppelpunkt })
                {
                    foreach (Match m in rx.Matches(zeile)) feldWert(ln, zeile, m.Index + m.Length, NachFeldart(m.Groups[1].Value), m.Groups[1].Value);
                }
                foreach (Match m in RxNachXmlData.Matches(zeile))
                {
                    string n = m.Groups[1].Value;
                    if (n.EndsWith("Sid", StringComparison.OrdinalIgnoreCase)) continue;
                    if (n.EndsWith("UserName", StringComparison.OrdinalIgnoreCase)) pruefeWert(ln, "B", m.Groups[2].Value.Trim(), null);
                    else if (n.EndsWith("DomainName", StringComparison.OrdinalIgnoreCase)) pruefeWert(ln, "D", m.Groups[2].Value.Trim(), null);
                    else if (Regex.IsMatch(n, "^(?:Workstation|Computer)Name$", RegexOptions.IgnoreCase)) pruefeWert(ln, "H", m.Groups[2].Value.Trim(), null);
                }
                foreach (Match m in RxNachXmlComputer.Matches(zeile)) pruefeWert(ln, "H", m.Groups[1].Value.Trim(), null);
                foreach (Match m in RxNachSnmpHost.Matches(zeile))
                {
                    string w = Regex.Replace(m.Groups[1].Value, "^[\"']|[\"']$", "");
                    if (!Regex.IsMatch(w, "^(?:informs|traps|version|udp-port|vrf)$", RegexOptions.IgnoreCase)) pruefeWert(ln, "G", w, null);
                }
                foreach (Match m in RxNachUrlZugang.Matches(zeile))
                {
                    pruefeWert(ln, "B", m.Groups[1].Value, null);
                    pruefeWert(ln, "G", m.Groups[2].Value, null);
                }
                foreach (Match m in RxNachSid.Matches(zeile)) melde(ln, "", m.Value, "Nachpruefung-SID");
            }

            // Tabellen mit Spalte "Serial": Wert unter dem Spaltenkopf (Zeilen bis zur nächsten Leerzeile)
            for (int i = 0; i < zeilen.Length; i++)
            {
                string kopf = zeilen[i];
                if (kopf.IndexOf(':') >= 0 || kopf.IndexOf('=') >= 0 || Regex.Split(kopf.Trim(), "[ \\t]+").Length < 3) continue;
                Match km = RxNachSerialKopf.Match(kopf);
                if (!km.Success) continue;
                // Tabelle: innerhalb von drei Zeilen folgt eine Trennlinie aus "-" / "="; Daten stehen darunter
                int trenn = -1;
                for (int t = i + 1; t <= i + 3 && t < zeilen.Length; t++)
                {
                    if (RxNachTrennlinie.IsMatch(zeilen[t])) { trenn = t; break; }
                }
                if (trenn < 0) continue;
                for (int j = trenn + 1; j < zeilen.Length && j < i + 500 && zeilen[j].Trim() != ""; j++)
                {
                    string z = zeilen[j];
                    int a = km.Index;
                    if (a >= z.Length) continue;
                    if (z[a] == ' ' || z[a] == '\t')
                    {
                        int k = 1;
                        while (k <= 3 && !(a + k < z.Length && z[a + k] != ' ' && z[a + k] != '\t')) k++;
                        if (k > 3) continue;
                        a += k;
                    }
                    while (a > 0 && z[a - 1] != ' ' && z[a - 1] != '\t') a--;
                    int b = a;
                    while (b < z.Length && z[b] != ' ' && z[b] != '\t') b++;
                    string wert = z.Substring(a, b - a);
                    if (Regex.IsMatch(wert, "[0-9]") && Regex.IsMatch(wert, "[A-Za-z]") && !Regex.IsMatch(wert, "^-+$")) pruefeWert(j + 1, "S", wert, null);
                }
            }
            return funde;
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
        $sr.NurWertSchuetzen = ((Get-JsonProp $gm "nurWertSchuetzen") -eq $true)
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
    foreach ($pat in (Get-MergedRuleList $jsonObj $lokalObj "" "benutzerMusterSchwach")) {
        $cfg.BenutzerMusterSchwach.Add((New-Object System.Text.RegularExpressions.Regex ([string]$pat, $rxCompiled, $rxTimeout)))
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
            $vk = Get-JsonProp $sp "vorkommen"
            if ($null -ne $vk) { $col.Vorkommen = [int]$vk }
            $rule.Spalten.Add($col)
        }
        $cfg.TabellenSpalten.Add($rule)
    }

    # Lern-Stoppliste: CLI-Schlüsselwörter und Tabellenköpfe aus strukturvorlage.json (neben der Regeldatei oder neben anon.ps1)
    $woerterDatei = Get-StrukturWoerterPfad -RegelDatei $RegelDatei
    if ([string]::IsNullOrEmpty($woerterDatei)) {
        throw "strukturvorlage.json nicht gefunden (wird als Lern-Stoppliste benötigt; neben anon-regeln.json oder anon.ps1 ablegen)."
    }
    $vorlageObj = ConvertFrom-Json -InputObject ([AnonTool.TarGzHelper]::DecodeTextWithBom([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $woerterDatei).Path)))
    $swObj = Get-JsonProp $vorlageObj "schluesselwoerter"
    $alleWoerter = New-Object 'System.Collections.Generic.List[string]'
    if ($null -ne $swObj) {
        foreach ($prop in $swObj.PSObject.Properties) {
            foreach ($w in @($prop.Value)) { if ($null -ne $w) { $alleWoerter.Add([string]$w) } }
        }
    }
    $cfg.LernStoppwoerter = [AnonTool.AnonEngine]::BuildKeywordSet($alleWoerter)

    return $cfg
}

# strukturvorlage.json: neben der Regeldatei, neben anon.ps1 oder unter ..\regeln\
function Get-StrukturWoerterPfad {
    param([string]$RegelDatei)
    $kandidaten = @()
    if (-not [string]::IsNullOrEmpty($RegelDatei)) { $kandidaten += (Join-Path (Split-Path -Parent ([System.IO.Path]::GetFullPath($RegelDatei))) "strukturvorlage.json") }
    $kandidaten += (Join-Path $PSScriptRoot "strukturvorlage.json")
    $kandidaten += (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) "regeln") "strukturvorlage.json")
    foreach ($k in $kandidaten) { if (Test-Path -LiteralPath $k) { return $k } }
    return $null
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

# Schema und Formatversion einer (entschlüsselten) Zuordnungstabelle; bei Fehlern Abbruch ohne Zustandsänderung
function Assert-TabellenSchema {
    param($Obj)
    $abbruch = "Zuordnungstabelle abgelehnt: {0}. Die Tabelle wird nicht verwendet und nicht überschrieben."
    if ($null -eq $Obj -or $Obj -is [System.Array] -or -not ($Obj -is [System.Management.Automation.PSCustomObject])) { throw ($abbruch -f "kein Tabellenobjekt") }
    $version = Get-JsonProp $Obj "version"
    if ([string]$version -ne "1.0") { throw ($abbruch -f "unbekannte Formatversion") }
    foreach ($pflicht in @("vorwaerts", "rueckwaerts")) {
        $teil = Get-JsonProp $Obj $pflicht
        if ($null -eq $teil -or -not ($teil -is [System.Management.Automation.PSCustomObject])) { throw ($abbruch -f "Abschnitt '$pflicht' fehlt oder ist kein Objekt") }
        foreach ($p in $teil.PSObject.Properties) {
            if (-not ($p.Value -is [string]) -or [string]::IsNullOrWhiteSpace($p.Name)) { throw ($abbruch -f "ungültiger Eintrag in '$pflicht'") }
        }
    }
    $zaehl = Get-JsonProp $Obj "zaehler"
    if ($null -ne $zaehl) {
        if (-not ($zaehl -is [System.Management.Automation.PSCustomObject])) { throw ($abbruch -f "Abschnitt 'zaehler' ist kein Objekt") }
        foreach ($p in $zaehl.PSObject.Properties) {
            $zahl = 0
            if (-not [int]::TryParse([string]$p.Value, [ref]$zahl) -or $zahl -lt 0) { throw ($abbruch -f "ungültiger Zähler") }
        }
    }
    $nh = Get-JsonProp $Obj "netzHosts"
    if ($null -ne $nh) {
        if (-not ($nh -is [System.Management.Automation.PSCustomObject])) { throw ($abbruch -f "Abschnitt 'netzHosts' ist kein Objekt") }
        foreach ($p in $nh.PSObject.Properties) {
            if (-not ($p.Value -is [System.Management.Automation.PSCustomObject])) { throw ($abbruch -f "ungültiger Eintrag in 'netzHosts'") }
            foreach ($h in $p.Value.PSObject.Properties) { if (-not ($h.Value -is [string])) { throw ($abbruch -f "ungültiger Eintrag in 'netzHosts'") } }
        }
    }
    $al = Get-JsonProp $Obj "aliase"
    if ($null -ne $al) {
        if (-not ($al -is [System.Management.Automation.PSCustomObject])) { throw ($abbruch -f "Abschnitt 'aliase' ist kein Objekt") }
        foreach ($p in $al.PSObject.Properties) { if (-not ($p.Value -is [string])) { throw ($abbruch -f "ungültiger Eintrag in 'aliase'") } }
    }
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
    Assert-TabellenSchema $tObj

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
    $konsistenz = [AnonTool.AnonEngine]::ValidateStateConsistency($state)
    if ($konsistenz.Count -gt 0) {
        throw ("Zuordnungstabelle abgelehnt: " + (@($konsistenz | Select-Object -First 5) -join "; ") + ". Die Tabelle wird nicht verwendet und nicht überschrieben.")
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

# Pfadvergleich ohne Groß-/Kleinschreibung (Windows), mit Trennzeichen am Ende
function Test-PfadGleich {
    param([string]$A, [string]$B)
    return [string]::Equals($A.TrimEnd('\', '/'), $B.TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-PfadInnerhalb {
    param([string]$Kind, [string]$Eltern)
    if (Test-PfadGleich $Kind $Eltern) { return $true }
    $e = $Eltern.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $k = $Kind.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    $e = $e.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    return $k.StartsWith($e, [System.StringComparison]::OrdinalIgnoreCase)
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
# MODUS 0: Strukturvorlage (-Strukturvorlage)
# ----------------------------------------------------------------------------
if ($Strukturvorlage) {
    if ($null -eq $Eingabe -or $Eingabe.Count -eq 0) {
        throw "Bitte -Eingabe für die Strukturvorlage angeben."
    }
    $woerterPfad = $Strukturwoerter
    if ([string]::IsNullOrEmpty($woerterPfad)) {
        $woerterPfad = Join-Path $scriptDir "strukturvorlage.json"
        $repoWoerter = Join-Path (Join-Path (Split-Path -Parent $scriptDir) "regeln") "strukturvorlage.json"
        if (-not (Test-Path -LiteralPath $woerterPfad) -and (Test-Path -LiteralPath $repoWoerter)) { $woerterPfad = $repoWoerter }
    }
    if (-not (Test-Path -LiteralPath $woerterPfad)) {
        throw "Schlüsselwortliste strukturvorlage.json nicht gefunden (Parameter -Strukturwoerter)."
    }
    $vorlageObj = ConvertFrom-Json -InputObject ([AnonTool.TarGzHelper]::DecodeTextWithBom([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $woerterPfad).Path)))
    $alleWoerter = New-Object 'System.Collections.Generic.List[string]'
    $swObj = Get-JsonProp $vorlageObj "schluesselwoerter"
    if ($null -ne $swObj) {
        foreach ($prop in $swObj.PSObject.Properties) {
            foreach ($w in @($prop.Value)) { if ($null -ne $w) { $alleWoerter.Add([string]$w) } }
        }
    }
    $keywords = [AnonTool.AnonEngine]::BuildKeywordSet($alleWoerter)
    $freitextPh = [string](Get-JsonProp $vorlageObj "freitextPlatzhalter")
    if ([string]::IsNullOrEmpty($freitextPh)) { $freitextPh = "<FREITEXT>" }

    $strukturZiel = $Ausgabe
    if ([string]::IsNullOrEmpty($strukturZiel)) {
        $strukturZiel = Join-Path (Join-Path (Get-AnonBaseDir) "struktur") (Get-Date).ToString("yyyyMMdd-HHmmss")
    }
    if (-not (Test-Path -LiteralPath $strukturZiel)) { [void](New-Item -ItemType Directory -Path $strukturZiel -Force) }

    # Dateien in fester Reihenfolge (relativer Pfad, ordinal), Ausgabenamen nur nummeriert (Originalnamen können Werte enthalten)
    $strukturDateien = New-Object 'System.Collections.Generic.List[string]'
    $einNr = 0
    foreach ($ein in $Eingabe) {
        $einNr++
        if (-not (Test-Path -LiteralPath $ein)) { throw "Eingabe Nr. $einNr existiert nicht." }
        $item = Get-Item -LiteralPath $ein
        if ($item.PSIsContainer) {
            $kinder = @(Get-ChildItem -LiteralPath $item.FullName -Recurse -File | ForEach-Object { $_.FullName })
            [Array]::Sort($kinder, [System.StringComparer]::Ordinal)
            foreach ($k in $kinder) { $strukturDateien.Add($k) }
        } else {
            $strukturDateien.Add($item.FullName)
        }
    }
    $erlaubteEndungen = @(".txt", ".log", ".cfg", ".conf", ".json", ".xml", ".csv")
    $nr = 0
    $geschrieben = 0
    foreach ($quelle in $strukturDateien) {
        $nr++
        try {
            $bytes = [System.IO.File]::ReadAllBytes($quelle)
            if ([AnonTool.TarGzHelper]::IsBinaryContent($bytes)) { continue }
            $vorlage = [AnonTool.AnonEngine]::BuildStructureTemplate([AnonTool.TarGzHelper]::DecodeTextWithBom($bytes), $cfg, $keywords, $freitextPh)
            $endung = [System.IO.Path]::GetExtension($quelle).ToLowerInvariant()
            if ($erlaubteEndungen -notcontains $endung) { $endung = ".txt" }
            $zielDatei = Join-Path $strukturZiel ("strukturvorlage-{0:D3}{1}" -f $nr, $endung)
            [System.IO.File]::WriteAllText($zielDatei, $vorlage, (New-Object System.Text.UTF8Encoding($false)))
            $geschrieben++
        } catch {
            Stop-MitNummer -Nummer $nr -Schritt "Strukturvorlage" -Fehler $_
        }
    }
    Write-Host ("STRUKTURVORLAGE: {0} Datei(en) erzeugt in {1}" -f $geschrieben, $strukturZiel) -ForegroundColor Cyan
    Write-Host "HINWEIS: Vor Weitergabe sichten! Die Vorlage enthält nur die Form der Daten (A/a/9), aber unbekannte Formate oder ungewöhnliche Werte können trotzdem Rückschlüsse erlauben." -ForegroundColor Yellow
    exit 0
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
        Write-Host "Prüfergebnis: KEINE_RESTFUNDE (Keine Restfunde nach aktivem Regelwerk)" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "Prüfergebnis: RESTFUNDE_VORHANDEN ($($alleFunde.Count) Treffer gefunden)" -ForegroundColor Red
        Write-PruefFunde $alleFunde
        Write-Host "ACHTUNG: Diese Dateien NICHT weitergeben. Restfunde prüfen, Regeln oder Ausnahmen in anon-regeln.lokal.json ergänzen und neu anonymisieren." -ForegroundColor Red
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

# Kanonische Pfade prüfen, BEVOR etwas angelegt oder gelöscht wird: Eingaben dürfen sich nicht mit dem
# Ausgabeordner überschneiden (er enthält anonym\, bericht.json und wird teilweise gelöscht), und die
# Zuordnungstabelle darf nicht in einer Eingabe liegen.
$kanonTabelle = [System.IO.Path]::GetFullPath($TabellenPfad)
$kanonAusgabe = if ([string]::IsNullOrEmpty($Ausgabe)) { $null } else { [System.IO.Path]::GetFullPath($Ausgabe) }
$einNr = 0
foreach ($ein in $Eingabe) {
    $einNr++
    if (-not (Test-Path -LiteralPath $ein)) { throw "Eingabe Nr. $einNr nicht gefunden." }
    $kanonEin = (Resolve-Path -LiteralPath $ein).ProviderPath
    $istOrdner = Test-Path -LiteralPath $ein -PathType Container
    if ($null -ne $kanonAusgabe -and ((Test-PfadInnerhalb $kanonEin $kanonAusgabe) -or ($istOrdner -and (Test-PfadInnerhalb $kanonAusgabe $kanonEin)))) {
        throw "SICHERHEITSFEHLER: Eingabe Nr. $einNr überschneidet sich mit dem Ausgabeordner (-Ausgabe). Es wurde nichts verändert."
    }
    if (($istOrdner -and (Test-PfadInnerhalb $kanonTabelle $kanonEin)) -or (Test-PfadGleich $kanonTabelle $kanonEin)) {
        throw "SICHERHEITSFEHLER: Die Zuordnungstabelle überschneidet sich mit Eingabe Nr. $einNr. Es wurde nichts verändert."
    }
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

# Eindeutigkeit der Platzhalter: geladene Tabelle und festeZuordnung dürfen keinen Platzhalter doppelt vergeben
$kollisionen = [AnonTool.AnonEngine]::FindPlaceholderCollisions($state, $cfg.FesteZuordnung)
if ($kollisionen.Count -gt 0) {
    throw ("Zuordnungstabelle abgelehnt: " + ($kollisionen -join "; ") + ". Die Tabelle wird nicht verwendet und nicht überschrieben.")
}

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

    # Ausgabepfade vor dem ersten Schreiben auf Eindeutigkeit prüfen (Windows: ohne Groß-/Kleinschreibung)
    $zielPfade = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)
    $dateiNr = 0
    foreach ($eintrag in $dateiListe) {
        $dateiNr++
        $vorschauPfad = ([AnonTool.AnonEngine]::ProcessPath($eintrag.RelPfad, $cfg, $state)) -replace '\\', '/'
        if ($zielPfade.ContainsKey($vorschauPfad)) {
            throw ("Ausgabepfad-Kollision: Datei Nr. {0} und Nr. {1} ergeben denselben anonymisierten Ausgabepfad. Es wurde nichts geschrieben." -f $zielPfade[$vorschauPfad], $dateiNr)
        }
        $zielPfade[$vorschauPfad] = $dateiNr
    }

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

$pruefStatus = if ($allePruefFunde.Count -eq 0) { "KEINE_RESTFUNDE" } else { "RESTFUNDE_VORHANDEN" }

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
if ($pruefStatus -eq "KEINE_RESTFUNDE") {
    Write-Host "Prüfergebnis (-Pruefen)  : KEINE_RESTFUNDE (Keine Restfunde nach aktivem Regelwerk)" -ForegroundColor Green
    exit 0
} else {
    Write-Host ("Prüfergebnis (-Pruefen)  : {0} ({1} Treffer)" -f $pruefStatus, $allePruefFunde.Count) -ForegroundColor Red
    Write-PruefFunde $allePruefFunde
    Write-Host "ACHTUNG: Ausgabe NICHT weitergeben. Restfunde prüfen, Regeln oder Ausnahmen in anon-regeln.lokal.json ergänzen und neu anonymisieren." -ForegroundColor Red
    exit 2
}
