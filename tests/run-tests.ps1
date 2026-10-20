<#
.SYNOPSIS
    Automatisiertes Testskript für anon.ps1 (PowerShell 5.1+ und PowerShell 7+).
    Prüft:
    1. Alle 48 Testfälle in tests\faelle.json (LF UND CRLF, inkl. Grenzfälle, JSON-Validität, Rückübersetzung)
    2. Identische Ausgaben zwischen anon.ps1 und anonymisierer.html (LF UND CRLF über tests\erwartet\)
    3. Archiv-Verarbeitung (.zip und .tar.gz), Überspringen von Binärdateien
    4. Sicherheitsregeln: Zuordnungstabelle darf NIE im Ausgabeordner liegen; <Ausgabe>\_arbeit\ wird gelöscht; nur <Ausgabe>\anonym\ und bericht.json bleiben übrig
    5. Explizite Tests für alle 11 Code-Review-Befunde (Befund 1 bis Befund 11)
    6. Performance- & Stresstest (40.000+ Zeilen Aruba Show-Tech)
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$testDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Split-Path -Parent $testDir
$anonScript = Join-Path (Join-Path $rootDir "powershell") "anon.ps1"
$rulesPath = Join-Path (Join-Path $rootDir "regeln") "anon-regeln.json"
# Standard ist der IP-Schlüsselmodus; die bestehenden Tests laufen ausdrücklich im alten Modus (Platzhalter NET-n.Hm)
# über eine Kopie der Regeldatei. Die Tests des Schlüsselmodus übergeben -IpModus schluessel.
$rulesPathStandard = $rulesPath
$rulesAltDir = Join-Path $testDir "_tmp_regeln"
if (-not (Test-Path -LiteralPath $rulesAltDir)) { [void](New-Item -ItemType Directory -Path $rulesAltDir -Force) }
$rulesStandardText = [System.IO.File]::ReadAllText($rulesPathStandard, [System.Text.Encoding]::UTF8)
$rulesPath = Join-Path $rulesAltDir "anon-regeln.json"
[System.IO.File]::WriteAllText($rulesPath, $rulesStandardText.Replace('"ipModus": "schluessel"', '"ipModus": "platzhalter"'), (New-Object System.Text.UTF8Encoding($false)))
$casesPath = Join-Path $testDir "faelle.json"
$beispieleDir = Join-Path $testDir "beispiele"
$erwartetDir = Join-Path $testDir "erwartet"

$passed = 0
$failed = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        $script:passed++
    } else {
        $script:failed++
        Write-Host "  [FEHLER] $Message" -ForegroundColor Red
    }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -eq $Expected) {
        $script:passed++
    } else {
        $script:failed++
        Write-Host "  [FEHLER] $Message (Erwartet: '$Expected', Erhalten: '$Actual')" -ForegroundColor Red
    }
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $threw = $false
    try {
        & $Action
    } catch {
        $threw = $true
    }
    Assert-True $threw $Message
}

# Hilfen für die IP-Testvektoren (Hex, IPv4 als Bytes)
function ConvertFrom-TestHex { param([string]$Hex) $b = New-Object byte[] ($Hex.Length / 2); for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring(2 * $i, 2), 16) }; return ,$b }
function ConvertTo-TestHex { param([byte[]]$Bytes) return (($Bytes | ForEach-Object { $_.ToString("x2") }) -join "") }
function ConvertFrom-TestIp4 { param([string]$Ip) return ,([byte[]]($Ip.Split(".") | ForEach-Object { [byte]$_ })) }
function ConvertTo-TestIp4 { param([byte[]]$Bytes) return (($Bytes | ForEach-Object { [string]$_ }) -join ".") }

Write-Host "=== 1. Initialisiere AnonTool.AnonEngine über anon.ps1 (Trockenlauf) ===" -ForegroundColor Cyan
Assert-True ($rulesStandardText.Contains('"ipModus": "schluessel"') -and [System.IO.File]::ReadAllText($rulesPath).Contains('"ipModus": "platzhalter"')) "Regeln: Standard-IP-Modus 'schluessel', Testkopie ausdrücklich im alten Modus"
& $anonScript -Eingabe (Join-Path $beispieleDir "01-aruba-aoscx.txt") -Regeln $rulesPath -Probe > $null
Assert-True ($LASTEXITCODE -eq 0) "Trockenlauf auf sauberer Beispieldatei liefert Exit-Code 0"
Assert-True ($null -ne ("AnonTool.AnonEngine" -as [type])) "C# AnonEngine erfolgreich geladen"

Write-Host "=== 2. Prüfe alle Testfälle aus tests\faelle.json (LF und CRLF, Parität A == B) ===" -ForegroundColor Cyan
$casesJson = [System.IO.File]::ReadAllText($casesPath, [System.Text.Encoding]::UTF8)
$cases = ConvertFrom-Json -InputObject $casesJson
Assert-True ($cases.Count -ge 48) "Mindestens 48 Testfälle geladen ($($cases.Count))"

$rawRules = [System.IO.File]::ReadAllText($rulesPath, [System.Text.Encoding]::UTF8)
$rulesObj = ConvertFrom-Json -InputObject $rawRules

function New-TestConfig {
    param($RulesObj, [bool]$Netzerhaltend = $true, [string[]]$KatFilter = $null)
    $cfg = New-Object AnonTool.EngineConfig
    $rxTimeout = [TimeSpan]::FromSeconds(5)
    $rxOpts = [System.Text.RegularExpressions.RegexOptions]::Compiled
    $cfg.Netzerhaltend = $Netzerhaltend
    $cfg.IpPrivatOeffentlichTrennen = [bool]$RulesObj.optionen.ipPrivatOeffentlichTrennen
    $cfg.SubnetzmaskenBehalten = [bool]$RulesObj.optionen.subnetzmaskenBehalten
    $cfg.MacNormalisieren = [bool]$RulesObj.optionen.macNormalisieren

    if ($null -ne $KatFilter -and $KatFilter.Count -gt 0) {
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($k in $KatFilter) { [void]$set.Add($k) }
        $cfg.CatGeheimnisse = $set.Contains("geheimnisseEntfernen")
        $cfg.CatIp = $set.Contains("ip")
        $cfg.CatMac = $set.Contains("mac")
        $cfg.CatHostnamen = $set.Contains("hostnamen")
        $cfg.CatBenutzer = $set.Contains("benutzer")
        $cfg.CatSeriennummern = $set.Contains("seriennummern")
        $cfg.CatFreitext = $set.Contains("freitext")
        $cfg.CatEigeneBegriffe = $set.Contains("eigeneBegriffe")
    }

    foreach ($p in $RulesObj.eigeneBegriffe.festeZuordnung.PSObject.Properties) { $cfg.FesteZuordnung[$p.Name] = [string]$p.Value }
    foreach ($x in $RulesObj.eigeneBegriffe.firmenUndStandorte) { $cfg.FirmenUndStandorte.Add([string]$x) }
    foreach ($x in $RulesObj.eigeneBegriffe.interneDomains) { $cfg.InterneDomains.Add([string]$x) }
    foreach ($x in $RulesObj.ausnahmen.exakteWoerter) { [void]$cfg.ExakteAusnahmen.Add([string]$x) }
    foreach ($x in $RulesObj.ausnahmen.versionKontext) { $cfg.VersionKontextRegex.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    foreach ($x in $RulesObj.ausnahmen.musterRegex) { $cfg.AusnahmenRegex.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    foreach ($x in $RulesObj.pruefung.erlaubtListe) { [void]$cfg.PruefungErlaubtListe.Add([string]$x) }
    foreach ($x in $RulesObj.pruefung.erlaubtMuster) { $cfg.PruefungErlaubtMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }

    foreach ($gm in $RulesObj.geheimnisMuster) {
        $sr = New-Object AnonTool.SecretRule
        $sr.Name = [string]$gm.name
        $sr.Pattern = [string]$gm.suche
        $sr.Replacement = [string]$gm.ersetzen
        $sr.NurWertSchuetzen = ($null -ne $gm.PSObject.Properties["nurWertSchuetzen"] -and [bool]$gm.nurWertSchuetzen)
        $sr.Compiled = New-Object System.Text.RegularExpressions.Regex ($sr.Pattern, $rxOpts, $rxTimeout)
        $cfg.GeheimnisMuster.Add($sr)
    }
    foreach ($fm in $RulesObj.freitextMuster) {
        $fr = New-Object AnonTool.FreeTextRule
        $fr.Name = [string]$fm.name
        $fr.Category = [string]$fm.kategorie
        $fr.Pattern = [string]$fm.suche
        $fr.Compiled = New-Object System.Text.RegularExpressions.Regex ($fr.Pattern, $rxOpts, $rxTimeout)
        $cfg.FreitextMuster.Add($fr)
    }
    foreach ($x in $RulesObj.seriennummerMuster) { $cfg.SeriennummerMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    foreach ($x in $RulesObj.benutzerMuster) { $cfg.BenutzerMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    foreach ($x in $RulesObj.benutzerMusterSchwach) { $cfg.BenutzerMusterSchwach.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    foreach ($x in $RulesObj.hostnamenMuster) { $cfg.HostnamenMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    if ($null -ne $RulesObj.PSObject.Properties["eigeneHostnamenMuster"]) {
        foreach ($x in $RulesObj.eigeneHostnamenMuster) { $cfg.HostnamenMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    }
    if ($null -ne $RulesObj.PSObject.Properties["tabellenSpalten"]) {
        foreach ($tr in $RulesObj.tabellenSpalten) {
            $rule = New-Object AnonTool.TableRule
            $rule.Name = [string]$tr.name
            foreach ($k in $tr.kopf) { $rule.Kopf.Add([string]$k) }
            foreach ($sp in $tr.spalten) {
                $col = New-Object AnonTool.TableColumnSpec
                $col.Name = [string]$sp.name
                $col.Kategorie = [string]$sp.kategorie
                if ($null -ne $sp.PSObject.Properties["vorkommen"]) { $col.Vorkommen = [int]$sp.vorkommen }
                $rule.Spalten.Add($col)
            }
            $cfg.TabellenSpalten.Add($rule)
        }
    }
    $woerter = New-Object 'System.Collections.Generic.List[string]'
    foreach ($prop in $script:strukturVorlageObj.schluesselwoerter.PSObject.Properties) { foreach ($w in $prop.Value) { $woerter.Add([string]$w) } }
    $cfg.LernStoppwoerter = [AnonTool.AnonEngine]::BuildKeywordSet($woerter)
    return $cfg
}
$script:strukturVorlageObj = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path (Join-Path $rootDir "regeln") "strukturvorlage.json"), [System.Text.Encoding]::UTF8))

foreach ($tc in $cases) {
    $netMode = if ($null -ne $tc.netzerhaltend) { [bool]$tc.netzerhaltend } else { $true }
    $katFilter = if ($null -ne $tc.PSObject.Properties["kategorien"]) { @($tc.kategorien) } else { $null }
    $cfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $netMode -KatFilter $katFilter
    if ($null -ne $tc.PSObject.Properties["festeZuordnung"]) {
        foreach ($fz in $tc.festeZuordnung.PSObject.Properties) { $cfg.FesteZuordnung[$fz.Name] = [string]$fz.Value }
    }

    # 2a. LF-Variante
    $st = New-Object AnonTool.AnonState
    $actual = [AnonTool.AnonEngine]::ProcessText([string]$tc.eingabe, $cfg, $st)
    $isEqual = ($actual -ceq [string]$tc.erwartet)
    if (-not $isEqual) {
        Write-Host "  [$($tc.id) LF] Erwartet: $($tc.erwartet)" -ForegroundColor Yellow
        Write-Host "  [$($tc.id) LF] Erhalten: $actual" -ForegroundColor Yellow
    }
    Assert-True $isEqual "$($tc.id) (LF): $($tc.name) (PS1 == Erwartet)"

    $findings = [AnonTool.AnonEngine]::AuditText($actual, "$($tc.id).txt", $cfg, $st)
    $isClean = ($findings.Count -eq 0)
    Assert-True ($isClean -eq [bool]$tc.sauber) "$($tc.id) (LF): Prüfmodus sauber=$isClean (erwartet $($tc.sauber))"

    $tabAlles = (($st.Forward.Keys + $st.Forward.Values + $st.Reverse.Keys + $st.Reverse.Values) -join "`n")
    Assert-True (-not ($tabAlles.Contains([string][char]2) -or $tabAlles.Contains([string][char]3))) "$($tc.id): Zuordnungstabelle enthält keine Schutz-Marker"
    if ($null -ne $tc.PSObject.Properties["tabelleEnthaeltNicht"]) {
        $tabText = (($st.Forward.Keys + $st.Forward.Values + $st.Reverse.Keys + $st.Reverse.Values) -join "`n")
        foreach ($geheim in $tc.tabelleEnthaeltNicht) {
            Assert-True ((-not $tabText.Contains([string]$geheim)) -and (-not $actual.Contains([string]$geheim))) "$($tc.id): '$geheim' steht weder in der Ausgabe noch in der Zuordnungstabelle"
        }
    }

    # 2b. Befund 1: CRLF-Variante für den gesamten Testkorpus
    $crlfIn = ([string]$tc.eingabe) -replace "\r?\n", "`r`n"
    $crlfExp = ([string]$tc.erwartet) -replace "\r?\n", "`r`n"
    $stCrlf = New-Object AnonTool.AnonState
    $actualCrlf = [AnonTool.AnonEngine]::ProcessText($crlfIn, $cfg, $stCrlf)
    $isEqualCrlf = ($actualCrlf -ceq $crlfExp)
    if (-not $isEqualCrlf) {
        Write-Host "  [$($tc.id) CRLF] Erwartet: $crlfExp" -ForegroundColor Yellow
        Write-Host "  [$($tc.id) CRLF] Erhalten: $actualCrlf" -ForegroundColor Yellow
    }
    Assert-True $isEqualCrlf "$($tc.id) (CRLF): $($tc.name) (PS1 CRLF == Erwartet CRLF)"

    $findingsCrlf = [AnonTool.AnonEngine]::AuditText($actualCrlf, "$($tc.id).txt", $cfg, $stCrlf)
    Assert-True (($findingsCrlf.Count -eq 0) -eq [bool]$tc.sauber) "$($tc.id) (CRLF): Prüfmodus sauber=$($findingsCrlf.Count -eq 0)"

    # Bekannte Lücken: Der Prüfmodus muss die Rohdaten (ohne Anonymisierung) beanstanden
    if ($null -ne $tc.PSObject.Properties["pruefeRoh"] -and [bool]$tc.pruefeRoh) {
        $rawFindings = [AnonTool.AnonEngine]::AuditText([string]$tc.eingabe, "$($tc.id).txt", $cfg)
        Assert-True ($rawFindings.Count -gt 0) "$($tc.id): Prüfmodus meldet die Lücke in den Rohdaten ($($rawFindings.Count) Treffer)"
        if ($null -ne $tc.PSObject.Properties["pruefeRohKategorie"]) {
            $rohKat = [string]$tc.pruefeRohKategorie
            Assert-True (@($rawFindings | Where-Object { $_.Kategorie -eq $rohKat }).Count -gt 0) "$($tc.id): Prüfmodus meldet in den Rohdaten die Kategorie $rohKat"
        }
    }

    if ($null -ne $tc.PSObject.Properties["jsonValid"] -and [bool]$tc.jsonValid) {
        $validJson = $false
        try {
            $null = ConvertFrom-Json -InputObject $actual -ErrorAction Stop
            $validJson = $true
        } catch {}
        Assert-True $validJson "$($tc.id): JSON-Struktur nach Anonymisierung gültig"
    }

    if ($null -ne $tc.PSObject.Properties["pruefeRueck"] -and [bool]$tc.pruefeRueck) {
        $restored = [AnonTool.AnonEngine]::DeanonymizeText($actual, $st.Reverse)
        Assert-True ($restored -ceq [string]$tc.eingabe) "$($tc.id) (LF): Rückübersetzung exakt wie Original"
        $restoredCrlf = [AnonTool.AnonEngine]::DeanonymizeText($actualCrlf, $stCrlf.Reverse)
        Assert-True ($restoredCrlf -ceq $crlfIn) "$($tc.id) (CRLF): Rückübersetzung exakt wie CRLF-Original"
    }
}

Write-Host "=== 3. Prüfe End-to-End CLI-Lauf (Ordner, Referenzvergleich A == B auf LF & CRLF) ===" -ForegroundColor Cyan
$tempRunRoot = Join-Path $testDir "_tmp_testlauf"
if (Test-Path -LiteralPath $tempRunRoot) { Remove-Item -LiteralPath $tempRunRoot -Recurse -Force }
$outDir = Join-Path $tempRunRoot "ausgabe"
$tabDir = Join-Path $tempRunRoot "tabellen"
$tabFile = Join-Path $tabDir "test-tabelle.json"
$secPass = ConvertTo-SecureString "TestPasswort123!" -AsPlainText -Force
# Arbeitsordner und Standardtabellen des Testlaufs in einen eigenen LOCALAPPDATA-Ordner legen
$origLocalAppData = $env:LOCALAPPDATA
$env:LOCALAPPDATA = Join-Path $tempRunRoot "localappdata"
$arbeitRoot = Join-Path (Join-Path $env:LOCALAPPDATA "Anon") "arbeit"

& $anonScript -Eingabe $beispieleDir -Ausgabe $outDir -Regeln $rulesPath -TabellenPfad $tabFile -PasswortSecure $secPass > $null
Assert-True ($LASTEXITCODE -eq 0) "End-to-End CLI-Lauf auf sauberen Beispieldateien liefert Exit-Code 0"

Assert-True (Test-Path -LiteralPath (Join-Path $outDir "anonym")) "<Ausgabe>\anonym\ wurde erstellt"
Assert-True (-not (Test-Path -LiteralPath (Join-Path $outDir "_arbeit"))) "Kein Arbeitsordner im Ausgabeordner"
Assert-True ((Test-Path -LiteralPath $arbeitRoot) -and (@(Get-ChildItem -LiteralPath $arbeitRoot -Directory).Count -eq 0)) "Arbeitsordner unter LOCALAPPDATA\Anon\arbeit wurde nach dem Lauf gelöscht"
Assert-True (Test-Path -LiteralPath (Join-Path $outDir "bericht.json")) "<Ausgabe>\bericht.json wurde erstellt"
Assert-True (Test-Path -LiteralPath $tabFile) "Zuordnungstabelle wurde außerhalb von <Ausgabe> gespeichert"

# Vergleiche die von anon.ps1 erzeugten Dateien Byte-für-Byte mit tests\erwartet\ (aus der HTML/JS-Engine)
$expFiles = Get-ChildItem -LiteralPath $erwartetDir -File
foreach ($ef in $expFiles) {
    $psAnonFile = Join-Path (Join-Path $outDir "anonym") $ef.Name
    Assert-True (Test-Path -LiteralPath $psAnonFile) "Anonymisierte Datei $($ef.Name) existiert"
    $psText = [System.IO.File]::ReadAllText($psAnonFile, [System.Text.Encoding]::UTF8)
    $expText = [System.IO.File]::ReadAllText($ef.FullName, [System.Text.Encoding]::UTF8)
    Assert-True ($psText -ceq $expText) "Parität A == B (LF): 100 % identische Ausgabe für $($ef.Name)"
}

# Paritätstest A == B auch für CRLF auf allen Beispieldateien
$crlfBeispieleDir = Join-Path $tempRunRoot "beispiele_crlf"
$crlfOutDir = Join-Path $tempRunRoot "ausgabe_crlf"
$crlfTabFile = Join-Path $tabDir "test-tabelle-crlf.json"
[void](New-Item -ItemType Directory -Path $crlfBeispieleDir -Force)
foreach ($ef in $expFiles) {
    $srcPath = Join-Path $beispieleDir $ef.Name
    $rawLf = [System.IO.File]::ReadAllText($srcPath, [System.Text.Encoding]::UTF8)
    $rawCrlf = $rawLf -replace "\r?\n", "`r`n"
    [System.IO.File]::WriteAllText((Join-Path $crlfBeispieleDir $ef.Name), $rawCrlf, (New-Object System.Text.UTF8Encoding($false)))
}
& $anonScript -Eingabe $crlfBeispieleDir -Ausgabe $crlfOutDir -Regeln $rulesPath -TabellenPfad $crlfTabFile -Unverschluesselt > $null
Assert-True ($LASTEXITCODE -eq 0) "CRLF-Mehrdateienlauf liefert Exit-Code 0"
foreach ($ef in $expFiles) {
    $psCrlfFile = Join-Path (Join-Path $crlfOutDir "anonym") $ef.Name
    $psCrlfText = [System.IO.File]::ReadAllText($psCrlfFile, [System.Text.Encoding]::UTF8)
    $expCrlfText = ([System.IO.File]::ReadAllText($ef.FullName, [System.Text.Encoding]::UTF8)) -replace "\r?\n", "`r`n"
    Assert-True ($psCrlfText -ceq $expCrlfText) "Parität A == B (CRLF): 100 % identische CRLF-Ausgabe für $($ef.Name)"
}

Write-Host "=== 4. Explizite Tests für alle 11 Code-Review-Befunde ===" -ForegroundColor Cyan

# ----------------------------------------------------------------------------
# Befund 1: CRLF Gegenprobe in .NET
# ----------------------------------------------------------------------------
$probePattern = '(?im)^([ \t]*description[ \t]+)([^\r\n]+)(?=\r?$)'
Assert-True ([regex]::IsMatch("description Test`r`nx", $probePattern)) "Befund 1 Gegenprobe: [regex]::IsMatch('description Test`r`nx', '(?im)^([ \t]*description[ \t]+)([^\r\n]+)(?=\r?$)') liefert True"

# ----------------------------------------------------------------------------
# Befund 2: Dateinamen & Pfade anonymisieren und prüfen
# ----------------------------------------------------------------------------
$pathCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
$pathState = New-Object AnonTool.AnonState
$origRelPath = "Rechenzentrum-Nord/dc1-sw-core01/show-tech-acc-halle2-01_192.0.2.1.txt"
$anonRelPath = [AnonTool.AnonEngine]::ProcessPath($origRelPath, $pathCfg, $pathState)
Assert-True ($anonRelPath -ceq "FIRMA-1/CORE-A/show-tech-HOST-1_NET-1.H1.txt") "Befund 2: ProcessPath anonymisiert jeden Pfadbestandteil ($anonRelPath)"

$cleanPathAudit = [AnonTool.AnonEngine]::AuditText("interface 1/1/1", $anonRelPath, $pathCfg)
Assert-True ($cleanPathAudit.Count -eq 0) "Befund 2: Anonymisierter Dateipfad ist in AuditText ohne Restfunde"

$dirtyPathAudit = [AnonTool.AnonEngine]::AuditText("interface 1/1/1", $origRelPath, $pathCfg)
Assert-True ($dirtyPathAudit.Count -ge 3) "Befund 2: Nicht anonymisierter Dateipfad wird in AuditText als Restfund gemeldet ($($dirtyPathAudit.Count) Treffer)"

# End-to-End Dateinamen-Test inkl. Binärdatei-Name im Bericht
$pathInDir = Join-Path $tempRunRoot "pfad_in"
$pathOutDir = Join-Path $tempRunRoot "pfad_out"
$pathTabFile = Join-Path $tabDir "pfad-tab.json"
[void](New-Item -ItemType Directory -Path $pathInDir -Force)
[System.IO.File]::WriteAllText((Join-Path $pathInDir "show-tech-dc1-sw-core01_192.0.2.1.txt"), "hostname dc1-sw-core01`r`n", [System.Text.Encoding]::UTF8)
[System.IO.File]::WriteAllBytes((Join-Path $pathInDir "firmware-dc1-sw-core01.bin"), [byte[]]@(0, 1, 2, 0, 255, 0, 42))
& $anonScript -Eingabe $pathInDir -Ausgabe $pathOutDir -Regeln $rulesPath -TabellenPfad $pathTabFile -Unverschluesselt > $null
Assert-True (Test-Path -LiteralPath (Join-Path (Join-Path $pathOutDir "anonym") "show-tech-CORE-A_NET-1.H1.txt")) "Befund 2: Ausgabedatei in anonym\ trägt anonymisierten Namen (show-tech-CORE-A_NET-1.H1.txt)"
Assert-True (-not (Test-Path -LiteralPath (Join-Path (Join-Path $pathOutDir "anonym") "show-tech-dc1-sw-core01_192.0.2.1.txt"))) "Befund 2: Originaldateiname mit Hostname existiert NICHT in anonym\"
$pathBericht = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $pathOutDir "bericht.json"), [System.Text.Encoding]::UTF8))
Assert-True ($pathBericht.uebersprungeneBinaer[0] -ceq "firmware-CORE-A.bin") "Befund 2: Auch uebersprungeneBinaer im Bericht nutzt anonymisierten Pfad ($($pathBericht.uebersprungeneBinaer[0]))"

# ----------------------------------------------------------------------------
# Befund 3: Zeichenkodierung (UTF-16-LE BOM, UTF-16-BE BOM, UTF-8 BOM -> UTF-8 ohne BOM)
# ----------------------------------------------------------------------------
$bomInDir = Join-Path $tempRunRoot "bom_in"
$bomOutDir = Join-Path $tempRunRoot "bom_out"
$bomTabFile = Join-Path $tabDir "bom-tab.json"
[void](New-Item -ItemType Directory -Path $bomInDir -Force)
$evText = "EventID=4624 IpAddress=203.0.113.60 ClientMAC=00:1a:2b:3c:4d:5e`r`n"
# Schreibe UTF-16 LE mit BOM, UTF-16 BE mit BOM und UTF-8 mit BOM
[System.IO.File]::WriteAllText((Join-Path $bomInDir "ev-utf16le.log"), $evText, [System.Text.Encoding]::Unicode)
[System.IO.File]::WriteAllText((Join-Path $bomInDir "ev-utf16be.log"), $evText, [System.Text.Encoding]::BigEndianUnicode)
[System.IO.File]::WriteAllText((Join-Path $bomInDir "ev-utf8bom.log"), $evText, (New-Object System.Text.UTF8Encoding($true)))

& $anonScript -Eingabe $bomInDir -Ausgabe $bomOutDir -Regeln $rulesPath -TabellenPfad $bomTabFile -Unverschluesselt > $null
Assert-True ($LASTEXITCODE -eq 0) "Befund 3: BOM-Dateien (UTF-16 LE/BE, UTF-8-BOM) verarbeitet und ohne Restfunde (Exit-Code 0)"
foreach ($bFile in @("ev-utf16le.log", "ev-utf16be.log", "ev-utf8bom.log")) {
    $outPath = Join-Path (Join-Path $bomOutDir "anonym") $bFile
    $outBytes = [System.IO.File]::ReadAllBytes($outPath)
    $hasBom = ($outBytes.Length -ge 2 -and (($outBytes[0] -eq 0xFF -and $outBytes[1] -eq 0xFE) -or ($outBytes[0] -eq 0xFE -and $outBytes[1] -eq 0xFF))) -or
              ($outBytes.Length -ge 3 -and $outBytes[0] -eq 0xEF -and $outBytes[1] -eq 0xBB -and $outBytes[2] -eq 0xBF)
    Assert-True (-not $hasBom) "Befund 3: Ausgabe von $bFile ist UTF-8 ohne BOM"
    $outContent = [System.Text.Encoding]::UTF8.GetString($outBytes).Trim()
    Assert-True ($outContent -ceq "EventID=4624 IpAddress=NET-1.H1 ClientMAC=MAC-1") "Befund 3: IPs und MACs in $bFile erkannt und ersetzt ($outContent)"
}

# ----------------------------------------------------------------------------
# Befund 4: ANON-AES256-2 Tabellenverschlüsselung + 6 Pflicht-Negativtests + ANON-AES256-1 Upgrade
# ----------------------------------------------------------------------------
$tabHeaderObj = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
Assert-True ($tabHeaderObj.format -eq "ANON-AES256-2") "Befund 4: Tabellenformat ist ANON-AES256-2"
$expKdf = if ([AnonTool.AnonCrypto]::Sha256KdfAvailable()) { "PBKDF2-SHA256" } else { "PBKDF2-SHA1" }
Assert-True ($tabHeaderObj.kdf -eq $expKdf) "Befund 4: Tabellenkopf kdf ist $expKdf (SHA256 ab .NET 4.7.2)"
Assert-True ([int]$tabHeaderObj.iterations -eq 600000) "Befund 4: PBKDF2 Iterationszahl im Tabellenkopf ist 600.000 ($($tabHeaderObj.iterations))"

$kiAntwortPfad = Join-Path $tempRunRoot "ki-antwort.txt"
$kiRueckPfad = Join-Path $tempRunRoot "ki-rueck.txt"
[System.IO.File]::WriteAllText($kiAntwortPfad, "Bitte prüfen Sie auf CORE-A das Interface zu CORE-B mit IP NET-1.H2/24 und MAC MAC-1.", [System.Text.Encoding]::UTF8)
& $anonScript -Zurueck -Eingabe $kiAntwortPfad -Ausgabe $kiRueckPfad -TabellenPfad $tabFile -PasswortSecure $secPass > $null
$rueckText = [System.IO.File]::ReadAllText($kiRueckPfad, [System.Text.Encoding]::UTF8)
Assert-True ($rueckText.Contains("dc1-sw-core01") -and $rueckText.Contains("dc2-sw-core02") -and $rueckText.Contains("192.0.2.1/24") -and $rueckText.Contains("00:1a:2b:3c:4d:5e")) "Befund 4: Rückübersetzung (-Zurueck) mit ANON-AES256-2 erfolgreich"

# 6 Pflicht-Negativtests gegen ANON-AES256-2
$tamperDir = Join-Path $tempRunRoot "tamper"
[void](New-Item -ItemType Directory -Path $tamperDir -Force)

# 4a. leeres hmac
$t1 = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
$t1.hmac = ""
$t1Path = Join-Path $tamperDir "t1-empty-hmac.json"
[System.IO.File]::WriteAllText($t1Path, ($t1 | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $t1Path -PasswortSecure $secPass > $null 2>&1 } "Befund 4 Negativtest 1: Leeres 'hmac' MUSS fehlschlagen"

# 4b. verkürztes hmac (16 Byte statt 32 Byte)
$t2 = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
$fullMacBytes = [Convert]::FromBase64String([string]$t2.hmac)
$shortMacBytes = New-Object byte[] 16
[System.Buffer]::BlockCopy($fullMacBytes, 0, $shortMacBytes, 0, 16)
$t2.hmac = [Convert]::ToBase64String($shortMacBytes)
$t2Path = Join-Path $tamperDir "t2-short-hmac.json"
[System.IO.File]::WriteAllText($t2Path, ($t2 | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $t2Path -PasswortSecure $secPass > $null 2>&1 } "Befund 4 Negativtest 2: Verkürztes 'hmac' MUSS fehlschlagen"

# 4c. verändertes IV
$t3 = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
$ivBytes = [Convert]::FromBase64String([string]$t3.iv)
$ivBytes[0] = $ivBytes[0] -bxor 1
$t3.iv = [Convert]::ToBase64String($ivBytes)
$t3Path = Join-Path $tamperDir "t3-bad-iv.json"
[System.IO.File]::WriteAllText($t3Path, ($t3 | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $t3Path -PasswortSecure $secPass > $null 2>&1 } "Befund 4 Negativtest 3: Verändertes IV MUSS fehlschlagen"

# 4d. verändertes Salt
$t4 = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
$saltBytes = [Convert]::FromBase64String([string]$t4.salt)
$saltBytes[0] = $saltBytes[0] -bxor 1
$t4.salt = [Convert]::ToBase64String($saltBytes)
$t4Path = Join-Path $tamperDir "t4-bad-salt.json"
[System.IO.File]::WriteAllText($t4Path, ($t4 | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $t4Path -PasswortSecure $secPass > $null 2>&1 } "Befund 4 Negativtest 4: Verändertes Salt MUSS fehlschlagen"

# 4e. verändertes iterations-Feld
$t5 = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($tabFile, [System.Text.Encoding]::UTF8))
$t5.iterations = 600001
$t5Path = Join-Path $tamperDir "t5-bad-iter.json"
[System.IO.File]::WriteAllText($t5Path, ($t5 | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $t5Path -PasswortSecure $secPass > $null 2>&1 } "Befund 4 Negativtest 5: Verändertes iterations-Feld MUSS fehlschlagen"

# 4f. falsches Passwort
$wrongPass = ConvertTo-SecureString "FalschesPasswort99!" -AsPlainText -Force
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiAntwortPfad -TabellenPfad $tabFile -PasswortSecure $wrongPass > $null 2>&1 } "Befund 4 Negativtest 6: Falsches Passwort MUSS fehlschlagen"

# 4g. ANON-AES256-1 bleibt ladbar mit Warnung und wird beim Speichern auf ANON-AES256-2 gehoben
$legacySalt = New-Object byte[] 16
$legacyIv = New-Object byte[] 16
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($legacySalt)
$rng.GetBytes($legacyIv)
$legacyKdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes("AltPasswort99!", $legacySalt, 100000)
$legacyKey = $legacyKdf.GetBytes(32)
$legacyAes = [System.Security.Cryptography.Aes]::Create()
$legacyAes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$legacyAes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$legacyAes.Key = $legacyKey
$legacyAes.IV = $legacyIv
$legacyPlain = '{"version":"1.0","vorwaerts":{"fixed|dc1-sw-core01":"CORE-A"},"rueckwaerts":{"CORE-A":"dc1-sw-core01"},"zaehler":{},"netzHosts":{}}'
$legacyPlainBytes = [System.Text.Encoding]::UTF8.GetBytes($legacyPlain)
$legacyCipher = $legacyAes.CreateEncryptor().TransformFinalBlock($legacyPlainBytes, 0, $legacyPlainBytes.Length)
$legacyHmac = (New-Object System.Security.Cryptography.HMACSHA256(,$legacyKey)).ComputeHash($legacyCipher)
$legacyWrapper = [ordered]@{
    format = "ANON-AES256-1"
    salt   = [Convert]::ToBase64String($legacySalt)
    iv     = [Convert]::ToBase64String($legacyIv)
    hmac   = [Convert]::ToBase64String($legacyHmac)
    daten  = [Convert]::ToBase64String($legacyCipher)
} | ConvertTo-Json -Depth 5
$legacyTabFile = Join-Path $tabDir "legacy-tabelle-100k.json"
[System.IO.File]::WriteAllText($legacyTabFile, $legacyWrapper, [System.Text.Encoding]::UTF8)
$legacyInFile = Join-Path $tempRunRoot "legacy-in.txt"
$legacyOutFile = Join-Path $tempRunRoot "legacy-out.txt"
[System.IO.File]::WriteAllText($legacyInFile, "Switch CORE-A ist aktiv.", [System.Text.Encoding]::UTF8)
$secLegacyPass = ConvertTo-SecureString "AltPasswort99!" -AsPlainText -Force
$warnStream = & $anonScript -Zurueck -Eingabe $legacyInFile -Ausgabe $legacyOutFile -TabellenPfad $legacyTabFile -PasswortSecure $secLegacyPass 3>&1
$warnText = ($warnStream | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message }) -join " "
$legacyRestored = [System.IO.File]::ReadAllText($legacyOutFile, [System.Text.Encoding]::UTF8)
Assert-True ($legacyRestored -ceq "Switch dc1-sw-core01 ist aktiv.") "Befund 4: ANON-AES256-1 (100.000 Iterationen ohne Kopf-Feld) bleibt ladbar"
Assert-True ($warnText.Contains("ANON-AES256-1")) "Befund 4: Laden von ANON-AES256-1 erzeugt Warnung ($warnText)"

# ----------------------------------------------------------------------------
# Befund 5: Keine stille Herabstufung beim Weiterverwenden + Upgrade von -1 auf -2 beim Speichern
# ----------------------------------------------------------------------------
$reuseOutDir = Join-Path $tempRunRoot "reuse_out"
# Lade die ANON-AES256-1 Tabelle über -Tabelle und führe einen Lauf durch (ohne -Unverschluesselt) -> muss verschlüsselt bleiben und auf ANON-AES256-2 gehoben werden!
$null = & $anonScript -Eingabe (Join-Path $beispieleDir "01-aruba-aoscx.txt") -Ausgabe $reuseOutDir -Regeln $rulesPath -Tabelle $legacyTabFile -PasswortSecure $secLegacyPass 3>&1 > $null
$upgradedTabObj = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($legacyTabFile, [System.Text.Encoding]::UTF8))
Assert-True ($upgradedTabObj.format -eq "ANON-AES256-2") "Befund 4 & 5: Beim Weiterverwenden bleibt Tabelle verschlüsselt (keine stille Herabstufung) und wird von ANON-AES256-1 auf ANON-AES256-2 gehoben"

# ----------------------------------------------------------------------------
# Befund 6: Exit-Code 2 im Hauptlauf bei Restfunden
# ----------------------------------------------------------------------------
$dirtyOutDir = Join-Path $tempRunRoot "dirty_out"
$dirtyTabFile = Join-Path $tabDir "dirty-tab.json"
& $anonScript -Eingabe (Join-Path $beispieleDir "01-aruba-aoscx.txt") -Ausgabe $dirtyOutDir -Regeln $rulesPath -TabellenPfad $dirtyTabFile -Unverschluesselt -Kategorien "geheimnisseEntfernen" > $null
Assert-True ($LASTEXITCODE -eq 2) "Befund 6: Hauptlauf mit Restfunden (pruefTrefferAnzahl > 0) liefert Exit-Code 2 (erhalten: $LASTEXITCODE)"

# ----------------------------------------------------------------------------
# Befund 7: Set-StrictMode -Version Latest mit minimaler Regeldatei (ohne optionen, ausnahmen, pruefung)
# ----------------------------------------------------------------------------
$minRulesPath = Join-Path $tempRunRoot "min-regeln.json"
$minRulesContent = '{"eigeneBegriffe":{"festeZuordnung":{"dc1-sw-core01":"MIN-CORE-1"}}}'
[System.IO.File]::WriteAllText($minRulesPath, $minRulesContent, [System.Text.Encoding]::UTF8)
$minInFile = Join-Path $tempRunRoot "min-in.txt"
[System.IO.File]::WriteAllText($minInFile, "hostname dc1-sw-core01`r`nip address 198.51.100.3/24`r`n", [System.Text.Encoding]::UTF8)
$minOutDir = Join-Path $tempRunRoot "min_out"
$minTabFile = Join-Path $tabDir "min-tab.json"
& $anonScript -Eingabe $minInFile -Ausgabe $minOutDir -Regeln $minRulesPath -TabellenPfad $minTabFile -Unverschluesselt > $null
Assert-True ($LASTEXITCODE -eq 0) "Befund 7: Minimale Regeldatei ohne optionen, ausnahmen und pruefung läuft unter Set-StrictMode -Version Latest fehlerfrei"
$minResultText = [System.IO.File]::ReadAllText((Join-Path (Join-Path $minOutDir "anonym") "min-in.txt"), [System.Text.Encoding]::UTF8)
Assert-True ($minResultText.Contains("MIN-CORE-1") -and $minResultText.Contains("NET-1.H1/24")) "Befund 7: Minimale Regeldatei ersetzt festeZuordnung und Standard-Kategorien korrekt"

# ----------------------------------------------------------------------------
# Befund 8: Wort-/Namensgrenzen bei festeZuordnung und firmenUndStandorte
# ----------------------------------------------------------------------------
$bState = New-Object AnonTool.AnonState
$bOut = [AnonTool.AnonEngine]::ProcessText("dc1-tor-01 und dc1-tor-010", $pathCfg, $bState)
Assert-True ($bOut -ceq "TOR-A und dc1-tor-010" -and (-not $bOut.Contains("TOR-A0"))) "Befund 8: Wort-/Namensgrenzen verhindern Teilwort-Ersetzung ('dc1-tor-010' -> 'HOST-1' statt 'TOR-A0')"

# ----------------------------------------------------------------------------
# Befund 9: Add-Type sauber nach PSEdition verzweigt ohne stillen Catch-Fallback
# ----------------------------------------------------------------------------
$ps1Raw = [System.IO.File]::ReadAllText($anonScript, [System.Text.Encoding]::UTF8)
Assert-True ($ps1Raw.Contains('$PSVersionTable.PSEdition -eq "Desktop"') -and ($ps1Raw -notmatch '(?s)try\s*\{\s*Add-Type.*?\}\s*catch\s*\{\s*Add-Type')) "Befund 9: Add-Type verzweigt sauber nach PSEdition ohne stillen Catch-Fallback"

# ----------------------------------------------------------------------------
# Befund 10: Mindestlänge 12 Zeichen für Passwörter erzwingen
# ----------------------------------------------------------------------------
$shortPass = ConvertTo-SecureString "Kurz1234567" -AsPlainText -Force # 11 Zeichen
$shortTabFile = Join-Path $tabDir "short-pass-tab.json"
$shortOutDir = Join-Path $tempRunRoot "short_out"
Assert-Throws {
    & $anonScript -Eingabe $minInFile -Ausgabe $shortOutDir -Regeln $rulesPath -TabellenPfad $shortTabFile -PasswortSecure $shortPass > $null 2>&1
} "Befund 10: Passwort unter 12 Zeichen (11 Zeichen) wird abgelehnt"

# ----------------------------------------------------------------------------
# Befund 11: Regex-Timeout (5 Sekunden) auf allen Regex-Instanzen in A
# ----------------------------------------------------------------------------
Assert-True ([AnonTool.AnonEngine]::RxTimeout.TotalSeconds -eq 5) "Befund 11: Statisches RxTimeout in AnonEngine beträgt 5 Sekunden"
$allRulesHaveTimeout = $true
foreach ($r in $pathCfg.GeheimnisMuster) { if ($r.Compiled.MatchTimeout.TotalSeconds -ne 5) { $allRulesHaveTimeout = $false } }
foreach ($r in $pathCfg.FreitextMuster) { if ($r.Compiled.MatchTimeout.TotalSeconds -ne 5) { $allRulesHaveTimeout = $false } }
foreach ($r in $pathCfg.HostnamenMuster) { if ($r.MatchTimeout.TotalSeconds -ne 5) { $allRulesHaveTimeout = $false } }
Assert-True $allRulesHaveTimeout "Befund 11: Alle kompilierten Regel-Regex-Instanzen haben 5 Sekunden MatchTimeout"

# Prüfe Sicherheitsabbruch, wenn -TabellenPfad im Ausgabeordner liegt
$unsafeTab = Join-Path $outDir "geheim.json"
Assert-Throws {
    & $anonScript -Eingabe $beispieleDir -Ausgabe $outDir -TabellenPfad $unsafeTab -Unverschluesselt > $null 2>&1
} "Sicherheitsprüfung verhindert Speichern der Zuordnungstabelle im Ausgabeordner"

# Prüfe Archiv-Entpackung (.zip) und Binärdatei-Überspringen
$archInputDir = Join-Path $tempRunRoot "arch_in"
[void](New-Item -ItemType Directory -Path $archInputDir -Force)
Copy-Item -LiteralPath (Join-Path $beispieleDir "01-aruba-aoscx.txt") -Destination (Join-Path $archInputDir "config.txt")
[System.IO.File]::WriteAllBytes((Join-Path $archInputDir "firmware.bin"), [byte[]]@(0, 1, 2, 0, 255, 0, 42, 0, 99))
$zipPath = Join-Path $tempRunRoot "showtech.zip"
[System.IO.Compression.ZipFile]::CreateFromDirectory($archInputDir, $zipPath)

$zipOutDir = Join-Path $tempRunRoot "zip_out"
& $anonScript -Eingabe $zipPath -Ausgabe $zipOutDir -Regeln $rulesPath -TabellenPfad $tabFile -PasswortSecure $secPass > $null
$zipBericht = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $zipOutDir "bericht.json"), [System.Text.Encoding]::UTF8))
Assert-True ($zipBericht.verarbeiteteDateien -eq 1) "ZIP-Archiv entpackt und 1 Textdatei verarbeitet"
Assert-True ($zipBericht.uebersprungeneBinaer.Count -eq 1) "Binärdatei im ZIP erkannt und im Bericht als übersprungen gemeldet"
Assert-True ($zipBericht.pruefergebnis -eq "KEINE_RESTFUNDE") "ZIP-Ausgabe ist ohne Restfunde"

Write-Host "=== 5. Performance- & Stresstest: Großer Aruba AOS-CX Show-Tech (40.000+ Zeilen) ===" -ForegroundColor Cyan
$sb = New-Object System.Text.StringBuilder (4 * 1024 * 1024)
[void]$sb.AppendLine("================================f=show tech====================================")
[void]$sb.AppendLine("hostname dc1-sw-core01")
[void]$sb.AppendLine("Version : FL.10.13.1020")
[void]$sb.AppendLine("snmp-server system-location Rechenzentrum-Nord Halle 3")
[void]$sb.AppendLine("snmp-server system-contact Max Mustermann (netze@intern.example.invalid)")
[void]$sb.AppendLine("user admin password ciphertext AQBapf92384719283749182374918273948172938471928374")
for ($i = 1; $i -le 5000; $i++) {
    $vId = ($i % 400) + 10
    $o4 = ($i % 250) + 1
    $hex = ($i -band 0xFF).ToString("x2")
    $port = ($i % 48) + 1
    $dist = ($i % 30) + 1
    $acc = ($i % 80) + 1
    $net = @("192.0.2", "198.51.100", "203.0.113")[$i % 3]
    [void]$sb.AppendLine("vlan $vId")
    [void]$sb.AppendLine("    name KD_${vId}_${net}.0-24")
    [void]$sb.AppendLine("interface 1/1/$port")
    [void]$sb.AppendLine("    description Uplink_$i zu dist-sw$dist (Musterfirma GmbH)")
    [void]$sb.AppendLine("    ip address ${net}.${o4}/24")
    [void]$sb.AppendLine("1/1/$port  acc-sw$acc  00:1a:2b:3c:4d:$hex  ${net}.254  Aruba JL658A  FL.10.13.1020")
    [void]$sb.AppendLine("2026-10-16T14:22:15.123Z dc1-sw-core01 hpe-routing[$i]: Event on sn link state up for ${net}.${o4}")
}
$largeShowTech = $sb.ToString()
$perfCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
# Aufwärmlauf (JIT, Regex-Kompilierung), danach Median aus 3 Messungen
[void][AnonTool.AnonEngine]::ProcessText($largeShowTech, $perfCfg, (New-Object AnonTool.AnonState))
$perfMessungen = New-Object 'System.Collections.Generic.List[long]'
for ($perfLauf = 0; $perfLauf -lt 3; $perfLauf++) {
    $perfState = New-Object AnonTool.AnonState
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $largeAnon = [AnonTool.AnonEngine]::ProcessText($largeShowTech, $perfCfg, $perfState)
    $largeFindings = [AnonTool.AnonEngine]::AuditText($largeAnon, "aruba-show-tech-large.txt", $perfCfg)
    $sw.Stop()
    $perfMessungen.Add($sw.ElapsedMilliseconds)
}
$perfSortiert = @($perfMessungen | Sort-Object)
$perfMedian = $perfSortiert[1]
Write-Host ("  Großer Show-Tech ({0:N2} MB) verarbeitet + geprüft: Median {1} ms aus {2} Messungen ({3})" -f ($largeShowTech.Length / 1MB), $perfMedian, $perfMessungen.Count, ($perfMessungen -join ", ")) -ForegroundColor Gray
Assert-True ($perfMessungen.Count -eq 3) "Performance: Aufwärmlauf und 3 Messungen"
# Grenze: lokal 8000 ms; Windows PowerShell 5.1 (Desktop) und CI-Runner sind deutlich langsamer, dort 30000 ms
$perfGrenze = if ($PSVersionTable.PSEdition -eq "Desktop" -or -not [string]::IsNullOrEmpty($env:CI)) { 30000 } else { 8000 }
Assert-True ($perfMedian -lt $perfGrenze) "Performance-Ziel erreicht: Median $perfMedian ms (< $perfGrenze ms)"
Assert-True ($largeFindings.Count -eq 0) "Großer Aruba Show-Tech ist nach Anonymisierung ohne Restfunde (0 Restfunde)"
Assert-True (-not $largeAnon.Contains([string][char]2 + "PROT_")) "Alle Schutz-Marker vollständig aufgelöst"

Write-Host "`n=== 7. Prüfe Code-Review Commit 65cd5d4 (Befund 1; Befunde 2-3 betrafen den Sammler, eigenes Projekt) ===" -ForegroundColor Cyan

# 7.1 Befund 1: Freitext-Leck bei geschützten Wörtern im Body (LF + CRLF, inkl. Alle-freitextMuster-Schleife)
$freitextSamplesByRule = @{
    "Mehrzeilige oder einzeilige Banner (banner/header motd, exec, login, shell, incoming)" = "banner motd ^Kunde Mustermann Ethernet1/1/1^"
    "SNMP Location & System-Location (CLI)"                                                 = "snmp-server system-location Kunde Mustermann Ethernet1/1/1"
    "SNMP Contact & System-Contact (CLI)"                                                   = "snmp-server system-contact Kunde Mustermann Ethernet1/1/1"
    "Interface Description / Alias (CLI)"                                                   = " description Kunde Mustermann Ethernet1/1/1"
    "VLAN-Namen (CLI)"                                                                      = " name Kunde Mustermann Ethernet1/1/1"
    "VLAN-/Objektnamen (JSON)"                                                              = '"vlan_name": "Kunde Mustermann Ethernet1/1/1"'
    "SONiC / JSON Description, Alias, Location, Contact"                                    = '"description": "Kunde Mustermann Ethernet1/1/1"'
    "LLDP / CDP System Description & Port Description"                                      = "System Description : Kunde Mustermann Ethernet1/1/1"
    "MikroTik comment= (in Anführungszeichen, inkl. Leerzeichen und mehrzeiliger \-Fortsetzung)" = 'set [ find default-name=ether1 ] comment="Kunde Mustermann Ethernet1/1/1"'
    "MikroTik comment= (ohne Anführungszeichen)"                                            = "set [ find default-name=ether1 ] comment=Kunde Mustermann Ethernet1/1/1"
    "MikroTik SNMP Location (location=)"                                                    = '/snmp set location="Kunde Mustermann Ethernet1/1/1"'
    "MikroTik SNMP Contact (contact=)"                                                      = '/snmp set contact="Kunde Mustermann Ethernet1/1/1"'
    "MikroTik Interface-/VLAN-/Bridge-Namen (name= und interface= konsistent)"              = '/interface vlan add interface=bridge1 name="Kunde Mustermann Ethernet1/1/1" vlan-id=10'
    "Port-Name / Display-String (Ruckus ICX port-name, Extreme EXOS display-string)"         = ' port-name Kunde Mustermann Ethernet1/1/1'
}
Assert-Equal $rulesObj.freitextMuster.Count $freitextSamplesByRule.Count "Alle $($rulesObj.freitextMuster.Count) freitextMuster-Regeln sind im Mustermann+Ethernet1/1/1-Test abgedeckt"

foreach ($eol in @("`n", "`r`n")) {
    $eolName = if ($eol -eq "`r`n") { "CRLF" } else { "LF" }
    $ftState = New-Object AnonTool.AnonState
    $ftCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
    $ftLines = @(
        "interface 1/1/10",
        " description Uplink Praxis Dr Weber Ethernet1/1/10",
        "snmp-server system-location Praxis Weber München Ethernet1/1/2",
        'set [ find default-name=ether1 ] comment="Kunde Weber Gi1/0/1"',
        "vlan 20",
        " name Praxis_Weber_FL.10.13.1020",
        "System Description : Switch bei Weber FL.10.13.1020",
        "System Description : ArubaOS-CX FL.10.13.1020"
    )
    $ftInput = $ftLines -join $eol
    $ftOut = [AnonTool.AnonEngine]::ProcessText($ftInput, $ftCfg, $ftState)

    Assert-True ($ftOut.Contains(" description TEXT-1") -and -not $ftOut.Contains("Weber") -and -not $ftOut.Contains("Ethernet1/1/10")) "Befund 1 ($eolName): description mit Personenname + Portname (Ethernet1/1/10) wird komplett ersetzt"
    Assert-True ($ftOut.Contains("snmp-server system-location ORT-1") -and -not $ftOut.Contains("München") -and -not $ftOut.Contains("Ethernet1/1/2")) "Befund 1 ($eolName): snmp-server system-location mit Ort + Portname wird komplett ersetzt"
    Assert-True ($ftOut.Contains('comment="TEXT-4"') -and -not $ftOut.Contains("Gi1/0/1")) "Befund 1 ($eolName): MikroTik comment=""... Gi1/0/1"" wird komplett ersetzt"
    Assert-True ($ftOut.Contains(" name TEXT-2")) "Befund 1 ($eolName): VLAN-name mit Name + Versionsnummer (FL.10.13.1020) wird komplett ersetzt"
    Assert-True ($ftOut.Contains("System Description : TEXT-3") -and -not $ftOut.Contains("Switch bei Weber")) "Befund 1 ($eolName): System Description 'Switch bei Weber FL.10.13.1020' wird komplett ersetzt"
    Assert-True ($ftOut.Contains("System Description : ArubaOS-CX FL.10.13.1020")) "Befund 1 Positivtest ($eolName): System Description 'ArubaOS-CX FL.10.13.1020' (nur Produkt + Version) bleibt erhalten"

    # Schleife über ALLE freitextMuster: Body "Kunde Mustermann Ethernet1/1/1" muss bei jedem Muster ersetzt werden
    foreach ($fRule in $rulesObj.freitextMuster) {
        $rName = [string]$fRule.name
        $sampleLine = $freitextSamplesByRule[$rName]
        Assert-True (-not [string]::IsNullOrEmpty($sampleLine)) "Testzeile für freitextMuster '$rName' vorhanden"

        $singleRegeln = ($rawRules | ConvertFrom-Json)
        $singleRegeln.freitextMuster = @($fRule)
        $singleCfg = New-TestConfig -RulesObj $singleRegeln -Netzerhaltend $true
        $singleState = New-Object AnonTool.AnonState
        $singleInput = $sampleLine + $eol + "next-line"
        $singleOut = [AnonTool.AnonEngine]::ProcessText($singleInput, $singleCfg, $singleState)
        $expectedCat = if ([string]::IsNullOrWhiteSpace($fRule.kategorie)) { "TEXT" } else { [string]$fRule.kategorie }
        $expectedPh = "$expectedCat-1"
        Assert-True ($singleOut.Contains($expectedPh) -and -not $singleOut.Contains("Mustermann") -and -not $singleOut.Contains("Kunde") -and -not $singleOut.Contains("Ethernet1/1/1")) "Befund 1 Alle-Muster-Test ($eolName) [$rName]: 'Kunde Mustermann Ethernet1/1/1' wird durch $expectedPh ersetzt"
    }
}

# 7.4 Statische Prüfung für anonymisierer.html (keine Verwendung von localStorage/sessionStorage/indexedDB)
$htmlRawContent = [System.IO.File]::ReadAllText((Join-Path (Join-Path $rootDir "web") "anonymisierer.html"), [System.Text.Encoding]::UTF8)
Assert-True (-not [regex]::IsMatch($htmlRawContent, '(?i)\b(?:localStorage|sessionStorage|indexedDB)\b')) "Statischer Check (PowerShell): anonymisierer.html enthält kein localStorage, sessionStorage oder indexedDB"

Write-Host "=== 8. Prüfe editierbare Zuordnungstabelle & anon-regeln.lokal.json (ausnahmen.exakteWoerter) ===" -ForegroundColor Cyan
# 8.1 anon.ps1 mit -LokaleRegeln (festeZuordnung + ausnahmen.exakteWoerter)
$lokalTestDir = Join-Path $tempRunRoot "lokal_test"
[void](New-Item -ItemType Directory -Path $lokalTestDir -Force)
$lokalRegelnDatei = Join-Path $lokalTestDir "anon-regeln.lokal.json"
$lokalEingabeDatei = Join-Path $lokalTestDir "eingabe.txt"
$lokalAusgabeOrdner = Join-Path $lokalTestDir "ausgabe"
$lokalTabelleDatei = Join-Path $lokalTestDir "tabelle.json"

$lokalJsonContent = @'
{
  "eigeneBegriffe": {
    "festeZuordnung": {
      "sw-core-lokal01": "CORE-LOKAL"
    }
  },
  "ausnahmen": {
    "exakteWoerter": [
      "Rechenzentrum-Nord Raum 2.04",
      "198.51.100.77"
    ]
  }
}
'@
[System.IO.File]::WriteAllText($lokalRegelnDatei, $lokalJsonContent, [System.Text.Encoding]::UTF8)

$lokalInputText = @"
hostname sw-core-lokal01
snmp-server location Rechenzentrum-Nord Raum 2.04
interface 1/1/1
   ip address 198.51.100.77/24
   description Uplink zu Server
"@
[System.IO.File]::WriteAllText($lokalEingabeDatei, $lokalInputText, [System.Text.Encoding]::UTF8)

& $anonScript -Eingabe $lokalEingabeDatei -Ausgabe $lokalAusgabeOrdner -Regeln $rulesPath -LokaleRegeln $lokalRegelnDatei -TabellenPfad $lokalTabelleDatei -Unverschluesselt > $null
Assert-Equal $LASTEXITCODE 0 "anon.ps1 CLI mit -LokaleRegeln beendet mit Exit-Code 0"

$lokalOutFile = Join-Path (Join-Path $lokalAusgabeOrdner "anonym") "eingabe.txt"
Assert-True (Test-Path -LiteralPath $lokalOutFile) "Ausgabedatei wurde erzeugt"
$lokalOutText = [System.IO.File]::ReadAllText($lokalOutFile, [System.Text.Encoding]::UTF8)

Assert-True ($lokalOutText.Contains("hostname CORE-LOKAL")) "festeZuordnung aus -LokaleRegeln wird korrekt angewendet ('CORE-LOKAL')"
Assert-True ($lokalOutText.Contains("snmp-server location Rechenzentrum-Nord Raum 2.04")) "Freitext-Ausnahme aus ausnahmen.exakteWoerter bleibt im Klartext"
Assert-True ($lokalOutText.Contains("198.51.100.77")) "IP-Ausnahme aus ausnahmen.exakteWoerter bleibt im Klartext"

# Prüfmodus auf der Ausgabedatei über CLI (-Pruefen)
& $anonScript -Eingabe $lokalOutFile -Regeln $rulesPath -LokaleRegeln $lokalRegelnDatei -Pruefen > $null
Assert-Equal $LASTEXITCODE 0 "Prüfmodus: Ausgabedatei mit ausnahmen.exakteWoerter ist ohne Restfunde (Exit-Code 0)"

# 8.1b Lokale Muster (eigeneHostnamenMuster, seriennummerMuster, tabellenSpalten) aus anon-regeln.lokal.json
$musterTestDir = Join-Path $tempRunRoot "lokal_muster"
[void](New-Item -ItemType Directory -Path $musterTestDir -Force)
$musterRegeln = Join-Path $musterTestDir "anon-regeln.lokal.json"
$musterEingabe = Join-Path $musterTestDir "eingabe.txt"
$musterAusgabe = Join-Path $musterTestDir "ausgabe"
$musterTabelle = Join-Path $musterTestDir "tabelle.json"
$musterJson = @'
{
  "eigeneHostnamenMuster": ["(?i)(?<![A-Za-z0-9-])(xy[0-9]-(?:sw|dist)[0-9]{2})(?![A-Za-z0-9-])"],
  "seriennummerMuster": ["(?i)((?<![A-Za-z0-9_])Inventar-Nr[ \\t]*:[ \\t]*)([A-Za-z0-9-]{5,24})()"],
  "tabellenSpalten": [{ "name": "Beispiel Nachbartabelle", "kopf": ["Nachbar", "Schnittstelle"], "spalten": [{ "name": "Nachbar", "kategorie": "HOST" }] }]
}
'@
[System.IO.File]::WriteAllText($musterRegeln, $musterJson, (New-Object System.Text.UTF8Encoding($false)))
$musterInput = "Peer XY1-SW03 is reachable`nuplink xy2-dist11 up, backup xy2-dist11_alt`nInventar-Nr: INV-0042-77`n`nNachbar        Schnittstelle`nnb-lager-ost   1/1/7`n"
$musterExpected = "Peer HOST-2 is reachable`nuplink HOST-3 up, backup HOST-3_alt`nInventar-Nr: SERIAL-1`n`nNachbar        Schnittstelle`nHOST-1         1/1/7`n"
[System.IO.File]::WriteAllText($musterEingabe, $musterInput, (New-Object System.Text.UTF8Encoding($false)))

& $anonScript -Eingabe $musterEingabe -Ausgabe $musterAusgabe -Regeln $rulesPath -LokaleRegeln $musterRegeln -TabellenPfad $musterTabelle -Unverschluesselt > $null
Assert-Equal $LASTEXITCODE 0 "Lokale Muster: Ausgabe ist ohne Restfunde (Exit-Code 0)"
$musterOut = [System.IO.File]::ReadAllText((Join-Path (Join-Path $musterAusgabe "anonym") "eingabe.txt"), [System.Text.Encoding]::UTF8)
Assert-True ($musterOut -ceq $musterExpected) "Lokale Muster: eigeneHostnamenMuster, seriennummerMuster und tabellenSpalten greifen (PS1)"
& $anonScript -Eingabe $musterEingabe -Regeln $rulesPath -LokaleRegeln $musterRegeln -Pruefen > $null
Assert-Equal $LASTEXITCODE 2 "Lokale Muster: Prüfmodus beanstandet die Rohdaten (Exit-Code 2)"

# 8.2 Zuordnungstabelle: Aliase werden beim Export/Import beibehalten und für Rückübersetzung genutzt
$tabJson = [System.IO.File]::ReadAllText($lokalTabelleDatei, [System.Text.Encoding]::UTF8)
$tabObj = ConvertFrom-Json -InputObject $tabJson
Assert-True ($null -ne $tabObj.aliase) "Exportierte Tabelle enthält Feld 'aliase'"

# Ergänze einen Alias in der Tabelle für den CLI-Rückübersetzungstest
$tabObj.aliase | Add-Member -NotePropertyName "TEXT-23" -NotePropertyValue "VLAN-GAESTE"
$tabObj.rueckwaerts | Add-Member -NotePropertyName "VLAN-GAESTE" -NotePropertyValue "Uplink Praxis Dr Weber"
$tabObj.rueckwaerts | Add-Member -NotePropertyName "TEXT-23" -NotePropertyValue "Uplink Praxis Dr Weber"
[System.IO.File]::WriteAllText($lokalTabelleDatei, ($tabObj | ConvertTo-Json -Depth 8), [System.Text.Encoding]::UTF8)

# Rückübersetzung über CLI (-Zurueck)
$kiAntwortPfad = Join-Path $lokalTestDir "ki-antwort.txt"
$kiRueckPfad = Join-Path $lokalTestDir "ki-rueck.txt"
[System.IO.File]::WriteAllText($kiAntwortPfad, "Prüfe TEXT-23 und VLAN-GAESTE", [System.Text.Encoding]::UTF8)
& $anonScript -Zurueck -Eingabe $kiAntwortPfad -Ausgabe $kiRueckPfad -TabellenPfad $lokalTabelleDatei -Unverschluesselt > $null
Assert-Equal $LASTEXITCODE 0 "Rückübersetzung mit Aliastabelle beendet mit Exit-Code 0"

$kiRueckText = [System.IO.File]::ReadAllText($kiRueckPfad, [System.Text.Encoding]::UTF8)
Assert-True ($kiRueckText.Trim() -eq "Prüfe Uplink Praxis Dr Weber und Uplink Praxis Dr Weber") "Rückübersetzung (-Zurueck) funktioniert sowohl für neuen Namen als auch für alten Alias 'TEXT-23'"

Write-Host "=== 9. Datenabfluss & Tabellenformate (Punkt 2) ===" -ForegroundColor Cyan
$p2Dir = Join-Path $tempRunRoot "punkt2"
[void](New-Item -ItemType Directory -Path $p2Dir -Force)
$p2In = Join-Path $p2Dir "eingabe"
[void](New-Item -ItemType Directory -Path $p2In -Force)
[System.IO.File]::WriteAllText((Join-Path $p2In "probe.txt"), "hostname edge7`nlink edge7-alt`nip 192.0.2.10`n", (New-Object System.Text.UTF8Encoding($false)))

# 9.1 Unbekannte Tabellenformate: Abbruch, Datei bleibt unverändert
$fremdeTabellen = [ordered]@{
    "unbekannt" = '{ "format": "ANON-UNBEKANNT-9", "daten": "AAAA" }'
    "webcrypto" = '{ "format": "ANON-WEBCRYPTO-AESGCM-1", "kdf": "PBKDF2-SHA256", "iterations": 600000, "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "iv": "AAAAAAAAAAAAAAAA", "daten": "AAAA" }'
    "fremdjson" = '{ "irgendwas": 1 }'
    "kaputt"    = '{ kein json'
}
foreach ($name in $fremdeTabellen.Keys) {
    $tPfad = Join-Path $p2Dir "tabelle-$name.json"
    [System.IO.File]::WriteAllText($tPfad, $fremdeTabellen[$name], (New-Object System.Text.UTF8Encoding($false)))
    $vorher = [System.IO.File]::ReadAllText($tPfad)
    $meldung = ""
    try {
        & $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-$name") -Regeln $rulesPath -TabellenPfad $tPfad -Unverschluesselt *> $null
    } catch { $meldung = $_.Exception.Message }
    Assert-True ($meldung -ne "") "Tabellenformat '$name': anon.ps1 bricht mit Fehler ab"
    Assert-True ([System.IO.File]::ReadAllText($tPfad) -ceq $vorher) "Tabellenformat '$name': Tabellendatei wurde nicht überschrieben"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path (Join-Path $p2Dir "aus-$name") (Join-Path "anonym" "probe.txt")))) "Tabellenformat '$name': keine Ausgabe geschrieben"
}

# 9.2 Obergrenze 5.000.000 Iterationen
$iterTab = Join-Path $p2Dir "tabelle-iter.json"
[System.IO.File]::WriteAllText($iterTab, '{ "format": "ANON-AES256-2", "kdf": "PBKDF2-SHA1", "iterations": 5000001, "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "iv": "AAAAAAAAAAAAAAAAAAAAAA==", "hmac": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "daten": "AAAAAAAAAAAAAAAAAAAAAA==" }', (New-Object System.Text.UTF8Encoding($false)))
$iterMeldung = ""
try {
    & $anonScript -Zurueck -Eingabe (Join-Path $p2In "probe.txt") -TabellenPfad $iterTab -PasswortSecure $secPass *> $null
} catch { $iterMeldung = $_.Exception.Message }
Assert-True ($iterMeldung -like "*5.000.000*") "Iterationszahl über 5.000.000 wird beim Laden abgelehnt"

# 9.3 Konsole: Prüftreffer nur mit Kategorie, Datei und Zeile, nie mit dem Wert
$konsole = (& $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-konsole") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-konsole.json") -Unverschluesselt *>&1 | Out-String)
Assert-Equal $LASTEXITCODE 2 "Konsolentest: Restfund wird gemeldet (Exit-Code 2)"
Assert-True ($konsole.Contains("[Rest-Bekannt] probe.txt:2")) "Konsole nennt Kategorie, Datei und Zeile"
Assert-True (-not $konsole.Contains("edge7")) "Konsole enthält den gefundenen Wert nicht"
Assert-True ($konsole.Contains("NICHT weitergeben")) "Bei RESTFUNDE_VORHANDEN: Hinweis 'NICHT weitergeben' auf der Konsole"
$konsolePruef = (& $anonScript -Pruefen -Eingabe $p2In -Regeln $rulesPath *>&1 | Out-String)
Assert-True ($konsolePruef.Contains("NICHT weitergeben")) "-Pruefen mit Restfunden: Hinweis 'NICHT weitergeben' auf der Konsole"
Assert-True ($konsolePruef.Contains("[Rest-IPv4] probe.txt:3") -and -not $konsolePruef.Contains("192.0.2.10") -and -not $konsolePruef.Contains("edge7")) "-Pruefen: Konsole ohne gefundene Werte"
$berichtText = [System.IO.File]::ReadAllText((Join-Path (Join-Path $p2Dir "aus-konsole") "bericht.json"))
Assert-True (-not $berichtText.Contains("edge7")) "bericht.json enthält den gefundenen Wert nicht"

# 9.3b Fehlalarm über anon-regeln.lokal.json: umgebendes Wort als Ausnahme, Hostname bleibt ersetzt (wie anonymisierer.html)
$fehlalarmRegeln = Join-Path $p2Dir "fehlalarm.lokal.json"
[System.IO.File]::WriteAllText($fehlalarmRegeln, '{ "ausnahmen": { "exakteWoerter": ["edge7-alt"] } }', (New-Object System.Text.UTF8Encoding($false)))
& $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-fehlalarm") -Regeln $rulesPath -LokaleRegeln $fehlalarmRegeln -TabellenPfad (Join-Path $p2Dir "tab-fehlalarm.json") -Unverschluesselt *> $null
Assert-Equal $LASTEXITCODE 0 "Fehlalarm 'edge7-alt' als Ausnahme: Lauf ist ohne Restfunde (Exit-Code 0)"
$fehlalarmText = [System.IO.File]::ReadAllText((Join-Path (Join-Path (Join-Path $p2Dir "aus-fehlalarm") "anonym") "probe.txt"))
Assert-True ($fehlalarmText.StartsWith("hostname HOST-1") -and $fehlalarmText.Contains("link edge7-alt")) "Fehlalarm: Hostname bleibt ersetzt, nur das Wort 'edge7-alt' bleibt stehen"

# 9.4 Fehlermeldungen ohne Dateinamen
$fehlerMeldung = ""
try {
    & $anonScript -Eingabe (Join-Path $p2Dir "geheim-sw01_192.0.2.77.txt") -Ausgabe (Join-Path $p2Dir "aus-fehler") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-fehler.json") -Unverschluesselt *> $null
} catch { $fehlerMeldung = $_.Exception.Message }
Assert-True ($fehlerMeldung -like "*Nr. 1*" -and -not $fehlerMeldung.Contains("geheim-sw01") -and -not $fehlerMeldung.Contains("192.0.2.77")) "Fehlermeldung nennt nur die laufende Nummer, keinen Dateinamen ($fehlerMeldung)"
$fehlerPruef = ""
try { & $anonScript -Pruefen -Eingabe (Join-Path $p2Dir "geheim-sw01.txt") -Regeln $rulesPath *> $null } catch { $fehlerPruef = $_.Exception.Message }
Assert-True ($fehlerPruef -like "*Nr. 1*" -and -not $fehlerPruef.Contains("geheim-sw01")) "-Pruefen: Fehlermeldung ohne Dateinamen"
$sicherMeldung = ""
try {
    & $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "kunde-x") -TabellenPfad (Join-Path (Join-Path $p2Dir "kunde-x") "tab.json") -Regeln $rulesPath -Unverschluesselt *> $null
} catch { $sicherMeldung = $_.Exception.Message }
Assert-True ($sicherMeldung -like "*SICHERHEITSFEHLER*" -and -not $sicherMeldung.Contains("kunde-x")) "Tabelle im Ausgabeordner: Fehlermeldung ohne Pfade"

# 9.5 -Netzerhaltend / -NichtNetzerhaltend als Schalter
& $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-nicht") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-nicht.json") -Unverschluesselt -NichtNetzerhaltend *> $null
$nichtText = [System.IO.File]::ReadAllText((Join-Path (Join-Path $p2Dir "aus-nicht") (Join-Path "anonym" "probe.txt")))
Assert-True ($nichtText.Contains("ip IP-PUB-1")) "-NichtNetzerhaltend: IP wird als IP-PUB-n ersetzt"
& $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-netz") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-netz.json") -Unverschluesselt -Netzerhaltend *> $null
$netzText = [System.IO.File]::ReadAllText((Join-Path (Join-Path $p2Dir "aus-netz") (Join-Path "anonym" "probe.txt")))
Assert-True ($netzText.Contains("ip NET-1.H1")) "-Netzerhaltend: IP wird als NET-n.Hm ersetzt"
Assert-Throws { & $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-beide") -Regeln $rulesPath -Unverschluesselt -Netzerhaltend -NichtNetzerhaltend *> $null } "-Netzerhaltend und -NichtNetzerhaltend zusammen werden abgelehnt"
$paramInfo = (Get-Command $anonScript).Parameters
Assert-True ($paramInfo["Netzerhaltend"].ParameterType -eq [System.Management.Automation.SwitchParameter] -and $paramInfo["NichtNetzerhaltend"].ParameterType -eq [System.Management.Automation.SwitchParameter]) "-Netzerhaltend und -NichtNetzerhaltend sind Schalter (kein Nullable[bool])"

# 9.6 Verwaiste Arbeitsordner früherer Abbrüche werden beim Start entfernt
$verwaist = Join-Path $arbeitRoot "verwaist0001"
[void](New-Item -ItemType Directory -Path $verwaist -Force)
[System.IO.File]::WriteAllText((Join-Path $verwaist "reste.txt"), "hostname edge7")
(Get-Item -LiteralPath $verwaist).LastWriteTime = (Get-Date).AddDays(-2)
& $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-verwaist") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-verwaist.json") -Unverschluesselt *> $null
Assert-True (-not (Test-Path -LiteralPath $verwaist)) "Verwaister Arbeitsordner eines abgebrochenen Laufs wird beim nächsten Start gelöscht"

# 9.6b Rückübersetzung: Klartext nie unter anonym\ oder im Ausgabeordner eines Laufs, Standard <Basis>\klartext\
$laufOrdner = Join-Path $p2Dir "aus-konsole"
$kiDatei = Join-Path $p2Dir "ki.txt"
[System.IO.File]::WriteAllText($kiDatei, "Pruefe HOST-1 und NET-1.H1", (New-Object System.Text.UTF8Encoding($false)))
$konsoleTab = Join-Path $p2Dir "tab-konsole.json"
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiDatei -Ausgabe (Join-Path (Join-Path $laufOrdner "anonym") "rueck.txt") -TabellenPfad $konsoleTab *> $null } "-Zurueck: Ziel unterhalb von anonym\ wird abgelehnt"
Assert-Throws { & $anonScript -Zurueck -Eingabe $kiDatei -Ausgabe (Join-Path $laufOrdner "rueck.txt") -TabellenPfad $konsoleTab *> $null } "-Zurueck: Ziel im Ausgabeordner eines Laufs (anonym\ + bericht.json) wird abgelehnt"
Assert-True (-not (Test-Path -LiteralPath (Join-Path $laufOrdner "rueck.txt"))) "-Zurueck: im Ausgabeordner wurde nichts geschrieben"
$rueckKonsole = (& $anonScript -Zurueck -Eingabe $kiDatei -TabellenPfad $konsoleTab *>&1 | Out-String)
$klartextDir = Join-Path (Join-Path $env:LOCALAPPDATA "Anon") "klartext"
$klartextDateien = @(Get-ChildItem -LiteralPath $klartextDir -File -ErrorAction SilentlyContinue)
Assert-True ($klartextDateien.Count -eq 1) "-Zurueck ohne -Ausgabe: Klartext landet in <Basis>\klartext\"
Assert-True ($klartextDateien.Count -eq 1 -and [System.IO.File]::ReadAllText($klartextDateien[0].FullName).Contains("edge7")) "-Zurueck ohne -Ausgabe: Datei enthält den rückübersetzten Text"
Assert-True (-not $rueckKonsole.Contains("edge7")) "-Zurueck: Klartext erscheint nicht auf der Konsole"

# 9.6c Standard-Regeldatei: neben anon.ps1 (Admin-VM) oder ..\regeln\ (Repository)
$ohneRegeln = (& $anonScript -Pruefen -Eingabe $erwartetDir *>&1 | Out-String)
Assert-True ($LASTEXITCODE -eq 0 -and $ohneRegeln.Contains("KEINE_RESTFUNDE")) "Ohne -Regeln wird regeln\anon-regeln.json gefunden (Repository-Struktur)"

# 9.7 Prüfung der Quelldateien: UTF-8 mit BOM, keine Gedankenstriche (PS 5.1 liest .ps1 ohne BOM als ANSI)
foreach ($ps1 in @($anonScript, (Join-Path $testDir "run-tests.ps1"))) {
    $raw = [System.IO.File]::ReadAllBytes($ps1)
    $hasBom = ($raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF)
    Assert-True $hasBom "$([System.IO.Path]::GetFileName($ps1)) ist UTF-8 mit BOM"
    $txt = [System.Text.Encoding]::UTF8.GetString($raw)
    $dash = $txt.IndexOf([char]0x2013) -ge 0 -or $txt.IndexOf([char]0x2014) -ge 0 -or $txt.IndexOf([char]0x201E) -ge 0 -or $txt.IndexOf([char]0x201C) -ge 0
    Assert-True (-not $dash) "$([System.IO.Path]::GetFileName($ps1)) enthält keine Gedankenstriche oder typografischen Anführungszeichen"
}

# 9.9 Paket A4: bekannte Originalwerte in Dateinamen an "-" und "." ersetzen
$pfadIn = Join-Path $p2Dir "pfad_eingabe"
[void](New-Item -ItemType Directory -Path $pfadIn -Force)
[System.IO.File]::WriteAllText((Join-Path $pfadIn "privatehost01-backup.txt"), "hostname privatehost01`n", (New-Object System.Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText((Join-Path $pfadIn "privatehost01.old.log"), "uptime 3 days`n", (New-Object System.Text.UTF8Encoding($false)))
& $anonScript -Eingabe $pfadIn -Ausgabe (Join-Path $p2Dir "aus-pfad") -Regeln $rulesPath -TabellenPfad (Join-Path $p2Dir "tab-pfad.json") -Unverschluesselt *> $null
# Reihenfolgeunabhängig: Sort-Object sortiert unter PS 5.1 und PS 7 kulturabhängig verschieden ("-" vs ".")
$pfadNamen = @(Get-ChildItem -LiteralPath (Join-Path (Join-Path $p2Dir "aus-pfad") "anonym") -File | ForEach-Object { $_.Name })
$pfadErwartet = @("HOST-1-backup.txt", "HOST-1.old.log")
$pfadAlleDa = @($pfadErwartet | Where-Object { $pfadNamen -ccontains $_ }).Count -eq $pfadErwartet.Count
Assert-True ($pfadNamen.Count -eq 2 -and $pfadAlleDa) "A4: bekannter Host im Dateinamen an '-' und '.' ersetzt, genau zwei Dateien ($($pfadNamen -join ', '))"

# 9.10 Paket A5: Kollision zwischen geladener Tabelle und festeZuordnung -> Abbruch, Tabelle unverändert
$kollTab = Join-Path $p2Dir "tab-kollision.json"
[System.IO.File]::WriteAllText($kollTab, '{ "version": "1.0", "vorwaerts": { "HOST|device-x": "HOST-1" }, "rueckwaerts": { "HOST-1": "device-x" }, "zaehler": { "HOST": 1 } }', (New-Object System.Text.UTF8Encoding($false)))
$kollLokal = Join-Path $p2Dir "kollision.lokal.json"
[System.IO.File]::WriteAllText($kollLokal, '{ "eigeneBegriffe": { "festeZuordnung": { "device-one": "HOST-1" } } }', (New-Object System.Text.UTF8Encoding($false)))
$kollVorher = [System.IO.File]::ReadAllText($kollTab)
$kollMeldung = ""
try {
    & $anonScript -Eingabe $p2In -Ausgabe (Join-Path $p2Dir "aus-koll") -Regeln $rulesPath -LokaleRegeln $kollLokal -TabellenPfad $kollTab -Unverschluesselt *> $null
} catch { $kollMeldung = $_.Exception.Message }
Assert-True ($kollMeldung -like "*HOST-1*" -and [System.IO.File]::ReadAllText($kollTab) -ceq $kollVorher) "A5: Platzhalter-Kollision beim Laden führt zum Abbruch, Tabelle unverändert ($kollMeldung)"

# 9.11 Paket A9: Bezeichnung KEINE_RESTFUNDE statt SAUBER
$a9Konsole = (& $anonScript -Pruefen -Eingabe $erwartetDir *>&1 | Out-String)
Assert-True ($a9Konsole.Contains("KEINE_RESTFUNDE") -and $a9Konsole.Contains("Keine Restfunde nach aktivem Regelwerk") -and -not $a9Konsole.Contains("SAUBER")) "A9: Konsole meldet KEINE_RESTFUNDE (Keine Restfunde nach aktivem Regelwerk)"
$a9Bericht = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $outDir "bericht.json")))
Assert-True ($a9Bericht.pruefergebnis -eq "KEINE_RESTFUNDE") "A9: bericht.json pruefergebnis = KEINE_RESTFUNDE"
Assert-True (-not ([System.IO.File]::ReadAllText($anonScript)).Contains("SAUBER")) "A9: anon.ps1 verwendet die Bezeichnung 'SAUBER' nicht mehr"

# 9.12 Paket B4: Überschneidungen von Eingabe, Ausgabe und Tabelle; doppelte Ausgabepfade
$ovDir = Join-Path $p2Dir "ueberschneidung"
$ovEin = Join-Path $ovDir "eingang"
[void](New-Item -ItemType Directory -Path $ovEin -Force)
[System.IO.File]::WriteAllText((Join-Path $ovEin "a.txt"), "hostname ov-host01`n", (New-Object System.Text.UTF8Encoding($false)))
# a) Eingabe liegt im Ordner anonym\ der Ausgabe: darf vor dem Einsammeln nicht gelöscht werden
$ovAus = Join-Path $ovDir "aus"
$ovInAnonym = Join-Path (Join-Path $ovAus "anonym") "eingang"
[void](New-Item -ItemType Directory -Path $ovInAnonym -Force)
[System.IO.File]::WriteAllText((Join-Path $ovInAnonym "b.txt"), "hostname ov-host02`n", (New-Object System.Text.UTF8Encoding($false)))
$ovMeldung = ""
try { & $anonScript -Eingabe $ovInAnonym -Ausgabe $ovAus -Regeln $rulesPath -TabellenPfad (Join-Path $ovDir "tab-a.json") -Unverschluesselt *> $null } catch { $ovMeldung = $_.Exception.Message }
Assert-True ($ovMeldung -like "*berschneid*" -and (Test-Path -LiteralPath (Join-Path $ovInAnonym "b.txt"))) "B4: Eingabe innerhalb von <Ausgabe>\anonym wird abgelehnt und nicht gelöscht ($ovMeldung)"
# b) Ausgabe liegt im Eingabeordner
$ovMeldung2 = ""
try { & $anonScript -Eingabe $ovEin -Ausgabe (Join-Path $ovEin "aus") -Regeln $rulesPath -TabellenPfad (Join-Path $ovDir "tab-b.json") -Unverschluesselt *> $null } catch { $ovMeldung2 = $_.Exception.Message }
Assert-True ($ovMeldung2 -like "*berschneid*" -and -not (Test-Path -LiteralPath (Join-Path $ovEin "aus"))) "B4: Ausgabe innerhalb des Eingabeordners wird abgelehnt, nichts angelegt ($ovMeldung2)"
# c) Zuordnungstabelle liegt im Eingabeordner
$ovMeldung3 = ""
try { & $anonScript -Eingabe $ovEin -Ausgabe (Join-Path $ovDir "aus-c") -Regeln $rulesPath -TabellenPfad (Join-Path $ovEin "tabelle.json") -Unverschluesselt *> $null } catch { $ovMeldung3 = $_.Exception.Message }
Assert-True ($ovMeldung3 -like "*berschneid*" -and -not (Test-Path -LiteralPath (Join-Path $ovEin "tabelle.json"))) "B4: Zuordnungstabelle im Eingabeordner wird abgelehnt ($ovMeldung3)"
# d) Zwei Eingaben ergeben denselben Ausgabepfad: Abbruch, keine Datei geschrieben
$ovEin2 = Join-Path $ovDir "eingang2"
[void](New-Item -ItemType Directory -Path $ovEin2 -Force)
[System.IO.File]::WriteAllText((Join-Path $ovEin2 "a.txt"), "uptime 1 day`n", (New-Object System.Text.UTF8Encoding($false)))
$ovAusD = Join-Path $ovDir "aus-d"
$ovMeldung4 = ""
try { & $anonScript -Eingabe @($ovEin, $ovEin2) -Ausgabe $ovAusD -Regeln $rulesPath -TabellenPfad (Join-Path $ovDir "tab-d.json") -Unverschluesselt *> $null } catch { $ovMeldung4 = $_.Exception.Message }
$ovGeschrieben = @(Get-ChildItem -LiteralPath (Join-Path $ovAusD "anonym") -File -Recurse -ErrorAction SilentlyContinue).Count
Assert-True ($ovMeldung4 -like "*Ausgabepfad*" -and $ovGeschrieben -eq 0 -and -not $ovMeldung4.Contains("a.txt")) "B4: doppelter Ausgabepfad führt zum Abbruch ohne geschriebene Datei, Meldung ohne Dateinamen ($ovMeldung4)"

# 9.13 Paket B5: Tabellenimport prüft Schema, Formatversion und beide Richtungen; abgelehnte Tabelle bleibt unverändert
$imp = @{
    "widerspruch" = '{ "version": "1.0", "vorwaerts": { "HOST|device-one": "HOST-1" }, "rueckwaerts": { "HOST-1": "device-two" } }'
    "version"     = '{ "version": "9.9", "vorwaerts": {}, "rueckwaerts": {} }'
    "ohneRueck"   = '{ "version": "1.0", "vorwaerts": { "HOST|a-1": "HOST-1" } }'
}
foreach ($name in $imp.Keys) {
    $impTab = Join-Path $p2Dir "import-$name.json"
    [System.IO.File]::WriteAllText($impTab, $imp[$name], (New-Object System.Text.UTF8Encoding($false)))
    $impMeldung = ""
    try { & $anonScript -Zurueck -Eingabe $kiDatei -Ausgabe (Join-Path $p2Dir "import-$name-rueck.txt") -TabellenPfad $impTab *> $null } catch { $impMeldung = $_.Exception.Message }
    Assert-True ($impMeldung -ne "" -and -not (Test-Path -LiteralPath (Join-Path $p2Dir "import-$name-rueck.txt")) -and [System.IO.File]::ReadAllText($impTab) -ceq $imp[$name]) "B5: Tabellenimport '$name' wird abgelehnt, nichts geschrieben, Tabelle unverändert ($impMeldung)"
}

# 9.8 Strukturvorlage (-Strukturvorlage)
$svAus = Join-Path $p2Dir "struktur"
$svKonsole = (& $anonScript -Strukturvorlage -Eingabe (Join-Path $testDir "beispiele-struktur.txt") -Ausgabe $svAus -Regeln $rulesPath *>&1 | Out-String)
Assert-Equal $LASTEXITCODE 0 "-Strukturvorlage beendet mit Exit-Code 0"
Assert-True ($svKonsole.Contains("Vor Weitergabe sichten")) "-Strukturvorlage: Hinweis 'Vor Weitergabe sichten' auf der Konsole"
$svDatei = Join-Path $svAus "strukturvorlage-001.txt"
Assert-True (Test-Path -LiteralPath $svDatei) "-Strukturvorlage: nummerierte Ausgabedatei (kein Originalname)"
$svText = [System.IO.File]::ReadAllText($svDatei)
foreach ($wert in @("xy7", "core03", "Uplink", "192", "Buchhaltung", "Qwertz77", "AQBapG7xYz99", "TW12AB3456", "Kleinbach", "dist04", "leaf01")) {
    Assert-True (-not $svText.Contains($wert)) "-Strukturvorlage: Wert '$wert' aus der Eingabe ist nicht mehr enthalten"
}
Assert-True ($svText.Contains("description <FREITEXT>") -and $svText.Contains("snmp-server community *****") -and $svText.Contains("interface 9/9/99")) "-Strukturvorlage: Freitext, Geheimnis und Form wie erwartet"

# ----------------------------------------------------------------------------
# 10a. Multimengenvergleich für Funde (ordinal, Groß-/Kleinschreibung zählt, keine Deduplizierung)
# Diagnosen enthalten nur Quelle, Kategorie, Zeile und Anzahl, nie Fundwerte.
# ----------------------------------------------------------------------------
Write-Host "=== 10a. Selbsttest des Multimengenvergleichs ===" -ForegroundColor Cyan
# Fund-Zeile "quelle|zeile|kategorie|fund" zerlegen (fund ist der Rest und darf "|" enthalten)
function ConvertTo-FundEintrag {
    param([string]$Zeile)
    $t = $Zeile.Split([char]'|')
    $fund = if ($t.Length -gt 3) { [string]::Join("|", $t, 3, $t.Length - 3) } else { "" }
    return [pscustomobject]@{ quelle = $t[0]; zeile = $t[1]; kategorie = $t[2]; fund = $fund }
}
function Get-FundZaehlung {
    param($Liste)
    $orte = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
    foreach ($f in $Liste) {
        $ort = [string]$f.quelle + [char]0 + [string]$f.zeile + [char]0 + [string]$f.kategorie
        if (-not $orte.ContainsKey($ort)) { $orte[$ort] = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::Ordinal) }
        $werte = $orte[$ort]
        $w = [string]$f.fund
        if ($werte.ContainsKey($w)) { $werte[$w] = $werte[$w] + 1 } else { $werte[$w] = 1 }
    }
    return $orte
}
function Compare-FundMultimenge {
    param($Soll, $Ist)
    $a = Get-FundZaehlung $Soll
    $b = Get-FundZaehlung $Ist
    $alle = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($k in $a.Keys) { [void]$alle.Add($k) }
    foreach ($k in $b.Keys) { [void]$alle.Add($k) }
    $orte = New-Object 'System.Collections.Generic.List[string]' (,[string[]]@($alle))
    $orte.Sort([System.StringComparer]::Ordinal)
    $diag = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ort in $orte) {
        $teile = $ort.Split([char]0)
        $wo = "$($teile[0]) $($teile[2]) Zeile $($teile[1])"
        $sa = 0; $sb = 0
        if ($a.ContainsKey($ort)) { foreach ($n in $a[$ort].Values) { $sa += $n } }
        if ($b.ContainsKey($ort)) { foreach ($n in $b[$ort].Values) { $sb += $n } }
        if (-not $b.ContainsKey($ort)) { $diag.Add("fehlend: $wo, Anzahl $sa"); continue }
        if (-not $a.ContainsKey($ort)) { $diag.Add("zusätzlich: $wo, Anzahl $sb"); continue }
        $gleich = $true
        foreach ($w in (@($a[$ort].Keys) + @($b[$ort].Keys))) {
            $na = 0; $nb = 0
            if ($a[$ort].ContainsKey($w)) { $na = $a[$ort][$w] }
            if ($b[$ort].ContainsKey($w)) { $nb = $b[$ort][$w] }
            if ($na -ne $nb) { $gleich = $false; break }
        }
        if ($gleich) { continue }
        if ($sa -ne $sb) { $diag.Add("abweichende Häufigkeit: $wo, Soll $sa, Ist $sb") }
        else { $diag.Add("gleicher Fundort, abweichender Inhalt: $wo, Anzahl $sa") }
    }
    return $diag.ToArray()
}
$vgBasisZeilen = @("K1/a.txt|1|Nachpruefung-Benutzer|wertA", "K1/a.txt|1|Nachpruefung-Benutzer|wertA", "K1/a.txt|2|Nachpruefung-Geheimnis|wertB", "K2/b.txt|3|Nachpruefung-Hostname|wertC")
function New-VgListe { param([string[]]$Zeilen) $l = New-Object 'System.Collections.Generic.List[object]'; foreach ($z in $Zeilen) { $l.Add((ConvertTo-FundEintrag $z)) }; return ,$l }
$vgBasis = New-VgListe $vgBasisZeilen
$vgUmgekehrt = New-VgListe $vgBasisZeilen; $vgUmgekehrt.Reverse()
Assert-True (@(Compare-FundMultimenge $vgBasis $vgUmgekehrt).Count -eq 0) "Vergleich: gleiche Funde in anderer Reihenfolge bestehen"
$vgFehlt = @(Compare-FundMultimenge $vgBasis (New-VgListe $vgBasisZeilen[0..2]))
Assert-True ($vgFehlt.Count -eq 1 -and $vgFehlt[0].StartsWith("fehlend: K2/b.txt Nachpruefung-Hostname Zeile 3")) "Vergleich: fehlender Fund fällt durch ($($vgFehlt -join '; '))"
$vgExtra = @(Compare-FundMultimenge $vgBasis (New-VgListe ($vgBasisZeilen + @("K3/c.txt|4|Nachpruefung-SID|wertD"))))
Assert-True ($vgExtra.Count -eq 1 -and $vgExtra[0].StartsWith("zusätzlich: K3/c.txt Nachpruefung-SID Zeile 4")) "Vergleich: zusätzlicher Fund fällt durch ($($vgExtra -join '; '))"
$vgHaeufig = @(Compare-FundMultimenge $vgBasis (New-VgListe $vgBasisZeilen[1..3]))
Assert-True ($vgHaeufig.Count -eq 1 -and $vgHaeufig[0].StartsWith("abweichende Häufigkeit: K1/a.txt Nachpruefung-Benutzer Zeile 1, Soll 2, Ist 1")) "Vergleich: abweichende Häufigkeit fällt durch ($($vgHaeufig -join '; '))"
$vgGeaendert = New-VgListe $vgBasisZeilen; $vgGeaendert[2].fund = "wertX"
$vgInhalt = @(Compare-FundMultimenge $vgBasis $vgGeaendert)
Assert-True ($vgInhalt.Count -eq 1 -and $vgInhalt[0].StartsWith("gleicher Fundort, abweichender Inhalt: K1/a.txt Nachpruefung-Geheimnis Zeile 2")) "Vergleich: geänderter Fundwert am gleichen Fundort fällt durch ($($vgInhalt -join '; '))"
$vgGross = New-VgListe $vgBasisZeilen; $vgGross[3].fund = "WERTC"
Assert-True (@(Compare-FundMultimenge $vgBasis $vgGross).Count -eq 1) "Vergleich: Groß-/Kleinschreibung des Fundwerts zählt (ordinal)"
Assert-True (-not ((@($vgFehlt) + @($vgExtra) + @($vgHaeufig) + @($vgInhalt)) -join " ").ToLowerInvariant().Contains("wert")) "Vergleich: Diagnosen enthalten keine Fundwerte"

# ----------------------------------------------------------------------------
# 10. Leck-Katalog (tests\leck-katalog.json) und unabhängige Nachprüfung
# ----------------------------------------------------------------------------
Write-Host "=== 10. Leck-Katalog und unabhängige Nachprüfung ===" -ForegroundColor Cyan
$katalog = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $testDir "leck-katalog.json"), [System.Text.Encoding]::UTF8))
Assert-True (@($katalog.faelle).Count -ge 15) "Leck-Katalog: mindestens 15 Fälle ($(@($katalog.faelle).Count))"
$hatNachpruefung = $null -ne [AnonTool.AnonEngine].GetMethod("Nachpruefen")
Assert-True $hatNachpruefung "Nachprüfung: AnonEngine.Nachpruefen vorhanden"
$kCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
# Ein Fund deckt den Zielwert, wenn er ihm entspricht oder ihn als eigenen Teil enthält
# ('Alpha BetaSecret77', 'part1"SecretTail77', '-42.5e3'); eine andere Fundstelle genügt nicht
function Test-Deckt {
    param([string]$Fund, [string]$Wert)
    if ($Fund -ceq $Wert -or $Fund.Split("/")[0] -ceq $Wert) { return $true }
    foreach ($t in [regex]::Split($Fund, "[\s`"'``]+")) { if ($t -ceq $Wert -or ($t -replace '^[-+]', '') -ceq $Wert) { return $true } }
    return $false
}
# Lauf wie in anon.ps1: Durchlauf 1 lernt, Durchlauf 2 schreibt
function Invoke-KatalogLauf {
    param($Dateien, $State, $Cfg = $kCfg)
    foreach ($d in $Dateien) { [void][AnonTool.AnonEngine]::ProcessText([string]$d.text, $Cfg, $State) }
    $aus = New-Object 'System.Collections.Generic.List[string]'
    foreach ($d in $Dateien) { $aus.Add([AnonTool.AnonEngine]::ProcessText([string]$d.text, $Cfg, $State)) }
    return $aus.ToArray()
}
foreach ($k in $katalog.faelle) {
    $dateien = if ($null -ne $k.PSObject.Properties["dateien"]) { @($k.dateien) } else { @([pscustomobject]@{ path = "$($k.id).txt"; text = [string]$k.eingabe }) }
    $kState = New-Object AnonTool.AnonState
    # Fälle mit ipModus "schluessel" laufen im Schlüsselmodus, alle übrigen im alten Modus (Standard der Testkonfiguration)
    $lCfg = $kCfg
    if ($null -ne $k.PSObject.Properties["ipModus"] -and $k.ipModus -eq "schluessel") {
        $lCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
        $lCfg.IpModus = "schluessel"
        $lCfg.IpSchluessel = New-Object AnonTool.CryptoPan (,(ConvertFrom-TestHex $k.ipSchluesselHex))
    }
    $ausgabe = (Invoke-KatalogLauf -Dateien $dateien -State $kState -Cfg $lCfg) -join "`n"
    $tabelle = (@($kState.Forward.Keys) + @($kState.Forward.Values) + @($kState.Reverse.Keys) + @($kState.Reverse.Values) + @($kState.Aliases.Keys) + @($kState.Aliases.Values)) -join "`n"
    $rohFunde = @()
    if ($hatNachpruefung) { foreach ($d in $dateien) { $rohFunde += @([AnonTool.AnonEngine]::Nachpruefen([string]$d.text, [string]$d.path, $kCfg)) } }
    # IPs prüft die Nachprüfung nicht; auf der Roheingabe meldet sie der Prüfmodus
    $rohIp = @()
    foreach ($d in $dateien) { $rohIp += @([AnonTool.AnonEngine]::AuditText([string]$d.text, [string]$d.path, $kCfg, (New-Object AnonTool.AnonState))) }
    foreach ($z in $k.ziele) {
        $kurz = "$($k.id)/$($z.kategorie)"
        Assert-True (-not $ausgabe.Contains([string]$z.wert)) "${kurz}: Zielwert steht nicht in der Ausgabe"
        if ($z.art -eq "geheimnis") { Assert-True (-not $tabelle.Contains([string]$z.wert)) "${kurz}: Geheimnis steht nicht in der Zuordnungstabelle" }
        $soll = [string]$katalog.kategorien.($z.kategorie)
        $istIp = ($soll -eq "Rest-IPv4" -or $soll -eq "Rest-IPv6")
        $quelle = if ($istIp) { $rohIp } else { $rohFunde }
        $treffer = @($quelle | Where-Object { $_.Kategorie -eq $soll -and (Test-Deckt ([string]$_.Fund) ([string]$z.wert)) }).Count
        Assert-True ($treffer -gt 0) "${kurz}: $(if ($istIp) { 'Prüfmodus' } else { 'Nachprüfung' }) erkennt den Zielwert auf der Roheingabe als $soll"
    }
}
if ($hatNachpruefung) {
    $zeilenNach = New-Object 'System.Collections.Generic.List[string]'
    $quellen = New-Object 'System.Collections.Generic.List[object]'
    foreach ($k in $katalog.faelle) {
        $kd = if ($null -ne $k.PSObject.Properties["dateien"]) { @($k.dateien) } else { @([pscustomobject]@{ path = "$($k.id).txt"; text = [string]$k.eingabe }) }
        foreach ($d in $kd) { $quellen.Add(@("$($k.id)/$($d.path)", [string]$d.text)) }
    }
    foreach ($f in @(Get-ChildItem -LiteralPath $beispieleDir -File | Where-Object { -not $_.Name.StartsWith(".") } | Sort-Object { $_.Name } -Culture "")) {
        $quellen.Add(@("beispiele/$($f.Name)", [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)))
    }
    foreach ($q in $quellen) {
        foreach ($nf in [AnonTool.AnonEngine]::Nachpruefen([string]$q[1], [string]$q[0], $kCfg)) { $zeilenNach.Add("$($q[0])|$($nf.Zeile)|$($nf.Kategorie)|$($nf.Fund)") }
    }
    # Windows PowerShell 5.1 gibt ein JSON-Array aus ConvertFrom-Json als EIN Objekt aus (keine Aufzählung);
    # @(ConvertFrom-Json ...) ergäbe dort ein Element. Erst zuweisen, dann mit foreach aufzählen (5.1 und 7 gleich).
    $sollText = [System.IO.File]::ReadAllText((Join-Path $testDir "nachpruefung-erwartet.json"), [System.Text.Encoding]::UTF8)
    $sollNach = ConvertFrom-Json -InputObject $sollText
    $sollListe = New-Object 'System.Collections.Generic.List[object]'
    foreach ($e in $sollNach) { $sollListe.Add((ConvertTo-FundEintrag ([string]$e))) }
    # Unabhängige Gegenprobe: ein Eintrag je Zeile der Soll-Datei
    $sollZeilen = [regex]::Matches($sollText, '(?m)^  "').Count
    Assert-True ($sollListe.Count -eq $sollZeilen -and $sollZeilen -gt 0) "Parität: Soll-Datei vollständig geladen ($($sollListe.Count) von $sollZeilen Einträgen)"
    $istListe = New-Object 'System.Collections.Generic.List[object]'
    foreach ($e in $zeilenNach) { $istListe.Add((ConvertTo-FundEintrag $e)) }
    $diagNach = @(Compare-FundMultimenge $sollListe $istListe)
    foreach ($d in $diagNach) { Write-Host "    [Parität Nachprüfung] $d" -ForegroundColor Yellow }
    Assert-True ($diagNach.Count -eq 0) "Parität: Nachprüfung auf den Roheingaben entspricht tests\nachpruefung-erwartet.json (Soll $($sollListe.Count), Ist $($istListe.Count), Abweichungen $($diagNach.Count))"
}
$mState = New-Object AnonTool.AnonState
$mAus = Invoke-KatalogLauf -Dateien @([pscustomobject]@{ text = "show backup status`nbackup completed`n" }, [pscustomobject]@{ text = "user backup group operators`n" }) -State $mState
Assert-True ($mAus[0] -ceq "show backup status`nbackup completed`n" -and $mAus[1] -ceq "user USER-1 group operators`n") "A2-Folge 2: gelernter Benutzer 'backup' nur im Feldkontext ersetzt"
if ($hatNachpruefung) {
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $testDir "erwartet") -File)) {
        $nf = @([AnonTool.AnonEngine]::Nachpruefen([System.IO.File]::ReadAllText($f.FullName), $f.Name, $kCfg))
        Assert-True ($nf.Count -eq 0) "Nachprüfung: keine Fehlalarme in tests\erwartet\$($f.Name) ($(@($nf | ForEach-Object { $_.Kategorie + ':' + $_.Zeile }) -join ', '))"
    }
}

# Fix Spaltenerkennung: Tabelle endet an Befehlszeile, Trennlinie nach Daten oder Zeile außerhalb des Spaltenrasters
$sep = "-" * 110
$tabelleText = (@("show interface brief", $sep,
    "Port      Native  Mode   Type           Enabled Status  Reason                  Speed   Description",
    "          VLAN                                                                  (Mb/s)", $sep,
    "1/1/1     1       access 1GbT           yes     up                              1000    Uplink-Weber",
    "1/1/2     1       access 1GbT           yes     down    Waiting for link        --      --",
    "show logging",
    "2024-01-15T10:00:00.000+00:00 hpe-sshd[1234]: login failed for user bwagner from 198.51.100.4 port 22",
    "Build Date              : 2024-01-15 10:00:00 UTC                                      UTC",
    "show vlan", $sep,
    "VLAN  Name                              Status  Reason          Type      Interfaces                           Description", $sep,
    "1     DEFAULT_VLAN_1                    up      ok              default   1/1/1-1/1/2                          Standard", "") -join "`n")
$tNach = @([AnonTool.AnonEngine]::Nachpruefen($tabelleText, "t.txt", $kCfg) | Where-Object { $_.Kategorie -eq "Nachpruefung-Beschreibung" } | ForEach-Object { $_.Fund })
Assert-True (($tNach -join "|") -ceq "Uplink-Weber|Standard") "Fix 1: Nachprüfung meldet die Descriptions der Brief- und VLAN-Tabelle, nicht Log oder UTC ($($tNach -join ' | '))"
$tZeilen = [AnonTool.AnonEngine]::ProcessText($tabelleText, $kCfg, (New-Object AnonTool.AnonState)).Split("`n")
Assert-True ($tZeilen[5] -match "1000    TEXT-1$") "Fix 1: Description der Brief-Tabelle ersetzt"
Assert-True ($tZeilen[8] -cmatch "login failed for user USER-1 from NET-1\.H1 port 22$") "Fix 1: Benutzer und IP nach Benutzer-/IP-Regel, nicht als Spaltenwert ($($tZeilen[8]))"
Assert-True ($tZeilen[9] -ceq "Build Date              : 2024-01-15 10:00:00 UTC                                      UTC") "Fix 1: 'UTC' bleibt stehen"
Assert-True ($tZeilen[12] -cmatch "Interfaces {27}Description$" -and $tZeilen[14] -cmatch "1/1/1-1/1/2 {26}TEXT-[0-9]+$" -and $tZeilen[14].Contains("DEFAULT_VLAN_1")) "Fix 1: VLAN-Kopfzeile bleibt, Standardname bleibt, VLAN-Description ersetzt"
$tTab = [AnonTool.AnonEngine]::ProcessText("Port`tNative`tDescription`n1/1/1`t1`tUplink-Weber`nshow logging ohne Tabulator`n1/1/2`t1`tLog-Zeile`n", $kCfg, (New-Object AnonTool.AnonState))
Assert-True (-not $tTab.Contains("Uplink-Weber") -and $tTab.Contains("Log-Zeile")) "Fix 1: tabulatorgetrennte Tabelle endet an einer Zeile ohne Tabulator"
$tTrenn = [AnonTool.AnonEngine]::ProcessText((@("Port      Native  Type   Description", $sep, "1/1/1     1       1GbT   Uplink-Weber", $sep, "1/1/9     1       1GbT   Nach-Trennlinie", "") -join "`n"), $kCfg, (New-Object AnonTool.AnonState))
Assert-True (-not $tTrenn.Contains("Uplink-Weber") -and -not $tTrenn.Contains("Nach-Trennlinie")) "Fail-safe: Trennlinie nach Datenzeilen beendet die Tabelle nicht"
# Zeile außerhalb des Rasters ohne Ankerfeld: trotzdem ersetzt und zusätzlich als Fund gemeldet
$unsicherText = (@($sep, "Port      Native  Mode   Type           Enabled Status  Reason                  Speed   Description", $sep,
    "1/1/1     1       access 1GbT           yes     up                              1000    Uplink-Weber",
    "1/1/7     1       access 1GbT           yes     down    Link flap detected (err-disabled) Kiosk Wagner",
    "1/1/8     1       access 1GbT           yes     up                              1000    Telefon Wolf", "") -join "`n")
$uState = New-Object AnonTool.AnonState
$uAus = [AnonTool.AnonEngine]::ProcessText($unsicherText, $kCfg, $uState)
Assert-True (-not $uAus.Contains("Wagner") -and -not $uAus.Contains("Wolf") -and -not $uAus.Contains("Uplink-Weber")) "Fail-safe: Zeile außerhalb des Rasters wird ersetzt, Tabelle läuft weiter"
$uFunde = @([AnonTool.AnonEngine]::AuditTextDetail($uAus, "u.txt", $kCfg, $uState, [int[]]$uState.UnsichereTabellenzeilen.ToArray()).Funde | Where-Object { $_.Kategorie -eq "Rest-Tabellenzeile" })
Assert-True ($uFunde.Count -eq 1 -and $uFunde[0].Zeile -eq 5) "Fail-safe: nicht eindeutige Zeile wird als Fund gemeldet ($($uFunde.Count))"
Assert-Equal ([AnonTool.AnonEngine]::FreigabeKategorie("Rest-Tabellenzeile", "x", $null)) "Tabellenfeld" "Fail-safe: nicht eindeutige Zeile ist nach Prüfung freigebbar"
$nUnsicher = @([AnonTool.AnonEngine]::Nachpruefen($unsicherText, "u.txt", $kCfg) | Where-Object { $_.Kategorie -eq "Nachpruefung-Beschreibung" } | ForEach-Object { $_.Fund })
Assert-True (($nUnsicher -join "|") -ceq "Uplink-Weber|Kiosk Wagner|Telefon Wolf") "Nachprüfung: Freitext in der letzten Spalte jeder Zeile ($($nUnsicher -join ' | '))"
$vText = "VLAN Name                             Status    Ports`n---- -------------------------------- --------- ------`n1    default                          active    Gi0/1`n10   VLAN0010                         active    Gi0/3`n1002 fddi-default                     act/unsup`n"
Assert-True ([AnonTool.AnonEngine]::ProcessText($vText, $kCfg, (New-Object AnonTool.AnonState)) -ceq $vText -and @([AnonTool.AnonEngine]::Nachpruefen($vText, "v.txt", $kCfg)).Count -eq 0) "show vlan: Standardnamen (default, VLAN0010, fddi-default) bleiben, kein Fund"
$tPrompt = @([AnonTool.AnonEngine]::Nachpruefen((@("Port      Native  Type   Description", "1/1/1     1       1GbT   Uplink-Weber", "<brw-core07>display current-configuration", "sw-x1# show clock     10:00:00 Description-Spalte", "") -join "`n"), "p.txt", $kCfg) | Where-Object { $_.Kategorie -eq "Nachpruefung-Beschreibung" } | ForEach-Object { $_.Fund })
Assert-True ($tPrompt.Count -eq 1 -and $tPrompt[0] -ceq "Uplink-Weber") "Fix 1: Prompt-Zeilen (<name>, name#) beenden die Tabelle ($($tPrompt -join ' | '))"
# Fix Namensspalten: nur die Namensspalte ersetzen, übrige Spalten bleiben unverändert
$katText = @{}
foreach ($kf in $katalog.faelle) { if ($null -ne $kf.PSObject.Properties["eingabe"]) { $katText[[string]$kf.id] = [string]$kf.eingabe } }
function Get-KatAus([string]$Id) { return [AnonTool.AnonEngine]::ProcessText($katText[$Id], $kCfg, (New-Object AnonTool.AnonState)).Split("`n") }
$c = Get-KatAus "K26"; $ce = $katText["K26"].Split("`n")
Assert-True ($c[1].EndsWith("connected    10         a-full  a-1000 10/100/1000BaseTX") -and -not $c[1].Contains("Becker") -and $c[1].Length -eq $ce[1].Length) "Namensspalten: Cisco Name ersetzt, Status bis Type unverändert ($($c[1]))"
Assert-True ($c[2].EndsWith(" notconnect 20        auto    auto 10/100/1000BaseTX") -and -not $c[2].Contains("Hoffmann")) "Namensspalten: überlanger Name ersetzt, Rest bleibt ($($c[2]))"
Assert-True ($c[3] -ceq $ce[3]) "Namensspalten: leerer Name bleibt leer"
$n = Get-KatAus "K27"
Assert-True ($n[4] -cmatch "^  1     TEXT-[0-9]+$" -and $n[5] -cmatch "^  2     TEXT-[0-9]+$" -and $n[6] -ceq "  3") "Namensspalten: ArubaOS-Switch show name ersetzt"
$pr = Get-KatAus "K28"
Assert-True ($pr[0] -cmatch "^admin@HOST-[0-9]+> show version$" -and $pr[1] -cmatch "^admin@HOST-[0-9]+# show clock$") "Namensspalten: Prompt user@host ($($pr -join ' | '))"
$d = Get-KatAus "K29"; $de = $katText["K29"].Split("`n")
Assert-True ($d[1].EndsWith("Gig 1/0/1         150             R S I  C9300-48P Gig 1/0/48") -and $d[1] -cmatch "^HOST-[0-9]+ " -and $d[3] -ceq $de[3]) "Namensspalten: CDP nur Device ID ersetzt, Local Intrfce bleibt ($($d[1]) | $($d[3]))"
Assert-True (-not $d[2].Contains("brw-core12")) "Namensspalten: umbrochene Device ID ersetzt"
$nAlle = @([AnonTool.AnonEngine]::Nachpruefen("ID  Desc             Status`n1   Lager-Engel      up`n2   --               down`n`nIdx Alias        Port-Name      Speed`n1   Halle-Ost    Tor-Seidel     1000`n", "n.txt", $kCfg) | Where-Object { $_.Kategorie -eq "Nachpruefung-Beschreibung" } | ForEach-Object { $_.Fund })
Assert-True (($nAlle -join "|") -ceq "Lager-Engel|Halle-Ost|Tor-Seidel") "Nachprüfung: Spalten Name/Desc/Alias/Port-Name in beliebiger Position ($($nAlle -join ' | '))"
# Fix Praxistest 2: Befehls- und Logzeilen ohne Wert sind kein sicheres Geheimnis; Zeitstempel, Versionen und Kopfzeilen sind keine Benutzer
$pt = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $testDir "praxistest2.json"), [System.Text.Encoding]::UTF8))
function Invoke-PtLauf([string]$Text) {
    $st = New-Object AnonTool.AnonState
    [void][AnonTool.AnonEngine]::ProcessText($Text, $kCfg, $st)
    $aus = [AnonTool.AnonEngine]::ProcessText($Text, $kCfg, $st)
    return [pscustomobject]@{ Aus = $aus; Funde = @([AnonTool.AnonEngine]::AuditTextDetail($aus, "p.txt", $kCfg, $st, [int[]]$st.UnsichereTabellenzeilen.ToArray()).Funde) }
}
$geheimKat = @("Rest-Geheimnis", "Nachpruefung-Geheimnis", "Verdacht-Zugangsdaten", "Verdacht-Teilmaskierung", "Nachpruefung-Teilmaskierung", "Verdacht-Hash", "Verdacht-Geheimnis-Blob")
$bLauf = Invoke-PtLauf ((@($pt.befehle) -join "`n") + "`n")
$bSicher = @($bLauf.Funde | Where-Object { $geheimKat -contains $_.Kategorie -and $null -eq [AnonTool.AnonEngine]::FreigabeKategorie($_.Kategorie, $_.Fund, $null) })
Assert-True ($bSicher.Count -eq 0) "Praxistest 2: 30 Befehlszeilen ohne Wert ergeben keinen sicheren Fund ($(@($bSicher | ForEach-Object { $_.Fund }) -join ' | '))"
$aaa = @($bLauf.Funde | Where-Object { $_.Kontext -match "^(?:no )?aaa " })
Assert-True ($aaa.Count -eq 0) "Praxistest 2: AAA-Befehlszeilen sind kein Fund"
$lLauf = Invoke-PtLauf ((@($pt.logzeilen) -join "`n") + "`n")
Assert-True ($lLauf.Funde.Count -eq 0) "Praxistest 2: 15 Logzeilen ohne Wert ergeben keinen Fund ($(@($lLauf.Funde | ForEach-Object { $_.Kategorie + ':' + $_.Zeile }) -join ','))"
Assert-True ($null -eq [AnonTool.AnonEngine]::FreigabeKategorie("Verdacht-Zugangsdaten", "password Abc12345", $null) -and [AnonTool.AnonEngine]::FreigabeKategorie("Verdacht-Zugangsdaten", "password allow-fail-through", $null) -eq "Verdacht") "Praxistest 2: sicher nur mit Schlüsselwort und typischem Wert"
$cp = "Checkpoint name  Type     Writer  Date(YYYY/MM/DD)       Image Version`n---------------  -------  ------  ---------------------  -------------`nstartup-config   startup  User    2026-07-02T18:42:25Z   GL.10.13.1020`nckpt-20260702    latest   User    2026/07/02 18:42:25    GL.10.13.1020`n"
$cpLauf = Invoke-PtLauf $cp
Assert-True ($cpLauf.Aus -ceq $cp -and $cpLauf.Funde.Count -eq 0) "Praxistest 2: Zeitstempel und Firmware-Versionen sind kein Benutzername ($(@($cpLauf.Funde | ForEach-Object { $_.Kategorie + ':' + $_.Fund }) -join ' | '))"
$kopfText = "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND`n 1234 root      20   0  123456  12345   1234 S   0.0   0.1   0:00.12 hpe-restd`nUSER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND`nroot         1  0.0  0.1 167000 11000 ?        Ss   10:00   0:01 /sbin/init`n    Line       User       Host(s)              Idle       Location`n"
$kLauf = Invoke-PtLauf $kopfText
Assert-True ($kLauf.Funde.Count -eq 0 -and $kLauf.Aus -ceq $kopfText) "Praxistest 2: Kopfzeilen (top, ps, show users) liefern keinen Benutzernamen ($(@($kLauf.Funde | ForEach-Object { $_.Kategorie + ':' + $_.Fund }) -join ' | '))"
$ssh = [string](@($katalog.faelle | Where-Object { $_.id -eq "K30" })[0].eingabe)
$sState = New-Object AnonTool.AnonState
$sAus = [AnonTool.AnonEngine]::ProcessText($ssh, $kCfg, $sState)
Assert-True ($sAus -cmatch "(?m)^user admin authorized-key SSHKEY-1$" -and $sAus -cmatch "(?m)^SSHKEY-2$") "Praxistest 2: SSH Public Keys werden SSHKEY-n"
Assert-Equal ([AnonTool.AnonEngine]::DeanonymizeText($sAus, $sState.Reverse)) $ssh "Praxistest 2: SSH Public Keys über die Tabelle rückübersetzbar"
Assert-True (@([AnonTool.AnonEngine]::Nachpruefen($sAus, "s.txt", $kCfg)).Count -eq 0) "Praxistest 2: SSHKEY-n ist kein Restfund"
# Fix Geheimnis-Typwörter und USER-Spalte
$twAus = (Get-KatAus "K32")
Assert-True ($twAus[0].EndsWith("key cleartext *****") -and $twAus[1] -ceq "pre-shared-key ascii-text *****" -and $twAus[2] -cmatch "crypto isakmp key 0 \*{5} address" -and $twAus[5].EndsWith('pre-shared-key ascii-text "*****"')) "Typwörter: Typwort bleibt, Wert wird maskiert ($(($twAus[0..5]) -join ' | '))"
$twLauf = Invoke-PtLauf $katText["K32"]
$twGeheim = @($twLauf.Funde | Where-Object { $_.Kategorie -match "Geheimnis|Verdacht|Teilmaskierung" })
Assert-True ($twGeheim.Count -eq 0) "Typwörter: Prüfung der Ausgabe ohne Geheimnis-Funde ($(@($twGeheim | ForEach-Object { $_.Kategorie + ':' + $_.Zeile }) -join ','))"
$ohneWert = "password complexity`nno password-recovery`npassword minimum-length 8`nservice password-encryption`n"
Assert-True ([AnonTool.AnonEngine]::ProcessText($ohneWert, $kCfg, (New-Object AnonTool.AnonState)) -ceq $ohneWert) "Typwörter: Befehlszeilen ohne Wert bleiben unverändert"
$twNach = @([AnonTool.AnonEngine]::Nachpruefen((($twAus -join "`n") + "`nkey cleartext *****`npassword ciphertext *****`nwpa-psk hex *****`n"), "t.txt", $kCfg))
Assert-True ($twNach.Count -eq 0) "Typwörter: Typwörter und maskierte Werte sind kein Fund ($(@($twNach | ForEach-Object { $_.Kategorie + ':' + $_.Fund }) -join ' | '))"
$twRoh = @([AnonTool.AnonEngine]::Nachpruefen("tacacs-server host 192.0.2.6 key cleartext tacgeheim`npassword ciphertext AQBapXyZ12`n", "t.txt", $kCfg) | ForEach-Object { $_.Fund })
Assert-True (($twRoh -join "|") -ceq "tacgeheim|AQBapXyZ12") "Typwörter: Nachprüfung meldet Wert nach Typwort, nicht das Typwort ($($twRoh -join ' | '))"
$usAus = [AnonTool.AnonEngine]::ProcessText($katText["K33"], $kCfg, (New-Object AnonTool.AnonState))
Assert-True ($usAus -cmatch "(?m)^ 1234 root " -and $usAus -cmatch "(?m)^www-data    5432" -and $usAus -cmatch "(?m)^  987 messageb\+ " -and $usAus -cmatch "(?m)^systemd\+     321") "USER-Spalte: Systemkonten bleiben"
Assert-True ($usAus -cmatch "(?m)^ 2345 USER-[0-9]+ " -and $usAus -cmatch "(?m)^USER-[0-9]+ +4321" -and $usAus -cmatch "(?m)^\*  2 vty 0     USER-[0-9]+ ") "USER-Spalte: Benutzer in Datenzeilen ersetzt"
Assert-True ($usAus -cmatch "(?m)^  PID USER      PR" -and $usAus -cmatch "(?m)^    Line       User       Host\(s\)") "USER-Spalte: Kopfzeilen bleiben unverändert"
# Fix 2: eigene Platzhalter (auch mit Satzzeichen) sind kein Restfund der Nachprüfung
$pFunde = @([AnonTool.AnonEngine]::Nachpruefen("description (HOST-1), TEXT-2;`n Port Description : [USER-1]`nhostname HOST-1.`nuser USER-3,`nPort      Native  Type   Description`n1/1/1     1       1GbT   TEXT-1 (FIRMA-1)`n", "p.txt", $kCfg))
Assert-True ($pFunde.Count -eq 0) "Fix 2: Nachprüfung meldet keine eigenen Platzhalter ($(@($pFunde | ForEach-Object { $_.Kategorie + ':' + $_.Fund }) -join ' | '))"
$pText = "description Uplink zu (HOST-1), siehe TEXT-2;`n Port Description : [USER-1]`nhostname HOST-1.`nuser USER-3,`nPort      Native  Type   Description`n1/1/1     1       1GbT   TEXT-1 (FIRMA-1)`n"
Assert-True (@([AnonTool.AnonEngine]::Nachpruefen($pText, "p.txt", $kCfg)).Count -eq 1) "Fix 2: echter Freitext neben Platzhaltern wird weiter gemeldet"

# ----------------------------------------------------------------------------
# 11. Kategoriegebundene Freigaben (ausnahmen.freigegeben)
# ----------------------------------------------------------------------------
Write-Host "=== 11. Kategoriegebundene Freigaben (ausnahmen.freigegeben) ===" -ForegroundColor Cyan
$frText = "<Data Name=`"TargetUserName`">jdoe7</Data>`nhostname jdoe7`n"
$hatDetail = $null -ne [AnonTool.AnonEngine].GetMethod("AuditTextDetail", [Type[]]@([string], [string], [AnonTool.EngineConfig], [AnonTool.AnonState]))
Assert-True $hatDetail "Freigaben: AnonEngine.AuditTextDetail vorhanden"
if ($hatDetail) {
    $frCfg = New-TestConfig -RulesObj $rulesObj
    $ohne = [AnonTool.AnonEngine]::AuditTextDetail($frText, "f.txt", $frCfg, $null)
    $frCfg.Freigegeben.Add("Benutzer" + [char]0 + "jdoe7") | Out-Null
    $mit = [AnonTool.AnonEngine]::AuditTextDetail($frText, "f.txt", $frCfg, $null)
    $ohneBenutzer = @($ohne.Funde | Where-Object { $_.Kategorie -like "*Benutzer*" }).Count
    Assert-True ($ohneBenutzer -gt 0 -and $ohne.Freigegeben -eq 0) "Freigaben: ohne Freigabe wird der Benutzer gemeldet"
    Assert-True (@($mit.Funde | Where-Object { $_.Kategorie -like "*Benutzer*" }).Count -eq 0) "Freigaben: freigegebener Benutzer wird in Kategorie Benutzer nicht gemeldet"
    Assert-True (@($mit.Funde | Where-Object { $_.Kategorie -like "*Hostname*" }).Count -gt 0) "Freigaben: derselbe Wert als Hostname wird weiter gemeldet"
    Assert-True ($mit.Freigegeben -eq $ohneBenutzer) "Freigaben: bewusst freigegebene Funde werden gezählt ($($mit.Freigegeben))"
    Assert-True (@([AnonTool.AnonEngine]::AuditText($frText, "f.txt", $frCfg, $null)).Count -eq $mit.Funde.Count) "Freigaben: AuditText liefert dieselben Funde wie AuditTextDetail"
    $grossCfg = New-TestConfig -RulesObj $rulesObj
    $grossCfg.Freigegeben.Add("Benutzer" + [char]0 + "JDOE7") | Out-Null
    Assert-True ([AnonTool.AnonEngine]::AuditTextDetail($frText, "f.txt", $grossCfg, $null).Freigegeben -eq 0) "Freigaben: Wert wird exakt verglichen (Groß-/Kleinschreibung zählt)"
    $gCfg = New-TestConfig -RulesObj $rulesObj
    $gCfg.Freigegeben.Add("Geheimnis" + [char]0 + "Geheim77x") | Out-Null
    $g = [AnonTool.AnonEngine]::AuditTextDetail("password Geheim77x`n", "f.txt", $gCfg, $null)
    Assert-True ($g.Freigegeben -eq 0 -and $g.Funde.Count -gt 0) "Freigaben: Geheimnisse sind nicht freigebbar"
    # Verdachtsfunde (Heuristik ohne eindeutiges Schlüsselwort) sind als "Verdacht" freigebbar, sicher erkannte Geheimnisse nicht
    $blob = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
    $blobText = "ArubaOS-CX build id $blob`n"
    $vOhne = [AnonTool.AnonEngine]::AuditTextDetail($blobText, "b.txt", (New-TestConfig -RulesObj $rulesObj), $null)
    Assert-True (@($vOhne.Funde | Where-Object { $_.Kategorie -eq "Verdacht-Geheimnis-Blob" }).Count -gt 0) "Verdacht: Build-ID wird als Verdacht-Geheimnis-Blob gemeldet"
    $vCfg = New-TestConfig -RulesObj $rulesObj
    $vCfg.Freigegeben.Add("Verdacht" + [char]0 + $blob) | Out-Null
    $vMit = [AnonTool.AnonEngine]::AuditTextDetail($blobText, "b.txt", $vCfg, $null)
    Assert-True ($vMit.Funde.Count -eq 0 -and $vMit.Freigegeben -eq 1) "Verdacht: freigegebene Build-ID ist kein Restfund und wird gezählt ($($vMit.Funde.Count)/$($vMit.Freigegeben))"
    foreach ($kw in @(@("Rest-Geheimnis", "password Abc12345"), @("Verdacht-Zugangsdaten", "password Abc12345"), @("Verdacht-Zugangsdaten", "secret Abc12345"), @("Verdacht-Hash", '$6$abcdefghij$klmnopqrstuv'), @("Verdacht-Teilmaskierung", "*****x"))) {
        Assert-True ($null -eq [AnonTool.AnonEngine]::FreigabeKategorie($kw[0], $kw[1], $null)) "Sicher erkanntes Geheimnis $($kw[0]) ist nicht freigebbar"
    }
    foreach ($kw in @(@("Verdacht-Geheimnis-Blob", $blob), @("Verdacht-Zugangsdaten", "token Abc12345"), @("Verdacht-Zugangsdaten", "pwd Abc12345"), @("Nachpruefung-Geheimnis", "Abc12345"), @("Nachpruefung-Teilmaskierung", "ab*****"))) {
        Assert-Equal ([AnonTool.AnonEngine]::FreigabeKategorie($kw[0], $kw[1], $null)) "Verdacht" "Verdachtsfund $($kw[0]) ist als Verdacht freigebbar"
    }
    Assert-Equal ([AnonTool.AnonEngine]::FreigabeKategorie("Nachpruefung-SID", "S-1-5-21-1-2-3-500", $null)) "SID" "Nachprüfung SID ist freigebbar (Kategorie SID)"
    Assert-Equal ([AnonTool.AnonEngine]::FreigabeKategorie("Nachpruefung-Beschreibung", "Uplink-Weber", $null)) "Freitext" "Nachprüfung Beschreibung ist als Freitext freigebbar"
}
# Ungültige Freigaben in anon-regeln.lokal.json brechen ab, Meldung ohne Werte
$frDir = Join-Path $tempRunRoot "freigabe"
New-Item -ItemType Directory -Path $frDir -Force | Out-Null
$frEin = Join-Path $frDir "ein.txt"
[System.IO.File]::WriteAllText($frEin, "<Data Name=`"TargetUserName`">jdoe7</Data>`n", (New-Object System.Text.UTF8Encoding($false)))
$frLok = Join-Path $frDir "ungueltig.lokal.json"
[System.IO.File]::WriteAllText($frLok, '{ "ausnahmen": { "freigegeben": [ { "kategorie": "Geheimnis", "wert": "x1geheim" } ] } }', (New-Object System.Text.UTF8Encoding($false)))
$frMeldung = ""
try { & $anonScript -Eingabe $frEin -Ausgabe (Join-Path $frDir "aus-u") -Regeln $rulesPath -LokaleRegeln $frLok -TabellenPfad (Join-Path $frDir "tab-u.json") -Unverschluesselt *> $null } catch { $frMeldung = $_.Exception.Message }
Assert-True ($frMeldung -like "*Freigabe*" -and -not $frMeldung.Contains("x1geheim")) "Freigaben: ungültige Freigabe in anon-regeln.lokal.json bricht ab, Meldung ohne Wert ($frMeldung)"
$frLok2 = Join-Path $frDir "benutzer.lokal.json"
[System.IO.File]::WriteAllText($frLok2, '{ "ausnahmen": { "freigegeben": [ { "kategorie": "Benutzer", "wert": "jdoe7" } ] } }', (New-Object System.Text.UTF8Encoding($false)))
& $anonScript -Eingabe $frEin -Ausgabe (Join-Path $frDir "aus-b") -Regeln $rulesPath -LokaleRegeln $frLok2 -TabellenPfad (Join-Path $frDir "tab-b.json") -Unverschluesselt *> $null
$frCode = $LASTEXITCODE
$frBericht = $null
$frBerichtPfad = Join-Path (Join-Path $frDir "aus-b") "bericht.json"
if (Test-Path -LiteralPath $frBerichtPfad) { $frBericht = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($frBerichtPfad, [System.Text.Encoding]::UTF8)) }
Assert-True ($frCode -eq 0 -and $null -ne $frBericht -and [int]$frBericht.bewusstFreigegeben -ge 1) "Freigaben: anon.ps1 ohne Restfunde, Bericht zählt bewusstFreigegeben ($frCode)"

# Entscheidung "Alle ersetzen" bei Geheimnissen erzeugt ein Muster im Dialekt der Regeldatei (gleich wie anonymisierer.html)
$litCfg = New-TestConfig -RulesObj $rulesObj
$litRule = New-Object AnonTool.SecretRule
$litRule.Name = "Entscheidung: Geheimnis entfernen"
$litRule.Pattern = "(?<![A-Za-z0-9])Geheim9z(?![A-Za-z0-9])"
$litRule.Replacement = "*****"
$litRule.Compiled = New-Object System.Text.RegularExpressions.Regex ($litRule.Pattern, [System.Text.RegularExpressions.RegexOptions]::Compiled, [TimeSpan]::FromSeconds(5))
$litCfg.GeheimnisMuster.Add($litRule)
Assert-Equal ([AnonTool.AnonEngine]::ProcessText("note Geheim9z here`n", $litCfg, (New-Object AnonTool.AnonState))) "note ***** here`n" "Entscheidung 'Alle ersetzen' bei Geheimnis: Wert wird zu ***** (Parität)"

Write-Host "=== IP-Modell: Crypto-PAn-Kern und Testvektoren ===" -ForegroundColor Cyan
$ipVek = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $testDir "ip-testvektoren.json"), [System.Text.Encoding]::UTF8))
$ipKernDa = $null -ne ("AnonTool.CryptoPan" -as [type])
Assert-True $ipKernDa "IP-Modell: C#-Klasse AnonTool.CryptoPan vorhanden"
if ($ipKernDa) {
    foreach ($a in $ipVek.aes128) {
        $ct = [AnonTool.CryptoPan]::Aes128Block((ConvertFrom-TestHex $a.schluesselHex), (ConvertFrom-TestHex $a.klartextHex))
        Assert-Equal (ConvertTo-TestHex $ct) $a.geheimtextHex "IP-Modell: AES-128 $($a.quelle)"
    }
    $ipPaare = 0; $ipOk = 0; $ipRueck = 0
    foreach ($v in $ipVek.cryptoPanStandard) {
        $kb = if ($v.PSObject.Properties["schluesselHex"]) { ConvertFrom-TestHex $v.schluesselHex } else { [System.Text.Encoding]::UTF8.GetBytes($v.schluesselText) }
        $ks = New-Object AnonTool.CryptoPan (,$kb)
        foreach ($pr in $v.paare) {
            $ipPaare++
            $r = ConvertTo-TestIp4 ($ks.Standard((ConvertFrom-TestIp4 $pr[0]), $false))
            if ($r -eq $pr[1]) { $ipOk++ } else { Write-Host "    Crypto-PAn $($pr[0]): erwartet $($pr[1]), erhalten $r" -ForegroundColor Yellow }
            if ((ConvertTo-TestIp4 ($ks.Standard((ConvertFrom-TestIp4 $pr[1]), $true))) -eq $pr[0]) { $ipRueck++ }
        }
    }
    Assert-True ($ipPaare -ge 25 -and $ipOk -eq $ipPaare) "IP-Modell: Crypto-PAn-Testvektoren gleich JS ($ipOk von $ipPaare)"
    Assert-True ($ipRueck -eq $ipPaare) "IP-Modell: Umkehrung liefert bei allen Vektoren das Original ($ipRueck von $ipPaare)"
}

Write-Host "=== IP-Modell: Adressklassen und IPv6 ===" -ForegroundColor Cyan
if ($ipKernDa) {
    $ks6 = New-Object AnonTool.CryptoPan (,(ConvertFrom-TestHex $ipVek.cryptoPanStandard6[0].schluesselHex))
    $v6ok = 0; $v6n = 0
    foreach ($pr in $ipVek.cryptoPanStandard6[0].paare) {
        $v6n++
        $r = $ks6.Standard([AnonTool.CryptoPan]::Ip6Lesen($pr[0]), $false)
        if ((ConvertTo-TestHex $r) -eq (ConvertTo-TestHex ([AnonTool.CryptoPan]::Ip6Lesen($pr[1]))) -and [AnonTool.CryptoPan]::Ip6Text($ks6.Standard($r, $true)) -eq [AnonTool.CryptoPan]::Ip6Text([AnonTool.CryptoPan]::Ip6Lesen($pr[0]))) { $v6ok++ }
    }
    Assert-True ($v6n -ge 4 -and $v6ok -eq $v6n) "IP-Modell: Crypto-PAn IPv6-Testvektoren hin und zurück ($v6ok von $v6n)"
    $kok = 0; $kn = 0
    foreach ($v in $ipVek.klassen) {
        $kk = New-Object AnonTool.CryptoPan (,(ConvertFrom-TestHex $v.schluesselHex))
        foreach ($pr in $v.paare) {
            $kn++
            $praef = if ($null -eq $pr[1]) { -1 } else { [int]$pr[1] }
            $r = $kk.TextVerfremden([string]$pr[0], $praef, $false)
            if ($r -ceq $pr[2]) { $kok++ } else { Write-Host "    Klassen $($pr[0])/$($pr[1]): erwartet $($pr[2]), erhalten $r" -ForegroundColor Yellow }
        }
    }
    Assert-True ($kn -ge 30 -and $kok -eq $kn) "IP-Modell: Klassen-Testvektoren gleich JS ($kok von $kn)"
    # Prüfsumme über öffentliche Adressen aus derselben Zahlenfolge wie in run-tests.js
    $pk = New-Object AnonTool.CryptoPan (,(ConvertFrom-TestHex $ipVek.pruefsummeOeffentlich.schluesselHex))
    $pAus = New-Object System.Collections.Generic.List[string]
    $pl = 0
    for ([long]$i = 1; $pAus.Count -lt [int]$ipVek.pruefsummeOeffentlich.anzahl; $i++) {
        [long]$z = ($i * 2654435761) % 4294967296
        $b = [byte[]]@((($z -shr 24) -band 255), (($z -shr 16) -band 255), (($z -shr 8) -band 255), ($z -band 255))
        if ([AnonTool.CryptoPan]::Klasse($b, [ref]$pl) -ne "oeffentlich") { continue }
        $pAus.Add([AnonTool.CryptoPan]::Ip4Text($pk.Verfremden($b, $false)))
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $pHash = ConvertTo-TestHex ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($pAus -join "`n"))))
    Assert-Equal $pHash $ipVek.pruefsummeOeffentlich.sha256 "IP-Modell: Prüfsumme über $($pAus.Count) öffentliche Adressen gleich JS"
    $fest = @("0.0.0.0", "255.255.255.255", "127.0.0.1", "224.0.0.5", "240.0.0.1", "0.0.0.15", "255.255.255.0", "::", "::1", "ff02::1")
    $festOk = @($fest | Where-Object { $pk.TextVerfremden($_, -1, $false) -ceq $_ }).Count
    Assert-Equal $festOk $fest.Count "IP-Modell: Sonderadressen, Masken und Wildcards unverändert"
    $r230 = $pk.TextVerfremden("172.22.0.230", -1, $false)
    $o230 = [AnonTool.CryptoPan]::Ip4Lesen($r230)
    Assert-True ($o230[0] -eq 172 -and $o230[1] -ge 16 -and $o230[1] -le 31 -and $o230[3] -eq 230) "IP-Modell: 172.22.0.230 bleibt in 172.16.0.0/12 mit Host .230 ($r230)"
    # Zufallstest: öffentlich nie in einem Sonderbereich, Umkehrung stimmt
    $rng = New-Object System.Random 4711
    $zk = New-Object byte[] 32; $rng.NextBytes($zk)
    $zks = New-Object AnonTool.CryptoPan (,$zk)
    $oeff = 0; $oeffFehler = 0; $kl = 0; $klo = 0
    while ($oeff -lt 3000) {
        $b = New-Object byte[] 4; $rng.NextBytes($b)
        if ([AnonTool.CryptoPan]::Klasse($b, [ref]$kl) -ne "oeffentlich") { continue }
        $oeff++
        $o = $zks.Verfremden($b, $false)
        if ([AnonTool.CryptoPan]::Klasse($o, [ref]$klo) -ne "oeffentlich" -or $o[3] -ne $b[3] -or (ConvertTo-TestHex ($zks.Verfremden($o, $true))) -ne (ConvertTo-TestHex $b)) { $oeffFehler++ }
    }
    Assert-Equal $oeffFehler 0 "IP-Modell: Zufallstest 3000 öffentliche IPv4 nie in einem Sonderbereich, umkehrbar"
    Assert-True ($pk.TextVerfremden("2001:db8:0:0:0:0:0:1", -1, $false) -ceq $pk.TextVerfremden("2001:DB8::1", -1, $false)) "IP-Modell: IPv6 Kurz- und Langform gleich"
}

Write-Host "=== IP-Modell: Engine (Schlüsselmodus) und Prüfung ===" -ForegroundColor Cyan
if ($ipKernDa) {
    $eCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
    $eCfg.IpModus = "schluessel"
    Assert-Throws { [void][AnonTool.AnonEngine]::ProcessText("ntp server 192.0.2.10`n", $eCfg, (New-Object AnonTool.AnonState)) } "IP-Modell: Schlüsselmodus ohne Schlüssel wird abgelehnt"
    $eCfg.IpSchluessel = New-Object AnonTool.CryptoPan (,(ConvertFrom-TestHex $ipVek.engine.schluesselHex))
    $eState = New-Object AnonTool.AnonState
    [void][AnonTool.AnonEngine]::ProcessText([string]$ipVek.engine.eingabe, $eCfg, $eState)
    $eAus = [AnonTool.AnonEngine]::ProcessText([string]$ipVek.engine.eingabe, $eCfg, $eState)
    if ($eAus -cne [string]$ipVek.engine.ausgabe) {
        $ea = $eAus.Split("`n"); $es = ([string]$ipVek.engine.ausgabe).Split("`n")
        for ($i = 0; $i -lt [Math]::Min($ea.Length, $es.Length); $i++) { if ($ea[$i] -cne $es[$i]) { Write-Host "    Zeile $($i + 1): erwartet '$($es[$i])', erhalten '$($ea[$i])'" -ForegroundColor Yellow } }
    }
    Assert-True ($eAus -ceq [string]$ipVek.engine.ausgabe) "IP-Modell: Parität A == B, Engine-Ausgabe im Schlüsselmodus gleich JS"
    $eA = $eCfg.IpSchluessel.TextVerfremden("172.22.0.230", -1, $false)
    $eN = $eCfg.IpSchluessel.TextVerfremden("10.0.0.0", 23, $false)
    Assert-True ($eState.Reverse.ContainsKey($eA) -and $eState.Reverse[$eA] -eq "172.22.0.230" -and $eState.Reverse[$eN] -eq "10.0.0.0") "IP-Modell: Zuordnungstabelle enthält Ausgabe -> Original (auch kanonisch)"
    $eFunde = @([AnonTool.AnonEngine]::AuditText($eAus, "e.txt", $eCfg, $eState) | Where-Object { $_.Kategorie -match "IPv[46]" })
    Assert-Equal $eFunde.Count 0 "IP-Modell: Prüfmodus meldet keine verfremdeten IPs"
    $eNach = @([AnonTool.AnonEngine]::Nachpruefen($eAus, "e.txt", $eCfg))
    Assert-Equal $eNach.Count 0 "IP-Modell: Nachprüfung meldet keine verfremdeten IPs"
    $eOhne = @([AnonTool.AnonEngine]::AuditText($eAus, "e.txt", $eCfg, (New-Object AnonTool.AnonState)) | Where-Object { $_.Kategorie -eq "Rest-IPv4" })
    Assert-True ($eOhne.Count -gt 0) "IP-Modell: Prüfmodus ohne passende Zuordnung meldet IPs weiterhin"
    $eState2 = New-Object AnonTool.AnonState
    [void][AnonTool.AnonEngine]::ProcessText([string]$ipVek.engine.eingabe, $eCfg, $eState2)
    Assert-True ([AnonTool.AnonEngine]::ProcessText([string]$ipVek.engine.eingabe, $eCfg, $eState2) -ceq $eAus) "IP-Modell: gleiche Abbildung über Läufe mit demselben Schlüssel"
    $altCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
    Assert-Equal ([AnonTool.AnonEngine]::ProcessText("ip address 172.22.0.230 255.255.255.0`n", $altCfg, (New-Object AnonTool.AnonState))) "ip address NET-1.H1 255.255.255.0`n" "IP-Modell: alter Modus NET-n.Hm weiter wählbar"
}

Write-Host "=== IP-Modell: Schlüsselverwaltung (anon.ps1) ===" -ForegroundColor Cyan
$ipDir = Join-Path $tempRunRoot "ipmodell"
[void](New-Item -ItemType Directory -Path $ipDir -Force)
$ipEin = Join-Path $ipDir "eingabe.txt"
[System.IO.File]::WriteAllText($ipEin, "ntp server 192.0.2.10`nip address 172.22.0.230 255.255.255.0`nipv6 address 2001:db8:0:1::10/64`n", (New-Object System.Text.UTF8Encoding($false)))
$ipKey = Join-Path (Join-Path $tempRunRoot "ipschluessel") "fall-1.anonkey"
$ipLauf1 = & $anonScript -Eingabe $ipEin -Ausgabe (Join-Path $ipDir "aus1") -Regeln $rulesPath -TabellenPfad (Join-Path $tabDir "ip-1.json") -PasswortSecure $secPass -IpModus schluessel -IpSchluessel $ipKey 6>&1 2>&1 | Out-String
$ipCode1 = $LASTEXITCODE
$ipAus1 = if (Test-Path -LiteralPath (Join-Path $ipDir "aus1/anonym/eingabe.txt")) { [System.IO.File]::ReadAllText((Join-Path $ipDir "aus1/anonym/eingabe.txt")) } else { "" }
Assert-True ($ipCode1 -eq 0 -and (Test-Path -LiteralPath $ipKey)) "IP-Modell: Lauf im Schlüsselmodus legt den IP-Schlüssel an ($ipCode1)"
Assert-True ($ipLauf1 -match "Neuer IP-Schl" -and $ipLauf1 -match "anders abgebildet") "IP-Modell: Hinweis 'neuer Schlüssel = andere Abbildung als frühere Läufe'"
$ipKeyObj = if (Test-Path -LiteralPath $ipKey) { ConvertFrom-Json ([System.IO.File]::ReadAllText($ipKey)) } else { $null }
Assert-True ($null -ne $ipKeyObj -and $ipKeyObj.format -eq "ANON-AES256-2") "IP-Modell: IP-Schlüssel mit Passwort geschützt (ANON-AES256-2)"
Assert-True ($ipAus1.Length -gt 0 -and $ipAus1 -notmatch '(?<![0-9.])(?:192\.0\.2\.10|172\.22\.0\.230)(?![0-9])' -and $ipAus1.Contains(" 255.255.255.0") -and -not $ipAus1.Contains("NET-")) "IP-Modell: Ausgabe verfremdet, ohne Platzhalter, Maske bleibt"
$ipBericht1 = if (Test-Path -LiteralPath (Join-Path $ipDir "aus1/bericht.json")) { ConvertFrom-Json ([System.IO.File]::ReadAllText((Join-Path $ipDir "aus1/bericht.json"))) } else { $null }
Assert-True ($null -ne $ipBericht1 -and $ipBericht1.ipModus -eq "schluessel" -and $ipBericht1.ipHinweis -eq "IP-Adressen sind schlüsselbasiert verfremdet, Netze rechnerisch korrekt." -and $ipBericht1.ipSchluesselKennung -match '^[0-9a-f]{16}$') "IP-Modell: Bericht mit Modus, Hinweis und Schlüsselkennung"
$ipLauf2 = & $anonScript -Eingabe $ipEin -Ausgabe (Join-Path $ipDir "aus2") -Regeln $rulesPath -TabellenPfad (Join-Path $tabDir "ip-2.json") -PasswortSecure $secPass -IpModus schluessel -IpSchluessel $ipKey 6>&1 2>&1 | Out-String
$ipAus2 = if (Test-Path -LiteralPath (Join-Path $ipDir "aus2/anonym/eingabe.txt")) { [System.IO.File]::ReadAllText((Join-Path $ipDir "aus2/anonym/eingabe.txt")) } else { "x" }
Assert-True ($ipAus2 -ceq $ipAus1 -and $ipLauf2 -notmatch "Neuer IP-Schl") "IP-Modell: zweiter Lauf mit demselben Schlüssel bildet gleich ab (neue Tabelle, kein Hinweis)"
$ipKey3 = Join-Path (Join-Path $tempRunRoot "ipschluessel") "fall-2.anonkey"
$null = & $anonScript -Eingabe $ipEin -Ausgabe (Join-Path $ipDir "aus3") -Regeln $rulesPath -TabellenPfad (Join-Path $tabDir "ip-3.json") -PasswortSecure $secPass -IpModus schluessel -IpSchluessel $ipKey3 6>&1 2>&1
$ipAus3 = if (Test-Path -LiteralPath (Join-Path $ipDir "aus3/anonym/eingabe.txt")) { [System.IO.File]::ReadAllText((Join-Path $ipDir "aus3/anonym/eingabe.txt")) } else { $ipAus1 }
Assert-True ($ipAus3 -cne $ipAus1) "IP-Modell: anderer Schlüssel (pro Fall) bildet anders ab"
# Prüfmodus: mit der Zuordnungstabelle des Laufs keine Restfunde, ohne Tabelle gelten die verfremdeten IPs als Restfund
$null = & $anonScript -Pruefen -Eingabe (Join-Path $ipDir "aus1/anonym") -Regeln $rulesPath -TabellenPfad (Join-Path $tabDir "ip-1.json") -PasswortSecure $secPass -IpModus schluessel 6>&1 2>&1
Assert-Equal $LASTEXITCODE 0 "IP-Modell: -Pruefen mit Zuordnungstabelle meldet keine verfremdeten IPs"
$null = & $anonScript -Pruefen -Eingabe (Join-Path $ipDir "aus1/anonym") -Regeln $rulesPath -IpModus schluessel 6>&1 2>&1
Assert-Equal $LASTEXITCODE 2 "IP-Modell: -Pruefen ohne Zuordnungstabelle meldet die IPs"
# Arbeitsbereich-Schlüssel ohne -IpSchluessel: liegt unter <Basis>/schluessel/arbeitsbereich.anonkey
$null = & $anonScript -Eingabe $ipEin -Ausgabe (Join-Path $ipDir "aus4") -Regeln $rulesPath -TabellenPfad (Join-Path $tabDir "ip-4.json") -PasswortSecure $secPass -IpModus schluessel 6>&1 2>&1
Assert-True (Test-Path -LiteralPath (Join-Path (Join-Path (Join-Path $env:LOCALAPPDATA "Anon") "schluessel") "arbeitsbereich.anonkey")) "IP-Modell: Arbeitsbereich-Schlüssel wird angelegt"
# Trockenlauf ohne Schlüsseldatei: temporärer Schlüssel, nichts gespeichert
$ipKeyProbe = Join-Path (Join-Path $tempRunRoot "ipschluessel") "probe.anonkey"
$ipProbe = & $anonScript -Eingabe $ipEin -Regeln $rulesPath -Probe -IpModus schluessel -IpSchluessel $ipKeyProbe 6>&1 2>&1 | Out-String
Assert-True ($LASTEXITCODE -eq 0 -and -not (Test-Path -LiteralPath $ipKeyProbe) -and $ipProbe -match "tempor") "IP-Modell: Trockenlauf nutzt einen temporären Schlüssel und speichert nichts"
# Sicherheit und Bedienfehler
Assert-Throws { & $anonScript -Eingabe $ipEin -Ausgabe (Join-Path $ipDir "aus5") -Regeln $rulesPath -TabellenPfad (Join-Path $tabDir "ip-5.json") -PasswortSecure $secPass -IpModus schluessel -IpSchluessel (Join-Path $ipDir "aus5/k.anonkey") > $null 2>&1 } "IP-Modell: IP-Schlüssel im Ausgabeordner wird abgelehnt"
Assert-Throws { & $anonScript -Eingabe $ipEin -Ausgabe (Join-Path $ipDir "aus6") -Regeln $rulesPath -IpModus schluessel -Netzerhaltend > $null 2>&1 } "IP-Modell: -IpModus schluessel zusammen mit -Netzerhaltend wird abgelehnt"
Assert-Throws { & $anonScript -Eingabe $ipEin -Ausgabe (Join-Path $ipDir "aus7") -Regeln $rulesPath -TabellenPfad (Join-Path $tabDir "ip-7.json") -PasswortSecure (ConvertTo-SecureString "AnderesPasswort99!" -AsPlainText -Force) -IpModus schluessel -IpSchluessel $ipKey > $null 2>&1 } "IP-Modell: falsches Passwort für den IP-Schlüssel wird abgelehnt"
$istWin = ($env:OS -eq "Windows_NT")
if (-not $istWin) {
    Assert-Throws { & $anonScript -Eingabe $ipEin -Ausgabe (Join-Path $ipDir "aus8") -Regeln $rulesPath -TabellenPfad (Join-Path $tabDir "ip-8.json") -Unverschluesselt -IpModus schluessel -IpSchluessel (Join-Path (Join-Path $tempRunRoot "ipschluessel") "ohne.anonkey") > $null 2>&1 } "IP-Modell: ohne DPAPI und ohne Passwort wird kein IP-Schlüssel angelegt"
} else {
    $null = & $anonScript -Eingabe $ipEin -Ausgabe (Join-Path $ipDir "aus8") -Regeln $rulesPath -TabellenPfad (Join-Path $tabDir "ip-8.json") -IpModus schluessel -IpSchluessel (Join-Path (Join-Path $tempRunRoot "ipschluessel") "dpapi.anonkey") 6>&1 2>&1
    Assert-True ((ConvertFrom-Json ([System.IO.File]::ReadAllText((Join-Path (Join-Path $tempRunRoot "ipschluessel") "dpapi.anonkey")))).format -eq "ANON-DPAPI-1") "IP-Modell: unter Windows wird der IP-Schlüssel mit DPAPI geschützt"
}
# Gegenprobe der Formate mit dem Browser-Kern (Node), falls vorhanden
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if ($null -ne $nodeCmd) {
    $hilfe = Join-Path $testDir "ip-schluessel-hilfe.js"
    $kNode = (& node $hilfe lesen $ipKey "TestPasswort123!" | Out-String).Trim()
    Assert-Equal $kNode ([string]$ipBericht1.ipSchluesselKennung) "IP-Modell: Browser-Kern liest den von anon.ps1 erzeugten IP-Schlüssel (gleiche Kennung)"
    $ipKeyJs = Join-Path (Join-Path $tempRunRoot "ipschluessel") "browser.anonkey"
    $kJs = (& node $hilfe erstellen $ipKeyJs "TestPasswort123!" | Out-String).Trim()
    $null = & $anonScript -Eingabe $ipEin -Ausgabe (Join-Path $ipDir "aus9") -Regeln $rulesPath -TabellenPfad (Join-Path $tabDir "ip-9.json") -PasswortSecure $secPass -IpModus schluessel -IpSchluessel $ipKeyJs 6>&1 2>&1
    $ipBericht9 = ConvertFrom-Json ([System.IO.File]::ReadAllText((Join-Path $ipDir "aus9/bericht.json")))
    Assert-Equal ([string]$ipBericht9.ipSchluesselKennung) $kJs "IP-Modell: anon.ps1 liest den im Browser erzeugten IP-Schlüssel (gleiche Kennung)"
} else {
    Write-Host "  [NICHT AUSGEFÜHRT] Gegenprobe .anonkey mit Node: node nicht gefunden" -ForegroundColor Yellow
}

Write-Host "=== IP-Modell: Rückübersetzung ===" -ForegroundColor Cyan
if ($ipKernDa) {
    $rKs = New-Object AnonTool.CryptoPan (,(ConvertFrom-TestHex $ipVek.engine.schluesselHex))
    $rA = 0; $rB = 0
    $rText = [AnonTool.AnonEngine]::DeanonymizeText([string]$ipVek.engine.ausgabe, (New-Object AnonTool.AnonState).Reverse, $rKs, [ref]$rA, [ref]$rB)
    Assert-True ($rText -ceq [string]$ipVek.engine.rueckNurSchluessel -and $rB -eq [int]$ipVek.engine.rueckNurSchluesselAnzahl -and $rA -eq 0) "IP-Modell: Parität A == B, Rückübersetzung nur über den Schlüssel gleich JS ($rB)"
    $rState = New-Object AnonTool.AnonState
    $rCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
    $rCfg.IpModus = "schluessel"
    $rCfg.IpSchluessel = $rKs
    [void][AnonTool.AnonEngine]::ProcessText([string]$ipVek.engine.eingabe, $rCfg, $rState)
    $rAus = [AnonTool.AnonEngine]::ProcessText([string]$ipVek.engine.eingabe, $rCfg, $rState)
    $rText2 = [AnonTool.AnonEngine]::DeanonymizeText($rAus, $rState.Reverse, $null, [ref]$rA, [ref]$rB)
    Assert-True ($rText2 -ceq ([string]$ipVek.engine.rueckNurSchluessel).Replace("hostname HOST-1", "hostname sw-ip01") -and $rB -eq 0 -and $rA -gt 0) "IP-Modell: Rückübersetzung über die Zuordnungstabelle liefert das Original"
    Assert-Equal ([AnonTool.AnonEngine]::DeanonymizeText("mask 255.255.255.0 wc 0.0.0.15 lo 127.0.0.1 any 0.0.0.0`n", (New-Object AnonTool.AnonState).Reverse, $rKs, [ref]$rA, [ref]$rB)) "mask 255.255.255.0 wc 0.0.0.15 lo 127.0.0.1 any 0.0.0.0`n" "IP-Modell: Masken, Wildcards und Sonderadressen bleiben bei der Rückübersetzung"
}
# CLI: -Zurueck über die Zuordnungstabelle und nur über den IP-Schlüssel
$ipOrig = [System.IO.File]::ReadAllText($ipEin)
$zr1 = Join-Path $ipDir "rueck-tabelle.txt"
$null = & $anonScript -Zurueck -Eingabe (Join-Path $ipDir "aus1/anonym/eingabe.txt") -Ausgabe $zr1 -TabellenPfad (Join-Path $tabDir "ip-1.json") -PasswortSecure $secPass 6>&1 2>&1
Assert-True ((Test-Path -LiteralPath $zr1) -and [System.IO.File]::ReadAllText($zr1) -ceq $ipOrig) "IP-Modell: -Zurueck über die Zuordnungstabelle liefert das Original"
$zr2 = Join-Path $ipDir "rueck-schluessel.txt"
$zrLog = & $anonScript -Zurueck -Eingabe (Join-Path $ipDir "aus1/anonym/eingabe.txt") -Ausgabe $zr2 -IpSchluessel $ipKey -PasswortSecure $secPass 6>&1 2>&1 | Out-String
Assert-True ((Test-Path -LiteralPath $zr2) -and [System.IO.File]::ReadAllText($zr2) -ceq $ipOrig -and $zrLog -match "nur über den IP-Schl") "IP-Modell: -Zurueck nur über den IP-Schlüssel liefert die Original-IPs, mit Hinweis"
Assert-True (-not $zrLog.Contains("172.22.0.230")) "IP-Modell: -Zurueck gibt keinen Klartext auf der Konsole aus"
Assert-Throws { & $anonScript -Zurueck -Eingabe (Join-Path $ipDir "aus1/anonym/eingabe.txt") -Ausgabe (Join-Path $ipDir "r3.txt") > $null 2>&1 } "IP-Modell: -Zurueck ohne Tabelle und ohne IP-Schlüssel wird abgelehnt"

Write-Host "=== Fix IP-Sonderformen (eingebettete IPv4, ::ffff:hhhh:hhhh, führende Nullen, Schnittstellenkennung) ===" -ForegroundColor Cyan
if ($ipKernDa) {
    $sv = $ipVek.sonderformen
    $sKs = New-Object AnonTool.CryptoPan (,(ConvertFrom-TestHex $sv.schluesselHex))
    foreach ($modus in @("schluessel", "platzhalter")) {
        $sCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
        if ($modus -eq "schluessel") { $sCfg.IpModus = "schluessel"; $sCfg.IpSchluessel = $sKs }
        $sSt = New-Object AnonTool.AnonState
        [void][AnonTool.AnonEngine]::ProcessText([string]$sv.eingabe, $sCfg, $sSt)
        $sAus = [AnonTool.AnonEngine]::ProcessText([string]$sv.eingabe, $sCfg, $sSt)
        $sSoll = if ($modus -eq "schluessel") { [string]$sv.ausgabeSchluessel } else { [string]$sv.ausgabePlatzhalter }
        if ($sAus -cne $sSoll) {
            $ea = $sAus.Split("`n"); $es = $sSoll.Split("`n")
            for ($i = 0; $i -lt [Math]::Min($ea.Length, $es.Length); $i++) { if ($ea[$i] -cne $es[$i]) { Write-Host "    Zeile $($i + 1): erwartet '$($es[$i])', erhalten '$($ea[$i])'" -ForegroundColor Yellow } }
        }
        Assert-True ($sAus -ceq $sSoll) "Sonderformen ($modus): Parität A == B, Ausgabe gleich JS"
        $sF = @([AnonTool.AnonEngine]::AuditText($sAus, "s.txt", $sCfg, $sSt) | Where-Object { $_.Kategorie -match "IP" })
        Assert-Equal $sF.Count 0 "Sonderformen ($modus): Prüfung meldet keine verfremdeten Adressen"
        Assert-Equal (@([AnonTool.AnonEngine]::Nachpruefen($sAus, "s.txt", $sCfg)).Count) 0 "Sonderformen ($modus): Nachprüfung der Ausgabe ohne Fund"
        $ra = 0; $rb = 0
        $sR = [AnonTool.AnonEngine]::DeanonymizeText($sAus, $sSt.Reverse, $null, [ref]$ra, [ref]$rb)
        $sRSoll = if ($modus -eq "schluessel") { [string]$sv.rueckNurSchluessel } else { ([string]$sv.rueckNurSchluessel).Replace("d ::ffff:0a00:000d", "d ::ffff:10.0.0.13") }
        Assert-True ($sR -ceq $sRSoll) "Sonderformen ($modus): Rückübersetzung über die Zuordnung"
    }
    $ra = 0; $rb = 0
    $sR2 = [AnonTool.AnonEngine]::DeanonymizeText([string]$sv.ausgabeSchluessel, (New-Object AnonTool.AnonState).Reverse, $sKs, [ref]$ra, [ref]$rb)
    Assert-True ($sR2 -ceq [string]$sv.rueckNurSchluessel) "Sonderformen: Rückübersetzung nur über den Schlüssel gleich JS"
    $nCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
    $nRest = @([AnonTool.AnonEngine]::Nachpruefen("neighbor 98:41dc:2a1b:81ef.0.0.13`nntp server 010.000.000.013`nlogging host 10.0.0.013`nversion 16.9.3`n", "r.txt", $nCfg) | Where-Object { $_.Kategorie -eq "Nachpruefung-IP" })
    Assert-Equal $nRest.Count 3 "Nachprüfung: Rest einer IPv4 an einer IPv6 und führende Nullen sind Funde"
    Assert-True (@([AnonTool.AnonEngine]::AuditText("neighbor 98:41dc:2a1b:81ef.0.0.13`n", "r.txt", $nCfg, (New-Object AnonTool.AnonState)) | Where-Object { $_.Kategorie -eq "Nachpruefung-IP" }).Count -gt 0) "Prüfung im Lauf meldet den Rest einer IPv4 an einer IPv6"
    # Schnittstellenkennung: kleine Kennungen bleiben, andere landen nie dort, umkehrbar
    $rng = New-Object System.Random 815
    $iidFehler = 0
    $netz = [AnonTool.CryptoPan]::Ip6Lesen("2001:db8:0:1::")
    for ($i = 0; $i -lt 600; $i++) {
        $b = [byte[]]$netz.Clone()
        $r = New-Object byte[] 8; $rng.NextBytes($r)
        for ($j = 0; $j -lt 8; $j++) { $b[8 + $j] = $r[$j] }
        if ($i % 3 -eq 0) { for ($j = 8; $j -lt 14; $j++) { $b[$j] = 0 } }
        $o = $sKs.Verfremden($b, $false)
        $klein = [AnonTool.CryptoPan]::KleineKennung($b)
        if ($klein -ne [AnonTool.CryptoPan]::KleineKennung($o) -or ($klein -and (ConvertTo-TestHex $o[8..15]) -ne (ConvertTo-TestHex $b[8..15])) -or (ConvertTo-TestHex ($sKs.Verfremden($o, $true))) -ne (ConvertTo-TestHex $b)) { $iidFehler++ }
    }
    Assert-Equal $iidFehler 0 "Sonderformen: kleine Schnittstellenkennungen bleiben, andere landen nie dort, umkehrbar"
}

$env:LOCALAPPDATA = $origLocalAppData

# Aufräumen des temporären Testordners
if (Test-Path -LiteralPath $tempRunRoot) { Remove-Item -LiteralPath $tempRunRoot -Recurse -Force }
if (Test-Path -LiteralPath $rulesAltDir) { Remove-Item -LiteralPath $rulesAltDir -Recurse -Force }

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TESTERGEBNIS (PowerShell): $passed bestanden, $failed fehlgeschlagen" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor Cyan
if ($failed -gt 0) { exit 1 } else { exit 0 }


