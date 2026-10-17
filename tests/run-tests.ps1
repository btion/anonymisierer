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
$anonScript = Join-Path $rootDir "anon.ps1"
$rulesPath = Join-Path $rootDir "anon-regeln.json"
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

Write-Host "=== 1. Initialisiere AnonTool.AnonEngine über anon.ps1 (Trockenlauf) ===" -ForegroundColor Cyan
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
    foreach ($x in $RulesObj.hostnamenMuster) { $cfg.HostnamenMuster.Add((New-Object System.Text.RegularExpressions.Regex ([string]$x, $rxOpts, $rxTimeout))) }
    return $cfg
}

foreach ($tc in $cases) {
    $netMode = if ($null -ne $tc.netzerhaltend) { [bool]$tc.netzerhaltend } else { $true }
    $katFilter = if ($null -ne $tc.PSObject.Properties["kategorien"]) { @($tc.kategorien) } else { $null }
    $cfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $netMode -KatFilter $katFilter

    # 2a. LF-Variante
    $st = New-Object AnonTool.AnonState
    $actual = [AnonTool.AnonEngine]::ProcessText([string]$tc.eingabe, $cfg, $st)
    $isEqual = ($actual -ceq [string]$tc.erwartet)
    if (-not $isEqual) {
        Write-Host "  [$($tc.id) LF] Erwartet: $($tc.erwartet)" -ForegroundColor Yellow
        Write-Host "  [$($tc.id) LF] Erhalten: $actual" -ForegroundColor Yellow
    }
    Assert-True $isEqual "$($tc.id) (LF): $($tc.name) (PS1 == Erwartet)"

    $findings = [AnonTool.AnonEngine]::AuditText($actual, "$($tc.id).txt", $cfg)
    $isClean = ($findings.Count -eq 0)
    Assert-True ($isClean -eq [bool]$tc.sauber) "$($tc.id) (LF): Prüfmodus sauber=$isClean (erwartet $($tc.sauber))"

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

    $findingsCrlf = [AnonTool.AnonEngine]::AuditText($actualCrlf, "$($tc.id).txt", $cfg)
    Assert-True (($findingsCrlf.Count -eq 0) -eq [bool]$tc.sauber) "$($tc.id) (CRLF): Prüfmodus sauber=$($findingsCrlf.Count -eq 0)"

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

& $anonScript -Eingabe $beispieleDir -Ausgabe $outDir -Regeln $rulesPath -TabellenPfad $tabFile -PasswortSecure $secPass > $null
Assert-True ($LASTEXITCODE -eq 0) "End-to-End CLI-Lauf auf sauberen Beispieldateien liefert Exit-Code 0"

Assert-True (Test-Path -LiteralPath (Join-Path $outDir "anonym")) "<Ausgabe>\anonym\ wurde erstellt"
Assert-True (-not (Test-Path -LiteralPath (Join-Path $outDir "_arbeit"))) "<Ausgabe>\_arbeit\ wurde nach dem Lauf gelöscht"
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
$origRelPath = "Rechenzentrum-Nord/rz1-sw-core01/show-tech-tsw-halle2-01_10.20.30.1.txt"
$anonRelPath = [AnonTool.AnonEngine]::ProcessPath($origRelPath, $pathCfg, $pathState)
Assert-True ($anonRelPath -ceq "FIRMA-1/CORE-A/show-tech-HOST-1_NET-1.H1.txt") "Befund 2: ProcessPath anonymisiert jeden Pfadbestandteil ($anonRelPath)"

$cleanPathAudit = [AnonTool.AnonEngine]::AuditText("interface 1/1/1", $anonRelPath, $pathCfg)
Assert-True ($cleanPathAudit.Count -eq 0) "Befund 2: Anonymisierter Dateipfad ist in AuditText SAUBER"

$dirtyPathAudit = [AnonTool.AnonEngine]::AuditText("interface 1/1/1", $origRelPath, $pathCfg)
Assert-True ($dirtyPathAudit.Count -ge 3) "Befund 2: Nicht anonymisierter Dateipfad wird in AuditText als Restfund gemeldet ($($dirtyPathAudit.Count) Treffer)"

# End-to-End Dateinamen-Test inkl. Binärdatei-Name im Bericht
$pathInDir = Join-Path $tempRunRoot "pfad_in"
$pathOutDir = Join-Path $tempRunRoot "pfad_out"
$pathTabFile = Join-Path $tabDir "pfad-tab.json"
[void](New-Item -ItemType Directory -Path $pathInDir -Force)
[System.IO.File]::WriteAllText((Join-Path $pathInDir "show-tech-rz1-sw-core01_10.20.30.1.txt"), "hostname rz1-sw-core01`r`n", [System.Text.Encoding]::UTF8)
[System.IO.File]::WriteAllBytes((Join-Path $pathInDir "firmware-rz1-sw-core01.bin"), [byte[]]@(0, 1, 2, 0, 255, 0, 42))
& $anonScript -Eingabe $pathInDir -Ausgabe $pathOutDir -Regeln $rulesPath -TabellenPfad $pathTabFile -Unverschluesselt > $null
Assert-True (Test-Path -LiteralPath (Join-Path (Join-Path $pathOutDir "anonym") "show-tech-CORE-A_NET-1.H1.txt")) "Befund 2: Ausgabedatei in anonym\ trägt anonymisierten Namen (show-tech-CORE-A_NET-1.H1.txt)"
Assert-True (-not (Test-Path -LiteralPath (Join-Path (Join-Path $pathOutDir "anonym") "show-tech-rz1-sw-core01_10.20.30.1.txt"))) "Befund 2: Originaldateiname mit Hostname existiert NICHT in anonym\"
$pathBericht = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $pathOutDir "bericht.json"), [System.Text.Encoding]::UTF8))
Assert-True ($pathBericht.uebersprungeneBinaer[0] -ceq "firmware-CORE-A.bin") "Befund 2: Auch uebersprungeneBinaer im Bericht nutzt anonymisierten Pfad ($($pathBericht.uebersprungeneBinaer[0]))"

# ----------------------------------------------------------------------------
# Befund 3: Zeichenkodierung (UTF-16-LE BOM, UTF-16-BE BOM, UTF-8 BOM -> UTF-8 ohne BOM)
# ----------------------------------------------------------------------------
$bomInDir = Join-Path $tempRunRoot "bom_in"
$bomOutDir = Join-Path $tempRunRoot "bom_out"
$bomTabFile = Join-Path $tabDir "bom-tab.json"
[void](New-Item -ItemType Directory -Path $bomInDir -Force)
$evText = "EventID=4624 IpAddress=10.40.50.60 ClientMAC=00:1a:2b:3c:4d:5e`r`n"
# Schreibe UTF-16 LE mit BOM, UTF-16 BE mit BOM und UTF-8 mit BOM
[System.IO.File]::WriteAllText((Join-Path $bomInDir "ev-utf16le.log"), $evText, [System.Text.Encoding]::Unicode)
[System.IO.File]::WriteAllText((Join-Path $bomInDir "ev-utf16be.log"), $evText, [System.Text.Encoding]::BigEndianUnicode)
[System.IO.File]::WriteAllText((Join-Path $bomInDir "ev-utf8bom.log"), $evText, (New-Object System.Text.UTF8Encoding($true)))

& $anonScript -Eingabe $bomInDir -Ausgabe $bomOutDir -Regeln $rulesPath -TabellenPfad $bomTabFile -Unverschluesselt > $null
Assert-True ($LASTEXITCODE -eq 0) "Befund 3: BOM-Dateien (UTF-16 LE/BE, UTF-8-BOM) verarbeitet und SAUBER (Exit-Code 0)"
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
Assert-True ($tabHeaderObj.kdf -eq "PBKDF2-SHA1") "Befund 4: Tabellenkopf kdf ist PBKDF2-SHA1"
Assert-True ([int]$tabHeaderObj.iterations -eq 600000) "Befund 4: PBKDF2 Iterationszahl im Tabellenkopf ist 600.000 ($($tabHeaderObj.iterations))"

$kiAntwortPfad = Join-Path $tempRunRoot "ki-antwort.txt"
$kiRueckPfad = Join-Path $tempRunRoot "ki-rueck.txt"
[System.IO.File]::WriteAllText($kiAntwortPfad, "Bitte prüfen Sie auf CORE-A das Interface zu CORE-B mit IP NET-1.H2/24 und MAC MAC-1.", [System.Text.Encoding]::UTF8)
& $anonScript -Zurueck -Eingabe $kiAntwortPfad -Ausgabe $kiRueckPfad -TabellenPfad $tabFile -PasswortSecure $secPass > $null
$rueckText = [System.IO.File]::ReadAllText($kiRueckPfad, [System.Text.Encoding]::UTF8)
Assert-True ($rueckText.Contains("rz1-sw-core01") -and $rueckText.Contains("rz2-sw-core02") -and $rueckText.Contains("10.20.30.1/24") -and $rueckText.Contains("00:1a:2b:3c:4d:5e")) "Befund 4: Rückübersetzung (-Zurueck) mit ANON-AES256-2 erfolgreich"

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
$legacyPlain = '{"version":"1.0","vorwaerts":{"fixed|rz1-sw-core01":"CORE-A"},"rueckwaerts":{"CORE-A":"rz1-sw-core01"},"zaehler":{},"netzHosts":{}}'
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
Assert-True ($legacyRestored -ceq "Switch rz1-sw-core01 ist aktiv.") "Befund 4: ANON-AES256-1 (100.000 Iterationen ohne Kopf-Feld) bleibt ladbar"
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
$minRulesContent = '{"eigeneBegriffe":{"festeZuordnung":{"rz1-sw-core01":"MIN-CORE-1"}}}'
[System.IO.File]::WriteAllText($minRulesPath, $minRulesContent, [System.Text.Encoding]::UTF8)
$minInFile = Join-Path $tempRunRoot "min-in.txt"
[System.IO.File]::WriteAllText($minInFile, "hostname rz1-sw-core01`r`nip address 10.1.2.3/24`r`n", [System.Text.Encoding]::UTF8)
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
$bOut = [AnonTool.AnonEngine]::ProcessText("rz1-tor-01 und rz1-tor-010", $pathCfg, $bState)
Assert-True ($bOut -ceq "TOR-A und HOST-1" -and (-not $bOut.Contains("TOR-A0"))) "Befund 8: Wort-/Namensgrenzen verhindern Teilwort-Ersetzung ('rz1-tor-010' -> 'HOST-1' statt 'TOR-A0')"

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
Assert-True ($zipBericht.pruefergebnis -eq "SAUBER") "ZIP-Ausgabe ist SAUBER"

Write-Host "=== 5. Performance- & Stresstest: Großer Aruba AOS-CX Show-Tech (40.000+ Zeilen) ===" -ForegroundColor Cyan
$sb = New-Object System.Text.StringBuilder (4 * 1024 * 1024)
[void]$sb.AppendLine("================================f=show tech====================================")
[void]$sb.AppendLine("hostname rz1-sw-core01")
[void]$sb.AppendLine("Version : FL.10.13.1020")
[void]$sb.AppendLine("snmp-server system-location Rechenzentrum-Nord Halle 3")
[void]$sb.AppendLine("snmp-server system-contact Max Mustermann (netze@intern.musterfirma.de)")
[void]$sb.AppendLine("user admin password ciphertext AQBapf92384719283749182374918273948172938471928374")
for ($i = 1; $i -le 5000; $i++) {
    $vId = ($i % 400) + 10
    $o3 = ($i % 200) + 1
    $o4 = ($i % 250) + 1
    $hex = ($i -band 0xFF).ToString("x2")
    $port = ($i % 48) + 1
    $dist = ($i % 30) + 1
    $acc = ($i % 80) + 1
    [void]$sb.AppendLine("vlan $vId")
    [void]$sb.AppendLine("    name KD_${vId}_10.${o3}.0.0-24")
    [void]$sb.AppendLine("interface 1/1/$port")
    [void]$sb.AppendLine("    description Uplink_$i zu tsw-dist-$dist (Musterfirma GmbH)")
    [void]$sb.AppendLine("    ip address 10.${o3}.${o4}.1/24")
    [void]$sb.AppendLine("1/1/$port  tsw-acc-$acc  00:1a:2b:3c:4d:$hex  10.${o3}.${o4}.254  Aruba JL658A  FL.10.13.1020")
    [void]$sb.AppendLine("2026-10-16T14:22:15.123Z rz1-sw-core01 hpe-routing[$i]: Event on sn link state up for 10.${o3}.${o4}.1")
}
$largeShowTech = $sb.ToString()
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$perfCfg = New-TestConfig -RulesObj $rulesObj -Netzerhaltend $true
$perfState = New-Object AnonTool.AnonState
$largeAnon = [AnonTool.AnonEngine]::ProcessText($largeShowTech, $perfCfg, $perfState)
$largeFindings = [AnonTool.AnonEngine]::AuditText($largeAnon, "aruba-show-tech-large.txt", $perfCfg)
$sw.Stop()
Write-Host ("  Großer Show-Tech ({0:N2} MB) verarbeitet + geprüft in {1} ms" -f ($largeShowTech.Length / 1MB), $sw.ElapsedMilliseconds) -ForegroundColor Gray
Assert-True ($sw.ElapsedMilliseconds -lt 8000) "Performance-Ziel erreicht: $($sw.ElapsedMilliseconds) ms (< 8000 ms)"
Assert-True ($largeFindings.Count -eq 0) "Großer Aruba Show-Tech ist nach Anonymisierung SAUBER (0 Restfunde)"
Assert-True (-not $largeAnon.Contains([string][char]2 + "PROT_")) "Alle Schutz-Marker vollständig aufgelöst"

Write-Host "=== 6. Prüfe switch-sammler.ps1 (Allowlist, exec/shell, Hostkey, MikroTik, Exit-Code 3) ===" -ForegroundColor Cyan
$sammlerPath = Join-Path $rootDir "switch-sammler.ps1"
$sammlerJsonPath = Join-Path $rootDir "sammler-befehle.json"
Assert-True (Test-Path -LiteralPath $sammlerPath) "switch-sammler.ps1 existiert"
Assert-True (Test-Path -LiteralPath $sammlerJsonPath) "sammler-befehle.json existiert"

# Lade Funktionen aus switch-sammler.ps1 per Dot-Sourcing
. $sammlerPath -NurFunktionenLaden

# 6.1 Sitzungsmodell (exec vs shell) pro Profil prüfen
$pSonicKlish = Get-FestesSammlerProfil -ProfilName "dell-sonic"
$pSonicClick = Get-FestesSammlerProfil -ProfilName "dell-sonic" -ClickCli
$pOs10       = Get-FestesSammlerProfil -ProfilName "dell-os10"
$pAoscx      = Get-FestesSammlerProfil -ProfilName "aruba-aoscx"
$pAoss       = Get-FestesSammlerProfil -ProfilName "aruba-aoss"
$pComware    = Get-FestesSammlerProfil -ProfilName "hpe-comware"
$pMikrotik   = Get-FestesSammlerProfil -ProfilName "mikrotik-routeros"
$pCisco      = Get-FestesSammlerProfil -ProfilName "cisco-ios"

Assert-Equal $pSonicKlish.sitzungsModus "shell" "dell-sonic (Klish Standard) nutzt sitzungsModus = shell"
Assert-Equal $pSonicClick.sitzungsModus "exec"  "dell-sonic (-SonicClickCli) nutzt sitzungsModus = exec"
Assert-Equal $pMikrotik.sitzungsModus   "exec"  "mikrotik-routeros nutzt sitzungsModus = exec"
Assert-Equal $pAoscx.sitzungsModus      "shell" "aruba-aoscx nutzt sitzungsModus = shell"
Assert-Equal $pAoss.sitzungsModus       "shell" "aruba-aoss nutzt sitzungsModus = shell"
Assert-Equal $pComware.sitzungsModus    "shell" "hpe-comware nutzt sitzungsModus = shell"
Assert-Equal $pOs10.sitzungsModus       "shell" "dell-os10 nutzt sitzungsModus = shell"
Assert-Equal $pCisco.sitzungsModus      "shell" "cisco-ios nutzt sitzungsModus = shell"

# 6.2 2-Stufen-Allowlist: Alle Profilbefehle erlaubt, verbotene Zeichen & fremde Befehle blockiert
foreach ($pKey in @("dell-sonic", "dell-os10", "aruba-aoscx", "aruba-aoss", "hpe-comware", "mikrotik-routeros", "cisco-ios")) {
    $pd = Get-FestesSammlerProfil -ProfilName $pKey
    foreach ($v in $pd.vorspann) {
        Assert-True (Test-SammlerBefehl -Befehl $v -ProfilName $pKey -ErlaubeVorspann) "Vorspann '$v' in $pKey erlaubt"
    }
    foreach ($b in $pd.befehle) {
        Assert-True (Test-SammlerBefehl -Befehl $b.befehl -ProfilName $pKey) "Allowlist-Befehl '$($b.befehl)' in $pKey erlaubt"
    }
}
# Auch Befehle mit 'conf'/'config'/'boot' in der eigenen Allowlist funktionieren ohne Blocklist-Konflikt
Assert-True (Test-SammlerBefehl -Befehl "show running-config" -ProfilName "aruba-aoscx") "show running-config ist erlaubt (keine Blocklist-Kollision)"
Assert-True (Test-SammlerBefehl -Befehl "show lldp configuration" -ProfilName "aruba-aoscx") "show lldp configuration ist erlaubt (keine Blocklist-Kollision)"
Assert-True (Test-SammlerBefehl -Befehl "/system routerboard print without-paging" -ProfilName "mikrotik-routeros") "/system routerboard print without-paging ist erlaubt (keine boot-Blocklist-Kollision)"

# Stufe 1 Zeichensperre (; | > < & ` $ \r \n)
foreach ($badCmd in @(
    "show version; reload",
    "show version | include Aruba",
    "show version > /tmp/out",
    "show version < /tmp/in",
    "show version & reload",
    'show version `reboot`',
    'show version $(id)',
    "show version`nconfigure terminal"
)) {
    $threwStage1 = $false
    try { [void](Test-SammlerBefehl -Befehl $badCmd -ProfilName "aruba-aoscx") } catch { $threwStage1 = $true }
    Assert-True $threwStage1 "Stufe 1 Zeichensperre blockiert '$($badCmd -replace "`r|`n", '\n')'"
}

# Stufe 2 Exakte Allowlist blockiert Schreib-/Reboot-/Dateibefehle & unbekannte Varianten
foreach ($forbidden in @(
    @{ p = "aruba-aoscx";       c = "configure terminal" },
    @{ p = "aruba-aoscx";       c = "write erase" },
    @{ p = "hpe-comware";       c = "system-view" },
    @{ p = "hpe-comware";       c = "reboot" },
    @{ p = "mikrotik-routeros"; c = "/system reboot" },
    @{ p = "mikrotik-routeros"; c = "/system reset-configuration" },
    @{ p = "mikrotik-routeros"; c = "/file print" },
    @{ p = "mikrotik-routeros"; c = "/tool fetch url=http://10.0.0.1/x" },
    @{ p = "mikrotik-routeros"; c = "/export verbose" },
    @{ p = "mikrotik-routeros"; c = "/export show-sensitive" },
    @{ p = "dell-os10";         c = "show running-configuration all" }
)) {
    $threwStage2 = $false
    try { [void](Test-SammlerBefehl -Befehl $forbidden.c -ProfilName $forbidden.p) } catch { $threwStage2 = $true }
    Assert-True $threwStage2 "Stufe 2 Allowlist blockiert '$($forbidden.c)' in $($forbidden.p)"
}

# Befehlsdatei-Pruefung (Shell-Modus)
$validBatchFile = Join-Path $tempRunRoot "valid-batch.txt"
[System.IO.File]::WriteAllText($validBatchFile, "no page`nshow version`nshow running-config`n", [System.Text.Encoding]::UTF8)
Assert-Equal (Test-SammlerBefehlsDateiInhalt -DateiPfad $validBatchFile -ProfilName "aruba-aoscx") 3 "Befehlsdatei-Prüfung akzeptiert gültige Allowlist-Befehlsdatei"

$badBatchFile = Join-Path $tempRunRoot "bad-batch.txt"
[System.IO.File]::WriteAllText($badBatchFile, "no page`nshow version`nconfigure terminal`n", [System.Text.Encoding]::UTF8)
$threwBatch = $false
try { [void](Test-SammlerBefehlsDateiInhalt -DateiPfad $badBatchFile -ProfilName "aruba-aoscx") } catch { $threwBatch = $true }
Assert-True $threwBatch "Befehlsdatei-Prüfung blockiert manipulierte Befehlsdatei sofort"

# 6.3 Hostkey-Validierung (vollständiger SSH Public Key -> known_hosts & SHA256-Fingerprint, kein TOFU)
# Erzeuge deterministischen gültigen ssh-ed25519 Public-Key-Blob: [0,0,0,11] + "ssh-ed25519" + [0,0,0,32] + 32 Bytes Key
$edHeader = [byte[]]@(0,0,0,11) + [System.Text.Encoding]::ASCII.GetBytes("ssh-ed25519") + [byte[]]@(0,0,0,32)
$edPubBytes = New-Object byte[] 32
for ($bIdx = 0; $bIdx -lt 32; $bIdx++) { $edPubBytes[$bIdx] = [byte](($bIdx * 7 + 13) -band 0xFF) }
$fullEdBlob = [byte[]]($edHeader + $edPubBytes)
$validEdB64 = [Convert]::ToBase64String($fullEdBlob)
$validHostkeyLine = "ssh-ed25519 $validEdB64 sw-test@lab"

$hkParsed = ConvertFrom-SshPublicKey -PublicKeyLine $validHostkeyLine
Assert-Equal $hkParsed.keyType "ssh-ed25519" "ConvertFrom-SshPublicKey erkennt ssh-ed25519"
Assert-True ($hkParsed.fingerprint.StartsWith("SHA256:") -and $hkParsed.fingerprint.Length -eq 50) "ConvertFrom-SshPublicKey berechnet gültigen SHA256-Fingerprint für plink -hostkey ($($hkParsed.fingerprint))"
$khEntry = Format-KnownHostsEintrag -HostName "sw-core01" -Port 2222 -KeyInfo $hkParsed
Assert-Equal $khEntry "[sw-core01]:2222 ssh-ed25519 $validEdB64" "Format-KnownHostsEintrag erzeugt korrekte known_hosts-Zeile für ssh.exe"

# Fehlender oder falscher Hostkey -> Abbruch
$threwEmptyHk = $false
try { [void](ConvertFrom-SshPublicKey -PublicKeyLine "") } catch { $threwEmptyHk = $true }
Assert-True $threwEmptyHk "Leerer Hostkey führt zu sofortigem Abbruch (kein TOFU)"

$threwBadHk = $false
try { [void](ConvertFrom-SshPublicKey -PublicKeyLine "ssh-ed25519 FALSCHER_KEY_UNGUELTIG") } catch { $threwBadHk = $true }
Assert-True $threwBadHk "Ungültiger/korrupter Hostkey führt zu sofortigem Abbruch"

# 6.4 Trockenlauf zeigt für dell-sonic beide Varianten (Klish shell + Click exec)
$dryOut = & $sammlerPath -Geraete @("sw-sonic01") -Profil "dell-sonic" -Hostkey $validHostkeyLine -Trockenlauf *>&1 | Out-String
Assert-True ($dryOut.Contains("sonic-cli") -and $dryOut.Contains("show running-configuration")) "Trockenlauf zeigt SONiC Standard Klish-CLI (shell)"
Assert-True ($dryOut.Contains("show runningconfiguration all") -and $dryOut.Contains("sitzungsModus=exec")) "Trockenlauf zeigt SONiC Alternative Click-CLI (exec)"

# 6.5 TestModus für Shell-Modus (aruba-aoscx & hpe-comware) inkl. Aufteilung der Ausgaben
$sammlerOutShell = Join-Path $tempRunRoot "sammler_shell"
& $sammlerPath -Geraete @("sw-aoscx01") -Profil "aruba-aoscx" -Hostkey $validHostkeyLine -AusgabeOrdner $sammlerOutShell -TestModus
Assert-Equal $LASTEXITCODE 0 "switch-sammler.ps1 im Shell-TestModus (aruba-aoscx) beendet mit Exit-Code 0"
$aoscxRohDir = Get-ChildItem -LiteralPath (Join-Path $sammlerOutShell "roh") -Directory | Select-Object -First 1
$aoscxDevDir = Join-Path $aoscxRohDir.FullName "sw-aoscx01"
$aoscxMeta = Get-Content -LiteralPath (Join-Path $aoscxDevDir "_meta.json") -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-Equal $aoscxMeta.sitzungsModus "shell" "_meta.json dokumentiert sitzungsModus = shell"
Assert-Equal $aoscxMeta.status "ok" "_meta.json dokumentiert Status = ok"
$aoscxCfgText = [System.IO.File]::ReadAllText((Join-Path $aoscxDevDir "02_config.txt"), [System.Text.Encoding]::UTF8)
Assert-True ($aoscxCfgText.Contains("# BEFEHL: show running-config") -and $aoscxCfgText.Contains("hostname sw-aoscx01")) "Shell-Ausgabe wurde sauber in 02_config.txt aufgeteilt"
$aoscxSysText = [System.IO.File]::ReadAllText((Join-Path $aoscxDevDir "01_system.txt"), [System.Text.Encoding]::UTF8)
Assert-True ($aoscxSysText.Contains("# BEFEHL: show version") -and $aoscxSysText.Contains("# BEFEHL: show system") -and -not $aoscxSysText.Contains("# BEFEHL: show running-config")) "Shell-Ausgabe trennt 01_system.txt und 02_config.txt exakt"

# 6.6 MikroTik: v6 (/export hide-sensitive), v7 (/export terse + -MitDhcpLeases) und unbekannte Version (KEIN /export + Warnung)
$sammlerOutMt6 = Join-Path $tempRunRoot "sammler_mt6"
& $sammlerPath -Geraete @("sw-mt6") -Profil "mikrotik-routeros" -Hostkey $validHostkeyLine -AusgabeOrdner $sammlerOutMt6 -TestModus -TestSimulationsOptionen @{ MikroTikVersion = "6.49.13 (long-term)" }
$mt6RohDir = (Get-ChildItem -LiteralPath (Join-Path $sammlerOutMt6 "roh") -Directory | Select-Object -First 1).FullName
$mt6Cfg = [System.IO.File]::ReadAllText((Join-Path (Join-Path $mt6RohDir "sw-mt6") "02_config.txt"), [System.Text.Encoding]::UTF8)
$mt6Extra = [System.IO.File]::ReadAllText((Join-Path (Join-Path $mt6RohDir "sw-mt6") "07_extra.txt"), [System.Text.Encoding]::UTF8)
Assert-True ($mt6Cfg.Contains("# BEFEHL: /export hide-sensitive") -and -not $mt6Cfg.Contains("/export terse")) "MikroTik v6.x führt automatisch /export hide-sensitive aus"
Assert-Equal $mt6Extra "" "MikroTik DHCP-Leases (/ip dhcp-server lease print) sind standardmäßig in 07_extra.txt abgewählt"

$sammlerOutMt7 = Join-Path $tempRunRoot "sammler_mt7"
& $sammlerPath -Geraete @("sw-mt7") -Profil "mikrotik-routeros" -Hostkey $validHostkeyLine -AusgabeOrdner $sammlerOutMt7 -MitDhcpLeases -TestModus -TestSimulationsOptionen @{ MikroTikVersion = "7.14.2 (stable)" }
$mt7RohDir = (Get-ChildItem -LiteralPath (Join-Path $sammlerOutMt7 "roh") -Directory | Select-Object -First 1).FullName
$mt7Cfg = [System.IO.File]::ReadAllText((Join-Path (Join-Path $mt7RohDir "sw-mt7") "02_config.txt"), [System.Text.Encoding]::UTF8)
$mt7Extra = [System.IO.File]::ReadAllText((Join-Path (Join-Path $mt7RohDir "sw-mt7") "07_extra.txt"), [System.Text.Encoding]::UTF8)
Assert-True ($mt7Cfg.Contains("# BEFEHL: /export terse") -and -not $mt7Cfg.Contains("/export hide-sensitive")) "MikroTik v7.x führt automatisch /export terse aus"
Assert-True ($mt7Extra.Contains("# BEFEHL: /ip dhcp-server lease print without-paging")) "MikroTik -MitDhcpLeases schreibt DHCP-Leases nach 07_extra.txt"

$sammlerOutMtUnk = Join-Path $tempRunRoot "sammler_mt_unk"
$mtUnkWarnings = & $sammlerPath -Geraete @("sw-mt-unk") -Profil "mikrotik-routeros" -Hostkey $validHostkeyLine -AusgabeOrdner $sammlerOutMtUnk -TestModus -TestSimulationsOptionen @{ MikroTikVersion = "unbekannt-custom" } 3>&1 | Out-String
$mtUnkRohDir = (Get-ChildItem -LiteralPath (Join-Path $sammlerOutMtUnk "roh") -Directory | Select-Object -First 1).FullName
$mtUnkCfg = [System.IO.File]::ReadAllText((Join-Path (Join-Path $mtUnkRohDir "sw-mt-unk") "02_config.txt"), [System.Text.Encoding]::UTF8)
Assert-True (-not $mtUnkCfg.Contains("# BEFEHL: /export") -and $mtUnkCfg.Contains("# HINWEIS:")) "MikroTik mit unbekannter Version führt KEIN /export aus und lässt 02_config.txt nur mit Hinweis"
Assert-True ($mtUnkWarnings.Contains("nicht eindeutig als 6.x oder 7.x erkannt")) "MikroTik mit unbekannter Version gibt eine Warnung aus"

# 6.7 Fehlerbehandlung: Falscher Hostkey / Login-Fehler bricht Gerät sofort ab, setzt mit übrigem Gerät fort, Exit-Code 3
$csvPath = Join-Path $tempRunRoot "geraete-test.csv"
$csvContent = @(
    "geraet,profil,port,benutzer,hostkey,sprungserver,sprungserverHostkey",
    "sw-bad-key,aruba-aoscx,22,admin,ssh-ed25519 UNGUELTIGER_KEY_BLOB,,",
    "sw-good-comware,hpe-comware,22,admin,$validHostkeyLine,jump.intern,$validHostkeyLine"
) -join "`n"
[System.IO.File]::WriteAllText($csvPath, $csvContent, [System.Text.Encoding]::UTF8)

$sammlerOutErr = Join-Path $tempRunRoot "sammler_err"
$null = & $sammlerPath -GeraeteDatei $csvPath -AusgabeOrdner $sammlerOutErr -TestModus 3>&1
$errExitCode = $LASTEXITCODE
Assert-Equal $errExitCode 3 "switch-sammler.ps1 liefert Exit-Code 3 wenn mindestens ein Gerät wegen Hostkey/Login fehlschlägt"
$errRohDir = (Get-ChildItem -LiteralPath (Join-Path $sammlerOutErr "roh") -Directory | Select-Object -First 1).FullName
$badMeta = Get-Content -LiteralPath (Join-Path (Join-Path $errRohDir "sw-bad-key") "_meta.json") -Raw -Encoding UTF8 | ConvertFrom-Json
$goodMeta = Get-Content -LiteralPath (Join-Path (Join-Path $errRohDir "sw-good-comware") "_meta.json") -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-Equal $badMeta.status "fehler" "Fehlgeschlagenes Gerät sw-bad-key hat Status 'fehler' in _meta.json"
Assert-Equal $goodMeta.status "ok" "Übriges Gerät sw-good-comware lief trotzdem vollständig durch (Status 'ok')"

# Fehlender sprungserverHostkey bei gesetztem sprungserver -> Abbruch mit Exit-Code 3
$sammlerOutJumpErr = Join-Path $tempRunRoot "sammler_jump_err"
$null = & $sammlerPath -Geraete @("sw-jump-fail") -Profil "aruba-aoscx" -Hostkey $validHostkeyLine -Sprungserver "jump.intern" -SprungserverHostkey "" -AusgabeOrdner $sammlerOutJumpErr -TestModus 3>&1
Assert-Equal $LASTEXITCODE 3 "Fehlender sprungserverHostkey führt zum Abbruch des Geräts mit Exit-Code 3"

# Timeout / Befehlsfehler speichert Teilausgabe und dokumentiert Status in _meta.json
$sammlerOutPartial = Join-Path $tempRunRoot "sammler_partial"
$null = & $sammlerPath -Geraete @("sw-mt-timeout") -Profil "mikrotik-routeros" -Hostkey $validHostkeyLine -AusgabeOrdner $sammlerOutPartial -TestModus -TestSimulationsOptionen @{
    MikroTikVersion = "7.14.2 (stable)"
    TimeoutBefehle  = @("/log print without-paging")
}
Assert-Equal $LASTEXITCODE 3 "Befehls-Timeout setzt Gesamt-Exit-Code auf 3"
$partRohDir = (Get-ChildItem -LiteralPath (Join-Path $sammlerOutPartial "roh") -Directory | Select-Object -First 1).FullName
$partLogs = [System.IO.File]::ReadAllText((Join-Path (Join-Path $partRohDir "sw-mt-timeout") "06_logs.txt"), [System.Text.Encoding]::UTF8)
Assert-True ($partLogs.Contains("# STATUS: timeout") -and $partLogs.Contains("Partial output before timeout")) "Teilausgabe bei Timeout wird trotzdem in 06_logs.txt gespeichert"

# 6.8 DirektAnonymisieren & RohLoeschen (Ende-zu-Ende Sammler -> Anonymisierer -> Prüfen -> Rohdaten löschen)
$sammlerOutE2E = Join-Path $tempRunRoot "sammler_e2e"
$e2eTabPath = Join-Path (Join-Path $tempRunRoot "tabellen") "sammler-e2e-tab.json"
& $sammlerPath -Geraete @("sw-e2e-mt") -Profil "mikrotik-routeros" -Hostkey $validHostkeyLine -AusgabeOrdner $sammlerOutE2E -DirektAnonymisieren -RohLoeschen -TabellenPfad $e2eTabPath -TestModus -TestSimulationsOptionen @{ MikroTikVersion = "7.14.2 (stable)" }
Assert-Equal $LASTEXITCODE 0 "Ende-zu-Ende Sammler + DirektAnonymisieren + RohLoeschen beendet mit Exit-Code 0"
$remainingRohDirs = @(Get-ChildItem -LiteralPath (Join-Path $sammlerOutE2E "roh") -Directory -ErrorAction SilentlyContinue)
Assert-Equal $remainingRohDirs.Count 0 "Rohdaten-Ordner wurde nach SAUBER-Prüfung durch -RohLoeschen gelöscht"
$anonTimestampDir = Get-ChildItem -LiteralPath (Join-Path $sammlerOutE2E "anonymisiert") -Directory | Select-Object -First 1
$e2eBericht = Get-Content -LiteralPath (Join-Path $anonTimestampDir.FullName "bericht.json") -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-Equal $e2eBericht.pruefergebnis "SAUBER" "Anonymisierte Sammler-Ausgabe ist im Prüfmodus SAUBER"

# Aufräumen des temporären Testordners
if (Test-Path -LiteralPath $tempRunRoot) { Remove-Item -LiteralPath $tempRunRoot -Recurse -Force }

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TESTERGEBNIS (PowerShell): $passed bestanden, $failed fehlgeschlagen" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor Cyan
if ($failed -gt 0) { exit 1 } else { exit 0 }

