<#
.SYNOPSIS
    switch-sammler.ps1 - Read-Only Switch-Datensammler (Windows PowerShell 5.1+ / PowerShell 7+)
.DESCRIPTION
    Sammelt ausschliesslich lesende Diagnose-, Konfigurations-, Nachbarschafts- und
    Zustandsdaten von Switches per SSH (ssh.exe mit Key-Auth oder plink.exe als Passwort-Fallback).

    Sicherheitsarchitektur (2-Stufen-Pruefung ohne Blocklist):
      1. Harte Zeichensperre: Verbietet jegliche Befehlsverkettung, Umleitung, Pipes
         und Steuerzeichen (; | > < & ` $ \r \n).
      2. Exakte, fest im Skript verdrahtete Allowlist pro Plattform-Profil (1:1 String-Vergleich,
         kein Regex). Die optionale Datei sammler-befehle.json darf ausschliesslich Befehle aus
         der festen Allowlist ABWAEHLEN, niemals neue Befehle ergaenzen.

    Sitzungsmodell:
      - sitzungsModus = "exec" (ein SSH-Aufruf pro Befehl): nur fuer dell-sonic (Click-CLI)
        und mikrotik-routeros.
      - sitzungsModus = "shell" (EINE SSH-Sitzung pro Geraet ueber stdin / Befehlsdatei):
        fuer aruba-aoscx, aruba-aoss, hpe-comware, dell-os10, dell-sonic (Klish-CLI Standard)
        und cisco-ios. Ausgabe wird anhand des Befehls-Echos/Prompts aufgeteilt.

    Hostkey-Pruefung (kein TOFU):
      - Pflichtfeld hostkey enthaelt den vollstaendigen SSH Public Key ("ssh-ed25519 AAAA...").
      - Daraus wird pro Lauf eine temporaere known_hosts fuer ssh.exe erzeugt und der
        SHA256-Fingerprint fuer plink.exe -hostkey berechnet.
      - Sprungserver benoetigt ebenfalls ein Pflichtfeld sprungserverHostkey.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$Geraete = @(),

    [Parameter(Mandatory = $false)]
    [ValidateSet("dell-sonic", "dell-os10", "aruba-aoscx", "aruba-aoss", "hpe-comware", "mikrotik-routeros", "cisco-ios")]
    [string]$Profil = "aruba-aoscx",

    [Parameter(Mandatory = $false)]
    [string]$Hostkey = "",

    [Parameter(Mandatory = $false)]
    [string]$GeraeteDatei = "",

    [Parameter(Mandatory = $false)]
    [string]$Benutzer = "admin",

    [Parameter(Mandatory = $false)]
    [string]$SshKeyPfad = "",

    [Parameter(Mandatory = $false)]
    [switch]$MitPasswort,

    [Parameter(Mandatory = $false)]
    [string]$PlinkPfad = "plink.exe",

    [Parameter(Mandatory = $false)]
    [string]$Sprungserver = "",

    [Parameter(Mandatory = $false)]
    [string]$SprungserverHostkey = "",

    [Parameter(Mandatory = $false)]
    [int]$Port = 22,

    [Parameter(Mandatory = $false)]
    [switch]$SonicClickCli,

    [Parameter(Mandatory = $false)]
    [switch]$MitShowTech,

    [Parameter(Mandatory = $false)]
    [switch]$MitDhcpLeases,

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSekunden = 60,

    [Parameter(Mandatory = $false)]
    [int]$ShowTechTimeoutSekunden = 600,

    [Parameter(Mandatory = $false)]
    [string]$BefehlsDatei = "",

    [Parameter(Mandatory = $false)]
    [string]$AusgabeOrdner = "",

    [Parameter(Mandatory = $false)]
    [switch]$DirektAnonymisieren,

    [Parameter(Mandatory = $false)]
    [switch]$RohLoeschen,

    [Parameter(Mandatory = $false)]
    [string]$RegelDatei = "",

    [Parameter(Mandatory = $false)]
    [string]$TabellenPfad = "",

    [Parameter(Mandatory = $false)]
    [switch]$Trockenlauf,

    [Parameter(Mandatory = $false)]
    [switch]$TestModus,

    [Parameter(Mandatory = $false)]
    [hashtable]$TestSimulationsOptionen = @{},

    [Parameter(Mandatory = $false)]
    [switch]$NurFunktionenLaden
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# 1. FEST VERDRAHTETE PLATTFORM-PROFILE & ALLOWLISTS (READ-ONLY)
# ============================================================================
function Get-FestesSammlerProfil {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfilName,
        [switch]$ClickCli
    )

    $profile = @{
        "dell-sonic-klish" = @{
            profilName    = "dell-sonic"
            variante      = "klish"
            beschreibung  = "Dell Enterprise SONiC (Standard: Klish-CLI sonic-cli)"
            sitzungsModus = "shell"
            vorspann      = @("sonic-cli", "terminal length 0")
            befehle       = @(
                @{ befehl = "show version";                zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show platform summary";       zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show system-health summary";  zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show running-configuration";  zieldatei = "02_config.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show interface status";       zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show ip interfaces";          zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show ipv6 interfaces";        zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show portchannel summary";    zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show vlan brief";             zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp table";             zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp neighbors";         zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show mac address-table";      zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ip arp";                 zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ipv6 neighbors";         zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ip route";               zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ipv6 route";             zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ip bgp summary";         zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ip ospf neighbor";       zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show vrrp";                   zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show evpn vni";               zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show logging";                zieldatei = "06_logs.txt";             standard = $true;  istShowTech = $false },
                @{ befehl = "show tech-support";           zieldatei = "07_extra.txt";            standard = $false; istShowTech = $true }
            )
        }
        "dell-sonic-click" = @{
            profilName    = "dell-sonic"
            variante      = "click"
            beschreibung  = "Dell Enterprise SONiC (Alternative: Click-CLI per -SonicClickCli)"
            sitzungsModus = "exec"
            vorspann      = @()
            befehle       = @(
                @{ befehl = "show version";                zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show platform summary";       zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show system-health summary";  zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show runningconfiguration all"; zieldatei = "02_config.txt";         standard = $true;  istShowTech = $false },
                @{ befehl = "show interfaces status";      zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show ip interfaces";          zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show ipv6 interfaces";        zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show interfaces portchannel"; zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show vlan brief";             zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp table";             zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp neighbors";         zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show mac";                    zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show arp";                    zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ndp";                    zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ip route";               zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ipv6 route";             zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ip bgp summary";         zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show logging";                zieldatei = "06_logs.txt";             standard = $true;  istShowTech = $false },
                @{ befehl = "show techsupport";            zieldatei = "07_extra.txt";            standard = $false; istShowTech = $true }
            )
        }
        "dell-os10" = @{
            profilName    = "dell-os10"
            variante      = "standard"
            beschreibung  = "Dell SmartFabric OS10"
            sitzungsModus = "shell"
            vorspann      = @("terminal length 0")
            befehle       = @(
                @{ befehl = "show version";                zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show inventory";              zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show environment";            zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show system";                 zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show running-configuration";  zieldatei = "02_config.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show interface status";       zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show ip interface brief";     zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show port-channel summary";   zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show vlan";                   zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show spanning-tree";          zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp neighbors";         zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp neighbors detail";  zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show mac address-table";      zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ip arp";                 zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ip route";               zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ipv6 route";             zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ip bgp summary";         zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ip ospf neighbor";       zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show vrrp brief";             zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show logging log-file";       zieldatei = "06_logs.txt";             standard = $true;  istShowTech = $false },
                @{ befehl = "show tech-support";           zieldatei = "07_extra.txt";            standard = $false; istShowTech = $true }
            )
        }
        "aruba-aoscx" = @{
            profilName    = "aruba-aoscx"
            variante      = "standard"
            beschreibung  = "HPE Aruba Networking AOS-CX"
            sitzungsModus = "shell"
            vorspann      = @("no page")
            befehle       = @(
                @{ befehl = "show version";                zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show system";                 zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show environment";            zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show module";                 zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show capacities-status";      zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show running-config";         zieldatei = "02_config.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show interface brief";        zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show interface";              zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show lacp interfaces";        zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show vlan";                   zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show spanning-tree";          zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp configuration";     zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp neighbor-info";     zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp neighbor-info detail"; zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true; istShowTech = $false },
                @{ befehl = "show mac-address-table";      zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show arp";                    zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ipv6 neighbors";         zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ip route";               zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ipv6 route";             zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show bgp all summary";        zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ip ospf neighbors";      zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show vrrp";                   zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show vsx status";             zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show events -r";              zieldatei = "06_logs.txt";             standard = $true;  istShowTech = $false },
                @{ befehl = "show tech";                   zieldatei = "07_extra.txt";            standard = $false; istShowTech = $true }
            )
        }
        "aruba-aoss" = @{
            profilName    = "aruba-aoss"
            variante      = "standard"
            beschreibung  = "Aruba / HPE ProCurve AOS-S"
            sitzungsModus = "shell"
            vorspann      = @("no page")
            befehle       = @(
                @{ befehl = "show version";                zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show system";                 zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show modules";                zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show flash";                  zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show running-config";         zieldatei = "02_config.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show interfaces brief";       zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show interfaces custom all";  zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show trunks";                 zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show lacp";                   zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show vlans";                  zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show spanning-tree";          zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp info remote-device"; zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true; istShowTech = $false },
                @{ befehl = "show lldp info remote-device detail"; zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true; istShowTech = $false },
                @{ befehl = "show mac-address";            zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show arp";                    zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ip route";               zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ipv6 route";             zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ip ospf neighbor";       zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show logging -r";             zieldatei = "06_logs.txt";             standard = $true;  istShowTech = $false },
                @{ befehl = "show tech all";               zieldatei = "07_extra.txt";            standard = $false; istShowTech = $true }
            )
        }
        "hpe-comware" = @{
            profilName    = "hpe-comware"
            variante      = "standard"
            beschreibung  = "HPE Comware (Comware v5 / v7)"
            sitzungsModus = "shell"
            vorspann      = @("screen-length disable")
            befehle       = @(
                @{ befehl = "display version";             zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "display device";              zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "display device manuinfo";     zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "display environment";         zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "display fan";                 zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "display power";               zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "display current-configuration"; zieldatei = "02_config.txt";         standard = $true;  istShowTech = $false },
                @{ befehl = "display interface brief";     zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "display ip interface brief";  zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "display link-aggregation summary"; zieldatei = "03_interfaces.txt";  standard = $true;  istShowTech = $false },
                @{ befehl = "display link-aggregation verbose"; zieldatei = "03_interfaces.txt";  standard = $true;  istShowTech = $false },
                @{ befehl = "display vlan all";            zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "display stp brief";           zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "display lldp neighbor-information list"; zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true; istShowTech = $false },
                @{ befehl = "display lldp neighbor-information verbose"; zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true; istShowTech = $false },
                @{ befehl = "display mac-address";         zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "display arp all";             zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "display ipv6 neighbors all";  zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "display ip routing-table";    zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "display ipv6 routing-table";  zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "display bgp peer ipv4";       zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "display ospf peer";           zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "display vrrp";                zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "display logbuffer reverse";   zieldatei = "06_logs.txt";             standard = $true;  istShowTech = $false },
                @{ befehl = "display diagnostic-information"; zieldatei = "07_extra.txt";         standard = $false; istShowTech = $true }
            )
        }
        "mikrotik-routeros" = @{
            profilName    = "mikrotik-routeros"
            variante      = "standard"
            beschreibung  = "MikroTik RouterOS (v6 / v7 mit automatischer Export-Erkennung)"
            sitzungsModus = "exec"
            vorspann      = @()
            befehle       = @(
                @{ befehl = "/system resource print without-paging";    zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "/system routerboard print without-paging"; zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "/system identity print without-paging";    zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "/system package print without-paging";     zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "/system health print without-paging";      zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "/export hide-sensitive";                   zieldatei = "02_config.txt";           standard = $true;  istShowTech = $false; nurVersion = "6" },
                @{ befehl = "/export terse";                            zieldatei = "02_config.txt";           standard = $true;  istShowTech = $false; nurVersion = "7" },
                @{ befehl = "/interface print detail without-paging";   zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "/interface ethernet print without-paging"; zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "/interface bridge print without-paging";   zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "/interface bridge port print without-paging"; zieldatei = "03_interfaces.txt";    standard = $true;  istShowTech = $false },
                @{ befehl = "/interface bridge vlan print without-paging"; zieldatei = "03_interfaces.txt";    standard = $true;  istShowTech = $false },
                @{ befehl = "/interface bonding print without-paging";  zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "/interface vlan print without-paging";     zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "/ip address print without-paging";         zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "/ipv6 address print without-paging";       zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "/ip neighbor print detail without-paging"; zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "/interface bridge host print without-paging"; zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true; istShowTech = $false },
                @{ befehl = "/ip arp print without-paging";             zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "/ipv6 neighbor print without-paging";      zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "/ip route print without-paging";           zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "/ipv6 route print without-paging";         zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "/routing bgp session print without-paging"; zieldatei = "05_routing.txt";         standard = $true;  istShowTech = $false },
                @{ befehl = "/routing ospf neighbor print without-paging"; zieldatei = "05_routing.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "/log print without-paging";                zieldatei = "06_logs.txt";             standard = $true;  istShowTech = $false },
                @{ befehl = "/ip dhcp-server lease print without-paging"; zieldatei = "07_extra.txt";          standard = $false; istShowTech = $false; istDhcpLeases = $true }
            )
        }
        "cisco-ios" = @{
            profilName    = "cisco-ios"
            variante      = "standard"
            beschreibung  = "Cisco IOS / IOS-XE / NX-OS"
            sitzungsModus = "shell"
            vorspann      = @("terminal length 0")
            befehle       = @(
                @{ befehl = "show version";                zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show inventory";              zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show environment all";        zieldatei = "01_system.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show running-config";         zieldatei = "02_config.txt";           standard = $true;  istShowTech = $false },
                @{ befehl = "show interfaces status";      zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show ip interface brief";     zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show etherchannel summary";   zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show vlan brief";             zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show spanning-tree summary";  zieldatei = "03_interfaces.txt";       standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp neighbors";         zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show lldp neighbors detail";  zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show cdp neighbors detail";   zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show mac address-table";      zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ip arp";                 zieldatei = "04_nachbarn_mac_arp.txt"; standard = $true;  istShowTech = $false },
                @{ befehl = "show ip route";               zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ipv6 route";             zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ip bgp summary";         zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show ip ospf neighbor";       zieldatei = "05_routing.txt";          standard = $true;  istShowTech = $false },
                @{ befehl = "show logging";                zieldatei = "06_logs.txt";             standard = $true;  istShowTech = $false },
                @{ befehl = "show tech-support";           zieldatei = "07_extra.txt";            standard = $false; istShowTech = $true }
            )
        }
    }

    $key = $ProfilName.ToLowerInvariant()
    if ($key -eq "dell-sonic") {
        if ($ClickCli) {
            $key = "dell-sonic-click"
        } else {
            $key = "dell-sonic-klish"
        }
    }
    if (-not $profile.ContainsKey($key)) {
        throw "Unbekanntes Plattform-Profil: '$ProfilName'"
    }
    return $profile[$key]
}

# ============================================================================
# 2. SICHERHEITSARCHITEKTUR: 2-STUFEN-ALLOWLIST (KEINE BLOCKLIST, KEIN REGEX)
# ============================================================================
function Test-SammlerBefehl {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Befehl,
        [Parameter(Mandatory = $true)]
        [string]$ProfilName,
        [switch]$ClickCli,
        [switch]$ErlaubeVorspann
    )

    if ([string]::IsNullOrWhiteSpace($Befehl)) {
        throw "SICHERHEITSVERSTOSS: Leerer Befehl ist nicht erlaubt."
    }

    # Stufe 1: Harte Zeichensperre gegen Verkettung, Pipes, Umleitungen, Subshells & Zeilenumbrueche
    $verboteneZeichen = @(';', '|', '>', '<', '&', '`', '$', "`r", "`n")
    foreach ($z in $verboteneZeichen) {
        if ($Befehl.IndexOf($z, [StringComparison]::Ordinal) -ge 0) {
            $anzeige = $z
            if ($z -eq "`r") { $anzeige = "\r" }
            elseif ($z -eq "`n") { $anzeige = "\n" }
            throw "SICHERHEITSVERSTOSS (Stufe 1 Zeichensperre): Befehl '$Befehl' enthaelt verbotenes Zeichen '$anzeige'."
        }
    }

    # Stufe 2: Exakter 1:1 String-Vergleich gegen die fest im Skript verdrahtete Allowlist
    $profilDef = Get-FestesSammlerProfil -ProfilName $ProfilName -ClickCli:$ClickCli
    $erlaubt = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($eintrag in $profilDef.befehle) {
        [void]$erlaubt.Add([string]$eintrag.befehl)
    }
    if ($ErlaubeVorspann) {
        foreach ($v in $profilDef.vorspann) {
            [void]$erlaubt.Add([string]$v)
        }
    }

    if (-not $erlaubt.Contains($Befehl)) {
        throw "SICHERHEITSVERSTOSS (Stufe 2 Exakte Allowlist): Befehl '$Befehl' ist im Profil '$ProfilName' nicht exakt freigegeben."
    }

    return $true
}

function Test-SammlerBefehlsDateiInhalt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DateiPfad,
        [Parameter(Mandatory = $true)]
        [string]$ProfilName,
        [switch]$ClickCli
    )

    if (-not (Test-Path -LiteralPath $DateiPfad)) {
        throw "Befehlsdatei '$DateiPfad' existiert nicht."
    }
    $inhalt = [System.IO.File]::ReadAllText($DateiPfad, [System.Text.Encoding]::UTF8)
    $zeilen = $inhalt -split "`r?`n"
    $gepruefteZeilen = 0
    foreach ($zeile in $zeilen) {
        if ([string]::IsNullOrEmpty($zeile)) { continue }
        [void](Test-SammlerBefehl -Befehl $zeile -ProfilName $ProfilName -ClickCli:$ClickCli -ErlaubeVorspann)
        $gepruefteZeilen++
    }
    if ($gepruefteZeilen -eq 0) {
        throw "Befehlsdatei '$DateiPfad' enthaelt keine gueltigen Befehle."
    }
    return $gepruefteZeilen
}

function Import-SammlerBefehlsAbwahl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonPfad
    )

    if (-not (Test-Path -LiteralPath $JsonPfad)) {
        throw "Befehlsdatei '$JsonPfad' nicht gefunden."
    }
    $raw = [System.IO.File]::ReadAllText($JsonPfad, [System.Text.Encoding]::UTF8)
    $parsed = $raw | ConvertFrom-Json

    # Verhindere jegliche Versuche, eigene Befehle ueber JSON einzuschleusen
    $erlaubteTopFelder = @("version", "hinweis", "abgewaehlteBefehle")
    foreach ($prop in $parsed.PSObject.Properties) {
        if ($erlaubteTopFelder -notcontains $prop.Name) {
            throw "SICHERHEITSVERSTOSS in sammler-befehle.json: Unbekanntes oder verbotenes Feld '$($prop.Name)'. Es duerfen nur Befehle ueber 'abgewaehlteBefehle' abgewählt werden."
        }
    }

    $abwahlMap = @{}
    if ($null -ne $parsed.abgewaehlteBefehle) {
        foreach ($profProp in $parsed.abgewaehlteBefehle.PSObject.Properties) {
            $pName = $profProp.Name.ToLowerInvariant()
            # Pruefe, dass das Profil existiert und alle abgewählten Befehle aus der Allowlist stammen
            $alleErlaubten = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            if ($pName -eq "dell-sonic") {
                $pKlish = Get-FestesSammlerProfil -ProfilName "dell-sonic"
                $pClick = Get-FestesSammlerProfil -ProfilName "dell-sonic" -ClickCli
                foreach ($b in $pKlish.befehle) { [void]$alleErlaubten.Add([string]$b.befehl) }
                foreach ($b in $pClick.befehle) { [void]$alleErlaubten.Add([string]$b.befehl) }
            } else {
                $pDef = Get-FestesSammlerProfil -ProfilName $pName
                foreach ($b in $pDef.befehle) { [void]$alleErlaubten.Add([string]$b.befehl) }
            }

            $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            foreach ($cmd in $profProp.Value) {
                $cmdStr = [string]$cmd
                if (-not $alleErlaubten.Contains($cmdStr)) {
                    throw "SICHERHEITSVERSTOSS in sammler-befehle.json: Befehl '$cmdStr' existiert nicht in der Allowlist von '$pName'."
                }
                [void]$set.Add($cmdStr)
            }
            $abwahlMap[$pName] = $set
        }
    }
    return $abwahlMap
}

# ============================================================================
# 3. HOSTKEY-VALIDIERUNG & SHA256-FINGERPRINT (KEIN TOFU)
# ============================================================================
function ConvertFrom-SshPublicKey {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$PublicKeyLine,
        [string]$Kontext = "hostkey"
    )

    if ([string]::IsNullOrWhiteSpace($PublicKeyLine)) {
        throw "SICHERHEITSFEHLER ($Kontext): Hostkey fehlt (Pflichtfeld, kein Trust-On-First-Use erlaubt)."
    }

    $trimmed = $PublicKeyLine.Trim()
    if ($trimmed.IndexOf("`r") -ge 0 -or $trimmed.IndexOf("`n") -ge 0) {
        throw "SICHERHEITSFEHLER ($Kontext): Hostkey darf keine Zeilenumbrueche enthalten."
    }

    $parts = $trimmed -split '\s+'
    if ($parts.Count -lt 2) {
        throw "SICHERHEITSFEHLER ($Kontext): Ungueltiges Format. Erwartet wird der vollstaendige SSH Public Key ('<key-typ> <base64-key>'), z. B. 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...'."
    }

    $keyType = $parts[0]
    $base64Blob = $parts[1]
    $erlaubteKeyTypen = @(
        "ssh-ed25519",
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521"
    )
    if ($erlaubteKeyTypen -notcontains $keyType) {
        throw "SICHERHEITSFEHLER ($Kontext): Nicht unterstuetzter oder ungueltiger SSH-Key-Typ '$keyType'."
    }

    if ($base64Blob.Length -lt 32 -or $base64Blob -notmatch '^[A-Za-z0-9+/]+={0,2}$') {
        throw "SICHERHEITSFEHLER ($Kontext): Ungueltiger Base64-Key-Blob fuer '$keyType'."
    }

    $blobBytes = $null
    try {
        $blobBytes = [Convert]::FromBase64String($base64Blob)
    } catch {
        throw "SICHERHEITSFEHLER ($Kontext): Base64-Dekodierung des SSH Public Keys fehlgeschlagen."
    }

    if ($null -eq $blobBytes -or $blobBytes.Length -lt 20) {
        throw "SICHERHEITSFEHLER ($Kontext): Dekodierter SSH Public Key ist zu kurz."
    }

    # Pruefe RFC 4253 Binary-Header im Key-Blob: [uint32 len][ascii key-type]
    $typeLen = ([int]$blobBytes[0] -shl 24) -bor ([int]$blobBytes[1] -shl 16) -bor ([int]$blobBytes[2] -shl 8) -bor [int]$blobBytes[3]
    if ($typeLen -le 0 -or $typeLen -gt 64 -or (4 + $typeLen) -ge $blobBytes.Length) {
        throw "SICHERHEITSFEHLER ($Kontext): Korrupter SSH-Key-Blob (ungueltiger Key-Header)."
    }
    $embeddedType = [System.Text.Encoding]::ASCII.GetString($blobBytes, 4, $typeLen)
    $erwarteterEmbeddedType = $keyType
    if ($keyType -eq "rsa-sha2-256" -or $keyType -eq "rsa-sha2-512") {
        $erwarteterEmbeddedType = "ssh-rsa"
    }
    if ($embeddedType -ne $erwarteterEmbeddedType -and $embeddedType -ne $keyType) {
        throw "SICHERHEITSFEHLER ($Kontext): Key-Typ im Blob ('$embeddedType') stimmt nicht mit '$keyType' ueberein."
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($blobBytes)
    } finally {
        $sha256.Dispose()
    }
    $fpBase64 = [Convert]::ToBase64String($hashBytes).TrimEnd('=')
    $fingerprint = "SHA256:$fpBase64"

    return @{
        keyType      = $keyType
        base64Blob   = $base64Blob
        publicKey    = "$keyType $base64Blob"
        fingerprint  = $fingerprint
    }
}

function Format-KnownHostsEintrag {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,
        [int]$Port = 22,
        [Parameter(Mandatory = $true)]
        [hashtable]$KeyInfo
    )
    $hostFeld = $HostName.Trim()
    if ($Port -ne 22 -and $hostFeld -notmatch '^\[.*\]:\d+$') {
        $hostFeld = "[$hostFeld]:$Port"
    }
    return "$hostFeld $($KeyInfo.keyType) $($KeyInfo.base64Blob)"
}

# ============================================================================
# 4. DATEISCHUTZ (ACL NUR FUER AKTUELLEN BENUTZER & SICHERES LOESCHEN)
# ============================================================================
function Protect-SammlerTempDatei {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Pfad
    )
    $isWin = ($env:OS -eq "Windows_NT")
    if ($isWin) {
        try {
            $acl = New-Object System.Security.AccessControl.FileSecurity
            $acl.SetAccessRuleProtection($true, $false)
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $currentUser,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $Pfad -AclObject $acl
        } catch {
            Write-Verbose "ACL-Schutz Hinweis: $($_.Exception.Message)"
        }
    } else {
        try {
            & chmod 600 $Pfad 2>$null
        } catch {}
    }
}

function Remove-SammlerTempDateiSicher {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Pfad
    )
    if ([string]::IsNullOrWhiteSpace($Pfad)) { return }
    if (Test-Path -LiteralPath $Pfad) {
        try {
            $len = (Get-Item -LiteralPath $Pfad).Length
            if ($len -lt 64) { $len = 64 }
            $zeros = New-Object byte[] $len
            [System.IO.File]::WriteAllBytes($Pfad, $zeros)
        } catch {}
        try {
            Remove-Item -LiteralPath $Pfad -Force -ErrorAction SilentlyContinue
        } catch {}
    }
}

# ============================================================================
# 5. SHELL-AUSGABE-AUFTEILUNG & MIKROTIK-VERSIONSERKENNUNG
# ============================================================================
function Split-ShellSessionOutput {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$RohAusgabe,
        [Parameter(Mandatory = $true)]
        [string[]]$BefehlsListe
    )

    $ergebnis = @{}
    foreach ($cmd in $BefehlsListe) {
        $ergebnis[$cmd] = @{
            gefunden = $false
            ausgabe  = ""
        }
    }

    if ([string]::IsNullOrEmpty($RohAusgabe)) {
        return $ergebnis
    }

    $zeilen = $RohAusgabe -split "`r?`n"
    $startIndizes = @{}
    $echoZeileIndex = @{}
    $suchStart = 0

    for ($i = 0; $i -lt $BefehlsListe.Count; $i++) {
        $cmd = $BefehlsListe[$i]
        $escapedCmd = [regex]::Escape($cmd)
        # Erkenne Prompt + Befehls-Echo (z. B. "sw-core01# show version", "<comware> display version", "OS10# show version") oder reines Befehls-Echo
        $echoRegex = "^(?:[^\r\n]*?[>#%\$\]]\s*)?$escapedCmd\s*$"

        for ($lineIdx = $suchStart; $lineIdx -lt $zeilen.Count; $lineIdx++) {
            if ($zeilen[$lineIdx] -match $echoRegex) {
                $echoZeileIndex[$i] = $lineIdx
                $startIndizes[$i] = $lineIdx + 1
                $suchStart = $lineIdx + 1
                break
            }
        }
    }

    for ($i = 0; $i -lt $BefehlsListe.Count; $i++) {
        $cmd = $BefehlsListe[$i]
        if (-not $echoZeileIndex.ContainsKey($i)) {
            continue
        }
        $von = $startIndizes[$i]
        $bis = $zeilen.Count - 1

        # Suche den naechsten gefundenen Befehl als Ende dieses Blocks
        for ($j = $i + 1; $j -lt $BefehlsListe.Count; $j++) {
            if ($echoZeileIndex.ContainsKey($j)) {
                $bis = $echoZeileIndex[$j] - 1
                break
            }
        }

        $blockZeilen = New-Object 'System.Collections.Generic.List[string]'
        for ($k = $von; $k -le $bis; $k++) {
            $blockZeilen.Add($zeilen[$k])
        }

        # Entferne abschliessende leere Prompt-/Exit-Zeilen am Ende des letzten Befehlsblocks
        while ($blockZeilen.Count -gt 0) {
            $letzte = $blockZeilen[$blockZeilen.Count - 1]
            if ($letzte -match '^\s*[A-Za-z0-9._\-()\/:\[\]~]+[>#%\$\]]\s*(?:exit|quit|logout)?\s*$') {
                $blockZeilen.RemoveAt($blockZeilen.Count - 1)
            } else {
                break
            }
        }

        $ergebnis[$cmd] = @{
            gefunden = $true
            ausgabe  = ($blockZeilen -join "`n").TrimEnd("`r", "`n")
        }
    }

    return $ergebnis
}

function Get-MikroTikHauptversion {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ResourceOutput
    )

    if ([string]::IsNullOrWhiteSpace($ResourceOutput)) {
        return $null
    }

    $m = [regex]::Match($ResourceOutput, '(?im)^\s*version:\s*([0-9]+)\.[0-9]+')
    if (-not $m.Success) {
        return $null
    }
    $major = $m.Groups[1].Value
    if ($major -eq "6" -or $major -eq "7") {
        return $major
    }
    return $null
}

# ============================================================================
# 6. PROZESS-AUSFUEHRUNG MIT TIMEOUT & TEILAUSGABEN-ERFASSUNG
# ============================================================================
function Invoke-SshProzess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Programm,
        [Parameter(Mandatory = $true)]
        [string[]]$Argumente,
        [Parameter(Mandatory = $false)]
        [string]$StdinInhalt = "",
        [int]$TimeoutSek = 60
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Programm
    # Baue ArgumentString sauber mit Quoting
    $escapedArgs = foreach ($a in $Argumente) {
        if ($a -match '[\s"]') {
            '"' + ($a -replace '"', '\"') + '"'
        } else {
            $a
        }
    }
    $psi.Arguments = ($escapedArgs -join " ")
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    $stdoutSb = New-Object System.Text.StringBuilder
    $stderrSb = New-Object System.Text.StringBuilder

    $outAction = {
        if ($null -ne $EventArgs.Data) {
            [void]$Event.MessageData.AppendLine($EventArgs.Data)
        }
    }
    $errAction = {
        if ($null -ne $EventArgs.Data) {
            [void]$Event.MessageData.AppendLine($EventArgs.Data)
        }
    }

    $outEvent = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action $outAction -MessageData $stdoutSb
    $errEvent = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action $errAction -MessageData $stderrSb

    $timedOut = $false
    try {
        [void]$proc.Start()
        $proc.BeginOutputReadLine()
        $proc.BeginErrorReadLine()

        if (-not [string]::IsNullOrEmpty($StdinInhalt)) {
            $proc.StandardInput.Write($StdinInhalt)
        }
        $proc.StandardInput.Close()

        $beendet = $proc.WaitForExit($TimeoutSek * 1000)
        if (-not $beendet) {
            $timedOut = $true
            try { $proc.Kill() } catch {}
        } else {
            $proc.WaitForExit()
        }
    } finally {
        Unregister-Event -SourceIdentifier $outEvent.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $errEvent.Name -ErrorAction SilentlyContinue
        Remove-Job -Id $outEvent.Id -Force -ErrorAction SilentlyContinue
        Remove-Job -Id $errEvent.Id -Force -ErrorAction SilentlyContinue
    }

    $exitCode = if ($timedOut) { -1 } else { $proc.ExitCode }
    $proc.Dispose()

    return @{
        exitCode = $exitCode
        timedOut = $timedOut
        stdout   = $stdoutSb.ToString().TrimEnd("`r", "`n")
        stderr   = $stderrSb.ToString().TrimEnd("`r", "`n")
    }
}

function Test-IstLoginOderHostkeyFehler {
    param(
        [AllowEmptyString()]
        [string]$StderrText,
        [AllowEmptyString()]
        [string]$StdoutText,
        [int]$ExitCode
    )

    $kombiniert = "$StderrText`n$StdoutText"
    if ($kombiniert -match '(?i)(?:Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|WARNING: POTENTIAL SECURITY BREACH|host key is not cached|host key does not match|Permission denied|Access denied|Authentication failed|Unable to authenticate|Connection refused|No supported authentication methods)') {
        return $true
    }
    if ($ExitCode -eq 255 -and $kombiniert -match '(?i)(?:ssh|host key|kex_exchange_identification|connection|auth)') {
        return $true
    }
    return $false
}

# ============================================================================
# 7. SYNTHETISCHE AUSGABEN FUER DEN OFFLINE-TESTMODUS (-TestModus)
# ============================================================================
function Get-SynthetischeBefehlsAusgabe {
    param(
        [string]$GeraeteName,
        [string]$ProfilName,
        [string]$Befehl,
        [hashtable]$SimOptionen = @{}
    )

    $mtVersion = "7.14.2 (stable)"
    if ($null -ne $SimOptionen -and $SimOptionen.ContainsKey("MikroTikVersion")) {
        $mtVersion = [string]$SimOptionen["MikroTikVersion"]
    }

    switch -Exact ($Befehl) {
        "/system resource print without-paging" {
            return @"
                   uptime: 42d11h18m05s
                  version: $mtVersion
               build-time: 2026-02-15 10:12:00
              free-memory: 892.4MiB
             total-memory: 1024.0MiB
               board-name: CRS326-24G-2S+RM
                 platform: MikroTik
"@
        }
        "/system routerboard print without-paging" {
            return @"
       routerboard: yes
        board-name: CRS326-24G-2S+RM
             model: CRS326-24G-2S+
     serial-number: HE808SYN9912
     firmware-type: dx3230L
  factory-firmware: 6.48.6
  current-firmware: 7.14.2
"@
        }
        "/system identity print without-paging" {
            return "  name: $GeraeteName"
        }
        "/export hide-sensitive" {
            return @"
# routeros 6.x export hide-sensitive
/interface bridge
add name=bridge1
/interface vlan
add interface=bridge1 name=VLAN10_Intern vlan-id=10
/interface bridge port
add bridge=bridge1 interface=ether1 comment="Uplink Core"
/system identity
set name=$GeraeteName
/ip address
add address=10.20.30.11/24 interface=VLAN10_Intern
/snmp
set contact="Netzbetrieb +49 89 12345" enabled=yes location="Rechenzentrum-Nord Rack 4"
"@
        }
        "/export terse" {
            return @"
# routeros 7.x export terse
/interface bridge add name=bridge1
/interface vlan add interface=bridge1 name=VLAN10_Intern vlan-id=10
/interface bridge port add bridge=bridge1 interface=ether1 comment="Uplink Core"
/system identity set name=$GeraeteName
/user add name=tikadmin group=full password=Geheim123!
/interface wireguard add listen-port=13231 name=wg_standort private-key="cGxhY2Vob2xkZXJfcHJpdmF0ZV9rZXlfMTIzNDU2Nzg="
/interface wireguard peers add interface=wg_standort public-key="cHVibGljX2tleV9leGFtcGxlX2Jhc2U2NF8xMjM0NTY="
/ip address add address=10.20.30.11/24 interface=VLAN10_Intern
/snmp set contact="Netzbetrieb +49 89 12345" enabled=yes location="Rechenzentrum-Nord Rack 4"
"@
        }
        "/ip dhcp-server lease print without-paging" {
            return @"
Flags: D - DYNAMIC
Columns: ADDRESS, MAC-ADDRESS, HOST-NAME, SERVER, STATUS
#   ADDRESS        MAC-ADDRESS        HOST-NAME      SERVER  STATUS
0 D 10.20.30.150   AA:BB:CC:11:22:33  nb-mueller-01  dhcp1   bound
"@
        }
        "display current-configuration" {
            return @"
#
 version 7.1.070, Release 6316
#
 sysname $GeraeteName
#
 header motd %Nur fuer autorisierte Admins der Musterfirma GmbH%
#
 local-user netops class manage
  password cipher `$c`$3`$uZ8kP9mN2qL5vR7x
  service-type ssh terminal
#
 snmp-agent community read cipher `$c`$3`$ReadSec99
 snmp-agent sys-info contact Max Mustermann
 snmp-agent sys-info location Rechenzentrum-Nord
#
 interface Bridge-Aggregation10
  description Uplink_Core_rz1-sw-core01
#
 interface Vlan-interface10
  ip address 10.20.30.12 255.255.255.0
#
return
"@
        }
        "show running-config" {
            return @"
hostname $GeraeteName
user admin group administrators password ciphertext AQBap99213ExampleSecret
snmp-server system-location Rechenzentrum-Nord Rack 2
snmp-server system-contact Max Mustermann
vlan 10
    name VLAN10_Intern
interface 1/1/1
    description Uplink_rz1-sw-core01
    ip address 10.20.30.13/24
"@
        }
        "show running-configuration" {
            return @"
hostname $GeraeteName
username netadmin password 9 `$9`$SaltHashExample123456 role sysadmin
snmp-server location "Rechenzentrum-Nord"
snmp-server contact "Max Mustermann"
interface ethernet1/1/1
 description "Uplink_rz1-sw-core01"
 ip address 10.20.30.14/24
"@
        }
        "show runningconfiguration all" {
            return @"
{
  "DEVICE_METADATA": {
    "localhost": {
      "hostname": "$GeraeteName",
      "mac": "00:1a:2b:3c:4d:5e"
    }
  },
  "INTERFACE": {
    "Ethernet0|10.20.30.15/24": {}
  }
}
"@
        }
        default {
            return @"
# Synthetische Testausgabe fuer $GeraeteName ($ProfilName)
Befehl: $Befehl
System Name: $GeraeteName
Management IP: 10.20.30.10/24
Neighbor: rz1-sw-core01 (00:1a:2b:3c:4d:5e)
Serial Number: SN-TEST-987654
"@
        }
    }
}

# Erlaube Dot-Sourcing fuer Unit-Tests ohne Hauptlauf
if ($NurFunktionenLaden) {
    return
}

# ============================================================================
# 8. GERAETELISTE LADEN & PARAMETER PRUEFEN
# ============================================================================
$skriptOrdner = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($skriptOrdner)) {
    $skriptOrdner = (Get-Location).Path
}

if ([string]::IsNullOrWhiteSpace($AusgabeOrdner)) {
    $AusgabeOrdner = Join-Path $skriptOrdner "sammler-ausgabe"
}

$abwahlProProfil = @{}
if (-not [string]::IsNullOrWhiteSpace($BefehlsDatei)) {
    $abwahlProProfil = Import-SammlerBefehlsAbwahl -JsonPfad $BefehlsDatei
} else {
    $defaultBefehlsJson = Join-Path $skriptOrdner "sammler-befehle.json"
    if (Test-Path -LiteralPath $defaultBefehlsJson) {
        $abwahlProProfil = Import-SammlerBefehlsAbwahl -JsonPfad $defaultBefehlsJson
    }
}

$geraeteListe = New-Object 'System.Collections.Generic.List[hashtable]'

if (-not [string]::IsNullOrWhiteSpace($GeraeteDatei)) {
    if (-not (Test-Path -LiteralPath $GeraeteDatei)) {
        throw "Geraetedatei '$GeraeteDatei' wurde nicht gefunden."
    }
    $ext = [System.IO.Path]::GetExtension($GeraeteDatei).ToLowerInvariant()
    if ($ext -eq ".json") {
        $jsonItems = ([System.IO.File]::ReadAllText($GeraeteDatei, [System.Text.Encoding]::UTF8) | ConvertFrom-Json)
        foreach ($item in $jsonItems) {
            $gPort = if ($null -ne $item.PSObject.Properties["port"] -and "$($item.port)" -ne "") { [int]$item.port } else { $Port }
            $gBenutzer = if ($null -ne $item.PSObject.Properties["benutzer"] -and "$($item.benutzer)" -ne "") { [string]$item.benutzer } else { $Benutzer }
            $gHostkey = if ($null -ne $item.PSObject.Properties["hostkey"]) { [string]$item.hostkey } else { "" }
            $gJump = if ($null -ne $item.PSObject.Properties["sprungserver"] -and "$($item.sprungserver)" -ne "") { [string]$item.sprungserver } else { $Sprungserver }
            $gJumpKey = if ($null -ne $item.PSObject.Properties["sprungserverHostkey"] -and "$($item.sprungserverHostkey)" -ne "") { [string]$item.sprungserverHostkey } else { $SprungserverHostkey }
            $gLegacy = if ($null -ne $item.PSObject.Properties["legacyKex"] -and ("$($item.legacyKex)" -match '^(?i:true|1|ja|yes)$')) { $true } else { $false }
            $gClick = if ($null -ne $item.PSObject.Properties["sonicClickCli"] -and ("$($item.sonicClickCli)" -match '^(?i:true|1|ja|yes)$')) { $true } else { [bool]$SonicClickCli }

            $geraeteListe.Add(@{
                geraet              = [string]$item.geraet
                profil              = ([string]$item.profil).ToLowerInvariant()
                port                = $gPort
                benutzer            = $gBenutzer
                hostkey             = $gHostkey
                sprungserver        = $gJump
                sprungserverHostkey = $gJumpKey
                legacyKex           = $gLegacy
                sonicClickCli       = $gClick
            })
        }
    } else {
        $csvItems = Import-Csv -LiteralPath $GeraeteDatei -Encoding UTF8
        foreach ($row in $csvItems) {
            if ([string]::IsNullOrWhiteSpace($row.geraet)) { continue }
            $gPort = if ($null -ne $row.PSObject.Properties["port"] -and "$($row.port)" -ne "") { [int]$row.port } else { $Port }
            $gBenutzer = if ($null -ne $row.PSObject.Properties["benutzer"] -and "$($row.benutzer)" -ne "") { [string]$row.benutzer } else { $Benutzer }
            $gHostkey = if ($null -ne $row.PSObject.Properties["hostkey"]) { [string]$row.hostkey } else { "" }
            $gJump = if ($null -ne $row.PSObject.Properties["sprungserver"] -and "$($row.sprungserver)" -ne "") { [string]$row.sprungserver } else { $Sprungserver }
            $gJumpKey = if ($null -ne $row.PSObject.Properties["sprungserverHostkey"] -and "$($row.sprungserverHostkey)" -ne "") { [string]$row.sprungserverHostkey } else { $SprungserverHostkey }
            $gLegacy = if ($null -ne $row.PSObject.Properties["legacyKex"] -and ("$($row.legacyKex)" -match '^(?i:true|1|ja|yes)$')) { $true } else { $false }
            $gClick = if ($null -ne $row.PSObject.Properties["sonicClickCli"] -and ("$($row.sonicClickCli)" -match '^(?i:true|1|ja|yes)$')) { $true } else { [bool]$SonicClickCli }

            $geraeteListe.Add(@{
                geraet              = [string]$row.geraet
                profil              = ([string]$row.profil).ToLowerInvariant()
                port                = $gPort
                benutzer            = $gBenutzer
                hostkey             = $gHostkey
                sprungserver        = $gJump
                sprungserverHostkey = $gJumpKey
                legacyKex           = $gLegacy
                sonicClickCli       = $gClick
            })
        }
    }
} elseif ($Geraete.Count -gt 0) {
    foreach ($g in $Geraete) {
        $geraeteListe.Add(@{
            geraet              = [string]$g
            profil              = $Profil.ToLowerInvariant()
            port                = $Port
            benutzer            = $Benutzer
            hostkey             = $Hostkey
            sprungserver        = $Sprungserver
            sprungserverHostkey = $SprungserverHostkey
            legacyKex           = $false
            sonicClickCli       = [bool]$SonicClickCli
        })
    }
} else {
    throw "Bitte mindestens ein Geraet ueber -Geraete oder -GeraeteDatei angeben."
}

# ============================================================================
# 9. TROCKENLAUF (-Trockenlauf): BEFEHLE, SITZUNGSMODUS & HOSTKEY-STATUS ZEIGEN
# ============================================================================
if ($Trockenlauf) {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " TROCKENLAUF (KEINE SSH-VERBINDUNG)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    foreach ($g in $geraeteListe) {
        $gName = $g.geraet
        $pName = $g.profil
        Write-Host ""
        Write-Host "Geraet: $gName | Profil: $pName | Port: $($g.port) | Benutzer: $($g.benutzer)" -ForegroundColor Yellow

        # Pruefe Hostkey bereits im Trockenlauf
        $hkInfo = ConvertFrom-SshPublicKey -PublicKeyLine $g.hostkey -Kontext "Geraet '$gName' (hostkey)"
        Write-Host "  Hostkey-Typ        : $($hkInfo.keyType)"
        Write-Host "  Plink-Fingerprint  : $($hkInfo.fingerprint)"

        if (-not [string]::IsNullOrWhiteSpace($g.sprungserver)) {
            $jkInfo = ConvertFrom-SshPublicKey -PublicKeyLine $g.sprungserverHostkey -Kontext "Sprungserver '$($g.sprungserver)' (sprungserverHostkey)"
            Write-Host "  Sprungserver       : $($g.sprungserver) ($($jkInfo.fingerprint))"
        }

        if ($pName -eq "dell-sonic") {
            # Beide Varianten (Standard Klish-CLI und Alternative Click-CLI) im Trockenlauf anzeigen
            $klishDef = Get-FestesSammlerProfil -ProfilName "dell-sonic"
            $clickDef = Get-FestesSammlerProfil -ProfilName "dell-sonic" -ClickCli
            $aktiveVar = if ($g.sonicClickCli) { "Click-CLI (-SonicClickCli aktiv)" } else { "Klish-CLI (Standard)" }
            Write-Host "  Aktive SONiC-CLI   : $aktiveVar"
            Write-Host "  --- Variante 1 (Standard): $($klishDef.beschreibung) [sitzungsModus=$($klishDef.sitzungsModus)] ---"
            foreach ($v in $klishDef.vorspann) {
                [void](Test-SammlerBefehl -Befehl $v -ProfilName "dell-sonic" -ErlaubeVorspann)
                Write-Host "    [VORSPANN]           $v"
            }
            foreach ($b in $klishDef.befehle) {
                if ($b.istShowTech -and -not $MitShowTech) { continue }
                if ($abwahlProProfil.ContainsKey("dell-sonic") -and $abwahlProProfil["dell-sonic"].Contains([string]$b.befehl)) { continue }
                [void](Test-SammlerBefehl -Befehl $b.befehl -ProfilName "dell-sonic")
                Write-Host "    [$($b.zieldatei)] $($b.befehl)"
            }
            Write-Host "  --- Variante 2 (Alternative -SonicClickCli): $($clickDef.beschreibung) [sitzungsModus=$($clickDef.sitzungsModus)] ---"
            foreach ($b in $clickDef.befehle) {
                if ($b.istShowTech -and -not $MitShowTech) { continue }
                if ($abwahlProProfil.ContainsKey("dell-sonic") -and $abwahlProProfil["dell-sonic"].Contains([string]$b.befehl)) { continue }
                [void](Test-SammlerBefehl -Befehl $b.befehl -ProfilName "dell-sonic" -ClickCli)
                Write-Host "    [$($b.zieldatei)] $($b.befehl)"
            }
        } else {
            $profDef = Get-FestesSammlerProfil -ProfilName $pName
            Write-Host "  Sitzungsmodus      : $($profDef.sitzungsModus)"
            foreach ($v in $profDef.vorspann) {
                [void](Test-SammlerBefehl -Befehl $v -ProfilName $pName -ErlaubeVorspann)
                Write-Host "    [VORSPANN]           $v"
            }
            foreach ($b in $profDef.befehle) {
                if ($b.istShowTech -and -not $MitShowTech) { continue }
                if ($b.ContainsKey("istDhcpLeases") -and $b.istDhcpLeases -and -not $MitDhcpLeases) { continue }
                if ($abwahlProProfil.ContainsKey($pName) -and $abwahlProProfil[$pName].Contains([string]$b.befehl)) { continue }
                [void](Test-SammlerBefehl -Befehl $b.befehl -ProfilName $pName)
                $zusatz = ""
                if ($b.ContainsKey("nurVersion")) { $zusatz = " (automatisch bei RouterOS v$($b.nurVersion).x)" }
                Write-Host "    [$($b.zieldatei)] $($b.befehl)$zusatz"
            }
        }
    }
    exit 0
}

# ============================================================================
# 10. HAUPTLAUF: SAMMELN PRO GERAET (EXEC ODER SHELL)
# ============================================================================
$zeitstempel = (Get-Date).ToString("yyyyMMdd-HHmmss")
$rohBasisOrdner = Join-Path (Join-Path $AusgabeOrdner "roh") $zeitstempel
[void](New-Item -ItemType Directory -Path $rohBasisOrdner -Force)

$tempKnownHosts = Join-Path ([System.IO.Path]::GetTempPath()) ("sammler_known_hosts_" + [guid]::NewGuid().ToString("N") + ".txt")
$tempPwFile = ""
$tempBefehlsDateien = New-Object 'System.Collections.Generic.List[string]'
$mindestensEinGeraetFehlgeschlagen = $false

try {
    # Passwort-Fallback nur interaktiv per Read-Host -AsSecureString
    if ($MitPasswort -and -not $TestModus) {
        $secPw = Read-Host -Prompt "SSH-Passwort fuer plink.exe eingeben" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPw)
        try {
            $plainPw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            $tempPwFile = Join-Path ([System.IO.Path]::GetTempPath()) ("sammler_pw_" + [guid]::NewGuid().ToString("N") + ".txt")
            [System.IO.File]::WriteAllText($tempPwFile, $plainPw, (New-Object System.Text.UTF8Encoding($false)))
            Protect-SammlerTempDatei -Pfad $tempPwFile
        } finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    [System.IO.File]::WriteAllText($tempKnownHosts, "", (New-Object System.Text.UTF8Encoding($false)))
    Protect-SammlerTempDatei -Pfad $tempKnownHosts

    foreach ($g in $geraeteListe) {
        $gName = $g.geraet
        $pName = $g.profil
        $gClick = [bool]$g.sonicClickCli
        $sichererGeraeteOrdnerName = ($gName -replace '[^A-Za-z0-9._-]', '_')
        $geraeteRohOrdner = Join-Path $rohBasisOrdner $sichererGeraeteOrdnerName
        [void](New-Item -ItemType Directory -Path $geraeteRohOrdner -Force)

        $startZeit = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $befehlsMeta = New-Object 'System.Collections.Generic.List[hashtable]'
        $geraetStatus = "ok"
        $geraetFehlerMeldung = ""

        # 1. Hostkey & optionalen Sprungserver-Hostkey validieren (kein TOFU!)
        $hkInfo = $null
        $jkInfo = $null
        try {
            $hkInfo = ConvertFrom-SshPublicKey -PublicKeyLine $g.hostkey -Kontext "Geraet '$gName' (hostkey)"
            $khLine = Format-KnownHostsEintrag -HostName $gName -Port $g.port -KeyInfo $hkInfo
            [System.IO.File]::AppendAllText($tempKnownHosts, "$khLine`n", (New-Object System.Text.UTF8Encoding($false)))

            if (-not [string]::IsNullOrWhiteSpace($g.sprungserver)) {
                $jkInfo = ConvertFrom-SshPublicKey -PublicKeyLine $g.sprungserverHostkey -Kontext "Sprungserver '$($g.sprungserver)' fuer '$gName' (sprungserverHostkey)"
                $jkLine = Format-KnownHostsEintrag -HostName $g.sprungserver -Port 22 -KeyInfo $jkInfo
                [System.IO.File]::AppendAllText($tempKnownHosts, "$jkLine`n", (New-Object System.Text.UTF8Encoding($false)))
            }
        } catch {
            $geraetStatus = "fehler"
            $geraetFehlerMeldung = $_.Exception.Message
            $mindestensEinGeraetFehlgeschlagen = $true
            Write-Warning "Geraet '$gName' sofort abgebrochen: $geraetFehlerMeldung"

            $metaObj = [ordered]@{
                geraet             = $gName
                profil             = $pName
                sitzungsModus      = "abgebrochen"
                port               = $g.port
                startUtc           = $startZeit
                endeUtc            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                status             = $geraetStatus
                fehler             = $geraetFehlerMeldung
                befehle            = @()
            }
            $metaPfad = Join-Path $geraeteRohOrdner "_meta.json"
            [System.IO.File]::WriteAllText($metaPfad, ($metaObj | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
            continue
        }

        # Simuliere Login-/Hostkey-Fehler im TestModus falls angefordert
        if ($TestModus -and $null -ne $TestSimulationsOptionen -and $TestSimulationsOptionen.ContainsKey("LoginFehlerGeraete")) {
            $fehlerGeraete = $TestSimulationsOptionen["LoginFehlerGeraete"]
            if ($fehlerGeraete -contains $gName) {
                $geraetStatus = "fehler"
                $geraetFehlerMeldung = "SSH Login-/Hostkey-Fehler fuer '$gName': Permission denied / Host key verification failed"
                $mindestensEinGeraetFehlgeschlagen = $true
                Write-Warning "Geraet '$gName' wegen Login-/Hostkey-Fehler sofort abgebrochen (kein Retry)."

                $profDefTmp = Get-FestesSammlerProfil -ProfilName $pName -ClickCli:$gClick
                $metaObj = [ordered]@{
                    geraet             = $gName
                    profil             = $pName
                    sitzungsModus      = $profDefTmp.sitzungsModus
                    hostkeyFingerprint = $hkInfo.fingerprint
                    port               = $g.port
                    startUtc           = $startZeit
                    endeUtc            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    status             = $geraetStatus
                    fehler             = $geraetFehlerMeldung
                    befehle            = @()
                }
                $metaPfad = Join-Path $geraeteRohOrdner "_meta.json"
                [System.IO.File]::WriteAllText($metaPfad, ($metaObj | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
                continue
            }
        }

        $profDef = Get-FestesSammlerProfil -ProfilName $pName -ClickCli:$gClick
        $sitzungsModus = $profDef.sitzungsModus

        # Filtere aktive Befehle fuer dieses Geraet
        $aktiveBefehlsEintraege = New-Object 'System.Collections.Generic.List[hashtable]'
        foreach ($b in $profDef.befehle) {
            if ($b.istShowTech -and -not $MitShowTech) { continue }
            if ($b.ContainsKey("istDhcpLeases") -and $b.istDhcpLeases -and -not $MitDhcpLeases) { continue }
            if ($abwahlProProfil.ContainsKey($pName) -and $abwahlProProfil[$pName].Contains([string]$b.befehl)) { continue }
            # 2-Stufen-Allowlist-Pruefung fuer jeden Befehl vorab
            [void](Test-SammlerBefehl -Befehl ([string]$b.befehl) -ProfilName $pName -ClickCli:$gClick)
            $aktiveBefehlsEintraege.Add($b)
        }
        foreach ($v in $profDef.vorspann) {
            [void](Test-SammlerBefehl -Befehl ([string]$v) -ProfilName $pName -ClickCli:$gClick -ErlaubeVorspann)
        }

        # Sammler-Puffer pro Zieldatei (01_system.txt .. 07_extra.txt)
        $dateiInhalte = @{}
        $standardDateien = @(
            "01_system.txt",
            "02_config.txt",
            "03_interfaces.txt",
            "04_nachbarn_mac_arp.txt",
            "05_routing.txt",
            "06_logs.txt",
            "07_extra.txt"
        )
        foreach ($dn in $standardDateien) {
            $dateiInhalte[$dn] = New-Object 'System.Collections.Generic.List[string]'
        }

        # Hilfsfunktion zum Aufbau der SSH/Plink-Argumente
        $buildSshArgs = {
            param([string]$EinzelBefehl = "", [string]$ShellBatchDatei = "")
            if ($MitPasswort) {
                $pArgs = @("-batch", "-P", "$($g.port)", "-l", $g.benutzer, "-hostkey", $hkInfo.fingerprint, "-pwfile", $tempPwFile)
                if (-not [string]::IsNullOrWhiteSpace($g.sprungserver)) {
                    $proxyCmd = "$PlinkPfad -batch -hostkey $($jkInfo.fingerprint) -pwfile `"$tempPwFile`" -nc %host:%port $($g.sprungserver)"
                    $pArgs += @("-proxycmd", $proxyCmd)
                }
                if (-not [string]::IsNullOrWhiteSpace($ShellBatchDatei)) {
                    $pArgs += @("-m", $ShellBatchDatei, $gName)
                } else {
                    $pArgs += @($gName, $EinzelBefehl)
                }
                return @{ prog = $PlinkPfad; args = $pArgs }
            } else {
                $sArgs = @(
                    "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=yes",
                    "-o", "UserKnownHostsFile=$tempKnownHosts",
                    "-o", "ConnectTimeout=15",
                    "-p", "$($g.port)"
                )
                if (-not [string]::IsNullOrWhiteSpace($SshKeyPfad)) {
                    $sArgs += @("-i", $SshKeyPfad)
                }
                if ($g.legacyKex) {
                    $sArgs += @(
                        "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256",
                        "-o", "HostKeyAlgorithms=+ssh-rsa"
                    )
                }
                if (-not [string]::IsNullOrWhiteSpace($g.sprungserver)) {
                    $sArgs += @("-J", $g.sprungserver)
                }
                if (-not [string]::IsNullOrWhiteSpace($ShellBatchDatei)) {
                    $sArgs += @("-T", "$($g.benutzer)@$gName")
                } else {
                    $sArgs += @("$($g.benutzer)@$gName", $EinzelBefehl)
                }
                return @{ prog = "ssh.exe"; args = $sArgs }
            }
        }

        if ($sitzungsModus -eq "shell") {
            # ====================================================================
            # SHELL-MODUS: EINE SSH-Sitzung pro Geraet ueber Befehlsdatei / stdin
            # ====================================================================
            $alleSitzungsBefehle = New-Object 'System.Collections.Generic.List[string]'
            foreach ($v in $profDef.vorspann) {
                $alleSitzungsBefehle.Add([string]$v)
            }
            foreach ($b in $aktiveBefehlsEintraege) {
                $alleSitzungsBefehle.Add([string]$b.befehl)
            }

            # Schreibe temporaere Befehlsdatei mit Benutzer-ACL und pruefe sie gegen die 2-Stufen-Allowlist
            $tempBatchPfad = Join-Path ([System.IO.Path]::GetTempPath()) ("sammler_cmd_" + $sichererGeraeteOrdnerName + "_" + [guid]::NewGuid().ToString("N") + ".txt")
            $tempBefehlsDateien.Add($tempBatchPfad)
            $batchText = ($alleSitzungsBefehle -join "`n") + "`n"
            [System.IO.File]::WriteAllText($tempBatchPfad, $batchText, (New-Object System.Text.UTF8Encoding($false)))
            Protect-SammlerTempDatei -Pfad $tempBatchPfad

            # Pflichtpruefung: Befehlsdatei unterliegt derselben 2-Stufen-Allowlist-Pruefung
            [void](Test-SammlerBefehlsDateiInhalt -DateiPfad $tempBatchPfad -ProfilName $pName -ClickCli:$gClick)

            $hatShowTech = $false
            foreach ($b in $aktiveBefehlsEintraege) {
                if ($b.istShowTech) { $hatShowTech = $true }
            }
            $sitzungsTimeout = if ($hatShowTech) { $ShowTechTimeoutSekunden } else { [Math]::Max($TimeoutSekunden, 60) }

            $rawShellOutput = ""
            $shellTimedOut = $false
            $shellExitCode = 0
            $shellStderr = ""

            if ($TestModus) {
                # Erzeuge im TestModus einen kombinierten Shell-Transkript-Stream mit Prompts + Befehls-Echos
                $simLines = New-Object 'System.Collections.Generic.List[string]'
                $promptPrefix = if ($pName -eq "hpe-comware") { "<$gName>" } else { "$gName#" }
                foreach ($v in $profDef.vorspann) {
                    $simLines.Add("$promptPrefix $v")
                }
                foreach ($b in $aktiveBefehlsEintraege) {
                    $cmdStr = [string]$b.befehl
                    $simLines.Add("$promptPrefix $cmdStr")
                    $outBlock = Get-SynthetischeBefehlsAusgabe -GeraeteName $gName -ProfilName $pName -Befehl $cmdStr -SimOptionen $TestSimulationsOptionen
                    $simLines.Add($outBlock)
                }
                $simLines.Add("$promptPrefix exit")
                $rawShellOutput = ($simLines -join "`n")

                if ($null -ne $TestSimulationsOptionen -and $TestSimulationsOptionen.ContainsKey("TimeoutGeraete") -and ($TestSimulationsOptionen["TimeoutGeraete"] -contains $gName)) {
                    $shellTimedOut = $true
                    $shellExitCode = -1
                }
            } else {
                $callSpec = & $buildSshArgs "" $tempBatchPfad
                $stdinText = if ($MitPasswort) { "" } else { $batchText }
                $res = Invoke-SshProzess -Programm $callSpec.prog -Argumente $callSpec.args -StdinInhalt $stdinText -TimeoutSek $sitzungsTimeout
                $rawShellOutput = $res.stdout
                $shellStderr = $res.stderr
                $shellTimedOut = $res.timedOut
                $shellExitCode = $res.exitCode

                if (Test-IstLoginOderHostkeyFehler -StderrText $shellStderr -StdoutText $rawShellOutput -ExitCode $shellExitCode) {
                    $geraetStatus = "fehler"
                    $geraetFehlerMeldung = "SSH Login-/Hostkey-Fehler: $shellStderr"
                    $mindestensEinGeraetFehlgeschlagen = $true
                    Write-Warning "Geraet '$gName' wegen Login-/Hostkey-Fehler sofort abgebrochen."

                    $metaObj = [ordered]@{
                        geraet             = $gName
                        profil             = $pName
                        sitzungsModus      = $sitzungsModus
                        hostkeyFingerprint = $hkInfo.fingerprint
                        port               = $g.port
                        startUtc           = $startZeit
                        endeUtc            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                        status             = $geraetStatus
                        fehler             = $geraetFehlerMeldung
                        befehle            = @()
                    }
                    $metaPfad = Join-Path $geraeteRohOrdner "_meta.json"
                    [System.IO.File]::WriteAllText($metaPfad, ($metaObj | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
                    continue
                }
            }

            # Teile die kombinierte Shell-Ausgabe anhand der Befehls-Echos/Prompts auf
            $aufgeteilt = Split-ShellSessionOutput -RohAusgabe $rawShellOutput -BefehlsListe ([string[]]$alleSitzungsBefehle.ToArray())

            foreach ($b in $aktiveBefehlsEintraege) {
                $cmdStr = [string]$b.befehl
                $ziel = [string]$b.zieldatei
                $teil = $aufgeteilt[$cmdStr]
                $cmdStatus = "ok"
                $cmdText = ""

                if ($null -ne $teil -and $teil.gefunden) {
                    $cmdText = $teil.ausgabe
                    if ($shellTimedOut) {
                        $cmdStatus = "timeout"
                        $geraetStatus = "teilweise_fehler"
                        $mindestensEinGeraetFehlgeschlagen = $true
                    } elseif ($shellExitCode -ne 0) {
                        $cmdStatus = "fehler"
                        $geraetStatus = "teilweise_fehler"
                        $mindestensEinGeraetFehlgeschlagen = $true
                    }
                } else {
                    $cmdStatus = if ($shellTimedOut) { "timeout" } else { "fehler" }
                    $geraetStatus = "teilweise_fehler"
                    $mindestensEinGeraetFehlgeschlagen = $true
                    $cmdText = if (-not [string]::IsNullOrWhiteSpace($shellStderr)) { "# FEHLER/TEILAUSGABE:`n$shellStderr" } else { "# KEINE AUSGABE ERHALTEN" }
                }

                # Speichere Ausgabe (auch Fehler-/Teilausgabe) in der Zieldatei
                $dateiInhalte[$ziel].Add("============================================================")
                $dateiInhalte[$ziel].Add("# BEFEHL: $cmdStr")
                $dateiInhalte[$ziel].Add("# STATUS: $cmdStatus")
                $dateiInhalte[$ziel].Add("============================================================")
                $dateiInhalte[$ziel].Add($cmdText)
                $dateiInhalte[$ziel].Add("")

                $befehlsMeta.Add([ordered]@{
                    befehl    = $cmdStr
                    zieldatei = $ziel
                    status    = $cmdStatus
                    zeilen    = if ([string]::IsNullOrEmpty($cmdText)) { 0 } else { ($cmdText -split "`r?`n").Count }
                })
            }
        } else {
            # ====================================================================
            # EXEC-MODUS: Ein SSH-Aufruf pro Befehl (SONiC Click-CLI & MikroTik)
            # ====================================================================
            $erkannteMikroTikVersion = $null
            $mikroTikVersionGeprueft = $false

            foreach ($b in $aktiveBefehlsEintraege) {
                $cmdStr = [string]$b.befehl
                $ziel = [string]$b.zieldatei

                # Spezialbehandlung fuer MikroTik /export (erst nach /system resource print)
                if ($pName -eq "mikrotik-routeros" -and $b.ContainsKey("nurVersion")) {
                    if (-not $mikroTikVersionGeprueft) {
                        $mikroTikVersionGeprueft = $true
                    }
                    if ([string]::IsNullOrEmpty($erkannteMikroTikVersion)) {
                        # Version wurde NICHT eindeutig als 6.x oder 7.x erkannt -> KEIN /export ausfuehren!
                        if ($b.nurVersion -eq "6") {
                            $warnText = "MikroTik RouterOS-Version auf '$gName' konnte nicht eindeutig als 6.x oder 7.x erkannt werden. /export wird NICHT ausgefuehrt!"
                            Write-Warning $warnText
                            $dateiInhalte["02_config.txt"].Add("# HINWEIS: RouterOS-Version aus '/system resource print' nicht eindeutig als 6.x oder 7.x erkannt. Kein /export ausgefuehrt.")
                            $befehlsMeta.Add([ordered]@{
                                befehl    = "/export (uebersprungen: unbekannte Version)"
                                zieldatei = "02_config.txt"
                                status    = "uebersprungen"
                                zeilen    = 0
                            })
                        }
                        continue
                    }
                    if ($b.nurVersion -ne $erkannteMikroTikVersion) {
                        # Andere Hauptversion (z. B. v6-Export bei erkannter v7) still ueberspringen
                        continue
                    }
                }

                # 2-Stufen-Allowlist-Pruefung unmittelbar vor Ausfuehrung
                [void](Test-SammlerBefehl -Befehl $cmdStr -ProfilName $pName -ClickCli:$gClick)

                $cmdTimeout = if ($b.istShowTech) { $ShowTechTimeoutSekunden } else { $TimeoutSekunden }
                $cmdStatus = "ok"
                $cmdOutput = ""

                if ($TestModus) {
                    if ($null -ne $TestSimulationsOptionen -and $TestSimulationsOptionen.ContainsKey("FehlerBefehle") -and ($TestSimulationsOptionen["FehlerBefehle"] -contains $cmdStr)) {
                        $cmdStatus = "fehler"
                        $cmdOutput = "# TEILAUSGABE VOR FEHLER:`nERROR: command execution interrupted"
                        $geraetStatus = "teilweise_fehler"
                        $mindestensEinGeraetFehlgeschlagen = $true
                    } elseif ($null -ne $TestSimulationsOptionen -and $TestSimulationsOptionen.ContainsKey("TimeoutBefehle") -and ($TestSimulationsOptionen["TimeoutBefehle"] -contains $cmdStr)) {
                        $cmdStatus = "timeout"
                        $cmdOutput = "# TEILAUSGABE VOR TIMEOUT (`nPartial output before timeout..."
                        $geraetStatus = "teilweise_fehler"
                        $mindestensEinGeraetFehlgeschlagen = $true
                    } else {
                        $cmdOutput = Get-SynthetischeBefehlsAusgabe -GeraeteName $gName -ProfilName $pName -Befehl $cmdStr -SimOptionen $TestSimulationsOptionen
                    }
                } else {
                    $callSpec = & $buildSshArgs $cmdStr ""
                    $res = Invoke-SshProzess -Programm $callSpec.prog -Argumente $callSpec.args -TimeoutSek $cmdTimeout

                    if (Test-IstLoginOderHostkeyFehler -StderrText $res.stderr -StdoutText $res.stdout -ExitCode $res.exitCode) {
                        $geraetStatus = "fehler"
                        $geraetFehlerMeldung = "SSH Login-/Hostkey-Fehler bei '$cmdStr': $($res.stderr)"
                        $mindestensEinGeraetFehlgeschlagen = $true
                        Write-Warning "Geraet '$gName' wegen Login-/Hostkey-Fehler sofort abgebrochen (kein Retry)."
                        break
                    }

                    if ($res.timedOut) {
                        $cmdStatus = "timeout"
                        $geraetStatus = "teilweise_fehler"
                        $mindestensEinGeraetFehlgeschlagen = $true
                    } elseif ($res.exitCode -ne 0) {
                        $cmdStatus = "fehler"
                        $geraetStatus = "teilweise_fehler"
                        $mindestensEinGeraetFehlgeschlagen = $true
                    }

                    $cmdOutput = $res.stdout
                    if (-not [string]::IsNullOrWhiteSpace($res.stderr)) {
                        if (-not [string]::IsNullOrWhiteSpace($cmdOutput)) {
                            $cmdOutput = "$cmdOutput`n# STDERR:`n$($res.stderr)"
                        } else {
                            $cmdOutput = "# STDERR:`n$($res.stderr)"
                        }
                    }
                }

                # Falls MikroTik /system resource print without-paging lief: Version parsen!
                if ($pName -eq "mikrotik-routeros" -and $cmdStr -eq "/system resource print without-paging") {
                    $mikroTikVersionGeprueft = $true
                    $erkannteMikroTikVersion = Get-MikroTikHauptversion -ResourceOutput $cmdOutput
                }

                # Speichere Ausgabe (auch Fehler-/Teilausgabe) in der Zieldatei
                $dateiInhalte[$ziel].Add("============================================================")
                $dateiInhalte[$ziel].Add("# BEFEHL: $cmdStr")
                $dateiInhalte[$ziel].Add("# STATUS: $cmdStatus")
                $dateiInhalte[$ziel].Add("============================================================")
                $dateiInhalte[$ziel].Add($cmdOutput)
                $dateiInhalte[$ziel].Add("")

                $befehlsMeta.Add([ordered]@{
                    befehl    = $cmdStr
                    zieldatei = $ziel
                    status    = $cmdStatus
                    zeilen    = if ([string]::IsNullOrEmpty($cmdOutput)) { 0 } else { ($cmdOutput -split "`r?`n").Count }
                })
            }
        }

        # Schreibe Zieldateien 01_system.txt .. 07_extra.txt
        foreach ($dn in $standardDateien) {
            $zielPfad = Join-Path $geraeteRohOrdner $dn
            $text = ($dateiInhalte[$dn] -join "`n").TrimEnd("`r", "`n")
            if (-not [string]::IsNullOrEmpty($text)) {
                $text += "`n"
            }
            [System.IO.File]::WriteAllText($zielPfad, $text, (New-Object System.Text.UTF8Encoding($false)))
        }

        # Schreibe _meta.json
        $metaObj = [ordered]@{
            geraet             = $gName
            profil             = $pName
            sitzungsModus      = $sitzungsModus
            hostkeyFingerprint = $hkInfo.fingerprint
            port               = $g.port
            startUtc           = $startZeit
            endeUtc            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            status             = $geraetStatus
            fehler             = $geraetFehlerMeldung
            befehle            = $befehlsMeta
        }
        $metaPfad = Join-Path $geraeteRohOrdner "_meta.json"
        [System.IO.File]::WriteAllText($metaPfad, ($metaObj | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    }
} finally {
    Remove-SammlerTempDateiSicher -Pfad $tempKnownHosts
    Remove-SammlerTempDateiSicher -Pfad $tempPwFile
    foreach ($bf in $tempBefehlsDateien) {
        Remove-SammlerTempDateiSicher -Pfad $bf
    }
}

# ============================================================================
# 11. OPTIONALE DIREKT-ANONYMISIERUNG (-DirektAnonymisieren / -RohLoeschen)
# ============================================================================
if ($DirektAnonymisieren) {
    $anonSkript = Join-Path $skriptOrdner "anon.ps1"
    if (-not (Test-Path -LiteralPath $anonSkript)) {
        throw "anon.ps1 wurde unter '$anonSkript' nicht gefunden."
    }

    $anonAusgabe = Join-Path (Join-Path $AusgabeOrdner "anonymisiert") $zeitstempel
    $anonParams = @{
        Eingabe = $rohBasisOrdner
        Ausgabe = $anonAusgabe
    }
    if (-not [string]::IsNullOrWhiteSpace($RegelDatei)) {
        $anonParams["Regeln"] = $RegelDatei
    }
    if (-not [string]::IsNullOrWhiteSpace($TabellenPfad)) {
        $anonParams["TabellenPfad"] = $TabellenPfad
    }
    if ($TestModus -and ($env:OS -ne "Windows_NT")) {
        $anonParams["Unverschluesselt"] = $true
    }

    & $anonSkript @anonParams
    $anonExit = $LASTEXITCODE

    $berichtPfad = Join-Path $anonAusgabe "bericht.json"
    $pruefStatus = ""
    if (Test-Path -LiteralPath $berichtPfad) {
        try {
            $bJson = ([System.IO.File]::ReadAllText($berichtPfad, [System.Text.Encoding]::UTF8) | ConvertFrom-Json)
            $pruefStatus = [string]$bJson.pruefergebnis
        } catch {}
    }

    if ($RohLoeschen) {
        if ($anonExit -eq 0 -and $pruefStatus -eq "SAUBER") {
            Remove-Item -LiteralPath $rohBasisOrdner -Recurse -Force
            Write-Host "Rohdaten-Ordner '$rohBasisOrdner' nach sauberer Anonymisierung geloescht." -ForegroundColor Green
        } else {
            Write-Warning "Rohdaten-Ordner '$rohBasisOrdner' wurde NICHT geloescht (anon.ps1 ExitCode=$anonExit, pruefStatus='$pruefStatus')."
        }
    }
}

if ($mindestensEinGeraetFehlgeschlagen) {
    exit 3
}
exit 0
