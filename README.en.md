# Network Anonymizer (English summary)

The full documentation is in German: [README.md](./README.md).

Offline tool that anonymizes network logs, show-techs, configuration files and JSON dumps (Aruba AOS-CX/AOS-S, HPE Comware, Dell SONiC/OS10, MikroTik RouterOS, Cisco IOS/NX-OS, FortiGate, Sophos, syslog, Windows event logs) before they are shared with an AI or external experts.

## Components

| Path | Purpose |
|---|---|
| `powershell/anon.ps1` | CLI for Windows PowerShell 5.1 and PowerShell 7 (embedded C# engine, no modules, no internet) |
| `web/anonymisierer.html` | Single-file offline browser app with the same engine and identical output |
| `web/text/text-anonymisierer.html` | Single-file offline page for free text (emails, letters, notes) with per-category mechanism: placeholder, remove, generalize |
| `regeln/anon-regeln.json` | Shared rule set (example values only). Real names go into `anon-regeln.lokal.json`, which is never committed |
| `core/` | Shared JavaScript core embedded into both pages (`node tools/einbetten.js`) |

## Key properties

- Placeholders are consistent across all files of a run; network relations stay visible (`NET-3.H17/24`, `MAC-1`, `HOST-2`).
- Secrets (passwords, keys, SNMP communities, hashes, PEM blocks) are irreversibly replaced by `*****`.
- The mapping table is stored outside the output folder, protected by an ACL and encrypted (DPAPI or password, format `ANON-AES256-2`), and is shared between both pages and the CLI.
- A built-in audit (`-Pruefen`) reports remaining IPs, MACs, hostnames, serial numbers, users, secrets, free-text fields and every original value detected during the run. Console output never contains the values.
- AI answers containing placeholders are translated back locally (`-Zurueck`); plain text is never written below `anonym\`.

## Quick start (Windows PowerShell 5.1)

```powershell
cd C:\Tools\anonymisierer
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\powershell\anon.ps1 `
    -Eingabe "C:\Cases\In" -Ausgabe "C:\Cases\Out" -LokaleRegeln ".\anon-regeln.lokal.json"
```

Share only `C:\Cases\Out\anonym\`. Run the tests with `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\run-tests.ps1` and `node tests/run-tests.js`, `node tests/run-tests-text.js`.

## License

`LICENSE` contains Apache-2.0 as a **placeholder**; the final license decision is still open.

Concepts (no code) were inspired by [netconan](https://github.com/intentionet/netconan) (Apache-2.0) and [Presidio](https://github.com/data-privacy-stack/presidio) (MIT).
