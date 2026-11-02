<div align="center">

# SysPeek

<img src="https://github.com/user-attachments/assets/970285bc-5f5d-40aa-a8e7-cf8c767d01ea">

### A blue-team recon & threat-detection toolkit for Windows

**Stop scrolling through 500 lines of raw output. Get a Threat Score.**

![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=flat-square&logo=go)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square&logo=windows)
![License](https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square)
![Version](https://img.shields.io/badge/version-1.0.0-blueviolet?style=flat-square)
![Status](https://img.shields.io/badge/status-active-success?style=flat-square)

</div>

---

SysPeek digs into what's *actually* running on a Windows host — processes, DLLs, drivers, persistence mechanisms, network connections — and instead of dumping raw data on you, it tells you **why** something deserves a second look. 🎯

Built for SOC analysts and incident responders who need to walk up to an unfamiliar box and answer *"what's really going on here?"* in minutes, not hours.

```
🛡️  Threat Score: 82/100  [CRITICAL]

Critical & High Findings
────────────────────────────────────────
✓ [ 95] lsass          rundll32.exe (PID:4821)   💀 LSASS dump via comsvcs.dll MiniDump
✓ [ 70] processes      chrome.exe (PID:2210)      🩹 DLL search-order hijack: version.dll
✓ [ 55] lolbin         powershell.exe (PID:3390)  ⚠️  Base64-encoded command, hidden window

MITRE ATT&CK Coverage
────────────────────────────────────────
  T1003.001  LSASS Memory
  T1059.001  PowerShell
  T1574.001  DLL Search Order Hijacking

Recommendation
────────────────────────────────────────
  → Isolate the affected host and capture a memory image before further changes.
  → Pull PowerShell ScriptBlock/Module logs (Event ID 4104) and Sysmon Event ID 1.
```

---

## 📚 Table of Contents

- [🤔 Why SysPeek](#-why-syspeek)
- [✨ Features](#-features)
- [⚡ Installation](#-installation)
- [🚀 Quick Start](#-quick-start)
- [👁️ Live Monitoring](#️-live-monitoring)
- [🧰 Command Reference](#-command-reference)
- [⚙️ Configuration](#️-configuration)
- [📸 Baseline & Diff Workflow](#-baseline--diff-workflow)
- [📤 Report Export](#-report-export)
- [🏗️ Architecture](#️-architecture)
- [🎯 MITRE ATT&CK Coverage](#-mitre-attck-coverage)
- [⚠️ Known Limitations](#️-known-limitations)
- [🚨 Disclaimer](#-disclaimer)

---

## 🤔 Why SysPeek

Most "system info" tools dump data and leave the thinking to you. SysPeek **scores** what it finds, explains *why* it's suspicious, maps it to MITRE ATT&CK, and correlates everything into one summary — so `syspeek --all` gives you a triage-ready verdict instead of a wall of text. 🧠

It's built to be **low-noise on purpose**. 🤫 Signed system DLLs, common install locations like `%LOCALAPPDATA%\Programs`, and everyday admin tooling don't light up the report. What *does* light up is high-confidence stuff:

- 🔓 Tampered Authenticode signatures
- 🪝 DLL search-order hijacks
- 💀 LSASS dumping techniques
- 🧬 Reflective/manually-mapped PE loading in memory
- 🆕 New persistence since your last baseline

No noise, no fatigue, no "just ignore that one, it's always red."

## ✨ Features

| Module | Flag | What it catches |
|---|---|---|
| 🔬 **Process & DLL Analysis** | `--processes=1` | Unsigned/tampered DLLs, DLL search-order hijacking, threads starting outside any module, reflective/manually-mapped PE in memory, deleted-on-disk (fileless) executables |
| 🛡️ **EDR/AV Inventory** | `--edr` / `--antivirus` | What security products are actually installed on the box |
| 🎣 **LOLBin Detector** | `--lolbin` | `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wmic`, PowerShell, etc. matched against suspicious argument patterns, with the full parent→child process chain |
| 💀 **LSASS Credential-Access Hunter** | `--lsass` | `comsvcs.dll` MiniDump technique, ProcDump, SAM/SECURITY hive saves, known dumping-tool filenames |
| 🔒 **Ransomware Precursor Hunter** | `--ransomware-hunt` | Shadow-copy deletion, backup/catalog sabotage, boot-recovery tampering, anti-forensics (`cipher /w`, USN journal wipe) |
| 🧟 **Persistence Hunter** | `--persistence` | IFEO debugger hijacks (incl. the sticky-keys backdoor family), `AppInit_DLLs`, Winlogon `Shell`/`Userinit` tampering, rogue LSA security packages, WMI permanent event subscriptions |
| ⚙️ **Driver Scanner** | `--drivers` | Test-signing mode, unsigned/tampered kernel drivers, drivers loaded from non-standard paths |
| 🌐 **Network Watch** | `--netwatch` | TCP connections attributed to their owning process, flagged when that process is unsigned or has a tampered signature |
| 🗂️ **Unified Autoruns Inventory** | `--autoruns` | Every service, scheduled task, Run/RunOnce key, and Startup-folder entry in one signature-checked table |
| 📸 **Baseline / Diff** | `--baseline` / `--diff` | Snapshot services/tasks/run-keys/drivers today, get only *what changed* on your next visit |
| 👁️ **Live Monitor** | `--monitor` | Polls processes/services/connections at an interval and prints new activity as it happens |
| 📁 **Folder Watch** | `--watch-folder` | Real-time (`ReadDirectoryChangesW`, event-driven, not polling) create/modify/delete/rename alerts for a folder |
| 🧩 **Correlation Engine** | `--correlate` | Weighted Threat Score, critical findings, MITRE coverage, chronological timeline, and short remediation pointers |
| 📤 **Report Export** | `--export=json\|csv\|html` | A dark-themed HTML dashboard, or JSON/CSV for feeding into your own pipeline |
| 🗄️ **General Inventory** | `--registry`, `--services`, `--hardware`, `--filesystem`, `--environment`, `--logs` | Registry, services, hardware, filesystem, environment, and event log inventory |

Everything is tunable **without a rebuild** — see [⚙️ Configuration](#️-configuration).

## ⚡ Installation

> SysPeek is Windows-only 🪟 — it uses `kernel32`, `psapi`, `wintrust`, and shells out to PowerShell for structured host data.

### `go install`

```bash
go install gitlab.com/specterog/SysPeek@latest
```

Drops a `SysPeek.exe` in your `$GOBIN` (or `$GOPATH/bin`). Make sure that directory is on your `PATH`.

### 🔨 Build from source

```bash
git clone https://gitlab.com/specterog/SysPeek.git
cd SysPeek
go build -o SysPeek.exe .
```

Requires **Go 1.25+**. No CGO, no external system dependencies beyond PowerShell (present on every supported Windows version).

> 💡 **Tip:** Run as Administrator for full visibility — several modules (driver scanning, some registry hives, process memory inspection) return partial results otherwise.

## 🚀 Quick Start

```powershell
# 🔎 Full scan with a triage summary at the end
SysPeek.exe --all

# 🎣 Just processes with suspicious DLLs, plus the LOLBin/parent-chain analyzer
SysPeek.exe --processes=1 --lolbin --correlate

# 📸 First visit to a host: capture what "normal" looks like
SysPeek.exe --baseline

# 🆕 Every visit after that: show only what changed
SysPeek.exe --diff --persistence --drivers --correlate

# 📤 Full scan, exported as a shareable HTML report
SysPeek.exe --all --export=html --output=incident-2026-08-07.html
```

## 👁️ Live Monitoring

SysPeek has **two** different monitoring modes, built on genuinely different mechanisms — worth knowing which one you actually want.

### `--monitor` — polling watch over processes/services/connections

```powershell
SysPeek.exe --monitor
SysPeek.exe --monitor --monitor-interval=2s
```

Every interval (default 3s), SysPeek re-samples processes, services, and TCP connections and prints whatever's new or gone since the last poll:

```
Monitoring processes, services, and network connections every 3s. Press Ctrl+C to stop.

[14:02:10] [BASELINE ] Initial snapshot: 187 processes, 142 services, 34 connections
[14:02:13] [PROCESS+ ] New process: powershell.exe (PID:9182) chain=explorer.exe -> powershell.exe
[14:02:13] [CONN+    ] New network connection: Established|51422|20.42.65.92|443|9182
[14:02:19] [PROCESS- ] Process exited: powershell.exe (PID:9182)
```

⚠️ **This is polling, not a kernel event stream.** Anything that starts and fully exits *between* two polls is invisible to it — the interval is a direct trade-off between how much you might miss and how much overhead (PowerShell spawns) you're willing to pay per poll. New processes and new services are registered as findings, so they show up in `--correlate` and `--export` too.

### `--watch-folder` — real-time, event-driven folder watch

```powershell
SysPeek.exe --watch-folder="C:\Users\Public\Downloads"
SysPeek.exe --watch-folder="C:\ProgramData" --watch-recursive
```

This one is backed directly by Windows' `ReadDirectoryChangesW` — a genuine kernel-level event stream, **not** a polling loop. Nothing that happens in the watched folder is missed, no matter how briefly:

```
Watching C:\Users\Public\Downloads (recursive=false) for file changes. Press Ctrl+C to stop.

[14:05:02] [CREATED     ] C:\Users\Public\Downloads\invoice.pdf.exe
[14:05:02] [MODIFIED    ] C:\Users\Public\Downloads\invoice.pdf.exe
[14:05:03] [RENAMED-FROM] C:\Users\Public\Downloads\invoice.pdf.exe
[14:05:03] [RENAMED-TO  ] C:\Users\Public\Downloads\update.exe
```

A newly-created executable/script (`.exe`, `.dll`, `.ps1`, `.bat`, `.vbs`, `.js`, `.hta`, `.scr`, `.cmd`) is registered as a finding automatically. Great for watching `Downloads`, a Startup folder, or a share you suspect is being used to stage payloads.

Both modes run until you press **Ctrl+C**.

## 🧰 Command Reference

| Flag | Description |
|---|---|
| `--all` | 🔎 Run every detection module and print the correlation report |
| `--processes=0` | List all processes with DLL info |
| `--processes=1` | List only processes with suspicious DLLs |
| `--edr` | 🛡️ Inventory installed EDR products |
| `--antivirus` | 🛡️ Inventory installed AV products |
| `--registry` | Registry-based system info |
| `--services` | Windows services inventory |
| `--hardware` | Hardware inventory |
| `--network` | Raw network connection listing |
| `--filesystem` | Filesystem inventory |
| `--environment` | Environment variable inventory |
| `--logs` | Event log inventory |
| `--lolbin` | 🎣 LOLBin abuse detector with parent-chain reconstruction |
| `--lsass` | 💀 LSASS credential-dumping signature hunter |
| `--ransomware-hunt` | 🔒 Shadow-copy/backup-sabotage/anti-forensics hunter |
| `--persistence` | 🧟 Registry-based persistence hunter |
| `--drivers` | ⚙️ Kernel driver scanner |
| `--netwatch` | 🌐 Process-attributed network connection watcher |
| `--autoruns` | 🗂️ Unified autoruns inventory |
| `--baseline` | 📸 Capture a state snapshot |
| `--diff` | 🆕 Compare current state against the saved baseline |
| `--monitor` | 👁️ Poll processes/services/connections continuously (Ctrl+C to stop) |
| `--monitor-interval` | Polling interval for `--monitor` (default `3s`) |
| `--watch-folder=DIR` | 📁 Real-time folder watch via `ReadDirectoryChangesW` (Ctrl+C to stop) |
| `--watch-recursive` | Watch subdirectories too (used with `--watch-folder`) |
| `--correlate` | 🧩 Print the Threat Score / MITRE / Timeline summary |
| `--export=json\|csv\|html` | 📤 Export this run's findings |
| `--output=PATH` | Output path for `--export` |
| `--config-init` | ⚙️ Write a default `syspeek_config.json` next to the executable and exit |
| `--help` | Show usage |

## ⚙️ Configuration

Drop a `syspeek_config.json` next to `SysPeek.exe` (or set `SYSPEEK_CONFIG` to a custom path) to tune detection **without recompiling**. Generate a starting point with:

```powershell
SysPeek.exe --config-init
```

```json
{
  "trusted_publishers": ["Microsoft", "Google", "YourCompany Inc"],
  "hijack_targets": ["version.dll", "dbghelp.dll", "amsi.dll"],
  "lsass_allowlist": ["wmiprvse.exe", "YourEDRAgent.exe"],
  "thresholds": { "low": 20, "medium": 50, "high": 80 }
}
```

Any field you omit falls back to the built-in default — you only need to specify what you want changed. 🎛️ Common reasons to edit this file:

- 🏢 Add your organization's internal signing certificate name to `trusted_publishers` so internally-built tools stop showing up as "unknown publisher."
- 🛡️ Add your EDR/AV agent's process name to `lsass_allowlist` if it legitimately opens handles to LSASS.
- 🎚️ Raise or lower `thresholds` to match your environment's baseline noise level.

## 📸 Baseline & Diff Workflow

```powershell
# Day 1 - capture what this host normally looks like
SysPeek.exe --baseline

# Any later visit - see only what's new
SysPeek.exe --diff
```

`--diff` reports additions (new services, tasks, run keys, drivers) as findings that feed the correlation engine; removals are shown for completeness but aren't scored, since cleanup is the common case there. ✅

## 📤 Report Export

```powershell
SysPeek.exe --all --export=html --output=report.html
SysPeek.exe --all --export=json --output=findings.json
SysPeek.exe --all --export=csv  --output=findings.csv
```

The HTML report is a self-contained, dark-themed dashboard 🌑 — safe to attach to a ticket or an audit trail without needing SysPeek installed to view it.

## 🏗️ Architecture

```
SysPeek/
├── main.go                  # flag parsing, module orchestration
├── modules/
│   ├── findings.go          # shared Finding type + MITRE technique names
│   ├── config.go            # external allowlist/threshold config
│   ├── correlation.go       # Threat Score, timeline, recommendations
│   ├── processes.go         # process/DLL/memory analysis
│   ├── lolbin.go            # LOLBin detection + parent-chain builder
│   ├── lsass.go             # credential-access hunting
│   ├── persistence.go       # IFEO/AppInit/Winlogon/LSA/WMI persistence
│   ├── drivers.go           # kernel driver scanning
│   ├── ransomware.go        # destructive-action precursor hunting
│   ├── netwatch.go          # process-attributed network watch
│   ├── autoruns.go          # unified autoruns inventory
│   ├── baseline.go          # snapshot capture + diff
│   ├── monitor.go           # polling live monitor (processes/services/connections)
│   ├── folder_watch.go      # real-time folder watch (ReadDirectoryChangesW)
│   ├── report.go            # JSON/CSV/HTML export
│   └── ...                  # edr, antivirus, registry, services, hardware,
│                             # network, filesystem, environment, logs
└── utils/
    └── display.go            # table rendering
```

💡 Every detection module registers its findings into a single in-memory registry (`modules/findings.go`). The correlation engine reads from that registry, so anything a module flags **automatically** shows up in the Threat Score, MITRE coverage, timeline, and exported reports — no extra wiring needed per module.

## 🎯 MITRE ATT&CK Coverage

SysPeek maps its findings to ATT&CK techniques including:

`T1003` / `T1003.001` / `T1003.002` (OS Credential Dumping) · `T1027` (Obfuscated Files) · `T1036` / `T1036.001` (Masquerading) · `T1047` (WMI) · `T1053.005` (Scheduled Task) · `T1055` / `T1055.001` (Process Injection) · `T1059.001` (PowerShell) · `T1070` / `T1070.004` (Indicator Removal) · `T1071` (Application Layer Protocol) · `T1105` (Ingress Tool Transfer) · `T1127` (Trusted Developer Utilities Proxy Execution) · `T1197` (BITS Jobs) · `T1218.*` (System Binary Proxy Execution / LOLBins) · `T1490` (Inhibit System Recovery) · `T1543.003` (Windows Service) · `T1546.003/.008/.010/.012` (Event-Triggered Execution) · `T1547.001/.004/.005/.006` (Boot or Logon Autostart Execution) · `T1553.002/.006` (Subvert Trust Controls) · `T1574.001` (DLL Search Order Hijacking)

## ⚠️ Known Limitations

- 🩻 **LSASS handle detection is signature-based, not handle-table-based.** Reliably enumerating which processes hold open handles to `lsass.exe` requires walking the system handle table via undocumented, build-sensitive structures. SysPeek deliberately doesn't attempt that; pair `--lsass` with **Sysmon Event ID 10** (ProcessAccess) for kernel-level handle visibility.
- 🐚 **PowerShell-dependent modules** (`--lolbin`, `--lsass`, `--ransomware-hunt`, `--netwatch`, `--autoruns`, `--persistence`, `--baseline`) shell out to PowerShell for structured data (`Get-CimInstance`, `Get-NetTCPConnection`, etc.) — a deliberate trade-off of a little performance for correctness over hand-rolled parsing of undocumented Windows internals. `Get-NetTCPConnection` needs PowerShell 3.0+ and isn't available on very old systems (Windows 7/Server 2008 R2) without a fallback to `netstat`.
- 🔓 **Baseline files are unsigned.** An attacker with sufficient privilege to tamper with the host could also tamper with the local baseline file. Store baselines somewhere the box itself can't write to if that's part of your threat model.
- 👁️ **`--monitor` is polling, not push.** It re-samples state on an interval and diffs; anything that starts and exits entirely within one interval is missed. `--watch-folder` doesn't have this gap (it's a real kernel event stream), but it only covers filesystem events in the folder you point it at — it won't tell you about new processes or network connections.
- 🚪 **Neither monitoring mode intercepts Ctrl+C gracefully by design.** `--monitor` shuts down cleanly via a signal handler; `--watch-folder` is a blocking syscall and Ctrl+C simply terminates the process (the OS default) — output already printed stays valid either way.
- 🙋 SysPeek is a **detection aid for a human analyst**, not an EDR. It doesn't block anything, doesn't run continuously by default, and its findings should be triaged, not auto-actioned.

## 🚨 Disclaimer

SysPeek is intended for use by security professionals on systems they own or are explicitly authorized to assess. Some of what it detects (LOLBin abuse, LSASS dumping techniques, ransomware precursors) overlaps with offensive tradecraft by necessity — that's what makes it useful for defense. Using it against systems without authorization is **your** responsibility, not the maintainers'.

---

<div align="center">

**🦇 SysPeek v1.0.0** — *see what's really running.*

</div>
