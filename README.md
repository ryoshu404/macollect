# macollect

macollect is a modular macOS forensic artifact collector written in Python that collects security-relevant artifacts and produces structured JSON output suitable for incident response, threat hunting, and security automation workflows. The goal of macollect is to provide a simple, dependency-free collector that can be integrated into existing security pipelines or used directly for analysis.

The tool collects persistence mechanisms, running process snapshots, code signing metadata, TCC privacy permissions, extended attributes, credential artifacts, and Unified Log activity across eight independent collection modules.

macollect requires no third-party dependencies and is designed for enterprise IR deployment out of the box.

---

# Features

macollect implements eight independent collection modules:

- System baseline (macOS version, architecture, SIP status, executing user context)
- Persistence enumeration (LaunchAgents, LaunchDaemons, BTM, Login Items, shell configs, sudoers, cron)
- Process snapshot (PID tree, RUID/EUID, command line, binary path)
- Code signing enrichment (signing status, Team ID, notarization, Mach-O validation)
- TCC database collection (system-wide and per-user privacy permission grants)
- Extended attribute collection (quarantine flags, download provenance)
- Credential and shell artifact collection (shell history, SSH artifacts, keychain metadata)
- Unified Log collection (configurable time window, filtered to security-relevant subsystems)

Each module produces independent structured output with its own flags array for anomaly surfacing.

---

# Architecture

macollect follows a modular orchestrator architecture where each collection module runs independently and produces its own structured output.

Collection flow:
```
sudo macollect
↓
Orchestrator
↓
┌─────────────────────────────────────┐
│  Module 1: System Baseline          │
│  Module 2: Persistence              │
│  Module 3: Process Snapshot         │
│  Module 4: Code Signing Enrichment  │
│  Module 5: TCC Databases            │
│  Module 6: Extended Attributes      │
│  Module 7: Credential Artifacts     │
│  Module 8: Unified Log              │
└─────────────────────────────────────┘
↓
ReportBuilder
↓
JSONFormatter
↓
output.json
```

Each component is responsible for a single concern:

| Component | Responsibility |
|-----------|----------------|
| Orchestrator | Runs modules in dependency order and assembles results |
| Collection Modules | Collect artifacts and surface per-module flags |
| ReportBuilder | Assembles structured output envelope |
| JSONFormatter | Produces deterministic JSON output |

---

# Design Decisions

## Read-Only Guarantee

macollect never modifies system state. Every collection operation is strictly read-only. No files are created, moved, or deleted on the target system. This is a hard architectural constraint, not a runtime option.

## Zero Third-Party Dependencies

macollect is written entirely against the Python standard library. No pip install is required beyond the tool itself. This is a deliberate design constraint for enterprise IR deployment — tools that introduce dependency chains create friction in locked-down environments and supply chain risk in security-sensitive contexts.

## Sudo Requirement

macollect requires sudo execution. Several artifact sources — TCC databases, sudoers, keychain metadata, and certain process attributes — are not accessible to standard user context. Rather than silently collecting a partial picture, the tool fails fast if not run with elevated privileges.

## ESF Boundary

macollect does not use Apple's Endpoint Security Framework. ESF provides real-time kernel-level event streaming and requires a native Swift or C implementation with an Apple-issued entitlement. macollect is a polling-based artifact collector — it reads state that already exists on disk and in memory at collection time. Python is sufficient for this class of work. Real-time event streaming is deferred to a future Swift ESF companion project.

## Code Signing Detection — codesign over spctl

Module 4 derives notarization status directly from `codesign -dvvv` output rather than making a separate `spctl --assess` call. `spctl` performs a live Gatekeeper policy assessment that requires network access to reach Apple's OCSP and notarization servers. In air-gapped or network-restricted IR environments this call will time out or return misleading results. `codesign -dvvv` reads the stapled notarization ticket directly from the binary without any network dependency, making it reliable in offline deployment contexts.

## Per-Module Flags

Each module surfaces its own anomalies independently via a flags array. Flags are not aggregated into a global list. This keeps findings localized to their source and makes triage straightforward — an analyst can go directly to the module that raised a flag without cross-referencing a separate findings section.

## Modular Architecture

Each collection module is implemented as an independent class with a single collect() method Modules have no knowledge of each other. This separation keeps the codebase maintainable and allows modules to be run selectively via the --modules flag without modifying collection logic.

## Unified Log Collection — Default Level
macollect collects Unified Log entries at the default log level rather than filtering to error-only. Security-relevant events — TCC decisions, authorization events, XPC rejections, BTM registrations, and launchd job submissions — are logged at default or info level in normal macOS operation. Error-level filtering captures almost nothing of forensic value on a healthy system and would make the module effectively inert in most IR deployments.


---

# Requirements

## System Requirements

- macOS (any version supported by Python 3.11+)
- Python 3.11 or later
- sudo execution

## Full Disk Access

Module 5 (TCC Databases) requires Full Disk Access (FDA) to be granted to the executing terminal application. TCC databases are protected by macOS privacy controls and are not readable without FDA regardless of sudo privileges.

To grant FDA:
1. Open System Settings → Privacy & Security → Full Disk Access
2. Enable the toggle for your terminal application (Terminal, iTerm2, etc.)

Without FDA, Module 5 degrades gracefully — the TCC module will still run and report an access error in the output rather than failing the collection. All other modules are unaffected. For complete TCC coverage, FDA should be granted before running macollect.

---

# Repository Structure
```
macollect/
├── src/
│   └── macollect/
│       ├── cli.py
│       ├── pipeline.py
│       ├── report.py
│       ├── modules/
│       │   ├── system_baseline.py
│       │   ├── persistence.py
│       │   ├── process_snapshot.py
│       │   ├── code_signing.py
│       │   ├── tcc_databases.py
│       │   ├── extended_attributes.py
│       │   ├── credential_artifacts.py
│       │   └── unified_log.py
│       └── formatters/
│           └── json_formatter.py
├── samples/
├── tests/
├── README.md
└── pyproject.toml
```

---

# Installation

Clone the repository:
```bash
git clone https://github.com/ryoshu404/macollect.git
cd macollect
```

Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate
```

Install the project in editable mode:
```bash
pip install -e .
```

Verify the installation:
```bash
macollect --version
```

---

# Usage

Run a full collection:
```bash
sudo macollect
```

Write output to a file:
```bash
sudo macollect --output /path/to/output.json
```

Run specific modules only:
```bash
sudo macollect --modules persistence processes
```

Set a custom Unified Log time window (default: 24 hours):
```bash
sudo macollect --time-window 48
```

View available options:
```bash
macollect --help
```

---

# Output Format

macollect produces a single JSON file with the following top-level structure:
```json
{
  "collection_metadata": {
    "macollect_version": "1.0.0",
    "collected_at": "2025-01-01T00:00:00.000000",
    "collected_by": "analyst",
    "hostname": "host.local",
    "macos_version": "15.0",
    "architecture": "arm64"
  },
  "modules": {
    "persistence": {
      "data": { ... },
      "flags": [ ... ]
    }
  },
  "errors": []
}
```

Each module entry follows the same schema:
```json
{
  "data": {},
  "flags": [
    {
      "type": "writable_path",
      "source": "/Library/LaunchDaemons/com.example.agent.plist",
      "detail": "/Users/user/Library/agent",
      "reason": "Persistence method runs from a writable location"
    }
  ]
}
```

Some modules include additional fields beyond the base schema where operationally useful.
For example, process_snapshot flags include a `responsible_pid` field derived from
`launchctl procinfo`.

---

# Triage with jq

macollect output is structured for direct consumption by jq. The following snippets cover the most common triage workflows.

**Show all flags across all modules:**
```bash
jq '[.modules | to_entries[] | select(.value.flags | length > 0) | {module: .key, flags: .value.flags}]' output.json
```

**Show flags for a specific module:**
```bash
jq '.modules.persistence.flags' output.json
jq '.modules.process_snapshot.flags' output.json
jq '.modules.code_signing.flags' output.json
```

**Filter flags by type:**
```bash
jq '[.modules[].flags[] | select(.type == "writable_path")]' output.json
jq '[.modules[].flags[] | select(.type == "autologin_enabled")]' output.json
jq '[.modules[].flags[] | select(.type == "unsigned")]' output.json
```

**Show all TCC grants for sensitive services:**
```bash
jq '[.modules.tcc_databases.data.tcc_entries[] | select(.auth_value == 2)]' output.json
```

**Show all TCC grants for a specific service:**
```bash
jq '[.modules.tcc_databases.data.tcc_entries[] | select(.service == "kTCCServiceSystemPolicyAllFiles")]' output.json
```

**List all persistence binaries with their signing status:**
```bash
jq '[.modules.code_signing.data.signing[] | {path: .path, status: .signing_status, team_id: .team_id}]' output.json
```

**Show only unsigned or ad-hoc signed binaries:**
```bash
jq '[.modules.code_signing.data.signing[] | select(.signing_status == "unsigned" or .signing_status == "adhoc")]' output.json
```

**List all running processes from writable paths:**
```bash
jq '[.modules.process_snapshot.flags[] | select(.type == "writable_path")]' output.json
```

**Show processes with EUID/RUID mismatch:**
```bash
jq '[.modules.process_snapshot.flags[] | select(.type == "euid_ruid_mismatch")]' output.json
```

**Show all files with download provenance:**
```bash
jq '[.modules.extended_attributes.data.xattr_entries[] | select(.where_froms | length > 0)]' output.json
```

**Show collection metadata:**
```bash
jq '.collection_metadata' output.json
```

**Check for collection errors:**
```bash
jq '.errors' output.json
```

**Show all credential artifacts:**
```bash
jq '.modules.credential_artifacts.data' output.json
```

**Show shell history entries:**
```bash
jq '.modules.credential_artifacts.data.shell_history' output.json
```

**Show SSH artifacts:**
```bash
jq '.modules.credential_artifacts.data.ssh' output.json
```

---

# Known Limitations

**Binary path truncation for processes with spaces in path**
`binary_path` in process_snapshot is derived from `argv[0]` via `shlex.split()`. Processes whose executable path contains unquoted spaces (e.g. Image Capture, Screen Sharing) will have their path truncated at the first space. A full fix requires `proc_pidpath` via ctypes. Tracked in GitHub issue #3.

**Notarization ticket detection**
`notarization_ticket` in code_signing reflects whether a stapled notarization ticket was detected in `codesign -dvvv` output. This field may not be reliable for all binary types and should be treated as informational.

**Unrun modules in partial collection**
When running with `--modules` to select a subset of modules, unrun modules still appear in the output with empty `data` and `flags`. This is intentional — the output envelope is always complete. Unrun modules are indistinguishable from modules that ran and found nothing.

**Code signing failure states**
Binaries that error during `codesign` inspection (permission denied, not a Mach-O, etc.) are recorded with a `signing_status` of `error: <reason>` rather than silently dropped.

---

# Roadmap

## v1.0 Coverage

macollect v1.0 implements eight collection modules:

- System baseline and collection context
- Persistence enumeration across all major macOS persistence mechanisms
- Point-in-time process snapshot with flag logic
- Code signing enrichment for persistence and flagged process binaries
- TCC database collection for system-wide and per-user privacy permissions
- Extended attribute collection for download provenance
- Credential and shell artifact collection
- Unified Log collection filtered to security-relevant subsystems

## v1.x Candidates

The following are documented as planned additions post v1.0:

- Mach port snapshot via `lsmp` for flagged PIDs
- URL scheme enumeration via `lsregister`
- Full `launchctl procinfo` enrichment for all flagged PIDs
- Dylib presence checks in application bundles
- Spotlight metadata via `mdls` for suspicious files
- Bonjour/dns-sd enumeration for network context
- Severity levels on flags (high / medium / informational)
- argv0 suppression tuning for additional Apple system process patterns
- Resolve `binary_path` truncation via `proc_pidpath` (ctypes)

---

# Related Projects

This project is part of a larger security tooling portfolio.

### [Statica (complete)](https://github.com/ryoshu404/statica)
Modular static analysis pipeline written in Python. Extracts file hashes, printable strings, and common indicators of compromise from arbitrary files. Natural pre-collection companion to macollect.

### IOC Correlation Service (planned)
Threat intelligence correlation service written in Go. Future enrichment integration layer for macollect output.

### Swift ESF Telemetry Tool (planned)
Real-time kernel event streaming companion to macollect using Apple's Endpoint Security Framework. The natural v2 evolution for environments requiring live event telemetry rather than polling-based artifact collection.

---

# Author

R. Santos
GitHub: https://github.com/ryoshu404

---

# License

MIT