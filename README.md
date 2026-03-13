# macollect

macollect is a modular macOS forensic artifact collector written in Python that collects relevant items of interest and produces structured JSON output suitable for incident response, threat hunting, and security automation workflows. The goal of macollect is to provide a simple, dependency free, collector that can be integrated into other security workflows or used as is for analysis.

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
|-----------|---------------|
| Orchestrator | Runs modules in order and assembles results |
| Collection Modules | Collect artifacts and surface per-module flags |
| ReportBuilder | Assembles structured output envelope |
| JSONFormatter | Produces deterministic JSON output |

---

# Design Decisions

## Read-Only Guarantee

macollect never modifies system state. Every collection operation is strictly read-only. No files are created, moved, or deleted on the target system. This is a hard architectural constraint, not a runtime option.

## Zero Third-Party Dependencies

macollect is written entirely against the Python standard library. No pip install is required beyond the tool itself. This is a deliberate design constraint for enterprise IR deployment as tools that introduce dependency chains create friction in locked-down environments and supply chain risk in security-sensitive contexts.

## Sudo Requirement

macollect requires sudo execution. Several artifact sources such as TCC databases, sudoers, keychain metadata, and certain process attributes are not accessible to standard user context. Rather than collecting a partial picture silently, the tool fails fast if not run with elevated privileges.

## ESF Boundary

macollect does not use Apple's Endpoint Security Framework. ESF provides real-time kernel-level event streaming and requires a native Swift or C implementation with an Apple-issued entitlement. macollect is a polling-based artifact collector, it reads state that already exists on disk and in memory at collection time. Python is sufficient for this class of work. Real-time event streaming is deferred to a future Swift ESF companion project.

## Per-Module Flags

Each module surfaces its own anomalies independently via a flags array. Flags are not aggregated into a global list. This keeps findings localized to their source and makes triage straightforward. An analyst can go directly to the module that raised a flag without cross-referencing a separate findings section.

## Modular Architecture

Each collection module is implemented as an independent class with a single collect() method. Modules have no knowledge of each other. This separation keeps the codebase maintainable and allows modules to be run selectively via the --modules flag without modifying collection logic.

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

Requires Python 3.11+

Requires sudo execution.

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

Write output to a specific file:
```bash
sudo macollect --output /path/to/output.json
```

Run specific modules only:
```bash
sudo macollect --modules persistence process_snapshot
```

Set a custom Unified Log time window (default: 24 hours):
```bash
sudo macollect --time-window 48
```

View available options:
```bash
macollect --help
```

Check installed version:
```bash
macollect --version
```

---

# Example Output

Added after v1 publication

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

---

# Related Projects

This project is part of a larger security tooling portfolio.

### Statica (complete)
Modular static analysis pipeline written in Python. Extracts file hashes, printable strings, and common indicators of compromise from arbitrary files. Natural pre-collection companion to macollect.
GitHub: https://github.com/ryoshu404/statica

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