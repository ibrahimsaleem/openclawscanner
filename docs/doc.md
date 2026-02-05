# openclawscanner deep-dive documentation

This document explains in detail how the `openclawscanner` scripts work, what they scan for, why those artifacts matter, and how to integrate them with common MDM/RMM platforms.

It covers:

- The overall architecture and data flow
- macOS/Linux script internals (`detect-openclaw.sh`)
- Windows script internals (`detect-openclaw.ps1`)
- Output format and exit codes
- Environment variables and profiles
- Integration patterns (and how the `docs/` guides fit in)
- Security considerations and roadmap

---

## 1. High-level architecture

`openclawscanner` consists of two main entrypoints:

- `detect-openclaw.sh` — Bash script for **macOS** and **Linux**
- `detect-openclaw.ps1` — PowerShell script for **Windows**

Both scripts:

- Run a series of **read-only checks** to identify OpenClaw (and legacy Moltbot/Clawdbot) installations and activity.
- Print a **human- and machine-readable report** (key/value lines).
- Exit with an **opinionated exit code** to drive MDM/RMM compliance logic.

### 1.1 Data flow overview

![Architecture data-flow for detect-openclaw scripts](./assets/openclawscanner-arch-flow.png)

---

## 2. What is being scanned, and why

The scanner looks for several classes of artifacts. Each one supports a different detection goal:

### 2.1 CLI binaries and app bundles

- **What**:
  - `openclaw` CLI in:
    - `PATH`
    - Common global paths: `/usr/local/bin/openclaw`, `/opt/homebrew/bin/openclaw`, `/usr/bin/openclaw` (macOS/Linux)
    - Per-user paths: `~/.volta/bin/openclaw`, `~/.local/bin/openclaw`, `~/.nvm/current/bin/openclaw`, `~/bin/openclaw`
    - Windows paths such as:
      - `C:\Program Files\openclaw\openclaw.exe`
      - `C:\Program Files (x86)\openclaw\openclaw.exe`
      - User-scoped paths like `AppData\Local\Programs\openclaw\openclaw.exe`, various `npm` / `pnpm` / `volta` shims.
  - macOS app bundle: `/Applications/OpenClaw.app`

- **Why**:
  - Presence of the CLI or app bundle is a strong indicator that OpenClaw tooling is installed.
  - CLI version output (`openclaw --version`) helps responders know which build is present.

### 2.2 State directories and configuration files

- **What**:
  - Per-user state for OpenClaw:
    - `~/.openclaw` (or profile-specific: `~/.openclaw-<profile>`)
  - Legacy names:
    - `~/.moltbot` with `moltbot.json`
    - `~/.clawdbot` with `clawdbot.json`
  - Main config file: `openclaw.json` inside each state directory.

- **Why**:
  - State directories indicate **persistent installation and use**.
  - Configs typically contain:
    - Profile-specific settings
    - Gateway port(s)
    - Possibly other environment bindings
  - Even if the CLI binary has been removed, state/config may remain and is useful forensic evidence.

### 2.3 Services / scheduled tasks (persistence)

- **What**:
  - macOS: `launchd` GUI service, label derived from profile:
    - Default: `bot.molt.gateway`
    - Profiled: `bot.molt.<PROFILE>`
  - Linux: user-level `systemd` services:
    - `openclaw-gateway.service`
    - `openclaw-gateway-<PROFILE>.service`
  - Windows: scheduled tasks whose names include:
    - `OpenClaw Gateway`
    - `Moltbot Gateway`
    - `Clawdbot Gateway`

- **Why**:
  - These reflect **persistence mechanisms** used to start OpenClaw’s gateway automatically.
  - They are critical for:
    - Determining whether a host is **actively connected** to OpenClaw infrastructure.
    - Enabling MDM/RMM policies to distinguish “installed but dormant” vs “installed and actively running”.

### 2.4 Gateway ports

- **What**:
  - Default gateway port: `18789`, or overridden via:
    - `OPENCLAW_GATEWAY_PORT` environment variable.
    - `port` entry in `openclaw.json` and legacy config files.
  - The scripts:
    - Aggregate a set of candidate ports from environment and configs.
    - Deduplicate them.
    - Probe each candidate on `localhost` using:
      - `nc -z localhost <port>` on macOS/Linux.
      - `Test-NetConnection -ComputerName localhost -Port <port>` on Windows.

- **Why**:
  - A listening gateway port means **active communication** (or at least a bound process).
  - Port-based detection helps confirm running status even if service metadata is missing or inconsistent.

### 2.5 Docker containers and images

- **What**:
  - Containers: `docker ps --format '{{.Names}} ({{.Image}})'` filtered with `/openclaw|moltbot|clawdbot/i`.
  - Images: `docker images --format '{{.Repository}}:{{.Tag}}'` filtered similarly.

- **Why**:
  - Some deployments may run OpenClaw in containers rather than directly on the host.
  - Images indicate **installed but not necessarily running** deployments.
  - Containers indicate **active or recently active** usage.

### 2.6 From artifacts to conclusions

![Mapping artifacts to installed/running conclusions and exit codes](./assets/openclawscanner-artifacts-to-exitcodes.png)

---

## 3. macOS/Linux script internals (`detect-openclaw.sh`)

### 3.1 Platform and user discovery

- **Platform detection**:
  - Uses `uname -s` to return `darwin`, `linux`, or `unknown`.
  - If `unknown`, the script emits `summary: error` and exits with `2`.

- **User enumeration**:
  - If running as **root**:
    - macOS: iterates `/Users/*` excluding `Shared`.
    - Linux: iterates `/home/*`.
  - Otherwise: only the **current user** (`whoami`).

- **Home directory resolution**:
  - `darwin`: `/Users/<user>`
  - `linux`: `/home/<user>`

The script transparently supports **multi-user scanning** when run with elevated privileges (MDM typical pattern).

### 3.2 State directory and profile handling

- **Environment**: `OPENCLAW_PROFILE`
  - If set, state dir for a user is `~/.openclaw-<PROFILE>`.
  - Otherwise, `~/.openclaw`.
- Legacy state dirs:
  - `~/.clawdbot` and `~/.moltbot`.

For each user:

- Report:
  - `state-dir`
  - `config` (path or `not-found`)
  - `clawdbot-state-dir` / `clawdbot-config`
  - `moltbot-state-dir` / `moltbot-config`

Ports mentioned in any of the config files are collected and unioned with `OPENCLAW_GATEWAY_PORT` (default `18789` if unset).

### 3.3 CLI and app detection

Order of checks:

1. `check_cli_in_path`: `command -v openclaw`.
2. `check_cli_global`: well-known global paths.
3. Per-user paths if global CLI not already found.

If found:

- Emit `cli: <path>` and `cli-version: <first-line-of-openclaw --version>`.

On macOS only, also check `/Applications/OpenClaw.app` and emit `app: <path>` or `app: not-found`.

### 3.4 Services and ports

- macOS:
  - Build `launchd` label `bot.molt.gateway` or `bot.molt.<PROFILE>`.
  - Call `launchctl print gui/<uid>/<label>`.
  - Report `gateway-service: <label>` or `gateway-service: not-loaded`.

- Linux:
  - Build `systemd` unit:
    - `openclaw-gateway.service` or `openclaw-gateway-<PROFILE>.service`.
  - Call `systemctl --user is-active <unit>`.
  - Report `gateway-service: <unit>` or `gateway-service: inactive`.

- Ports:
  - Combine:
    - `OPENCLAW_GATEWAY_PORT` value.
    - `port` values parsed from each config.
  - Deduplicate, then probe with `nc -z localhost <port>`.
  - Report `gateway-port: <listening-port>` or `gateway-port: not-listening`.

### 3.5 Docker

- Only run Docker checks if `docker` is on `PATH`.
- Containers:
  - `docker ps --format '{{.Names}} ({{.Image}})' | grep -Ei 'openclaw|moltbot|clawdbot'`
  - If any match: `docker-container: <matching-lines>`, else `docker-container: not-found`.
- Images:
  - `docker images --format '{{.Repository}}:{{.Tag}}' | grep -Ei 'openclaw|moltbot|clawdbot'`
  - If any match: `docker-image: <matching-lines>`, else `docker-image: not-found`.

### 3.6 macOS/Linux flow diagram

![macOS/Linux script flow for detect-openclaw.sh](./assets/openclawscanner-macos-linux-flow.png)

---

## 4. Windows script internals (`detect-openclaw.ps1`)

### 4.1 Context and configuration

- **Environment**:
  - `$env:OPENCLAW_PROFILE` → profile suffix for state dirs and service/task names.
  - `$env:OPENCLAW_GATEWAY_PORT` → base port (default `18789`).
- Error behavior:
  - `$ErrorActionPreference = "Stop"` so fatal errors yield `summary: error` and exit `2`.

### 4.2 User enumeration and state

- If the current identity is in the **Administrators** group:
  - Enumerate all directories under `C:\Users` except:
    - `Public`, `Default`, `Default User`, `All Users`.
- Otherwise:
  - Use only `$env:USERNAME`.

For each user:

- Home: `C:\Users\<User>`.
- State dir: `.openclaw` or `.openclaw-<PROFILE>`.
- Legacy dirs:
  - `.clawdbot` + `clawdbot.json`
  - `.moltbot` + `moltbot.json`
- Collect ports from:
  - `openclaw.json`
  - legacy configs (if present).

### 4.3 CLI detection

- **Path-based**:
  - `Get-Command openclaw` (if present in `%PATH%`).
- **Global paths**:
  - `C:\Program Files\openclaw\openclaw.exe`
  - `C:\Program Files (x86)\openclaw\openclaw.exe`
- **User-scoped paths**:
  - `AppData\Local\Programs\openclaw\openclaw.exe`
  - `AppData\Roaming\npm\openclaw.cmd`
  - `AppData\Local\pnpm\openclaw.cmd`
  - `.volta\bin\openclaw.exe`
  - `scoop\shims\openclaw.exe`

If found, the script runs `<path> --version` and records the first line as `cli-version`.

### 4.4 Scheduled tasks and ports

- **Scheduled task names**:
  - Base names:
    - `OpenClaw Gateway`
    - `Moltbot Gateway`
    - `Clawdbot Gateway`
  - Profiled: base + ` <PROFILE>`, e.g. `OpenClaw Gateway prod`.
  - Checks via `schtasks /Query /TN <taskName>`.

- **Ports**:
  - Aggregate:
    - `$Port` (from env/default).
    - Ports discovered via `Get-ConfiguredPort` reading JSON and matching `"port": <number>`.
  - Deduplicate (`Sort-Object -Unique`).
  - Probe using `Test-NetConnection -ComputerName localhost -Port <port>`.

### 4.5 Docker on Windows

- Uses `Get-Command docker` to confirm availability.
- Containers and images are queried in the same way as on macOS/Linux, using `Select-String` to filter for `openclaw|moltbot|clawdbot`.

### 4.6 Windows flow diagram

![Windows script flow for detect-openclaw.ps1](./assets/openclawscanner-windows-flow.png)

---

## 5. Output format and exit codes

Both scripts emit:

- A **`summary:` line**:
  - `summary: not-installed`
  - `summary: installed-and-running`
  - `summary: installed-not-running`
- Additional key/value lines such as:
  - `platform: windows|darwin|linux`
  - `cli: <path>|not-found`
  - `cli-version: <string>|n/a`
  - `app: <path>|not-found` (macOS)
  - `state-dir: <path>|not-found`
  - `config: <path>|not-found`
  - `gateway-service: <id>|not-loaded|inactive|not-scheduled`
  - `gateway-port: <number>|not-listening`
  - `docker-container: <matches>|not-found`
  - `docker-image: <matches>|not-found`

### 5.1 Exit codes

| Exit code | Meaning                             | Summary                   | Recommended MDM status        |
|-----------|--------------------------------------|---------------------------|--------------------------------|
| `0`       | OpenClaw/Moltbot/Clawdbot not found | `not-installed`           | **Compliant / Pass / Clean**  |
| `1`       | Evidence of install (running or not)| `installed-and-running` or `installed-not-running` | **Non-compliant / Fail / With issues** |
| `2`       | Script error                        | `error` (or similar)      | **Error / Investigate**       |

MDM/RMM platforms typically:

- Treat **0** as “good / compliant”.
- Treat **1** as “detection found / non-compliant”.
- Treat **2** as “script failure” and may surface errors in logs.

---

## 6. Environment variables and profiles

Two environment variables influence scanner behavior:

| Variable             | Default  | Effect                                                                 |
|----------------------|----------|------------------------------------------------------------------------|
| `OPENCLAW_PROFILE`   | (empty)  | Changes state/config paths (`~/.openclaw-<PROFILE>`) and service names|
| `OPENCLAW_GATEWAY_PORT` | `18789` | Sets base port; merged with ports discovered in config files          |

### 6.1 Profiles

Profiles exist to support:

- Multiple logical OpenClaw instances on the same machine.
- Separate environments (e.g. `dev`, `staging`, `prod`) per user.

The scanner:

- Uses the profile when building:
  - State directory names.
  - Service / task labels.
  - Config paths.
- Still inspects legacy un-profiled directories (`.moltbot`, `.clawdbot`) for completeness.

---

## 7. Integration pattern (how MDM/RMM uses the scripts)

Conceptually, all integrations follow the same model:

![MDM/RMM integration sequence for detect-openclaw](./assets/openclawscanner-mdm-sequence.png)

At a high level:

- The script itself is **stateless** and **read-only**.
- The MDM/RMM:
  - Interprets the **exit code** for compliance.
  - Optionally parses the `summary:` line or other fields for richer classification.
  - May trigger **tickets, alerts, or remediation** based on detection.

---

## 8. `docs/` folder overview

The `docs/` directory contains **vendor-specific integration guides** that all share a common idea:

- Run the detection script on managed endpoints.
- Interpret exit codes to drive compliance/alerts.
- Show operators where to view results.

### 8.1 `docs/addigy.md`

- Uses **Custom Facts** to capture the `OpenClaw Status`:
  - Small wrapper around `detect-openclaw.sh` that:
    - Runs the script.
    - Extracts the `summary` as the fact value (`not-installed`, `installed-and-running`, etc.).
- A **Monitoring item** is then created:
  - Triggers when the fact contains `installed`.
  - Can create alerts and tickets.

### 8.2 `docs/intune.md`

- Uses **Intune Remediations** (detection-only) on Windows:
  - `detect-openclaw.ps1` is uploaded as the **detection script**.
  - There is no remediation script (detection-only).
- Exit code mapping:
  - `0` → **Compliant** (OpenClaw not installed).
  - `1` → **Non-compliant** (OpenClaw detected).
  - `2` → **Error** (script failure).

### 8.3 `docs/jamf.md`

- Jamf Pro **Policy + Script**:
  - Script payload wraps `bash detect-openclaw.sh`.
  - Policy runs at recurring check-in.
- Results:
  - Jamf logs display output and exit codes.
  - A **Smart Group** can be created:
    - Criteria: Policy **failed** = OpenClaw detected.

### 8.4 `docs/jumpcloud.md`

- JumpCloud **Commands**:
  - macOS/Linux:
    - Command snippet: `bash detect-openclaw.sh`.
  - Windows:
    - PowerShell command: `powershell -ExecutionPolicy Bypass -File .\detect-openclaw.ps1`.
- Results:
  - JumpCloud stores stdout/stderr and exit codes.
  - Admins can filter by exit code:
    - `0` = clean.
    - `1` = found.
    - `2` = error.

### 8.5 `docs/kandji.md`

- Kandji **Custom Scripts**:
  - `detect-openclaw.sh` is used as an **Audit Script** (no remediation).
- Exit code mapping:
  - `0` → Pass (not installed).
  - Non-zero → Fail (detected or error).
- Device list filters can show all devices failing the OpenClaw audit.

### 8.6 `docs/workspace-one.md`

- Workspace ONE **Scripts** for macOS:
  - Bash script wrapper around `detect-openclaw.sh`.
  - Runs as **System** to inspect all users.
- Exit code mapping:
  - `0` → Success (OpenClaw not installed).
  - Non-zero → Failed (OpenClaw detected or error).
- Smart Groups can be based on script execution status.

---

## 9. Security considerations

- **Read-only**:
  - The provided scripts **do not remove or modify** OpenClaw or any files.
  - They only read:
    - File system metadata.
    - Config contents.
    - Service/task status.
    - Local ports and Docker state.

- **Minimal dependencies**:
  - Bash script avoids heavy dependencies like `jq` to be MDM-friendly.
  - Uses built-in tools (`grep`, `nc`) that are usually present.

- **Limitations**:
  - If OpenClaw binaries, configs, or services are:
    - Renamed to something entirely unrelated.
    - Relocated to deeply custom paths without any of the expected indicators.
  - Then detection may miss such installations.
  - The scripts match **known patterns** (names and locations); extremely stealthy or heavily obfuscated deployments may require additional EDR/forensic tooling.

---

## 10. Roadmap: skills and prompt-injection detection

The current scripts **do not** inspect OpenClaw skills or LLM prompt content. The roadmap (also reflected in `README.md`) includes:

- Enumerating skills installed for a running or configured OpenClaw instance.
- Flagging:
  - Skills known to be malicious (e.g., exfiltration tools, untrusted sources).
  - Skills suspected of abusing prompt-injection or unsafe model control.
- Surfacing this as:
  - Additional fields in the output (e.g., `skills-malicious: ...`).
  - Potentially refined exit codes or tags for policy engines.

These features are **planned** and will be documented with:

- New output field definitions.
- Updated examples and integration notes.

---

## 11. Usage examples and one-liners

### 11.1 Local runs

- **macOS / Linux**:

  ```bash
  bash detect-openclaw.sh
  ```

  As root to scan all users:

  ```bash
  sudo bash detect-openclaw.sh
  ```

- **Windows (PowerShell)**:

  ```powershell
  powershell -ExecutionPolicy Bypass -File .\detect-openclaw.ps1
  ```

### 11.2 Direct-from-GitHub one-liners

- **macOS / Linux**:

  ```bash
  bash <(curl -fsSL https://raw.githubusercontent.com/ibrahimsaleem/openclawscanner/main/detect-openclaw.sh)
  ```

- **Windows (PowerShell)**:

  ```powershell
  irm https://raw.githubusercontent.com/ibrahimsaleem/openclawscanner/main/detect-openclaw.ps1 | powershell -ExecutionPolicy Bypass -NoProfile -
  ```

These are useful for:

- Incident responders doing spot checks.
- Environments where you do not want to clone the repository locally.

---

## 12. Summary

`openclawscanner` provides:

- A **consistent, cross-platform** way to detect OpenClaw/Moltbot/Clawdbot installations and activity.
- A **simple exit-code contract** that fits naturally into MDM/RMM compliance models.
- **Vendor-specific guides** to accelerate integration on Addigy, Intune, Jamf, JumpCloud, Kandji, and VMware Workspace ONE.

The scripts are intentionally **simple, transparent, and read-only**, making them suitable for production detection and incident response workflows. Future work will extend detection to cover **skills and prompt-injection risk** while preserving the same integration patterns.

