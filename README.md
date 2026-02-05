# openclawscanner

Lightweight cross-platform detection scripts for **OpenClaw** and its previous names **Moltbot** and **Clawdbot**.  
These scripts are designed for:

- **MDM / RMM deployment** (Addigy, Intune, Jamf, JumpCloud, Workspace ONE, Kandji, etc.)
- **Standalone use by incident responders or admins**

Currently the repo ships:

- `detect-openclaw.sh` — macOS / Linux
- `detect-openclaw.ps1` — Windows

Both scripts return machine-readable output and opinionated exit codes for easy policy wiring.

---

## Features

The detectors look for OpenClaw/Moltbot/Clawdbot presence via:

| Check | macOS | Linux | Windows |
|-------|-------|-------|---------|
| CLI binary (`openclaw`) | Yes | Yes | Yes |
| CLI version | Yes | Yes | Yes |
| macOS app (`/Applications/OpenClaw.app`) | Yes | - | - |
| State directory (`~/.openclaw`, legacy: `~/.moltbot`, `~/.clawdbot`) | Yes | Yes | Yes |
| Config file (`openclaw.json` / legacy configs) | Yes | Yes | Yes |
| Gateway service (launchd/systemd/schtasks) | Yes | Yes | Yes |
| Gateway port (default `18789` plus any ports found in configs) | Yes | Yes | Yes |
| Docker containers | Yes | Yes | Yes |
| Docker images | Yes | Yes | Yes |

---

## Exit codes

Both scripts use the same exit code contract so your MDM policy logic is consistent:

| Exit code | Meaning | MDM status suggestion |
|-----------|---------|-----------------------|
| `0` | Not installed / no indicators found | **Success (clean)** |
| `1` | Installed (running or not) | **Error / non-compliant (found)** |
| `2` | Script error (permissions, environment, etc.) | **Error (investigate)** |

---

## Usage

### macOS / Linux

Local run:

```bash
bash detect-openclaw.sh
```

Scan all local users (requires root):

```bash
sudo bash detect-openclaw.sh
```

You can deploy the script via MDM custom scripts / extension attributes and branch on the exit code and/or parse the `summary:` line.

### Windows (PowerShell)

Local run from an elevated or standard PowerShell session:

```powershell
powershell -ExecutionPolicy Bypass -File .\detect-openclaw.ps1
```

As with the bash variant, you can:

- key off the **exit code** in your MDM/RMM
- parse the **text output** for `summary:` and other fields

If you host these scripts on your own HTTP server or Git repository, update any MDM-side URLs to point at your hosted copies.

---

## Environment variables

Both scripts support the same tuning knobs:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCLAW_PROFILE` | (empty) | Profile name for multi-instance setups; affects state/config paths and service names |
| `OPENCLAW_GATEWAY_PORT` | `18789` | Base gateway port to check; additional ports are discovered from config files |

---

## Example output

Example from a macOS host with OpenClaw running:

```text
summary: installed-and-running
platform: darwin
cli: /usr/local/bin/openclaw
cli-version: 2026.1.15
app: /Applications/OpenClaw.app
state-dir: /Users/alice/.openclaw
config: /Users/alice/.openclaw/openclaw.json
gateway-service: gui/501/bot.molt.gateway
gateway-port: 18789
docker-container: not-found
docker-image: not-found
```

`summary` plus the exit code are usually all you need for compliance / detection policies.

---

## MDM integration guides

Platform-specific deployment notes live under `docs/`:

| Platform | Guide |
|----------|-------|
| Addigy | `docs/addigy.md` |
| JumpCloud | `docs/jumpcloud.md` |
| Microsoft Intune | `docs/intune.md` |
| Jamf Pro | `docs/jamf.md` |
| VMware Workspace ONE | `docs/workspace-one.md` |
| Kandji | `docs/kandji.md` |

---

## License

Apache 2.0 — see `LICENSE` for details.
# OpenClaw / Moltbot / Clawdbot Detection Scripts

Lightweight detection scripts for macOS, Linux, and Windows that check for CLI binaries, app bundles, config files, gateway services, and Docker artifacts for OpenClaw and its previous names Moltbot and Clawdbot. Designed for MDM deployment or standalone use.

---

## TL;DR

Detection scripts for MDM deployment to identify OpenClaw/Moltbot/Clawdbot installations on managed devices.

## What It Detects

| Check | macOS | Linux | Windows |
|-------|-------|-------|---------|
| CLI binary (`openclaw`) | Yes | Yes | Yes |
| CLI version | Yes | Yes | Yes |
| macOS app (`/Applications/OpenClaw.app`) | Yes | - | - |
| State directory (`~/.openclaw`) | Yes | Yes | Yes |
| Config file (`~/.openclaw/openclaw.json`) | Yes | Yes | Yes |
| Gateway service (launchd/systemd/schtasks) | Yes | Yes | Yes |
| Gateway port (default 18789) | Yes | Yes | Yes |
| Docker containers | Yes | Yes | Yes |
| Docker images | Yes | Yes | Yes |

## Exit Codes

| Exit Code | Meaning | MDM Status |
|-----------|---------|------------|
| 0 | NOT installed | Success (clean) |
| 1 | Installed (running or not) | Error (found) |
| 2 | Script error | Error (investigate) |

## Usage

### macOS/Linux (local script)

```bash
bash detect-openclaw.sh
```

To scan all users, run with `sudo`:

```bash
sudo bash detect-openclaw.sh
```

### Windows (PowerShell, local script)

```powershell
powershell -ExecutionPolicy Bypass -File .\detect-openclaw.ps1
```

If you host these scripts on your own HTTP server or Git repository, update the URLs in your MDM integration to point at your copies.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCLAW_PROFILE` | (none) | Profile name for multi-instance setups |
| `OPENCLAW_GATEWAY_PORT` | 18789 | Gateway port to check |

## Example Output

```
summary: installed-and-running
platform: darwin
cli: /usr/local/bin/openclaw
cli-version: 2026.1.15
app: /Applications/OpenClaw.app
state-dir: /Users/alice/.openclaw
config: /Users/alice/.openclaw/openclaw.json
gateway-service: gui/501/bot.molt.gateway
gateway-port: 18789
docker-container: not-found
docker-image: not-found
```

---

## MDM Integration

| Platform | Guide |
|----------|-------|
| Addigy | [docs/addigy.md](docs/addigy.md) |
| JumpCloud | [docs/jumpcloud.md](docs/jumpcloud.md) |
| Microsoft Intune | [docs/intune.md](docs/intune.md) |
| Jamf Pro | [docs/jamf.md](docs/jamf.md) |
| VMware Workspace ONE | [docs/workspace-one.md](docs/workspace-one.md) |
| Kandji | [docs/kandji.md](docs/kandji.md) |

