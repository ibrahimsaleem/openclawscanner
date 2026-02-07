# Microsoft Intune Integration

Intune Remediations allow you to deploy detection scripts to Windows devices. For OpenClaw detection, only a detection script is needed (no remediation script).

## Setup

1. Navigate to **Devices > Manage devices > Scripts and remediations**
2. Click **Create script package**
3. **Name:** OpenClaw Detection
4. **Detection script:** Upload the PowerShell script below
5. **Remediation script:** Leave empty (detection only)
6. **Run script in 64-bit PowerShell:** Yes
7. **Run this script using the logged-on credentials:** No (runs as SYSTEM)

## Detection Script

Save as `detect-openclaw.ps1` and upload the script from this repository, or host it on your own internal server and adjust the download command accordingly.

**Optional skill scanning:** To detect malicious skills, add the `-ScanSkills` parameter and ensure `risk.txt` is in the **same folder** as the script when you package it. Intune runs the script from a working directory where the script is extracted; the script resolves `risk.txt` via `$PSScriptRoot`.

## Exit Codes

| Exit Code | Intune Status | Meaning |
|-----------|---------------|---------|
| 0 | Compliant | OpenClaw not installed |
| 1 | Non-compliant | OpenClaw detected (no malicious skills) |
| 2 | Error | Script failed |
| 3 | Non-compliant | OpenClaw detected and malicious skill(s) found (when using `-ScanSkills`) |

## Assignment

1. Click **Assignments**
2. Add device groups to target
3. Set schedule (default: every 8 hours)

## Viewing Results

1. Navigate to **Devices > Manage devices > Scripts and remediations**
2. Select **OpenClaw Detection**
3. View **Device status** for per-device results
4. Filter by **Detection status: With issues** to find devices with OpenClaw

## Reference

[Microsoft Learn - Remediations](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/remediations)
