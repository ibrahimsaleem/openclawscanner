# Security Audit Report: openclawscanner

**Date:** 2026-02-05  
**Auditor:** Automated Security Analysis  
**Scope:** `detect-openclaw.sh` and `detect-openclaw.ps1`  
**Status:** HIGH and MEDIUM priority fixes **APPLIED** (see changelog at end).

---

## Executive Summary

Overall security posture: **GOOD**. Recommended hardening fixes have been implemented.

The scripts are **read-only detection tools** with no network operations or data exfiltration. They follow security best practices but have a few areas for improvement.

---

## Findings

### ✅ **STRENGTHS**

1. **Read-only operations**: Scripts only read filesystem metadata and configs; no modifications
2. **No network operations**: No outbound connections (except localhost port checks)
3. **Proper error handling**: `set -euo pipefail` in bash, try-catch in PowerShell
4. **Safe command execution**: Uses `command -v` instead of direct execution where possible
5. **Path validation**: Uses `basename`, `dirname`, and `Join-Path` to prevent path traversal
6. **Controlled inputs**: Most variables come from environment or controlled sources

---

### ⚠️ **MEDIUM RISK FINDINGS**

#### 1. **Environment Variable Injection (Bash)**
**Location:** `detect-openclaw.sh` lines 88, 200, 214  
**Issue:** `OPENCLAW_PROFILE` environment variable is used directly in path/service name construction without sanitization.

```bash
echo "${home}/.openclaw-${PROFILE}"  # Line 88
label="bot.molt.${PROFILE}"          # Line 200
service="openclaw-gateway-${PROFILE}.service"  # Line 214
```

**Risk:** If `OPENCLAW_PROFILE` contains special characters or path separators (`/`, `\`, `..`), it could:
- Create unexpected directory paths
- Break service name validation
- Potentially allow path traversal in edge cases

**Recommendation:**
```bash
# Sanitize PROFILE to alphanumeric, dash, underscore only
PROFILE="${OPENCLAW_PROFILE:-}"
PROFILE="${PROFILE//[^a-zA-Z0-9_-]/}"  # Remove invalid chars
```

**Severity:** Medium (exploitation requires control of environment variables)

---

#### 2. **Command Execution from Discovered Paths (Bash)**
**Location:** `detect-openclaw.sh` lines 279, 311, 406  
**Issue:** Executes binaries found in filesystem without full path validation.

```bash
out "cli-version: $("$cli_result" --version 2>/dev/null | head -1 || echo "unknown")"
```

**Risk:** If an attacker controls the filesystem and places a malicious `openclaw` binary in a scanned location, it could execute arbitrary code when `--version` is called.

**Mitigation:** 
- ✅ Uses `command -v` which checks PATH integrity
- ✅ Only checks specific hardcoded paths
- ✅ Uses `2>/dev/null` to suppress errors
- ⚠️ Still executes discovered binaries

**Recommendation:** Add path validation:
```bash
# Ensure path is absolute and within expected locations
if [[ "$cli_result" =~ ^(/usr|/opt|/home|~)/ ]] && [[ -x "$cli_result" ]]; then
    # Safe to execute
fi
```

**Severity:** Medium (requires filesystem compromise)

---

#### 3. **Port Injection via Config File (Both Scripts)**
**Location:** `detect-openclaw.sh` line 229, `detect-openclaw.ps1` line 186  
**Issue:** Ports extracted from JSON config files are used directly in network operations.

```bash
grep -o '"port"[[:space:]]*:[[:space:]]*[0-9]*' "$config_file" | grep -o '[0-9]*$'
```

**Risk:** If a malicious config file contains a port outside valid range (1-65535), or contains injection characters, it could:
- Cause port scan failures
- Potentially be used in command injection (though `nc` and `Test-NetConnection` are generally safe)

**Current Mitigation:**
- ✅ Uses regex to extract only digits
- ✅ `nc -z` and `Test-NetConnection` are relatively safe

**Recommendation:** Validate port range:
```bash
if [[ "$configured_port" =~ ^[0-9]+$ ]] && (( configured_port >= 1 && configured_port <= 65535 )); then
    # Valid port
fi
```

**Severity:** Low-Medium (limited impact, but good practice)

---

#### 4. **PowerShell Script Injection via Profile (PowerShell)**
**Location:** `detect-openclaw.ps1` lines 104, 197  
**Issue:** `$script:Profile` from environment is used in string interpolation.

```powershell
return Join-Path $HomeDir ".openclaw-$($script:Profile)"
$taskName = if ($script:Profile) { "$base $($script:Profile)" } else { $base }
```

**Risk:** If `OPENCLAW_PROFILE` contains PowerShell special characters (`$`, `` ` ``, `"`), it could cause:
- Path construction errors
- Potential code injection in string evaluation contexts

**Recommendation:**
```powershell
# Sanitize profile name
$script:Profile = if ($env:OPENCLAW_PROFILE) { 
    $env:OPENCLAW_PROFILE -replace '[^a-zA-Z0-9_-]', '' 
} else { '' }
```

**Severity:** Medium (requires environment variable control)

---

### 🔍 **LOW RISK / INFORMATIONAL FINDINGS**

#### 5. **Docker Command Execution**
**Location:** `detect-openclaw.sh` lines 248, 255  
**Issue:** Executes `docker` commands if available.

```bash
docker ps --format '{{.Names}} ({{.Image}})' 2>/dev/null | grep -Ei 'openclaw|moltbot|clawdbot'
```

**Risk:** If Docker is compromised or returns malicious output, it could affect parsing. However:
- ✅ Output is only parsed, not executed
- ✅ Uses `2>/dev/null` to suppress errors
- ✅ Only reads container/image names

**Severity:** Low (read-only operation)

---

#### 6. **File Path Disclosure**
**Location:** Both scripts output full file paths  
**Issue:** Scripts output discovered paths in plaintext.

**Risk:** Information disclosure if logs are captured by attackers. However, this is expected behavior for a detection tool.

**Severity:** Informational (by design)

---

#### 7. **User Enumeration**
**Location:** `detect-openclaw.sh` lines 99-106, `detect-openclaw.ps1` line 111  
**Issue:** Enumerates all users when run as root/admin.

**Risk:** Information disclosure, but this is expected behavior for MDM/RMM tools.

**Severity:** Informational (by design)

---

### ✅ **SECURE PRACTICES OBSERVED**

1. **No eval/exec**: No use of `eval`, `exec`, or unsafe command substitution
2. **Proper quoting**: Variables are properly quoted in bash (`"$var"`)
3. **Error suppression**: Uses `2>/dev/null` and `|| true` appropriately
4. **Path sanitization**: Uses `basename`, `dirname`, `Join-Path` to prevent traversal
5. **Read-only**: All file operations are read-only
6. **No secrets**: No hardcoded credentials or API keys
7. **Safe defaults**: Uses `:-` for default values in bash

---

## Recommendations Priority

### **HIGH PRIORITY**
1. ✅ Sanitize `OPENCLAW_PROFILE` environment variable in both scripts
2. ✅ Validate port numbers are in valid range (1-65535)

### **MEDIUM PRIORITY**
3. ⚠️ Add path validation before executing discovered binaries
4. ⚠️ Consider rate limiting for port scans (if scanning many ports)

### **LOW PRIORITY**
5. 📝 Add input validation documentation
6. 📝 Consider adding a `--dry-run` mode for testing

---

## Attack Surface Analysis

### **Potential Attack Vectors**

1. **Environment Variable Manipulation**
   - Attacker sets `OPENCLAW_PROFILE` to malicious value
   - **Mitigation:** Sanitize input (recommended above)

2. **Filesystem Poisoning**
   - Attacker places malicious `openclaw` binary in scanned location
   - **Mitigation:** Path validation (recommended above)

3. **Config File Manipulation**
   - Attacker modifies `openclaw.json` with malicious port values
   - **Mitigation:** Port validation (recommended above)

4. **Docker Output Injection**
   - Attacker controls Docker container/image names
   - **Mitigation:** Current parsing is safe (low risk)

---

## Compliance Notes

- ✅ **Read-only**: Complies with security policy
- ✅ **No network egress**: Safe for air-gapped environments
- ✅ **No data collection**: Privacy-friendly
- ✅ **Audit-friendly**: Clear exit codes and structured output

---

## Conclusion

The scripts are **well-designed** for their purpose as read-only detection tools. The identified issues are **low-to-medium risk** and mostly require **environment variable control** or **filesystem compromise** to exploit.

**Overall Security Rating: 7.5/10**

**Recommendation:** Implement the HIGH PRIORITY fixes (profile sanitization and port validation) before production deployment in high-security environments.

---

## Testing Recommendations

1. **Fuzzing**: Test with malicious `OPENCLAW_PROFILE` values
2. **Path traversal**: Test with `../` in profile names
3. **Port validation**: Test with ports outside 1-65535 range
4. **Binary execution**: Test with symlinked malicious binaries
5. **Docker injection**: Test with Docker containers with special characters in names

---

---

## Changelog (fixes applied)

- **PROFILE sanitization:** `OPENCLAW_PROFILE` is sanitized to `[a-zA-Z0-9_-]` only in both scripts.
- **Port validation:** Base port and config-derived ports are validated to 1–65535 in both scripts; invalid ports are ignored or defaulted.
- **Safe CLI execution (Bash):** `is_safe_cli_path()` ensures only absolute paths under `/usr`, `/opt`, `/home`, `/Users` are executed for `--version`.
- **Safe CLI execution (PowerShell):** `Test-SafeCliPath()` ensures only paths under `C:\Program Files`, `C:\Program Files (x86)`, or `C:\Users` are executed for `--version`.
- **risk.txt path (PowerShell):** Uses `$PSScriptRoot` when available so the script finds `risk.txt` when run as Intune/SentinelOne custom script (script and risk.txt in same folder).

---

**Report Generated:** 2026-02-05
