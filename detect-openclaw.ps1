param(
    [switch]$ScanSkills
)

# Detection script for OpenClaw / Moltbot / Clawdbot (Windows)
# Exit codes:
#   0 = not-installed (clean)
#   1 = OpenClaw/Moltbot/Clawdbot installed (non-compliant)
#   2 = error
#   3 = malicious skill installed (from risk.txt, only when -ScanSkills is used)

$ErrorActionPreference = "Stop"

# Sanitize profile: alphanumeric, dash, underscore only (safe for paths and task names)
$script:Profile = if ($env:OPENCLAW_PROFILE) { ($env:OPENCLAW_PROFILE -replace '[^a-zA-Z0-9_-]', '') } else { '' }

# Validate base port (1-65535); default 18789
$portRaw = if ($env:OPENCLAW_GATEWAY_PORT) { $env:OPENCLAW_GATEWAY_PORT } else { 18789 }
$portNum = 0
if ([int]::TryParse($portRaw, [ref]$portNum) -and $portNum -ge 1 -and $portNum -le 65535) {
    $Port = $portNum
} else {
    $Port = 18789
}

$script:Output = [System.Collections.ArrayList]::new()
$script:InstalledSkills = [System.Collections.ArrayList]::new()

function Out {
    param([string]$Line)
    [void]$script:Output.Add($Line)
}

function Get-MaliciousSkillSet {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
    $riskPath = Join-Path $scriptDir "risk.txt"
    if (-not (Test-Path $riskPath -PathType Leaf)) { return @() }

    $lines = Get-Content $riskPath
    $start = $lines | Select-String -Pattern "Malicious Skills" -SimpleMatch | Select-Object -First 1
    if (-not $start) { return @() }

    $idx = $start.LineNumber
    if ($idx -ge $lines.Count) { return @() }

    $tail = $lines[$idx..($lines.Count - 1)]
    $skills = @()

    foreach ($line in $tail) {
        $token = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        if ($token.StartsWith("#")) { continue }
        $skills += $token.ToLowerInvariant()
    }

    return $skills
}

function Test-SkillMalicious {
    param(
        [string]$Name,
        [string[]]$MaliciousSet
    )

    if (-not $MaliciousSet -or -not $Name) { return $false }
    $nameLc = $Name.ToLowerInvariant()
    return $MaliciousSet -contains $nameLc
}

function Get-InstalledSkills {
    param([string]$Root)

    $results = @()
    if (-not (Test-Path $Root -PathType Container)) { return $results }

    Get-ChildItem $Root -Recurse -Filter "SKILL.md" -File -ErrorAction SilentlyContinue | ForEach-Object {
        $results += [PSCustomObject]@{
            Name = $_.Directory.Name
            Path = $_.FullName
        }
    }

    return $results
}

function Add-SkillsFromStateDir {
    param([string]$StateDir)

    if (-not $StateDir) { return }
    if (-not $ScanSkills) { return }

    $skillsRoot = Join-Path $StateDir "skills"
    if (Test-Path $skillsRoot -PathType Container) {
        foreach ($s in (Get-InstalledSkills -Root $skillsRoot)) {
            [void]$script:InstalledSkills.Add($s)
        }
    }

    $extensionsRoot = Join-Path $StateDir "extensions"
    if (Test-Path $extensionsRoot -PathType Container) {
        Get-ChildItem $extensionsRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $extSkillsRoot = Join-Path $_.FullName "skills"
            if (Test-Path $extSkillsRoot -PathType Container) {
                foreach ($s in (Get-InstalledSkills -Root $extSkillsRoot)) {
                    [void]$script:InstalledSkills.Add($s)
                }
            }
        }
    }
}

function Get-StateDir {
    param([string]$HomeDir)
    if ($script:Profile) {
        return Join-Path $HomeDir ".openclaw-$($script:Profile)"
    }
    return Join-Path $HomeDir ".openclaw"
}

function Get-UsersToCheck {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544') {
        Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } | ForEach-Object { $_.Name }
    } else {
        $env:USERNAME
    }
}

function Get-HomeDir {
    param([string]$User)
    return "C:\Users\$User"
}

function Test-CliInPath {
    try {
        $cmd = Get-Command openclaw -ErrorAction SilentlyContinue
        if ($cmd) {
            return $cmd.Source
        }
    } catch {}
    return $null
}

function Test-CliGlobal {
    $locations = @(
        "C:\Program Files\openclaw\openclaw.exe",
        "C:\Program Files (x86)\openclaw\openclaw.exe"
    )
    foreach ($loc in $locations) {
        if (Test-Path $loc) {
            return $loc
        }
    }
    return $null
}

function Test-CliForUser {
    param([string]$HomeDir)
    $locations = @(
        (Join-Path $HomeDir "AppData\Local\Programs\openclaw\openclaw.exe"),
        (Join-Path $HomeDir "AppData\Roaming\npm\openclaw.cmd"),
        (Join-Path $HomeDir "AppData\Local\pnpm\openclaw.cmd"),
        (Join-Path $HomeDir ".volta\bin\openclaw.exe"),
        (Join-Path $HomeDir "scoop\shims\openclaw.exe")
    )
    foreach ($loc in $locations) {
        if (Test-Path $loc) {
            return $loc
        }
    }
    return $null
}

function Test-SafeCliPath {
    param([string]$CliPath)
    if ([string]::IsNullOrWhiteSpace($CliPath)) { return $false }
    try {
        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CliPath)
        if (-not $fullPath) { return $false }
        # Allow only under Program Files or Users (Intune/S1 typical install locations)
        if ($fullPath -like "C:\Program Files*") { return $true }
        if ($fullPath -like "C:\Program Files (x86)*") { return $true }
        if ($fullPath -like "C:\Users*") { return $true }
    } catch {}
    return $false
}

function Get-CliVersion {
    param([string]$CliPath)
    if (-not (Test-SafeCliPath -CliPath $CliPath)) { return "unknown" }
    try {
        $version = & $CliPath --version 2>$null | Select-Object -First 1
        if ($version) { return $version }
    } catch {}
    return "unknown"
}

function Test-StateDir {
    param([string]$Path)
    return Test-Path $Path -PathType Container
}

function Test-Config {
    param([string]$StateDir)
    return Test-Path (Join-Path $StateDir "openclaw.json") -PathType Leaf
}

function Get-ConfiguredPort {
    param([string]$ConfigFile)
    if (Test-Path $ConfigFile) {
        try {
            $content = Get-Content $ConfigFile -Raw
            if ($content -match '"port"\s*:\s*(\d+)') {
                $p = [int]$matches[1]
                if ($p -ge 1 -and $p -le 65535) { return $matches[1] }
            }
        } catch {}
    }
    return $null
}

function Test-ScheduledTask {
    $baseNames = @("OpenClaw Gateway", "Moltbot Gateway", "Clawdbot Gateway")
    foreach ($base in $baseNames) {
        $taskName = if ($script:Profile) { "$base $($script:Profile)" } else { $base }
        try {
            $null = schtasks /Query /TN $taskName 2>$null
            if ($LASTEXITCODE -eq 0) {
                return $taskName
            }
        } catch {}
    }
    return $null
}

function Test-GatewayPort {
    param([int]$PortNum)
    if ($PortNum -lt 1 -or $PortNum -gt 65535) { return $false }
    try {
        $result = Test-NetConnection -ComputerName localhost -Port $PortNum -WarningAction SilentlyContinue
        return $result.TcpTestSucceeded
    } catch {
        return $false
    }
}

function Get-DockerContainers {
    try {
        $cmd = Get-Command docker -ErrorAction SilentlyContinue
        if (-not $cmd) { return $null }
        $containers = docker ps --format '{{.Names}} ({{.Image}})' 2>$null | Select-String -Pattern "openclaw|moltbot|clawdbot"
        if ($containers) {
            return ($containers -join ", ")
        }
    } catch {}
    return $null
}

function Get-DockerImages {
    try {
        $cmd = Get-Command docker -ErrorAction SilentlyContinue
        if (-not $cmd) { return $null }
        $images = docker images --format '{{.Repository}}:{{.Tag}}' 2>$null | Select-String -Pattern "openclaw|moltbot|clawdbot"
        if ($images) {
            return ($images -join ", ")
        }
    } catch {}
    return $null
}

function Main {
    $cliFound = $false
    $stateFound = $false
    $serviceRunning = $false
    $portListening = $false
    $maliciousFound = $false

    Out "platform: windows"

    # check global CLI locations first
    $cliPath = Test-CliInPath
    if (-not $cliPath) { $cliPath = Test-CliGlobal }
    if ($cliPath) {
        $cliFound = $true
        Out "cli: $cliPath"
        Out "cli-version: $(Get-CliVersion $cliPath)"
    }

    $users = @(Get-UsersToCheck)
    $multiUser = $users.Count -gt 1
    $portsToCheck = @($Port)

    foreach ($user in $users) {
        $homeDir = Get-HomeDir $user
        $stateDir = Get-StateDir $homeDir
        $configFile = Join-Path $stateDir "openclaw.json"

        if ($multiUser) {
            Out "user: $user"
            # check user-specific CLI if not already found
            if (-not $cliFound) {
                $userCli = Test-CliForUser $homeDir
                if ($userCli) {
                    $cliFound = $true
                    Out "  cli: $userCli"
                    Out "  cli-version: $(Get-CliVersion $userCli)"
                }
            }
            if (Test-StateDir $stateDir) {
                Out "  state-dir: $stateDir"
                $stateFound = $true
                Add-SkillsFromStateDir -StateDir $stateDir
            } else {
                Out "  state-dir: not-found"
            }
            if (Test-Config $stateDir) {
                Out "  config: $configFile"
            } else {
                Out "  config: not-found"
            }
            $configPort = Get-ConfiguredPort $configFile
            if ($configPort) {
                Out "  config-port: $configPort"
                $portsToCheck += [int]$configPort
            }
            # legacy names: Clawdbot and Moltbot state/config
            $clawdbotStateDir = Join-Path $homeDir ".clawdbot"
            $clawdbotConfigFile = Join-Path $clawdbotStateDir "clawdbot.json"
            if (Test-StateDir $clawdbotStateDir) {
                Out "  clawdbot-state-dir: $clawdbotStateDir"
                $stateFound = $true
                Add-SkillsFromStateDir -StateDir $clawdbotStateDir
            } else {
                Out "  clawdbot-state-dir: not-found"
            }
            if (Test-Path $clawdbotConfigFile -PathType Leaf) {
                Out "  clawdbot-config: $clawdbotConfigFile"
                $configPort = Get-ConfiguredPort $clawdbotConfigFile
                if ($configPort) {
                    Out "  clawdbot-config-port: $configPort"
                    $portsToCheck += [int]$configPort
                }
            } else {
                Out "  clawdbot-config: not-found"
            }

            $moltbotStateDir = Join-Path $homeDir ".moltbot"
            $moltbotConfigFile = Join-Path $moltbotStateDir "moltbot.json"
            if (Test-StateDir $moltbotStateDir) {
                Out "  moltbot-state-dir: $moltbotStateDir"
                $stateFound = $true
                Add-SkillsFromStateDir -StateDir $moltbotStateDir
            } else {
                Out "  moltbot-state-dir: not-found"
            }
            if (Test-Path $moltbotConfigFile -PathType Leaf) {
                Out "  moltbot-config: $moltbotConfigFile"
                $configPort = Get-ConfiguredPort $moltbotConfigFile
                if ($configPort) {
                    Out "  moltbot-config-port: $configPort"
                    $portsToCheck += [int]$configPort
                }
            } else {
                Out "  moltbot-config: not-found"
            }
        } else {
            # single user mode - check user CLI
            if (-not $cliFound) {
                $userCli = Test-CliForUser $homeDir
                if ($userCli) {
                    $cliFound = $true
                    Out "cli: $userCli"
                    Out "cli-version: $(Get-CliVersion $userCli)"
                }
            }
            if (-not $cliFound) {
                Out "cli: not-found"
                Out "cli-version: n/a"
            }
            if (Test-StateDir $stateDir) {
                Out "state-dir: $stateDir"
                $stateFound = $true
                Add-SkillsFromStateDir -StateDir $stateDir
            } else {
                Out "state-dir: not-found"
            }
            if (Test-Config $stateDir) {
                Out "config: $configFile"
            } else {
                Out "config: not-found"
            }
            $configPort = Get-ConfiguredPort $configFile
            if ($configPort) {
                Out "config-port: $configPort"
                $portsToCheck += [int]$configPort
            }

            # legacy names: Clawdbot and Moltbot state/config
            $clawdbotStateDir = Join-Path $homeDir ".clawdbot"
            $clawdbotConfigFile = Join-Path $clawdbotStateDir "clawdbot.json"
            if (Test-StateDir $clawdbotStateDir) {
                Out "clawdbot-state-dir: $clawdbotStateDir"
                $stateFound = $true
                Add-SkillsFromStateDir -StateDir $clawdbotStateDir
            } else {
                Out "clawdbot-state-dir: not-found"
            }
            if (Test-Path $clawdbotConfigFile -PathType Leaf) {
                Out "clawdbot-config: $clawdbotConfigFile"
                $configPort = Get-ConfiguredPort $clawdbotConfigFile
                if ($configPort) {
                    Out "clawdbot-config-port: $configPort"
                    $portsToCheck += [int]$configPort
                }
            } else {
                Out "clawdbot-config: not-found"
            }

            $moltbotStateDir = Join-Path $homeDir ".moltbot"
            $moltbotConfigFile = Join-Path $moltbotStateDir "moltbot.json"
            if (Test-StateDir $moltbotStateDir) {
                Out "moltbot-state-dir: $moltbotStateDir"
                $stateFound = $true
                Add-SkillsFromStateDir -StateDir $moltbotStateDir
            } else {
                Out "moltbot-state-dir: not-found"
            }
            if (Test-Path $moltbotConfigFile -PathType Leaf) {
                Out "moltbot-config: $moltbotConfigFile"
                $configPort = Get-ConfiguredPort $moltbotConfigFile
                if ($configPort) {
                    Out "moltbot-config-port: $configPort"
                    $portsToCheck += [int]$configPort
                }
            } else {
                Out "moltbot-config: not-found"
            }
        }
    }

    # print cli not-found for multi-user if none found
    if ($multiUser -and -not $cliFound) {
        Out "cli: not-found"
        Out "cli-version: n/a"
    }

    $taskResult = Test-ScheduledTask
    if ($taskResult) {
        Out "gateway-service: $taskResult"
        $serviceRunning = $true
    } else {
        Out "gateway-service: not-scheduled"
    }

    $uniquePorts = $portsToCheck | Sort-Object -Unique
    $listeningPort = $null
    foreach ($p in $uniquePorts) {
        if (Test-GatewayPort $p) {
            $portListening = $true
            $listeningPort = $p
            break
        }
    }
    if ($portListening) {
        Out "gateway-port: $listeningPort"
    } else {
        Out "gateway-port: not-listening"
    }

    $dockerContainers = Get-DockerContainers
    $dockerRunning = $false
    if ($dockerContainers) {
        $dockerRunning = $true
        Out "docker-container: $dockerContainers"
    } else {
        Out "docker-container: not-found"
    }

    $dockerImages = Get-DockerImages
    $dockerInstalled = $false
    if ($dockerImages) {
        $dockerInstalled = $true
        Out "docker-image: $dockerImages"
    } else {
        Out "docker-image: not-found"
    }

    $installed = $cliFound -or $stateFound -or $dockerInstalled
    $running = $serviceRunning -or $portListening -or $dockerRunning

    # Skills and malicious skills summary (only if something is installed and -ScanSkills is used)
    $skillsInstalledCount = 0
    $maliciousSkills = @()
    $maliciousSet = @()
    if ($installed -and $ScanSkills) {
        $skillsInstalledCount = $script:InstalledSkills.Count
        if ($skillsInstalledCount -gt 0) {
            $maliciousSet = Get-MaliciousSkillSet
            Out "skills-installed-count: $skillsInstalledCount"
            foreach ($s in $script:InstalledSkills) {
                Out "installed-skill: $($s.Name) (path: $($s.Path))"
                if (Test-SkillMalicious -Name $s.Name -MaliciousSet $maliciousSet) {
                    $maliciousSkills += $s
                }
            }
            Out "malicious-skills-count: $($maliciousSkills.Count)"
            foreach ($m in $maliciousSkills) {
                Out "malicious-skill: $($m.Name) (path: $($m.Path))"
            }
            if ($maliciousSkills.Count -gt 0) {
                $maliciousFound = $true
            }
        }
    }

    # exit codes:
    #   0 = not-installed (clean)
    #   1 = installed (non-compliant), no malicious skills
    #   2 = error
    #   3 = malicious skills installed
    if (-not $installed) {
        Write-Output "summary: not-installed"
        $script:Output | ForEach-Object { Write-Output $_ }
        exit 0
    } elseif ($maliciousFound) {
        if ($running) {
            Write-Output "summary: installed-and-running"
        } else {
            Write-Output "summary: installed-not-running"
        }
        $script:Output | ForEach-Object { Write-Output $_ }
        exit 3
    } elseif ($running) {
        Write-Output "summary: installed-and-running"
        $script:Output | ForEach-Object { Write-Output $_ }
        exit 1
    } else {
        Write-Output "summary: installed-not-running"
        $script:Output | ForEach-Object { Write-Output $_ }
        exit 1
    }
}

try {
    Main
} catch {
    Write-Output "summary: error"
    Write-Output "error: $_"
    exit 2
}
