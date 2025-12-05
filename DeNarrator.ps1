param(
    [switch]$Activate,
    [switch]$Deactivate
)

# Global state for DeNarrator
if (-not $Global:DeNarratorState) {
    $Global:DeNarratorState = [ordered]@{
        Active        = $false
        Key           = $null
        StartTime     = Get-Date
        FakeHostname  = "lab-gateway-01"
        FakeUser      = "svc_backup"
        FakeDomain    = "LAB-SEGMENT"
        FakeOS        = "Microsoft Windows Server 2016 Datacenter"
        FakeIP        = "10.13.37.42"
        FakeMAC       = "00-15-5D-AB-CD-EF"
        FakeUUID      = "EC2F3A12-0F9E-4C8F-9B3D-11AA22BB33CC"
        Job           = $null
        LogsPath      = Join-Path $PSScriptRoot 'logs'
        OriginalFuncs = @{}
    }
}

function New-DeNarratorKey {
    $keyPath = Join-Path $PSScriptRoot 'key.txt'
    if (-not (Test-Path $keyPath)) {
        $key = [guid]::NewGuid().ToString('N')
        Set-Content -Path $keyPath -Value $key -Encoding ASCII
    }
    Get-Content -Path $keyPath -Raw
}

function Start-DeNarratorCore {
    if ($Global:DeNarratorState.Active) { return }

    $Global:DeNarratorState.Key = New-DeNarratorKey

    if (-not (Test-Path $Global:DeNarratorState.LogsPath)) {
        New-Item -ItemType Directory -Path $Global:DeNarratorState.LogsPath | Out-Null
    }

    # Background job to evolve fake logs
    $scriptRoot = $PSScriptRoot
    $job = Start-Job -ScriptBlock {
        param($logsPath)
        $logFile = Join-Path $logsPath 'fake_system.log'
        if (-not (Test-Path $logFile)) {
            "`n=== DeNarrator fake system log started: $(Get-Date -Format o) ===" | Out-File -FilePath $logFile -Encoding UTF8 -Append
        }
        $events = @(
            'INFO  BackupService   Completed incremental backup to NAS-01',
            'WARN  DiskMonitor     High latency detected on volume E:',
            'INFO  AuthService     Successful kerberos ticket renewal for svc_backup',
            'WARN  FW              Rejected inbound connection from 203.0.113.45:445',
            'INFO  PatchAgent      Update cycle postponed; maintenance window not reached',
            'WARN  RAID            Rebuild in progress on slot 3',
            'INFO  JobRunner       Archive job 4921 completed with 0 errors',
            'WARN  AuthService     3 failed logon attempts for disabled user temp_admin'
        )
        while ($true) {
            $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') " + ($events | Get-Random)
            $line | Out-File -FilePath $logFile -Encoding UTF8 -Append
            Start-Sleep -Seconds (Get-Random -Minimum 20 -Maximum 60)
        }
    } -ArgumentList @($Global:DeNarratorState.LogsPath)

    $Global:DeNarratorState.Job = $job
    $Global:DeNarratorState.Active = $true

    # Wrap selected commands in this session
    Wrap-DeNarratorCommands

    Write-Host "[DeNarrator] Honeypot active in this session." -ForegroundColor Yellow
}

function Stop-DeNarratorCore {
    if (-not $Global:DeNarratorState.Active) { return }

    if ($Global:DeNarratorState.Job) {
        try { Stop-Job -Job $Global:DeNarratorState.Job -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Job -Job $Global:DeNarratorState.Job -ErrorAction SilentlyContinue } catch {}
    }

    Unwrap-DeNarratorCommands

    $Global:DeNarratorState.Active = $false
    Write-Host "[DeNarrator] Honeypot deactivated and session restored." -ForegroundColor Green
}

function Wrap-DeNarratorCommands {
    # Save originals only once
    $targets = 'systeminfo','hostname','whoami','ipconfig','Get-ComputerInfo','Get-EventLog'
    foreach ($name in $targets) {
        if (-not $Global:DeNarratorState.OriginalFuncs.ContainsKey($name)) {
            $cmd = Get-Command $name -ErrorAction SilentlyContinue
            if ($cmd) { $Global:DeNarratorState.OriginalFuncs[$name] = $cmd }
        }
    }

    function global:systeminfo {
        if (-not $Global:DeNarratorState.Active) {
            & $env:SystemRoot\System32\systeminfo.exe @args
            return
        }
        "Host Name:                 $($Global:DeNarratorState.FakeHostname)"
        "OS Name:                   $($Global:DeNarratorState.FakeOS)"
        "OS Version:                10.0.14393 N/A Build 14393"
        "System Manufacturer:       Generic Virtual Machine"
        "System Model:              Sandbox-Node"
        "System Type:               x64-based PC"
        "BIOS Version:              Hypervisor BIOS 1.0"
        "Original Install Date:     $(Get-Date (Get-Date).AddDays(-120) -Format 'dd-MM-yyyy, HH:mm:ss')"
        "System Boot Time:          $(Get-Date (Get-Date).AddHours(-19) -Format 'dd-MM-yyyy, HH:mm:ss')"
        "Domain:                    $($Global:DeNarratorState.FakeDomain)"
        "Hotfix(s):                 42 Hotfix(s) Installed."
        "Network Card(s):          1 NIC(s) installed."
        "                             $($Global:DeNarratorState.FakeIP)  $($Global:DeNarratorState.FakeMAC)"
    }

    function global:hostname {
        if (-not $Global:DeNarratorState.Active) { & $env:SystemRoot\System32\hostname.exe @args; return }
        $Global:DeNarratorState.FakeHostname
    }

    function global:whoami {
        if (-not $Global:DeNarratorState.Active) { & $env:SystemRoot\System32\whoami.exe @args; return }
        "$($Global:DeNarratorState.FakeDomain.ToLower())\$($Global:DeNarratorState.FakeUser)"
    }

    function global:ipconfig {
        if (-not $Global:DeNarratorState.Active) { & $env:SystemRoot\System32\ipconfig.exe @args; return }
        @"
Windows IP Configuration

Ethernet adapter CorpNet:

   Connection-specific DNS Suffix  . : corp.lab
   IPv4 Address. . . . . . . . . . . : $($Global:DeNarratorState.FakeIP)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.13.37.1
"@
    }

    function global:Get-ComputerInfo {
        if (-not $Global:DeNarratorState.Active) { & (Get-Command Get-ComputerInfo -ErrorAction SilentlyContinue) @args; return }
        [pscustomobject]@{
            OsName               = $Global:DeNarratorState.FakeOS
            CsName               = $Global:DeNarratorState.FakeHostname
            OsVersion            = '10.0.14393'
            CsDomain             = $Global:DeNarratorState.FakeDomain
            CsManufacturer       = 'Generic Virtual Machine'
            CsModel              = 'Sandbox-Node'
            BiosSerialNumber     = $Global:DeNarratorState.FakeUUID
            WindowsInstallDateFromRegistry = (Get-Date).AddDays(-120)
        }
    }

    function global:Get-EventLog {
        param(
            [string]$LogName,
            [int]$Newest = 100
        )
        if (-not $Global:DeNarratorState.Active) {
            & (Get-Command Microsoft.PowerShell.Management\Get-EventLog) -LogName $LogName -Newest $Newest
            return
        }
        $logFile = Join-Path $Global:DeNarratorState.LogsPath 'fake_system.log'
        if (-not (Test-Path $logFile)) {
            "(no events)" | Out-File -FilePath $logFile -Encoding UTF8
        }
        Get-Content -Path $logFile -Tail $Newest | ForEach-Object {
            [pscustomobject]@{
                TimeGenerated = ($_ -split ' ')[0..1] -join ' '
                EntryType     = (if ($_ -match 'WARN') {'Warning'} else {'Information'})
                Source        = ($_ -split '\s+')[1]
                Message       = ($_ -split '\s+',4)[-1]
                Index         = 0
            }
        }
    }
}

function Unwrap-DeNarratorCommands {
    foreach ($name in $Global:DeNarratorState.OriginalFuncs.Keys) {
        if (Test-Path "function:$name") {
            Remove-Item "function:$name" -Force -ErrorAction SilentlyContinue
        }
    }
}

function Use-DeNarratorKey {
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [switch]$Disable
    )
    $realKey = $Global:DeNarratorState.Key
    if (-not $realKey) {
        $realKey = New-DeNarratorKey
        $Global:DeNarratorState.Key = $realKey
    }
    if ($Key -ne $realKey) {
        Write-Host '[DeNarrator] Invalid key.' -ForegroundColor Red
        return
    }
    if ($Disable) {
        Stop-DeNarratorCore
    } else {
        Start-DeNarratorCore
    }
}

if ($Activate) {
    Start-DeNarratorCore
} elseif ($Deactivate) {
    Stop-DeNarratorCore
}