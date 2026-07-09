# =====================================================================
# Network Validation Observer Script
# Run Location : VDI / Jump Server
# Purpose      : Observe ICMP + TCP reachability and send periodic reports
# =====================================================================
# NOTE: This is a sanitized template. All IPs use documentation/example
# ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and
# all names, emails, and identifiers are placeholders. Replace the
# values in the "IMPORTANT VARIABLES" section with your own before use.
# =====================================================================

# =====================================================================
# IMPORTANT VARIABLES - EDIT ONLY THIS SECTION
# =====================================================================

# -------------------------------
# Run Context
# -------------------------------
$ObserverName = $env:COMPUTERNAME
$ObserverIPNote = "Running from VDI / observer machine. This does NOT represent the actual source path of the systems being validated."

# -------------------------------
# Log Settings
# -------------------------------
$BaseFolder = Get-Location
$RunTimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFolder = Join-Path $BaseFolder "NetworkValidation_Report_$RunTimeStamp"

# -------------------------------
# Test Intervals
# -------------------------------
$PingCountPerTarget = 4
$TcpTimeoutSeconds = 5

$ReportIntervalSeconds = 300       # 5 minutes
$TracerouteIntervalMinutes = 15
$PathPingIntervalMinutes = 60

# -------------------------------
# Alert Thresholds
# -------------------------------
$PacketLossThresholdPercent = 25    # Alert if packet loss >= 25%
$LatencyThresholdMs = 150           # Alert if average latency > 150ms
$TcpFailureIsAbnormal = $true       # TCP failure will be treated as abnormal

# -------------------------------
# Continuous Ping Monitor Settings
# -------------------------------
# Independent of the periodic report above. Runs one lightweight
# background job per destination, pinging every $ContinuousPingIntervalSeconds
# using raw ICMP (fast .NET Ping, not Test-Connection/pathping) and logs
# every result. A state is only declared DOWN/UP after N consecutive
# results in that direction (debounce), and a state change fires an
# immediate email independent of the periodic report.
$EnableContinuousPingMonitor = $true
$ContinuousPingIntervalSeconds = 1
$ContinuousPingTimeoutMs = 1000
$ConsecutiveFailThreshold = 3       # consecutive failed pings before declaring DOWN
$ConsecutiveSuccessThreshold = 3    # consecutive successful pings before declaring UP again
$SendStateChangeAlerts = $true

# -------------------------------
# Mail Settings
# -------------------------------
$SMTPserver = "smtp.example.com"
$SMTPport   = 25

$Mailto = "network-team@example.com"

$MailCC = @(
    "oncall-1@example.com",
    "oncall-2@example.com"
)

$Mailfrom = "network-monitoring@example.com"

# Optional reference/ticket number for this monitoring run - leave blank if not applicable
$TicketReference = "<TICKET-NUMBER>"
$MailSubjectPrefix = if ($TicketReference -and $TicketReference -ne "<TICKET-NUMBER>") { "$TicketReference - Network Validation Report" } else { "Network Validation Report" }

# Attach latest CSV report?
$AttachReport = $true

# -------------------------------
# Validation Connections
# -------------------------------
# ReferenceSourceName / ReferenceSourceIP are informational only, since
# the script runs from the VDI/observer machine - the actual packet
# source is always the observer, not the referenced system.
#
# All values below are placeholders using documentation IP ranges
# (RFC 5737). Replace FlowName, Reference*, Destination*, Port, Purpose,
# and ExpectedStatus with your real environment's details.

$Connections = @(

    # --------------------------------------------------
    # Transit / Hop Validation
    # --------------------------------------------------

    @{
        FlowName = "Application Server A to Network Transit Interface"
        ReferenceSourceName = "Application Server A"
        ReferenceSourceIP = "192.0.2.10"
        DestinationName = "Network Transit Interface"
        DestinationIP = "192.0.2.1"
        Port = ""
        Purpose = "Hop validation"
        ExpectedStatus = "Reference"
    },

    @{
        FlowName = "Application Server A to Firewall Transit Zone"
        ReferenceSourceName = "Application Server A"
        ReferenceSourceIP = "192.0.2.10"
        DestinationName = "Firewall Transit Zone"
        DestinationIP = "192.0.2.2"
        Port = ""
        Purpose = "Hop validation"
        ExpectedStatus = "Reference"
    },

    @{
        FlowName = "Application Server A to Firewall Production Zone"
        ReferenceSourceName = "Application Server A"
        ReferenceSourceIP = "192.0.2.10"
        DestinationName = "Firewall Production Zone"
        DestinationIP = "192.0.2.3"
        Port = ""
        Purpose = "Hop validation"
        ExpectedStatus = "Reference"
    },

    # --------------------------------------------------
    # Critical Application Flow
    # --------------------------------------------------

    @{
        FlowName = "Critical Flow - App Server A to Database Node 1"
        ReferenceSourceName = "Application Server A"
        ReferenceSourceIP = "192.0.2.10"
        DestinationName = "Database Node 1"
        DestinationIP = "198.51.100.10"
        Port = "5000"
        Purpose = "Primary application data fetch"
        ExpectedStatus = "Critical"
    },

    @{
        FlowName = "Critical Flow - App Server A to Database Node 2 (redundant)"
        ReferenceSourceName = "Application Server A"
        ReferenceSourceIP = "192.0.2.10"
        DestinationName = "Database Node 2"
        DestinationIP = "198.51.100.11"
        Port = "5000"
        Purpose = "Redundant database node validation"
        ExpectedStatus = "Critical"
    },

    @{
        FlowName = "Critical Flow - App Server A to Destination Application Server"
        ReferenceSourceName = "Application Server A"
        ReferenceSourceIP = "192.0.2.10"
        DestinationName = "Destination Application Server"
        DestinationIP = "198.51.100.12"
        Port = "5000"
        Purpose = "Final destination validation"
        ExpectedStatus = "Critical"
    },

    # --------------------------------------------------
    # Monitoring Platform
    # --------------------------------------------------

    @{
        FlowName = "Monitoring Platform to Database Node 1"
        ReferenceSourceName = "Monitoring Platform"
        ReferenceSourceIP = "192.0.2.20"
        DestinationName = "Database Node 1"
        DestinationIP = "198.51.100.10"
        Port = "5000"
        Purpose = "Application access and monitoring via transit path"
        ExpectedStatus = "Critical"
    },

    @{
        FlowName = "Monitoring Platform to Database Node 2 (redundant)"
        ReferenceSourceName = "Monitoring Platform"
        ReferenceSourceIP = "192.0.2.20"
        DestinationName = "Database Node 2"
        DestinationIP = "198.51.100.11"
        Port = "5000"
        Purpose = "Application access and monitoring via transit path"
        ExpectedStatus = "Critical"
    },

    @{
        FlowName = "Monitoring Platform to DNS Server"
        ReferenceSourceName = "Monitoring Platform"
        ReferenceSourceIP = "192.0.2.20"
        DestinationName = "DNS Server"
        DestinationIP = "192.0.2.30"
        Port = ""
        Purpose = "DNS / infrastructure validation"
        ExpectedStatus = "Reference"
    },

    # --------------------------------------------------
    # Additional / Redundant Source Flows
    # --------------------------------------------------

    @{
        FlowName = "Additional Flow - App Server A Alternate Interface to Database Node 1"
        ReferenceSourceName = "Application Server A (alternate interface)"
        ReferenceSourceIP = "192.0.2.11"
        DestinationName = "Database Node 1"
        DestinationIP = "198.51.100.10"
        Port = "5000"
        Purpose = "Secondary source interface for primary application flow"
        ExpectedStatus = "Critical"
    },

    @{
        FlowName = "Additional Flow - App Server B to Database Node 1"
        ReferenceSourceName = "Application Server B"
        ReferenceSourceIP = "192.0.2.12"
        DestinationName = "Database Node 1"
        DestinationIP = "198.51.100.10"
        Port = "5000"
        Purpose = "Secondary source system for primary application flow"
        ExpectedStatus = "Critical"
    },

    @{
        FlowName = "Additional Flow - Monitoring Platform to Node Under Packet Capture"
        ReferenceSourceName = "Monitoring Platform"
        ReferenceSourceIP = "192.0.2.20"
        DestinationName = "Node Under Packet Capture"
        DestinationIP = "198.51.100.13"
        Port = ""
        Purpose = "Host targeted for packet capture / deep-dive analysis"
        ExpectedStatus = "Critical"
    },

    @{
        FlowName = "Additional Flow - Monitoring Platform to Secondary Monitoring Target"
        ReferenceSourceName = "Monitoring Platform"
        ReferenceSourceIP = "192.0.2.20"
        DestinationName = "Secondary Monitoring Target"
        DestinationIP = "198.51.100.14"
        Port = ""
        Purpose = "Preliminary testing / continuous ping monitoring target"
        ExpectedStatus = "Critical"
    },

    @{
        FlowName = "Monitoring Platform to Messaging Server"
        ReferenceSourceName = "Monitoring Platform"
        ReferenceSourceIP = "192.0.2.20"
        DestinationName = "Messaging / Queue Server"
        DestinationIP = "198.51.100.15"
        Port = ""
        Purpose = "Messaging platform reachability"
        ExpectedStatus = "Reference"
    },

    # --------------------------------------------------
    # Source Host Reachability Checks
    # (Ping the source servers themselves, not just the destinations,
    #  since observer -> source reachability can also explain failures.)
    # --------------------------------------------------

    @{
        FlowName = "Observer to Application Server A - Source Reachability"
        ReferenceSourceName = "Observer / VDI"
        ReferenceSourceIP = ""
        DestinationName = "Application Server A"
        DestinationIP = "192.0.2.10"
        Port = ""
        Purpose = "Confirm source server itself is reachable from observer"
        ExpectedStatus = "Reference"
    },

    @{
        FlowName = "Observer to Application Server A Alternate Interface - Source Reachability"
        ReferenceSourceName = "Observer / VDI"
        ReferenceSourceIP = ""
        DestinationName = "Application Server A (alternate interface)"
        DestinationIP = "192.0.2.11"
        Port = ""
        Purpose = "Confirm source server itself is reachable from observer"
        ExpectedStatus = "Reference"
    },

    @{
        FlowName = "Observer to Application Server B - Source Reachability"
        ReferenceSourceName = "Observer / VDI"
        ReferenceSourceIP = ""
        DestinationName = "Application Server B"
        DestinationIP = "192.0.2.12"
        Port = ""
        Purpose = "Confirm source server itself is reachable from observer"
        ExpectedStatus = "Reference"
    },

    @{
        FlowName = "Observer to Monitoring Platform - Source Reachability"
        ReferenceSourceName = "Observer / VDI"
        ReferenceSourceIP = ""
        DestinationName = "Monitoring Platform"
        DestinationIP = "192.0.2.20"
        Port = ""
        Purpose = "Confirm source server itself is reachable from observer"
        ExpectedStatus = "Reference"
    }

    # --------------------------------------------------
    # Add further entries below as new flows / IPs are confirmed
    # --------------------------------------------------

    # @{
    #     FlowName = "<Flow Name>"
    #     ReferenceSourceName = "<Reference Source Name>"
    #     ReferenceSourceIP = "<x.x.x.x>"
    #     DestinationName = "<Destination Name>"
    #     DestinationIP = "<x.x.x.x>"
    #     Port = "<port or blank for ICMP-only>"
    #     Purpose = "<why this flow is being tested>"
    #     ExpectedStatus = "Critical | Reference | Known Good"
    # }
)

# =====================================================================
# DO NOT EDIT BELOW UNLESS REQUIRED
# =====================================================================

New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null

$MasterCsv = Join-Path $LogFolder "NetworkValidation_MasterLog.csv"
$LatestReportCsv = Join-Path $LogFolder "NetworkValidation_LatestReport.csv"
$TraceFolder = Join-Path $LogFolder "TraceLogs"
$ContinuousPingFolder = Join-Path $LogFolder "ContinuousPing"

New-Item -ItemType Directory -Path $TraceFolder -Force | Out-Null
New-Item -ItemType Directory -Path $ContinuousPingFolder -Force | Out-Null

"DateTime,ObserverName,ReferenceSourceName,ReferenceSourceIP,DestinationName,DestinationIP,Port,Purpose,ExpectedStatus,PingStatus,PacketsSent,PacketsReceived,PacketLossPercent,AverageLatencyMs,TcpStatus,OverallStatus,IssueSummary" |
    Out-File $MasterCsv -Encoding UTF8

# -------------------------------
# Validate connection entries up front so a malformed entry (missing
# DestinationIP, etc.) is caught immediately instead of failing deep
# inside the report loop.
# -------------------------------

function Test-ConnectionEntryValid {
    param([hashtable]$Conn)

    $RequiredKeys = @("FlowName","ReferenceSourceName","ReferenceSourceIP","DestinationName","DestinationIP","Port","Purpose","ExpectedStatus")
    foreach ($Key in $RequiredKeys) {
        if (-not $Conn.ContainsKey($Key)) {
            return $false
        }
    }
    if ([string]::IsNullOrWhiteSpace($Conn.DestinationIP)) {
        return $false
    }
    return $true
}

$InvalidConnections = $Connections | Where-Object { -not (Test-ConnectionEntryValid $_) }
if ($InvalidConnections.Count -gt 0) {
    Write-Host "WARNING: $($InvalidConnections.Count) connection entr(ies) are missing required fields and will be skipped." -ForegroundColor Yellow
    $Connections = $Connections | Where-Object { Test-ConnectionEntryValid $_ }
}

# -------------------------------
# Safe File Name
# -------------------------------

function Get-SafeName {
    param([string]$Text)
    return ($Text -replace '[\\/:*?"<>| ]', '_')
}

# -------------------------------
# Test Ping
# -------------------------------

function Test-PingSummary {
    param(
        [string]$DestinationIP,
        [int]$Count
    )

    $PacketsReceived = 0
    $LatencyValues = @()

    for ($i = 1; $i -le $Count; $i++) {
        try {
            $Reply = Test-Connection -ComputerName $DestinationIP -Count 1 -ErrorAction Stop

            $Latency = $null

            if ($Reply.ResponseTime -ne $null) {
                $Latency = $Reply.ResponseTime
            }
            elseif ($Reply.Latency -ne $null) {
                $Latency = $Reply.Latency
            }

            if ($Latency -eq $null) {
                $Latency = 0
            }

            $PacketsReceived++
            $LatencyValues += [double]$Latency
        }
        catch {
            # Failed ping - counted as packet loss below
        }

        Start-Sleep -Milliseconds 500
    }

    $LossPercent = [math]::Round((($Count - $PacketsReceived) / $Count) * 100, 2)

    if ($LatencyValues.Count -gt 0) {
        $AvgLatency = [math]::Round(($LatencyValues | Measure-Object -Average).Average, 2)
    }
    else {
        $AvgLatency = ""
    }

    if ($PacketsReceived -eq 0) {
        $PingStatus = "FAILED"
    }
    elseif ($LossPercent -gt 0) {
        $PingStatus = "PARTIAL_LOSS"
    }
    else {
        $PingStatus = "SUCCESS"
    }

    return [PSCustomObject]@{
        PingStatus = $PingStatus
        PacketsSent = $Count
        PacketsReceived = $PacketsReceived
        PacketLossPercent = $LossPercent
        AverageLatencyMs = $AvgLatency
    }
}

# -------------------------------
# Test TCP Port
# -------------------------------

function Test-TcpPortSummary {
    param(
        [string]$DestinationIP,
        [string]$Port
    )

    if ([string]::IsNullOrEmpty($Port)) {
        return "NOT_APPLICABLE"
    }

    try {
        $Result = Test-NetConnection `
            -ComputerName $DestinationIP `
            -Port ([int]$Port) `
            -WarningAction SilentlyContinue

        if ($Result.TcpTestSucceeded -eq $true) {
            return "SUCCESS"
        }
        else {
            return "FAILED"
        }
    }
    catch {
        return "ERROR"
    }
}

# -------------------------------
# Send HTML Mail Report
# -------------------------------

function Send-NetworkReportMail {
    param(
        [array]$ReportRows,
        [string]$CsvAttachment,
        [bool]$HasAbnormality,
        [array]$ContinuousSnapshot = @()
    )

    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    if ($HasAbnormality) {
        $Subject = "$MailSubjectPrefix - ABNORMALITY FOUND - $date"
        $HeaderColour = "#b00020"
        $HeaderText = "Network Validation Report - Abnormality Found"
    }
    else {
        $Subject = "$MailSubjectPrefix - Healthy Summary - $date"
        $HeaderColour = "#107c10"
        $HeaderText = "Network Validation Report - Healthy Summary"
    }

    $RowsHtml = ""

    foreach ($Row in $ReportRows) {

        if ($Row.OverallStatus -eq "ABNORMAL") {
            $RowColour = "#ffe5e5"
            $StatusColour = "#b00020"
        }
        elseif ($Row.OverallStatus -eq "WARNING") {
            $RowColour = "#fff4ce"
            $StatusColour = "#8a6d00"
        }
        else {
            $RowColour = "#e6f4ea"
            $StatusColour = "#107c10"
        }

        $RowsHtml += @"
<tr style='background-color:$RowColour'>
<td>$($Row.ReferenceSourceName)</td>
<td>$($Row.ReferenceSourceIP)</td>
<td>$($Row.DestinationName)</td>
<td>$($Row.DestinationIP)</td>
<td>$($Row.Port)</td>
<td>$($Row.Purpose)</td>
<td>$($Row.PingStatus)</td>
<td>$($Row.PacketLossPercent)%</td>
<td>$($Row.AverageLatencyMs)</td>
<td>$($Row.TcpStatus)</td>
<td style='color:$StatusColour'><b>$($Row.OverallStatus)</b></td>
<td>$($Row.IssueSummary)</td>
</tr>
"@
    }

    $AbnormalRows = $ReportRows | Where-Object { $_.OverallStatus -eq "ABNORMAL" }
    $WarningRows  = $ReportRows | Where-Object { $_.OverallStatus -eq "WARNING" }
    $HealthyRows  = $ReportRows | Where-Object { $_.OverallStatus -eq "HEALTHY" }

    # Real-time continuous-ping snapshot table (optional, additive)
    $ContinuousRowsHtml = ""
    foreach ($CRow in $ContinuousSnapshot) {
        $CColour = if ($CRow.State -eq "DOWN") { "#ffe5e5" } elseif ($CRow.State -eq "UNKNOWN") { "#f0f0f0" } else { "#e6f4ea" }
        $ContinuousRowsHtml += @"
<tr style='background-color:$CColour'>
<td>$($CRow.DestinationName)</td>
<td>$($CRow.DestinationIP)</td>
<td>$($CRow.LastChecked)</td>
<td>$($CRow.LastPingSuccess)</td>
<td>$($CRow.LastLatencyMs)</td>
<td>$($CRow.ConsecutiveFails)</td>
<td>$($CRow.State)</td>
</tr>
"@
    }

    $ContinuousSectionHtml = ""
    if ($ContinuousSnapshot.Count -gt 0) {
        $ContinuousSectionHtml = @"
<br>
<p><b>Continuous Ping Monitor - Real-Time Snapshot (independent of this periodic report):</b></p>
<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse'>
<tr style='background-color:#d9eaf7'>
<th>Destination</th>
<th>Destination IP</th>
<th>Last Checked</th>
<th>Last Ping Success</th>
<th>Last Latency ms</th>
<th>Consecutive Fails</th>
<th>Confirmed State</th>
</tr>
$ContinuousRowsHtml
</table>
"@
    }

    $body = @"
<html>
<body style='font-family:Segoe UI, Arial, sans-serif; font-size:13px'>

<h2 style='color:$HeaderColour'>$HeaderText</h2>

<p><b>Report Time:</b> $date</p>
<p><b>Observer Machine:</b> $ObserverName</p>
<p><b>Important Note:</b> $ObserverIPNote</p>

<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse'>
<tr>
<td><b>Total Connections Checked</b></td>
<td>$($ReportRows.Count)</td>
</tr>
<tr>
<td><b>Healthy</b></td>
<td>$($HealthyRows.Count)</td>
</tr>
<tr>
<td><b>Warnings</b></td>
<td>$($WarningRows.Count)</td>
</tr>
<tr>
<td><b>Abnormal</b></td>
<td>$($AbnormalRows.Count)</td>
</tr>
<tr>
<td><b>Log Folder</b></td>
<td>$LogFolder</td>
</tr>
</table>

<br>

<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse'>
<tr style='background-color:#d9eaf7'>
<th>Reference Source</th>
<th>Reference Source IP</th>
<th>Destination</th>
<th>Destination IP</th>
<th>Port</th>
<th>Purpose</th>
<th>Ping Status</th>
<th>Packet Loss</th>
<th>Avg Latency ms</th>
<th>TCP Status</th>
<th>Overall Status</th>
<th>Issue Summary</th>
</tr>
$RowsHtml
</table>
$ContinuousSectionHtml

<br>

<p><b>Interpretation:</b></p>
<ul>
<li>This script is running from the VDI/observer machine.</li>
<li>Results confirm reachability only from the observer machine, not from the referenced source systems.</li>
<li>If the observer also shows packet loss or TCP failure, it may indicate a wider network reachability issue.</li>
<li>If the observer is healthy but the application still fails from the actual source system, validation is required from that source server or by the relevant server/application teams.</li>
</ul>

<br>
<p>---------------------------</p>

</body>
</html>
"@

    try {
        if (($AttachReport -eq $true) -and (Test-Path $CsvAttachment)) {
            Send-MailMessage `
                -SmtpServer $SMTPserver `
                -To $Mailto `
                -Cc $MailCC `
                -From $Mailfrom `
                -Subject $Subject `
                -Port $SMTPport `
                -Body $body `
                -BodyAsHtml `
                -Attachments $CsvAttachment
        }
        else {
            Send-MailMessage `
                -SmtpServer $SMTPserver `
                -To $Mailto `
                -Cc $MailCC `
                -From $Mailfrom `
                -Subject $Subject `
                -Port $SMTPport `
                -Body $body `
                -BodyAsHtml
        }

        Write-Host "Mail sent: $Subject" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to send mail: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# -------------------------------
# Optional Traceroute Capture
# -------------------------------

function Start-TraceCapture {
    param(
        [array]$Connections
    )

    Start-Job -Name "Traceroute_Capture" -ArgumentList $Connections,$TraceFolder,$TracerouteIntervalMinutes -ScriptBlock {

        param($Connections,$TraceFolder,$TracerouteIntervalMinutes)

        function Get-SafeName {
            param([string]$Text)
            return ($Text -replace '[\\/:*?"<>| ]', '_')
        }

        while ($true) {

            foreach ($Conn in $Connections) {

                try {
                    $DestIP = $Conn.DestinationIP
                    $SafeName = Get-SafeName "$($Conn.DestinationName)_$DestIP"
                    $TraceFile = Join-Path $TraceFolder "TRACERT_$SafeName.log"

                    "====================================================" | Out-File $TraceFile -Append
                    "DateTime       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $TraceFile -Append
                    "Reference Src  : $($Conn.ReferenceSourceName) / $($Conn.ReferenceSourceIP)" | Out-File $TraceFile -Append
                    "Actual Source  : Observer / VDI running this script" | Out-File $TraceFile -Append
                    "Destination    : $($Conn.DestinationName) / $DestIP" | Out-File $TraceFile -Append
                    "Purpose        : $($Conn.Purpose)" | Out-File $TraceFile -Append
                    "====================================================" | Out-File $TraceFile -Append

                    tracert -d $DestIP | Out-File $TraceFile -Append

                    "`n" | Out-File $TraceFile -Append
                }
                catch {
                    # One bad target should not kill the background job loop
                    continue
                }
            }

            Start-Sleep -Seconds ($TracerouteIntervalMinutes * 60)
        }
    }
}

# -------------------------------
# Optional PathPing Capture
# -------------------------------

function Start-PathPingCapture {
    param(
        [array]$Connections
    )

    Start-Job -Name "PathPing_Capture" -ArgumentList $Connections,$TraceFolder,$PathPingIntervalMinutes -ScriptBlock {

        param($Connections,$TraceFolder,$PathPingIntervalMinutes)

        function Get-SafeName {
            param([string]$Text)
            return ($Text -replace '[\\/:*?"<>| ]', '_')
        }

        while ($true) {

            foreach ($Conn in $Connections) {

                try {
                    $DestIP = $Conn.DestinationIP
                    $SafeName = Get-SafeName "$($Conn.DestinationName)_$DestIP"
                    $PathFile = Join-Path $TraceFolder "PATHPING_$SafeName.log"

                    "====================================================" | Out-File $PathFile -Append
                    "DateTime       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $PathFile -Append
                    "Reference Src  : $($Conn.ReferenceSourceName) / $($Conn.ReferenceSourceIP)" | Out-File $PathFile -Append
                    "Actual Source  : Observer / VDI running this script" | Out-File $PathFile -Append
                    "Destination    : $($Conn.DestinationName) / $DestIP" | Out-File $PathFile -Append
                    "Purpose        : $($Conn.Purpose)" | Out-File $PathFile -Append
                    "====================================================" | Out-File $PathFile -Append

                    pathping -n $DestIP | Out-File $PathFile -Append

                    "`n" | Out-File $PathFile -Append
                }
                catch {
                    # One bad target should not kill the background job loop
                    continue
                }
            }

            Start-Sleep -Seconds ($PathPingIntervalMinutes * 60)
        }
    }
}

# -------------------------------
# Continuous Ping Monitor (fast, ICMP-only, per destination)
# -------------------------------
# One background job per destination. Pings every $IntervalSeconds using
# raw .NET Ping (fast, no cmdlet/CIM overhead like Test-Connection).
# State is confirmed DOWN/UP only after N consecutive results in that
# direction (debounce), and fires its own immediate alert email on a
# confirmed state change - independent of the periodic summary report.

function Start-ContinuousPingMonitor {
    param(
        [array]$Connections,
        [string]$ContinuousPingFolder,
        [int]$IntervalSeconds,
        [int]$TimeoutMs,
        [int]$FailThreshold,
        [int]$SuccessThreshold,
        [bool]$SendAlerts,
        [string]$SMTPserver,
        [int]$SMTPport,
        [string]$Mailfrom,
        [string]$Mailto,
        [array]$MailCC,
        [string]$MailSubjectPrefix,
        [string]$ObserverName
    )

    $Jobs = @()

    foreach ($Conn in $Connections) {

        $Job = Start-Job -Name "ContinuousPing_$(($Conn.DestinationName) -replace '[\\/:*?"<>| ]', '_')" -ArgumentList `
            $Conn, $ContinuousPingFolder, $IntervalSeconds, $TimeoutMs, $FailThreshold, $SuccessThreshold, $SendAlerts,
            $SMTPserver, $SMTPport, $Mailfrom, $Mailto, $MailCC, $MailSubjectPrefix, $ObserverName -ScriptBlock {

            param($Conn,$ContinuousPingFolder,$IntervalSeconds,$TimeoutMs,$FailThreshold,$SuccessThreshold,$SendAlerts,
                  $SMTPserver,$SMTPport,$Mailfrom,$Mailto,$MailCC,$MailSubjectPrefix,$ObserverName)

            function Get-SafeName {
                param([string]$Text)
                return ($Text -replace '[\\/:*?"<>| ]', '_')
            }

            function Send-StateChangeMail {
                param($Conn,$NewState,$OldState,$Timestamp,$ConsecutiveCount)

                $Subject = "$MailSubjectPrefix - STATE CHANGE - $($Conn.DestinationName) is now $NewState - $Timestamp"
                $Colour = if ($NewState -eq "DOWN") { "#b00020" } else { "#107c10" }
                $CheckWord = if ($NewState -eq "DOWN") { "failed" } else { "successful" }

                $body = @"
<html>
<body style='font-family:Segoe UI, Arial, sans-serif; font-size:13px'>
<h2 style='color:$Colour'>Continuous Ping State Change</h2>
<p><b>Observer Machine:</b> $ObserverName</p>
<p><b>Destination:</b> $($Conn.DestinationName) ($($Conn.DestinationIP))</p>
<p><b>Reference Source:</b> $($Conn.ReferenceSourceName) / $($Conn.ReferenceSourceIP)</p>
<p><b>Purpose:</b> $($Conn.Purpose)</p>
<p><b>Previous State:</b> $OldState</p>
<p><b>New State:</b> <span style='color:$Colour'><b>$NewState</b></span></p>
<p><b>Confirmed after:</b> $ConsecutiveCount consecutive $CheckWord pings</p>
<p><b>Time:</b> $Timestamp</p>
<p>This is a real-time alert from the continuous ping monitor ($($IntervalSeconds)s interval), independent of the periodic summary report.</p>
</body>
</html>
"@
                try {
                    Send-MailMessage -SmtpServer $SMTPserver -To $Mailto -Cc $MailCC -From $Mailfrom `
                        -Subject $Subject -Port $SMTPport -Body $body -BodyAsHtml
                }
                catch {
                    # Mail failure here should not stop the ping loop; state change is still logged below
                }
            }

            $SafeName = Get-SafeName $Conn.DestinationName
            $CsvFile = Join-Path $ContinuousPingFolder "ContinuousPing_$SafeName.csv"
            $StateLogFile = Join-Path $ContinuousPingFolder "StateChanges_$SafeName.log"

            if (-not (Test-Path $CsvFile)) {
                "DateTime,DestinationName,DestinationIP,Success,LatencyMs,ConsecutiveFails,ConsecutiveSuccess,State" |
                    Out-File $CsvFile -Encoding UTF8
            }

            $Ping = New-Object System.Net.NetworkInformation.Ping

            $ConsecutiveFails = 0
            $ConsecutiveSuccess = 0
            $CurrentState = "UNKNOWN"

            while ($true) {

                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                $Success = $false
                $Latency = ""

                try {
                    $Reply = $Ping.Send($Conn.DestinationIP, $TimeoutMs)
                    if ($Reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                        $Success = $true
                        $Latency = $Reply.RoundtripTime
                    }
                }
                catch {
                    $Success = $false
                }

                if ($Success) {
                    $ConsecutiveSuccess++
                    $ConsecutiveFails = 0
                }
                else {
                    $ConsecutiveFails++
                    $ConsecutiveSuccess = 0
                }

                $OldState = $CurrentState

                if ($CurrentState -ne "DOWN" -and $ConsecutiveFails -ge $FailThreshold) {
                    $CurrentState = "DOWN"
                }
                elseif ($CurrentState -ne "UP" -and $ConsecutiveSuccess -ge $SuccessThreshold) {
                    $CurrentState = "UP"
                }

                "$Timestamp,$($Conn.DestinationName),$($Conn.DestinationIP),$Success,$Latency,$ConsecutiveFails,$ConsecutiveSuccess,$CurrentState" |
                    Out-File $CsvFile -Append -Encoding UTF8

                if ($OldState -ne $CurrentState -and $OldState -ne "UNKNOWN") {

                    $ChangeCount = if ($CurrentState -eq "DOWN") { $ConsecutiveFails } else { $ConsecutiveSuccess }

                    "$Timestamp : $($Conn.DestinationName) changed from $OldState to $CurrentState (confirmed after $ChangeCount checks)" |
                        Out-File $StateLogFile -Append -Encoding UTF8

                    if ($SendAlerts -eq $true) {
                        Send-StateChangeMail -Conn $Conn -NewState $CurrentState -OldState $OldState -Timestamp $Timestamp -ConsecutiveCount $ChangeCount
                    }
                }

                Start-Sleep -Seconds $IntervalSeconds
            }
        }

        $Jobs += $Job
    }

    return $Jobs
}

# -------------------------------
# Read the latest continuous-ping state for each destination so it can
# be included as a real-time snapshot in the periodic mail report.
# -------------------------------

function Get-ContinuousPingSnapshot {
    param(
        [array]$Connections,
        [string]$ContinuousPingFolder
    )

    $Snapshot = @()

    foreach ($Conn in $Connections) {
        $SafeName = Get-SafeName $Conn.DestinationName
        $CsvFile = Join-Path $ContinuousPingFolder "ContinuousPing_$SafeName.csv"

        if (Test-Path $CsvFile) {
            $LastLine = Get-Content $CsvFile -Tail 1
            if ($LastLine -and $LastLine -notmatch "^DateTime,") {
                $Fields = $LastLine -split ","
                if ($Fields.Count -ge 8) {
                    $Snapshot += [PSCustomObject]@{
                        DestinationName    = $Conn.DestinationName
                        DestinationIP      = $Conn.DestinationIP
                        LastChecked        = $Fields[0]
                        LastPingSuccess    = $Fields[3]
                        LastLatencyMs      = $Fields[4]
                        ConsecutiveFails   = $Fields[5]
                        ConsecutiveSuccess = $Fields[6]
                        State              = $Fields[7]
                    }
                }
            }
        }
    }

    return $Snapshot
}

# -------------------------------
# Clean up background jobs on Ctrl+C / script exit so repeated runs
# don't leave orphaned Traceroute_Capture / PathPing_Capture /
# ContinuousPing_* jobs behind.
# -------------------------------

$CleanupAction = {
    Get-Job -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @("Traceroute_Capture","PathPing_Capture") -or $_.Name -like "ContinuousPing_*" } |
        Stop-Job -ErrorAction SilentlyContinue
    Get-Job -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @("Traceroute_Capture","PathPing_Capture") -or $_.Name -like "ContinuousPing_*" } |
        Remove-Job -Force -ErrorAction SilentlyContinue
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $CleanupAction | Out-Null

# -------------------------------
# Start Background Trace Jobs
# -------------------------------

Start-TraceCapture -Connections $Connections
Start-PathPingCapture -Connections $Connections

if ($EnableContinuousPingMonitor -eq $true) {
    Start-ContinuousPingMonitor `
        -Connections $Connections `
        -ContinuousPingFolder $ContinuousPingFolder `
        -IntervalSeconds $ContinuousPingIntervalSeconds `
        -TimeoutMs $ContinuousPingTimeoutMs `
        -FailThreshold $ConsecutiveFailThreshold `
        -SuccessThreshold $ConsecutiveSuccessThreshold `
        -SendAlerts $SendStateChangeAlerts `
        -SMTPserver $SMTPserver `
        -SMTPport $SMTPport `
        -Mailfrom $Mailfrom `
        -Mailto $Mailto `
        -MailCC $MailCC `
        -MailSubjectPrefix $MailSubjectPrefix `
        -ObserverName $ObserverName | Out-Null
}

Write-Host ""
Write-Host "Network validation observer started." -ForegroundColor Green
Write-Host "Running from: $ObserverName" -ForegroundColor Cyan
Write-Host "Log folder  : $LogFolder" -ForegroundColor Cyan
Write-Host ""
Write-Host "A report will be emailed every 5 minutes." -ForegroundColor Yellow
Write-Host ""

# -------------------------------
# Main Report Loop
# -------------------------------

while ($true) {

    $ReportRows = @()
    $Now = Get-Date
    $DateString = $Now.ToString("yyyy-MM-dd HH:mm:ss")

    foreach ($Conn in $Connections) {

        # Wrap each connection check so one unexpected exception doesn't
        # abort the whole report cycle.
        try {

            $PingResult = Test-PingSummary `
                -DestinationIP $Conn.DestinationIP `
                -Count $PingCountPerTarget

            $TcpResult = Test-TcpPortSummary `
                -DestinationIP $Conn.DestinationIP `
                -Port $Conn.Port

            $IssueList = @()
            $OverallStatus = "HEALTHY"

            if ($PingResult.PacketLossPercent -ge $PacketLossThresholdPercent) {
                $IssueList += "Packet loss $($PingResult.PacketLossPercent)% is above threshold $PacketLossThresholdPercent%."
                $OverallStatus = "ABNORMAL"
            }
            elseif ($PingResult.PacketLossPercent -gt 0) {
                $IssueList += "Partial packet loss observed: $($PingResult.PacketLossPercent)%."
                if ($OverallStatus -ne "ABNORMAL") {
                    $OverallStatus = "WARNING"
                }
            }

            if (($PingResult.AverageLatencyMs -ne "") -and ([double]$PingResult.AverageLatencyMs -gt $LatencyThresholdMs)) {
                $IssueList += "Average latency $($PingResult.AverageLatencyMs)ms is above threshold $LatencyThresholdMs ms."
                $OverallStatus = "ABNORMAL"
            }

            if (($TcpResult -eq "FAILED" -or $TcpResult -eq "ERROR") -and ($Conn.Port -ne "")) {
                $IssueList += "TCP port $($Conn.Port) test failed."
                if ($TcpFailureIsAbnormal -eq $true) {
                    $OverallStatus = "ABNORMAL"
                }
                else {
                    if ($OverallStatus -ne "ABNORMAL") {
                        $OverallStatus = "WARNING"
                    }
                }
            }

            if ($IssueList.Count -eq 0) {
                $IssueSummary = "No abnormality observed from the observer."
            }
            else {
                $IssueSummary = ($IssueList -join " ")
            }

            $Row = [PSCustomObject]@{
                DateTime = $DateString
                ObserverName = $ObserverName
                ReferenceSourceName = $Conn.ReferenceSourceName
                ReferenceSourceIP = $Conn.ReferenceSourceIP
                DestinationName = $Conn.DestinationName
                DestinationIP = $Conn.DestinationIP
                Port = $Conn.Port
                Purpose = $Conn.Purpose
                ExpectedStatus = $Conn.ExpectedStatus
                PingStatus = $PingResult.PingStatus
                PacketsSent = $PingResult.PacketsSent
                PacketsReceived = $PingResult.PacketsReceived
                PacketLossPercent = $PingResult.PacketLossPercent
                AverageLatencyMs = $PingResult.AverageLatencyMs
                TcpStatus = $TcpResult
                OverallStatus = $OverallStatus
                IssueSummary = $IssueSummary
            }
        }
        catch {
            # Record the failure as an ABNORMAL row instead of crashing the loop
            $Row = [PSCustomObject]@{
                DateTime = $DateString
                ObserverName = $ObserverName
                ReferenceSourceName = $Conn.ReferenceSourceName
                ReferenceSourceIP = $Conn.ReferenceSourceIP
                DestinationName = $Conn.DestinationName
                DestinationIP = $Conn.DestinationIP
                Port = $Conn.Port
                Purpose = $Conn.Purpose
                ExpectedStatus = $Conn.ExpectedStatus
                PingStatus = "ERROR"
                PacketsSent = $PingCountPerTarget
                PacketsReceived = 0
                PacketLossPercent = 100
                AverageLatencyMs = ""
                TcpStatus = "ERROR"
                OverallStatus = "ABNORMAL"
                IssueSummary = "Unexpected error while testing this connection: $($_.Exception.Message)"
            }
        }

        $ReportRows += $Row

        "$($Row.DateTime),$($Row.ObserverName),$($Row.ReferenceSourceName),$($Row.ReferenceSourceIP),$($Row.DestinationName),$($Row.DestinationIP),$($Row.Port),$($Row.Purpose),$($Row.ExpectedStatus),$($Row.PingStatus),$($Row.PacketsSent),$($Row.PacketsReceived),$($Row.PacketLossPercent),$($Row.AverageLatencyMs),$($Row.TcpStatus),$($Row.OverallStatus),$($Row.IssueSummary)" |
            Out-File $MasterCsv -Append -Encoding UTF8
    }

    $ReportRows | Export-Csv -Path $LatestReportCsv -NoTypeInformation -Encoding UTF8

    $HasAbnormality = (($ReportRows | Where-Object { $_.OverallStatus -eq "ABNORMAL" }).Count -gt 0)

    $ContinuousSnapshotForReport = @()
    if ($EnableContinuousPingMonitor -eq $true) {
        $ContinuousSnapshotForReport = Get-ContinuousPingSnapshot -Connections $Connections -ContinuousPingFolder $ContinuousPingFolder
    }

    Send-NetworkReportMail `
        -ReportRows $ReportRows `
        -CsvAttachment $LatestReportCsv `
        -HasAbnormality $HasAbnormality `
        -ContinuousSnapshot $ContinuousSnapshotForReport

    Write-Host "Report completed at $DateString. Abnormality found: $HasAbnormality" -ForegroundColor Cyan

    Start-Sleep -Seconds $ReportIntervalSeconds
}
