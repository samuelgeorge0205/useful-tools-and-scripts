param(
    [string]$ClientID,
    [string]$ClientSecret,
    [string]$TokenUrl  = "https://sso.common.cloud.hpe.com/as/token.oauth2",
    [string]$SwarmsUrl = "https://de1.api.central.arubanetworks.com/network-monitoring/v1/swarms",

    [ValidateSet("Ask", "Test", "Full")]
    [string]$RunMode = "Ask",

    [int]$MaxPages = 1,
    [int]$MaxItems = 20,
    [int]$PageSize = 1000,
    [string]$PfsPattern = "PFS",
    [switch]$NoAutoOpen
)

# ============================================================
# Aruba Central - Swarm VC / Conductor AP Export (v7)
# ============================================================
# - Dynamic prompts for credentials
# - Test / Full run prompt
# - Token cache in JSON file
# - Raw JSON + 3 CSV exports (RAW, DEDUPED, PFS)
# - Uses API's "next" cursor for paging
# - Dedupes by ClusterId (keeps latest copy per swarm)
# - Reports field conflicts across API pages
# - Detects PFS APs acting as VC
# - Auto-opens CSV files on completion
# - Summary at the very end (no VC details in CLI)
# ============================================================

$ErrorActionPreference = "Stop"

# -----------------------------
# File paths (millisecond-precise timestamp)
# -----------------------------

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"

$TokenBackupFile  = ".\ArubaCentral_Token_Backup.json"
$RawPagesJsonFile = ".\ArubaCentral_Swarms_RawPages_$TimeStamp.json"
$RawItemsJsonFile = ".\ArubaCentral_Swarms_RawItems_$TimeStamp.json"
$RawCsvFile       = ".\ArubaCentral_Swarms_VC_Report_RAW_$TimeStamp.csv"
$FinalCsvFile     = ".\ArubaCentral_Swarms_VC_Report_DEDUPED_$TimeStamp.csv"
$ConflictCsvFile  = ".\ArubaCentral_Swarms_Conflicts_$TimeStamp.csv"
$PfsCsvFile       = ".\ArubaCentral_PFS_As_VC_$TimeStamp.csv"

$TokenExpiryBufferMinutes = 5
$MaxLoopIterations = 10000

# -----------------------------
# Logging helpers
# -----------------------------

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Good {
    param([string]$Message)
    Write-Host "[OK]   $Message" -ForegroundColor Green
}

function Write-Warn2 {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Bad {
    param([string]$Message)
    Write-Host "[ERR]  $Message" -ForegroundColor Red
}

# -----------------------------
# Simple helpers
# -----------------------------

function Is-Empty {
    param($Value)

    if ($null -eq $Value) {
        return $true
    }

    if ($Value -is [string]) {
        if ($Value.Trim().Length -eq 0) {
            return $true
        }
    }

    return $false
}

function Convert-SecureToPlain {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Secure
    )

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)

    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Ask-Value {
    param(
        [string]$Current,
        [string]$Prompt,
        [switch]$Secret
    )

    if (-not (Is-Empty $Current)) {
        return $Current
    }

    if ($Secret) {
        $secure = Read-Host $Prompt -AsSecureString
        return Convert-SecureToPlain -Secure $secure
    }

    return Read-Host $Prompt
}

function Ask-RunMode {

    while ($true) {
        Write-Host ""
        Write-Host "Select run mode:" -ForegroundColor Yellow
        Write-Host "  1. TEST run  - only fetch a few pages / items (safe test)"
        Write-Host "  2. FULL run  - fetch ALL swarms"
        Write-Host ""

        $choice = Read-Host "Enter 1 or 2"

        if ($choice -eq "1") { return "Test" }
        if ($choice -eq "2") { return "Full" }

        Write-Warn2 "Invalid choice. Please enter 1 or 2."
    }
}

function Ask-PositiveInt {
    param(
        [string]$Prompt,
        [int]$Default
    )

    while ($true) {

        $raw = Read-Host "$Prompt [$Default]"

        if (Is-Empty $raw) {
            return $Default
        }

        $raw = $raw.Trim()

        $parsed = 0
        $isNumber = $false

        try {
            $parsed = [int]$raw
            $isNumber = $true
        }
        catch {
            $isNumber = $false
        }

        if ($isNumber -and $parsed -gt 0) {
            return $parsed
        }

        Write-Warn2 "Please enter a positive whole number."
    }
}

# -----------------------------
# Token helpers
# -----------------------------

function Test-TokenValidByExpiry {
    param([string]$ExpiresAtIso)

    if (Is-Empty $ExpiresAtIso) {
        return $false
    }

    try {
        $expiresAt = Get-Date $ExpiresAtIso
        $safeTime  = $expiresAt.AddMinutes(-$TokenExpiryBufferMinutes)

        if ((Get-Date) -lt $safeTime) {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        return $false
    }
}

function Save-TokenBackup {
    param(
        [Parameter(Mandatory = $true)]
        $TokenResponse,
        [Parameter(Mandatory = $true)]
        [string]$ClientIdValue
    )

    $generatedAt = Get-Date
    $expiresInSec = 0

    if ($TokenResponse.expires_in) {
        $expiresInSec = [int]$TokenResponse.expires_in
    }

    $expiresAt = $generatedAt.AddSeconds($expiresInSec)

    $tokenObj = [pscustomobject]@{
        token_type         = $TokenResponse.token_type
        expires_in_seconds = $expiresInSec
        generated_at_local = $generatedAt.ToString("yyyy-MM-dd HH:mm:ss")
        expires_at_local   = $expiresAt.ToString("yyyy-MM-dd HH:mm:ss")
        generated_at_iso   = $generatedAt.ToString("o")
        expires_at_iso     = $expiresAt.ToString("o")
        client_id          = $ClientIdValue
        token_url          = $TokenUrl
        swarms_url         = $SwarmsUrl
        access_token       = $TokenResponse.access_token
    }

    $tokenObj |
        ConvertTo-Json -Depth 10 |
        Set-Content -Path $TokenBackupFile -Encoding UTF8

    Write-Good "Token backup saved to: $TokenBackupFile"
    Write-Info "Generated at : $($tokenObj.generated_at_local)"
    Write-Info "Expires at   : $($tokenObj.expires_at_local)"

    return $tokenObj
}

function Get-NewToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientIdValue,
        [Parameter(Mandatory = $true)]
        [string]$ClientSecretValue
    )

    Write-Info "Generating new Aruba Central token using client credentials..."

    $headers = @{
        accept = "application/json"
    }

    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientIdValue
        client_secret = $ClientSecretValue
    }

    try {
        $resp = Invoke-RestMethod `
            -Uri $TokenUrl `
            -Method POST `
            -Headers $headers `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $body

        if (Is-Empty $resp.access_token) {
            throw "Token response did not contain access_token."
        }

        Write-Good "New token generated successfully."

        return Save-TokenBackup -TokenResponse $resp -ClientIdValue $ClientIdValue
    }
    catch {
        Write-Bad "Failed to generate token."
        throw $_
    }
}

function Get-CurrentToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientIdValue,
        [Parameter(Mandatory = $true)]
        [string]$ClientSecretValue
    )

    if (Test-Path $TokenBackupFile) {

        try {
            $cached = Get-Content -Path $TokenBackupFile -Raw | ConvertFrom-Json

            if (-not (Is-Empty $cached.access_token)) {

                if (Test-TokenValidByExpiry -ExpiresAtIso $cached.expires_at_iso) {
                    Write-Good "Using valid cached token from: $TokenBackupFile"
                    Write-Info "Expires at: $($cached.expires_at_local)"
                    return $cached
                }
                else {
                    Write-Warn2 "Cached token expired or near expiry. Will regenerate."
                }
            }
            else {
                Write-Warn2 "Cached token file did not contain access_token. Will regenerate."
            }
        }
        catch {
            Write-Warn2 "Could not read cached token file. Will regenerate."
        }
    }
    else {
        Write-Info "No cached token file. Will generate a new token."
    }

    return Get-NewToken `
        -ClientIdValue $ClientIdValue `
        -ClientSecretValue $ClientSecretValue
}

# -----------------------------
# API helpers
# -----------------------------

function Invoke-ArubaGet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

    $headers = @{
        accept        = "application/json"
        authorization = "Bearer $AccessToken"
    }

    return Invoke-RestMethod -Uri $Uri -Method GET -Headers $headers
}

function Build-PagedUrl {
    param(
        [string]$BaseUrl,
        [string]$Next,
        [int]$Limit
    )

    $parts = @()
    $parts += ("limit=" + $Limit)

    if (-not (Is-Empty $Next)) {
        $parts += ("next=" + $Next)
    }

    $query = ($parts -join "&")

    if ($BaseUrl.Contains("?")) {
        return ($BaseUrl + "&" + $query)
    }
    else {
        return ($BaseUrl + "?" + $query)
    }
}

function Open-File {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Warn2 "Cannot open - file not found: $Path"
        return
    }

    $info = Get-Item -Path $Path
    $ageSec = (New-TimeSpan -Start $info.LastWriteTime -End (Get-Date)).TotalSeconds

    if ($ageSec -gt 60) {
        Write-Warn2 "Stale file (age=$([int]$ageSec)s) - will NOT open: $($info.Name)"
        return
    }

    try {
        $full = (Resolve-Path -Path $Path).Path
        Start-Process -FilePath $full
        Write-Good "Opened: $full"
    }
    catch {
        Write-Warn2 "Failed to open file '$Path'. Error: $($_.Exception.Message)"
    }
}

# -----------------------------
# Start
# -----------------------------

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host " Aruba Central - Swarm VC / Conductor AP Export (v7)"
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""

# Credentials
$ClientID     = Ask-Value -Current $ClientID     -Prompt "Enter Aruba Central Client ID"
$ClientSecret = Ask-Value -Current $ClientSecret -Prompt "Enter Aruba Central Client Secret" -Secret

if (Is-Empty $ClientID)     { throw "Client ID is required." }
if (Is-Empty $ClientSecret) { throw "Client Secret is required." }

# Run mode
if ($RunMode -eq "Ask") {
    $RunMode = Ask-RunMode
}

$IsTestRun = $false

if ($RunMode -eq "Test") {
    $IsTestRun = $true

    Write-Host ""
    Write-Warn2 "TEST mode selected."

    $MaxPages = Ask-PositiveInt -Prompt "Enter maximum pages to fetch" -Default $MaxPages
    $MaxItems = Ask-PositiveInt -Prompt "Enter maximum items to save"  -Default $MaxItems
}
else {
    Write-Host ""
    Write-Info "FULL mode selected. Script will fetch ALL available swarms."
}

# Page size
if ($PageSize -gt 1000) {
    Write-Warn2 "PageSize $PageSize exceeds API max 1000. Forcing to 1000."
    $PageSize = 1000
}

if ($PageSize -lt 1) {
    Write-Warn2 "PageSize $PageSize invalid. Using 1000."
    $PageSize = 1000
}

Write-Host ""
Write-Info "Token URL    : $TokenUrl"
Write-Info "Swarms URL   : $SwarmsUrl"
Write-Info "Run mode     : $RunMode"
Write-Info "Page size    : $PageSize"
Write-Info "PFS pattern  : $PfsPattern"

if ($IsTestRun) {
    Write-Info "Max pages    : $MaxPages"
    Write-Info "Max items    : $MaxItems"
}

# Get token
$ActiveToken = Get-CurrentToken `
    -ClientIdValue $ClientID `
    -ClientSecretValue $ClientSecret

$AccessToken = $ActiveToken.access_token

# -----------------------------
# Paging loop - uses API's "next" cursor
# -----------------------------

$AllRawPages = New-Object System.Collections.Generic.List[object]
$AllItems    = New-Object System.Collections.Generic.List[object]

$NextToken  = ""
$PageNumber = 1
$ApiTotal   = $null
$StopPaging = $false
$LoopGuard  = 0

$StartTime = Get-Date

Write-Host ""
Write-Host "============== STARTING DATA COLLECTION =============" -ForegroundColor Magenta
Write-Host "Start time : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "=====================================================" -ForegroundColor Magenta

while ($true) {

    $LoopGuard++
    if ($LoopGuard -gt $MaxLoopIterations) {
        Write-Bad "Safety stop: loop exceeded $MaxLoopIterations iterations."
        break
    }

    if ($IsTestRun -and $PageNumber -gt $MaxPages) {
        Write-Warn2 "Stopping: TEST mode max pages reached ($MaxPages)."
        break
    }

    $Uri = Build-PagedUrl -BaseUrl $SwarmsUrl -Next $NextToken -Limit $PageSize

    Write-Host ""
    Write-Host "------------------ PAGE $PageNumber ------------------" -ForegroundColor White
    Write-Info "Next token : '$NextToken'"
    Write-Info "Limit      : $PageSize"
    Write-Info "URI        : $Uri"

    $pageStart = Get-Date

    try {
        $Response = Invoke-ArubaGet -Uri $Uri -AccessToken $AccessToken
    }
    catch {
        $code = $null
        if ($_.Exception.Response) {
            try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        }

        if ($code -eq 401) {
            Write-Warn2 "Got 401 Unauthorized. Generating a new token and retrying once..."

            $ActiveToken = Get-NewToken `
                -ClientIdValue $ClientID `
                -ClientSecretValue $ClientSecret

            $AccessToken = $ActiveToken.access_token

            $Response = Invoke-ArubaGet -Uri $Uri -AccessToken $AccessToken
        }
        else {
            throw $_
        }
    }

    $pageEnd = Get-Date
    $pageDurationSec = [System.Math]::Round(($pageEnd - $pageStart).TotalSeconds, 2)

    $AllRawPages.Add($Response) | Out-Null

    if ($Response.total) {
        try { $ApiTotal = [int]$Response.total } catch { $ApiTotal = $null }
    }

    $itemsInThisPage = 0

    if ($Response.items) {
        foreach ($item in $Response.items) {

            if ($IsTestRun -and $AllItems.Count -ge $MaxItems) {
                Write-Warn2 "Stopping: TEST mode max items reached ($MaxItems)."
                $StopPaging = $true
                break
            }

            $AllItems.Add($item) | Out-Null
            $itemsInThisPage++
        }
    }

    $collected = $AllItems.Count
    $elapsed = (Get-Date) - $StartTime
    $elapsedStr = ("{0:hh\:mm\:ss}" -f $elapsed)

    Write-Good "Items returned this page : $itemsInThisPage  (fetched in $pageDurationSec s)"

    if ($ApiTotal) {

        $remaining = $ApiTotal - $collected
        if ($remaining -lt 0) { $remaining = 0 }

        $percentDone = [System.Math]::Round((($collected / $ApiTotal) * 100), 2)

        $etaText = "n/a"
        if ($collected -gt 0 -and $remaining -gt 0) {
            $secPerItem = $elapsed.TotalSeconds / $collected
            $etaSeconds = [System.Math]::Round($secPerItem * $remaining, 0)
            $etaSpan    = New-TimeSpan -Seconds $etaSeconds
            $etaText    = ("{0:hh\:mm\:ss}" -f $etaSpan)
        }

        Write-Info "Collected total          : $collected / $ApiTotal ($percentDone %)"
        Write-Info "Remaining                : $remaining"
        Write-Info "Elapsed                  : $elapsedStr"
        Write-Info "Estimated remaining      : $etaText"

        $percentForBar = [int]$percentDone
        if ($percentForBar -gt 100) { $percentForBar = 100 }
        if ($percentForBar -lt 0)   { $percentForBar = 0 }

        Write-Progress `
            -Activity "Fetching Aruba Central Swarms" `
            -Status ("Collected {0} of {1} ({2}%) - ETA {3}" -f $collected, $ApiTotal, $percentDone, $etaText) `
            -PercentComplete $percentForBar
    }
    else {
        Write-Info "Collected total          : $collected"
        Write-Info "Elapsed                  : $elapsedStr"

        Write-Progress `
            -Activity "Fetching Aruba Central Swarms" `
            -Status ("Collected {0} entries..." -f $collected)
    }

    if ($StopPaging) {
        break
    }

    if (Is-Empty $Response.next) {
        Write-Info "API returned no more pages (next is null/empty). Done."
        break
    }

    if ($itemsInThisPage -eq 0) {
        Write-Info "No items returned. Stopping."
        break
    }

    $NextToken  = [string]$Response.next
    $PageNumber++
}

Write-Progress -Activity "Fetching Aruba Central Swarms" -Completed

$EndTime = Get-Date
$TotalDuration = $EndTime - $StartTime
$TotalDurationStr = ("{0:hh\:mm\:ss}" -f $TotalDuration)

# -----------------------------
# Save raw JSON
# -----------------------------

Write-Host ""
Write-Info "Saving raw JSON outputs..."

$exportedAt = Get-Date

$maxPagesValue = $null
$maxItemsValue = $null

if ($IsTestRun) {
    $maxPagesValue = $MaxPages
    $maxItemsValue = $MaxItems
}

$pageWrapper = [pscustomobject]@{
    exported_at_local = $exportedAt.ToString("yyyy-MM-dd HH:mm:ss")
    exported_at_iso   = $exportedAt.ToString("o")
    run_mode          = $RunMode
    test_run          = [bool]$IsTestRun
    page_size         = $PageSize
    max_pages         = $maxPagesValue
    max_items         = $maxItemsValue
    source_url        = $SwarmsUrl
    api_total         = $ApiTotal
    total_items       = $AllItems.Count
    page_count        = $AllRawPages.Count
    pages             = $AllRawPages
}

$itemWrapper = [pscustomobject]@{
    exported_at_local = $exportedAt.ToString("yyyy-MM-dd HH:mm:ss")
    exported_at_iso   = $exportedAt.ToString("o")
    run_mode          = $RunMode
    test_run          = [bool]$IsTestRun
    page_size         = $PageSize
    max_pages         = $maxPagesValue
    max_items         = $maxItemsValue
    source_url        = $SwarmsUrl
    api_total         = $ApiTotal
    total_items       = $AllItems.Count
    items             = $AllItems
}

$pageWrapper |
    ConvertTo-Json -Depth 50 |
    Set-Content -Path $RawPagesJsonFile -Encoding UTF8

$itemWrapper |
    ConvertTo-Json -Depth 50 |
    Set-Content -Path $RawItemsJsonFile -Encoding UTF8

Write-Good "Raw page JSON saved: $RawPagesJsonFile"
Write-Good "Raw item JSON saved: $RawItemsJsonFile"

# -----------------------------
# Build CSV data
# -----------------------------

Write-Info "Building CSV report..."

$CsvData = foreach ($item in $AllItems) {

    $storeCode = ""

    if ($item.clusterName) {
        if ($item.clusterName -match "^(.*?)-VC$") {
            $storeCode = $Matches[1]
        }
        else {
            $storeCode = $item.clusterName
        }
    }

    $vcName = $item.conductorDeviceName

    $isPfs = $false
    if ($vcName -and ($vcName -match $PfsPattern)) {
        $isPfs = $true
    }

    [pscustomobject]@{
        StoreCode          = $storeCode
        ClusterName        = $item.clusterName
        ClusterId          = $item.clusterId
        SiteId             = $item.siteId
        SiteName           = $item.siteName
        VC_AP_Name         = $vcName
        VC_AP_SerialNumber = $item.conductorSerialNumber
        VC_IPv4            = $item.ipv4
        VC_IPv6            = $item.ipv6
        PublicIpAddress    = $item.publicIpAddress
        FirmwareVersion    = $item.firmwareVersion
        Type               = $item.type
        RawId              = $item.id
        IsPFS_VC           = $isPfs
    }
}

# -----------------------------
# Save RAW CSV (before dedup) for validation
# -----------------------------

$RawRowCount = @($CsvData).Count

$CsvData |
    Sort-Object StoreCode, ClusterName |
    Export-Csv -Path $RawCsvFile -NoTypeInformation -Encoding UTF8

Write-Good "RAW CSV saved (pre-dedup): $RawCsvFile  ($RawRowCount rows)"

# -----------------------------
# Deduplicate by ClusterId
# Keeps the latest copy of each swarm (page 2 wins if same ClusterId in both pages)
# -----------------------------

Write-Info "Deduplicating by ClusterId (keeping latest copy of each swarm)..."

$bucket = @{}

foreach ($row in $CsvData) {

    $key = [string]$row.ClusterId

    if (Is-Empty $key) {
        # No clusterId - use synthetic unique key so the row is preserved
        $key = "NOCLUSTERID_" + [System.Guid]::NewGuid().ToString()
    }

    # Always overwrite so LAST occurrence wins (= freshest data)
    $bucket[$key] = $row
}

$Deduped = @($bucket.Values)
$AfterCount   = $Deduped.Count
$RemovedCount = $RawRowCount - $AfterCount

# -----------------------------
# Detect field-level conflicts across pages (same ClusterId, different content)
# -----------------------------

$diagFields = @(
    "VC_AP_Name",
    "VC_AP_SerialNumber",
    "VC_IPv4",
    "VC_IPv6",
    "PublicIpAddress",
    "FirmwareVersion",
    "SiteName",
    "SiteId",
    "ClusterName"
)

$ConflictRows = New-Object System.Collections.Generic.List[object]
$byCluster = $CsvData | Group-Object -Property ClusterId

foreach ($g in $byCluster) {

    if ($g.Count -lt 2) { continue }

    $diffs = @{}
    $hasConflict = $false

    foreach ($f in $diagFields) {
        $vals = ($g.Group | ForEach-Object { [string]$_.$f }) | Sort-Object -Unique
        if (@($vals).Count -gt 1) {
            $hasConflict = $true
            $diffs[$f] = ($vals -join " | ")
        }
    }

    if ($hasConflict) {

        $obj = [ordered]@{
            ClusterId      = $g.Name
            OccurrenceCount = $g.Count
            ClusterName    = ($g.Group | Select-Object -First 1).ClusterName
        }

        foreach ($f in $diagFields) {
            if ($diffs.ContainsKey($f)) {
                $obj["$f`_Differs"] = $diffs[$f]
            }
        }

        $ConflictRows.Add([pscustomobject]$obj) | Out-Null
    }
}

$ConflictCount = $ConflictRows.Count

if ($RemovedCount -gt 0) {
    Write-Warn2 "Removed $RemovedCount duplicate row(s) by ClusterId. Unique swarms: $AfterCount (was $RawRowCount)."
}
else {
    Write-Good "No duplicates by ClusterId. Total unique swarms: $AfterCount."
}

if ($ConflictCount -gt 0) {
    $ConflictRows |
        Sort-Object ClusterName |
        Export-Csv -Path $ConflictCsvFile -NoTypeInformation -Encoding UTF8

    Write-Warn2 "$ConflictCount swarm(s) had different field values across API pages."
    Write-Warn2 "Conflicts CSV saved: $ConflictCsvFile"
    Write-Warn2 "These swarms likely changed state between API page 1 and page 2."
}
else {
    Write-Good "No field-level conflicts detected across pages."
}

# Promote deduped data to $CsvData for downstream use
$CsvData = $Deduped

# -----------------------------
# Save DEDUPED CSV
# -----------------------------

$CsvData |
    Sort-Object StoreCode, ClusterName |
    Export-Csv -Path $FinalCsvFile -NoTypeInformation -Encoding UTF8

Write-Good "DEDUPED CSV saved: $FinalCsvFile  ($($CsvData.Count) rows)"

# -----------------------------
# PFS-as-VC analysis (no detail printed in CLI)
# -----------------------------

$PfsRows = $CsvData | Where-Object { $_.IsPFS_VC -eq $true }

$PfsCount   = $PfsRows.Count
$TotalCount = $CsvData.Count

$PfsPct = 0
if ($TotalCount -gt 0) {
    $PfsPct = [System.Math]::Round((($PfsCount / $TotalCount) * 100), 2)
}

if ($PfsCount -gt 0) {
    $PfsRows |
        Select-Object StoreCode, ClusterName, VC_AP_Name, VC_AP_SerialNumber, VC_IPv4, FirmwareVersion, SiteId, ClusterId |
        Sort-Object StoreCode, ClusterName |
        Export-Csv -Path $PfsCsvFile -NoTypeInformation -Encoding UTF8

    Write-Good "PFS-as-VC CSV saved: $PfsCsvFile  ($PfsCount rows)"
}

# -----------------------------
# Auto-open CSVs
# -----------------------------

if (-not $NoAutoOpen) {
    Write-Host ""
    Write-Info "Opening CSV files..."

    Open-File -Path $RawCsvFile
    Open-File -Path $FinalCsvFile

    if ($ConflictCount -gt 0) {
        Open-File -Path $ConflictCsvFile
    }

    if ($PfsCount -gt 0) {
        Open-File -Path $PfsCsvFile
    }
}
else {
    Write-Info "Auto-open disabled by -NoAutoOpen switch."
}

# -----------------------------
# Final summary (at the very end)
# -----------------------------

Write-Host ""
Write-Host "====================== SUMMARY ======================" -ForegroundColor Green
Write-Host "Run mode                : $RunMode"
Write-Host "Test run enabled        : $IsTestRun"
Write-Host "Page size               : $PageSize"
Write-Host "API total reported      : $ApiTotal"
Write-Host "Total swarms collected  : $($AllItems.Count)"
Write-Host "RAW rows                : $RawRowCount"
Write-Host "Unique rows (deduped)   : $($CsvData.Count)"
Write-Host "Duplicate rows removed  : $RemovedCount"
Write-Host "ClusterId conflicts     : $ConflictCount"
Write-Host "Total API pages         : $($AllRawPages.Count)"
Write-Host "Total duration          : $TotalDurationStr"
Write-Host "PFS pattern searched    : $PfsPattern"
Write-Host "Swarms with PFS as VC   : $PfsCount ($PfsPct %)"
Write-Host "Token backup file       : $TokenBackupFile"
Write-Host "Raw page JSON           : $RawPagesJsonFile"
Write-Host "Raw item JSON           : $RawItemsJsonFile"
Write-Host "RAW CSV (pre-dedup)     : $RawCsvFile  ($RawRowCount rows)"
Write-Host "DEDUPED CSV             : $FinalCsvFile  ($($CsvData.Count) rows)"
if ($ConflictCount -gt 0) {
    Write-Host "Conflicts CSV           : $ConflictCsvFile  ($ConflictCount rows)"
}
else {
    Write-Host "Conflicts CSV           : (none)"
}
if ($PfsCount -gt 0) {
    Write-Host "PFS offenders CSV       : $PfsCsvFile  ($PfsCount rows)"
}
else {
    Write-Host "PFS offenders CSV       : (none - no PFS APs acting as VC)"
}
Write-Host "=====================================================" -ForegroundColor Green
Write-Host ""
