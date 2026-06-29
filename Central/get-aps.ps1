param(
    [string]$ClientID,
    [string]$ClientSecret,
    [string]$TokenUrl  = "https://sso.common.cloud.hpe.com/as/token.oauth2",
    [string]$ApsUrl    = "https://de1.api.central.arubanetworks.com/network-monitoring/v1/aps",

    [ValidateSet("Ask", "Test", "Full")]
    [string]$RunMode = "Ask",

    [int]$MaxPages = 1,
    [int]$MaxItems = 20,
    [int]$PageSize = 1000,
    [string]$PfsPattern = "PFS",
    [switch]$NoAutoOpen
)

# ============================================================
# Aruba Central - Access Points Export & Analysis (v9)
# ============================================================
# - Pulls ALL APs from /network-monitoring/v1/aps
# - Saves every attribute (raw JSON + full CSV)
# - Filters APs where role = "Conductor" (= VC for that cluster)
# - Within Conductors, flags PFS APs as problematic
# - Detects multi-Conductor clusters and orphan clusters
# - Detects sites (siteId) hosting more than one cluster
# - Token cache, dynamic prompts, test/full mode
# - Auto-opens CSV files on completion
# ============================================================

$ErrorActionPreference = "Stop"

# -----------------------------
# File paths (millisecond-precise timestamp)
# -----------------------------

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"

$TokenBackupFile     = ".\ArubaCentral_Token_Backup.json"
$RawPagesJsonFile    = ".\ArubaCentral_APs_RawPages_$TimeStamp.json"
$RawItemsJsonFile    = ".\ArubaCentral_APs_RawItems_$TimeStamp.json"
$AllApsCsvFile       = ".\ArubaCentral_APs_ALL_$TimeStamp.csv"
$ConductorCsvFile    = ".\ArubaCentral_APs_CONDUCTORS_$TimeStamp.csv"
$PfsCsvFile          = ".\ArubaCentral_APs_PFS_CONDUCTORS_$TimeStamp.csv"
$MultiClusterCsvFile = ".\ArubaCentral_Sites_MultiCluster_$TimeStamp.csv"

$TokenExpiryBufferMinutes = 5
$MaxLoopIterations = 10000

# -----------------------------
# Logging
# -----------------------------

function Write-Info  { param([string]$m) Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Good  { param([string]$m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Bad   { param([string]$m) Write-Host "[ERR]  $m" -ForegroundColor Red }

# -----------------------------
# Helpers
# -----------------------------

function Is-Empty {
    param($Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [string]) {
        if ($Value.Trim().Length -eq 0) { return $true }
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

    if (-not (Is-Empty $Current)) { return $Current }

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
        Write-Host "  2. FULL run  - fetch ALL APs"
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
        if (Is-Empty $raw) { return $Default }
        $raw = $raw.Trim()
        $parsed = 0
        $ok = $false
        try { $parsed = [int]$raw; $ok = $true } catch { $ok = $false }
        if ($ok -and $parsed -gt 0) { return $parsed }
        Write-Warn2 "Please enter a positive whole number."
    }
}

# -----------------------------
# Token helpers
# -----------------------------

function Test-TokenValidByExpiry {
    param([string]$ExpiresAtIso)

    if (Is-Empty $ExpiresAtIso) { return $false }

    try {
        $expiresAt = Get-Date $ExpiresAtIso
        $safeTime  = $expiresAt.AddMinutes(-$TokenExpiryBufferMinutes)
        if ((Get-Date) -lt $safeTime) { return $true } else { return $false }
    }
    catch { return $false }
}

function Save-TokenBackup {
    param(
        [Parameter(Mandatory = $true)] $TokenResponse,
        [Parameter(Mandatory = $true)] [string]$ClientIdValue
    )

    $generatedAt = Get-Date
    $expiresInSec = 0
    if ($TokenResponse.expires_in) { $expiresInSec = [int]$TokenResponse.expires_in }
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
        aps_url            = $ApsUrl
        access_token       = $TokenResponse.access_token
    }

    $tokenObj | ConvertTo-Json -Depth 10 | Set-Content -Path $TokenBackupFile -Encoding UTF8

    Write-Good "Token backup saved: $TokenBackupFile"
    Write-Info "Generated at : $($tokenObj.generated_at_local)"
    Write-Info "Expires at   : $($tokenObj.expires_at_local)"

    return $tokenObj
}

function Get-NewToken {
    param(
        [Parameter(Mandatory = $true)] [string]$ClientIdValue,
        [Parameter(Mandatory = $true)] [string]$ClientSecretValue
    )

    Write-Info "Generating new Aruba Central token using client credentials..."

    $headers = @{ accept = "application/json" }
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
        [Parameter(Mandatory = $true)] [string]$ClientIdValue,
        [Parameter(Mandatory = $true)] [string]$ClientSecretValue
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

    return Get-NewToken -ClientIdValue $ClientIdValue -ClientSecretValue $ClientSecretValue
}

# -----------------------------
# API helpers
# -----------------------------

function Invoke-ArubaGet {
    param(
        [Parameter(Mandatory = $true)] [string]$Uri,
        [Parameter(Mandatory = $true)] [string]$AccessToken
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
Write-Host " Aruba Central - APs Export & Conductor / PFS Detector (v9)"
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""

$ClientID     = Ask-Value -Current $ClientID     -Prompt "Enter Aruba Central Client ID"
$ClientSecret = Ask-Value -Current $ClientSecret -Prompt "Enter Aruba Central Client Secret" -Secret

if (Is-Empty $ClientID)     { throw "Client ID is required." }
if (Is-Empty $ClientSecret) { throw "Client Secret is required." }

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
    Write-Info "FULL mode selected. Script will fetch ALL APs."
}

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
Write-Info "APs URL      : $ApsUrl"
Write-Info "Run mode     : $RunMode"
Write-Info "Page size    : $PageSize"
Write-Info "PFS pattern  : $PfsPattern"

if ($IsTestRun) {
    Write-Info "Max pages    : $MaxPages"
    Write-Info "Max items    : $MaxItems"
}

$ActiveToken = Get-CurrentToken -ClientIdValue $ClientID -ClientSecretValue $ClientSecret
$AccessToken = $ActiveToken.access_token

# -----------------------------
# Paging loop
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

    $Uri = Build-PagedUrl -BaseUrl $ApsUrl -Next $NextToken -Limit $PageSize

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
            Write-Warn2 "Got 401. Refreshing token and retrying..."
            $ActiveToken = Get-NewToken -ClientIdValue $ClientID -ClientSecretValue $ClientSecret
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
            -Activity "Fetching Aruba Central APs" `
            -Status ("Collected {0} of {1} ({2}%) - ETA {3}" -f $collected, $ApiTotal, $percentDone, $etaText) `
            -PercentComplete $percentForBar
    }
    else {
        Write-Info "Collected total          : $collected"
        Write-Info "Elapsed                  : $elapsedStr"
        Write-Progress -Activity "Fetching Aruba Central APs" `
                       -Status ("Collected {0} entries..." -f $collected)
    }

    if ($StopPaging) { break }

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

Write-Progress -Activity "Fetching Aruba Central APs" -Completed

$EndTime = Get-Date
$TotalDuration = $EndTime - $StartTime
$TotalDurationStr = ("{0:hh\:mm\:ss}" -f $TotalDuration)

# -----------------------------
# Save raw JSON (all attributes preserved)
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
    source_url        = $ApsUrl
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
    source_url        = $ApsUrl
    api_total         = $ApiTotal
    total_items       = $AllItems.Count
    items             = $AllItems
}

$pageWrapper | ConvertTo-Json -Depth 50 | Set-Content -Path $RawPagesJsonFile -Encoding UTF8
$itemWrapper | ConvertTo-Json -Depth 50 | Set-Content -Path $RawItemsJsonFile -Encoding UTF8

Write-Good "Raw page JSON saved: $RawPagesJsonFile"
Write-Good "Raw item JSON saved: $RawItemsJsonFile"

# -----------------------------
# Build ALL-APs CSV (every attribute preserved)
# -----------------------------

Write-Info "Building ALL-APs CSV (every attribute)..."

# Collect every property name across the entire dataset
$allPropNames = New-Object System.Collections.Generic.HashSet[string]
foreach ($item in $AllItems) {
    foreach ($p in $item.PSObject.Properties) {
        [void]$allPropNames.Add($p.Name)
    }
}

# Add derived columns
[void]$allPropNames.Add("IsConductor")
[void]$allPropNames.Add("IsPFS_Conductor")
[void]$allPropNames.Add("StoreCode")

$columnOrder = $allPropNames | Sort-Object

$AllApsCsvData = foreach ($item in $AllItems) {

    $deviceName = $item.deviceName

    # Derive store code
    $storeCode = ""
    if ($item.clusterName -and $item.clusterName -match "^(.*?)-VC$") {
        $storeCode = $Matches[1]
    }
    elseif ($deviceName -and $deviceName -match "^([A-Za-z]+\d+)") {
        $storeCode = $Matches[1]
    }
    elseif ($item.clusterName) {
        $storeCode = $item.clusterName
    }

    $isConductor = $false
    if ($item.role -and ($item.role -eq "Conductor")) {
        $isConductor = $true
    }

    $isPfsConductor = $false
    if ($isConductor -and $deviceName -and ($deviceName -match $PfsPattern)) {
        $isPfsConductor = $true
    }

    $row = [ordered]@{}

    foreach ($col in $columnOrder) {

        if ($col -eq "IsConductor")     { $row[$col] = $isConductor;     continue }
        if ($col -eq "IsPFS_Conductor") { $row[$col] = $isPfsConductor;  continue }
        if ($col -eq "StoreCode")       { $row[$col] = $storeCode;       continue }

        $val = $null
        if ($item.PSObject.Properties.Name -contains $col) {
            $val = $item.$col
        }

        # Convert nested arrays/objects to JSON so CSV stays readable
        if ($null -ne $val -and ($val -is [System.Collections.IEnumerable]) -and -not ($val -is [string])) {
            $val = ($val | ConvertTo-Json -Compress -Depth 5)
        }

        $row[$col] = $val
    }

    [pscustomobject]$row
}

$AllApsCsvData |
    Sort-Object StoreCode, clusterName, deviceName |
    Export-Csv -Path $AllApsCsvFile -NoTypeInformation -Encoding UTF8

Write-Good "ALL APs CSV saved: $AllApsCsvFile  ($($AllApsCsvData.Count) rows)"

# -----------------------------
# Conductors-only CSV
# -----------------------------

Write-Info "Filtering Conductors..."

$ConductorRows = $AllApsCsvData | Where-Object { $_.IsConductor -eq $true }
$ConductorCount = @($ConductorRows).Count

$ConductorRows |
    Sort-Object StoreCode, clusterName, deviceName |
    Export-Csv -Path $ConductorCsvFile -NoTypeInformation -Encoding UTF8

Write-Good "CONDUCTORS CSV saved: $ConductorCsvFile  ($ConductorCount rows)"

# -----------------------------
# Conductors-per-cluster diagnostics
# -----------------------------

$ConductorClusterGroups = $ConductorRows | Group-Object -Property clusterId

$ClustersWithMultiConductor = $ConductorClusterGroups | Where-Object { $_.Count -gt 1 }

$ClustersWithZeroConductor = $AllApsCsvData |
    Where-Object { -not (Is-Empty $_.clusterId) } |
    Group-Object -Property clusterId |
    Where-Object { -not ($_.Group | Where-Object { $_.IsConductor -eq $true }) }

$MultiConductorCount = @($ClustersWithMultiConductor).Count
$ZeroConductorCount  = @($ClustersWithZeroConductor).Count

if ($MultiConductorCount -gt 0) {
    Write-Host ""
    Write-Warn2 "$MultiConductorCount cluster(s) have MORE than 1 Conductor AP:"
    Write-Host ""

    $multiConductorDetails = foreach ($g in $ClustersWithMultiConductor) {

        $first = $g.Group | Select-Object -First 1

        [pscustomobject]@{
            StoreCode       = $first.StoreCode
            ClusterName     = $first.clusterName
            ClusterId       = $g.Name
            ConductorCount  = $g.Count
            ConductorAPs    = ($g.Group | ForEach-Object { $_.deviceName }) -join ", "
            SiteId          = $first.siteId
            SiteName        = $first.siteName
        }
    }

    $multiConductorDetails |
        Sort-Object StoreCode, ClusterName |
        Format-Table StoreCode, ClusterName, ConductorCount, ConductorAPs, SiteName -AutoSize -Wrap
}

if ($ZeroConductorCount -gt 0) {
    Write-Host ""
    Write-Warn2 "$ZeroConductorCount cluster(s) have NO Conductor AP ( Might be Standalone APs ) :"
    Write-Host ""

    $zeroConductorDetails = foreach ($g in $ClustersWithZeroConductor) {

        $first = $g.Group | Select-Object -First 1

        [pscustomobject]@{
            StoreCode    = $first.StoreCode
            ClusterName  = $first.clusterName
            ClusterId    = $g.Name
            APCount      = $g.Count
            APs          = ($g.Group | ForEach-Object { $_.deviceName }) -join ", "
            SiteId       = $first.siteId
            SiteName     = $first.siteName
            APStatuses   = ($g.Group | ForEach-Object { "$($_.deviceName)=$($_.status)" }) -join ", "
        }
    }

    $zeroConductorDetails |
        Sort-Object StoreCode, ClusterName |
        Format-Table StoreCode, ClusterName, APCount, APs, APStatuses, SiteName -AutoSize -Wrap
}

# -----------------------------
# Sites with more than 1 cluster
# -----------------------------

Write-Info "Checking for sites with more than 1 cluster..."

$MultiClusterRows = New-Object System.Collections.Generic.List[object]

$bySite = $AllApsCsvData |
    Where-Object { -not (Is-Empty $_.siteId) } |
    Group-Object -Property siteId

foreach ($s in $bySite) {

    $clusters = @($s.Group |
        Where-Object { -not (Is-Empty $_.clusterId) } |
        Group-Object -Property clusterId)

    if ($clusters.Count -gt 1) {

        $siteName  = ($s.Group | Select-Object -First 1).siteName
        $storeCode = ($s.Group | Select-Object -First 1).StoreCode

        $clusterNames = ($clusters | ForEach-Object {
                            ($_.Group | Select-Object -First 1).clusterName
                        }) -join " | "

        $clusterIds = ($clusters | ForEach-Object { $_.Name }) -join " | "

        $apCountPerCluster = ($clusters | ForEach-Object {
                                "$(($_.Group | Select-Object -First 1).clusterName)=$($_.Count)"
                            }) -join " | "

        $conductorPerCluster = ($clusters | ForEach-Object {
                                  $conductorsInCluster = $_.Group | Where-Object { $_.IsConductor -eq $true }
                                  $names = ($conductorsInCluster | ForEach-Object { $_.deviceName }) -join ","
                                  if (Is-Empty $names) { $names = "(none)" }
                                  "$(($_.Group | Select-Object -First 1).clusterName)=$names"
                              }) -join " | "

        $MultiClusterRows.Add([pscustomobject]@{
            SiteId                 = $s.Name
            StoreCode              = $storeCode
            SiteName               = $siteName
            ClusterCount           = $clusters.Count
            TotalAPsAtSite         = $s.Group.Count
            ClusterNames           = $clusterNames
            ClusterIds             = $clusterIds
            APsPerCluster          = $apCountPerCluster
            ConductorsPerCluster   = $conductorPerCluster
        }) | Out-Null
    }
}

$MultiClusterSiteCount = $MultiClusterRows.Count

if ($MultiClusterSiteCount -gt 0) {

    $MultiClusterRows |
        Sort-Object StoreCode, SiteName |
        Export-Csv -Path $MultiClusterCsvFile -NoTypeInformation -Encoding UTF8

    Write-Warn2 "$MultiClusterSiteCount site(s) have MORE than 1 cluster."
    Write-Warn2 "Multi-cluster CSV saved: $MultiClusterCsvFile"
}
else {
    Write-Good "All sites have exactly 1 cluster. No anomalies."
}

# -----------------------------
# PFS Conductors CSV
# -----------------------------

Write-Info "Filtering PFS-named Conductors..."

$PfsRows = $ConductorRows | Where-Object { $_.IsPFS_Conductor -eq $true }
$PfsCount = @($PfsRows).Count

$PfsPct = 0
if ($ConductorCount -gt 0) {
    $PfsPct = [System.Math]::Round((($PfsCount / $ConductorCount) * 100), 2)
}

if ($PfsCount -gt 0) {
    $PfsRows |
        Sort-Object StoreCode, clusterName, deviceName |
        Export-Csv -Path $PfsCsvFile -NoTypeInformation -Encoding UTF8

    Write-Good "PFS Conductors CSV saved: $PfsCsvFile  ($PfsCount rows)"
}

# -----------------------------
# Auto-open
# -----------------------------

if (-not $NoAutoOpen) {
    Write-Host ""
    Write-Info "Opening CSV files..."

    Open-File -Path $AllApsCsvFile
    Open-File -Path $ConductorCsvFile

    if ($MultiClusterSiteCount -gt 0) {
        Open-File -Path $MultiClusterCsvFile
    }

    if ($PfsCount -gt 0) {
        Open-File -Path $PfsCsvFile
    }
}
else {
    Write-Info "Auto-open disabled by -NoAutoOpen switch."
}

# -----------------------------
# Summary
# -----------------------------

Write-Host ""
Write-Host "====================== SUMMARY ======================" -ForegroundColor Green
Write-Host "Run mode                     : $RunMode"
Write-Host "Test run enabled             : $IsTestRun"
Write-Host "Page size                    : $PageSize"
Write-Host "API total reported           : $ApiTotal"
Write-Host "Total APs collected          : $($AllItems.Count)"
Write-Host "Total API pages              : $($AllRawPages.Count)"
Write-Host "Total duration               : $TotalDurationStr"
Write-Host ""
Write-Host "Conductors found             : $ConductorCount"
Write-Host "Clusters w/ multi-Conductor  : $MultiConductorCount"
Write-Host "Clusters w/ NO Conductor     : $ZeroConductorCount"
Write-Host "Sites with >1 cluster        : $MultiClusterSiteCount"
Write-Host ""
Write-Host "PFS pattern searched         : $PfsPattern"
Write-Host "PFS APs acting as Conductor  : $PfsCount ($PfsPct % of Conductors)"
Write-Host ""
Write-Host "Token backup file            : $TokenBackupFile"
Write-Host "Raw page JSON                : $RawPagesJsonFile"
Write-Host "Raw item JSON                : $RawItemsJsonFile"
Write-Host "ALL APs CSV                  : $AllApsCsvFile"
Write-Host "CONDUCTORS CSV               : $ConductorCsvFile"
if ($MultiClusterSiteCount -gt 0) {
    Write-Host "Multi-cluster Sites CSV      : $MultiClusterCsvFile"
}
else {
    Write-Host "Multi-cluster Sites CSV      : (none - all sites have 1 cluster)"
}
if ($PfsCount -gt 0) {
    Write-Host "PFS Conductors CSV           : $PfsCsvFile"
}
else {
    Write-Host "PFS Conductors CSV           : (none - no PFS APs acting as Conductor)"
}
Write-Host "=====================================================" -ForegroundColor Green
Write-Host ""
