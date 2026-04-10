# Define paths
$csvPath   = "IPs.csv"          # Input CSV file
$outputCsv = "PingResults.csv"  # Output CSV file

# Import the CSV file (assuming the column header is 'IP')
$ipList = Import-Csv -Path $csvPath

# Create an array to hold results
$results = @()

# Counter for progress
$total = $ipList.Count
$current = 0

foreach ($entry in $ipList) {
    $current++
    $ip = $entry.IP

    # Show progress bar
    Write-Progress -Activity "Pinging devices..." -Status "Checking $ip" -PercentComplete (($current / $total) * 100)

    $pingResult = Test-Connection -ComputerName $ip -Count 1 -Quiet

    if ($pingResult) {
        $status = "REACHABLE"
    } else {
        $status = "NOT REACHABLE"
    }

    # Add result to array with timestamp
    $results += [PSCustomObject]@{
        IP        = $ip
        Status    = $status
        Timestamp = (Get-Date)
    }
}

# Export results to CSV
$results | Export-Csv -Path $outputCsv -NoTypeInformation

Write-Output "Ping results saved to $outputCsv"

# Open the output file automatically
Invoke-Item $outputCsv
