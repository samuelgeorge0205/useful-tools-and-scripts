# Define paths
$csvPath   = "IPs.csv"          # Input CSV file
$outputCsv = "PingResults.csv"  # Output CSV file

# Import the CSV file (assuming one column is 'IP Address')
$ipList = Import-Csv -Path $csvPath

# Counter for progress
$total   = $ipList.Count
$current = 0

# Create an array to hold results
$results = @()

foreach ($entry in $ipList) {
    $current++
    $ip = $entry.'IP Address'

    # Show progress bar
    Write-Progress -Activity "Pinging devices..." -Status "Checking $ip" -PercentComplete (($current / $total) * 100)

    $pingResult = Test-Connection -ComputerName $ip -Count 1 -Quiet

    if ($pingResult) {
        $status = "REACHABLE"
    } else {
        $status = "NOT REACHABLE"
    }

    # Clone the original row and add PingStatus
    $newEntry = $entry | Select-Object *
    $newEntry | Add-Member -NotePropertyName PingStatus -NotePropertyValue $status

    # Add to results
    $results += $newEntry
}

# Export results to CSV
$results | Export-Csv -Path $outputCsv -NoTypeInformation

Write-Output "Ping results saved to $outputCsv"

# Open the output file automatically
Invoke-Item $outputCsv
