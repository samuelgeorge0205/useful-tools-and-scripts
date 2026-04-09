Add-Type -AssemblyName System.Windows.Forms
while ($true) {
    $pos = [System.Windows.Forms.Cursor]::Position
    Write-Host "X=$($pos.X) Y=$($pos.Y)"
    Start-Sleep -Milliseconds 500
}
