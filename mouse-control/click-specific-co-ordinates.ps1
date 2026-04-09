Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Mouse {
    [DllImport("user32.dll")]
    public static extern bool SetCursorPos(int X, int Y);

    [DllImport("user32.dll")]
    public static extern void mouse_event(int dwFlags, int dx, int dy, int cButtons, int dwExtraInfo);

    public const int LEFTDOWN = 0x02;
    public const int LEFTUP   = 0x04;
}
"@

# === CONFIGURATION ===
$X = 1342         # Base X coordinate
$Y = 663           # Y coordinate
$ClickGap = 1      # Seconds between the two clicks
$WaitPeriod = 15   # Seconds to wait after both clicks

Write-Host "Starting double-click loop. Press Ctrl+C to stop."

while ($true) {

    # First click at (X, Y)
    [Mouse]::SetCursorPos($X, $Y)
    Start-Sleep -Milliseconds 100
    [Mouse]::mouse_event([Mouse]::LEFTDOWN, 0, 0, 0, 0)
    Start-Sleep -Milliseconds 50
    [Mouse]::mouse_event([Mouse]::LEFTUP, 0, 0, 0, 0)

    # Wait 1 second
    Start-Sleep -Seconds $ClickGap

    # Second click at (X - 2, Y)
    [Mouse]::SetCursorPos($X - 2, $Y)
    Start-Sleep -Milliseconds 100
    [Mouse]::mouse_event([Mouse]::LEFTDOWN, 0, 0, 0, 0)
    Start-Sleep -Milliseconds 50
    [Mouse]::mouse_event([Mouse]::LEFTUP, 0, 0, 0, 0)

    # Wait full cycle period
    Start-Sleep -Seconds $WaitPeriod
}
