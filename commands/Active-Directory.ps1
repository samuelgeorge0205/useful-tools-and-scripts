

#To Add

Add-DnsServerResourceRecordA -ZoneName "foo.com" `
-Name "foo.proxy" `
-IPv4Address "a.b.c.d" `
-TimeToLive 00:05:00 `
-ComputerName "foo"

# Get RR

Get-DnsServerResourceRecord -ZoneName "foo.com" -Name "foo.proxy" -ComputerName "foo"

#

Get-DnsServerResourceRecord -ZoneName "foo.com" -Name "foo.proxy" -RRType A -ComputerName "foo" |
Where-Object {$_.RecordData.IPv4Address -eq "a.b.c.d"} |
Remove-DnsServerResourceRecord -ZoneName "foo.com" -ComputerName "foo" -Force

# GEN DNS RECORD DETAILS

Get-DnsServerResourceRecord -ZoneName "foo.net" -ComputerName "foo.NET" | ? {$_.HostName -like "foo*"} | fl *

Get-DnsServerResourceRecord -ZoneName "foo.com" -ComputerName "foo" | Where-Object {$_.HostName -like "foo.proxy*"}

#

Get-DnsServerZone -ComputerName "foo" | ForEach-Object {
>>     $zone = $_.ZoneName
>>     Get-DnsServerResourceRecord -ZoneName $zone -RRType A -ComputerName "foo" -ErrorAction SilentlyContinue |
>>     Select-Object @{Name="ZoneName";Expression={$zone}}, HostName, RecordType, TimeToLive, RecordData
>> } | Where-Object {
>>     $_.HostName -like "*default*" -or $_.RecordData.IPv4Address -in ("a.b.c.d","e.f.g.h")
>> }


#

Get-DnsServerZone -ComputerName "foo" | ForEach-Object {
>>     Get-DnsServerResourceRecord -ZoneName $_.ZoneName -RRType A -ComputerName "foo" -ErrorAction SilentlyContinue
>> } | Where-Object {
>>     $_.HostName -like "*default*" -or $_.RecordData.IPv4Address -in ("a.b.c.d","e.f.g.h")
>> }




