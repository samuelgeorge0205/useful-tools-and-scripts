#Requires -Version 5.1
<#
.SYNOPSIS
    Legacy MPLS Zone-Based Firewall (ZBFW) Analyzer
.DESCRIPTION
    Parses Cisco IOS "show running-config" and simulates ZBFW packet-flow logic:
    Interface -> Zone -> Zone-Pair -> Policy-Map -> Class-Map -> ACL
    Supports extended ACLs with any/host/subnet, eq/range/gt/lt/neq ports.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ======================================================================
# SCRIPT-SCOPE STATE
# ======================================================================
$script:Interfaces   = [ordered]@{}   # ifName  -> { Name, IP, Mask, SecondaryIPs[], VRF, Zone }
$script:Zones        = [System.Collections.ArrayList]@()
$script:ZonePairs    = @{}            # zpName  -> { Name, SourceZone, DestZone, PolicyMap }
$script:PolicyMaps   = @{}            # pmName  -> { Name, Classes[] }
$script:ClassMaps    = @{}            # cmName  -> { Name, MatchType, Matches[] }
$script:AccessLists  = @{}            # aclName -> { Name, Rules[] }
$script:ConfigLoaded = $false
$script:VRFs         = [System.Collections.ArrayList]@()   # discovered VRF names
$script:TopologyDB   = @{}            # "SrcZone|DstZone" -> pre-resolved topology entry
$script:KnownVLANZones = @('VLAN202','VLAN203','VLAN204','VLAN205','VLAN206','VLAN207','VLAN208','VLAN300','VLAN511')
$script:VLANPolicyDB   = @{}          # VLANZone -> { PolicyMap, ClassMaps[], PrimaryACL, AllACLs[] }

# ======================================================================
# SAFE LOOKUP HELPER
# ======================================================================
function Test-KeyExists {
    param($Collection, [string]$Key)
    if ($Collection -is [hashtable])                                         { return $Collection.ContainsKey($Key) }
    if ($Collection -is [System.Collections.Specialized.OrderedDictionary])   { return $Collection.Contains($Key) }
    return $false
}

# ======================================================================
# IP / SUBNET UTILITIES
# ======================================================================

function ConvertTo-IPInt {
    param([string]$IP)
    $o = $IP.Trim().Split('.')
    return [long]([long]$o[0] * 16777216 + [long]$o[1] * 65536 + [long]$o[2] * 256 + [long]$o[3])
}

function Convert-MaskToWildcard {
    param([string]$Mask)
    $parts = $Mask.Trim().Split('.') | ForEach-Object { 255 - [int]$_ }
    return ($parts -join '.')
}

function Test-IPMatchWildcard {
    param([string]$TestIP, [string]$NetworkIP, [string]$WildcardMask)
    [long]$ipInt   = ConvertTo-IPInt $TestIP
    [long]$netInt  = ConvertTo-IPInt $NetworkIP
    [long]$wildInt = ConvertTo-IPInt $WildcardMask
    [long]$maskInt = ([long]4294967295) -bxor $wildInt
    return (($ipInt -band $maskInt) -eq ($netInt -band $maskInt))
}

$script:KnownPorts = @{
    'ftp-data'=20; 'ftp'=21; 'ssh'=22; 'telnet'=23; 'smtp'=25;
    'domain'=53;   'dns'=53;  'www'=80; 'http'=80;   'pop3'=110;
    'nntp'=119;    'ntp'=123; 'imap'=143; 'snmp'=161; 'bgp'=179;
    'ldap'=389;    'https'=443; 'smb'=445; 'sip'=5060; 'rdp'=3389;
    'tacacs'=49;   'isakmp'=500; 'non500-isakmp'=4500; 'radius'=1812;
    'kerberos'=88; 'msrpc'=135; 'netbios-ssn'=139; 'sqlnet'=1521
}

$script:NBARProtocols = @{
    'dns'           = @{ Protos=@('udp','tcp'); Ports=@(53)          }
    'msrpc'         = @{ Protos=@('tcp');       Ports=@(135)         }
    'sqlsrv'        = @{ Protos=@('tcp');       Ports=@(1433)        }
    'sqlserv'       = @{ Protos=@('tcp');       Ports=@(1433)        }
    'sql-net'       = @{ Protos=@('tcp');       Ports=@(1521)        }
    'microsoft-ds'  = @{ Protos=@('tcp');       Ports=@(445)         }
    'netbios-ssn'   = @{ Protos=@('tcp');       Ports=@(139)         }
    'netbios-dgm'   = @{ Protos=@('udp');       Ports=@(138)         }
    'rtelnet'       = @{ Protos=@('tcp');       Ports=@(23)          }
    'ftp'           = @{ Protos=@('tcp');       Ports=@(21,20)       }
    'smtp'          = @{ Protos=@('tcp');       Ports=@(25)          }
    'snmp'          = @{ Protos=@('udp');       Ports=@(161,162)     }
    'ntp'           = @{ Protos=@('udp');       Ports=@(123)         }
    'tftp'          = @{ Protos=@('udp');       Ports=@(69)          }
    'bgp'           = @{ Protos=@('tcp');       Ports=@(179)         }
    'ldap'          = @{ Protos=@('tcp');       Ports=@(389)         }
    'rdp'           = @{ Protos=@('tcp');       Ports=@(3389)        }
    'sip'           = @{ Protos=@('tcp','udp'); Ports=@(5060,5061)   }
    'isakmp'        = @{ Protos=@('udp');       Ports=@(500)         }
    'non500-isakmp' = @{ Protos=@('udp');       Ports=@(4500)        }
    'icmp'          = @{ Protos=@('icmp');      Ports=@()            }
    'tcp'           = @{ Protos=@('tcp');       Ports=@()            }
    'udp'           = @{ Protos=@('udp');       Ports=@()            }
    'ip'            = @{ Protos=@('ip');        Ports=@()            }
    'http'          = @{ Protos=@('tcp');       Ports=@(80)          }
    'https'         = @{ Protos=@('tcp');       Ports=@(443)         }
    'ssh'           = @{ Protos=@('tcp');       Ports=@(22)          }
    'telnet'        = @{ Protos=@('tcp');       Ports=@(23)          }
}

function Test-NBARProtocolMatch {
    param([string]$NBARName, [string]$Proto, [int]$DstPort)
    $key = $NBARName.ToLower()
    $p   = $Proto.ToLower()
    if ($key -eq $p) { return $true }
    if (-not $script:NBARProtocols.ContainsKey($key)) { return $false }
    $entry = $script:NBARProtocols[$key]
    if ($entry.Protos -notcontains $p) { return $false }
    if ($entry.Ports.Count -eq 0) { return $true }
    if ($DstPort -eq 0) { return $true }
    return ($entry.Ports -contains $DstPort)
}

function Resolve-PortName {
    param([string]$Token)
    if ($Token -match '^\d+$')   { return [int]$Token }
    $lower = $Token.ToLower()
    if ($script:KnownPorts.ContainsKey($lower)) { return $script:KnownPorts[$lower] }
    return -1
}

function Test-PortMatch {
    param([int]$TestPort, $Spec)
    if ($null -eq $Spec) { return $true }
    switch ($Spec.Type) {
        'any'   { return $true }
        'eq'    { return ($TestPort -eq $Spec.Port) }
        'multi' { return ($Spec.Ports -contains $TestPort) }
        'range' { return ($TestPort -ge $Spec.Start -and $TestPort -le $Spec.End) }
        'gt'    { return ($TestPort -gt $Spec.Port) }
        'lt'    { return ($TestPort -lt $Spec.Port) }
        'neq'   { return ($TestPort -ne $Spec.Port) }
    }
    return $false
}

# ======================================================================
# CONFIGURATION PARSER
# ======================================================================

function Parse-CiscoConfig {
    param([string]$ConfigText)

    $script:Interfaces  = [ordered]@{}
    $script:Zones       = [System.Collections.ArrayList]@()
    $script:ZonePairs   = @{}
    $script:PolicyMaps  = @{}
    $script:ClassMaps   = @{}
    $script:AccessLists = @{}
    $script:VRFs        = [System.Collections.ArrayList]@()
    $script:TopologyDB  = @{}

    $lines = $ConfigText -split "\r?\n"
    $n     = $lines.Count
    $i     = 0

    while ($i -lt $n) {
        $raw  = $lines[$i]
        $line = $raw.TrimStart()

        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('!')) { $i++; continue }

        if ($line -match '^interface\s+(\S+)') {
            $ifName = $Matches[1]
            $iface  = [ordered]@{ Name=$ifName; IP=$null; Mask=$null; SecondaryIPs=[System.Collections.ArrayList]@(); VRF='DEFAULT'; Zone=$null; ACLIn=$null; ACLOut=$null }
            $i++
            while ($i -lt $n -and $lines[$i] -match '^[ \t]') {
                $s = $lines[$i].Trim()
                if ($s -match '^ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+secondary') {
                    [void]$iface.SecondaryIPs.Add([ordered]@{ IP=$Matches[1]; Mask=$Matches[2] })
                }
                elseif ($s -match '^ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)') {
                    $iface.IP   = $Matches[1]
                    $iface.Mask = $Matches[2]
                }
                elseif ($s -match '^vrf forwarding\s+(\S+)') {
                    $vrf = $Matches[1]
                    $iface.VRF = $vrf
                    if (-not $script:VRFs.Contains($vrf)) { [void]$script:VRFs.Add($vrf) }
                }
                elseif ($s -match '^zone-member security\s+(\S+)') {
                    $iface.Zone = $Matches[1]
                }
                elseif ($s -match '^ip access-group\s+(\S+)\s+(in|out)\b') {
                    if ($Matches[2] -eq 'in')  { $iface.ACLIn  = $Matches[1] }
                    else                        { $iface.ACLOut = $Matches[1] }
                }
                $i++
            }
            $script:Interfaces[$ifName] = $iface
            continue
        }

        if ($line -match '^zone security\s+(\S+)') {
            $zName = $Matches[1]
            if (-not $script:Zones.Contains($zName)) { [void]$script:Zones.Add($zName) }
            $i++; continue
        }

        if ($line -match '^zone-pair security\s+(\S+)') {
            $zpName = $Matches[1]
            $zp     = [ordered]@{ Name=$zpName; SourceZone=$null; DestZone=$null; PolicyMap=$null; PolicyMapInferred=$false }
            if ($line -match '^zone-pair security\s+\S+\s+source\s+(\S+)\s+destination\s+(\S+)') {
                $zp.SourceZone = $Matches[1]
                $zp.DestZone   = $Matches[2]
            }
            $i++
            $zpTermRx = '^(zone-pair\s|zone\s+security|policy-map\s|class-map\s|interface\s|ip\s+access-list|ip\s+route|router\s|crypto\s|end\b)'
            while ($i -lt $n) {
                $subRaw  = $lines[$i]
                $subLine = $subRaw.Trim()
                if ([string]::IsNullOrWhiteSpace($subLine) -or $subLine.StartsWith('!')) { $i++; continue }
                if ($subLine -match $zpTermRx)                                            { break }
                if      ($subLine -match '^source\s+(\S+)')                              { $zp.SourceZone = $Matches[1] }
                elseif  ($subLine -match '^destination\s+(\S+)')                         { $zp.DestZone   = $Matches[1] }
                elseif  ($subLine -match '^service-policy\s+type\s+inspect\s+(\S+)')    { $zp.PolicyMap  = $Matches[1] }
                elseif  ($subLine -match '^service-policy\s+inspect\s+(\S+)')           { $zp.PolicyMap  = $Matches[1] }
                $i++
            }
            $script:ZonePairs[$zpName] = $zp
            continue
        }

        if ($line -match '^policy-map type inspect\s+(\S+)') {
            $pmName = $Matches[1]
            $pm     = [ordered]@{ Name=$pmName; Classes=[System.Collections.ArrayList]@() }
            $curCls = $null
            $i++
            while ($i -lt $n -and $lines[$i] -match '^[ \t]') {
                $s = $lines[$i].Trim()
                if ($s -match '^class(?:\s+type\s+inspect)?\s+(\S+)') {
                    $curCls = [ordered]@{ ClassName=$Matches[1]; Action=$null; InspectParam=$null }
                    [void]$pm.Classes.Add($curCls)
                }
                elseif ($s -match '^(inspect|pass|drop)(?:\s+(\S+))?' -and $null -ne $curCls) {
                    $curCls.Action = $Matches[1]
                    if ($Matches[2]) { $curCls.InspectParam = $Matches[2] }
                }
                $i++
            }
            $script:PolicyMaps[$pmName] = $pm
            continue
        }

        if ($line -match '^class-map type inspect\s+(?:(match-all|match-any)\s+)?(\S+)') {
            $mType  = if ($Matches[1]) { $Matches[1] } else { 'match-all' }
            $cmName = $Matches[2]
            $cm     = [ordered]@{ Name=$cmName; MatchType=$mType; Matches=[System.Collections.ArrayList]@() }
            $i++
            while ($i -lt $n -and $lines[$i] -match '^[ \t]') {
                $s = $lines[$i].Trim()
                if      ($s -match '^match access-group name\s+(\S+)') { [void]$cm.Matches.Add([ordered]@{ Type='acl';      Value=$Matches[1] }) }
                elseif  ($s -match '^match access-group\s+(\d+)')      { [void]$cm.Matches.Add([ordered]@{ Type='acl-num';  Value=$Matches[1] }) }
                elseif  ($s -match '^match protocol\s+(\S+)')          { [void]$cm.Matches.Add([ordered]@{ Type='protocol'; Value=$Matches[1] }) }
                elseif  ($s -match '^match class-map\s+(\S+)')         { [void]$cm.Matches.Add([ordered]@{ Type='classmap'; Value=$Matches[1] }) }
                $i++
            }
            $script:ClassMaps[$cmName] = $cm
            continue
        }

        if ($line -match '^ip access-list extended\s+(\S+)') {
            $aclName = $Matches[1]
            $acl     = [ordered]@{ Name=$aclName; Rules=[System.Collections.ArrayList]@() }
            $i++
            while ($i -lt $n -and $lines[$i] -match '^[ \t]') {
                $s = $lines[$i].Trim()
                $r = ConvertTo-ACLRule $s
                if ($null -ne $r) { [void]$acl.Rules.Add($r) }
                $i++
            }
            $script:AccessLists[$aclName] = $acl
            continue
        }

        $i++
    }

    foreach ($zpName in @($script:ZonePairs.Keys)) {
        $zp = $script:ZonePairs[$zpName]
        if ($zp.PolicyMap)                              { continue }
        if (-not $zp.SourceZone -or -not $zp.DestZone) { continue }

        $src = $zp.SourceZone; $dst = $zp.DestZone
        $candidates = @(
            "PM_${src}-2-${dst}",
            "PM-${src}-2-${dst}",
            "PM_${src}_to_${dst}",
            "PM-${src}-to-${dst}",
            "PMAP_${src}_${dst}"
        )
        $found = $null
        foreach ($cand in $candidates) {
            $hit = $script:PolicyMaps.Keys | Where-Object { $_ -ieq $cand } | Select-Object -First 1
            if ($hit) { $found = $hit; break }
        }
        if (-not $found) {
            $found = $script:PolicyMaps.Keys |
                Where-Object { $_ -imatch [regex]::Escape($src) -and $_ -imatch [regex]::Escape($dst) } |
                Select-Object -First 1
        }
        if ($found) {
            $zp.PolicyMap         = $found
            $zp.PolicyMapInferred = $true
        }
    }

    Build-TopologyDB
    Build-VLANPolicyDB
}

function ConvertTo-ACLRule {
    param([string]$Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
    $Line = ($Line -replace '^\d+\s+', '').Trim()
    if ($Line -match '^remark\b') { return $null }
    if (-not ($Line -match '^(permit|deny)\s+(\S+)\s+(.+)$')) { return $null }

    $action   = $Matches[1]
    $protocol = $Matches[2].ToLower()
    $rest     = $Matches[3].Trim()

    $rule = [ordered]@{
        Raw      = $Line
        Action   = $action
        Protocol = $protocol
        SrcType  = $null; SrcIP = $null; SrcWild = $null; SrcPort = $null
        DstType  = $null; DstIP = $null; DstWild = $null; DstPort = $null
    }

    $addr = Get-ACLAddressPart $rest
    if ($null -eq $addr) { return $null }
    $rule.SrcType = $addr.Type; $rule.SrcIP = $addr.IP; $rule.SrcWild = $addr.Wild
    $rest = $addr.Remaining

    $portR = Get-ACLPortSpec $rest
    if ($portR.Spec) { $rule.SrcPort = $portR.Spec; $rest = $portR.Remaining }

    $addr = Get-ACLAddressPart $rest
    if ($null -eq $addr) { return $null }
    $rule.DstType = $addr.Type; $rule.DstIP = $addr.IP; $rule.DstWild = $addr.Wild
    $rest = $addr.Remaining

    $portR = Get-ACLPortSpec $rest
    if ($portR.Spec) { $rule.DstPort = $portR.Spec }

    return $rule
}

function Get-ACLAddressPart {
    param([string]$Text)
    $Text = $Text.Trim()
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    if ($Text -match '^any\b(.*)') {
        return @{ Type='any'; IP='0.0.0.0'; Wild='255.255.255.255'; Remaining=$Matches[1].Trim() }
    }
    if ($Text -match '^host\s+(\d+\.\d+\.\d+\.\d+)\s*(.*)') {
        return @{ Type='host'; IP=$Matches[1]; Wild='0.0.0.0'; Remaining=$Matches[2].Trim() }
    }
    if ($Text -match '^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s*(.*)') {
        return @{ Type='subnet'; IP=$Matches[1]; Wild=$Matches[2]; Remaining=$Matches[3].Trim() }
    }
    return $null
}

function Get-ACLPortSpec {
    param([string]$Text)
    $Text   = $Text.Trim()
    $result = @{ Spec=$null; Remaining=$Text }
    if ([string]::IsNullOrEmpty($Text)) { return $result }

    if ($Text -match '^range\s+(\S+)\s+(\S+)\s*(.*)') {
        $result.Spec      = @{ Type='range'; Start=(Resolve-PortName $Matches[1]); End=(Resolve-PortName $Matches[2]) }
        $result.Remaining = $Matches[3].Trim()
    }
    elseif ($Text -match '^eq\s+(.+)') {
        $portTokens = [System.Collections.ArrayList]@()
        $tokens     = ($Matches[1].Trim() -split '\s+')
        $consumed   = 0
        foreach ($tok in $tokens) {
            if ($tok -match '^\d{1,3}\.\d{1,3}' -or
                $tok -in @('any','host','log','established','fragments','time-range','dscp','precedence','tos','ttl')) { break }
            $p = Resolve-PortName $tok
            if ($p -lt 0) { break }
            [void]$portTokens.Add($p)
            $consumed++
        }
        if ($portTokens.Count -eq 1) {
            $result.Spec = @{ Type='eq'; Port=$portTokens[0] }
        } elseif ($portTokens.Count -gt 1) {
            $result.Spec = @{ Type='multi'; Ports=$portTokens.ToArray() }
        }
        $result.Remaining = if ($consumed -lt $tokens.Count) {
            ($tokens | Select-Object -Skip $consumed) -join ' '
        } else { '' }
    }
    elseif ($Text -match '^gt\s+(\S+)\s*(.*)') {
        $result.Spec      = @{ Type='gt'; Port=(Resolve-PortName $Matches[1]) }
        $result.Remaining = $Matches[2].Trim()
    }
    elseif ($Text -match '^lt\s+(\S+)\s*(.*)') {
        $result.Spec      = @{ Type='lt'; Port=(Resolve-PortName $Matches[1]) }
        $result.Remaining = $Matches[2].Trim()
    }
    elseif ($Text -match '^neq\s+(\S+)\s*(.*)') {
        $result.Spec      = @{ Type='neq'; Port=(Resolve-PortName $Matches[1]) }
        $result.Remaining = $Matches[2].Trim()
    }
    return $result
}

# ======================================================================
# ANALYSIS ENGINE
# ======================================================================

function Find-InterfaceAndMatchForIP {
    param([string]$IP)
    foreach ($ifName in $script:Interfaces.Keys) {
        $iface = $script:Interfaces[$ifName]
        if ($iface.IP -and $iface.Mask) {
            $wild = Convert-MaskToWildcard $iface.Mask
            if (Test-IPMatchWildcard $IP $iface.IP $wild) {
                return @{ Interface=$iface; MatchedIP=$iface.IP; MatchedMask=$iface.Mask; IsPrimary=$true }
            }
        }
        foreach ($sec in $iface.SecondaryIPs) {
            $wild = Convert-MaskToWildcard $sec.Mask
            if (Test-IPMatchWildcard $IP $sec.IP $wild) {
                return @{ Interface=$iface; MatchedIP=$sec.IP; MatchedMask=$sec.Mask; IsPrimary=$false }
            }
        }
    }
    return $null
}

function Find-InterfaceForIP {
    param([string]$IP)
    $r = Find-InterfaceAndMatchForIP $IP
    if ($r) { return $r.Interface }
    return $null
}

function Build-TopologyDB {
    $script:TopologyDB = @{}
    foreach ($zpName in $script:ZonePairs.Keys) {
        $zp = $script:ZonePairs[$zpName]
        if (-not $zp.SourceZone -or -not $zp.DestZone) { continue }
        $key   = "$($zp.SourceZone)|$($zp.DestZone)"
        $entry = [ordered]@{
            ZonePairName = $zpName
            PolicyMap    = $zp.PolicyMap
            Classes      = [System.Collections.ArrayList]@()
        }
        if ($zp.PolicyMap -and (Test-KeyExists $script:PolicyMaps $zp.PolicyMap)) {
            foreach ($cls in $script:PolicyMaps[$zp.PolicyMap].Classes) {
                $cEntry = [ordered]@{
                    ClassName    = $cls.ClassName
                    Action       = $cls.Action
                    InspectParam = $cls.InspectParam
                    ACLs         = [System.Collections.ArrayList]@()
                }
                if ($cls.ClassName -ne 'class-default') {
                    foreach ($a in (Get-ACLsFromClassMap $cls.ClassName)) {
                        [void]$cEntry.ACLs.Add($a)
                    }
                }
                [void]$entry.Classes.Add($cEntry)
            }
        }
        $script:TopologyDB[$key] = $entry
    }
}

function Build-VLANPolicyDB {
    $script:VLANPolicyDB = @{}
    foreach ($vlanZone in $script:KnownVLANZones) {
        $vlanNum    = $vlanZone -replace '^VLAN', ''
        $primaryACL = $null
        $allACLs    = [System.Collections.ArrayList]@()
        $directCMs  = [System.Collections.ArrayList]@()
        $sourceDesc = $null

        foreach ($ifName in $script:Interfaces.Keys) {
            $iface = $script:Interfaces[$ifName]
            if ($iface.Zone -ieq $vlanZone -and $iface.ACLIn) {
                $primaryACL = $iface.ACLIn
                $sourceDesc = "ip access-group on $ifName"
                if (-not $allACLs.Contains($iface.ACLIn)) { [void]$allACLs.Add($iface.ACLIn) }
                break
            }
        }

        if (-not $primaryACL) {
            foreach ($cmKey in $script:ClassMaps.Keys) {
                if ($cmKey -match $vlanNum) {
                    if (-not $directCMs.Contains($cmKey)) { [void]$directCMs.Add($cmKey) }
                    foreach ($m in $script:ClassMaps[$cmKey].Matches) {
                        if ($m.Type -eq 'acl' -and -not $allACLs.Contains($m.Value)) {
                            [void]$allACLs.Add($m.Value)
                        }
                    }
                }
            }
            if ($allACLs.Count -gt 0) {
                $primaryACL = $allACLs[0]
                $sourceDesc = "class-map reference"
            }
        }

        if (-not $primaryACL) { continue }

        $script:VLANPolicyDB[$vlanZone] = [ordered]@{
            VLANZone    = $vlanZone
            ClassMaps   = $directCMs
            PrimaryACL  = $primaryACL
            AllACLs     = $allACLs
            SourceDesc  = $sourceDesc
        }
    }
}

function Find-ZonePair {
    param([string]$SrcZone, [string]$DstZone)
    $key = "$SrcZone|$DstZone"
    if (Test-KeyExists $script:TopologyDB $key) {
        $zpName = $script:TopologyDB[$key].ZonePairName
        if (Test-KeyExists $script:ZonePairs $zpName) { return $script:ZonePairs[$zpName] }
    }
    foreach ($k in $script:TopologyDB.Keys) {
        $parts = $k -split '\|', 2
        if ($parts[0] -ieq $SrcZone -and $parts[1] -ieq $DstZone) {
            $zpName = $script:TopologyDB[$k].ZonePairName
            if (Test-KeyExists $script:ZonePairs $zpName) { return $script:ZonePairs[$zpName] }
        }
    }
    foreach ($name in $script:ZonePairs.Keys) {
        $zp = $script:ZonePairs[$name]
        if ($zp.SourceZone -ieq $SrcZone -and $zp.DestZone -ieq $DstZone) { return $zp }
    }
    return $null
}

function Find-OutsideZone {
    foreach ($z in $script:Zones) { if ($z -ieq 'Outside')  { return $z } }
    foreach ($z in $script:Zones) { if ($z -imatch 'outside|wan|internet|external|egress|untrust') { return $z } }
    return $null
}

function Get-ACLsFromClassMap {
    param([string]$CMName, [System.Collections.ArrayList]$Visited = $null)
    if ($null -eq $Visited) { $Visited = [System.Collections.ArrayList]@() }
    if ($Visited.Contains($CMName)) { return [System.Collections.ArrayList]@() }
    [void]$Visited.Add($CMName)
    $acls = [System.Collections.ArrayList]@()
    if (-not (Test-KeyExists $script:ClassMaps $CMName)) { return $acls }
    foreach ($m in $script:ClassMaps[$CMName].Matches) {
        if ($m.Type -eq 'acl' -and -not $acls.Contains($m.Value)) {
            [void]$acls.Add($m.Value)
        } elseif ($m.Type -eq 'classmap') {
            foreach ($a in (Get-ACLsFromClassMap $m.Value $Visited)) {
                if (-not $acls.Contains($a)) { [void]$acls.Add($a) }
            }
        }
    }
    return $acls
}

function Get-ACLRuleMatchDetail {
    param($Rule, [string]$SrcIP, [string]$DstIP, [string]$Proto, [int]$DstPort, [int]$SrcPort = 0)

    $detail = [ordered]@{
        Matched       = $false
        SrcMatch      = $false
        DstMatch      = $false
        ProtoMatch    = $false
        PortMatch     = $false
        SkipReason    = $null
    }

    if ($Rule.Protocol -eq 'ip') {
        $detail.ProtoMatch = $true
    } else {
        $detail.ProtoMatch = ($Rule.Protocol -eq $Proto.ToLower())
    }

    switch ($Rule.SrcType) {
        'any'    { $detail.SrcMatch = $true }
        'host'   { $detail.SrcMatch = ($SrcIP -eq $Rule.SrcIP) }
        'subnet' { $detail.SrcMatch = (Test-IPMatchWildcard $SrcIP $Rule.SrcIP $Rule.SrcWild) }
        default  { $detail.SrcMatch = $false }
    }

    switch ($Rule.DstType) {
        'any'    { $detail.DstMatch = $true }
        'host'   { $detail.DstMatch = ($DstIP -eq $Rule.DstIP) }
        'subnet' { $detail.DstMatch = (Test-IPMatchWildcard $DstIP $Rule.DstIP $Rule.DstWild) }
        default  { $detail.DstMatch = $false }
    }

    $srcPortOK = $true
    $dstPortOK = $true
    $srcPortSkipReason = $null
    $dstPortSkipReason = $null

    if ($Proto -in @('tcp','udp')) {
        if ($null -ne $Rule.SrcPort) {
            if ($SrcPort -eq 0) {
                $srcPortOK = $false
                $srcPortSkipReason = "ACE has source-port constraint ($(Format-PortSpec $Rule.SrcPort)) but source port was not provided"
            } else {
                $srcPortOK = (Test-PortMatch $SrcPort $Rule.SrcPort)
                if (-not $srcPortOK) {
                    $srcPortSkipReason = "Source port $SrcPort does not match ACE source-port constraint ($(Format-PortSpec $Rule.SrcPort))"
                }
            }
        }
        if ($null -ne $Rule.DstPort) {
            $dstPortOK = (Test-PortMatch $DstPort $Rule.DstPort)
            if (-not $dstPortOK) {
                $dstPortSkipReason = "Destination port $DstPort does not match ACE destination-port constraint ($(Format-PortSpec $Rule.DstPort))"
            }
        }
    }
    $detail.PortMatch = $srcPortOK -and $dstPortOK
    $detail.Matched = $detail.SrcMatch -and $detail.DstMatch -and $detail.ProtoMatch -and $detail.PortMatch

    if (-not $detail.Matched) {
        if (-not $detail.ProtoMatch) {
            $detail.SkipReason = "Protocol '$($Proto.ToLower())' does not match ACL protocol '$($Rule.Protocol)'"
        } elseif (-not $detail.SrcMatch) {
            $srcDesc = switch ($Rule.SrcType) {
                'host'   { "host $($Rule.SrcIP)" }
                'subnet' { "$($Rule.SrcIP) $($Rule.SrcWild)" }
                default  { $Rule.SrcType }
            }
            $detail.SkipReason = "Source IP $SrcIP not within $srcDesc"
        } elseif (-not $detail.DstMatch) {
            $dstDesc = switch ($Rule.DstType) {
                'host'   { "host $($Rule.DstIP)" }
                'subnet' { "$($Rule.DstIP) $($Rule.DstWild)" }
                default  { $Rule.DstType }
            }
            $detail.SkipReason = "Destination IP $DstIP not within $dstDesc"
        } elseif (-not $detail.PortMatch) {
            $detail.SkipReason = if ($srcPortSkipReason) { $srcPortSkipReason } else { $dstPortSkipReason }
        }
    }

    return $detail
}

function Format-PortSpec {
    param($Spec)
    if ($null -eq $Spec) { return 'any' }
    switch ($Spec.Type) {
        'eq'    { return "eq $($Spec.Port)" }
        'multi' { return "eq $($Spec.Ports -join ',')" }
        'range' { return "range $($Spec.Start)-$($Spec.End)" }
        'gt'    { return "gt $($Spec.Port)" }
        'lt'    { return "lt $($Spec.Port)" }
        'neq'   { return "neq $($Spec.Port)" }
        'any'   { return 'any' }
        default { return $Spec.Type }
    }
}

function Test-ACLRuleMatch {
    param($Rule, [string]$SrcIP, [string]$DstIP, [string]$Proto, [int]$DstPort, [int]$SrcPort = 0)
    return (Get-ACLRuleMatchDetail $Rule $SrcIP $DstIP $Proto $DstPort $SrcPort).Matched
}

function Invoke-ACLEvaluation {
    param([string]$ACLName, [string]$SrcIP, [string]$DstIP, [string]$Proto, [int]$DstPort, [int]$SrcPort = 0)
    $emptyRules = [System.Collections.ArrayList]@()
    if (-not (Test-KeyExists $script:AccessLists $ACLName)) {
        return @{ Found=$false; Hit=$false; Action='acl-not-found'; Rule=$null; RuleResults=$emptyRules }
    }
    $ruleResults = [System.Collections.ArrayList]@()
    $seqNum      = 0
    foreach ($rule in $script:AccessLists[$ACLName].Rules) {
        $seqNum++
        $detail = Get-ACLRuleMatchDetail $rule $SrcIP $DstIP $Proto $DstPort $SrcPort
        [void]$ruleResults.Add([ordered]@{
            Seq        = $seqNum
            Raw        = $rule.Raw
            Matched    = $detail.Matched
            Action     = $rule.Action
            SrcMatch   = $detail.SrcMatch
            DstMatch   = $detail.DstMatch
            ProtoMatch = $detail.ProtoMatch
            PortMatch  = $detail.PortMatch
            SkipReason = $detail.SkipReason
        })
        if ($detail.Matched) {
            return @{ Found=$true; Hit=$true; Action=$rule.Action; Rule=$rule.Raw; RuleResults=$ruleResults }
        }
    }
    return @{ Found=$true; Hit=$false; Action='implicit-deny'; Rule=$null; RuleResults=$ruleResults }
}

function Invoke-ClassMapEvaluation {
    param([string]$CMName, [string]$SrcIP, [string]$DstIP, [string]$Proto, [int]$DstPort, [int]$Depth = 0)
    $res = [ordered]@{
        Name          = $CMName
        Found         = $false
        MatchType     = $null
        Match         = $false
        CheckResults  = [System.Collections.ArrayList]@()
        Depth         = $Depth
        ProtocolMatch = $null
        ACLMatch      = $null
        ACLName       = $null
        MatchedRule   = $null
    }
    if (-not (Test-KeyExists $script:ClassMaps $CMName)) { return $res }
    $cm = $script:ClassMaps[$CMName]
    $res.Found     = $true
    $res.MatchType = $cm.MatchType
    $checks        = [System.Collections.ArrayList]@()
    foreach ($m in $cm.Matches) {
        switch ($m.Type) {
            'protocol' {
                $ok = Test-NBARProtocolMatch $m.Value $Proto $DstPort
                if ($null -eq $res.ProtocolMatch) { $res.ProtocolMatch = $ok }
                $check = [ordered]@{ Type='protocol'; Label="Protocol [$($m.Value)]"; Match=$ok }
                [void]$res.CheckResults.Add($check)
                [void]$checks.Add($ok)
            }
            'acl' {
                $aclRes = Invoke-ACLEvaluation $m.Value $SrcIP $DstIP $Proto $DstPort
                $ok     = ($aclRes.Hit -and $aclRes.Action -eq 'permit')
                $res.ACLMatch = $ok
                $res.ACLName  = $m.Value
                if ($ok -and $aclRes.Rule) { $res.MatchedRule = $aclRes.Rule }
                $check = [ordered]@{ Type='acl'; Label="ACL [$($m.Value)]"; Match=$ok; ACLResult=$aclRes }
                [void]$res.CheckResults.Add($check)
                [void]$checks.Add($ok)
            }
            'acl-num' {
                $check = [ordered]@{ Type='acl-num'; Label="ACL# [$($m.Value)] (numbered ACL - skipped)"; Match=$false }
                [void]$res.CheckResults.Add($check)
                [void]$checks.Add($false)
            }
            'classmap' {
                $childRes = Invoke-ClassMapEvaluation $m.Value $SrcIP $DstIP $Proto $DstPort ($Depth + 1)
                $ok       = $childRes.Match
                $check    = [ordered]@{ Type='classmap'; Label="Class-Map [$($m.Value)]"; Match=$ok; ChildResult=$childRes }
                [void]$res.CheckResults.Add($check)
                [void]$checks.Add($ok)
            }
        }
    }
    if ($checks.Count -eq 0) { return $res }
    $res.Match = if ($cm.MatchType -eq 'match-any') { $checks -contains $true } else { $checks -notcontains $false }
    return $res
}

# ======================================================================
# COVERAGE ENGINE — for partial input (only Src, only Dst, or Src+Dst
# without protocol/port). Instead of a single first-match verdict, these
# functions surface EVERY ACE across every reachable ACL that the given
# IP(s) would touch, so the user can see full policy coverage at a glance.
# ======================================================================

function Get-ZonePairsForZone {
    <#
    .SYNOPSIS
        Returns all zone-pairs where the given zone plays the requested role.
    #>
    param([string]$Zone, [ValidateSet('Source','Dest')][string]$Role)
    $out = [System.Collections.ArrayList]@()
    foreach ($zpName in $script:ZonePairs.Keys) {
        $zp = $script:ZonePairs[$zpName]
        if ($Role -eq 'Source' -and $zp.SourceZone -ieq $Zone) { [void]$out.Add($zp) }
        if ($Role -eq 'Dest'   -and $zp.DestZone   -ieq $Zone) { [void]$out.Add($zp) }
    }
    return $out
}

function Get-ACLsReachableFromZonePair {
    <#
    .SYNOPSIS
        Walks ZonePair -> PolicyMap -> Classes -> ACLs and returns a flat list
        of { ZonePair, ClassName, Action, ACLName } tuples (skips class-default,
        which has no ACL of its own).
    #>
    param($ZonePair)
    $out = [System.Collections.ArrayList]@()
    if (-not $ZonePair.PolicyMap -or -not (Test-KeyExists $script:PolicyMaps $ZonePair.PolicyMap)) { return $out }
    foreach ($cls in $script:PolicyMaps[$ZonePair.PolicyMap].Classes) {
        if ($cls.ClassName -eq 'class-default') { continue }
        foreach ($aclName in (Get-ACLsFromClassMap $cls.ClassName)) {
            [void]$out.Add([ordered]@{
                ZonePair  = $ZonePair.Name
                PolicyMap = $ZonePair.PolicyMap
                ClassName = $cls.ClassName
                Action    = $cls.Action
                ACLName   = $aclName
            })
        }
    }
    return $out
}

function Get-ACLLinesMatchingIP {
    <#
    .SYNOPSIS
        Evaluates every ACE in an ACL against a single IP on ONE side only
        (Src or Dst) — the other side and the port are ignored/unknown.
        Returns every ACE that matches on that side, in order, with a note
        of whether it would ultimately win (first matching ACE = the one
        that governs, since ACLs are first-match-wins) or is shadowed by an
        earlier ACE.
    #>
    param([string]$ACLName, [string]$IP, [ValidateSet('Src','Dst')][string]$Side)

    $result = [ordered]@{ Found=$false; Matches=[System.Collections.ArrayList]@(); FirstWinner=$null }
    if (-not (Test-KeyExists $script:AccessLists $ACLName)) { return $result }
    $result.Found = $true

    $seq = 0
    $winnerSet = $false
    foreach ($rule in $script:AccessLists[$ACLName].Rules) {
        $seq++
        $sideMatch = if ($Side -eq 'Src') {
            switch ($rule.SrcType) {
                'any'    { $true }
                'host'   { $IP -eq $rule.SrcIP }
                'subnet' { Test-IPMatchWildcard $IP $rule.SrcIP $rule.SrcWild }
                default  { $false }
            }
        } else {
            switch ($rule.DstType) {
                'any'    { $true }
                'host'   { $IP -eq $rule.DstIP }
                'subnet' { Test-IPMatchWildcard $IP $rule.DstIP $rule.DstWild }
                default  { $false }
            }
        }
        if (-not $sideMatch) { continue }
        $isFirstWinner = (-not $winnerSet)
        if ($isFirstWinner) { $winnerSet = $true; $result.FirstWinner = $seq }
        [void]$result.Matches.Add([ordered]@{
            Seq         = $seq
            Raw         = $rule.Raw
            Action      = $rule.Action
            Protocol    = $rule.Protocol
            IsFirstWin  = $isFirstWinner
            OtherSide   = if ($Side -eq 'Src') {
                              switch ($rule.DstType) { 'any' {'any'} 'host' {"host $($rule.DstIP)"} default {"$($rule.DstIP) $($rule.DstWild)"} }
                          } else {
                              switch ($rule.SrcType) { 'any' {'any'} 'host' {"host $($rule.SrcIP)"} default {"$($rule.SrcIP) $($rule.SrcWild)"} }
                          }
            PortNote    = if ($Side -eq 'Src') { Format-PortSpec $rule.DstPort } else { Format-PortSpec $rule.SrcPort }
        })
    }
    return $result
}

function Get-ACLLinesMatchingPair {
    <#
    .SYNOPSIS
        Evaluates every ACE in an ACL against a Src+Dst IP pair, ignoring
        protocol/port (since the caller only supplied the two addresses).
        Returns every ACE whose IP fields both match, in order.
    #>
    param([string]$ACLName, [string]$SrcIP, [string]$DstIP, [string]$Proto = $null)

    $result = [ordered]@{ Found=$false; Matches=[System.Collections.ArrayList]@(); FirstWinner=$null }
    if (-not (Test-KeyExists $script:AccessLists $ACLName)) { return $result }
    $result.Found = $true

    $seq = 0
    $winnerSet = $false
    foreach ($rule in $script:AccessLists[$ACLName].Rules) {
        $seq++
        if ($Proto -and $rule.Protocol -ne 'ip' -and $rule.Protocol -ne $Proto.ToLower()) { continue }

        $srcOK = switch ($rule.SrcType) {
            'any'    { $true }
            'host'   { $SrcIP -eq $rule.SrcIP }
            'subnet' { Test-IPMatchWildcard $SrcIP $rule.SrcIP $rule.SrcWild }
            default  { $false }
        }
        if (-not $srcOK) { continue }
        $dstOK = switch ($rule.DstType) {
            'any'    { $true }
            'host'   { $DstIP -eq $rule.DstIP }
            'subnet' { Test-IPMatchWildcard $DstIP $rule.DstIP $rule.DstWild }
            default  { $false }
        }
        if (-not $dstOK) { continue }

        $isFirstWinner = (-not $winnerSet)
        if ($isFirstWinner) { $winnerSet = $true; $result.FirstWinner = $seq }
        [void]$result.Matches.Add([ordered]@{
            Seq        = $seq
            Raw        = $rule.Raw
            Action     = $rule.Action
            Protocol   = $rule.Protocol
            SrcPort    = Format-PortSpec $rule.SrcPort
            DstPort    = Format-PortSpec $rule.DstPort
            IsFirstWin = $isFirstWinner
        })
    }
    return $result
}

function Invoke-IPCoverageAnalysis {
    <#
    .SYNOPSIS
        Handles "only one IP supplied" queries. Resolves the IP's interface
        and zone, then finds every zone-pair (and, if applicable, VLAN ACL)
        where that zone participates in the requested role, and reports
        every ACE across every reachable ACL that the IP would touch.
    #>
    param([string]$IP, [ValidateSet('Source','Dest')][string]$Role)

    $output = [System.Collections.ArrayList]@()
    $out = { param([string]$t,[string]$s) [void]$output.Add([PSCustomObject]@{ Text=$t; Style=$s }) }
    $roleLabel = if ($Role -eq 'Source') { 'SOURCE' } else { 'DESTINATION' }
    $sideForACL = if ($Role -eq 'Source') { 'Src' } else { 'Dst' }

    & $out "  #=========================================================#" "head"
    & $out "   $roleLabel-ONLY ACL COVERAGE — $IP" "head"
    & $out "  #=========================================================#" "head"
    & $out "" "info"
    & $out "  Only the $roleLabel address was supplied, so this shows every ACE" "detail"
    & $out "  across every reachable ACL that this address would match against" "detail"
    & $out "  on the $roleLabel field. The opposite address, protocol, and port" "detail"
    & $out "  are unconstrained (treated as 'any') until you supply them." "detail"
    & $out "" "info"

    $ifMatch = Find-InterfaceAndMatchForIP $IP
    if (-not $ifMatch) {
        & $out "  [!] No interface subnet matches $IP -- cannot resolve a zone." "warn"
        & $out "      This address is not local to any configured interface." "detail"
        return @{ Output=$output }
    }
    $iface = $ifMatch.Interface
    & $out "  Interface  : $($iface.Name)" "info"
    & $out "  Subnet     : $($ifMatch.MatchedIP) / $($ifMatch.MatchedMask)$(if (-not $ifMatch.IsPrimary) { '  [secondary]' })" "detail"
    if (-not $iface.Zone) {
        & $out "  [!] Interface has no zone-member assignment -- not part of ZBFW." "warn"
        return @{ Output=$output }
    }
    & $out "  Zone       : $($iface.Zone)" "ok"
    & $out "" "info"

    $zonePairs = Get-ZonePairsForZone -Zone $iface.Zone -Role $Role
    $totalACEs = 0
    $totalACLs = 0

    if ($zonePairs.Count -eq 0) {
        & $out "  [i] No zone-pairs found with this zone as $Role." "warn"
    } else {
        foreach ($zp in $zonePairs) {
            $otherZone = if ($Role -eq 'Source') { $zp.DestZone } else { $zp.SourceZone }
            $arrow     = if ($Role -eq 'Source') { "$($iface.Zone) --> $otherZone" } else { "$otherZone --> $($iface.Zone)" }
            & $out "  +-[ ZONE-PAIR: $($zp.Name)  ($arrow) ]" "head"
            & $out "    Policy-Map : $(if ($zp.PolicyMap) { $zp.PolicyMap } else { '(none)' })" "detail"
            $tuples = Get-ACLsReachableFromZonePair $zp
            if ($tuples.Count -eq 0) {
                & $out "    (no ACL-bearing classes in this policy-map)" "detail"
                & $out "" "info"
                continue
            }
            foreach ($t in $tuples) {
                $totalACLs++
                & $out "    Class : $($t.ClassName)  [action: $(if ($t.Action) { $t.Action } else { 'drop' })]   ACL: $($t.ACLName)" "info"
                $cov = Get-ACLLinesMatchingIP -ACLName $t.ACLName -IP $IP -Side $sideForACL
                if (-not $cov.Found) {
                    & $out "      [!] ACL '$($t.ACLName)' not found in config." "warn"
                } elseif ($cov.Matches.Count -eq 0) {
                    & $out "      No ACEs in this ACL match $IP on the $roleLabel field." "detail"
                } else {
                    foreach ($m in $cov.Matches) {
                        $totalACEs++
                        $style = if ($m.Action -eq 'permit') { 'ok' } else { 'deny' }
                        $tag   = if ($m.IsFirstWin) { '>> GOVERNS (first match) <<' } else { '(shadowed by an earlier ACE)' }
                        & $out "      Line $($m.Seq.ToString().PadLeft(3)) [$($m.Action.ToUpper())] $($m.Raw)" $style
                        & $out "               other side: $($m.OtherSide)   port(other side): $($m.PortNote)   $tag" "detail"
                    }
                }
                & $out "" "info"
            }
        }
    }

    if ($iface.Zone -and ($script:KnownVLANZones -contains $iface.Zone) -and (Test-KeyExists $script:VLANPolicyDB $iface.Zone)) {
        $ve = $script:VLANPolicyDB[$iface.Zone]
        & $out "  +-[ VLAN DIRECT ACL: $($iface.Zone) ]" "head"
        & $out "    ACL : $($ve.PrimaryACL)   (source: $($ve.SourceDesc))" "detail"
        $cov = Get-ACLLinesMatchingIP -ACLName $ve.PrimaryACL -IP $IP -Side $sideForACL
        if ($cov.Found -and $cov.Matches.Count -gt 0) {
            $totalACLs++
            foreach ($m in $cov.Matches) {
                $totalACEs++
                $style = if ($m.Action -eq 'permit') { 'ok' } else { 'deny' }
                $tag   = if ($m.IsFirstWin) { '>> GOVERNS (first match) <<' } else { '(shadowed by an earlier ACE)' }
                & $out "      Line $($m.Seq.ToString().PadLeft(3)) [$($m.Action.ToUpper())] $($m.Raw)" $style
                & $out "               other side: $($m.OtherSide)   port(other side): $($m.PortNote)   $tag" "detail"
            }
        } else {
            & $out "    No ACEs in this ACL match $IP on the $roleLabel field." "detail"
        }
        & $out "" "info"
    }

    & $out "  #=========================================================#" "head"
    & $out "   COVERAGE SUMMARY" "head"
    & $out "  #=========================================================#" "head"
    & $out "  ACLs examined   : $totalACLs" "info"
    & $out "  Matching ACEs   : $totalACEs" $(if ($totalACEs -gt 0) { 'ok' } else { 'warn' })
    & $out "  Tip: supply the opposite address too for a Src+Dst coverage view," "detail"
    & $out "       or add protocol + port for a full pass/fail verdict." "detail"

    return @{ Output=$output }
}

function Invoke-PairCoverageAnalysis {
    <#
    .SYNOPSIS
        Handles "Src + Dst supplied, protocol/port omitted" queries.
        Resolves the zone-pair exactly like the full engine, then reports
        EVERY ACE across the applicable ACL(s) that both addresses satisfy,
        so the user can see all protocol/port combinations that are covered
        between this pair -- not just the first (winning) match.
    #>
    param([string]$SrcIP, [string]$DstIP, [string]$Proto = $null)

    $output = [System.Collections.ArrayList]@()
    $out = { param([string]$t,[string]$s) [void]$output.Add([PSCustomObject]@{ Text=$t; Style=$s }) }

    & $out "  #=========================================================#" "head"
    & $out "   SRC + DST ACL COVERAGE  ($SrcIP  -->  $DstIP)" "head"
    & $out "  #=========================================================#" "head"
    & $out "" "info"
    if ($Proto) {
        & $out "  Protocol constraint : $Proto   (port not supplied -- all ports of this protocol shown)" "detail"
    } else {
        & $out "  No protocol/port supplied -- every protocol/port combination covered" "detail"
        & $out "  between this address pair is listed below." "detail"
    }
    & $out "" "info"

    $srcMatch = Find-InterfaceAndMatchForIP $SrcIP
    $dstMatch = Find-InterfaceAndMatchForIP $DstIP
    $srcIface = if ($srcMatch) { $srcMatch.Interface } else { $null }
    $dstIface = if ($dstMatch) { $dstMatch.Interface } else { $null }

    if (-not $srcIface) {
        $wanZone = Find-OutsideZone
        if ($wanZone) {
            $srcIface = [ordered]@{ Name='(external)'; Zone=$wanZone }
            & $out "  [i] Source $SrcIP not local -- inferred zone '$wanZone'." "warn"
        } else {
            & $out "  [!] No interface matches source IP $SrcIP and no Outside zone found." "deny"
            return @{ Output=$output }
        }
    }
    if (-not $dstIface) {
        $wanZone = Find-OutsideZone
        if ($wanZone) {
            $dstIface = [ordered]@{ Name='(external)'; Zone=$wanZone }
            & $out "  [i] Destination $DstIP not local -- inferred zone '$wanZone'." "warn"
        } else {
            & $out "  [!] No interface matches destination IP $DstIP and no Outside zone found." "deny"
            return @{ Output=$output }
        }
    }

    $srcZone = $srcIface.Zone
    $dstZone = $dstIface.Zone
    & $out "  Source Zone      : $(if ($srcZone) { $srcZone } else { '(none)' })" "info"
    & $out "  Destination Zone : $(if ($dstZone) { $dstZone } else { '(none)' })" "info"
    & $out "" "info"

    if (-not $srcZone -or -not $dstZone) {
        & $out "  [!] One or both interfaces have no zone-member -- outside ZBFW scope." "warn"
        return @{ Output=$output }
    }

    if ($srcZone -eq $dstZone) {
        & $out "  Source and destination share zone '$srcZone' -- intra-zone traffic" "ok"
        & $out "  is implicitly permitted by Cisco ZBFW (no ACL evaluation applies)." "ok"
        return @{ Output=$output }
    }

    $totalACEs = 0
    $totalACLs = 0

    # VLAN direct-ACL path (applies if either zone is a known VLAN zone)
    foreach ($z in @($srcZone, $dstZone)) {
        if (($script:KnownVLANZones -contains $z) -and (Test-KeyExists $script:VLANPolicyDB $z)) {
            $ve = $script:VLANPolicyDB[$z]
            & $out "  +-[ VLAN DIRECT ACL: $z ]" "head"
            & $out "    ACL : $($ve.PrimaryACL)   (source: $($ve.SourceDesc))" "detail"
            $cov = Get-ACLLinesMatchingPair -ACLName $ve.PrimaryACL -SrcIP $SrcIP -DstIP $DstIP -Proto $Proto
            if ($cov.Found -and $cov.Matches.Count -gt 0) {
                $totalACLs++
                foreach ($m in $cov.Matches) {
                    $totalACEs++
                    $style = if ($m.Action -eq 'permit') { 'ok' } else { 'deny' }
                    $tag   = if ($m.IsFirstWin) { '>> GOVERNS (first match, port-agnostic) <<' } else { '(shadowed by an earlier ACE)' }
                    & $out "      Line $($m.Seq.ToString().PadLeft(3)) [$($m.Action.ToUpper())] proto:$($m.Protocol) src-port:$($m.SrcPort) dst-port:$($m.DstPort)" $style
                    & $out "               $($m.Raw)   $tag" "detail"
                }
            } else {
                & $out "    No ACEs in this ACL match both addresses." "detail"
            }
            & $out "" "info"
        }
    }

    $zp = Find-ZonePair $srcZone $dstZone
    if (-not $zp) {
        & $out "  [!] No zone-pair defined for $srcZone --> $dstZone (implicit drop if reached)." "warn"
    } else {
        & $out "  +-[ ZONE-PAIR: $($zp.Name) ]" "head"
        & $out "    Policy-Map : $(if ($zp.PolicyMap) { $zp.PolicyMap } else { '(none)' })" "detail"
        $tuples = Get-ACLsReachableFromZonePair $zp
        if ($tuples.Count -eq 0) {
            & $out "    (no ACL-bearing classes in this policy-map)" "detail"
        }
        foreach ($t in $tuples) {
            $totalACLs++
            & $out "    Class : $($t.ClassName)  [action: $(if ($t.Action) { $t.Action } else { 'drop' })]   ACL: $($t.ACLName)" "info"
            $cov = Get-ACLLinesMatchingPair -ACLName $t.ACLName -SrcIP $SrcIP -DstIP $DstIP -Proto $Proto
            if (-not $cov.Found) {
                & $out "      [!] ACL '$($t.ACLName)' not found in config." "warn"
            } elseif ($cov.Matches.Count -eq 0) {
                & $out "      No ACEs in this ACL match both addresses$(if ($Proto) { " for protocol $Proto" })." "detail"
            } else {
                foreach ($m in $cov.Matches) {
                    $totalACEs++
                    $style = if ($m.Action -eq 'permit') { 'ok' } else { 'deny' }
                    $tag   = if ($m.IsFirstWin) { '>> GOVERNS (first match, port-agnostic) <<' } else { '(shadowed by an earlier ACE)' }
                    & $out "      Line $($m.Seq.ToString().PadLeft(3)) [$($m.Action.ToUpper())] proto:$($m.Protocol) src-port:$($m.SrcPort) dst-port:$($m.DstPort)" $style
                    & $out "               $($m.Raw)   $tag" "detail"
                }
            }
            & $out "" "info"
        }
    }

    & $out "  #=========================================================#" "head"
    & $out "   COVERAGE SUMMARY" "head"
    & $out "  #=========================================================#" "head"
    & $out "  ACLs examined   : $totalACLs" "info"
    & $out "  Matching ACEs   : $totalACEs" $(if ($totalACEs -gt 0) { 'ok' } else { 'warn' })
    if ($totalACEs -gt 0) {
        & $out "  Note: 'GOVERNS' marks the first (winning) ACE per ACL under ACL" "detail"
        & $out "        first-match-wins rules; everything else is shown for visibility" "detail"
        & $out "        but is shadowed unless the governing line is removed." "detail"
    }
    & $out "  Tip: add protocol + destination port for a definitive pass/fail verdict." "detail"

    return @{ Output=$output }
}

# ======================================================================
# ZBFW TRAFFIC ANALYSIS  (full 4-field mode — Src+Dst+Proto+Port)
# ======================================================================

function Invoke-ZBFWAnalysis {
    param([string]$SrcIP, [string]$DstIP, [string]$Proto, [int]$DstPort)

    $output  = [System.Collections.ArrayList]@()
    $verdict = @{ Allowed=$null; Action=$null; MatchedClass=$null; MatchedRule=$null; Reason=$null; InspectParam=$null; MatchedACL=$null }
    $out = { param([string]$t, [string]$s) [void]$output.Add([PSCustomObject]@{ Text=$t; Style=$s }) }

    & $out "  #=========================================================#" "head"
    & $out "   ZBFW TRAFFIC FLOW ANALYSIS  (full verdict)" "head"
    & $out "  #=========================================================#" "head"
    & $out "" "info"

    & $out "  +-[ STEP 1: INTERFACE LOOKUP ]---------------------------+" "head"
    & $out "" "info"

    $srcMatch = Find-InterfaceAndMatchForIP $SrcIP
    $dstMatch = Find-InterfaceAndMatchForIP $DstIP
    $srcIface = if ($srcMatch) { $srcMatch.Interface } else { $null }
    $dstIface = if ($dstMatch) { $dstMatch.Interface } else { $null }

    if (-not $srcIface) {
        $wanZone = Find-OutsideZone
        if ($wanZone) {
            $srcIface = [ordered]@{ Name='(external)'; IP=$null; Mask=$null; SecondaryIPs=[System.Collections.ArrayList]@(); VRF='DEFAULT'; Zone=$wanZone }
            $srcMatch = @{ Interface=$srcIface; MatchedIP=$null; MatchedMask=$null; IsPrimary=$true; Inferred=$true }
            & $out "  [i] Source IP $SrcIP is not within any configured interface subnet." "warn"
            & $out "      WAN/Outside inference: assigned to zone '$wanZone'." "detail"
        } else {
            & $out "  [!] No interface subnet matches source IP: $SrcIP" "warn"
            $verdict.Allowed = $false; $verdict.Reason = "No interface subnet matches source IP $SrcIP"
            & $out "" "info"; & $out "  #=========================================================#" "head"
            & $out "   FINAL RESULT" "head"; & $out "  #=========================================================#" "head"
            & $out "  X  DENIED" "deny"; & $out "  Reason : $($verdict.Reason)" "deny"
            return @{ Output=$output; Verdict=$verdict }
        }
    }
    if ($srcMatch.Inferred) {
        & $out "  Source Interface : (external -- IP not in any local subnet)" "info"
    } else {
        $srcSubnetStr = "$($srcMatch.MatchedIP) / $($srcMatch.MatchedMask)$(if (-not $srcMatch.IsPrimary) { '  [secondary]' })"
        & $out "  Source Interface : $($srcIface.Name)" "info"
        & $out "  Source IF Subnet : $srcSubnetStr" "detail"
    }

    if (-not $dstIface) {
        $wanZone = Find-OutsideZone
        if ($wanZone) {
            $dstIface = [ordered]@{ Name='(external)'; IP=$null; Mask=$null; SecondaryIPs=[System.Collections.ArrayList]@(); VRF='DEFAULT'; Zone=$wanZone }
            $dstMatch = @{ Interface=$dstIface; MatchedIP=$null; MatchedMask=$null; IsPrimary=$true; Inferred=$true }
            & $out "  [i] Destination IP $DstIP is not within any configured interface subnet." "warn"
            & $out "      WAN/Outside inference: assigned to zone '$wanZone'." "detail"
        } else {
            & $out "  [!] No interface subnet matches destination IP: $DstIP" "warn"
            $verdict.Allowed = $false; $verdict.Reason = "No interface subnet matches destination IP $DstIP"
            & $out "" "info"; & $out "  #=========================================================#" "head"
            & $out "   FINAL RESULT" "head"; & $out "  #=========================================================#" "head"
            & $out "  X  DENIED" "deny"; & $out "  Reason : $($verdict.Reason)" "deny"
            return @{ Output=$output; Verdict=$verdict }
        }
    }
    if ($dstMatch.Inferred) {
        & $out "  Dest Interface   : (external -- IP not in any local subnet)" "info"
    } else {
        $dstSubnetStr = "$($dstMatch.MatchedIP) / $($dstMatch.MatchedMask)$(if (-not $dstMatch.IsPrimary) { '  [secondary]' })"
        & $out "  Dest Interface   : $($dstIface.Name)" "info"
        & $out "  Dest IF Subnet   : $dstSubnetStr" "detail"
    }
    & $out "" "info"

    & $out "  +-[ STEP 2: ZONE LOOKUP ]--------------------------------+" "head"
    & $out "" "info"
    $srcZone = $srcIface.Zone
    $dstZone = $dstIface.Zone

    if (-not $srcZone) {
        & $out "  [!] Source interface '$($srcIface.Name)' has no zone-member assignment." "warn"
        $verdict.Allowed = $false; $verdict.Reason = "Source interface '$($srcIface.Name)' has no security zone"
        & $out "" "info"; & $out "  #=========================================================#" "head"
        & $out "   FINAL RESULT" "head"; & $out "  #=========================================================#" "head"
        & $out "  X  DENIED" "deny"; & $out "  Reason : $($verdict.Reason)" "deny"
        return @{ Output=$output; Verdict=$verdict }
    }
    & $out "  Source Zone      : $srcZone$(if ($srcMatch.Inferred) { '  [inferred - external endpoint]' })" "info"

    if (-not $dstZone) {
        & $out "  [!] Destination interface '$($dstIface.Name)' has no zone-member assignment." "warn"
        $verdict.Allowed = $false; $verdict.Reason = "Destination interface '$($dstIface.Name)' has no security zone"
        & $out "" "info"; & $out "  #=========================================================#" "head"
        & $out "   FINAL RESULT" "head"; & $out "  #=========================================================#" "head"
        & $out "  X  DENIED" "deny"; & $out "  Reason : $($verdict.Reason)" "deny"
        return @{ Output=$output; Verdict=$verdict }
    }
    & $out "  Destination Zone : $dstZone$(if ($dstMatch.Inferred) { '  [inferred - external endpoint]' })" "info"
    & $out "" "info"

    $srcVRF = if ($srcIface.VRF) { $srcIface.VRF } else { 'DEFAULT' }
    $dstVRF = if ($dstIface.VRF) { $dstIface.VRF } else { 'DEFAULT' }
    & $out "  +-[ VRF AWARENESS ]--------------------------------------+" "head"
    & $out "" "info"
    & $out "  Source VRF       : $srcVRF" "info"
    & $out "  Destination VRF  : $dstVRF" "info"
    if ($srcVRF -ne $dstVRF) {
        & $out "  [!] VRF mismatch -- source and destination are in different routing domains." "warn"
    }
    & $out "" "info"

    if ($srcZone -eq $dstZone) {
        & $out "  +-[ INTRA-ZONE TRAFFIC ]---------------------------------+" "head"
        & $out "" "info"
        & $out "  Source and destination are in the SAME zone: $srcZone" "warn"
        & $out "  Cisco ZBFW: intra-zone traffic is implicitly permitted." "ok"
        $verdict.Allowed = $true; $verdict.Reason = "Intra-zone — zone: $srcZone"
        & $out "" "info"; & $out "  #=========================================================#" "head"
        & $out "   FINAL RESULT" "head"; & $out "  #=========================================================#" "head"
        & $out "  [OK] ALLOWED  (Intra-zone — no inspection applied)" "ok"
        return @{ Output=$output; Verdict=$verdict }
    }

    $isVLANSrc = ($script:KnownVLANZones -contains $srcZone)
    $isVLANDst = ($script:KnownVLANZones -contains $dstZone)
    if ($isVLANSrc -or $isVLANDst) {
        $vlanResult = Invoke-VLANACLAnalysis -SrcIP $SrcIP -DstIP $DstIP -Proto $Proto -DstPort $DstPort -SrcZone $srcZone -DstZone $dstZone -SrcIface $srcIface -DstIface $dstIface
        if ($null -ne $vlanResult) {
            foreach ($line in $vlanResult.Output) { [void]$output.Add($line) }
            if ($vlanResult.FallThrough) { } else { return @{ Output=$output; Verdict=$vlanResult.Verdict } }
        }
    }

    & $out "  +-[ STEP 3: ZONE-PAIR LOOKUP ]---------------------------+" "head"
    & $out "" "info"
    $zp = Find-ZonePair $srcZone $dstZone
    if (-not $zp) {
        & $out "  [!] No zone-pair found for: $srcZone --> $dstZone" "warn"
        $verdict.Allowed = $false; $verdict.Reason = "No zone-pair for $srcZone -> $dstZone (implicit drop)"
        & $out "" "info"; & $out "  #=========================================================#" "head"
        & $out "   FINAL RESULT" "head"; & $out "  #=========================================================#" "head"
        & $out "  X  DENIED" "deny"; & $out "  Reason : $($verdict.Reason)" "deny"
        return @{ Output=$output; Verdict=$verdict }
    }
    & $out "  Zone-Pair Found  : $($zp.Name)" "ok"
    & $out "  Policy-Map       : $(if ($zp.PolicyMap) { $zp.PolicyMap } else { '(none)' })$(if ($zp.PolicyMapInferred) { '  [matched by naming convention]' })" "info"
    & $out "" "info"

    if (-not $zp.PolicyMap) {
        $verdict.Allowed = $false; $verdict.Reason = "No service-policy on zone-pair '$($zp.Name)'"
        & $out "  #=========================================================#" "head"
        & $out "   FINAL RESULT" "head"; & $out "  #=========================================================#" "head"
        & $out "  X  DENIED" "deny"; & $out "  Reason : $($verdict.Reason)" "deny"
        return @{ Output=$output; Verdict=$verdict }
    }

    $pmExists = Test-KeyExists $script:PolicyMaps $zp.PolicyMap
    if (-not $pmExists) {
        $verdict.Allowed = $false; $verdict.Reason = "Policy-map '$($zp.PolicyMap)' not found"
        & $out "  #=========================================================#" "head"
        & $out "   FINAL RESULT" "head"; & $out "  #=========================================================#" "head"
        & $out "  X  DENIED" "deny"; & $out "  Reason : $($verdict.Reason)" "deny"
        return @{ Output=$output; Verdict=$verdict }
    }
    $pm = $script:PolicyMaps[$zp.PolicyMap]

    & $out "  +-[ STEP D-F: CLASS-MAP + ACL EVALUATION (first match) ]-+" "head"
    & $out "" "info"
    $matched  = $false
    $classIdx = 0
    foreach ($classEntry in $pm.Classes) {
        $classIdx++
        $cmName = $classEntry.ClassName
        $action = if ($classEntry.Action) { $classEntry.Action } else { 'drop' }
        & $out "  | Class #$classIdx : $cmName" "info"

        if ($cmName -eq 'class-default') {
            & $out "  |   (Default class — no previous class matched)" "warn"
            $aColor = if ($action -in @('inspect','pass')) { 'ok' } else { 'deny' }
            & $out "  |   Action : $($action.ToUpper())" $aColor
            $verdict.Allowed = ($action -in @('inspect','pass'))
            $verdict.Action = $action; $verdict.MatchedClass = $cmName
            if (-not $verdict.Allowed) { $verdict.Reason = "class-default action: $action" }
            $matched = $true; break
        }

        if (-not (Test-KeyExists $script:ClassMaps $cmName)) {
            & $out "  |   [FAIL] Class-map '$cmName' not found. Skipping." "deny"
            continue
        }
        $cmRes = Invoke-ClassMapEvaluation $cmName $SrcIP $DstIP $Proto $DstPort
        if ($cmRes.Match) {
            $aColor = if ($action -in @('inspect','pass')) { 'ok' } else { 'deny' }
            & $out "  |   >>> CLASS MATCHED  ->  Action: $($action.ToUpper())" $aColor
            $verdict.Allowed = ($action -in @('inspect','pass'))
            $verdict.Action = $action; $verdict.MatchedClass = $cmName; $verdict.MatchedRule = $cmRes.MatchedRule
            foreach ($chk in $cmRes.CheckResults) {
                if ($chk.Type -eq 'acl') { $verdict.MatchedACL = ($chk.Label -replace '^ACL \[','') -replace '\]$',''; break }
            }
            if (-not $verdict.Allowed) { $verdict.Reason = "Dropped by class '$cmName' (action: drop)" }
            $matched = $true; break
        } else {
            & $out "  |   No match — evaluating next class..." "detail"
        }
        & $out "" "info"
    }

    if (-not $matched) {
        & $out "  [!] No class map matched and no class-default found -- implicit drop." "warn"
        $verdict.Allowed = $false; $verdict.Reason = "No class map matched — implicit drop"
    }

    & $out "" "info"
    & $out "  #=========================================================#" "head"
    & $out "   FINAL RESULT" "head"
    & $out "  #=========================================================#" "head"
    if ($verdict.Allowed -eq $true) {
        & $out "  [OK] ALLOWED" "ok"
        & $out "  Action            : $($verdict.Action)" "ok"
        & $out "  Matched Class Map : $($verdict.MatchedClass)" "ok"
        if ($verdict.MatchedRule) { & $out "  Matched ACL Rule  : $($verdict.MatchedRule)" "ok" }
    } else {
        & $out "  [X]  DENIED" "deny"
        & $out "  Reason            : $($verdict.Reason)" "deny"
    }

    if ($null -ne $zp -and $null -ne $pm) {
        & $out "" "info"
        $flowAction = if ($verdict.Allowed) { $verdict.Action } else { 'DENIED' }
        $flowLines  = Format-VisualFlowView -SrcZone $srcZone -SrcIface $srcIface.Name -SrcVRF $srcIface.VRF -DstZone $dstZone -DstIface $dstIface.Name -DstVRF $dstIface.VRF -ZonePair $zp.Name -PolicyMap $pm.Name -ClassMap $(if ($verdict.MatchedClass) { $verdict.MatchedClass } else { 'no match' }) -ACL $verdict.MatchedACL -Action $flowAction
        foreach ($fl in $flowLines) { & $out $fl.Text $fl.Style }
    }

    return @{ Output=$output; Verdict=$verdict }
}

function Invoke-VLANACLAnalysis {
    param([string]$SrcIP, [string]$DstIP, [string]$Proto, [int]$DstPort, [string]$SrcZone, [string]$DstZone, $SrcIface, $DstIface)
    $output  = [System.Collections.ArrayList]@()
    $verdict = @{ Allowed=$null; Action=$null; MatchedClass=$null; MatchedRule=$null; Reason=$null; InspectParam=$null; MatchedACL=$null }
    $out = { param([string]$t, [string]$s) [void]$output.Add([PSCustomObject]@{ Text=$t; Style=$s }) }

    $detectedVLANZone = $null
    $vlanEntry        = $null
    foreach ($z in @($SrcZone, $DstZone)) {
        if (($script:KnownVLANZones -contains $z) -and (Test-KeyExists $script:VLANPolicyDB $z)) {
            $detectedVLANZone = $z; $vlanEntry = $script:VLANPolicyDB[$z]; break
        }
    }
    if ($null -eq $vlanEntry) { return $null }

    & $out "  +-[ VLAN ACL DETECTION ENGINE ]---------------------------+" "head"
    & $out "" "info"
    & $out "  VLAN Detection   : YES" "ok"
    & $out "  Detected VLAN    : $detectedVLANZone" "ok"
    & $out "  ACL Evaluated    : $(if ($vlanEntry.PrimaryACL) { $vlanEntry.PrimaryACL } else { '(none resolved)' })" "info"
    & $out "" "info"

    if (-not $vlanEntry.PrimaryACL) {
        & $out "  [!] No ACL resolved for this VLAN zone -- falling back to standard ZBFW." "warn"
        return $null
    }

    $aclRes = Invoke-ACLEvaluation $vlanEntry.PrimaryACL $SrcIP $DstIP $Proto $DstPort
    if (-not $aclRes.Found) {
        $verdict.Allowed = $false
        $verdict.Reason  = "VLAN ACL '$($vlanEntry.PrimaryACL)' not found in config"
    } else {
        $yesNo = { param($b) if ($b) { 'YES' } else { 'NO ' } }
        foreach ($rr in $aclRes.RuleResults) {
            $rrTag   = if ($rr.Matched) { 'MATCH' } else { 'SKIP ' }
            $rrStyle = if ($rr.Matched) { if ($rr.Action -eq 'permit') { 'ok' } else { 'deny' } } else { 'detail' }
            & $out "  Rule $($rr.Seq.ToString().PadLeft(3)): $rrTag  $($rr.Raw)" $rrStyle
            if (-not $rr.Matched -and $rr.SkipReason) { & $out "         Reason : $($rr.SkipReason)" "warn" }
        }
        if ($aclRes.Hit) {
            $verdict.Allowed = ($aclRes.Action -eq 'permit'); $verdict.Action = $aclRes.Action
            $verdict.MatchedACL = $vlanEntry.PrimaryACL; $verdict.MatchedRule = $aclRes.Rule
            if (-not $verdict.Allowed) { $verdict.Reason = "VLAN ACL '$($vlanEntry.PrimaryACL)' explicit deny" }
        } else {
            $verdict.Allowed = $false; $verdict.Reason = "VLAN ACL '$($vlanEntry.PrimaryACL)' implicit deny (no rule matched)"
        }
    }
    & $out "" "info"
    & $out "  #=========================================================#" "head"
    & $out "   FINAL ACL RESULT" "head"
    & $out "  #=========================================================#" "head"
    if ($verdict.Allowed -eq $true) {
        & $out "  [OK] PERMITTED" "ok"
        if ($verdict.MatchedRule) { & $out "  Matched Rule   : $($verdict.MatchedRule)" "ok" }
    } else {
        & $out "  [X]  DENIED" "deny"
        & $out "  Reason         : $($verdict.Reason)" "deny"
    }
    return @{ Output=$output; Verdict=$verdict }
}

# ======================================================================
# VISUAL FLOW VIEW
# ======================================================================

function Format-VisualFlowView {
    param([string]$SrcZone,[string]$SrcIface,[string]$SrcVRF,[string]$DstZone,[string]$DstIface,[string]$DstVRF,[string]$ZonePair,[string]$PolicyMap,[string]$ClassMap,[string]$ACL,[string]$Action)
    $lines = [System.Collections.ArrayList]@()
    $a = { param($t, $s) [void]$lines.Add([PSCustomObject]@{ Text=$t; Style=$s }) }
    & $a "  +-----------------------------------------+" "head"
    & $a "  |         VISUAL FLOW DIAGRAM              |" "head"
    & $a "  +-----------------------------------------+" "head"
    & $a "" "info"
    & $a "    Source Interface  : $SrcIface" "info"
    & $a "         |" "detail"; & $a "         v" "detail"
    & $a "    Source Zone       : [ $SrcZone ]" "info"
    & $a "         |" "detail"; & $a "         v" "detail"
    & $a "    Zone-Pair         : $ZonePair" "info"
    & $a "         |" "detail"; & $a "         v" "detail"
    & $a "    Policy-Map        : $PolicyMap" "info"
    & $a "         |" "detail"; & $a "         v" "detail"
    & $a "    Class-Map         : $ClassMap" "info"
    if ($ACL) { & $a "         |" "detail"; & $a "         v" "detail"; & $a "    ACL               : $ACL" "info" }
    & $a "         |" "detail"; & $a "         v" "detail"
    $aStyle = if ($Action -in @('inspect','pass','INSPECT','PASS')) { 'ok' } elseif ($Action -eq 'DENIED') { 'deny' } else { 'ok' }
    & $a "    Action            : [ $($Action.ToUpper()) ]" $aStyle
    & $a "         |" "detail"; & $a "         v" "detail"
    & $a "    Dest Zone         : [ $DstZone ]" "info"
    & $a "         |" "detail"; & $a "         v" "detail"
    & $a "    Dest Interface    : $DstIface" "info"
    & $a "" "info"
    return $lines
}

# ======================================================================
# ZONE-PAIR VALIDATION REPORT
# ======================================================================

function Invoke-ZonePairValidation {
    $report = [ordered]@{
        ZonePairsNoPM=[System.Collections.ArrayList]@(); ZonePairsNoSrc=[System.Collections.ArrayList]@()
        ZonePairsNoDst=[System.Collections.ArrayList]@(); MissingPMs=[System.Collections.ArrayList]@()
        MissingCMs=[System.Collections.ArrayList]@(); MissingACLs=[System.Collections.ArrayList]@()
        OrphanedZones=[System.Collections.ArrayList]@(); OrphanedCMs=[System.Collections.ArrayList]@()
    }
    foreach ($zpName in $script:ZonePairs.Keys) {
        $zp = $script:ZonePairs[$zpName]
        if (-not $zp.SourceZone) { [void]$report.ZonePairsNoSrc.Add($zpName) }
        if (-not $zp.DestZone)   { [void]$report.ZonePairsNoDst.Add($zpName) }
        if (-not $zp.PolicyMap) { [void]$report.ZonePairsNoPM.Add($zpName) }
        elseif (-not (Test-KeyExists $script:PolicyMaps $zp.PolicyMap)) {
            $e = "$($zp.PolicyMap)  (zone-pair: $zpName)"
            if ($report.MissingPMs -notcontains $e) { [void]$report.MissingPMs.Add($e) }
        }
    }
    foreach ($pmName in $script:PolicyMaps.Keys) {
        foreach ($cls in $script:PolicyMaps[$pmName].Classes) {
            $cn = $cls.ClassName
            if ($cn -eq 'class-default') { continue }
            if (-not (Test-KeyExists $script:ClassMaps $cn)) {
                $e = "$cn  (policy-map: $pmName)"
                if ($report.MissingCMs -notcontains $e) { [void]$report.MissingCMs.Add($e) }
            }
        }
    }
    foreach ($cmName in $script:ClassMaps.Keys) {
        foreach ($m in $script:ClassMaps[$cmName].Matches) {
            if ($m.Type -eq 'acl' -and -not (Test-KeyExists $script:AccessLists $m.Value)) {
                $e = "$($m.Value)  (class-map: $cmName)"
                if ($report.MissingACLs -notcontains $e) { [void]$report.MissingACLs.Add($e) }
            } elseif ($m.Type -eq 'classmap' -and -not (Test-KeyExists $script:ClassMaps $m.Value)) {
                $e = "$($m.Value)  (parent class-map: $cmName)"
                if ($report.MissingCMs -notcontains $e) { [void]$report.MissingCMs.Add($e) }
            }
        }
    }
    $usedZones = [System.Collections.ArrayList]@()
    foreach ($zp in $script:ZonePairs.Values) {
        if ($zp.SourceZone -and -not $usedZones.Contains($zp.SourceZone)) { [void]$usedZones.Add($zp.SourceZone) }
        if ($zp.DestZone   -and -not $usedZones.Contains($zp.DestZone))   { [void]$usedZones.Add($zp.DestZone) }
    }
    foreach ($z in $script:Zones) { if (-not $usedZones.Contains($z)) { [void]$report.OrphanedZones.Add($z) } }

    $referencedCMs = [System.Collections.ArrayList]@()
    foreach ($pm in $script:PolicyMaps.Values) {
        foreach ($cls in $pm.Classes) { if (-not $referencedCMs.Contains($cls.ClassName)) { [void]$referencedCMs.Add($cls.ClassName) } }
    }
    foreach ($cm in $script:ClassMaps.Values) {
        foreach ($m in $cm.Matches) { if ($m.Type -eq 'classmap' -and -not $referencedCMs.Contains($m.Value)) { [void]$referencedCMs.Add($m.Value) } }
    }
    foreach ($cmName in $script:ClassMaps.Keys) { if (-not $referencedCMs.Contains($cmName)) { [void]$report.OrphanedCMs.Add($cmName) } }
    return $report
}

function Get-ConfigInventory {
    $secIPTotal = ($script:Interfaces.Values | ForEach-Object { $_.SecondaryIPs.Count } | Measure-Object -Sum).Sum
    $vrfSet = ($script:Interfaces.Values | Where-Object { $_.VRF } | Select-Object -ExpandProperty VRF -Unique)
    return [ordered]@{
        Interfaces=$script:Interfaces.Count; SecondaryIPs=[int]$secIPTotal; VRFs=@($vrfSet).Count
        Zones=$script:Zones.Count; ZonePairs=$script:ZonePairs.Count; PolicyMaps=$script:PolicyMaps.Count
        ClassMaps=$script:ClassMaps.Count; NamedACLs=$script:AccessLists.Count
    }
}

# ======================================================================
# SUBNET / VLAN EXTRACTION HELPERS
# ======================================================================

function Get-SubnetInfo {
    <#
    .SYNOPSIS
        Given an IP + subnet mask, returns network address, broadcast address,
        usable host range, and usable host count. Used for VLAN IP extraction.
    #>
    param([string]$IP, [string]$Mask)
    try {
        $ipInt   = ConvertTo-IPInt $IP
        $maskInt = ConvertTo-IPInt $Mask
        $netInt  = $ipInt -band $maskInt
        $bcastInt = $netInt -bor (([long]4294967295) -bxor $maskInt)
        $hostBits = 0
        $m = $maskInt
        for ($b = 0; $b -lt 32; $b++) { if (-not (($m -shr $b) -band 1)) { $hostBits++ } }
        $usable = [Math]::Max(0, [Math]::Pow(2, $hostBits) - 2)
        $toIP = { param($n) "$(($n -shr 24) -band 255).$(($n -shr 16) -band 255).$(($n -shr 8) -band 255).$($n -band 255)" }
        return [ordered]@{
            Network      = & $toIP $netInt
            Broadcast    = & $toIP $bcastInt
            FirstUsable  = if ($usable -gt 0) { & $toIP ($netInt + 1) } else { '(n/a)' }
            LastUsable   = if ($usable -gt 0) { & $toIP ($bcastInt - 1) } else { '(n/a)' }
            UsableHosts  = [int]$usable
            CIDR         = 32 - $hostBits
        }
    } catch {
        return [ordered]@{ Network='(unparsable)'; Broadcast='(unparsable)'; FirstUsable='(n/a)'; LastUsable='(n/a)'; UsableHosts=0; CIDR=0 }
    }
}

function Get-VLANIPExtract {
    <#
    .SYNOPSIS
        Groups every interface (primary + secondary IPs) by security zone and
        computes subnet detail for each — the "extract VLAN IPs" report.
        Not limited to the KnownVLANZones list; covers every zone in use.
    #>
    $byZone = [ordered]@{}
    foreach ($ifName in $script:Interfaces.Keys) {
        $ifc = $script:Interfaces[$ifName]
        $zone = if ($ifc.Zone) { $ifc.Zone } else { '(no zone-member)' }
        if (-not $byZone.Contains($zone)) { $byZone[$zone] = [System.Collections.ArrayList]@() }
        if ($ifc.IP -and $ifc.Mask) {
            $info = Get-SubnetInfo -IP $ifc.IP -Mask $ifc.Mask
            [void]$byZone[$zone].Add([ordered]@{ Interface=$ifName; IP=$ifc.IP; Mask=$ifc.Mask; Secondary=$false; Info=$info })
        }
        foreach ($sec in $ifc.SecondaryIPs) {
            $info = Get-SubnetInfo -IP $sec.IP -Mask $sec.Mask
            [void]$byZone[$zone].Add([ordered]@{ Interface=$ifName; IP=$sec.IP; Mask=$sec.Mask; Secondary=$true; Info=$info })
        }
    }
    return $byZone
}

# ======================================================================
# FLOW RESOLUTION — structured (non-printing) path resolver, used by the
# Working-vs-Failing comparison tool so two flows can be diffed field by
# field rather than just eyeballing two separate text reports.
# ======================================================================

function Resolve-FlowPath {
    param([string]$SrcIP, [string]$DstIP, [string]$Proto = $null, [int]$DstPort = 0)

    $r = [ordered]@{
        SrcIP=$SrcIP; DstIP=$DstIP; Proto=$Proto; DstPort=$DstPort
        SrcZone=$null; DstZone=$null; SrcIfaceName=$null; DstIfaceName=$null
        Mode = if ($Proto -and ($Proto -notin @('tcp','udp') -or $DstPort -gt 0)) { 'full' } else { 'coverage' }
        IntraZone=$false; ZonePairName=$null; PolicyMap=$null; MatchedClass=$null
        ACLName=$null; ACLLineSeq=$null; ACLLineRaw=$null; Action=$null; Allowed=$null; Reason=$null
    }

    $srcMatch = Find-InterfaceAndMatchForIP $SrcIP
    $dstMatch = Find-InterfaceAndMatchForIP $DstIP
    $srcIface = if ($srcMatch) { $srcMatch.Interface } else { $null }
    $dstIface = if ($dstMatch) { $dstMatch.Interface } else { $null }

    if (-not $srcIface) {
        $wanZone = Find-OutsideZone
        if ($wanZone) { $srcIface = [ordered]@{ Name='(external)'; Zone=$wanZone } }
        else { $r.Reason = "No interface matches source IP $SrcIP and no Outside zone found"; $r.Allowed = $false; return $r }
    }
    if (-not $dstIface) {
        $wanZone = Find-OutsideZone
        if ($wanZone) { $dstIface = [ordered]@{ Name='(external)'; Zone=$wanZone } }
        else { $r.Reason = "No interface matches destination IP $DstIP and no Outside zone found"; $r.Allowed = $false; return $r }
    }

    $r.SrcIfaceName = $srcIface.Name; $r.DstIfaceName = $dstIface.Name
    $r.SrcZone = $srcIface.Zone;      $r.DstZone = $dstIface.Zone

    if (-not $r.SrcZone -or -not $r.DstZone) {
        $r.Reason = "Interface has no zone-member assignment"; $r.Allowed = $false; return $r
    }

    if ($r.SrcZone -eq $r.DstZone) {
        $r.IntraZone = $true; $r.Allowed = $true; $r.Reason = "Intra-zone — zone: $($r.SrcZone)"
        return $r
    }

    # VLAN direct-ACL path takes priority, same as the main engine
    foreach ($z in @($r.SrcZone, $r.DstZone)) {
        if (($script:KnownVLANZones -contains $z) -and (Test-KeyExists $script:VLANPolicyDB $z)) {
            $ve = $script:VLANPolicyDB[$z]
            $r.ACLName = $ve.PrimaryACL
            if ($r.Mode -eq 'full') {
                $aclRes = Invoke-ACLEvaluation $ve.PrimaryACL $SrcIP $DstIP $Proto $DstPort
                if ($aclRes.Found -and $aclRes.Hit) {
                    $r.Action = $aclRes.Action; $r.Allowed = ($aclRes.Action -eq 'permit'); $r.ACLLineRaw = $aclRes.Rule
                    if (-not $r.Allowed) { $r.Reason = "VLAN ACL '$($ve.PrimaryACL)' explicit deny" }
                } else {
                    $r.Allowed = $false; $r.Action = 'implicit-deny'; $r.Reason = "VLAN ACL '$($ve.PrimaryACL)' implicit deny (no rule matched)"
                }
            } else {
                $cov = Get-ACLLinesMatchingPair -ACLName $ve.PrimaryACL -SrcIP $SrcIP -DstIP $DstIP -Proto $Proto
                if ($cov.Found -and $cov.Matches.Count -gt 0) {
                    $gov = $cov.Matches | Where-Object { $_.IsFirstWin } | Select-Object -First 1
                    $r.ACLLineSeq = $gov.Seq; $r.ACLLineRaw = $gov.Raw; $r.Action = $gov.Action; $r.Allowed = ($gov.Action -eq 'permit')
                    if (-not $r.Allowed) { $r.Reason = "Governing VLAN ACE (line $($gov.Seq)) is a deny" }
                } else {
                    $r.Allowed = $false; $r.Action = 'implicit-deny'; $r.Reason = "No ACE in VLAN ACL '$($ve.PrimaryACL)' matches both addresses"
                }
            }
            return $r
        }
    }

    $zp = Find-ZonePair $r.SrcZone $r.DstZone
    if (-not $zp) {
        $r.Allowed = $false; $r.Reason = "No zone-pair for $($r.SrcZone) -> $($r.DstZone) (implicit drop)"
        return $r
    }
    $r.ZonePairName = $zp.Name; $r.PolicyMap = $zp.PolicyMap

    if (-not $zp.PolicyMap -or -not (Test-KeyExists $script:PolicyMaps $zp.PolicyMap)) {
        $r.Allowed = $false; $r.Reason = "No usable service-policy on zone-pair '$($zp.Name)'"
        return $r
    }
    $pm = $script:PolicyMaps[$zp.PolicyMap]

    if ($r.Mode -eq 'full') {
        foreach ($cls in $pm.Classes) {
            $action = if ($cls.Action) { $cls.Action } else { 'drop' }
            if ($cls.ClassName -eq 'class-default') {
                $r.MatchedClass = $cls.ClassName; $r.Action = $action; $r.Allowed = ($action -in @('inspect','pass'))
                if (-not $r.Allowed) { $r.Reason = "class-default action: $action" }
                return $r
            }
            if (-not (Test-KeyExists $script:ClassMaps $cls.ClassName)) { continue }
            $cmRes = Invoke-ClassMapEvaluation $cls.ClassName $SrcIP $DstIP $Proto $DstPort
            if ($cmRes.Match) {
                $r.MatchedClass = $cls.ClassName; $r.Action = $action; $r.Allowed = ($action -in @('inspect','pass'))
                $r.ACLLineRaw = $cmRes.MatchedRule
                foreach ($chk in $cmRes.CheckResults) { if ($chk.Type -eq 'acl') { $r.ACLName = $chk.Label -replace '^ACL \[','' -replace '\]$',''; break } }
                if (-not $r.Allowed) { $r.Reason = "Dropped by class '$($cls.ClassName)' (action: $action)" }
                return $r
            }
        }
        $r.Allowed = $false; $r.Reason = "No class map matched — implicit drop"
        return $r
    }
    else {
        foreach ($cls in $pm.Classes) {
            if ($cls.ClassName -eq 'class-default') { continue }
            $action = if ($cls.Action) { $cls.Action } else { 'drop' }
            foreach ($aclName in (Get-ACLsFromClassMap $cls.ClassName)) {
                $cov = Get-ACLLinesMatchingPair -ACLName $aclName -SrcIP $SrcIP -DstIP $DstIP -Proto $Proto
                if ($cov.Found -and $cov.Matches.Count -gt 0) {
                    $gov = $cov.Matches | Where-Object { $_.IsFirstWin } | Select-Object -First 1
                    $r.MatchedClass = $cls.ClassName; $r.ACLName = $aclName
                    $r.ACLLineSeq = $gov.Seq; $r.ACLLineRaw = $gov.Raw; $r.Action = $gov.Action; $r.Allowed = ($gov.Action -eq 'permit')
                    if (-not $r.Allowed) { $r.Reason = "Governing ACE (line $($gov.Seq)) in '$aclName' is a deny" }
                    return $r
                }
            }
        }
        $r.Allowed = $false; $r.Reason = "No ACE in any reachable ACL matches both addresses"
        return $r
    }
}

# ======================================================================
# CONFIG SNAPSHOTS — lets us hold two fully-parsed configs (e.g. a working
# store and a failing store) in memory at once and resolve flows against
# each in turn, without disturbing whichever config the main workspace
# tabs (Output/Validate/Inventory/VLAN Extract) currently have loaded.
# ======================================================================

function Get-ConfigSnapshot {
    [ordered]@{
        Interfaces=$script:Interfaces; Zones=$script:Zones; ZonePairs=$script:ZonePairs
        PolicyMaps=$script:PolicyMaps; ClassMaps=$script:ClassMaps; AccessLists=$script:AccessLists
        VRFs=$script:VRFs; TopologyDB=$script:TopologyDB; VLANPolicyDB=$script:VLANPolicyDB
        ConfigLoaded=$script:ConfigLoaded
    }
}

function Set-ConfigSnapshot {
    param($Snap)
    $script:Interfaces=$Snap.Interfaces; $script:Zones=$Snap.Zones; $script:ZonePairs=$Snap.ZonePairs
    $script:PolicyMaps=$Snap.PolicyMaps; $script:ClassMaps=$Snap.ClassMaps; $script:AccessLists=$Snap.AccessLists
    $script:VRFs=$Snap.VRFs; $script:TopologyDB=$Snap.TopologyDB; $script:VLANPolicyDB=$Snap.VLANPolicyDB
    $script:ConfigLoaded=$Snap.ConfigLoaded
}

function Format-FlowComparison {
    <#
    .SYNOPSIS
        Builds a field-by-field comparison + diagnosis report from two
        ALREADY-RESOLVED Resolve-FlowPath results. Works whether A and B
        came from the same config (two different flows) or two different
        configs (same-shaped flow, different store) — the caller decides
        which config was active when each was resolved.
    #>
    param($A, $B, [string]$LabelA='WORKING', [string]$LabelB='FAILING',
          [string]$DescA, [string]$DescB, [string]$SuggestFixSrc = $null, [string]$SuggestFixDst = $null)

    $output = [System.Collections.ArrayList]@()
    $out = { param([string]$t,[string]$s) [void]$output.Add([PSCustomObject]@{ Text=$t; Style=$s }) }

    & $out "  #=========================================================#" "head"
    & $out "   $LabelA vs $LabelB FLOW COMPARISON" "head"
    & $out "  #=========================================================#" "head"
    & $out "" "info"
    & $out "  $LabelA : $DescA" "ok"
    & $out "  $LabelB : $DescB" "deny"
    & $out "" "info"

    $rows = @(
        @{ Label='Source Interface';   A=$A.SrcIfaceName; B=$B.SrcIfaceName }
        @{ Label='Source Zone';        A=$A.SrcZone;       B=$B.SrcZone }
        @{ Label='Destination Iface';  A=$A.DstIfaceName; B=$B.DstIfaceName }
        @{ Label='Destination Zone';   A=$A.DstZone;       B=$B.DstZone }
        @{ Label='Intra-Zone?';        A=[string]$A.IntraZone; B=[string]$B.IntraZone }
        @{ Label='Zone-Pair';          A=$(if ($A.ZonePairName) { $A.ZonePairName } else { '(none)' }); B=$(if ($B.ZonePairName) { $B.ZonePairName } else { '(none)' }) }
        @{ Label='Policy-Map';         A=$(if ($A.PolicyMap) { $A.PolicyMap } else { '(none)' }); B=$(if ($B.PolicyMap) { $B.PolicyMap } else { '(none)' }) }
        @{ Label='Matched Class';      A=$(if ($A.MatchedClass) { $A.MatchedClass } else { '(none)' }); B=$(if ($B.MatchedClass) { $B.MatchedClass } else { '(none)' }) }
        @{ Label='ACL';                A=$(if ($A.ACLName) { $A.ACLName } else { '(none)' }); B=$(if ($B.ACLName) { $B.ACLName } else { '(none)' }) }
        @{ Label='Governing Line';     A=$(if ($A.ACLLineRaw) { $A.ACLLineRaw } else { '(none)' }); B=$(if ($B.ACLLineRaw) { $B.ACLLineRaw } else { '(none)' }) }
        @{ Label='Action';             A=$(if ($A.Action) { $A.Action } else { '(n/a)' }); B=$(if ($B.Action) { $B.Action } else { '(n/a)' }) }
        @{ Label='Result';             A=$(if ($A.Allowed) { 'ALLOWED' } else { 'DENIED' }); B=$(if ($B.Allowed) { 'ALLOWED' } else { 'DENIED' }) }
    )

    & $out "  FIELD-BY-FIELD COMPARISON" "head"
    & $out "  -----------------------------------------------------------" "detail"
    $diffCount = 0
    foreach ($row in $rows) {
        $same = ($row.A -eq $row.B)
        if (-not $same) { $diffCount++ }
        $style = if ($same) { 'detail' } else { 'warn' }
        $marker = if ($same) { ' ' } else { '*' }
        & $out "  $marker $($row.Label.PadRight(18)) A: $($row.A)" $style
        & $out "  $(' ')$(''.PadRight(18)) B: $($row.B)" $style
    }
    & $out "" "info"

    & $out "  #=========================================================#" "head"
    & $out "   DIAGNOSIS" "head"
    & $out "  #=========================================================#" "head"
    & $out "" "info"

    if ($A.Allowed -and -not $B.Allowed) {
        & $out "  $LabelA flow is ALLOWED; $LabelB flow is DENIED. Likely cause:" "ok"
        & $out "" "info"
        if ($A.ZonePairName -ne $B.ZonePairName -or $A.SrcZone -ne $B.SrcZone -or $A.DstZone -ne $B.DstZone) {
            & $out "  -> The two flows resolve to DIFFERENT zones/zone-pairs. The two configs" "warn"
            & $out "     aren't symmetric for this VLAN -- check that the same VLAN number" "warn"
            & $out "     maps to a zone-member on the right interface in both configs, and" "warn"
            & $out "     that the failing store's local IP is really inside that VLAN's subnet" "warn"
            & $out "     (wrong subnet, missing interface, or a routing/VRF difference)." "warn"
        } elseif ($A.ZonePairName -eq $B.ZonePairName -and $A.PolicyMap -ne $B.PolicyMap) {
            & $out "  -> Same zone-pair name in both configs, but a DIFFERENT (or missing)" "warn"
            & $out "     service-policy is attached in the $LabelB config. Check the" "warn"
            & $out "     'service-policy type inspect <name>' line under the zone-pair." "warn"
        } elseif ($A.ACLName -ne $B.ACLName -or $A.MatchedClass -ne $B.MatchedClass) {
            & $out "  -> Same zone-pair, but the $LabelB config lands on a DIFFERENT class/ACL" "warn"
            & $out "     than $LabelA. Compare the class-map / policy-map definitions for" "warn"
            & $out "     this zone-pair between the two configs (the Compare Configs tool" "warn"
            & $out "     can diff the raw text side by side)." "warn"
        } elseif ($A.ACLName -eq $B.ACLName -and $A.ACLName) {
            & $out "  -> Both resolve to an ACL with the SAME NAME ($($A.ACLName)), but the" "warn"
            & $out "     $LabelB config's version of it doesn't have a matching permit line" "warn"
            & $out "     for this address (or hits a deny first). This is very likely just a" "warn"
            & $out "     missing/incorrect ACE in the $LabelB store's ACL -- probably a copy-paste" "warn"
            & $out "     of the ACL that wasn't updated for this store's subnet. The working" "warn"
            & $out "     store's governing line, to model the fix on:" "warn"
            & $out "       $($A.ACLLineRaw)" "detail"
            if ($SuggestFixSrc -and $SuggestFixDst) {
                & $out "     Suggested line for $LabelB (verify direction/ports before applying):" "detail"
                & $out "       permit <proto> host $SuggestFixSrc host $SuggestFixDst <port-if-needed>" "detail"
            }
        } else {
            & $out "  -> $($B.Reason)" "warn"
        }
    } elseif (-not $A.Allowed -and -not $B.Allowed) {
        & $out "  Both flows are currently DENIED -- the '$LabelA' pair isn't actually" "warn"
        & $out "  permitted by its own config either. Double-check which store is really" "warn"
        & $out "  working, or whether NAT/routing (outside this tool's scope) is involved." "warn"
    } elseif ($A.Allowed -and $B.Allowed) {
        & $out "  Both flows resolve to ALLOWED in their respective configs. If $LabelB" "ok"
        & $out "  is still failing in production, the cause is likely outside the firewall" "ok"
        & $out "  policy itself -- routing, NAT, the destination host/service, or a" "ok"
        & $out "  different device in the path (check for a second hop/firewall)." "ok"
    } else {
        & $out "  $LabelA is DENIED and $LabelB is ALLOWED by these configs -- the labels" "warn"
        & $out "  may be swapped, or $LabelA relies on a path (NAT, alternate route) this" "warn"
        & $out "  tool doesn't model." "warn"
    }

    & $out "" "info"
    & $out "  $diffCount of $($rows.Count) fields differ between the two flows." "info"

    return @{ Output=$output }
}

# ======================================================================
# GUI — Windows Forms

# ======================================================================

[System.Windows.Forms.Application]::EnableVisualStyles()
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

$C_BG_FORM   = [System.Drawing.Color]::FromArgb(16,  17,  24)
$C_BG_TITLE  = [System.Drawing.Color]::FromArgb(12,  14,  30)
$C_BG_INPUT  = [System.Drawing.Color]::FromArgb(28,  31,  48)
$C_BG_FIELD  = [System.Drawing.Color]::FromArgb(36,  40,  60)
$C_BG_RTB    = [System.Drawing.Color]::FromArgb(10,  11,  17)
$C_BG_STATUS = [System.Drawing.Color]::FromArgb(13,  14,  21)
$C_BG_MODE   = [System.Drawing.Color]::FromArgb(20,  24,  40)

$C_FG_TITLE  = [System.Drawing.Color]::FromArgb(110, 190, 255)
$C_FG_LABEL  = [System.Drawing.Color]::FromArgb(140, 158, 200)
$C_FG_HINT   = [System.Drawing.Color]::FromArgb(95,  103, 130)
$C_FG_FIELD  = [System.Drawing.Color]::FromArgb(220, 226, 240)
$C_FG_PATH   = [System.Drawing.Color]::FromArgb(90,  100, 125)
$C_FG_STATUS = [System.Drawing.Color]::FromArgb(105, 113, 140)

$C_BTN_UPLOAD  = [System.Drawing.Color]::FromArgb(32,  75,  145)
$C_BTN_ANALYZE = [System.Drawing.Color]::FromArgb(14,  125,  58)
$C_BTN_CLEAR   = [System.Drawing.Color]::FromArgb(42,  45,   62)

$RTBColors = @{
    head   = [System.Drawing.Color]::FromArgb(96,  178, 255)
    info   = [System.Drawing.Color]::FromArgb(205, 214, 232)
    detail = [System.Drawing.Color]::FromArgb(120, 132, 160)
    ok     = [System.Drawing.Color]::FromArgb(80,  222, 112)
    deny   = [System.Drawing.Color]::FromArgb(255,  84,  84)
    warn   = [System.Drawing.Color]::FromArgb(255, 190,  48)
}

$fUI       = New-Object System.Drawing.Font("Segoe UI",  9)
$fUIBold   = New-Object System.Drawing.Font("Segoe UI",  9,  [System.Drawing.FontStyle]::Bold)
$fTitle    = New-Object System.Drawing.Font("Segoe UI", 13,  [System.Drawing.FontStyle]::Bold)
$fHint     = New-Object System.Drawing.Font("Segoe UI", 7.5, [System.Drawing.FontStyle]::Italic)
$fMono     = New-Object System.Drawing.Font("Consolas", 10)
$fMonoSm   = New-Object System.Drawing.Font("Consolas",  9)
$fMode     = New-Object System.Drawing.Font("Segoe UI",  9.5, [System.Drawing.FontStyle]::Bold)

$form = New-Object System.Windows.Forms.Form
$form.Text          = "ZBFW Analyzer — Coverage & Traffic Simulation"
$form.Size          = New-Object System.Drawing.Size(1460, 840)
$form.MinimumSize   = New-Object System.Drawing.Size(1240, 640)
$form.StartPosition = "CenterScreen"
$form.BackColor     = $C_BG_FORM
$form.ForeColor     = $C_FG_FIELD
$form.Font          = $fUI

# ======================================================================
# LAYOUT — TableLayoutPanel with fixed rows instead of stacked Dock='Top'
# panels. A TableLayoutPanel places each control in an explicit row/column
# index, so rows physically cannot overlap regardless of control-add order,
# DPI scaling, or timing — the class of bug that kept resurfacing with the
# stacked-panel approach. The workspace itself is wrapped in a TabControl
# for a hard, unmistakable visual boundary between header/toolbar and output.
# ======================================================================
$tblMain = New-Object System.Windows.Forms.TableLayoutPanel
$tblMain.Dock = 'Fill'
$tblMain.ColumnCount = 1
$tblMain.RowCount = 4
[void]$tblMain.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$tblMain.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 44)))   # header
[void]$tblMain.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 74)))   # toolbar
[void]$tblMain.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 28)))   # mode banner
[void]$tblMain.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))   # workspace (fills remaining space)
$tblMain.BackColor = $C_BG_FORM
$tblMain.Margin = New-Object System.Windows.Forms.Padding(0)
$tblMain.CellBorderStyle = 'None'

# ── Row 0: Header (title + config path, side by side, one fixed row) ───
$pnlHeader = New-Object System.Windows.Forms.Panel
$pnlHeader.Dock='Fill'; $pnlHeader.BackColor=$C_BG_TITLE; $pnlHeader.Margin = New-Object System.Windows.Forms.Padding(0)
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text="  LEGACY MPLS  |  ZONE-BASED FIREWALL ANALYZER"
$lblTitle.Dock='Left'; $lblTitle.AutoSize=$false; $lblTitle.Width=560
$lblTitle.Font=$fTitle; $lblTitle.ForeColor=$C_FG_TITLE; $lblTitle.TextAlign='MiddleLeft'
$lblConfigPath = New-Object System.Windows.Forms.Label
$lblConfigPath.Text="No configuration loaded — click 'Upload Config' to begin  "
$lblConfigPath.Dock='Fill'; $lblConfigPath.Font=$fMonoSm; $lblConfigPath.ForeColor=$C_FG_PATH; $lblConfigPath.TextAlign='MiddleRight'
$pnlHeader.Controls.Add($lblConfigPath)
$pnlHeader.Controls.Add($lblTitle)

# ── Row 1: Toolbar (input fields + action buttons) ─────────────────────
$pnlInputs = New-Object System.Windows.Forms.Panel
$pnlInputs.Dock='Fill'; $pnlInputs.BackColor=$C_BG_INPUT; $pnlInputs.Margin = New-Object System.Windows.Forms.Padding(0)

function New-FieldGroup {
    param($Parent, [string]$LabelText, [string]$HintText, [int]$X, [int]$W, [string]$Default = '')
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text=$LabelText; $lbl.Location=New-Object System.Drawing.Point($X,6); $lbl.Size=New-Object System.Drawing.Size($W,16)
    $lbl.ForeColor=$C_FG_LABEL; $lbl.Font=New-Object System.Drawing.Font("Segoe UI",7.7,[System.Drawing.FontStyle]::Bold); $lbl.TextAlign='TopLeft'
    $Parent.Controls.Add($lbl)

    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location=New-Object System.Drawing.Point($X,23); $tb.Size=New-Object System.Drawing.Size($W,24)
    $tb.BackColor=$C_BG_FIELD; $tb.ForeColor=$C_FG_FIELD; $tb.BorderStyle='FixedSingle'; $tb.Text=$Default; $tb.Font=$fMonoSm
    $Parent.Controls.Add($tb)

    $hint = New-Object System.Windows.Forms.Label
    $hint.Text=$HintText; $hint.Location=New-Object System.Drawing.Point($X,49); $hint.Size=New-Object System.Drawing.Size($W,16)
    $hint.ForeColor=$C_FG_HINT; $hint.Font=$fHint; $hint.TextAlign='TopLeft'
    $Parent.Controls.Add($hint)
    return $tb
}

$tbSrcIP   = New-FieldGroup $pnlInputs "SOURCE IP  (optional)"       "leave blank to skip"       10  165
$tbDstIP   = New-FieldGroup $pnlInputs "DESTINATION IP  (optional)"  "leave blank to skip"      185  165
$tbProto   = New-FieldGroup $pnlInputs "PROTOCOL  (optional)"        "tcp / udp / icmp / nbar"  360   95
$tbDstPort = New-FieldGroup $pnlInputs "DST PORT  (optional)"        "tcp/udp only"             463   82

$btnAnalyze = New-Object System.Windows.Forms.Button
$btnAnalyze.Text="Analyze"; $btnAnalyze.Size=New-Object System.Drawing.Size(112,44); $btnAnalyze.Location=New-Object System.Drawing.Point(561,17)
$btnAnalyze.FlatStyle='Flat'; $btnAnalyze.BackColor=$C_BTN_ANALYZE; $btnAnalyze.ForeColor=[System.Drawing.Color]::FromArgb(200,255,220)
$btnAnalyze.Font=New-Object System.Drawing.Font("Segoe UI Semibold",10,[System.Drawing.FontStyle]::Bold)
$btnAnalyze.FlatAppearance.BorderSize=1; $btnAnalyze.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(18,175,80)
$pnlInputs.Controls.Add($btnAnalyze)

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text="Clear"; $btnClear.Size=New-Object System.Drawing.Size(66,44); $btnClear.Location=New-Object System.Drawing.Point(681,17)
$btnClear.FlatStyle='Flat'; $btnClear.BackColor=$C_BTN_CLEAR; $btnClear.ForeColor=[System.Drawing.Color]::FromArgb(155,163,185)
$btnClear.Font=$fUI; $btnClear.FlatAppearance.BorderSize=1; $btnClear.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(55,60,82)
$pnlInputs.Controls.Add($btnClear)

$btnValidate = New-Object System.Windows.Forms.Button
$btnValidate.Text="Validate"; $btnValidate.Size=New-Object System.Drawing.Size(80,44); $btnValidate.Location=New-Object System.Drawing.Point(755,17)
$btnValidate.FlatStyle='Flat'; $btnValidate.BackColor=[System.Drawing.Color]::FromArgb(65,42,8); $btnValidate.ForeColor=[System.Drawing.Color]::FromArgb(255,190,48)
$btnValidate.Font=$fUI; $btnValidate.FlatAppearance.BorderSize=1; $btnValidate.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(120,85,20)
$pnlInputs.Controls.Add($btnValidate)

$btnInventory = New-Object System.Windows.Forms.Button
$btnInventory.Text="Inventory"; $btnInventory.Size=New-Object System.Drawing.Size(92,44); $btnInventory.Location=New-Object System.Drawing.Point(843,17)
$btnInventory.FlatStyle='Flat'; $btnInventory.BackColor=[System.Drawing.Color]::FromArgb(12,40,65); $btnInventory.ForeColor=[System.Drawing.Color]::FromArgb(96,178,255)
$btnInventory.Font=$fUI; $btnInventory.FlatAppearance.BorderSize=1; $btnInventory.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(40,90,140)
$pnlInputs.Controls.Add($btnInventory)

$btnUpload = New-Object System.Windows.Forms.Button
$btnUpload.Text="Upload Config"; $btnUpload.Size=New-Object System.Drawing.Size(130,44); $btnUpload.Location=New-Object System.Drawing.Point(943,17)
$btnUpload.FlatStyle='Flat'; $btnUpload.BackColor=$C_BTN_UPLOAD; $btnUpload.ForeColor=[System.Drawing.Color]::FromArgb(200,220,255)
$btnUpload.Font=$fUIBold; $btnUpload.FlatAppearance.BorderSize=1; $btnUpload.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(55,100,185)
$pnlInputs.Controls.Add($btnUpload)

$btnCompareConfigs = New-Object System.Windows.Forms.Button
$btnCompareConfigs.Text="Compare Configs"; $btnCompareConfigs.Size=New-Object System.Drawing.Size(140,44); $btnCompareConfigs.Location=New-Object System.Drawing.Point(1083,17)
$btnCompareConfigs.FlatStyle='Flat'; $btnCompareConfigs.BackColor=[System.Drawing.Color]::FromArgb(45,20,80); $btnCompareConfigs.ForeColor=[System.Drawing.Color]::FromArgb(190,140,255)
$btnCompareConfigs.Font=$fUIBold; $btnCompareConfigs.FlatAppearance.BorderSize=1; $btnCompareConfigs.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(110,60,180)
$pnlInputs.Controls.Add($btnCompareConfigs)

# ── Row 2: Mode banner ──────────────────────────────────────────────────
$pnlMode = New-Object System.Windows.Forms.Panel
$pnlMode.Dock='Fill'; $pnlMode.BackColor=$C_BG_MODE; $pnlMode.Margin = New-Object System.Windows.Forms.Padding(0)
$lblMode = New-Object System.Windows.Forms.Label
$lblMode.Text="   Mode: fill in any combination of fields above — Analyze adapts automatically"
$lblMode.Dock='Fill'; $lblMode.Font=$fMode; $lblMode.ForeColor=[System.Drawing.Color]::FromArgb(150,190,255); $lblMode.TextAlign='MiddleLeft'
$pnlMode.Controls.Add($lblMode)

# ── Row 3: Workspace — TabControl wrapping the output pane ─────────────
# A dedicated tab page gives the report area a hard, native-drawn boundary
# distinct from the header/toolbar above it — no shared Dock stack, no
# possibility of another panel bleeding into its space.
$tabMain = New-Object System.Windows.Forms.TabControl
$tabMain.Dock = 'Fill'
$tabMain.Margin = New-Object System.Windows.Forms.Padding(6,4,6,4)
$tabMain.Font = $fUI
$tabMain.BackColor = $C_BG_FORM

# Default TabControl rendering ignores dark themes entirely (stuck with a
# washed-out system-white tab strip). Owner-draw it instead so the selected
# tab is unmistakably highlighted against the unselected ones.
$tabMain.DrawMode = 'OwnerDrawFixed'
$tabMain.ItemSize = New-Object System.Drawing.Size(150, 34)
$tabMain.SizeMode = 'Fixed'
$tabFontSel   = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$tabFontUnsel = New-Object System.Drawing.Font("Segoe UI", 9.5)
$tabMain.Add_DrawItem({
    param($sender, $e)
    $tabPage = $sender.TabPages[$e.Index]
    $isSel = ($e.Index -eq $sender.SelectedIndex)
    $bg = if ($isSel) { [System.Drawing.Color]::FromArgb(34, 40, 64) } else { [System.Drawing.Color]::FromArgb(15, 16, 24) }
    $fg = if ($isSel) { [System.Drawing.Color]::FromArgb(130, 200, 255) } else { [System.Drawing.Color]::FromArgb(120, 128, 150) }
    $br = New-Object System.Drawing.SolidBrush($bg)
    $e.Graphics.FillRectangle($br, $e.Bounds)
    $br.Dispose()
    if ($isSel) {
        $accentBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(96, 178, 255))
        $accentRect = New-Object System.Drawing.Rectangle($e.Bounds.Left, ($e.Bounds.Bottom - 3), $e.Bounds.Width, 3)
        $e.Graphics.FillRectangle($accentBrush, $accentRect)
        $accentBrush.Dispose()
    }
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
    $textBrush = New-Object System.Drawing.SolidBrush($fg)
    $font = if ($isSel) { $tabFontSel } else { $tabFontUnsel }
    $e.Graphics.DrawString($tabPage.Text, $font, $textBrush, [System.Drawing.RectangleF]$e.Bounds, $sf)
    $textBrush.Dispose()
})

$tabOutput = New-Object System.Windows.Forms.TabPage
$tabOutput.Text = "Output"
$tabOutput.BackColor = $C_BG_RTB
$tabOutput.Padding = New-Object System.Windows.Forms.Padding(0)
[void]$tabMain.TabPages.Add($tabOutput)

# ── Tab: Store Compare (working store config vs failing store config) ──
$tabCompareFlow = New-Object System.Windows.Forms.TabPage
$tabCompareFlow.Text = "Store Compare"
$tabCompareFlow.BackColor = $C_BG_INPUT
$tabCompareFlow.Padding = New-Object System.Windows.Forms.Padding(0)
[void]$tabMain.TabPages.Add($tabCompareFlow)

$pnlCmpInputs = New-Object System.Windows.Forms.Panel
$pnlCmpInputs.Dock = 'Top'; $pnlCmpInputs.Height = 300; $pnlCmpInputs.BackColor = $C_BG_INPUT
$tabCompareFlow.Controls.Add($pnlCmpInputs)

function New-FieldGroupAt {
    param($Parent, [string]$LabelText, [int]$X, [int]$Y, [int]$W, [string]$Default = '')
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text=$LabelText; $lbl.Location=New-Object System.Drawing.Point($X,$Y); $lbl.Size=New-Object System.Drawing.Size($W,15)
    $lbl.ForeColor=$C_FG_LABEL; $lbl.Font=New-Object System.Drawing.Font("Segoe UI",7.3,[System.Drawing.FontStyle]::Bold); $lbl.TextAlign='TopLeft'
    $Parent.Controls.Add($lbl)
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location=New-Object System.Drawing.Point($X,($Y+19)); $tb.Size=New-Object System.Drawing.Size($W,24)
    $tb.BackColor=$C_BG_FIELD; $tb.ForeColor=$C_FG_FIELD; $tb.BorderStyle='FixedSingle'; $tb.Text=$Default; $tb.Font=$fMonoSm
    $Parent.Controls.Add($tb)
    return $tb
}

# Row 0: shared external endpoint + direction + optional proto/port
$lblCmpShared = New-Object System.Windows.Forms.Label
$lblCmpShared.Text = "SHARED SETTINGS  (applied to both stores)"
$lblCmpShared.Location = New-Object System.Drawing.Point(10,10); $lblCmpShared.Size = New-Object System.Drawing.Size(400,16)
$lblCmpShared.ForeColor = [System.Drawing.Color]::FromArgb(150,190,255); $lblCmpShared.Font = $fUIBold
$pnlCmpInputs.Controls.Add($lblCmpShared)

$tbExternalIP = New-FieldGroupAt $pnlCmpInputs "EXTERNAL / SHARED IP (e.g. Aura server)"  10  32 250
$tbCmpProto   = New-FieldGroupAt $pnlCmpInputs "PROTOCOL (optional)"                     270  32  95
$tbCmpPort    = New-FieldGroupAt $pnlCmpInputs "DST PORT (optional)"                     375  32  82

$lblDirection = New-Object System.Windows.Forms.Label
$lblDirection.Text = "DIRECTION"
$lblDirection.Location = New-Object System.Drawing.Point(467,32); $lblDirection.Size = New-Object System.Drawing.Size(200,14)
$lblDirection.ForeColor=$C_FG_LABEL; $lblDirection.Font=New-Object System.Drawing.Font("Segoe UI",7.3,[System.Drawing.FontStyle]::Bold)
$pnlCmpInputs.Controls.Add($lblDirection)
$cmbDirection = New-Object System.Windows.Forms.ComboBox
$cmbDirection.Location = New-Object System.Drawing.Point(467,51); $cmbDirection.Size = New-Object System.Drawing.Size(210,24)
$cmbDirection.DropDownStyle = 'DropDownList'; $cmbDirection.Font=$fMonoSm
[void]$cmbDirection.Items.Add("Store -> External")
[void]$cmbDirection.Items.Add("External -> Store")
$cmbDirection.SelectedIndex = 0
$pnlCmpInputs.Controls.Add($cmbDirection)

# Row 1: Working store
$lblCmpWorking = New-Object System.Windows.Forms.Label
$lblCmpWorking.Text = "WORKING STORE"
$lblCmpWorking.Location = New-Object System.Drawing.Point(10,96); $lblCmpWorking.Size = New-Object System.Drawing.Size(130,16)
$lblCmpWorking.ForeColor = [System.Drawing.Color]::FromArgb(80,222,112); $lblCmpWorking.Font = $fUIBold
$pnlCmpInputs.Controls.Add($lblCmpWorking)

$btnLoadStoreA = New-Object System.Windows.Forms.Button
$btnLoadStoreA.Text="Load Config"; $btnLoadStoreA.Size=New-Object System.Drawing.Size(100,26); $btnLoadStoreA.Location=New-Object System.Drawing.Point(150,92)
$btnLoadStoreA.FlatStyle='Flat'; $btnLoadStoreA.BackColor=$C_BTN_UPLOAD; $btnLoadStoreA.ForeColor=[System.Drawing.Color]::FromArgb(200,220,255); $btnLoadStoreA.Font=$fUI
$btnLoadStoreA.FlatAppearance.BorderSize=1; $btnLoadStoreA.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(55,100,185)
$pnlCmpInputs.Controls.Add($btnLoadStoreA)

$lblStoreAPath = New-Object System.Windows.Forms.Label
$lblStoreAPath.Text = "(no config loaded)"
$lblStoreAPath.Location = New-Object System.Drawing.Point(260,99); $lblStoreAPath.Size = New-Object System.Drawing.Size(420,16)
$lblStoreAPath.ForeColor = $C_FG_PATH; $lblStoreAPath.Font = $fMonoSm
$pnlCmpInputs.Controls.Add($lblStoreAPath)

$tbStoreALocalIP = New-FieldGroupAt $pnlCmpInputs "STORE A LOCAL IP (e.g. its printer)" 10 132 250

$lblCmpFailing = New-Object System.Windows.Forms.Label
$lblCmpFailing.Text = "FAILING STORE"
$lblCmpFailing.Location = New-Object System.Drawing.Point(10,200); $lblCmpFailing.Size = New-Object System.Drawing.Size(130,16)
$lblCmpFailing.ForeColor = [System.Drawing.Color]::FromArgb(255,84,84); $lblCmpFailing.Font = $fUIBold
$pnlCmpInputs.Controls.Add($lblCmpFailing)

$btnLoadStoreB = New-Object System.Windows.Forms.Button
$btnLoadStoreB.Text="Load Config"; $btnLoadStoreB.Size=New-Object System.Drawing.Size(100,26); $btnLoadStoreB.Location=New-Object System.Drawing.Point(150,196)
$btnLoadStoreB.FlatStyle='Flat'; $btnLoadStoreB.BackColor=$C_BTN_UPLOAD; $btnLoadStoreB.ForeColor=[System.Drawing.Color]::FromArgb(200,220,255); $btnLoadStoreB.Font=$fUI
$btnLoadStoreB.FlatAppearance.BorderSize=1; $btnLoadStoreB.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(55,100,185)
$pnlCmpInputs.Controls.Add($btnLoadStoreB)

$lblStoreBPath = New-Object System.Windows.Forms.Label
$lblStoreBPath.Text = "(no config loaded)"
$lblStoreBPath.Location = New-Object System.Drawing.Point(260,203); $lblStoreBPath.Size = New-Object System.Drawing.Size(420,16)
$lblStoreBPath.ForeColor = $C_FG_PATH; $lblStoreBPath.Font = $fMonoSm
$pnlCmpInputs.Controls.Add($lblStoreBPath)

$tbStoreBLocalIP = New-FieldGroupAt $pnlCmpInputs "STORE B LOCAL IP (e.g. its printer)" 10 236 250

$btnCompareFlows = New-Object System.Windows.Forms.Button
$btnCompareFlows.Text="Compare Stores"; $btnCompareFlows.Size=New-Object System.Drawing.Size(150,204); $btnCompareFlows.Location=New-Object System.Drawing.Point(697,92)
$btnCompareFlows.FlatStyle='Flat'; $btnCompareFlows.BackColor=$C_BTN_ANALYZE; $btnCompareFlows.ForeColor=[System.Drawing.Color]::FromArgb(200,255,220)
$btnCompareFlows.Font=New-Object System.Drawing.Font("Segoe UI Semibold",10,[System.Drawing.FontStyle]::Bold)
$btnCompareFlows.FlatAppearance.BorderSize=1; $btnCompareFlows.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(18,175,80)
$pnlCmpInputs.Controls.Add($btnCompareFlows)

$rtbCompare = New-Object System.Windows.Forms.RichTextBox
$rtbCompare.Dock='Fill'; $rtbCompare.BackColor=$C_BG_RTB; $rtbCompare.ForeColor=$C_FG_FIELD; $rtbCompare.Font=$fMono
$rtbCompare.ReadOnly=$true; $rtbCompare.BorderStyle='None'; $rtbCompare.ScrollBars='Both'; $rtbCompare.WordWrap=$false
$rtbCompare.Padding=New-Object System.Windows.Forms.Padding(6)
$tabCompareFlow.Controls.Add($rtbCompare)
$rtbCompare.BringToFront()

$script:CmpBuffer = [System.Collections.ArrayList]@()
function Add-CmpLine { param([string]$Text,[string]$Style) [void]$script:CmpBuffer.Add([PSCustomObject]@{ Text=$Text; Style=$Style }) }
function Start-CmpBatch { $script:CmpBuffer = [System.Collections.ArrayList]@() }
function Complete-CmpBatch { Set-RTBReport -RtbCtrl $rtbCompare -Rtf (Build-RTFDocument -Buffer $script:CmpBuffer) }

# ── Tab: VLAN IP Extract ────────────────────────────────────────────────
$tabVLAN = New-Object System.Windows.Forms.TabPage
$tabVLAN.Text = "VLAN Extract"
$tabVLAN.BackColor = $C_BG_INPUT
$tabVLAN.Padding = New-Object System.Windows.Forms.Padding(0)
[void]$tabMain.TabPages.Add($tabVLAN)

$pnlVlanBar = New-Object System.Windows.Forms.Panel
$pnlVlanBar.Dock='Top'; $pnlVlanBar.Height=44; $pnlVlanBar.BackColor=$C_BG_INPUT
$tabVLAN.Controls.Add($pnlVlanBar)

$btnExtractVLAN = New-Object System.Windows.Forms.Button
$btnExtractVLAN.Text="Extract VLAN / Zone IPs"; $btnExtractVLAN.Size=New-Object System.Drawing.Size(180,32); $btnExtractVLAN.Location=New-Object System.Drawing.Point(10,6)
$btnExtractVLAN.FlatStyle='Flat'; $btnExtractVLAN.BackColor=$C_BTN_UPLOAD; $btnExtractVLAN.ForeColor=[System.Drawing.Color]::FromArgb(200,220,255)
$btnExtractVLAN.Font=$fUIBold; $btnExtractVLAN.FlatAppearance.BorderSize=1; $btnExtractVLAN.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(55,100,185)
$pnlVlanBar.Controls.Add($btnExtractVLAN)

$rtbVLAN = New-Object System.Windows.Forms.RichTextBox
$rtbVLAN.Dock='Fill'; $rtbVLAN.BackColor=$C_BG_RTB; $rtbVLAN.ForeColor=$C_FG_FIELD; $rtbVLAN.Font=$fMono
$rtbVLAN.ReadOnly=$true; $rtbVLAN.BorderStyle='None'; $rtbVLAN.ScrollBars='Both'; $rtbVLAN.WordWrap=$false
$rtbVLAN.Padding=New-Object System.Windows.Forms.Padding(6)
$tabVLAN.Controls.Add($rtbVLAN)
$rtbVLAN.BringToFront()

$script:VlanBuffer = [System.Collections.ArrayList]@()
function Add-VlanLine { param([string]$Text,[string]$Style) [void]$script:VlanBuffer.Add([PSCustomObject]@{ Text=$Text; Style=$Style }) }
function Start-VlanBatch { $script:VlanBuffer = [System.Collections.ArrayList]@() }
function Complete-VlanBatch { Set-RTBReport -RtbCtrl $rtbVLAN -Rtf (Build-RTFDocument -Buffer $script:VlanBuffer) }

# Assemble the table
$tblMain.Controls.Add($pnlHeader,  0, 0)
$tblMain.Controls.Add($pnlInputs,  0, 1)
$tblMain.Controls.Add($pnlMode,    0, 2)
$tblMain.Controls.Add($tabMain,    0, 3)

# ── Status bar (single Dock='Bottom' control — no stacking ambiguity) ──
$pnlStatus = New-Object System.Windows.Forms.Panel
$pnlStatus.Dock='Bottom'; $pnlStatus.Height=26; $pnlStatus.BackColor=$C_BG_STATUS
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text="   Ready — load a Cisco IOS running-config to begin"
$lblStatus.Dock='Fill'; $lblStatus.Font=New-Object System.Drawing.Font("Segoe UI",8); $lblStatus.ForeColor=$C_FG_STATUS; $lblStatus.TextAlign='MiddleLeft'
$pnlStatus.Controls.Add($lblStatus)

# Add Bottom-docked status bar FIRST, then the Fill table — Fill always
# yields to whatever space Bottom/Top docks have already claimed, so this
# order is unambiguous regardless of the earlier stacking-order pitfall.
$form.Controls.Add($pnlStatus)
$form.Controls.Add($tblMain)

# ── Output RichTextBox — lives inside the Output tab page ──────────────
# REDESIGN NOTE: earlier versions streamed each line in with AppendText(),
# which continuously auto-scrolls to follow the newest text as it's typed —
# fine for a live tail, wrong for a report you want to read from line 1.
# Instead we now buffer every line for a report, render the whole thing as
# one RTF document, and load it into the control in a single assignment.
# A single content-load has no "follow the cursor" behavior and always
# starts at the top, so no scroll-correction hacks are needed at all.
$rtb = New-Object System.Windows.Forms.RichTextBox
$rtb.Dock='Fill'; $rtb.BackColor=$C_BG_RTB; $rtb.ForeColor=$C_FG_FIELD; $rtb.Font=$fMono
$rtb.ReadOnly=$true; $rtb.BorderStyle='None'; $rtb.ScrollBars='Both'; $rtb.WordWrap=$false
$rtb.Padding=New-Object System.Windows.Forms.Padding(6)
$tabOutput.Controls.Add($rtb)

$script:RTBBuffer = [System.Collections.ArrayList]@()

# RTF color-table order — index 0 is reserved (auto/default) per the RTF spec,
# so real colors start at \cf1.
$script:RTFColorOrder = @('info','head','detail','ok','deny','warn')
$script:RTFColorIndex = @{}
for ($i = 0; $i -lt $script:RTFColorOrder.Count; $i++) { $script:RTFColorIndex[$script:RTFColorOrder[$i]] = $i + 1 }

function ConvertTo-RtfEscaped {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int][char]$ch
        if     ($ch -eq '\' -or $ch -eq '{' -or $ch -eq '}') { [void]$sb.Append('\').Append($ch) }
        elseif ($code -gt 126)                                { [void]$sb.Append('\u').Append($code).Append('?') }
        else                                                    { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

function Add-RTBLine {
    # Buffers a line for the report currently being built — does NOT touch
    # the control directly. Call Start-RTBBatch first and Complete-RTBBatch
    # (or Complete-RTBBatch) when done.
    param([string]$Text, [string]$Style)
    [void]$script:RTBBuffer.Add([PSCustomObject]@{ Text=$Text; Style=$Style })
}

function Start-RTBBatch {
    $script:RTBBuffer = [System.Collections.ArrayList]@()
}

function Build-RTFDocument {
    # Shared RTF renderer — used by every output pane (main report, compare
    # tools, etc.) so the "load once, no scroll hacks needed" design applies
    # everywhere, not just the main Output tab.
    param([System.Collections.ArrayList]$Buffer)
    $sbColors = New-Object System.Text.StringBuilder
    [void]$sbColors.Append('{\colortbl ;')
    foreach ($k in $script:RTFColorOrder) {
        $c = $RTBColors[$k]
        [void]$sbColors.Append("\red$($c.R)\green$($c.G)\blue$($c.B);")
    }
    [void]$sbColors.Append('}')

    $sbBody = New-Object System.Text.StringBuilder
    foreach ($ln in $Buffer) {
        $cfN = if ($script:RTFColorIndex.ContainsKey($ln.Style)) { $script:RTFColorIndex[$ln.Style] } else { $script:RTFColorIndex['info'] }
        $escaped = ConvertTo-RtfEscaped $ln.Text
        if ([string]::IsNullOrEmpty($escaped)) {
            [void]$sbBody.Append('\par' + "`n")
        } else {
            [void]$sbBody.Append("\cf$cfN $escaped\par" + "`n")
        }
    }
    return "{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0\fmodern\fcharset0 Consolas;}}" + $sbColors.ToString() + "\f0\fs20 " + $sbBody.ToString() + "}"
}

function Set-RTBReport {
    # Loads an RTF document into a given RichTextBox in one shot and forces
    # the repaint fix (see notes on Complete-RTBBatch below).
    param($RtbCtrl, [string]$Rtf)
    $RtbCtrl.Rtf = $Rtf
    $RtbCtrl.SelectionStart = $RtbCtrl.TextLength
    $RtbCtrl.ScrollToCaret()
    $RtbCtrl.SelectionStart  = 0
    $RtbCtrl.SelectionLength = 0
    $RtbCtrl.ScrollToCaret()
    $RtbCtrl.Invalidate()
    $RtbCtrl.Update()
    $RtbCtrl.Refresh()
}

function Complete-RTBBatch {
    # Build one RTF document for the whole buffered report and load it in a
    # single shot — guarantees the view starts at line 1 every time.
    $rtf = Build-RTFDocument -Buffer $script:RTBBuffer
    Set-RTBReport -RtbCtrl $rtb -Rtf $rtf
}

function Show-WelcomeBanner {
    Start-RTBBatch
    Add-RTBLine "  #=========================================================#" "head"
    Add-RTBLine "   LEGACY MPLS  |  ZONE-BASED FIREWALL ANALYZER" "head"
    Add-RTBLine "   Cisco IOS ZBFW Traffic Simulation + ACL Coverage Engine" "head"
    Add-RTBLine "  #=========================================================#" "head"
    Add-RTBLine "" "info"
    Add-RTBLine "  All four traffic fields are OPTIONAL. What you fill in decides" "detail"
    Add-RTBLine "  the kind of analysis you get:" "detail"
    Add-RTBLine "" "info"
    Add-RTBLine "    Source IP only          -> ACL coverage for every zone-pair" "detail"
    Add-RTBLine "                               where this address is a SOURCE" "detail"
    Add-RTBLine "    Destination IP only     -> ACL coverage for every zone-pair" "detail"
    Add-RTBLine "                               where this address is a DESTINATION" "detail"
    Add-RTBLine "    Source + Destination    -> every ACE across the applicable ACL(s)" "detail"
    Add-RTBLine "    (protocol/port blank)      that both addresses satisfy, port-agnostic" "detail"
    Add-RTBLine "    Source + Dest + Proto   -> full first-match verdict, exactly like" "detail"
    Add-RTBLine "    + Port (all 4 fields)      real ZBFW packet processing" "detail"
    Add-RTBLine "" "info"
    Add-RTBLine "  Toolbar buttons:" "detail"
    Add-RTBLine "    Analyze   — runs whichever mode your filled-in fields select" "detail"
    Add-RTBLine "    Validate  — config integrity check (missing ACLs, orphans, etc.)" "detail"
    Add-RTBLine "    Inventory — config object count statistics + VLAN ACL map" "detail"
    Add-RTBLine "" "info"
    Add-RTBLine "  Load a Cisco IOS running-config to begin." "info"
    Add-RTBLine "" "info"
    Complete-RTBBatch
}

# NOTE: intentionally NOT calling Show-WelcomeBanner here. Doing so before the
# form has an on-screen handle/size means the RTB fills while still at its
# tiny pre-layout size, auto-scrolling down to keep pace — leaving the view
# scrolled past the top once the real window appears. It's called instead
# from $form.Add_Shown, below, once the control has its true final size.

# ======================================================================
# CONFIG COMPARE — restored feature: diffs two full config files
# side-by-side in a dedicated window (kept modal so it doesn't compete
# for space with the main workspace tabs).
# ======================================================================

# ── Fast diff engine (Myers O(ND), compiled once per session) ─────────
$script:FastDiffOK = $false
try {
    $null = [FastLineDiff]
    $script:FastDiffOK = $true
} catch {
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
public class DiffEdit {
    public string Tag;
    public int    IdxA, IdxB;
    public string LineA, LineB;
}
public static class FastLineDiff {
    public static DiffEdit[] Diff(string[] A, string[] B) {
        int N = A.Length, M = B.Length, MAX = N + M;
        if (MAX == 0) return new DiffEdit[0];
        int   offset = MAX;
        int[] V      = new int[2 * MAX + 2];
        var   Vs     = new List<int[]>(MAX + 1);
        for (int D = 0; D <= MAX; D++) {
            var snap = new int[2 * MAX + 2];
            Array.Copy(V, snap, V.Length);
            Vs.Add(snap);
            for (int k = -D; k <= D; k += 2) {
                int ki = k + offset, x;
                if (k == -D || (k != D && V[ki - 1] < V[ki + 1]))
                    x = V[ki + 1];
                else
                    x = V[ki - 1] + 1;
                int y = x - k;
                while (x < N && y < M && A[x] == B[y]) { x++; y++; }
                V[ki] = x;
                if (x >= N && y >= M) {
                    var edits = new List<DiffEdit>(D * 2 + N + M);
                    int cx = x, cy = y;
                    for (int d = D; d > 0; d--) {
                        int[] pv  = Vs[d];
                        int   kk  = cx - cy, kki = kk + offset;
                        bool isDown = (kk == -d) || (kk != d && pv[kki - 1] < pv[kki + 1]);
                        int xStart, yStart, xMid, yMid;
                        if (isDown) {
                            xStart = pv[kki + 1]; yStart = xStart - (kk + 1);
                            xMid   = xStart;      yMid   = yStart + 1;
                        } else {
                            xStart = pv[kki - 1]; yStart = xStart - (kk - 1);
                            xMid   = xStart + 1;  yMid   = yStart;
                        }
                        while (cx > xMid && cy > yMid) {
                            cx--; cy--;
                            edits.Add(new DiffEdit { Tag="equal",  IdxA=cx, IdxB=cy, LineA=A[cx], LineB=B[cy] });
                        }
                        if (!isDown) { cx--; edits.Add(new DiffEdit { Tag="delete", IdxA=cx, IdxB=-1, LineA=A[cx], LineB=null   }); }
                        else         { cy--; edits.Add(new DiffEdit { Tag="insert", IdxA=-1, IdxB=cy, LineA=null,  LineB=B[cy]  }); }
                    }
                    while (cx > 0 && cy > 0) {
                        cx--; cy--;
                        edits.Add(new DiffEdit { Tag="equal", IdxA=cx, IdxB=cy, LineA=A[cx], LineB=B[cy] });
                    }
                    edits.Reverse();
                    return edits.ToArray();
                }
            }
        }
        return new DiffEdit[0];
    }
}
'@
        $script:FastDiffOK = $true
    } catch { }
}

# ── Scroll-sync helper for the two diff panes ──────────────────────────
$script:CmpScrollOK = $false
try {
    $null = [CmpScrollHelper]
    $script:CmpScrollOK = $true
} catch {
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CmpScrollHelper {
    [DllImport("user32.dll")]
    public static extern int GetScrollPos(IntPtr hWnd, int nBar);
    [DllImport("user32.dll")]
    public static extern IntPtr SendMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);
}
'@
        $script:CmpScrollOK = $true
    } catch { }
}

function Get-NormalisedLine {
    param([string]$Line, [bool]$IgnoreCosmetic)
    if ($IgnoreCosmetic) {
        $t = $Line.Trim()
        if ($t -eq '!' -or $t -eq 'end' -or $t -eq '') { return $null }
        return $t
    }
    return $Line.TrimEnd()
}

function Invoke-LineDiff {
    param([string[]]$LinesA, [string[]]$LinesB)
    if ($script:FastDiffOK) { return [FastLineDiff]::Diff($LinesA, $LinesB) }
    $edits = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $LinesA.Count; $i++) { [void]$edits.Add([pscustomobject]@{ Tag='delete'; IdxA=$i; IdxB=-1; LineA=$LinesA[$i]; LineB=$null }) }
    for ($j = 0; $j -lt $LinesB.Count; $j++) { [void]$edits.Add([pscustomobject]@{ Tag='insert'; IdxA=-1; IdxB=$j; LineA=$null; LineB=$LinesB[$j] }) }
    return $edits.ToArray()
}

function Merge-AdjacentEdits {
    param($Edits)
    $result = [System.Collections.Generic.List[object]]::new(); $i = 0
    while ($i -lt $Edits.Count) {
        $e = $Edits[$i]
        if ($e.Tag -eq 'delete' -and ($i + 1) -lt $Edits.Count -and $Edits[$i + 1].Tag -eq 'insert') {
            [void]$result.Add(@{ Tag='change'; IdxA=$e.IdxA; IdxB=$Edits[$i+1].IdxB; LineA=$e.LineA; LineB=$Edits[$i+1].LineB }); $i += 2
        } else { [void]$result.Add($e); $i++ }
    }
    return $result.ToArray()
}

function Export-DiffReport {
    param([string]$PathA, [string]$PathB, $MergedEdits, [string]$Format, [string]$SavePath)
    $ts    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $adds  = ($MergedEdits | Where-Object { $_.Tag -eq 'insert' }).Count
    $dels  = ($MergedEdits | Where-Object { $_.Tag -eq 'delete' }).Count
    $chgs  = ($MergedEdits | Where-Object { $_.Tag -eq 'change' }).Count
    if ($Format -eq 'html') {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Config Diff Report</title>')
        [void]$sb.AppendLine('<style>body{font-family:Consolas,monospace;font-size:13px;background:#0b0c12;color:#c6d0e4;margin:20px}h2{color:#58a8ff}table{border-collapse:collapse;width:100%}th{background:#181822;color:#58a8ff;padding:4px 10px;text-align:left}td{padding:2px 10px;vertical-align:top;white-space:pre}.add{background:#0d3320;color:#48d466}.del{background:#3a0d0d;color:#ff4848}.chg{background:#3a2e00;color:#ffb626}.ln{color:#3a4060;min-width:40px;text-align:right;padding-right:8px}</style></head><body>')
        [void]$sb.AppendLine("<h2>Config Diff Report</h2><p><b>File A:</b> $([System.Security.SecurityElement]::Escape($PathA))<br><b>File B:</b> $([System.Security.SecurityElement]::Escape($PathB))<br><b>Generated:</b> $ts<br><b>Summary:</b> $adds added &nbsp; $dels removed &nbsp; $chgs modified</p>")
        [void]$sb.AppendLine('<table><tr><th>#</th><th>Config A</th><th>#</th><th>Config B</th></tr>')
        foreach ($e in $MergedEdits) {
            $cls = switch ($e.Tag) { 'insert' { 'add' } 'delete' { 'del' } 'change' { 'chg' } default { '' } }
            $lnA = if ($e.IdxA -ge 0) { $e.IdxA + 1 } else { '' }
            $lnB = if ($e.IdxB -ge 0) { $e.IdxB + 1 } else { '' }
            $tA  = if ($e.LineA) { [System.Security.SecurityElement]::Escape($e.LineA) } else { '' }
            $tB  = if ($e.LineB) { [System.Security.SecurityElement]::Escape($e.LineB) } else { '' }
            [void]$sb.AppendLine("<tr$(if($cls){" class='$cls'"})><td class='ln'>$lnA</td><td>$tA</td><td class='ln'>$lnB</td><td>$tB</td></tr>")
        }
        [void]$sb.AppendLine('</table></body></html>')
        [System.IO.File]::WriteAllText($SavePath, $sb.ToString(), [System.Text.Encoding]::UTF8)
    } else {
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add("Config Diff Report"); $lines.Add("==================")
        $lines.Add("File A    : $PathA"); $lines.Add("File B    : $PathB")
        $lines.Add("Generated : $ts")
        $lines.Add("Summary   : $adds added  $dels removed  $chgs modified"); $lines.Add("")
        foreach ($e in $MergedEdits) {
            if     ($e.Tag -eq 'change') { $lines.Add("- $($e.LineA)"); $lines.Add("+ $($e.LineB)") }
            elseif ($e.Tag -eq 'insert') { $lines.Add("+ $($e.LineB)") }
            elseif ($e.Tag -eq 'delete') { $lines.Add("- $($e.LineA)") }
            else                         { $lines.Add("  $($e.LineA)") }
        }
        [System.IO.File]::WriteAllLines($SavePath, $lines, [System.Text.Encoding]::UTF8)
    }
}

function Show-CompareWindow {
    $CB_BG   = [System.Drawing.Color]::FromArgb(13, 14, 22)
    $CB_PANE = [System.Drawing.Color]::FromArgb(11, 12, 18)
    $CB_HDR  = [System.Drawing.Color]::FromArgb(18, 20, 35)
    $CB_BTN  = [System.Drawing.Color]::FromArgb(32, 35, 55)
    $CB_INFO = [System.Drawing.Color]::FromArgb(95, 103, 130)
    $C_EQ   = [System.Drawing.Color]::FromArgb(198, 208, 228)
    $C_ADD  = [System.Drawing.Color]::FromArgb(72,  212, 102)
    $C_DEL  = [System.Drawing.Color]::FromArgb(255,  72,  72)
    $C_CHG  = [System.Drawing.Color]::FromArgb(255, 182,  38)
    $C_LN   = [System.Drawing.Color]::FromArgb(55,  62,  90)
    $BG_ADD = [System.Drawing.Color]::FromArgb(13,  50,  28)
    $BG_DEL = [System.Drawing.Color]::FromArgb(55,  12,  12)
    $BG_CHG = [System.Drawing.Color]::FromArgb(55,  42,   0)
    $BG_EQ  = [System.Drawing.Color]::FromArgb(11,  12,  18)
    $fM  = New-Object System.Drawing.Font("Consolas", 9.5)
    $fUL = New-Object System.Drawing.Font("Segoe UI", 9)
    $fBL = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

    $script:cmp_PathA = ''; $script:cmp_PathB = ''
    $script:cmp_LinesA = @(); $script:cmp_LinesB = @()
    $script:cmp_Edits = @(); $script:cmp_DiffIdxList = @()
    $script:cmp_DiffPos = -1

    $cw = New-Object System.Windows.Forms.Form
    $cw.Text          = "Config Comparator"
    $cw.Size          = New-Object System.Drawing.Size(1400, 860)
    $cw.MinimumSize   = New-Object System.Drawing.Size(900, 600)
    $cw.StartPosition = "CenterScreen"
    $cw.BackColor     = $CB_BG; $cw.ForeColor = $C_EQ; $cw.Font = $fUL

    $pnlTop = New-Object System.Windows.Forms.Panel
    $pnlTop.Dock = 'Top'; $pnlTop.Height = 44; $pnlTop.BackColor = $CB_HDR

    function New-CBtn { param([string]$T,[int]$X,[int]$W=120,[System.Drawing.Color]$BG,[System.Drawing.Color]$FG,[System.Drawing.Color]$BD)
        $b = New-Object System.Windows.Forms.Button; $b.Text=$T; $b.Size=New-Object System.Drawing.Size($W,28)
        $b.Location=New-Object System.Drawing.Point($X,8); $b.FlatStyle='Flat'; $b.BackColor=$BG; $b.ForeColor=$FG; $b.Font=$fBL
        $b.FlatAppearance.BorderSize=1; $b.FlatAppearance.BorderColor=$BD; return $b }

    $btnLA = New-CBtn "Load Config A" 8   130 ([System.Drawing.Color]::FromArgb(32,75,145))  ([System.Drawing.Color]::FromArgb(195,215,255)) ([System.Drawing.Color]::FromArgb(55,100,185))
    $btnLB = New-CBtn "Load Config B" 146 130 ([System.Drawing.Color]::FromArgb(32,75,145))  ([System.Drawing.Color]::FromArgb(195,215,255)) ([System.Drawing.Color]::FromArgb(55,100,185))
    $btnRD = New-CBtn "Run Diff"      284 100 ([System.Drawing.Color]::FromArgb(14,125,58))  ([System.Drawing.Color]::FromArgb(195,255,215)) ([System.Drawing.Color]::FromArgb(18,175,80))

    $chkIG = New-Object System.Windows.Forms.CheckBox
    $chkIG.Text='Ignore Non-Functional Changes'; $chkIG.Location=New-Object System.Drawing.Point(393,12)
    $chkIG.Size=New-Object System.Drawing.Size(230,20); $chkIG.ForeColor=[System.Drawing.Color]::FromArgb(150,158,180)
    $chkIG.Font=$fUL; $chkIG.BackColor=$CB_HDR

    $btnPR = New-CBtn "Prev"  632 88  $CB_BTN ([System.Drawing.Color]::FromArgb(150,158,180)) ([System.Drawing.Color]::FromArgb(70,75,100))
    $btnNX = New-CBtn "Next"  728 88  $CB_BTN ([System.Drawing.Color]::FromArgb(150,158,180)) ([System.Drawing.Color]::FromArgb(70,75,100))

    $lblNav = New-Object System.Windows.Forms.Label
    $lblNav.Text='No diff loaded'; $lblNav.Location=New-Object System.Drawing.Point(824,12)
    $lblNav.Size=New-Object System.Drawing.Size(200,20); $lblNav.ForeColor=$CB_INFO; $lblNav.Font=$fUL

    $btnEH = New-CBtn "Export HTML" 1030 110 $CB_BTN ([System.Drawing.Color]::FromArgb(190,140,255)) ([System.Drawing.Color]::FromArgb(110,60,180))
    $btnET = New-CBtn "Export TXT"  1148 100 $CB_BTN ([System.Drawing.Color]::FromArgb(190,140,255)) ([System.Drawing.Color]::FromArgb(110,60,180))

    foreach ($c in @($btnLA,$btnLB,$btnRD,$chkIG,$btnPR,$btnNX,$lblNav,$btnEH,$btnET)) { $pnlTop.Controls.Add($c) }

    $pnlPaths = New-Object System.Windows.Forms.Panel
    $pnlPaths.Dock='Top'; $pnlPaths.Height=24; $pnlPaths.BackColor=[System.Drawing.Color]::FromArgb(16,18,30)
    $lblPA = New-Object System.Windows.Forms.Label; $lblPA.Text='   Config A: (none)'; $lblPA.Location=New-Object System.Drawing.Point(0,4); $lblPA.Size=New-Object System.Drawing.Size(700,18); $lblPA.ForeColor=$CB_INFO; $lblPA.Font=New-Object System.Drawing.Font("Segoe UI",8)
    $lblPB = New-Object System.Windows.Forms.Label; $lblPB.Text='   Config B: (none)'; $lblPB.Location=New-Object System.Drawing.Point(700,4); $lblPB.Size=New-Object System.Drawing.Size(700,18); $lblPB.ForeColor=$CB_INFO; $lblPB.Font=New-Object System.Drawing.Font("Segoe UI",8)
    $pnlPaths.Controls.Add($lblPA); $pnlPaths.Controls.Add($lblPB)

    $pnlSt = New-Object System.Windows.Forms.Panel; $pnlSt.Dock='Bottom'; $pnlSt.Height=24; $pnlSt.BackColor=[System.Drawing.Color]::FromArgb(14,15,22)
    $lblSt = New-Object System.Windows.Forms.Label; $lblSt.Text='   Load two configs then click Run Diff'; $lblSt.Dock='Fill'; $lblSt.Font=New-Object System.Drawing.Font("Segoe UI",8); $lblSt.ForeColor=$CB_INFO; $lblSt.TextAlign='MiddleLeft'
    $pnlSt.Controls.Add($lblSt)

    $split = New-Object System.Windows.Forms.SplitContainer; $split.Dock='Fill'; $split.Orientation='Vertical'; $split.BackColor=[System.Drawing.Color]::FromArgb(30,32,50); $split.SplitterWidth=4

    $lblHA = New-Object System.Windows.Forms.Label; $lblHA.Text='  Config A'; $lblHA.Dock='Top'; $lblHA.Height=22; $lblHA.Font=$fBL; $lblHA.ForeColor=[System.Drawing.Color]::FromArgb(88,168,255); $lblHA.BackColor=[System.Drawing.Color]::FromArgb(18,20,35); $lblHA.TextAlign='MiddleLeft'
    $lblHB = New-Object System.Windows.Forms.Label; $lblHB.Text='  Config B'; $lblHB.Dock='Top'; $lblHB.Height=22; $lblHB.Font=$fBL; $lblHB.ForeColor=[System.Drawing.Color]::FromArgb(88,168,255); $lblHB.BackColor=[System.Drawing.Color]::FromArgb(18,20,35); $lblHB.TextAlign='MiddleLeft'

    function New-DiffRTB {
        $r = New-Object System.Windows.Forms.RichTextBox; $r.Dock='Fill'; $r.BackColor=$CB_PANE; $r.ForeColor=$C_EQ
        $r.Font=$fM; $r.ReadOnly=$true; $r.BorderStyle='None'; $r.ScrollBars='Both'; $r.WordWrap=$false; return $r }
    $rtbA = New-DiffRTB; $rtbB = New-DiffRTB

    $split.Panel1.Controls.Add($rtbA); $split.Panel1.Controls.Add($lblHA)
    $split.Panel2.Controls.Add($rtbB); $split.Panel2.Controls.Add($lblHB)

    $cw.Controls.Add($split); $cw.Controls.Add($pnlSt); $cw.Controls.Add($pnlPaths); $cw.Controls.Add($pnlTop)

    $script:cmpSyncing = $false; $script:cmpSrcA = $true
    $script:cmpLastVA  = 0;      $script:cmpLastHA = 0
    $script:cmpLastVB  = 0;      $script:cmpLastHB = 0

    function Invoke-ScrollSync { param($From, $To)
        if ($script:cmpSyncing -or -not $script:CmpScrollOK) { return }
        $script:cmpSyncing = $true
        try {
            $srcLine = [int][CmpScrollHelper]::SendMessage($From.Handle, 0x00CE, [IntPtr]::Zero, [IntPtr]::Zero)
            $dstLine = [int][CmpScrollHelper]::SendMessage($To.Handle,   0x00CE, [IntPtr]::Zero, [IntPtr]::Zero)
            $delta   = $srcLine - $dstLine
            if ($delta -ne 0) { [void][CmpScrollHelper]::SendMessage($To.Handle, 0x00B6, [IntPtr]::Zero, [IntPtr]$delta) }
            $h = [CmpScrollHelper]::GetScrollPos($From.Handle, 0)
            [void][CmpScrollHelper]::SendMessage($To.Handle, 0x114, [IntPtr](($h -shl 16) -bor 4), [IntPtr]::Zero)
            [void][CmpScrollHelper]::SendMessage($To.Handle, 0x114, [IntPtr]8, [IntPtr]::Zero)
        } catch {}
        $script:cmpSyncing = $false
    }

    $syncTmr = New-Object System.Windows.Forms.Timer; $syncTmr.Interval = 40
    $syncTmr.Add_Tick({
        if ($script:cmpSyncing -or -not $script:CmpScrollOK) { return }
        try {
            if ($script:cmpSrcA) {
                if (-not $rtbA.IsHandleCreated) { return }
                $v = [int][CmpScrollHelper]::SendMessage($rtbA.Handle, 0x00CE, [IntPtr]::Zero, [IntPtr]::Zero)
                $h = [CmpScrollHelper]::GetScrollPos($rtbA.Handle, 0)
                if ($v -ne $script:cmpLastVA -or $h -ne $script:cmpLastHA) { $script:cmpLastVA = $v; $script:cmpLastHA = $h; Invoke-ScrollSync $rtbA $rtbB }
            } else {
                if (-not $rtbB.IsHandleCreated) { return }
                $v = [int][CmpScrollHelper]::SendMessage($rtbB.Handle, 0x00CE, [IntPtr]::Zero, [IntPtr]::Zero)
                $h = [CmpScrollHelper]::GetScrollPos($rtbB.Handle, 0)
                if ($v -ne $script:cmpLastVB -or $h -ne $script:cmpLastHB) { $script:cmpLastVB = $v; $script:cmpLastHB = $h; Invoke-ScrollSync $rtbB $rtbA }
            }
        } catch {}
    })
    $rtbA.Add_MouseEnter({ $script:cmpSrcA = $true  }); $rtbA.Add_GotFocus({ $script:cmpSrcA = $true  })
    $rtbB.Add_MouseEnter({ $script:cmpSrcA = $false }); $rtbB.Add_GotFocus({ $script:cmpSrcA = $false })

    function Write-DiffLine { param($R,[string]$LN,[string]$TX,[System.Drawing.Color]$FG,[System.Drawing.Color]$BG)
        $R.SelectionStart=$R.TextLength; $R.SelectionLength=0; $R.SelectionBackColor=$BG; $R.SelectionColor=$C_LN; $R.AppendText($LN.PadLeft(5)+'  ')
        $R.SelectionStart=$R.TextLength; $R.SelectionLength=0; $R.SelectionBackColor=$BG; $R.SelectionColor=$FG;   $R.AppendText($TX+"`n") }

    function Invoke-RunDiff {
        if (-not $script:cmp_PathA -or -not $script:cmp_PathB) { $lblSt.Text='   Please load both Config A and Config B first.'; return }
        $lblSt.Text='   Computing diff...'; $cw.Refresh()
        $ignore = $chkIG.Checked
        $normA  = if ($ignore) { $script:cmp_LinesA | Where-Object { $null -ne (Get-NormalisedLine $_ $true) } | ForEach-Object { $_.Trim() } } else { $script:cmp_LinesA | ForEach-Object { $_.TrimEnd() } }
        $normB  = if ($ignore) { $script:cmp_LinesB | Where-Object { $null -ne (Get-NormalisedLine $_ $true) } | ForEach-Object { $_.Trim() } } else { $script:cmp_LinesB | ForEach-Object { $_.TrimEnd() } }
        $merged = Merge-AdjacentEdits (Invoke-LineDiff $normA $normB)
        $script:cmp_Edits = $merged
        $script:cmp_DiffIdxList = @(for ($i=0; $i -lt $merged.Count; $i++) { if ($merged[$i].Tag -ne 'equal') { $i } })
        $script:cmp_DiffPos = -1
        $rtbA.Clear(); $rtbB.Clear()
        if ($script:CmpScrollOK) {
            [void][CmpScrollHelper]::SendMessage($rtbA.Handle, 0x0B, [IntPtr]::new(0), [IntPtr]::Zero)
            [void][CmpScrollHelper]::SendMessage($rtbB.Handle, 0x0B, [IntPtr]::new(0), [IntPtr]::Zero)
        }
        $adds=0; $dels=0; $chgs=0
        foreach ($e in $merged) {
            switch ($e.Tag) {
                'equal'  { Write-DiffLine $rtbA (($e.IdxA+1).ToString()) $e.LineA $C_EQ $BG_EQ; Write-DiffLine $rtbB (($e.IdxB+1).ToString()) $e.LineB $C_EQ $BG_EQ }
                'delete' { Write-DiffLine $rtbA (($e.IdxA+1).ToString()) $e.LineA $C_DEL $BG_DEL; Write-DiffLine $rtbB '' '(removed)' $C_DEL $BG_DEL; $dels++ }
                'insert' { Write-DiffLine $rtbA '' '(added)'  $C_ADD $BG_ADD; Write-DiffLine $rtbB (($e.IdxB+1).ToString()) $e.LineB $C_ADD $BG_ADD; $adds++ }
                'change' { Write-DiffLine $rtbA (($e.IdxA+1).ToString()) $e.LineA $C_CHG $BG_CHG; Write-DiffLine $rtbB (($e.IdxB+1).ToString()) $e.LineB $C_CHG $BG_CHG; $chgs++ }
            }
        }
        if ($script:CmpScrollOK) {
            [void][CmpScrollHelper]::SendMessage($rtbA.Handle, 0x0B, [IntPtr]::new(1), [IntPtr]::Zero)
            [void][CmpScrollHelper]::SendMessage($rtbB.Handle, 0x0B, [IntPtr]::new(1), [IntPtr]::Zero)
            $rtbA.Invalidate(); $rtbA.Update(); $rtbB.Invalidate(); $rtbB.Update()
        }
        $script:cmpSyncing = $true
        $script:cmpLastVA = 0; $script:cmpLastHA = 0; $script:cmpLastVB = 0; $script:cmpLastHB = 0
        $rtbA.SelectionStart = 0; $rtbA.ScrollToCaret()
        $rtbB.SelectionStart = 0; $rtbB.ScrollToCaret()
        if ($script:CmpScrollOK) {
            $fvlA = [int][CmpScrollHelper]::SendMessage($rtbA.Handle, 0x00CE, [IntPtr]::Zero, [IntPtr]::Zero)
            if ($fvlA -gt 0) { [void][CmpScrollHelper]::SendMessage($rtbA.Handle, 0x00B6, [IntPtr]::Zero, [IntPtr](-$fvlA)) }
            $fvlB = [int][CmpScrollHelper]::SendMessage($rtbB.Handle, 0x00CE, [IntPtr]::Zero, [IntPtr]::Zero)
            if ($fvlB -gt 0) { [void][CmpScrollHelper]::SendMessage($rtbB.Handle, 0x00B6, [IntPtr]::Zero, [IntPtr](-$fvlB)) }
        }
        $script:cmpSyncing = $false
        $total = $adds+$dels+$chgs
        $lblSt.Text  = "   Diff complete -- $total differences  ($adds added  $dels removed  $chgs modified)"
        $lblNav.Text = if ($total -gt 0) { "Difference 0 of $total" } else { "Files are identical" }
    }

    function Jump-ToDiff { param([int]$Pos)
        if ($script:cmp_DiffIdxList.Count -eq 0) { return }
        $Pos = [Math]::Max(0,[Math]::Min($Pos,$script:cmp_DiffIdxList.Count-1))
        $script:cmp_DiffPos = $Pos
        $lblNav.Text = "Difference $($Pos+1) of $($script:cmp_DiffIdxList.Count)"
        $script:cmpSyncing = $true
        $ln = $script:cmp_DiffIdxList[$Pos]
        $cp = $rtbA.GetFirstCharIndexFromLine($ln); if ($cp -lt 0) { $cp=0 }
        $rtbA.SelectionStart=$cp; $rtbA.ScrollToCaret()
        $rtbB.SelectionStart=$cp; $rtbB.ScrollToCaret()
        $script:cmpSyncing = $false }

    $btnLA.Add_Click({ $ofd=New-Object System.Windows.Forms.OpenFileDialog; $ofd.Title='Select Config A'; $ofd.Filter='Config files (*.txt;*.cfg;*.conf;*.ios)|*.txt;*.cfg;*.conf;*.ios|All files (*.*)|*.*'
        if ($ofd.ShowDialog() -ne 'OK') { return }
        $script:cmp_PathA=$ofd.FileName; $script:cmp_LinesA=[System.IO.File]::ReadAllLines($ofd.FileName,[System.Text.Encoding]::UTF8)
        $lblPA.Text="   Config A: $($ofd.FileName)"; $lblHA.Text="  Config A -- $([System.IO.Path]::GetFileName($ofd.FileName))  ($($script:cmp_LinesA.Count) lines)"
        $lblSt.Text="   Config A loaded. $($script:cmp_LinesA.Count) lines." })

    $btnLB.Add_Click({ $ofd=New-Object System.Windows.Forms.OpenFileDialog; $ofd.Title='Select Config B'; $ofd.Filter='Config files (*.txt;*.cfg;*.conf;*.ios)|*.txt;*.cfg;*.conf;*.ios|All files (*.*)|*.*'
        if ($ofd.ShowDialog() -ne 'OK') { return }
        $script:cmp_PathB=$ofd.FileName; $script:cmp_LinesB=[System.IO.File]::ReadAllLines($ofd.FileName,[System.Text.Encoding]::UTF8)
        $lblPB.Text="   Config B: $($ofd.FileName)"; $lblHB.Text="  Config B -- $([System.IO.Path]::GetFileName($ofd.FileName))  ($($script:cmp_LinesB.Count) lines)"
        $lblSt.Text="   Config B loaded. $($script:cmp_LinesB.Count) lines." })

    $btnRD.Add_Click({ Invoke-RunDiff })
    $chkIG.Add_CheckedChanged({ if ($script:cmp_Edits.Count -gt 0) { Invoke-RunDiff } })
    $btnPR.Add_Click({ if ($script:cmp_DiffIdxList.Count -eq 0) { return }; $np=if($script:cmp_DiffPos -le 0){$script:cmp_DiffIdxList.Count-1}else{$script:cmp_DiffPos-1}; Jump-ToDiff $np })
    $btnNX.Add_Click({ if ($script:cmp_DiffIdxList.Count -eq 0) { return }; $np=if($script:cmp_DiffPos -ge $script:cmp_DiffIdxList.Count-1){0}else{$script:cmp_DiffPos+1}; Jump-ToDiff $np })

    $btnEH.Add_Click({ if ($script:cmp_Edits.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("Run a diff first.","No Diff",'OK','Information'); return }
        $sfd=New-Object System.Windows.Forms.SaveFileDialog; $sfd.Title='Export HTML Report'; $sfd.Filter='HTML files (*.html)|*.html'; $sfd.FileName="diff_report_$((Get-Date).ToString('yyyyMMdd_HHmmss')).html"
        if ($sfd.ShowDialog() -ne 'OK') { return }
        try { Export-DiffReport $script:cmp_PathA $script:cmp_PathB $script:cmp_Edits 'html' $sfd.FileName; $lblSt.Text="   HTML report exported: $($sfd.FileName)" }
        catch { [System.Windows.Forms.MessageBox]::Show("Export failed: $_","Export Error",'OK','Error') } })

    $btnET.Add_Click({ if ($script:cmp_Edits.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("Run a diff first.","No Diff",'OK','Information'); return }
        $sfd=New-Object System.Windows.Forms.SaveFileDialog; $sfd.Title='Export TXT Report'; $sfd.Filter='Text files (*.txt)|*.txt'; $sfd.FileName="diff_report_$((Get-Date).ToString('yyyyMMdd_HHmmss')).txt"
        if ($sfd.ShowDialog() -ne 'OK') { return }
        try { Export-DiffReport $script:cmp_PathA $script:cmp_PathB $script:cmp_Edits 'txt' $sfd.FileName; $lblSt.Text="   TXT report exported: $($sfd.FileName)" }
        catch { [System.Windows.Forms.MessageBox]::Show("Export failed: $_","Export Error",'OK','Error') } })

    $cw.Add_Resize({ $split.SplitterDistance = [int]($split.Width / 2) })
    $cw.Add_FormClosing({ $syncTmr.Stop(); $syncTmr.Dispose() })
    if ($script:CmpScrollOK) { $syncTmr.Start() }

    [void]$cw.ShowDialog(); $cw.Dispose()
}

# ======================================================================
# EVENT HANDLERS
# ======================================================================

function Set-ModeBanner {
    param([string]$Text, [System.Drawing.Color]$Color)
    $lblMode.Text = "   $Text"
    $lblMode.ForeColor = $Color
}

$COLOR_MODE_SRC   = [System.Drawing.Color]::FromArgb(150,190,255)
$COLOR_MODE_DST   = [System.Drawing.Color]::FromArgb(190,150,255)
$COLOR_MODE_PAIR  = [System.Drawing.Color]::FromArgb(255,200,110)
$COLOR_MODE_FULL  = [System.Drawing.Color]::FromArgb(120,230,150)
$COLOR_MODE_ERR   = [System.Drawing.Color]::FromArgb(255,110,110)

# ── Compare Configs ──────────────────────────────────────────────────
$btnCompareConfigs.Add_Click({ Show-CompareWindow })

# ── Upload Config ──────────────────────────────────────────────────────
$btnUpload.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Title  = "Select Cisco IOS Running Configuration"
    $ofd.Filter = "Config files (*.txt;*.cfg;*.conf;*.ios)|*.txt;*.cfg;*.conf;*.ios|All files (*.*)|*.*"
    if ([System.IO.Directory]::Exists([System.Environment]::GetFolderPath('Desktop'))) {
        $ofd.InitialDirectory = [System.Environment]::GetFolderPath('Desktop')
    }
    if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    try {
        $content = [System.IO.File]::ReadAllText($ofd.FileName, [System.Text.Encoding]::UTF8)
        Parse-CiscoConfig $content
        $script:ConfigLoaded = $true

        $lblConfigPath.Text      = "  $($ofd.FileName)"
        $lblConfigPath.ForeColor = [System.Drawing.Color]::FromArgb(72, 205, 100)

        $secIPTotal = ($script:Interfaces.Values | ForEach-Object { $_.SecondaryIPs.Count } | Measure-Object -Sum).Sum
        $summary = "  Loaded: IFs=$($script:Interfaces.Count)(+$secIPTotal sec)  VRFs=$($script:VRFs.Count)  Zones=$($script:Zones.Count)  ZP=$($script:ZonePairs.Count)  PM=$($script:PolicyMaps.Count)  CM=$($script:ClassMaps.Count)  ACLs=$($script:AccessLists.Count)  VLAN-ACLs=$($script:VLANPolicyDB.Count)"
        $lblStatus.Text      = $summary
        $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(72, 205, 100)
        Set-ModeBanner "Config loaded — fill in any combination of fields above and click Analyze" $COLOR_MODE_FULL

        Start-RTBBatch
        Add-RTBLine "  CONFIG PARSED SUCCESSFULLY" "ok"
        Add-RTBLine "  File : $($ofd.FileName)" "detail"
        Add-RTBLine "" "info"
        Add-RTBLine "  INTERFACES  ($($script:Interfaces.Count))" "head"
        foreach ($n in $script:Interfaces.Keys) {
            $ifc  = $script:Interfaces[$n]
            $ipS  = if ($ifc.IP)   { "$($ifc.IP) / $($ifc.Mask)" } else { "no IP" }
            $vrfS = if ($ifc.VRF)  { "  vrf:$($ifc.VRF)" }        else { "" }
            $zS   = if ($ifc.Zone) { "zone:$($ifc.Zone)" }         else { "(no zone-member)" }
            Add-RTBLine "    $($n.PadRight(32)) $($ipS.PadRight(24)) $zS$vrfS" "detail"
            foreach ($sec in $ifc.SecondaryIPs) {
                $secStr = "$($sec.IP) / $($sec.Mask)"
                Add-RTBLine "    $(''.PadRight(32)) $($secStr.PadRight(24)) [secondary]" "detail"
            }
        }
        Add-RTBLine "" "info"
        if ($script:VRFs.Count -gt 0) {
            Add-RTBLine "  VRFs  ($($script:VRFs.Count))" "head"
            Add-RTBLine "    $($script:VRFs -join '  |  ')" "detail"
            Add-RTBLine "" "info"
        }
        Add-RTBLine "  ZONES  ($($script:Zones.Count))" "head"
        if ($script:Zones.Count -gt 0) { Add-RTBLine "    $($script:Zones -join '  |  ')" "detail" }
        Add-RTBLine "" "info"

        Add-RTBLine "  ZONE-PAIRS  ($($script:ZonePairs.Count))" "head"
        $zpIssues = 0
        foreach ($n in $script:ZonePairs.Keys) {
            $zp     = $script:ZonePairs[$n]
            $srcStr = if ($zp.SourceZone) { $zp.SourceZone } else { '[MISSING]' }
            $dstStr = if ($zp.DestZone)   { $zp.DestZone   } else { '[MISSING]' }
            $pmStr  = if ($zp.PolicyMap)  { $zp.PolicyMap  } else { '[MISSING]' }
            $infStr = if ($zp.PolicyMapInferred) { '  [convention match]' } else { '' }
            $hasBad = (-not $zp.SourceZone) -or (-not $zp.DestZone) -or (-not $zp.PolicyMap)
            $pmStyle = if (-not $zp.PolicyMap) { 'warn' } elseif ($zp.PolicyMapInferred) { 'warn' } else { 'ok' }
            if ($hasBad) { $zpIssues++ }
            Add-RTBLine "    $($n.PadRight(30)) $srcStr -> $dstStr   Policy: $pmStr$infStr" $pmStyle
        }
        if ($zpIssues -gt 0) {
            Add-RTBLine "" "info"
            Add-RTBLine "  [!] $zpIssues zone-pair(s) missing source/destination/policy. Run Validate for details." "warn"
        }
        Add-RTBLine "" "info"

        Add-RTBLine "  === VLAN ACL INVENTORY ($($script:VLANPolicyDB.Count)) ===" "head"
        if ($script:VLANPolicyDB.Count -eq 0) {
            Add-RTBLine "  No VLAN direct ACLs detected (VLAN202-208 / VLAN300 / VLAN511)" "detail"
        } else {
            foreach ($vz in $script:KnownVLANZones) {
                if (-not (Test-KeyExists $script:VLANPolicyDB $vz)) { continue }
                $ve = $script:VLANPolicyDB[$vz]
                Add-RTBLine "  $vz   ACL: $(if ($ve.PrimaryACL) { $ve.PrimaryACL } else { '(none)' })   Source: $($ve.SourceDesc)" "info"
            }
        }
        Add-RTBLine "" "info"
        Add-RTBLine "  Ready — fill in any combination of fields above and click Analyze." "ok"
        Complete-RTBBatch
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to parse config file:`n`n$_", "Parse Error", 'OK', 'Error')
        $lblStatus.Text      = "   Error loading config: $_"
        $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(255, 84, 84)
    }
})

# ── Clear ────────────────────────────────────────────────────────────
$btnClear.Add_Click({
    Show-WelcomeBanner
    $lblStatus.Text = "   Ready"
    $lblStatus.ForeColor = $C_FG_STATUS
    Set-ModeBanner "Mode: fill in any combination of fields above — Analyze adapts automatically" $COLOR_MODE_FULL
    $tbSrcIP.Clear(); $tbDstIP.Clear(); $tbProto.Clear(); $tbDstPort.Clear()
})

# ── Validate ─────────────────────────────────────────────────────────
$btnValidate.Add_Click({
    if (-not $script:ConfigLoaded) {
        [System.Windows.Forms.MessageBox]::Show("Please upload a Cisco IOS configuration file first.", "No Config Loaded", 'OK', 'Warning'); return
    }
    Start-RTBBatch
    $report = Invoke-ZonePairValidation
    Set-ModeBanner "Mode: Configuration validation report" $COLOR_MODE_PAIR

    Add-RTBLine "  #=========================================================#" "head"
    Add-RTBLine "   ZBFW CONFIGURATION VALIDATION REPORT" "head"
    Add-RTBLine "  #=========================================================#" "head"
    Add-RTBLine "" "info"

    $sections = @(
        @{ Title="Zone-Pairs with No Source Zone";       Items=$report.ZonePairsNoSrc;  Style='deny' }
        @{ Title="Zone-Pairs with No Destination Zone";  Items=$report.ZonePairsNoDst;  Style='deny' }
        @{ Title="Zone-Pairs with No Policy";            Items=$report.ZonePairsNoPM;   Style='deny' }
        @{ Title="Missing Policy-Maps";                  Items=$report.MissingPMs;      Style='deny' }
        @{ Title="Missing Class-Maps";                   Items=$report.MissingCMs;      Style='deny' }
        @{ Title="Missing ACLs";                         Items=$report.MissingACLs;     Style='deny' }
        @{ Title="Orphaned Zones (not in any zone-pair)";Items=$report.OrphanedZones;   Style='warn' }
        @{ Title="Orphaned Class-Maps (unreferenced)";   Items=$report.OrphanedCMs;     Style='warn' }
    )
    foreach ($sec in $sections) {
        Add-RTBLine "  $($sec.Title)  ($($sec.Items.Count))" "head"
        if ($sec.Items.Count -eq 0) { Add-RTBLine "    None" "ok" }
        else { foreach ($i in $sec.Items) { Add-RTBLine "    $i" $sec.Style } }
        Add-RTBLine "" "info"
    }

    $totalIssues = $report.ZonePairsNoPM.Count + $report.ZonePairsNoSrc.Count + $report.ZonePairsNoDst.Count +
                   $report.MissingPMs.Count + $report.MissingCMs.Count + $report.MissingACLs.Count
    if ($totalIssues -eq 0) {
        Add-RTBLine "  [OK] No configuration integrity issues found." "ok"
        $lblStatus.Text = "   Validation: No issues found"; $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(72,205,100)
    } else {
        Add-RTBLine "  [!] $totalIssues integrity issue(s) found -- review sections above." "warn"
        $lblStatus.Text = "   Validation: $totalIssues issue(s) found"; $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(255,190,48)
    }
    Complete-RTBBatch
})

# ── Inventory ────────────────────────────────────────────────────────
$btnInventory.Add_Click({
    if (-not $script:ConfigLoaded) {
        [System.Windows.Forms.MessageBox]::Show("Please upload a Cisco IOS configuration file first.", "No Config Loaded", 'OK', 'Warning'); return
    }
    Start-RTBBatch
    $inv = Get-ConfigInventory
    Set-ModeBanner "Mode: Config inventory report" $COLOR_MODE_PAIR

    Add-RTBLine "  #=========================================================#" "head"
    Add-RTBLine "   CONFIG INVENTORY REPORT" "head"
    Add-RTBLine "  #=========================================================#" "head"
    Add-RTBLine "" "info"
    Add-RTBLine "  Component             Count" "head"
    Add-RTBLine "  -----------------------------" "detail"
    Add-RTBLine "  Interfaces            $($inv.Interfaces)" "info"
    Add-RTBLine "  Secondary IPs         $($inv.SecondaryIPs)" "info"
    Add-RTBLine "  VRFs                  $($inv.VRFs)" "info"
    Add-RTBLine "  Zones                 $($inv.Zones)" "info"
    Add-RTBLine "  Zone-Pairs            $($inv.ZonePairs)" "info"
    Add-RTBLine "  Policy-Maps           $($inv.PolicyMaps)" "info"
    Add-RTBLine "  Class-Maps            $($inv.ClassMaps)" "info"
    Add-RTBLine "  Named ACLs            $($inv.NamedACLs)" "info"
    Add-RTBLine "" "info"
    Add-RTBLine "  #=========================================================#" "head"
    Add-RTBLine "   VLAN ACL INVENTORY" "head"
    Add-RTBLine "  #=========================================================#" "head"
    Add-RTBLine "" "info"
    if ($script:VLANPolicyDB.Count -eq 0) {
        Add-RTBLine "  No VLAN direct ACLs detected in this config." "warn"
    } else {
        foreach ($vz in $script:KnownVLANZones) {
            if (-not (Test-KeyExists $script:VLANPolicyDB $vz)) { continue }
            $ve = $script:VLANPolicyDB[$vz]
            Add-RTBLine "  $($vz.PadRight(12)) ACL: $($ve.PrimaryACL.PadRight(22)) Source: $($ve.SourceDesc)" "info"
        }
    }
    Add-RTBLine "" "info"
    $lblStatus.Text = "   Inventory: $($inv.Interfaces) interfaces | $($inv.ZonePairs) zone-pairs | $($inv.ClassMaps) class-maps | $($inv.NamedACLs) ACLs"
    $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(96,178,255)
    Complete-RTBBatch
})

# ── Analyze — mode-routing logic ────────────────────────────────────
$btnAnalyze.Add_Click({
    try {
        if (-not $script:ConfigLoaded) {
            [System.Windows.Forms.MessageBox]::Show("Please upload a Cisco IOS configuration file first.", "No Config Loaded", 'OK', 'Warning'); return
        }

        $srcIP   = $tbSrcIP.Text.Trim()
        $dstIP   = $tbDstIP.Text.Trim()
        $proto   = $tbProto.Text.Trim().ToLower()
        $portTxt = $tbDstPort.Text.Trim()

        $ipRx = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        $haveSrc = -not [string]::IsNullOrWhiteSpace($srcIP)
        $haveDst = -not [string]::IsNullOrWhiteSpace($dstIP)
        $haveProto = -not [string]::IsNullOrWhiteSpace($proto)
        $havePort  = -not [string]::IsNullOrWhiteSpace($portTxt)

        if (-not $haveSrc -and -not $haveDst) {
            [System.Windows.Forms.MessageBox]::Show(
                "Enter at least a Source IP or a Destination IP to run any analysis.",
                "No Address Supplied", 'OK', 'Warning')
            $tbSrcIP.Focus(); return
        }
        if ($haveSrc -and $srcIP -notmatch $ipRx) {
            [System.Windows.Forms.MessageBox]::Show("Source IP is not a valid IPv4 address (e.g. 10.1.1.5)", "Invalid Source IP", 'OK', 'Warning')
            $tbSrcIP.Focus(); return
        }
        if ($haveDst -and $dstIP -notmatch $ipRx) {
            [System.Windows.Forms.MessageBox]::Show("Destination IP is not a valid IPv4 address (e.g. 192.168.10.20)", "Invalid Destination IP", 'OK', 'Warning')
            $tbDstIP.Focus(); return
        }
        if ($haveProto) {
            $validProtos = @('tcp','udp','icmp','ip','gre','esp','ah','ospf','eigrp','igmp','pim')
            $isNBAR = $script:NBARProtocols.ContainsKey($proto)
            if ($proto -notin $validProtos -and -not $isNBAR) {
                $nbarList = ($script:NBARProtocols.Keys | Sort-Object) -join ', '
                [System.Windows.Forms.MessageBox]::Show("Protocol must be a standard transport (tcp, udp, icmp, ip, gre, esp, ah) or an NBAR application name:`n`n$nbarList", "Invalid Protocol", 'OK', 'Warning')
                $tbProto.Focus(); return
            }
        }
        $dstPort = 0
        if ($havePort -and $proto -in @('tcp','udp')) {
            if (-not [int]::TryParse($portTxt, [ref]$dstPort) -or $dstPort -lt 1 -or $dstPort -gt 65535) {
                [System.Windows.Forms.MessageBox]::Show("Destination port must be a number between 1 and 65535.", "Invalid Port", 'OK', 'Warning')
                $tbDstPort.Focus(); return
            }
        }

        Start-RTBBatch
        $lblStatus.Text = "   Analyzing..."; $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(255,190,48)
        $form.Refresh()

        $result = $null
        $modeStyle = $COLOR_MODE_FULL

        if ($haveSrc -and $haveDst -and $haveProto -and ($proto -notin @('tcp','udp') -or $havePort)) {
            # FULL MODE — all fields present enough to give a definitive verdict
            Set-ModeBanner "Mode: FULL VERDICT — Src + Dst + Protocol$(if ($havePort) { ' + Port' })" $COLOR_MODE_FULL
            $modeStyle = $COLOR_MODE_FULL
            $result = Invoke-ZBFWAnalysis -SrcIP $srcIP -DstIP $dstIP -Proto $proto -DstPort $dstPort
        }
        elseif ($haveSrc -and $haveDst) {
            # PAIR COVERAGE — both addresses, proto/port missing or incomplete
            Set-ModeBanner "Mode: PAIR COVERAGE — Src + Dst (protocol/port not fully specified)" $COLOR_MODE_PAIR
            $result = Invoke-PairCoverageAnalysis -SrcIP $srcIP -DstIP $dstIP -Proto $(if ($haveProto) { $proto } else { $null })
        }
        elseif ($haveSrc) {
            # SOURCE-ONLY COVERAGE
            Set-ModeBanner "Mode: SOURCE-ONLY COVERAGE — $srcIP" $COLOR_MODE_SRC
            $result = Invoke-IPCoverageAnalysis -IP $srcIP -Role 'Source'
        }
        else {
            # DEST-ONLY COVERAGE
            Set-ModeBanner "Mode: DESTINATION-ONLY COVERAGE — $dstIP" $COLOR_MODE_DST
            $result = Invoke-IPCoverageAnalysis -IP $dstIP -Role 'Dest'
        }

        if (-not $result -or -not $result.Output) {
            Add-RTBLine "  [!] Analysis returned no output." "warn"
        } else {
            foreach ($line in $result.Output) { Add-RTBLine $line.Text $line.Style }
        }

        if ($result -and $result.Verdict) {
            $v = $result.Verdict
            if ($v.Allowed -eq $true) {
                $lblStatus.Text = "   ALLOWED  |  Action: $($v.Action)  |  Class: $($v.MatchedClass)"
                $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(72,205,100)
            } elseif ($v.Allowed -eq $false) {
                $lblStatus.Text = "   DENIED  |  $($v.Reason)"
                $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(255,84,84)
            }
        } else {
            $lblStatus.Text = "   Coverage analysis complete — see report above"
            $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(96,178,255)
        }
        Complete-RTBBatch
    }
    catch {
        $errMsg = $_.ToString()
        $errTrace = $_.ScriptStackTrace
        Start-RTBBatch
        Add-RTBLine "  ANALYSIS ERROR" "deny"
        Add-RTBLine "  $errMsg" "deny"
        Add-RTBLine "" "info"
        Add-RTBLine "  Stack Trace:" "detail"
        Add-RTBLine "  $errTrace" "detail"
        $lblStatus.Text = "   Error: $errMsg"; $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(255,84,84)
        Set-ModeBanner "Mode: error — see output" $COLOR_MODE_ERR
        Complete-RTBBatch
    }
})

# ── Store Compare: load Store A / Store B configs in isolation ─────────
$btnLoadStoreA.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Title  = "Select WORKING Store Configuration"
    $ofd.Filter = "Config files (*.txt;*.cfg;*.conf;*.ios)|*.txt;*.cfg;*.conf;*.ios|All files (*.*)|*.*"
    if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $prevSnap = Get-ConfigSnapshot
    try {
        $content = [System.IO.File]::ReadAllText($ofd.FileName, [System.Text.Encoding]::UTF8)
        Parse-CiscoConfig $content
        $script:StoreASnapshot = Get-ConfigSnapshot
        $script:StoreAPath = $ofd.FileName
        $lblStoreAPath.Text = [System.IO.Path]::GetFileName($ofd.FileName)
        $lblStoreAPath.ForeColor = [System.Drawing.Color]::FromArgb(80,222,112)
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to parse Store A config:`n`n$_", "Parse Error", 'OK', 'Error')
    } finally {
        Set-ConfigSnapshot $prevSnap
    }
})

$btnLoadStoreB.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Title  = "Select FAILING Store Configuration"
    $ofd.Filter = "Config files (*.txt;*.cfg;*.conf;*.ios)|*.txt;*.cfg;*.conf;*.ios|All files (*.*)|*.*"
    if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $prevSnap = Get-ConfigSnapshot
    try {
        $content = [System.IO.File]::ReadAllText($ofd.FileName, [System.Text.Encoding]::UTF8)
        Parse-CiscoConfig $content
        $script:StoreBSnapshot = Get-ConfigSnapshot
        $script:StoreBPath = $ofd.FileName
        $lblStoreBPath.Text = [System.IO.Path]::GetFileName($ofd.FileName)
        $lblStoreBPath.ForeColor = [System.Drawing.Color]::FromArgb(255,84,84)
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to parse Store B config:`n`n$_", "Parse Error", 'OK', 'Error')
    } finally {
        Set-ConfigSnapshot $prevSnap
    }
})

# ── Compare Stores ───────────────────────────────────────────────────
$btnCompareFlows.Add_Click({
    if (-not $script:StoreASnapshot -or -not $script:StoreBSnapshot) {
        [System.Windows.Forms.MessageBox]::Show("Load both a working-store config and a failing-store config first.", "Missing Store Config(s)", 'OK', 'Warning'); return
    }
    $ipRx = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    $extIP  = $tbExternalIP.Text.Trim()
    $localA = $tbStoreALocalIP.Text.Trim()
    $localB = $tbStoreBLocalIP.Text.Trim()
    foreach ($pair in @(@('External / shared IP',$extIP), @('Store A local IP',$localA), @('Store B local IP',$localB))) {
        if ([string]::IsNullOrWhiteSpace($pair[1]) -or $pair[1] -notmatch $ipRx) {
            [System.Windows.Forms.MessageBox]::Show("$($pair[0]) must be a valid IPv4 address.", "Missing/Invalid Address", 'OK', 'Warning')
            return
        }
    }
    $proto = $tbCmpProto.Text.Trim().ToLower()
    $port = 0; [void][int]::TryParse($tbCmpPort.Text.Trim(), [ref]$port)
    $useProto = if ($proto) { $proto } else { $null }

    $storeToExternal = ($cmbDirection.SelectedIndex -eq 0)
    if ($storeToExternal) {
        $srcA = $localA; $dstA = $extIP
        $srcB = $localB; $dstB = $extIP
    } else {
        $srcA = $extIP; $dstA = $localA
        $srcB = $extIP; $dstB = $localB
    }
    $arrow = if ($storeToExternal) { '-->' } else { '<--' }

    $mainSnap = Get-ConfigSnapshot
    try {
        Start-CmpBatch

        Set-ConfigSnapshot $script:StoreASnapshot
        $A = Resolve-FlowPath -SrcIP $srcA -DstIP $dstA -Proto $useProto -DstPort $port

        Set-ConfigSnapshot $script:StoreBSnapshot
        $B = Resolve-FlowPath -SrcIP $srcB -DstIP $dstB -Proto $useProto -DstPort $port

        $descA = "$([System.IO.Path]::GetFileName($script:StoreAPath))   ($localA $arrow $extIP$(if($useProto){" $useProto/$port"}))"
        $descB = "$([System.IO.Path]::GetFileName($script:StoreBPath))   ($localB $arrow $extIP$(if($useProto){" $useProto/$port"}))"
        $result = Format-FlowComparison -A $A -B $B -LabelA 'STORE A (working)' -LabelB 'STORE B (failing)' -DescA $descA -DescB $descB -SuggestFixSrc $srcB -SuggestFixDst $dstB
        foreach ($line in $result.Output) { Add-CmpLine $line.Text $line.Style }
        Complete-CmpBatch
    } catch {
        Start-CmpBatch
        Add-CmpLine "  COMPARISON ERROR" "deny"
        Add-CmpLine "  $($_.ToString())" "deny"
        Complete-CmpBatch
    } finally {
        Set-ConfigSnapshot $mainSnap
    }
})

# ── Extract VLAN / Zone IPs ──────────────────────────────────────────
$btnExtractVLAN.Add_Click({
    if (-not $script:ConfigLoaded) {
        [System.Windows.Forms.MessageBox]::Show("Please upload a Cisco IOS configuration file first.", "No Config Loaded", 'OK', 'Warning'); return
    }
    Start-VlanBatch
    Add-VlanLine "  #=========================================================#" "head"
    Add-VlanLine "   VLAN / ZONE IP EXTRACTION" "head"
    Add-VlanLine "  #=========================================================#" "head"
    Add-VlanLine "" "info"
    Add-VlanLine "  Every configured interface, grouped by security zone, with" "detail"
    Add-VlanLine "  computed network/broadcast/usable-host-range per subnet." "detail"
    Add-VlanLine "" "info"

    $byZone = Get-VLANIPExtract
    if ($byZone.Count -eq 0) {
        Add-VlanLine "  No interfaces with IP addresses found in this config." "warn"
    } else {
        foreach ($zone in $byZone.Keys) {
            $isVLAN = $script:KnownVLANZones -contains $zone
            $tag = if ($isVLAN) { "  [known VLAN zone]" } else { "" }
            Add-VlanLine "  ZONE: $zone$tag" "head"
            Add-VlanLine "  -----------------------------------------------------------" "detail"
            foreach ($entry in $byZone[$zone]) {
                $secTag = if ($entry.Secondary) { "  [secondary]" } else { "" }
                Add-VlanLine "    Interface  : $($entry.Interface)$secTag" "info"
                Add-VlanLine "    IP/Mask    : $($entry.IP) / $($entry.Mask)  (/$($entry.Info.CIDR))" "info"
                Add-VlanLine "    Network    : $($entry.Info.Network)" "detail"
                Add-VlanLine "    Broadcast  : $($entry.Info.Broadcast)" "detail"
                Add-VlanLine "    Usable     : $($entry.Info.FirstUsable) - $($entry.Info.LastUsable)  ($($entry.Info.UsableHosts) hosts)" "detail"
                Add-VlanLine "" "info"
            }
        }
    }
    Add-VlanLine "  #=========================================================#" "head"
    Add-VlanLine "   ZONES WITH NO IP INTERFACES" "head"
    Add-VlanLine "  #=========================================================#" "head"
    $noIPZones = $script:Zones | Where-Object { -not $byZone.Contains($_) }
    if (@($noIPZones).Count -eq 0) { Add-VlanLine "  None -- every configured zone has at least one addressed interface." "ok" }
    else { foreach ($z in $noIPZones) { Add-VlanLine "  $z" "warn" } }
    Complete-VlanBatch
    $lblStatus.Text = "   VLAN extract: $($byZone.Count) zones with IP interfaces"
    $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(96,178,255)
})

# ── Enter key triggers Analyze ──────────────────────────────────────
foreach ($ctrl in @($tbSrcIP, $tbDstIP, $tbProto, $tbDstPort)) {
    $ctrl.Add_KeyDown({
        param($sender, $e)
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Return) {
            $e.SuppressKeyPress = $true
            $btnAnalyze.PerformClick()
        }
    })
}

$form.Add_Shown({ $form.Activate(); Show-WelcomeBanner; $tbSrcIP.Focus() })

# ── Footer ───────────────────────────────────────────────────────────
$lblFooter = New-Object System.Windows.Forms.Label
$lblFooter.Text      = "ZBFW Analyzer  |  Coverage-aware ACL simulation"
$lblFooter.Dock      = [System.Windows.Forms.DockStyle]::Bottom
$lblFooter.Height    = 22
$lblFooter.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$lblFooter.Font      = New-Object System.Drawing.Font("Segoe UI", 8)
$lblFooter.ForeColor = [System.Drawing.Color]::FromArgb(70,76,95)
$lblFooter.BackColor = $C_BG_FORM
$form.Controls.Add($lblFooter)

[void]$form.ShowDialog()
$form.Dispose()
