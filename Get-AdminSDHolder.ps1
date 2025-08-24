<# 
Get-AdminSDHolder - Analyze effective protected groups in the AD Domain (AdminSDHolder), honoring dsHeuristics 16th char. 
Outputs to Console and CSV file (including AdminCount actual value), as well an optional Visual Map, by creating a DOT file for graphviz (can be rendered into a PNG)
version: 1.0
Comments to 1nTh15h311 (yossis@protonmail.com)
#>

<#
.SYNOPSIS
    Enumerate AdminSDHolder-protected groups and members.
    Show recurive membership, indicate direct vs. nested, 
    Show the source group if nested, and include AdminCount value.
    Generate CSV + DOT graph files, auto-render to PNG & open with Graphviz, if available.
    Comments to 1nTh15h311 (yossis@protonmail.com)
#>

#Require ActiveDirectory
Import-Module ActiveDirectory

# Get effective protected groups (AdminSDHolder), honoring dsHeuristics 16th char
function Get-DSHeuristicsProtectedGroups {
    $groups = @(
        "Enterprise Admins",
        "Domain Admins",
        "Schema Admins",
        "Administrators",
        "Domain Controllers",
        "Replicator",
        "Cert Publishers",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators"
    )

    $configNC = (Get-ADRootDSE).configurationNamingContext;
    $ds = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties dsHeuristics;
    $h = $ds.dsHeuristics

    # If the 16th character is '1' => exclude the four operator groups
    if ($h -and $h.Length -ge 16 -and $h[15] -eq '1') {
        $groups = $groups | Where-Object {$_ -notin @("Account Operators","Server Operators","Backup Operators","Print Operators")}
    }
    $groups
}

# Globals / outputs
$EffectiveProtectedGroups = Get-DSHeuristicsProtectedGroups;
Write-Host "Effective AdminSDHolder-protected groups:" -ForegroundColor Cyan;
$EffectiveProtectedGroups | ForEach-Object { Write-Host " - $_" }

$location = (Get-Location).Path;
$dotFile = "$location\AdminSDHolder_Map.dot";
$pngFile = [System.IO.Path]::ChangeExtension($dotFile, ".png");
$csvFile = "$location\AdminSDHolder_Members.csv"

# DOT header
$dot = @"
digraph AdminSDHolder {
    rankdir=LR;
    node [style=filled, shape=box, fontname=Arial];
"@

# Array for the CSV rows
$csvRows = New-Object System.Collections.Generic.List[object];

# Track visited groups by DN to prevent cycles
$visitedGroupDNs = New-Object System.Collections.Generic.HashSet[string];

function Add-DotNodeOnce {
    param([string]$Name, [string]$Fill="lightgray", [string]$Font="black")
    # De-duplicate node declarations by caching in a HashSet in script scope
    if (-not $script:declaredNodes) { $script:declaredNodes = New-Object System.Collections.Generic.HashSet[string] }
    if ($script:declaredNodes.Add($Name)) {
        $script:dot += "    `"$Name`" [fillcolor=$Fill, fontcolor=$Font];`n"
    }
}

function Add-DotEdge {
    param([string]$From, [string]$To, [string]$Color=$null)
    if ($Color) {
        $script:dot += "    `"$From`" -> `"$To`" [color=$Color];`n"
    } else {
        $script:dot += "    `"$From`" -> `"$To`";`n"
    }
}

# Recursively enumerate membership with path tracking
function Get-MembersRecursive {
    param(
        [Microsoft.ActiveDirectory.Management.ADGroup]$CurrentGroup, # the group whose members we enumerate
        [string]$RootGroupName,                                      # protected root group name
        [string[]]$PathSoFar                                         # path of groups from root up to CURRENT group (excluding current)
    )

    # Mark current group as node (orange unless root which is red set outside)
    Add-DotNodeOnce -Name $CurrentGroup.SamAccountName -Fill "orange"

    # Prevent cycles
    if (-not $visitedGroupDNs.Add($CurrentGroup.DistinguishedName)) {
        return
    }

    $members = @();
    try {
        $members = Get-ADGroupMember -Identity $CurrentGroup -ErrorAction Stop
    } catch {
        Write-Warning "Failed to get members of $($CurrentGroup.SamAccountName): $_";
        return
    }

    foreach ($m in $members) {
        $isDirect = ($PathSoFar.Count -eq 0);
        $membershipType = if ($isDirect) { "Direct" } else { "Nested" }

        # Immediate source group is always the current group
        $sourceImmediate = if ($isDirect) { "" } else { $CurrentGroup.SamAccountName }
        $fullPath = if ($isDirect) { "" } else { ($PathSoFar + $CurrentGroup.SamAccountName) -join " -> " }

        # Get AdminCount value, and later add it to Console output + CSV
        if ($m.objectClass -eq 'user' -or $m.objectClass -eq 'computer') {
            $adminCount = (Get-ADObject -Identity $m.distinguishedname -Properties adminCount -ErrorAction SilentlyContinue).adminCount
        }
        if (-not $adminCount) { $adminCount = [string]::Empty }

        if ($m.objectClass -eq 'group') {
            # Console line
            if ($isDirect) {
                Write-Host ("   {0} [group] (direct)" -f $m.SamAccountName) -ForegroundColor Green
            } else {
                Write-Host ("   {0} [group] (nested via {1})  path: {2}" -f $m.SamAccountName,$sourceImmediate,$fullPath) -ForegroundColor Yellow
            }

            # CSV row
            $csvRows.Add([pscustomobject]@{
                Group                = $RootGroupName
                Member               = $m.SamAccountName
                ObjectClass          = "group"
                MembershipType       = $membershipType
                SourceGroupImmediate = $sourceImmediate
                SourcePath           = $fullPath
                AdminCount           = "N/A"
                DistinguishedName    = $m.distinguishedname
            })

            # DOT: declare group node orange, edge from current group
            Add-DotNodeOnce -Name $m.SamAccountName -Fill "orange";
            Add-DotEdge -From $CurrentGroup.SamAccountName -To $m.SamAccountName -Color "orange";

            # Recurse deeper, extending the path to include the current group as we've moved down a level
            # PathSoFar represents path to CURRENT group; next call's path is PathSoFar + CurrentGroup
            try {
                $childGroup = Get-ADGroup -Identity $m.DistinguishedName -Properties SamAccountName -ErrorAction Stop;
                Get-MembersRecursive -CurrentGroup $childGroup -RootGroupName $RootGroupName -PathSoFar ($PathSoFar + $CurrentGroup.SamAccountName)
            } catch {
                Write-Warning "Failed to read nested group $($m.SamAccountName): $_"
            }
        }
        else {
            # Principal (user/computer/others)
            $cls = $m.objectClass;
            if ($isDirect) {
                Write-Host "$($m.SamAccountName) [$cls] <AdminCount=$adminCount> (direct)" -ForegroundColor Green
            } else {
                Write-Host "$($m.SamAccountName) [$cls] <AdminCount=$adminCount> (nested via $($sourceImmediate)  Path:$fullPath" -ForegroundColor Yellow
            }

            # CSV row
            $csvRows.Add([pscustomobject]@{
                Group                = $RootGroupName
                Member               = $m.SamAccountName
                ObjectClass          = $cls
                MembershipType       = $membershipType
                SourceGroupImmediate = $sourceImmediate
                SourcePath           = $fullPath
                AdminCount           = $adminCount
                DistinguishedName    = $m.distinguishedname
            })

            # DOT: principal node lightblue, edge from current group
            Add-DotNodeOnce -Name $m.SamAccountName -Fill "lightblue";
            Add-DotEdge -From $CurrentGroup.SamAccountName -To $m.SamAccountName;

            # reset admincount value
            Clear-Variable admincount
        }
    }
}

# Enumerate each protected group
foreach ($rootName in $EffectiveProtectedGroups) {
    try {
        $root = Get-ADGroup -Identity $rootName -ErrorAction Stop
    } catch {
        Write-Warning "Protected group '$rootName' not found in this domain."
        continue
    }

    Write-Host "`nMembers of $rootName (recursive):" -ForegroundColor Cyan;

    # Root node in red
    Add-DotNodeOnce -Name $root.SamAccountName -Fill "red" -Font "white";

    # Clear cycle tracker per root (optional; keep to avoid cross-root dedupe if same nesting shared)
    $null = $visitedGroupDNs.Clear();

    # Start recursion with empty path (we're at the root)
    Get-MembersRecursive -CurrentGroup $root -RootGroupName $root.SamAccountName -PathSoFar @()
}

# Write DOT & CSV, and render to PNG if Graphviz is available on local host PATH
$dot += "}`n";
$dot | Out-File -FilePath $dotFile -Encoding ascii;
$csvRows | Sort-Object Group, Member, ObjectClass, MembershipType, SourceGroupImmediate, admincount, distinguishedname | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8;

Write-Host "`nDOT file: $dotFile" -ForegroundColor Cyan;
Write-Host "CSV file: $csvFile" -ForegroundColor Cyan;

$dotExe = Get-Command dot -ErrorAction SilentlyContinue;
if ($dotExe) {
    Write-Host "Graphviz detected, generating visual map..." -ForegroundColor Cyan;
    & $dotExe.Source -Tpng $dotFile -o $pngFile;
    if (Test-Path $pngFile) { Start-Process $pngFile }
} else {
    Write-Warning "Graphviz 'dot.exe' not found in PATH. You can download from https://graphviz.org to auto-render.";
    Write-Host "Manual render: dot -Tpng `"$dotFile`" -o `"$pngFile`""
}