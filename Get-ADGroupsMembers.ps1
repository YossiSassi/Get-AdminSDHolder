<#
Get-ADGroupsMembers Sourced from Get-AdminSDHolder
Analyze effective protected groups in the AD Domain (AdminSDHolder), honoring dsHeuristics 16th char. 
Outputs to Console and CSV file (including AdminCount actual value), as well an optional Visual Map, by creating a DOT file for graphviz (can be rendered into a PNG)
version: 1.1
Comments to 1nTh15h311 (yossis@protonmail.com)

.SYNOPSIS
    Enumerate AD groups and members.
    Show recurive membership, indicate direct vs. nested, 
    Show the source group if nested, and include AdminCount value.
    Generate CSV + DOT graph files, auto-render to PNG & open with Graphviz, if available.
    Comments to 1nTh15h311 (yossis@protonmail.com)

.DESCRIPTION
    If -Action is not supplied, the script will prompt the user with a menu
    to select an option. Otherwise, it uses the supplied -Action parameter.

.CHANGELOG
    08-27-2025 - Version 1.1 <Emil.Gitman@gmail.com>
                Renamed from Get-AdminSDHolder to Get-ADGroupsMembers
                Script supports the following scan options
                    AD Protected groups - Default
                    CSV input file with the list of AD groups
                    OU to be scanned
                    Full AD scan
                All output files are now created in "\files" subfolder and timestemped to keep the execution history


.EXAMPLE
.\Get-ADGroupsMembers.ps1
    Script will prompt for scan option and default to AD Protected Groups if not selected

.EXAMPLE
.\Get-ADGroupsMembers.ps1 -Action Protected
    Script will scan the AD Protected Groups (Default)
    

.EXAMPLE
.\Get-ADGroupsMembers.ps1 -Action CSVFile -CSVFilePath D:\Scripts\Get-AdminSDHolder\ADGgroups.csv
    Script will generate the report based on the list of ADGroups from csv file

        CSV File format expected:
        "ADGroup"
        "LOB8TO15",
        "LOB24-30",
        "LOB1TO7",
        "LOB16TO23",
        "Administrators",
        "nested-group-test"

.EXAMPLE
.\Get-ADGroupsMembers.ps1 -Action OU -OU "OU=iam-ps-pam-na,OU=iamlab,DC=iamlab,DC=cyderes,DC=com"
    Script will scan the specific OU in AD. Script will prompt for OU if not provided

.EXAMPLE
.\Get-ADGroupsMembers.ps1 -Action FullScan
    Script will perform full AD scan! User will be prompted to confirm that
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Protected","CSVFile","OU","FullScan")]
    [string]$Action,

    [Parameter(Mandatory=$false)]
    [string]$CSVFilePath,

    [Parameter(Mandatory=$false)]
    [string]$OU  # $OU = "OU=Applications,OU=iamlab,DC=iamlab,DC=cyderes,DC=com"
)


#region Modules

#Require ActiveDirectory
Import-Module ActiveDirectory

#endregion Modules

#region Functions

# Get the list of AD Groups from CSV File
function Get-CsvData {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$false)]
        [bool]$FullScan
    )

    if (-Not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }

    try {
        # Import the CSV file and convert it to an array of objects
        $data = Import-Csv -Path $FilePath
        return ,$data  # ensure it's always returned as an array
    }
    catch {
        throw "Failed to read CSV file: $($_.Exception.Message)"
    }
}

# Get effective protected groups (AdminSDHolder), honoring dsHeuristics 16th char
function Get-DSHeuristicsProtectedGroups {

    # Execute based on final action
    switch ($Action) {
        "Protected" {
            Write-Host "Getting Protected Groups..."
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
        }
        "CSVFile" {
            Write-Host "Getting Groups from CSV File: $CSVFilePath"

            #get the groups object from CSV file
            $groupsfromcsv = Get-CsvData -FilePath $CSVFilePath

    
            # get the array of groups from CSV object
            $groups = $groupsfromcsv | ForEach-Object { $_.ADGroup }
        }
        "OU" {
            if (-not $OU) # Scan specific OU
            {
                $OU = Read-Host "Please provide OU path. [EXAMPLE: OU=Applications,OU=iamlab,DC=iamlab,DC=cyderes,DC=com]"
            }

            Write-Host "Getting Groups from OU: $OU"

            if (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$OU'") 
            {
                Write-Host "$OU already exists."
                $FullADGroupList =Get-ADGroup -Filter * -SearchBase $OU | Select-Object Name
                $groups = $FullADGroupList | ForEach-Object { $_.Name }
            }
            else
            {
                Write-Warning "$OU does not exist. Script will exit"
                Exit
            }
        }
        "FullScan" {
            $Confirm = Read-Host "Full AD scan will be performed. It can take some time! Are you sure? [Y/N]"

            Switch ($Confirm) 
            {

                Y 
                {
                    $FullADGroupList = Get-ADGroup -Filter * | Select-Object Name

                    $groups = $FullADGroupList | ForEach-Object { $_.Name }
                }

                N {
                    Write-Host "Declined. Script will exit"
                    exit
                }

                Default {
                    Write-Host "Invalid input"
                    exit
                }

            }
        }
    }


    $configNC = (Get-ADRootDSE).configurationNamingContext;
    $ds = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties dsHeuristics;
    $h = $ds.dsHeuristics

    # If the 16th character is '1' => exclude the four operator groups
    if ($h -and $h.Length -ge 16 -and $h[15] -eq '1') {
        $groups = $groups | Where-Object {$_ -notin @("Account Operators","Server Operators","Backup Operators","Print Operators")}
    }
    $groups
}

Function Add-DotNodeOnce {
    param([string]$Name, [string]$Fill="lightgray", [string]$Font="black")
    # De-duplicate node declarations by caching in a HashSet in script scope
    if (-not $script:declaredNodes) { $script:declaredNodes = New-Object System.Collections.Generic.HashSet[string] }
    if ($script:declaredNodes.Add($Name)) {
        $script:dot += "    `"$Name`" [fillcolor=$Fill, fontcolor=$Font];`n"
    }
}

Function Add-DotEdge {
    param([string]$From, [string]$To, [string]$Color=$null)
    if ($Color) {
        $script:dot += "    `"$From`" -> `"$To`" [color=$Color];`n"
    } else {
        $script:dot += "    `"$From`" -> `"$To`";`n"
    }
}

# Recursively enumerate membership with path tracking
Function Get-MembersRecursive {
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

#endregion Functions

#region Globals

#File parameters
$ScriptRunTimeStamp = (Get-Date).toString("yyyy-MM-dd_HH_mm_ss")

$location = (Get-Location).Path;
$logsFolder = "files"
$Logfolderpath = "$location\$logsFolder"

if (-not (Test-Path $Logfolderpath))
        {
            try
            {
                New-Item -ItemType Directory -Path $location\$logsFolder -Verbose -ErrorAction Stop
            }
            catch
            {
                Write-Warning "Unable to create logs folder"
                $Logfolderpath = $location
            }
        }


#$dotFile = "$location\AdminSDHolder_Map.dot";
$dotFile = ($Logfolderpath+"\"+$MyInvocation.MyCommand.Name+$ScriptRunTimeStamp+".dot") -replace ".ps1","_";
$pngFile = [System.IO.Path]::ChangeExtension($dotFile, ".png");
#$csvFile = "$location\AdminSDHolder_Members.csv"
$csvFile = ($Logfolderpath+"\"+$MyInvocation.MyCommand.Name+$ScriptRunTimeStamp+".csv") -replace ".ps1","_" ;
$Logfile = ($Logfolderpath+"\"+$MyInvocation.MyCommand.Name+$ScriptRunTimeStamp+".log") -replace ".ps1","_"

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


#endregion Globals

#region Select Action

# If no action was provided, prompt interactively
if (-not $Action) {
    Write-Host "Please choose an action:"
    Write-Host "1) Protected (default)"
    Write-Host "2) CSVFile"
    Write-Host "3) OU"
    Write-Host "4) FullScan"

    $choice = Read-Host "Enter your choice (1-4)"

    switch ($choice) {
        "1" { $Action = "Protected" }
        "2" { $Action = "CSVFile" }
        "3" { $Action = "OU" }
        "4" { $Action = "FullScan" }
        default { 
            Write-Host "Invalid choice. Defaulting to 'Protected'."
            $Action = "Protected"
        }
    }
}

#endregion Select Action

#region Main

# Globals / outputs
$EffectiveProtectedGroups = Get-DSHeuristicsProtectedGroups;
Write-Host "Effective AdminSDHolder-protected groups:" -ForegroundColor Cyan;
$EffectiveProtectedGroups | ForEach-Object { Write-Host " - $_" }

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

#region DOT and CSV

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

#endregion DOT and CSV

#endregion Main