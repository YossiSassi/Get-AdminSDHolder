# Get-AdminSDHolder
###  Analyze effective protected groups in AD, honoring dsHeuristics. Outputs to Console, CSV and DOT/PNG (creates a Visual Map using graphviz)
Tired of trying to understand how AdminCount works in your domain? How recursive nested group membership affects privileged members? need a clear mapping of all direct and nested members of privileged groups in your AD domain?<br><br>
The script performs the following:<br>
- Enumerate AdminSDHolder-protected groups and members<br>
- Show recurive membership, indicating direct vs. nested members<br>
- Show the source group if nested<br>
- Include AdminCount value and DN (distinguishedname)<br>
- Generate CSV + DOT graph files (for Visual Map)<br>
- Auto-render to PNG & open Visual Map (if Graphviz is available)<br><br>
![Sample results](/screenshots/AdminSDHolder_Map.png) <br><br>
Usage:
```
.\Get-AdminSDHolder.ps1
```
![Sample results](/screenshots/getadminsdholder2.png) <br><br>
CSV Output:<br>
![Sample results](/screenshots/getadminsdholder1.png)<br><br>
<b>To generate the Visual Map</b>, you can download graphviz from
<a title="https://graphviz.org" href="https://graphviz.org" target="_blank"><strong>https://graphviz.org</strong></a><br>
To render manually:<br>
```
dot -Tpng "PATH_TO_AdminSDHolder_Map.dot" -o "PATH_TO_AdminSDHolder_Map.png"
```
<br>
You can use the generated CSV file to quickly <b>get all accounts with AdminCount=1 which are NOT direct nor nested members of privileged groups</b>.<br>
These accounts need to be checked, and normally <b>reset their AdminCount</b> attribute value (since it prevents ACL inheritence/delegations etc.):<br><br>

```
$AdminCount = Get-ADObject -LDAPFilter "(admincount=1)" -Properties samaccountname | where objectclass -ne "group";
$AdminSDHolder = Import-Csv .\AdminSDHolder_Members.csv;
compare $AdminCount.samaccountname $AdminSDHolder.member | where {$_.sideIndicator -eq '<=' -and $_.inputobject -ne 'krbtgt'}
```
![Sample results](/screenshots/getadminsdholder3.png)<br><br>
<b>Comments and improvements are welcome!</b>
