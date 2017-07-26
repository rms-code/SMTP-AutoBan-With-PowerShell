
Import-Module Posh-SSH

#Variables and SecureString for Creds
$iplist = Get-Content "\\server\folder\notld.txt" | %{ if ($_ -imatch '^(?:[^,]*\,){5}(...(?:[^:]*){1})(?:[^\s]*\s){1}(...(?:[^,]*))') {($matches[1] -ireplace "$", "/32")} } | sort -Unique
$iplistcount = ($iplist).Count
$user = "someuser"
$file = "\\server\folder\creds.txt"
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, (Get-Content $file | ConvertTo-SecureString)
#This is just a filler IP to make a new object group as it needs an object to create, make sure its a private IP that isn't in any range you use
$appmem = "192.168.168.100"

#SSH Connection to firewall
New-SSHSession -ComputerName SERVERIP -Credential $creds

#Make sure you have group room, get highest autoban list
if ((Get-SSHSession | select SessionID).SessionID -eq 0)
{
	$sess = Get-SSHSession -SessionId 0
	$stream = $sess.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
	$stream.Write("get firewall addrgrp`r")
	Start-Sleep -Seconds 5
	$stream.Read() > .\addrgrp.txt
	$adrgrp = Get-Content .\addrgrp.txt
	$adrsort = $adrgrp -match "name: \d" -replace "name:\s"
	$adrarray = { $adrsort }.Invoke()
	$adrarray2 = $adrarray | measure -Maximum | Select Maximum | fw | Out-File .\adrlist.txt
	[string]$adrlist = Get-Content .\adrlist.txt
#Check object limit on FW, split and make read-able output for var
	$checkgrp = Invoke-SSHCommand -SessionId 0 -Command "show firewall addrgrp $adrlist"
	$checkgrp | Select Output | FL | Out-File addrgrp.txt
	$testreg = Get-Content .\addrgrp.txt
	$ipcount=($testreg -split """" -match "/32").Count
}
	else{exit}

#If the ipcount comes back and more than 299 objects
 if($ipcount + $iplistcount -ge 299){
        [string]$adrlist = Get-Content .\adrlist.txt
        [int]$adrlist += 1
        Set-Content .\adrlist.txt $adrlist
        Invoke-SSHCommand -SessionId 0 -Command "config firewall addrgrp`redit $adrlist`rappend member $appmem`rend`r" -EnsureConnection; sleep -Seconds 1
        Invoke-SSHCommand -SessionId 0 -Command "config firewall policy`redit 12`rappend srcaddr $adrlist`rend`r" -EnsureConnection; sleep -Seconds 1
        	foreach($ip in $iplist){
        	Invoke-SSHCommand -SessionId 0 -Command "config firewall address`redit $ip`rset subnet $ip`rend`r" -EnsureConnection; sleep -Seconds 1
        	Invoke-SSHCommand -SessionId 0 -Command "config firewall addrgrp`redit $adrlist`rappend member $ip`rend`r" -EnsureConnection; sleep -Seconds 1
        	}
   		Remove-SSHSession -SessionId 0,1,2
        }
        else
            {
            foreach($ip in $iplist){
            Invoke-SSHCommand -SessionId 0 -Command "config firewall address`redit $ip`rset subnet $ip`rend`r" -EnsureConnection; sleep -Seconds 1
            Invoke-SSHCommand -SessionId 0 -Command "config firewall addrgrp`redit $adrlist`rappend member $ip`rend`r" -EnsureConnection; sleep -Seconds 1
            }
    	Remove-SSHSession -SessionId 0,1,2
}


#Backup log for all banned IPS; for troubleshooting/analysis later
Add-Content -Path "\\server\folder\logs\full_list.txt" -Value $iplist

#Clear the nxlog for new IPs
Clear-Content "\\server\folder\notld.txt"
