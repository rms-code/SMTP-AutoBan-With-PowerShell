
#Variables and SecureString for Creds
$null_logins = Get-Content "\\SERVERNAME\data\nullloginlogs.txt"
Add-Content -Path "\\SERVERNAME\data\notld.txt" -Value $null_logins
$iplist = Get-Content "\\SERVERNAME\data\notld.txt" | %{ if ($_ -imatch '^(?:[^,]*\,){5}(...(?:[^:]*){1})(?:[^\s]*\s){1}(...(?:[^,]*))') {($matches[1] -ireplace "$", "/32")} } | sort -Unique
$iplistcount = ($iplist).Count
$user = "FWUSERNAME"
#encrypted pwd file
$file = "\\SERVERNAME\data\creds.txt"
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, (Get-Content $file | ConvertTo-SecureString)
#Use an IP that will never come inbound, this will be added to each new group made to start it, (you could use apipa too)
$appmem = "192.168.168.100"
$rawlist = Get-Content "\\SERVERNAME\data\notld.txt"
#SSH Connection to firewall - Make sure you have a dns entry that points to your firewall
New-SSHSession -ComputerName FIREWALLNAME -Credential $creds

#Make sure you have group room, get highest autoban list
$sess = Get-SSHSession -ComputerName FIREWALLNAME
$stream = $Sshsessions.FIREWALLNAME.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
$stream.Write("get firewall addrgrp`r")
#i have to add a bunch of returns to list everything, havn't found a better way yet.
$stream.Write("`r`r`r`r`r`r`r`r`r`r`r")
Start-Sleep -Seconds 5
$stream.Read() > .\test.txt
$adrgrp = Get-Content .\test.txt
$adrsort = $adrgrp -match "name: \d" -replace "name:\s"
$adrarray = {$adrsort}.Invoke()
$adrarray2 = $adrarray | measure -Maximum | Select Maximum | fw | Out-File .\adrlist.txt
[string]$adrlist = Get-Content .\adrlist.txt

    #Check object limit on FW, split and make read-able output for var
    $checkgrp = Invoke-SSHCommand -ComputerName FIREWALLNAME -Command "show firewall addrgrp $adrlist"
    $checkgrp | FL | Out-File test.txt
    $testreg = Get-Content .\test.txt
    $ipcount=($testreg -split """" -match "/32").Count

#If the ipcount comes back and more than 300 objects
 if($ipcount + $iplistcount -ge 295)
        {
        [string]$adrlist = Get-Content .\adrlist.txt
        [int]$adrlist += 1
        Set-Content .\adrlist.txt $adrlist
        Invoke-SSHCommand -ComputerName FIREWALLNAME -Command "config firewall addrgrp`redit $adrlist`rappend member $appmem`rend`r" ; sleep -Seconds 1
        Invoke-SSHCommand -ComputerName FIREWALLNAME -Command "config firewall policy`redit 12`rappend srcaddr $adrlist`rend`r" ; sleep -Seconds 1
        foreach($ip in $iplist){
        Invoke-SSHCommand -ComputerName FIREWALLNAME -Command "config firewall address`redit $ip`rset subnet $ip`rend`r" ; sleep -Seconds 1
        Invoke-SSHCommand -ComputerName FIREWALLNAME -Command "config firewall addrgrp`redit $adrlist`rappend member $ip`rend`r" ; sleep -Seconds 1
        }
        Remove-SSHSession -ComputerName FIREWALLNAME
        }
        else
            {
            foreach($ip in $iplist){
            Invoke-SSHCommand -ComputerName FIREWALLNAME -Command "config firewall address`redit $ip`rset subnet $ip`rend`r" ; sleep -Seconds 1
            Invoke-SSHCommand -ComputerName FIREWALLNAME -Command "config firewall addrgrp`redit $adrlist`rappend member $ip`rend`r" ; sleep -Seconds 1
            }
            Remove-SSHSession -ComputerName FIREWALLNAME
            }

#Backup log for all banned IPS; for troubleshooting/analysis later
Add-Content -Path "\\SERVERNAME\data\logs\full_list.txt" -Value $rawlist

#Clear the nxlog for new IPs
if($iplist -eq $null){}else{
	Send-MailMessage -From "" -To "" -Subject "AutoIP Bans" -Body "$iplist" -SmtpServer ""
}

Clear-Content "\\SERVERNAME\data\notld.txt"
Clear-Content "\\SERVERNAME\data\nullloginlogs.txt"