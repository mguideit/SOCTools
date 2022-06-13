Write-Host "__        ___     _____     _                  
\ \      / (_)_ _|_   _| __(_) __ _  __ _  ___ 
 \ \ /\ / /| | '_ \| || '__| |/ _` |/ _` |/ _ \
  \ V  V / | | | | | || |  | | (_| | (_| |  __/
   \_/\_/  |_|_| |_|_||_|  |_|\__,_|\__, |\___|
                                    |___/       `n`thttps://www.linkedin.com/in/m-hassoub`n`n`n"


$Folder= Test-Path -Path .\Output
if (-Not $Folder){
    Write-Output "[+] Creating Output Folder..."
    New-Item -ItemType Directory "Output" | Out-Null 
}


$out_Dir = ".\Output"


#####################
# Processes
#####################

function processesList {
    Write-Output "[+] Enumerating Processes..."
    Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, Description, ExecutablePath,  CommandLine, Handle | Export-Csv -Path $out_Dir\Processes.csv -NoTypeInformation
}


#####################
# TCP Connections
#####################

function connectionsTCPList {
    Write-Output "[+] Enumerating TCP Connections..."
    Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv -Path  $out_Dir\TCPConnections.csv -NoTypeInformation
}


#####################
# UDP Connections
#####################

function connectionsUDPList {
    Write-Output "[+] Enumerating UDP Connections..."
    Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,CreationTime | Export-Csv -Path $out_Dir\UDPConnections.csv -NoTypeInformation
}


#####################
# SMB
#####################

function smbInfo{
    Write-Host "[+] Enumerating SMB Shares on This Host..."
    "`n============================================" | Out-File -FilePath "$out_Dir\SMB.txt"
    "List of Shares on This Host" | Out-File -FilePath $out_Dir\SMB.txt -Append
    "============================================`n" | Out-File -FilePath "$out_Dir\SMB.txt" -Append
    Get-SmbShare | Out-File -FilePath $out_Dir\SMB.txt -Append

    Write-Host "[+] Enumerating SMB Opened Sessions to This Host..."
    "`n`n============================================" | Out-File -FilePath "$out_Dir\SMB.txt" -Append
    "List of SMB Opened Sessions to This Host" | Out-File -FilePath $out_Dir\SMB.txt -Append
    "============================================`n" | Out-File -FilePath "$out_Dir\SMB.txt" -Append
    Get-SmbSession | Out-File -FilePath $out_Dir\SMB.txt -Append

    Write-Host "[+] Enumerating SMB Opened Files on This Host..."
    "`n`n============================================" | Out-File -FilePath "$out_Dir\SMB.txt" -Append
    "List of SMB Opened Files on This Host" | Out-File -FilePath $out_Dir\SMB.txt -Append
    "============================================`n" | Out-File -FilePath "$out_Dir\SMB.txt" -Append
    Get-SmbOpenFile | Out-File -FilePath $out_Dir\SMB.txt -Append

    Write-Host "[+] Enumerating SMB Connections Established from This Host..."
    "`n`n============================================" | Out-File -FilePath "$out_Dir\SMB.txt" -Append
    "List of SMB Connections Established from This Hostt" | Out-File -FilePath $out_Dir\SMB.txt -Append
    "============================================`n" | Out-File -FilePath "$out_Dir\SMB.txt" -Append
    Get-SmbConnection | Out-File -FilePath $out_Dir\SMB.txt -Append
}


#####################
# Firewall config
#####################

function firewallConf {
    Write-Output "[+] Enumerating Firewall Config..."
    Get-NetFirewallProfile | Export-Csv -Path $out_Dir\FirewallConfig.csv -NoTypeInformation
}


#####################
# Auto Startup
#####################

function autoStartup {
    Write-Output "[+] Enumerating Auto Startups..."
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Export-Csv -Path $out_Dir\AutoStartup.csv -NoTypeInformation
}


#####################
# Users
#####################

function localUsers {
    Write-Output "[+] Enumerating Local Users..."
    Get-LocalUser | select * | Export-Csv -Path $out_Dir\LocalUsers.csv -NoTypeInformation
}


#####################
# Groups
#####################

function localGroups {
    Write-Output "[+] Enumerating Local Groups..."
    Get-LocalGroup | Select-Object Name,SID,Description | Export-Csv -Path $out_Dir\LocalGroups.csv -NoTypeInformation
}


#####################
# Administrators Group
#####################

function adminGroup {
    Write-Output "[+] Enumerating Administrators Group Members..."
    Get-LocalGroupMember -Group "Administrators" | select * | Export-Csv -Path $out_Dir\AdministratorsGroupMembers.csv -NoTypeInformation
}


#####################
# Scheduled Tasks
#####################

function scheduledTasks {
    Write-Output "[+] Enumerating Scheduled Tasks..."
    schtasks /query /fo CSV /v > "$out_Dir\ScheduledTasks.csv" 
}


#####################
# Network Config
#####################

function netConf {
    Write-Output "[+] Enumerating Network Config..."
    ipconfig /all > "$out_Dir\NetworkConf.txt"
}


#####################
# Failure Logons
#####################
# This function copied from https://livebook.manning.com/book/powershell-deep-dives/chapter-6/42

function failLogons {
    Write-Output "[+] Enumerating Last 100 Failed Logons..."

    function Get-FailureReason {
        Param($FailureReason)
        switch ($FailureReason) {
          '0xC0000064' {"Account does not exist"; break;}
          '0xC000006A' {"Incorrect password"; break;}
          '0xC000006D' {"Incorrect username or password"; break;}
          '0xC000006E' {"Account restriction"; break;}
          '0xC000006F' {"Invalid logon hours"; break;}
          '0xC000015B' {"Logon type not granted"; break;}
          '0xc0000070' {"Invalid Workstation"; break;}
          '0xC0000071' {"Password expired"; break;}
          '0xC0000072' {"Account disabled"; break;}
          '0xC0000133' {"Time difference at DC"; break;}
          '0xC0000193' {"Account expired"; break;}
          '0xC0000224' {"Password must change"; break;}
          '0xC0000234' {"Account locked out"; break;}
          '0x0' {"0x0"; break;}
          default {"Other"; break;}
      }
    }
    Get-EventLog -LogName 'security' -InstanceId 4625 -Newest 100 | Select-Object @{Label='Time';Expression={$_.TimeGenerated.ToString('g')}},
    @{Label='User Name';Expression={$_.replacementstrings[5]}},
    @{Label='Client Name';Expression={$_.replacementstrings[13]}},
    @{Label='Client Address';Expression={$_.replacementstrings[19]}},
    @{Label='Server Name';Expression={$_.MachineName}},
    @{Label='Failure Status';Expression={Get-FailureReason($_.replacementstrings[7])}},
    @{Label='Failure Sub Status';Expression={Get-FailureReason($_.replacementstrings[9])}} | Export-Csv  -Path $out_Dir\FailedlLogons.csv -NoTypeInformation
    

}


#####################
# Success Logons
#####################

function successLogons{
    Write-Output "[+] Enumerating Last 100 Success Logons..."

    function logonType{
        Param($codeVal)
        switch($codeVal){
            '0'  {"System"; break;}
            '2'  {"Interactive"; break;}
            '3'  {"Network"; break;}
            '4'  {"Batch"; break;}
            '5'  {"Service"; break;}
            '6'  {"Proxy"; break;}
            '7'  {"Unlock"; break;}
            '8'  {"NetworkCleartext"; break;}
            '9'  {"NewCredentials"; break;}
            '10' {"RemoteInteractive"; break;}
            '11' {"CachedInteractive"; break;}
            '12' {"CachedRemoteInteractive"; break;}
            '13' {"CachedUnlock"; break;}
            default {"Other"; break;}
        }
    
    }


   Get-EventLog -LogName 'security' -InstanceId 4624 -Newest 100 | select @{Label='Time';Expression={$_.TimeGenerated.ToString('g')}},
   @{Label='UserName';Expression={$_.ReplacementStrings[5]}},
   @{Label='Logon Type';Expression={logonType($_.ReplacementStrings[8])}},
   @{Label='Authentication';Expression={$_.ReplacementStrings[10]}},
   @{Label='Client Name';Expression={$_.ReplacementStrings[11]}},
   @{Label='Client Address';Expression={$_.ReplacementStrings[18]}} | Export-Csv  -Path $out_Dir\SuccesslLogons.csv -NoTypeInformation
}


#####################
# WMI
#####################

function wmiQuery {
     Write-Host "[+] Enumerating WMI..."
    "`n============================================" | Out-File -FilePath "$out_Dir\WMI.txt"
    "WMI Event Filters" | Out-File -FilePath $out_Dir\WMI.txt -Append
    "============================================`n" | Out-File -FilePath "$out_Dir\WMI.txt" -Append
    Get-WMIObject -Namespace root/Subscription -Class __EventFilter | Out-File -FilePath $out_Dir\WMI.txt -Append

    "`n============================================" | Out-File -FilePath "$out_Dir\WMI.txt" -Append
    "WMI Event Consumers" | Out-File -FilePath $out_Dir\WMI.txt -Append
    "============================================`n" | Out-File -FilePath "$out_Dir\WMI.txt" -Append
    Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Out-File -FilePath $out_Dir\WMI.txt -Append

    "`n============================================" | Out-File -FilePath "$out_Dir\WMI.txt" -Append
    "WMI Event Bindings" | Out-File -FilePath $out_Dir\WMI.txt -Append
    "============================================`n" | Out-File -FilePath "$out_Dir\WMI.txt" -Append
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Out-File -FilePath $out_Dir\WMI.txt -Append

    "`n============================================" | Out-File -FilePath "$out_Dir\WMI.txt" -Append
    "Listing WMI AutoRecover Folder" | Out-File -FilePath $out_Dir\WMI.txt -Append
    "============================================`n" | Out-File -FilePath "$out_Dir\WMI.txt" -Append
    Get-ChildItem C:\Windows\System32\wbem\AutoRecover | Out-File -FilePath $out_Dir\WMI.txt -Append

}


#####################
# Administrators Group
#####################

function adminGroup {
    Write-Output "[+] Enumerating Administrators Group Members..."

    Get-LocalGroupMember -Group "Administrators" | select * | Export-Csv -Path $out_Dir\AdministratorsGroupMembers.csv -NoTypeInformation
}


#####################
# Services Status
#####################

function servicesStatus {
    Write-Output "[+] Enumerating Services Status..."
    Get-Service | Select-Object Status, Name, DisplayName, StartType  | Sort-Object Status | Export-Csv -Path $out_Dir\ServicesStatus.csv -NoTypeInformation
}


#####################
# Services Created
#####################

function servicesCreated {
    Write-Output "[+] Enumerating Last 100 Created Services..."

    Get-EventLog -LogName System  | Where-Object {$_.EventID -eq 7045} | Select-Object -Last 100 | Select-Object @{Label='Time Created';Expression={$_.TimeGenerated}},
    @{Label='Service Name';Expression={$_.ReplacementStrings[0]}},
    @{Label='Service File Name';Expression={$_.ReplacementStrings[1]}},
    @{Label='Service Type';Expression={$_.ReplacementStrings[2]}},
    @{Label='Service Start Type';Expression={$_.ReplacementStrings[3]}},
    @{Label='Source';Expression={$_.Source}} | Export-Csv  -Path $out_Dir\ServicesCreated.csv -NoTypeInformation
}


#####################################
# Services Terminated Unexpectedly
#####################################

function servicesTerminated {
    Write-Output "[+] Enumerating Last 100 Unexpectedly Terminated Services..."

    Get-EventLog -LogName System  | Where-Object {$_.EventID -eq 7034} | Select-Object -Last 100 | Select-Object @{Label='Time Craeted';Expression={$_.TimeGenerated}},
    @{Label='Source';Expression={$_.Source}},
    @{Label='Message';Expression={$_.Message}} | Export-Csv  -Path $out_Dir\ServicesTerminatedUnexpectedly.csv -NoTypeInformation
}




processesList
connectionsTCPList
connectionsUDPList
smbInfo
firewallConf
autoStartup
localUsers
localGroups
adminGroup
scheduledTasks
netConf
failLogons
successLogons
wmiQuery
servicesStatus
servicesCreated
servicesTerminated