Function Invoke-HardeningKitty {

    <#
    .SYNOPSIS

        Invoke-HardeningKitty - Checks and hardens your Windows configuration


         =^._.^=
        _(      )/  HardeningKitty


        Author:  Michael Schneider
        License: MIT    
        Required Dependencies: AccessChk by Mark Russinovich
        Optional Dependencies: None


    .DESCRIPTION

        HardeningKitty supports hardening of a Windows system. The configuration of the system is
        retrieved and assessed using a finding list. In addition, the system can be hardened according
        to predefined values. HardeningKitty reads settings from the registry and uses other modules
        to read configurations outside the registry. 


    .PARAMETER FileFindingList

        Path to a finding list in CSV format. HardeningKitty has one list each for machine and user settings.


    .PARAMETER Mode
        
        The mode Config only retrieves the settings, while the mode Audit performs an assessment of the settings.
        The mode HailMary hardens the system according to recommendations of the HardeningKitty list.


    .PARAMETER EmojiSupport

        The use of emoji is activated. The terminal should support this accordingly. Windows Terminal
        offers full support.


    .PARAMETER Log
        
        The logging function is activated. The script output is additionally logged in a file. The file
        name is assigned by HardeningKitty itself and the file is stored in the same directory as the script.


    .PARAMETER LogFile

        The name and location of the log file can be defined by the user.
    
    
    .PARAMETER Report

        The retrieved settings and their assessment result are stored in CSV format in a machine-readable format.
        The file name is assigned by HardeningKitty itself and the file is stored in the same directory as the script.
    

    .PARAMETER ReportFile

        The name and location of the report file can be defined by the user.


    .PARAMETER BinaryAccesschk

        The path of the AccessChk binary can be defined by the user.


    .EXAMPLE
        
        Invoke-HardeningKitty -Mode "Audit" -Log $true -Report $true
        
        Description: HardeningKitty performs an audit, saves the results and creates a log file
    #>

    [CmdletBinding()]
    Param (
  
        # Definition of the finding list, default is machine setting list
        [ValidateScript({Test-Path $_})]
        [String]
        $FileFindingList,

        # Choose mode, read system config, audit system config, harden system config
        [ValidateSet("Audit","Config","HailMary")]
        [String]
        $Mode = "Audit",

        # Activate emoji support for Windows Terminal
        [Switch]
        $EmojiSupport = $false,

        # Create a log file
        [Switch]
        $Log = $false,

        # Define name and path of the log file
        [String]
        $LogFile,

        # Create a report file in CSV format
        [Switch]
        $Report = $false,

        # Define name and path of the report file
        [String]
        $ReportFile,

        # Define path to accessak binary
        [ValidateScript({Test-Path $_})]
        [String]
        $BinaryAccesschk
    )

    Function Write-ProtocolEntry {

        <#
        .SYNOPSIS
    
            Output of an event with timestamp and different formatting
            depending on the level. If the Log parameter is set, the
            output is also stored in a file.
        #>    

        [CmdletBinding()]
        Param (
            
            [String]
            $Text,

            [String]
            $LogLevel
        )

        $Time = Get-Date -Format G

        Switch ($LogLevel) {
            "Info"    { $Message = "[*] $Time - $Text"; Write-Host $Message; Break}
            "Debug"   { $Message = "[-] $Time - $Text"; Write-Host -ForegroundColor Cyan $Message; Break}
            "Warning" { $Message = "[?] $Time - $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
            "Error"   { $Message = "[!] $Time - $Text"; Write-Host -ForegroundColor Red $Message; Break}
            "Success" { $Message = "[$] $Time - $Text"; Write-Host -ForegroundColor Green $Message; Break}
            "Notime"  { $Message = "[*] $Text"; Write-Host -ForegroundColor Gray $Message; Break}
            Default   { $Message = "[*] $Time - $Text"; Write-Host $Message; }
        }
    
        If ($Log) {
            Add-ProtocolEntry -Text $Message
        }       
    }

    Function Add-ProtocolEntry {

        <#
        .SYNOPSIS

            Output of an event with timestamp and different formatting
            depending on the level. If the Log parameter is set, the
            output is also stored in a file.
        #>
    
        [CmdletBinding()]
        Param (
            
            [String]
            $Text
        )     

        Add-Content -Path $LogFile -Value $Text
    }

    Function Write-ResultEntry {

        <#
        .SYNOPSIS

            Output of the assessment result with different formatting
            depending on the severity level. If emoji support is enabled,
            a suitable symbol is used for the severity rating.
        #>
    
        [CmdletBinding()]
        Param (
            
            [String]
            $Text,

            [String]
            $SeverityLevel
        )

        If ($EmojiSupport) {

            Switch ($SeverityLevel) {

                "Passed" { $Emoji = [char]::ConvertFromUtf32(0x1F63A); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Gray $Message; Break}
                "Low"    { $Emoji = [char]::ConvertFromUtf32(0x1F63C); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Cyan $Message; Break}
                "Medium" { $Emoji = [char]::ConvertFromUtf32(0x1F63F); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
                "High"   { $Emoji = [char]::ConvertFromUtf32(0x1F640); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Red $Message; Break}
                Default  { $Message = "[*] $Text"; Write-Host $Message; }
            }

        } Else {

            Switch ($SeverityLevel) {

                "Passed" { $Message = "[+] $Text"; Write-Host -ForegroundColor Gray $Message; Break}
                "Low"    { $Message = "[-] $Text"; Write-Host -ForegroundColor Cyan $Message; Break}
                "Medium" { $Message = "[$] $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
                "High"   { $Message = "[!] $Text"; Write-Host -ForegroundColor Red $Message; Break}
                Default  { $Message = "[*] $Text"; Write-Host $Message; }
            }
        }
    }

    Function Add-ResultEntry {

        <#
        .SYNOPSIS

            The result of the test is saved in a CSV file with the retrieved
            value, the severity level and the recommended value.
        #>
    
        [CmdletBinding()]
        Param (
            
            [String]
            $Text
        )

        Add-Content -Path $ReportFile -Value $Text
    }

    #
    # Start Main
    #

    #
    # Log and report file
    #
    $Hostname = $env:COMPUTERNAME.ToLower()
    $FileDate = Get-Date -Format yyyyMMdd-HHmm

    If ($Log -and $LogFile.Length -eq 0) {        
        $LogFile = "hardeningkitty_log_$Hostname-$FileDate.log"
    }
    If ($Report -and $ReportFile.Length -eq 0) {
        $ReportFile = "hardeningkitty_report_$Hostname-$FileDate.csv"
    }
    If ($Report) {
        $Message = '"ID","Name","Severity","Result","Recommended"'
        Add-ResultEntry -Text $Message
    }

    #
    # Statistics
    #
    $StatsPassed = 0
    $StatsLow = 0
    $StatsMedium = 0
    $StatsHigh = 0
    $StatsTotal = 0

    #
    # Header
    #
    Write-Output "`n"
    Write-Output "      =^._.^="
    Write-Output "     _(      )/  HardeningKitty"
    Write-Output "`n"    
    Write-ProtocolEntry -Text "Starting HardeningKitty" -LogLevel "Info"

    # 
    # Definition and check for tools
    # If a tool is not available, the execution of the script is terminated
    #
    If (-Not $BinaryAccesschk) {
        $BinaryAccesschk = "C:\tmp\accesschk64.exe"
    }    
    If (-Not (Test-Path $BinaryAccesschk)) {
        Write-ProtocolEntry -Text "Binary for AccessChk not found" -LogLevel "Error"
        Break
    }
    $BinaryAuditpol = "C:\Windows\System32\auditpol.exe"
    If (-Not (Test-Path $BinaryAuditpol)) {
        Write-ProtocolEntry -Text "Binary for auditpol not found" -LogLevel "Error"
        Break
    }
    $BinaryNet = "C:\Windows\System32\net.exe"
    If (-Not (Test-Path $BinaryNet)) {
        Write-ProtocolEntry -Text "Binary for net not found" -LogLevel "Error"
        Break
    }
    $BinaryBcdedit = "C:\Windows\System32\bcdedit.exe"
    If (-Not (Test-Path $BinaryBcdedit)) {
        Write-ProtocolEntry -Text "Binary for bcdedit not found" -LogLevel "Error"
        Break
    }
    
    $BinarySecedit = "C:\Windows\System32\secedit.exe"
    If (-Not (Test-Path $BinarySecedit)) {
        Write-ProtocolEntry -Text "Binary for secedit not found" -LogLevel "Error"
        Break
    }

    #
    # Machine information
    #
    Write-Output "`n" 
    Write-ProtocolEntry -Text "Getting machine information" -LogLevel "Info"
    $MachineInformation = Get-ComputerInfo

    $Message = "Hostname: "+$MachineInformation.CsDNSHostName
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    $Message = "Domain: "+$MachineInformation.CsDomain
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    $Message = "Domain role: "+$MachineInformation.CsDomainRole
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    $Message = "Install date: "+$MachineInformation.OsInstallDate
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    $Message = "Last Boot Time: "+$MachineInformation.OsLastBootUpTime
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    $Message = "Uptime: "+$MachineInformation.OsUptime
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    $Message = "Windows: "+$MachineInformation.WindowsProductName
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    $Message = "Windows edition: "+$MachineInformation.WindowsEditionId
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    $Message = "Windows version: "+$MachineInformation.WindowsVersion
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    $Message = "Windows build: "+$MachineInformation.WindowsBuildLabEx
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"

    #
    # User information
    #
    Write-Output "`n" 
    Write-ProtocolEntry -Text "Getting user information" -LogLevel "Info"
    
    $Message = "Username: "+[Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    $Message = "Is Admin: "+$IsAdmin
    Write-ProtocolEntry -Text $Message -LogLevel "Notime"

    #
    # Start Config/Audit mode
    # The processing is done per category of the finding list.
    # The finding list defines which module is used and the arguments and recommended values for the test.
    # 
    If ($Mode -eq "Audit" -or $Mode -eq "Config") {

        # A CSV finding list is imported. HardeningKitty has one machine and one user list.
        If ($FileFindingList.Length -eq 0) {

            $CurrentLication = Get-Location
            $FileFindingList = "$CurrentLication\lists\finding_list_0x6d69636b_machine.csv"
        }

        $FindingList = Import-Csv -Path $FileFindingList -Delimiter ","
        $LastCategory = ""

        ForEach ($Finding in $FindingList) {

            #
            # Reset
            #
            $Result = ""
            
            #
            # Category
            #
            If ($LastCategory -ne $Finding.Category) {
                         
                $Message = "Starting Category " + $Finding.Category
                Write-Output "`n"                
                Write-ProtocolEntry -Text $Message -LogLevel "Info"
                $LastCategory = $Finding.Category
            }

            #
            # Get Registry Item
            # Registry entries can be read with a native PowerShell function. The retrieved value is evaluated later.
            # If the registry entry is not available, a default value is used. This must be specified in the finding list.
            #
            If ($Finding.Method -eq 'Registry') {

                If (Test-Path -Path $Finding.RegistryPath) {
                
                    try {
                        $Result = Get-ItemPropertyValue -Path $Finding.RegistryPath -Name $Finding.RegistryItem
                    } catch {
                        $Result = $Finding.DefaultValue
                    }
                } Else {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Get Registry List and search for item
            # Depending on the registry structure, the value cannot be accessed directly, but must be found within a data structure
            # If the registry entry is not available, a default value is used. This must be specified in the finding list.
            #
            ElseIf ($Finding.Method -eq 'RegistryList') {

                If (Test-Path -Path $Finding.RegistryPath) {
                
                    try {
                        $ResultList = Get-ItemProperty -Path $Finding.RegistryPath

                        If ($ResultList | Where-Object { $_ -like "*"+$Finding.RegistryItem+"*" }) {
                            $Result = $Finding.RegistryItem
                        } Else {
                            $Result = "Not found"
                        }

                    } catch {
                        $Result = $Finding.DefaultValue
                    }
                } Else {
                    $Result = $Finding.DefaultValue
                }
            }
            
            #
            # Get Audit Policy
            # The output of auditpol.exe is parsed and will be evaluated later.
            # The desired value is not output directly, some output lines can be ignored
            # and are therefore skipped. If the output changes, the parsing must be adjusted :(
            #
            ElseIf ($Finding.Method -eq 'auditpol') {

                If (-not($IsAdmin)) {
                    $Message = "ID "+$Finding.ID+", "+$Finding.Name+", Method "+$Finding.Method+" requires admin priviliges. Test skipped."
                    Write-ProtocolEntry -Text $Message -LogLevel "Error"
                    Continue
                }
                                            
                try {
                
                    $SubCategory = $Finding.Name    
                    $ResultOutput = &$BinaryAuditpol /get /subcategory:"$SubCategory"
                    
                    # "Parse" auditpol.exe output
                    $ResultOutput[4] -match '  ([a-z, /-]+)  ([a-z, ]+)' | Out-Null
                    $Result = $Matches[2]

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Get Account Policy
            # The output of net.exe is parsed and will be evaluated later.
            # It may be necessary to use the /domain parameter when calling net.exe.
            # The values of the user executing the script are read out. These may not match the password policy.
            #
            ElseIf ($Finding.Method -eq 'accountpolicy') {

                try {
                    
                    $ResultOutput = &$BinaryNet accounts

                    # "Parse" account policy
                    Switch ($Finding.Name) {
                       "Force user logoff how long after time expires" { $ResultOutput[0] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result=$Matches[2]; Break}
                       "Network security: Force logoff when logon hours expires" { $ResultOutput[0] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result=$Matches[2]; Break}
                       "Minimum password age" { $ResultOutput[1] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result=$Matches[2]; Break}
                       "Maximum password age" { $ResultOutput[2] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result=$Matches[2]; Break}
                       "Minimum password length" { $ResultOutput[3] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result=$Matches[2]; Break}
                       "Length of password history maintained" { $ResultOutput[4] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result=$Matches[2]; Break}
                       "Account lockout threshold" { $ResultOutput[5] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result=$Matches[2]; Break}
                       "Account lockout duration" { $ResultOutput[6] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result=$Matches[2]; Break}
                       "Reset account lockout counter" { $ResultOutput[7] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result=$Matches[2]; Break}
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Get Local Account Information
            # The PowerShell function Get-LocalUser is used for this.
            # In order to get the correct user, the query is made via the SID,
            # the base value of the computer must first be retrieved.
            #
            ElseIf ($Finding.Method -eq 'localaccount') {
                                           
                try {

                    # Get Computer SID
                    $ComputerSid = ((Get-LocalUser | Select-Object -First 1).SID).AccountDomainSID.ToString()

                    # Get User Status
                    $Sid = $ComputerSid+"-"+$Finding.MethodArgument
                    $ResultOutput = Get-LocalUser -SID $Sid

                    If ($Finding.Name.Contains("account status")){
                        $Result = $ResultOutput.Enabled
                    }
                    ElseIf ($Finding.Name.Contains("Renames")) {
                        $Result = $ResultOutput.Name
                    }
                    Else {
                        $Result = $Finding.DefaultValue
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # User Rights Assignment
            # Unfortunately there is no easy way to read out these results. Therefore the Sysinternals tool
            # accesschk is used and its output is parsed. To simplify parsing, the output is reduced.
            # If several users/groups have the appropriate rights, these are displayed per line. Therefore,
            # a loop must be performed over the output and all users/groups are combined in one variable at the end.
            # The values used are from the Microsoft documentation at:
            # https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment
            #
            ElseIf ($Finding.Method -eq 'accesschk') {

                If (-not($IsAdmin)) {
                    $Message = "ID "+$Finding.ID+", "+$Finding.Name+", Method "+$Finding.Method+" requires admin priviliges. Test skipped."
                    Write-ProtocolEntry -Text $Message -LogLevel "Error"
                    Continue
                }
                     
                try { 
                                   
                    $ResultOutput = &$BinaryAccesschk -accepteula -nobanner -a $Finding.MethodArgument

                    # "Parse" accesschk.exe output
                    ForEach($ResultEntry in $ResultOutput) {

                        If ($ResultEntry.Contains("No accounts granted")) {
                            
                            $Result = ""
                            Break

                        } Else {
                            
                            [String] $Result += $ResultEntry.Trim()+";"
                        }
                    }
                    # Remove last character
                    $Result = $Result -replace “.$”
                } catch {
                    $Result = $Finding.DefaultValue
                }                
            }

            #
            # Windows Optional Feature
            # Yay, a native PowerShell function! The status of the feature can easily be read out directly.
            #
            ElseIf ($Finding.Method -eq 'WindowsOptionalFeature') {

                If (-not($IsAdmin)) {
                    $Message = "ID "+$Finding.ID+", "+$Finding.Name+", Method "+$Finding.Method+" requires admin priviliges. Test skipped."
                    Write-ProtocolEntry -Text $Message -LogLevel "Error"
                    Continue
                }

                try {
                    
                    $ResultOutput = Get-WindowsOptionalFeature -Online -FeatureName $Finding.MethodArgument 
                    $Result = $ResultOutput.State

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Get CimInstance and search for item
            # Via a CIM instance classes can be read from the CIM server.
            # Afterwards, you have to search for the correct property within the class.
            #
            ElseIf ($Finding.Method -eq 'CimInstance') {
                
                try {

                    $ResultList = Get-CimInstance -ClassName $Finding.ClassName -Namespace $Finding.Namespace
                    $Property = $Finding.Property
                                         
                    If ($ResultList.$Property | Where-Object { $_ -like "*"+$Finding.RecommendedValue+"*" }) {
                        $Result = $Finding.RecommendedValue
                    } Else {
                        $Result = "Not available"
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # BitLocker Drive Encryption
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            #
            ElseIf ($Finding.Method -eq 'BitLockerVolume') {

                If (-not($IsAdmin)) {
                    $Message = "ID "+$Finding.ID+", "+$Finding.Name+", Method "+$Finding.Method+" requires admin priviliges. Test skipped."
                    Write-ProtocolEntry -Text $Message -LogLevel "Error"
                    Continue
                }

                try {
                    
                    $ResultOutput = Get-BitLockerVolume -MountPoint C:
                    If ($ResultOutput.VolumeType -eq 'OperatingSystem') {
                        $ResultArgument = $Finding.MethodArgument 
                        $Result = $ResultOutput.$ResultArgument
                    } Else {
                        $Result = "Manual check required"
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # PowerShell Language Mode
            # This is a single purpose function, the desired configuration is output directly.
            #
            ElseIf ($Finding.Method -eq 'LanguageMode') {

                try {
                                    
                    $ResultOutput = $ExecutionContext.SessionState.LanguageMode                    
                    $Result = $ResultOutput

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Microsoft Defender Preferences
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            #
            ElseIf ($Finding.Method -eq 'MpPreference') {

                try {
                                    
                    $ResultOutput = Get-MpPreference
                    $ResultArgument = $Finding.MethodArgument 
                    $Result = $ResultOutput.$ResultArgument

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Microsoft Defender Preferences - Attack surface reduction rules (ASR rules)
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            #
            ElseIf ($Finding.Method -eq 'MpPreferenceAsr') {

                try {
                                    
                    $ResultOutput = Get-MpPreference
                    $ResultAsrIds = $ResultOutput.AttackSurfaceReductionRules_Ids
                    $ResultAsrActions = $ResultOutput.AttackSurfaceReductionRules_Actions
                    $Counter = 0

                    ForEach ($AsrRule in $ResultAsrIds) {

                        If ($AsrRule -eq $Finding.MethodArgument) {
                            $Result = $ResultAsrActions[$Counter]
                            Continue
                        }
                        $Counter++
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Exploit protection
            # The values are saved from a PowerShell function into an object.
            # The desired arguments can be accessed directly.
            # Since the object has several dimensions and there is only one dimension
            # in the finding list (lazy) a workaround with split must be done...
            #
            ElseIf ($Finding.Method -eq 'Processmitigation') {

                try {  
                                                  
                    $ResultOutput = Get-Processmitigation -System
                    $ResultArgumentArray = $Finding.MethodArgument.Split(".")
                    $ResultArgument0 = $ResultArgumentArray[0]
                    $ResultArgument1 = $ResultArgumentArray[1]
                    $Result = $ResultOutput.$ResultArgument0.$ResultArgument1

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # bcdedit
            # Again, the output of a tool must be searched and parsed. Ugly...
            #
            ElseIf ($Finding.Method -eq 'bcdedit') {

                If (-not($IsAdmin)) {
                    $Message = "ID "+$Finding.ID+", "+$Finding.Name+", Method "+$Finding.Method+" requires admin priviliges. Test skipped."
                    Write-ProtocolEntry -Text $Message -LogLevel "Error"
                    Continue
                }

                try {
                                    
                    $ResultOutput = &$BinaryBcdedit
                    $ResultOutput = $ResultOutput | Where-Object { $_ -like "*"+$Finding.RecommendedValue+"*" }
                    
                    If ($ResultOutput -match ' ([a-z,A-Z]+)') {
                        $Result = $Matches[1]
                    } Else {
                        $Result = $Finding.DefaultValue
                    }

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # FirewallRule
            # Search for a specific firewall rule with a given name
            #
            ElseIf ($Finding.Method -eq 'FirewallRule') {

                try {
                    
                    $ResultOutput = Get-NetFirewallRule -DisplayName $Finding.Name 2> $null
                    $Result = $ResultOutput.Enabled

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Compare result value and recommendation
            # The finding list specifies the test, as well as the recommended values.
            # There are two output formats, one for command line output and one for the CSV file.
            #
            If ($Mode -eq "Audit") {
 
                $ResultPassed = $false
                Switch($Finding.Operator) {

                    "="  { If ([string] $Result -eq $Finding.RecommendedValue) { $ResultPassed = $true }; Break}
                    "<=" { try { If ([int]$Result -le [int]$Finding.RecommendedValue) { $ResultPassed = $true }} catch { $ResultPassed = $false }; Break}
                    ">=" { try { If ([int]$Result -ge [int]$Finding.RecommendedValue) { $ResultPassed = $true }} catch { $ResultPassed = $false }; Break}
                    "contains" { If ($Result.Contains($Finding.RecommendedValue)) { $ResultPassed = $true }; Break}
                    "!="  { If ([string] $Result -ne $Finding.RecommendedValue) { $ResultPassed = $true }; Break}
                }

                If ($ResultPassed) {

                    # Passed
                    $Message = "ID "+$Finding.ID+", "+$Finding.Name+", Result=$Result, Severity=Passed"
                    Write-ResultEntry -Text $Message -SeverityLevel "Passed"

                    If ($Log) {
                        Add-ProtocolEntry -Text $Message
                    }
                    
                    If ($Report) {
                        $Message = '"'+$Finding.ID+'","'+$Finding.Name+'","Passed","'+$Result+'"'
                        Add-ResultEntry -Text $Message
                    }

                    # Increment Counter
                    $StatsPassed++

                } Else {

                    # Failed
                    If ($Finding.Operator -eq "!=") {
                        $Message = "ID "+$Finding.ID+", "+$Finding.Name+", Result=$Result, Recommended=Not "+$Finding.RecommendedValue+", Severity="+$Finding.Severity
                    }
                    Else {
                        $Message = "ID "+$Finding.ID+", "+$Finding.Name+", Result=$Result, Recommended="+$Finding.RecommendedValue+", Severity="+$Finding.Severity
                    }
                    
                    Write-ResultEntry -Text $Message -SeverityLevel $Finding.Severity

                    If ($Log) {
                        Add-ProtocolEntry -Text $Message
                    }

                    If ($Report) {
                        $Message = '"'+$Finding.ID+'","'+$Finding.Name+'","'+$Finding.Severity+'","'+$Result+'","'+$Finding.RecommendedValue+'"'
                        Add-ResultEntry -Text $Message
                    }

                    # Increment Counter
                    Switch($Finding.Severity) {

                        "Low"    { $StatsLow++; Break}
                        "Medium" { $StatsMedium++; Break}
                        "High"   { $StatsHigh++; Break}
                    }
                }

            #
            # Only return received value
            #
            } Elseif ($Mode -eq "Config") {

                $Message = "ID "+$Finding.ID+"; "+$Finding.Name+"; Result=$Result"
                Write-ResultEntry -Text $Message

                If ($Log) {
                    Add-ProtocolEntry -Text $Message
                }
                If ($Report) {
                    $Message = '"'+$Finding.ID+'","'+$Finding.Name+'",,"'+$Result+'",'
                    Add-ResultEntry -Text $Message
                }
            }
        }

    } Elseif ($Mode = "HailMary") {

        # A CSV finding list is imported. HardeningKitty has one machine and one user list.
        If ($FileFindingList.Length -eq 0) {

            $CurrentLication = Get-Location
            $FileFindingList = "$CurrentLication\lists\finding_list_0x6d69636b_machine.csv"
        }

        $FindingList = Import-Csv -Path $FileFindingList -Delimiter ","
        $LastCategory = ""

        ForEach ($Finding in $FindingList) {

            # Todo
            # Set all hardening settings in findings file
            # You can do that as long as you know you're doing

            #
            # Category
            #
            If ($LastCategory -ne $Finding.Category) {
                         
                $Message = "Starting Category " + $Finding.Category
                Write-Output "`n"                
                Write-ProtocolEntry -Text $Message -LogLevel "Info"
                $LastCategory = $Finding.Category
            }

            #
            # FirewallRule
            # Create a firewall rule. First it will be checked if the rule already exists
            #
            If ($Finding.Method -eq 'FirewallRule') {

                If (-not($IsAdmin)) {
                    $Message = "ID "+$Finding.ID+", "+$Finding.Name+", Method "+$Finding.Method+" requires admin priviliges. Test skipped."
                    Write-ProtocolEntry -Text $Message -LogLevel "Error"
                    Continue
                }

                $FwRule = $Finding.MethodArgument
                $FwRuleArray = $FwRule.Split("|")

                $FwDisplayName = $Finding.Name 
                $FwProfile = $FwRuleArray[0]
                $FwDirection = $FwRuleArray[1]
                $FwAction = $FwRuleArray[2]
                $FwProtocol = $FwRuleArray[3]
                $FwLocalPort = @($FwRuleArray[4]).Split(",")
                $FwProgram = $FwRuleArray[5]

                # Check if rule already exists
                try {
                                    
                    $ResultOutput = Get-NetFirewallRule -DisplayName $FwDisplayName 2> $null
                    $Result = $ResultOutput.Enabled

                } catch {
                    $Result = $Finding.DefaultValue
                }

                # Go on if rule not exists
                If (-Not $Result) {

                    If ($FwProgram -eq "") {
                        
                        $ResultRule = New-NetFirewallRule -DisplayName $FwDisplayName -Profile $FwProfile -Direction $FwDirection -Action $FwAction -Protocol $FwProtocol -LocalPort $FwLocalPort
                    }
                    Else {
                        $ResultRule = New-NetFirewallRule -DisplayName $FwDisplayName -Profile $FwProfile -Direction $FwDirection -Action $FwAction -Program "$FwProgram"
                    }

                    If ($ResultRule.PrimaryStatus -eq "OK") {

                        # Excellent
                        $ResultText = "Rule created" 
                        $Message = "ID "+$Finding.ID+", "+$Finding.Name+", " + $ResultText
                        $MessageSeverity = "Passed"
                    } 
                    Else {
                        # Bogus
                        $ResultText = "Rule not created" 
                        $Message = "ID "+$Finding.ID+", "+$Finding.Name+", " + $ResultText
                        $MessageSeverity = "High"
                    }
                }
                Else {
                    # Excellent
                    $ResultText = "Rule already exists" 
                    $Message = "ID "+$Finding.ID+", "+$Finding.Name+", " + $ResultText
                    $MessageSeverity = "Passed"
                }
                
                Write-ResultEntry -Text $Message -SeverityLevel $MessageSeverity

                If ($Log) {
                    Add-ProtocolEntry -Text $Message
                }
                    
                If ($Report) {
                    $Message = '"'+$Finding.ID+'","'+$Finding.Name+'","'+$ResultText+'"'
                    Add-ResultEntry -Text $Message
                }
            }
        }
    }
    
    Write-Output "`n"
    Write-ProtocolEntry -Text "HardeningKitty is done" -LogLevel "Info"
    If ($Mode -eq "Audit") {
        $StatsTotal = $StatsPassed + $StatsLow + $StatsMedium + $StatsHigh
        Write-ProtocolEntry -Text "HardeningKitty Statistics: Total checks: $StatsTotal - Passed: $StatsPassed, Low: $StatsLow, Medium: $StatsMedium, High: $StatsHigh" -LogLevel "Info"
    }
    Write-Output "`n"
}