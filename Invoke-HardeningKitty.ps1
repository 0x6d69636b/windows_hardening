<#
    Invoke-HardeningKitty - Checks and hardens your Windows configuration

    Author: Michael Schneider
    License: MIT    
    Required Dependencies: None
    Optional Dependencies: None
#>

[CmdletBinding()]

Param (
  
    [ValidateScript({Test-Path $_})]
    [String]
    $FindingListFile = "finding_list_0x6d69636b_machine.csv",

    [ValidateSet("Audit","Config","HailMary")]
    [String]
    $Mode = "Audit",

    [Bool]
    $EmojiSupport = $false
)


<#
    to do:
    * [ ] Build checks for other items then registy
    * [ ] Add all registry checks
    * [ ] Create machine readable output file
    * [ ] Create log file
    * [ ] Build modules based on categories
#>

Function Write-ProtocolEntry($Text, $LogLevel) {

    $Time = Get-Date -Format G

    Switch ($LogLevel) {
        "Info" { $Message = "[*] $Time - $Text"; Write-Host $Message; Break}
        "Debug" { $Message = "[-] $Time - $Text"; Write-Host -ForegroundColor Cyan $Message; Break}
        "Warning" { $Message = "[?] $Time - $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
        "Error" { $Message = "[!] $Time - $Text"; Write-Host -ForegroundColor Red $Message; Break}
        "Success" { $Message = "[$] $Time - $Text"; Write-Host -ForegroundColor Green $Message; Break}
        Default { $Message = "[*] $Time - $Text"; Write-Host $Message; }
    }    
    # Add-Content -Path $ProtocolPath -Value $Message
}

Function Write-Result($Text, $SeverityLevel) {

    If($EmojiSupport) {
        Switch ($SeverityLevel) {
            "Passed" { $Emoji = [char]::ConvertFromUtf32(0x1F63A); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Gray $Message; Break}
            "Low" { $Emoji = [char]::ConvertFromUtf32(0x1F63C); $Message = "[$Emoji]  $Text"; Write-Host -ForegroundColor Cyan $Message; Break}        
            "Medium" { $Emoji = [char]::ConvertFromUtf32(0x1F63F); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
            "High" { $Emoji = [char]::ConvertFromUtf32(0x1F640); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Red $Message; Break}
            Default { $Message = "[*] $Text"; Write-Host $Message; }
        }
    } Else {
        Switch ($SeverityLevel) {
            "Passed" { $Message = "[+] $Text"; Write-Host -ForegroundColor Gray $Message; Break}
            "Low" { $Message = "[-] $Text"; Write-Host -ForegroundColor Cyan $Message; Break}        
            "Medium" { $Message = "[$] $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
            "High" { $Message = "[!] $Text"; Write-Host -ForegroundColor Red $Message; Break}
            Default { $Message = "[*] $Text"; Write-Host $Message; }
        }
    }
}

Function Import-FindingList {

    $FindingList = Import-Csv -Path $FindingListFile -Delimiter ","
    Return $FindingList
}

Function Main {

    Write-Output "`n"
    Write-Output "      =^._.^="
    Write-Output "     _(      )/  HardeningKitty"
    Write-Output "`n"    
    Write-ProtocolEntry "Starting HardeningKitty" "Info"

    # 
    # Tools
    #
    $BinaryAccesschk = "C:\tmp\accesschk64.exe"
    If (-Not (Test-Path $BinaryAccesschk)) {
        Write-ProtocolEntry "Binary for accesschk not found" "Error"
        Exit
    }
    $BinaryAuditpol = "C:\Windows\System32\auditpol.exe"
    If (-Not (Test-Path $BinaryAuditpol)) {
        Write-ProtocolEntry "Binary for auditpol not found" "Error"
        Exit
    }
    $BinaryNet = "C:\Windows\System32\net.exe"
    If (-Not (Test-Path $BinaryNet)) {
        Write-ProtocolEntry "Binary for net not found" "Error"
        Exit
    }

    #
    # Machine information
    #
    Write-Output "`n" 
    Write-ProtocolEntry "Getting machine information" "Info"
    $MachineInformation = Get-ComputerInfo

    $Message = "Hostname: "+$MachineInformation.CsDNSHostName
    Write-Result $Message "Passed"
    $Message = "Domain: "+$MachineInformation.CsDomain
    Write-Result $Message "Passed"
    $Message = "Domain role: "+$MachineInformation.CsDomainRole
    Write-Result $Message "Passed"
    $Message = "Uptime: "+$MachineInformation.OsUptime
    Write-Result $Message "Passed"
    $Message = "Install date: "+$MachineInformation.OsInstallDate
    Write-Result $Message "Passed"
    $Message = "Windows: "+$MachineInformation.WindowsProductName
    Write-Result $Message "Passed"
    $Message = "Windows edition: "+$MachineInformation.WindowsEditionId
    Write-Result $Message "Passed"
    $Message = "Windows version: "+$MachineInformation.WindowsVersion
    Write-Result $Message "Passed"
    $Message = "Windows build: "+$MachineInformation.WindowsBuildLabEx
    Write-Result $Message "Passed"

    #
    # Machine information
    #
    Write-Output "`n" 
    Write-ProtocolEntry "Getting user information" "Info"
    
    $Message = "Username: "+[Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Result $Message "Passed"
    $Message = "Is Admin: "+([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    Write-Result $Message "Passed"

    #
    # Start Config/Audit mode
    # 
    If ($Mode -eq "Audit" -or $Mode -eq "Config") {

        $FindingList = Import-FindingList
        $LastCategory = ""

        ForEach ($Finding in $FindingList) {

            #
            # Reset
            #
            $Result = ""
            
            #
            # Category
            #
            If($LastCategory -ne $Finding.Category) {              
                $Message = "Starting Category " + $Finding.Category
                Write-Output "`n"                
                Write-ProtocolEntry $Message "Info"                
                $LastCategory = $Finding.Category
            }

            #
            # Get Registry Item
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
            #
            If ($Finding.Method -eq 'RegistryList') {

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
            #
            Elseif ($Finding.Method -eq 'auditpol') {

                $SubCategory = $Finding.Name                
                try {
                    
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
            #
            Elseif ($Finding.Method -eq 'accountpolicy') {
                                           
                try {
                    
                    $ResultOutput = &$BinaryNet accounts

                    # "Parse" account policy
                    Switch ($Finding.Name) {
                       "Force user logoff how long after time expires" { $ResultOutput[0] -match '([a-zA-Z:, /-]+)  ([a-z0-9, ]+)' | Out-Null; $Result=$Matches[2]; Break}
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
            # User Rights Assignment
            # https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment
            #
            Elseif ($Finding.Method -eq 'accesschk') {
                                           
                try {                    
                    $ResultOutput = &$BinaryAccesschk -accepteula -nobanner -a $Finding.MethodArgument

                    # "Parse" accesschk.exe output
                    ForEach($ResultEntry in $ResultOutput) {

                        If ($ResultEntry.Contains("No accounts granted")) {
                            $Result = ""
                            Break
                        } else {
                            $ResultEntry -match '([a-z,A-Z,\\," "]+)' | Out-Null
                            [String] $Result += $Matches[0]+";"
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
            #
            Elseif ($Finding.Method -eq 'WindowsOptionalFeature') {

                try {
                    
                    $ResultOutput = Get-WindowsOptionalFeature -Online -FeatureName $Finding.MethodArgument 
                    $Result = $ResultOutput.State

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Get CimInstance and search for item
            #
            If ($Finding.Method -eq 'CimInstance') {
                
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
            # BitLocker Drive Encryptionc
            #
            Elseif ($Finding.Method -eq 'BitLockerVolume') {

                try {
                    
                    $ResultOutput = Get-BitLockerVolume
                    $ResultArgument = $Finding.MethodArgument 
                    $Result = $ResultOutput.$ResultArgument

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # PowerShell Language Mode
            #
            Elseif ($Finding.Method -eq 'LanguageMode') {

                try {
                                    
                    $ResultOutput = $ExecutionContext.SessionState.LanguageMode                    
                    $Result = $ResultOutput

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            #
            # Windows Defender Preferences
            #
            Elseif ($Finding.Method -eq 'MpPreference') {

                try {
                                    
                    $ResultOutput = Get-MpPreference
                    $ResultArgument = $Finding.MethodArgument 
                    $Result = $ResultOutput.$ResultArgument

                } catch {
                    $Result = $Finding.DefaultValue
                }
            }

            If ($Mode -eq "Audit") {
            
                #
                # Compare result value and recommendation
                #
                $ResultPassed = $false
                Switch($Finding.Operator) {
                    "=" { If ($Result -eq $Finding.RecommendedValue) { $ResultPassed = $true }; Break}
                    "<=" { If ([int]$Result -le [int]$Finding.RecommendedValue) { $ResultPassed = $true }; Break}
                    ">=" { If ([int]$Result -ge [int]$Finding.RecommendedValue) { $ResultPassed = $true }; Break}
                }

                If ($ResultPassed) {
                    # Passed
                    $Message = "ID "+$Finding.ID+"; "+$Finding.Name+"; Passed"
                    Write-Result $Message "Passed"
                } Else {
                    # Failed
                    $Message = "ID "+$Finding.ID+"; "+$Finding.Name+"; Result=$Result; Recommended="+$Finding.RecommendedValue+"; Severity="+$Finding.Severity
                    Write-Result $Message $Finding.Severity
                }

            }
            Elseif ($Mode -eq "Config") {

                $Message = "ID "+$Finding.ID+"; "+$Finding.Name+"; Result=$Result"
                Write-Result $Message ""
            }
        }
    } Elseif ($Mode = "HailMary") {

        # Set all hardening settings in findings file
        # You can do that as long as you know you're doing
    }
    
    Write-Output "`n"
    Write-ProtocolEntry "HardeningKitty is done" "Info"
    Write-Output "`n"
}

Main
