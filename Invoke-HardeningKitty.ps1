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
    $FindingListFile = "finding_list_0x6d69636b.csv",

    [ValidateSet("Audit","Hardening","HailMary")]
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
            "Passed" { $Message = "[$] $Text"; Write-Host -ForegroundColor Gray $Message; Break}
            "Low" { $Message = "[-] $Text"; Write-Host -ForegroundColor Cyan $Message; Break}        
            "Medium" { $Message = "[?] $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
            "High" { $Message = "[!] $Text"; Write-Host -ForegroundColor Red $Message; Break}
            Default { $Message = "[*] $Text"; Write-Host $Message; }
        }
    }
}

Function Import-FindingList {

    $FindingList = Import-Csv -Path $FindingListFile -Delimiter ";"
    Return $FindingList
}

Function Main {

    Write-Output "`n"
    Write-Output "      =^._.^="
    Write-Output "     _(      )/  HardeningKitty"
    Write-Output "`n"    
    Write-ProtocolEntry "Starting HardeningKitty" "Info"

    If ($Mode -eq "Audit") {

        $FindingList = Import-FindingList
        $LastCategory = ""

        ForEach ($Finding in $FindingList) {

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
                }
            }
            
            #
            # Get Audit Policy
            #
            Elseif ($Finding.Method -eq 'auditpol') {

                $SubCategory = $Finding.Name                
                try {
                    
                    $ResultOutput = auditpol.exe /get /subcategory:"$SubCategory"
                    
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
                    
                    $ResultOutput = net accounts

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
            # SMBv1 Protocol Support
            #
            Elseif ($Finding.Method -eq 'smb1protocol') {

                try {
                    
                    $ResultOutput = Get-WindowsOptionalFeature -Online -FeatureName smb1protocol 
                    $Result = $ResultOutput.State

                } catch {
                    $Result = $Finding.DefaultValue
                }

            }
            
            #
            # Compare result value and recommendation
            #
            $ResultPassed = $false
            Switch($Finding.Operator) {
                "=" { If($Result -eq $Finding.RecommendedValue) { $ResultPassed = $true }; Break}
                "<=" { If ([int]$Result -le [int]$Finding.RecommendedValue) { $ResultPassed = $true }; Break}
                ">=" { If ([int]$Result -ge [int]$Finding.RecommendedValue) { $ResultPassed = $true }; Break}
            }

            If ($ResultPassed) {
                # Passed
                $Message = $Finding.Name+": Passed"
                Write-Result $Message "Passed"
            } Else {
                # Failed
                $Message = $Finding.Name+": Result=$Result, Recommended="+$Finding.RecommendedValue+", Severity="+$Finding.Severity
                Write-Result $Message $Finding.Severity
            }
        }
    }
    
    Write-Output "`n"
    Write-ProtocolEntry "HardeningKitty is done" "Info"
    Write-Output "`n"
}

Main
