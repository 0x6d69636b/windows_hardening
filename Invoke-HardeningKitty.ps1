<#
    Invoke-HardeningKitty - Checks and hardens your Windows configuration

    Author: Michael Schneider
    License: MIT    
    Required Dependencies: None
    Optional Dependencies: None
#>

[CmdletBinding()]

Param (

    [ValidateSet("Audit","Hardening","HailMary")]
    [String]
    $Mode = "Audit"
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

    Switch ($SeverityLevel) {
        "Passed" { $Emoji = [char]::ConvertFromUtf32(0x1F63A); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Gray $Message; Break}
        "Low" { $Emoji = [char]::ConvertFromUtf32(0x1F63C); $Message = "[$Emoji]  $Text"; Write-Host -ForegroundColor Cyan $Message; Break}        
        "Medium" { $Emoji = [char]::ConvertFromUtf32(0x1F63F); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
        "High" { $Emoji = [char]::ConvertFromUtf32(0x1F640); $Message = "[$Emoji] $Text"; Write-Host -ForegroundColor Red $Message; Break}
        Default { $Message = "[*] $Text"; Write-Host $Message; }
    }
}

Function Create-FindingList {

    $FindingList = @(
        [pscustomobject]@{ID='1023';Name='LSASS Protection Mode';Method='Registry';RegistryPath='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';RegistryItem='RunAsPPL';DefaultValue='';RecommendedValue='1';Severity='Medium'}
        [pscustomobject]@{ID='1024';Name='LSASS Audit Mode';Method='Registry';RegistryPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe';RegistryItem='AuditLevel';DefaultValue='';RecommendedValue='8';Severity='Low'}
    )

    Return $FindingList
}

Function Main {

    Write-Output "`n"
    Write-Output "      =^._.^="
    Write-Output "     _(      )/  HardeningKitty"
    Write-Output "`n"    
    Write-ProtocolEntry "Starting HardeningKitty" "Info"
    Write-Output "`n"

    If ($Mode -eq "Audit") {

        $FindingList = Create-FindingList

        ForEach ($Finding in $FindingList) {

            # Get Registry Item
            If ($Finding.Method = 'Registry') {

                If (Test-Path -Path $Finding.RegistryPath) {
                
                    try {
                        $Result = Get-ItemPropertyValue -Path $Finding.RegistryPath -Name $Finding.RegistryItem
                    } catch {
                        $Result = $Finding.DefaultValue
                    }

                    If ($Result -eq $Finding.RecommendedValue) {
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
        }
    }
    
    Write-Output "`n"
    Write-ProtocolEntry "HardeningKitty is done" "Info"
    Write-Output "`n"
}

Main
