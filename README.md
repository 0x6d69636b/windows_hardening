# HardeningKitty and Windows Hardening

## Introduction

The project started as a simple hardening list for Windows 10. After some time, HardeningKitty was created to simplify the hardening of Windows. Now, HardeningKitty supports guidelines from Microsoft, CIS Benchmarks, DoD STIG and BSI SiSyPHuS Win10. And of course my own hardening list.

This is a hardening checklist that can be used in private and business environments for hardening Windows 10. The checklist can be used for all Windows versions, but in Windows 10 Home the Group Policy Editor is not integrated and the adjustment must be done directly in the registry. For this, there is the _HailMary_ mode from _HardeningKitty_.

The settings should be seen as security and privacy recommendation and should be carefully checked whether they will affect the operation of your infrastructure or impact the usability of key functions. It is important to weigh security against usability.

The project started with the creation of a simple hardening checklist for Windows 10. The focus has shifted to the audit of various well-known frameworks / benchmarks with the development of _HardeningKitty_. Meanwhile, various CIS benchmarks and Microsoft Security Baselines are supported. With the development of the _HailMary_ mode, it will also be possible to apply settings of any hardening checklist on a Windows system.

## HardeningKitty

_HardeningKitty_ supports hardening of a Windows system. The configuration of the system is retrieved and assessed using a finding list. In addition, the system can be hardened according to predefined values. _HardeningKitty_ reads settings from the registry and uses other modules to read configurations outside the registry.

The script was developed for English systems. It is possible that in other languages the analysis is incorrect. Please create an issue if this occurs.

### Signed Version

The development of _HardeningKitty_ happens in this repository. In the [repository of scip AG](https://github.com/scipag/HardeningKitty) is a stable version of _HardeningKitty_ that has been *signed* with the code signing certificate of _scip AG_. This means that _HardeningKitty_ can also be run on systems that only allow signed scripts.

### How To Run

Run the script with administrative privileges to access machine settings. For the user settings it is better to execute them with a normal user account. Ideally, the user account is used for daily work.

Download _HardeningKitty_ and copy it to the target system (script and lists). Then HardeningKitty can be imported and executed:

```powershell
PS C:\tmp> Import-Module .\HardeningKitty.psm1
PS C:\tmp> Invoke-HardeningKitty -EmojiSupport


         =^._.^=
        _(      )/  HardeningKitty 0.9.0-1662273740


[*] 9/4/2022 8:54:12 AM - Starting HardeningKitty


[*] 9/4/2022 8:54:12 AM - Getting user information
[*] Hostname: DESKTOP-DG83TOD
[*] Domain: WORKGROUP

...

[*] [*] 9/4/2022 8:54:12 AM - Starting Category Account Policies
[😺] ID 1103, Store passwords using reversible encryption, Result=0, Severity=Passed
[😺] ID 1100, Account lockout threshold, Result=10, Severity=Passed
[😺] ID 1101, Account lockout duration, Result=30, Severity=Passed

...

[*] 9/4/2022 8:54:12 AM - Starting Category User Rights Assignment
[😿] ID 1200, Access this computer from the network, Result=BUILTIN\Administrators;BUILTIN\Users, Recommended=BUILTIN\Administrators, Severity=Medium

...

[*] 9/4/2022 8:54:14 AM - Starting Category Administrative Templates: Printer
[🙀] ID 1764, Point and Print Restrictions: When installing drivers for a new connection (CVE-2021-34527), Result=1, Recommended=0, Severity=High
[🙀] ID 1765, Point and Print Restrictions: When updating drivers for an existing connection (CVE-2021-34527), Result=2, Recommended=0, Severity=High

...

[*] 9/4/2022 8:54:19 AM - Starting Category MS Security Guide
[😿] ID 2200, LSA Protection, Result=, Recommended=1, Severity=Medium
[😼] ID 2201, Lsass.exe audit mode, Result=, Recommended=8, Severity=Low

...

[*] 9/4/2022 8:54:25 AM - HardeningKitty is done
[*] 9/4/2022 8:54:25 AM - Your HardeningKitty score is: 4.82. HardeningKitty Statistics: Total checks: 325 - Passed: 213, Low: 33, Medium: 76, High: 3.
```

### How To Install

First create the directory *HardeningKitty* and for every version a sub directory like *0.9.2* in a path listed in the *PSModulePath* environment variable.

Copy the module *HardeningKitty.psm1*, *HardeningKitty.psd1*, and the *lists* directory to this new directory.

```powershell
PS C:\tmp> $Version = "0.9.2"
PS C:\tmp> New-Item -Path $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version -ItemType Directory
PS C:\tmp> Copy-Item -Path .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\lists\ -Destination $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\ -Recurse
```

For more information see Microsoft's article [Installing a PowerShell Module](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module).

### How to Automatically Download and Install the Latest Release

You can use the script below to download and install the latest release of *HardeningKitty*.

```powershell
Function InstallHardeningKitty() {
    $Version = (((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).Name).SubString(2)
    $HardeningKittyLatestVersionDownloadLink = ((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).zipball_url
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest $HardeningKittyLatestVersionDownloadLink -Out HardeningKitty$Version.zip
    Expand-Archive -Path ".\HardeningKitty$Version.zip" -Destination ".\HardeningKitty$Version" -Force
    $Folder = Get-ChildItem .\HardeningKitty$Version | Select-Object Name -ExpandProperty Name
    Move-Item ".\HardeningKitty$Version\$Folder\*" ".\HardeningKitty$Version\"
    Remove-Item ".\HardeningKitty$Version\$Folder\"
    New-Item -Path $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version -ItemType Directory
    Set-Location .\HardeningKitty$Version
    Copy-Item -Path .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\lists\ -Destination $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\ -Recurse
    Import-Module "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\HardeningKitty.psm1"
}
InstallHardeningKitty
```

### Examples

#### Audit

The default mode is _audit_. HardeningKitty performs an audit, saves the results to a CSV file and creates a log file. The files are automatically named and receive a timestamp. Using the parameters _ReportFile_ or _LogFile_, it is also possible to assign your own name and path.

The _Filter_ parameter can be used to filter the hardening list. For this purpose the PowerShell ScriptBlock syntax must be used, for example `{ $_.ID -eq 4505 }`. The following elements are useful for filtering: ID, Category, Name, Method, and Severity.

```powershell
Invoke-HardeningKitty -Mode Audit -Log -Report
```

HardeningKitty can be executed with a specific list defined by the parameter _FileFindingList_. If HardeningKitty is run several times on the same system, it may be useful to hide the machine information. The parameter _SkipMachineInformation_ is used for this purpose.

```powershell
Invoke-HardeningKitty -FileFindingList .\lists\finding_list_0x6d69636b_user.csv -SkipMachineInformation
```

HardeningKitty uses the default list, and checks only tests with the severity Medium.

```powershell
Invoke-HardeningKitty -Filter { $_.Severity -eq "Medium" }
```

#### Config

The mode _config_ retrives all current settings of a system. If a setting has not been configured, HardeningKitty will use a default value stored in the finding list. This mode can be combined with other functions, for example to create a backup.

HardeningKitty gets the current settings and stores them in a report:

```powershell
Invoke-HardeningKitty -Mode Config -Report -ReportFile C:\tmp\my_hardeningkitty_report.csv
```

#### Backup

Backups are important. Really important. Therefore, HardeningKitty also has a function to retrieve the current configuration and save it in a form that can be partially restored.

**Disclaimer:** HardeningKitty tries to restore the original configuration. This works quite well with registry keys and Hardening Kitty really tries its best. But the backup function is not a snapshot and does not replace a real system backup. It is not possible to restore the system 1:1 with HardeningKitty alone after HailMary. If this is a requirement, create an image or system backup and restore it.

The _Backup_ switch specifies that the file is written in form of a finding list and can thus be used for the _HailMary_ mode. The name and path of the backup can be specified with the parameter _BackupFile_.

```powershell
Invoke-HardeningKitty -Mode Config -Backup
```

Please test this function to see if it really works properly on the target system before making any serious changes. A Schrödinger's backup is dangerous.

##### Non-Default Finding List

Note that if _-FileFindingList_ is not specified, the backup is referred to the default finding list. Before deploying a _specific_ list in _HailMary_ mode, always create a backup _referred to that specific list_.

```powershell
Invoke-HardeningKitty -Mode Config -Backup -BackupFile ".\myBackup.csv" -FileFindingList ".\list\{list}.csv"
```

##### Restoring a Backup

The _Backup_ switch creates a file in form of a finding list, to restore the backup load it in _HailMary_ mode like any find list:

```powershell
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList ".\myBackup.csv"
```

#### HailMary

The _HailMary_ method is very powerful. It can be used to deploy a finding list on a system. All findings are set on this system as recommended in the list. With power comes responsibility. Please use this mode only if you know what you are doing. Be sure to have a backup of the system.

For now, the filter function is only supported in Audit and Config mode. As the HailMary mode is a delicate matter, create your own file and remove all the lines you want to filter.

```powershell
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\lists\finding_list_0x6d69636b_machine.csv
```

Before HailMary is run, a finding list must be picked. It is important to check whether the settings have an influence on the stability and functionality of the system. Before running HailMary, a backup should be made.

#### Create a Group Policy (experimental)

Thanks to [@gderybel](https://github.com/gderybel), HardeningKitty can convert a finding list into a group policy. As a basic requirement, the Group Policy Management PowerShell module must be installed. At the moment only registry settings can be converted and not everything has been tested yet. A new policy is created, as long as it is not assigned to an object, no change is made to the system. Use it with care.

```powershell
Invoke-HardeningKitty -Mode GPO -FileFindingList .\lists\finding_list_0x6d69636b_machine.csv -GPOName HardeningKitty-Machine-01
```

### HardeningKitty Score

Each Passed finding gives 4 points, a Low finding gives 2 points, a Medium finding gives 1 point and a High Finding gives 0 points.

The formula for the HardeningKitty Score is _(Points achieved / Maximum points) * 5 + 1_.

#### Rating

| Score | Rating Casual | Rating Professional |
| :---- | :------------ | :------------------ |
| 6 | 😹 Excellent | Excellent |
| 5 | 😺 Well done | Good |
| 4 | 😼 Sufficient | Sufficient |
| 3 | 😿 You should do better | Insufficient |
| 2 | 🙀 Weak | Insufficient |
| 1 | 😾 Bogus | Insufficient |

### HardeningKitty Interface

[@ataumo](https://github.com/ataumo) build a web based interface for HardeningKitty. The tool can be used to create your own lists and provides additional information on the hardening settings. The [source code](https://github.com/ataumo/policies_hardening_interface) is under AGPL license and there is a [demo site](https://phi.cryptonit.fr/policies_hardening_interface/).

### Last Update

HardeningKitty can be used to audit systems against the following baselines / benchmarks:

| Name | System Version    | Version  |
| :--- | :---------------- | :------  |
| 0x6d69636b Windows 10 (Machine) | 22H2 | |
| 0x6d69636b Windows 10 (User) | 22H2 | |
| BSI SiSyPHuS Windows 10 hoher Schutzbedarf Domänenmitglied (Machine) | 1809 | 1.0 |
| BSI SiSyPHuS Windows 10 hoher Schutzbedarf Domänenmitglied (User) | 1809| 1.0
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Domänenmitglied (Machine) | 1809| 1.0 |
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Domänenmitglied (User) | 1809| 1.0 |
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Einzelrechner (Machine) | 1809| 1.0 |
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Einzelrechner (User) | 1809 | 1.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 1809 | 1.6.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 1809 | 1.6.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 1903 | 1.7.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 1903 | 1.7.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 1909 | 1.8.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 1909 | 1.8.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 2004 | 1.9.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 2004 | 1.9.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 20H2 | 1.10.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 20H2 | 1.10.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 21H1 | 1.11.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 21H1 | 1.11.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 21H2 | 1.12.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 21H2 | 1.12.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 22H2 | 3.0.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 22H2 | 3.0.0 |
| CIS Microsoft Windows 11 Enterprise (Machine) | 21H2 | 1.0.0 |
| CIS Microsoft Windows 11 Enterprise (User) | 21H2 | 1.0.0 |
| CIS Microsoft Windows 11 Enterprise (Machine) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 11 Enterprise (User) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 11 Enterprise (Machine) | 23H2 | 3.0.0 |
| CIS Microsoft Windows 11 Enterprise (User) | 23H2 | 3.0.0 |
| CIS Microsoft Windows Server 2012 R2 (Machine) | R2 | 2.4.0 |
| CIS Microsoft Windows Server 2012 R2 (User) | R2 | 2.4.0 |
| CIS Microsoft Windows Server 2012 R2 (Machine) | R2 | 2.6.0 |
| CIS Microsoft Windows Server 2012 R2 (User) | R2 | 2.6.0 |
| CIS Microsoft Windows Server 2012 R2 (Machine) | R2 | 3.0.0 |
| CIS Microsoft Windows Server 2012 R2 (User) | R2 | 3.0.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 1.2.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 1.2.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 1.3.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 1.3.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 2.0.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 2.0.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 3.0.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 3.0.0 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 1.1.0 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 1.1.0 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 1.2.1 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 1.2.1 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 2.0.0 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 2.0.0 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 3.0.0 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 3.0.0 |
| CIS Microsoft Windows Server 2022 (Machine) | 21H2 | 1.0.0 |
| CIS Microsoft Windows Server 2022 (User) | 21H2 | 1.0.0 |
| CIS Microsoft Windows Server 2022 (Machine) | 22H2 | 2.0.0 |
| CIS Microsoft Windows Server 2022 (User) | 22H2 | 2.0.0 |
| CIS Microsoft Windows Server 2022 (Machine) | 22H2 | 3.0.0 |
| CIS Microsoft Windows Server 2022 (User) | 22H2 | 3.0.0 |
| DoD Microsoft Windows 10 STIG (Machine) | 20H2 | v2r1 |
| DoD Microsoft Windows 10 STIG (User) | 20H2 | v2r1 |
| DoD Windows Server 2019 Domain Controller STIG (Machine) | 20H2 | v2r1 |
| DoD Windows Server 2019 Domain Controller STIG (User) | 20H2 | v2r1 |
| DoD Windows Server 2019 Member Server STIG (Machine) | 20H2 | v2r1 |
| DoD Windows Server 2019 Member Server STIG (User) | 20H2 | v2r1 |
| DoD Windows Defender Antivirus STIG | 20H2 | v2r1 |
| DoD Windows Firewall STIG | 20H2 | v1r7 |
| Microsoft Security baseline for Microsoft Edge | 87 | Final |
| Microsoft Security baseline for Microsoft Edge | 88, 89, 90, 91 | Final |
| Microsoft Security baseline for Microsoft Edge | 92 | Final |
| Microsoft Security baseline for Microsoft Edge | 93, 94 | Final |
| Microsoft Security baseline for Microsoft Edge | 95 | Final |
| Microsoft Security baseline for Microsoft Edge | 96 | Final |
| Microsoft Security baseline for Microsoft Edge | 97 | Final |
| Microsoft Security baseline for Microsoft Edge | 98, 99, 100, 101, 102, 103, 104, 105, 106 | Final |
| Microsoft Security baseline for Microsoft Edge | 107, 108, 109, 110, 111 | Final |
| Microsoft Security baseline for Microsoft Edge | 112, 113 | Final |
| Microsoft Security baseline for Microsoft Edge | 114, 115, 116 | Final |
| Microsoft Security baseline for Microsoft Edge | 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127 | Final |
| Microsoft Security baseline for Microsoft Edge | 128, 129, 130 | Final |
| Microsoft Security baseline for Windows 10 | 2004 | Final |
| Microsoft Security baseline for Windows 10 | 20H2, 21H1 | Final |
| Microsoft Security baseline for Windows 10 | 21H2 | Final |
| Microsoft Security baseline for Windows 10 (Machine) | 22H2 | Final |
| Microsoft Security baseline for Windows 10 (User) | 22H2 | Final |
| Microsoft Security baseline for Windows 11 | 21H2 | Final |
| Microsoft Security baseline for Windows 11 (Machine) | 22H2 | Final |
| Microsoft Security baseline for Windows 11 (User) | 22H2 | Final |
| Microsoft Security baseline for Windows 11 (Machine) | 23H2 | Final |
| Microsoft Security baseline for Windows 11 (User) | 23H2 | Final |
| Microsoft Security baseline for Windows 11 (Machine) | 24H2 | Final |
| Microsoft Security baseline for Windows 11 (User) | 24H2 | Final |
| Microsoft Security baseline for Windows Server (DC) | 2004 | Final |
| Microsoft Security baseline for Windows Server (Member) | 2004 | Final |
| Microsoft Security baseline for Windows Server (DC) | 20H2 | Final |
| Microsoft Security baseline for Windows Server (Member) | 20H2 | Final |
| Microsoft Security baseline for Windows Server 2022 (DC) | 21H2 | Final |
| Microsoft Security baseline for Windows Server 2022 (Member) | 21H2 | Final |
| Microsoft Security baseline for Office 365 ProPlus (Machine) | Sept 2019 | Final |
| Microsoft Security baseline for Office 365 ProPlus (User) | Sept 2019 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2104, v2106 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2104, v2106 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2112 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2112 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2206 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2206 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2306, v2312 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2306, v2312 | Final |
| Microsoft Windows Server TLS Settings | 1809 | 1.0 |
| Microsoft Windows Server TLS Settings (Future Use with TLSv1.3) | 1903 | 1.0 |

## Sources

* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Security baseline (FINAL): Windows 10 and Windows Server, version 2004](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-final-windows-10-and-windows-server-version/ba-p/1543631)
* [Security baseline (FINAL) for Windows 10 and Windows Server, version 20H2](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-final-for-windows-10-and-windows-server/ba-p/1999393)
* [Security baseline (FINAL) for Windows 10, version 21H1](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-final-for-windows-10-version-21h1/ba-p/2362353)
* [Security baseline for Windows 10, version 21H2](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-windows-10-version-21h2/ba-p/3042703)
* [Windows Server 2022 Security Baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-server-2022-security-baseline/ba-p/2724685)
* [Windows 11 Security baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-security-baseline/ba-p/2810772)
* [Windows 11, version 22H2 Security baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-22h2-security-baseline/ba-p/3632520)
* [Windows 11, version 23H2 security baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-23h2-security-baseline/ba-p/3967618)
* [Windows 11, version 24H2 security baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-24h2-security-baseline/ba-p/4252801)
* [Kernel DMA Protection for Thunderbolt 3](https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt)
* [BitLocker Countermeasures](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures)
* [Blocking the SBP-2 driver and Thunderbolt controllers to reduce 1394 DMA and Thunderbolt DMA threats to BitLocker](https://support.microsoft.com/en-us/help/2516445/blocking-the-sbp-2-driver-and-thunderbolt-controllers-to-reduce-1394-d)
* [Manage Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
* [Reduce attack surfaces with attack surface reduction rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction)
* [Configuring Additional LSA Protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
* [Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440)
* [DDE registry settings](https://gist.githubusercontent.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b/raw/69c9d9d14b386d8f178e59a046804501ec1ee304/disable_ddeauto.reg)
* [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
* [Dane Stuckey - @cryps1s Endpoint Isolation with the Windows Firewall](https://medium.com/@cryps1s/endpoint-isolation-with-the-windows-firewall-462a795f4cfb)
* [Microsoft Security Compliance Toolkit 1.0](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
* [Policy Analyzer](https://blogs.technet.microsoft.com/secguide/2016/01/22/new-tool-policy-analyzer/)
* [Security baseline for Office 365 ProPlus (v1908, Sept 2019) - FINAL](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-office-365-proplus-v1908-sept-2019-final/ba-p/873084)
* [Security baseline for Microsoft 365 Apps for enterprise v2104 - FINAL](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-365-apps-for-enterprise-v2104/ba-p/2307695)
* [Security baseline for Microsoft 365 Apps for enterprise v2106 - FINAL](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-365-apps-for-enterprise-v2106/ba-p/2492355)
* [Security baseline for Microsoft 365 Apps for enterprise, v2112](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-365-apps-for-enterprise-v2112/ba-p/3038172)
* [Security baseline for Microsoft 365 Apps for enterprise v2206](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-m365-apps-for-enterprise-v2306/ba-p/3858702)
* [Security baseline for Microsoft 365 Apps for enterprise v2306](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-m365-apps-for-enterprise-v2306/ba-p/3858702)
* [Security baseline for Microsoft 365 Apps for enterprise v2312](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-m365-apps-for-enterprise-v2312/ba-p/4009591)
* [mackwage/windows_hardening.cmd](https://gist.github.com/mackwage/08604751462126599d7e52f233490efe)
* [Security baseline for Microsoft Edge version 87](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-87/ba-p/1950297)
* [Security baseline for Microsoft Edge version 89](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-89/ba-p/2186265)
* [Security baseline for Microsoft Edge v92](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v92/ba-p/2563679)
* [Security baseline for Microsoft Edge v93](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v93/ba-p/2744505)
* [Security baseline for Microsoft Edge v95](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v95/ba-p/2897269)
* [Security baseline for Microsoft Edge v96](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v96/ba-p/2997665)
* [Security baseline for Microsoft Edge v97](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v97/ba-p/3062252)
* [Security baseline for Microsoft Edge v98](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v98/ba-p/3165443)
* [Security baseline for Microsoft Edge v99](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v99/ba-p/3249241)
* [Security baseline for Microsoft Edge v100](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v100/ba-p/3281982)
* [Security baseline for Microsoft Edge v101](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v101/ba-p/3298140)
* [Security baseline for Microsoft Edge v102](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v102/ba-p/3465195)
* [Security baseline for Microsoft Edge v103](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v103/ba-p/3548236)
* [Security baseline for Microsoft Edge v104](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v104/ba-p/3593826)
* [Security baseline for Microsoft Edge v105](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v105/ba-p/3615904)
* [Security baseline for Microsoft Edge v106](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-106/ba-p/3643958)
* [Security baseline for Microsoft Edge v107](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v107/ba-p/3678903)
* [Security baseline for Microsoft Edge v108](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-108/ba-p/3691250)
* [Security baseline for Microsoft Edge v109](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-109/ba-p/3713981)
* [Security baseline for Microsoft Edge v110](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-110/ba-p/3740900)
* [Security baseline for Microsoft Edge v111](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-111/ba-p/3767483)
* [Security baseline for Microsoft Edge v112](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-112/ba-p/3789975)
* [Security baseline for Microsoft Edge v113](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-113/ba-p/3814398)
* [Security baseline for Microsoft Edge v114](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-114/ba-p/3839728)
* [Security baseline for Microsoft Edge v115](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-115/ba-p/3882420)
* [Security baseline for Microsoft Edge v116](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-116/ba-p/3905425)
* [Security baseline for Microsoft Edge v117](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-117/ba-p/3930862)
* [Security baseline for Microsoft Edge v118](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-118/ba-p/3955123)
* [Security baseline for Microsoft Edge v119](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-119/ba-p/3978427)
* [Security baseline for Microsoft Edge v120](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-120/ba-p/4009561)
* [Security baseline for Microsoft Edge v121](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-121/ba-p/4057135)
* [Security baseline for Microsoft Edge v122](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-122/ba-p/4073142)
* [Security baseline for Microsoft Edge v123](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-123/ba-p/4098458)
* [Security baseline for Microsoft Edge v124](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-124/ba-p/4124826)
* [Security baseline for Microsoft Edge v125](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-125/ba-p/4146218)
* [Security baseline for Microsoft Edge v126](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-126/ba-p/4168263)
* [Security baseline for Microsoft Edge v127](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-127/ba-p/4205820)
* [Security baseline for Microsoft Edge v128](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-128/ba-p/4237524)
* [Security baseline for Microsoft Edge v129](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-129/ba-p/4250551)
* [Security baseline for Microsoft Edge v130](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-130/ba-p/4273981)
* [Microsoft Edge - Policies](https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-policies)
* [A hint for Office 365 Telemetry](https://twitter.com/milenkowski/status/1326865844215934979)
* [BSI: Microsoft Office Telemetry Analysis report](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/Studien/Office_Telemetrie/Office_Telemetrie.pdf?__blob=publicationFile&v=5)
* [Use policy settings to manage privacy controls for Microsoft 365 Apps for enterprise](https://docs.microsoft.com/en-us/deployoffice/privacy/manage-privacy-controls)
* [DoD Cyber Exchange Public - Security Technical Implementation Guides (STIGs) - Group Policy Objects](https://public.cyber.mil/stigs/gpo/)
* [BSI SiSyPHuS Win10: Windows 10 Hardening Guideline](https://www.bsi.bund.de/EN/Topics/Cyber-Security/Recommendations/SiSyPHuS_Win10/AP11/SiSyPHuS_AP11.html)
* [Setup Microsoft Windows or IIS for SSL Perfect Forward Secrecy and TLS 1.2](https://www.hass.de/content/setup-microsoft-windows-or-iis-ssl-perfect-forward-secrecy-and-tls-12)
* [Nartac Software - IIS Crypto](https://www.nartac.com/Products/IISCrypto/)
* [Transport Layer Security (TLS) best practices with the .NET Framework](https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls)
* [TLS Cipher Suites in Windows Server 2022](https://docs.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022)
* [Transport Layer Security (TLS) registry settings](https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)
* [Windows Defender Antivirus can now run in a sandbox](https://www.microsoft.com/security/blog/2018/10/26/windows-defender-antivirus-can-now-run-in-a-sandbox/)
* [KB5005010: Restricting installation of new printer drivers after applying the July 6, 2021 updates](https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7)
* [admx.help - Group Policy Administrative Templates Catalog](https://admx.help/)
* [How to Defend Users from Interception Attacks via SMB Client Defense](https://techcommunity.microsoft.com/t5/itops-talk-blog/how-to-defend-users-from-interception-attacks-via-smb-client/ba-p/1494995)
* [Migrating from Windows PowerShell 5.1 to PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/whats-new/migrating-from-windows-powershell-51-to-powershell-7)
* [Data security and Python in Excel](https://support.microsoft.com/en-us/office/data-security-and-python-in-excel-33cc88a4-4a87-485e-9ff9-f35958278327)
* [Deprecated features for Windows client](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features)
