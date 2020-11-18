# Windows 10 Hardening

## Introduction

This is a hardening checklist that can be used in private and business environments for hardening Windows 10. The checklist can be used for all Windows versions, but in Windows 10 Home the Group Policy Editor is not integrated and the adjustment must be done directly in the registry. 

The settings should be seen as security and privacy recommendation and should be carefully checked whether they will affect the operation of your infrastructure or impact the usability of key functions. It is important to weigh security against usability.

## Policy Analyzer

_Policy Analzyer_ reads out and compares local registry and local policy values to a defined baseline. The PolicyRule file from [aha-181](https://github.com/aha-181) contains all rules which are needed to check Group Policy and Registry settings that are defined in the Windows 10 Hardening checklist.

Policy Analyzer supports the Hardening checklist up to version 0.2.0, additional entries are not yet supported. 

## HardeningKitty

_HardeningKitty_ supports hardening of a Windows system. The configuration of the system is retrieved and assessed using a finding list. In addition, the system can be hardened according to predefined values. _HardeningKitty_ reads settings from the registry and uses other modules to read configurations outside the registry.

**Attention**: HardeningKitty has a dependency for the tool AccessChk by Mark Russinovich. This must be present on the computer and defined in the script accordingly.

The script was developed for English systems. It is possible that in other languages the analysis is incorrect. Please create an issue if this occurs.

### How to run

Run the script with administrative privileges to access machine settings. For the user settings it is better to execute them with a normal user account. Ideally, the user account is used for daily work.

Download _HardeningKitty_ and copy it to the target system (script and lists). Additionally, [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) (tested with version 1.6.2) must be available on the target system. The path of the variable _$BinaryAccesschk_ must be modified accordingly. After that HardeningKitty can be imported and executed:

```powershell
PS C:\> Import-Module Invoke-HardeningKitty.ps1
PS C:\> Invoke-HardeningKitty -EmojiSupport


         =^._.^=
        _(      )/  HardeningKitty


[*] 5/28/2020 4:39:16 PM - Starting HardeningKitty


[*] 5/28/2020 4:39:16 PM - Getting machine information
[*] Hostname: w10
[*] Domain: WORKGROUP

...

[*] 5/28/2020 4:39:21 PM - Starting Category Account Policies
[😺] ID 1100, Account lockout duration, Result=30, Severity=Passed
[😺] ID 1101, Account lockout threshold, Result=5, Severity=Passed
[😺] ID 1102, Reset account lockout counter, Result=30, Severity=Passed

...

[*] 5/28/2020 4:39:23 PM - Starting Category Advanced Audit Policy Configuration
[😼] ID 1513, Kernel Object, Result=, Recommended=Success and Failure, Severity=Low

...

[*] 5/28/2020 4:39:24 PM - Starting Category System
[😿] ID 1614, Device Guard: Virtualization Based Security Status, Result=Not available, Recommended=2, Severity=Medium

...

[*] 5/28/2020 4:39:25 PM - Starting Category Windows Components
[🙀] ID 1708, BitLocker Drive Encryption: Volume status, Result=FullyDecrypted, Recommended=FullyEncrypted, Severity=High

...

[*] 5/28/2020 4:39:34 PM - HardeningKitty is done
```

## Last Update

The lists were last updated/checked against the following Microsoft Security Baseline or other frameworks:

* Hardening list Windows 10
	- Security baseline for Windows 10 and Windows Server, version 2004
	- Security baseline for Office 365 ProPlus, version 1908
* finding\_list\_0x6d69636b\_machine and finding\_list\_0x6d69636b\_user
	- Security baseline for Windows 10 and Windows Server, version 2004
	- Security baseline for Office 365 ProPlus, version 1908
	- 0x6d69636b own knowledge
* finding\_list\_cis\_microsoft\_windows\_10\_enterprise\_machine and finding\_list\_cis\_microsoft\_windows\_10\_enterprise\_user
	- CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1 - 10-23-2020
* finding\_list\_cis\_microsoft\_windows\_server\_2019\_machine and finding\_list\_cis\_microsoft\_windows\_server\_2019\_user
	- CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0 - 01-14-2020
* finding\_list\_msft\_security\_baseline\_edge\_machine
	- Security baseline for Microsoft Edge, version 86
* finding\_list\_msft\_security\_baseline\_windows\_10\_machine
	- Security baseline for Windows 10 and Windows Server, version 2004 
* finding\_list\_msft\_security\_baseline\_windows\_10\_machine_draft
	- Security baseline for Windows 10 and Windows Server, version 2009
* finding\_list\_msft\_security\_baseline\_windows\_server\_dc\_machine
	- Security baseline for Windows 10 and Windows Server, version 2004 
* finding\_list\_msft\_security\_baseline\_windows\_server\_dc\_machine_draft
	- Security baseline for Windows 10 and Windows Server, version 2009 
* finding\_list\_msft\_security\_baseline\_windows\_server\_member\_machine
	- Security baseline for Windows 10 and Windows Server, version 2004
* finding\_list\_msft\_security\_baseline\_windows\_server\_member\_machine_draft
	- Security baseline for Windows 10 and Windows Server, version 2009

## Sources

* [CIS Benchmarks for Microsoft Windows 10 Enterprise Release 1909 v1.8.1](https://www.cisecurity.org/cis-benchmarks/)
* [CIS Benchmarks for Microsoft Windows 10 Enterprise Release 2004 v1.9.1](https://www.cisecurity.org/cis-benchmarks/)
* [CIS Benchmarks for Microsoft Windows Server 2019 RTM Release 1809 v1.1.0](https://www.cisecurity.org/cis-benchmarks/)
* [Security baseline (FINAL): Windows 10 and Windows Server, version 2004](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-final-windows-10-and-windows-server-version/ba-p/1543631)
* [Security baseline (DRAFT): Windows 10 and Windows Server, version 20H2](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-draft-windows-10-and-windows-server-version/ba-p/1799721)
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
* [mackwage/windows_hardening.cmd](https://gist.github.com/mackwage/08604751462126599d7e52f233490efe)
* [Security baseline for Microsoft Edge version 86](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-86/ba-p/1758453)
* [Microsoft Edge - Policies](https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-policies)
* [A hint for Office 365 Telemetry](https://twitter.com/milenkowski/status/1326865844215934979)
* [BSI: Microsoft Office Telemetry Analysis report](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/Studien/Office_Telemetrie/Office_Telemetrie.pdf?__blob=publicationFile&v=5)
* [Use policy settings to manage privacy controls for Microsoft 365 Apps for enterprise](https://docs.microsoft.com/en-us/deployoffice/privacy/manage-privacy-controls)