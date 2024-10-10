# Windows 10 Hardening

The IDs correspond to the finding lists for HardeningKitty [finding_list_0x6d69636b_machine.csv](https://github.com/0x6d69636b/windows_hardening/blob/master/lists/finding_list_0x6d69636b_machine.csv) and [finding_list_0x6d69636b_user.csv](https://github.com/0x6d69636b/windows_hardening/blob/master/lists/finding_list_0x6d69636b_user.csv).

## Basic Hardening

* Use a separate local admin account
* ID 1708: Use of BitLocker Encryption (use of Enhanced PIN is recommended, see ID 1712)
* Enable Windows Defender
* ID 1000: Disable SMBv1 (only needed for Windows <1709 build)
	* Check Status: `Get-WindowsOptionalFeature -Online -FeatureName smb1protocol`
	* Disable: `Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol`

## Machine Configuration 

### Windows Settings\Security Settings\Account Policies

* ID 1103: Set _Password Policy\Store passwords using reversible encryption_ to **Disabled**
* ID 1101: Set _Account Lockout Policy\Account lockout duration_ to **15 or more minute(s)**
* ID 1100: Set _Account Lockout Policy\Account lockout threshold_ to **10 or fewer invalid logon attempt(s), but not 0**
* ID 1104: Set _Account Lockout Policy\Allow Administrator account lockout_ to **Enabled**
* ID 1102: Set _Account Lockout Policy\Reset account lockout counter after_ to **15 or more minute(s)**

### Windows Settings\Security Settings\Local Policies

#### Audit Policy

* Overridden by Advanced Audit Policy Configuration

#### User Rights Assignment

* ID 1200: Set _Access this computer from the network_ to **Administrators**
* ID 1201: Set _Allow log on locally_ to **Administrators, Users**
* ID 1202: Remove **Administrators** from _Debug programs_ (SeDebugPrivilege)
* ID 1203: Set _Deny access to this computer from the network_ to include **Guests, Local account**
* ID 1204: Set _Deny log on as a batch job_ to include **Guests**
* ID 1205: Set _Deny log on as a service_ to include **Guests**
* ID 1206: Set _Deny log on through Remote Desktop Services_ to include **Guests, Local account**

#### Security Options

##### Accounts

* ID 1300: Set _Accounts: Block Microsoft accounts_ to **Users can't add or log on with Microsoft accounts**

##### Audit

* ID 1301: Set _Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings_ to **Enabled**

##### Interactive Logon

* ID 1302: Set _Interactive logon: Do not require CTRL+ALT+DEL_ to **Disabled**
* ID 1303: Set _Interactive logon: Don't display last signed-in_ to **Enabled**
* ID 1304: Set _Interactive logon: Don't display username at sign-in_ to **Enabled**

##### Microsoft Network Client/Server

* ID 1305: Set _Microsoft network client: Digitally sign communications (always)_ to **Enabled**
* ID 1306: Set _Microsoft network client: Digitally sign communications (if server agrees)_ to **Enabled**
* ID 1307: Set _Microsoft network server: Digitally sign communications (always)_ to **Enabled**
* ID 1308: Set _Microsoft network server: Digitally sign communications (if client agrees)_ to **Enabled**

##### Network Access

* ID 1309: Set _Network access: Do not allow anonymous enumeration of SAM accounts_ to **Enabled**
* ID 1310: Set _Network access: Do not allow anonymous enumeration of SAM accounts and shares_ to **Enabled**
* ID 1311: Set _Network access: Do not allow storage of passwords and credentials for network authentication_ to **Enabled**
* ID 1324: Set _Network access: Restrict anonymous access to Named Pipes and Shares_ to **Enabled**
* ID 1325: Set _Network access: Restrict clients allowed to make remote calls to SAM_ to **O:BAG:BAD:(A;;RC;;;BA)** (Remote Access for Administrators allowed, no other groups/user)

##### Network Security

* ID 1312: Set _Network security: Allow LocalSystem NULL session fallback_ to **Disabled**
* ID 1326: Set _Network security: Do not store LAN Manager hash value on next password change_ to **Enabled**
* ID 1313: Set _Network security: LAN Manager authentication level_ to **Send NTLMv2 response only. Refuse LM & NTLM**
* ID 1314: Set _Network security: LDAP client signing requirements_ to **Negotiate signing**
* ID 1315: Set _Network security: Minimum session security for NTLM SSP based (including secure RPC) clients_ to **Require NTLMv2 session security, Require 128-bit encryption**
* ID 1316: Set _Network security: Minimum session security for NTLM SSP based (including secure RPC) servers_ to **Require NTLMv2 session security, Require 128-bit encryption**
* ID 1317: Set _Network security: Restrict NTLM: Audit Incoming NTLM Traffic_ to **Enable auditing for all accounts**
* ID 1318: Set _Network security: Restrict NTLM: Audit NTLM authentication in this domain_ to **Enable all**
* ID 1319: Set _Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers_ to **Audit all**

##### Shutdown

* ID 1320: Set _Shutdown: Allow system to be shut down without having to log on_ to **Disabled**

##### User Account Control

* ID 1321: Set _User Account Control: Admin Approval Mode for the Built-in Administrator account_ to **Enabled**
* ID 1322: Set _User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode_ to **Prompt for consent on the secure desktop**
* ID 1323: Set _User Account Control: Behavior of the elevation prompt for standard users_ to **Prompt for credentials on the secure desktop**

### Windows Settings\Security Settings\Windows Firewall With Advanced Security

#### Domain Profile

* ID 1400: _Firewall State_: **On**
* ID 1401: _Inbound Connections_: **Block**
* ID 1402: _Outbound Connections_: **Allow**
* ID 1403: _Size limit_: **16384**
* ID 1404: _Log dropped packets_: **Yes**
* ID 1405: _Log successful connections_: **Yes**

#### Private Profile

* ID 1406: _Firewall State_: **On**
* ID 1407: _Inbound Connections_: **Block**
* ID 1408: _Outbound Connections_: **Allow**
* ID 1409: _Size limit_: **16384**
* ID 1410: _Log dropped packets_: **Yes**
* ID 1411: _Log successful connections_: **Yes**

#### Public Profile

* ID 1412: _Firewall State_: **On**
* ID 1413: _Inbound Connections_: **Block**
* ID 1414: _Outbound Connections_: **Allow**
* ID 1415: _Size limit_: **16384**
* ID 1416: _Log dropped packets_: **Yes**
* ID 1417: _Log successful connections_: **Yes**

### Windows Settings\Security Settings\Advanced Audit Policy Configuration

* ID 1500: _Account Logon\Audit Credential Validation_: **Success and Failure**
* ID 1501: _Account Management\Audit Security Group Management_: **Success**
* ID 1502: _Account Management\Audit User Account Management_: **Success and Failure**
* ID 1503: _Detailed Tracking\Audit DPAPI Activity_: **Success and Failure**
* ID 1504: _Detailed Tracking\Audit PNP Activity_: **Success**
* ID 1505: _Detailed Tracking\Audit Process Creation_: **Success**
* ID 1506: _Logon/Logoff\Audit Account Lockout_: **Failure**
* ID 1507: _Logon/Logoff\Audit Group Membership_: **Success**
* ID 1508: _Logon/Logoff\Audit Logon_: **Success and Failure**
* ID 1509: _Logon/Logoff\Audit Other Logon/Logoff Events_: **Success and Failure**
* ID 1510: _Logon/Logoff\Audit Special Logon_: **Success**
* ID 1511: _Object Access\Audit Detailed File Share_: **Failure**
* ID 1512: _Object Access\Audit File Share_: **Success and Failure**
* ID 1513: _Object Access\Kernel Object_: **Success and Failure**
* ID 1514: _Object Access\Audit Other Object Access Events_: **Success and Failure**
* ID 1515: _Object Access\Audit Removable Storage_: **Success and Failure**
* ID 1516: _Object Access\Audit SAM_: **Success and Failure**
* ID 1517: _Policy Change\Audit Audit Policy Change_: **Success**
* ID 1518: _Policy Change\Audit Authentication Policy Change_: **Success**
* ID 1519: _Policy Change\Audit MPSSVC Rule-Level Policy Change_: **Success and Failure**
* ID 1520: _Policy Change\Audit Other Policy Change Events_: **Failure**
* ID 1521: _Privilege Use\Audit Sensitive Privilege Use_: **Success and Failure**
* ID 1522: _System\Audit Other System Events_: **Success and Failure**
* ID 1523: _System\Audit Security State Change_: **Success**
* ID 1524: _System\Audit Security System Extension_: **Success**
* ID 1525: _System\Audit System Integrity_: **Success and Failure**

### Administrative Templates\Control Panel

#### Personalization

* ID 1600: Set _Prevent enabling lock screen camera_ to **Enabled**

### Administrative Templates\Network

#### DNS Client

* ID 1601: Set _DNS Client\Turn off multicast name resolution_ (LLMNR) to **Enabled**

#### Lanman Workstation

* ID 1602: Set _Lanman Workstation\Enable insecure guest logons_ to **Disabled**

#### Microsoft Peer-to-Peer Networking Services

* ID 1603: Set _Turn off Microsoft Peer-to-Peer Networking Services_ to **Enabled**

#### WLAN Service

* ID 1604: Set _WLAN Service\WLAN Settings\Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services_ to **Disabled**

#### Administrative Templates\PowerShell Core

* ID 2108, ID 2109: Set _Turn on Module Logging_ to **Enabled**, Use Windows PowerShell Policy setting
* ID 2110: Set _Turn on Module Logging - Module Names_ to **\*** (Wildcard)
* ID 2111, ID 2112, ID 2113: Set _Turn on PowerShell Script Block Logging_ to **Enabled**, Log script block invocation, Use Windows PowerShell Policy setting
* ID 2114, ID 2115, ID 2116: Set _Turn on PowerShell Transcription_ to **Enabled**, Include invocation headers, Use Windows PowerShell Policy setting

### Administrative Templates\Printer

These settings are already set by default. If these settings are different, the system is vulnerable to [CVE-2021-34527](https://vuldb.com/?id.177880) and [CVE-2021-36958](https://vuldb.com/?id.180784).

* ID 1772: Set _Configure Redirection Guard_ to **Enabled: Redirection Guard Enabled**
* ID 1768: Set _Only use Package Point and Print_ to **Enabled**
* ID 1769: Set _Package Point and Print - Approved servers_ to **Enabled** and add a list of servers or a fake entry
* ID 1764: Set _Point and Print Restrictions\When installing drivers for a new connection_ to **Show warning and elevation prompt**
* ID 1765: Set _Point and Print Restrictions\When updating drivers for an existing connection_ to **Show warning and elevation prompt**

### Administrative Templates\Start Menu and Taskbar

#### Notifications

* ID 1771: Set _Turn off notifications network usage_ to **Enabled**

### Administrative Templates\System

#### Credentials Delegation

* ID 1605: Set _Credentials Delegation\Allow delegating default credentials_ to **Disabled** (tspkg)
* ID 1606: Set _Credentials Delegation\Encryption Oracle Remediation_ to **Enabled: Force Updated Clients**
* ID 1699: Set _Credentials Delegation\Remote host allows delegation of non-exportable credentials_ to **Enabled**

#### Device Installation

* ID 1607: Set _Device Installation Restrictions\Prevent installation of devices that match any of these device IDs_ to **Enabled**
	* ID 1608: Set _Also apply to matching devices that are already installed_ to **True**
	* ID 1609: Device ID = **PCI\CC_0C0010** (Plug and Play compatible ID for a 1394 controller)
	* ID 1610: Device ID = **PCI\CC_0C0A** (Plug and Play compatible ID for a Thunderbolt controller)
	**Note**: Not required if Kernel DMA protection is active (check with `msinfo32.exe`)
* ID 1611: Set _Device Installation Restrictions\Prevent installation of devices using drivers that match these device setup classes_ to **Enabled**
	* ID 1612: Set _Also apply to matching devices that are already installed_ to **True**
	* ID 1613: GUID = **{d48179be-ec20-11d1-b6b8-00c04fa372a7}** (Plug and Play device setup class GUID for an SBP-2 drive)

#### Device Guard

**Warning**: An Enterprise license is required to use Device Guard / Credential Guard. 

**Update**: VMware Workstation Pro 15.5.5 can now run on Windows 10 hosts with Hyper-V enabled (Device Guard/Credential Guard). This requires Windows 10 version 2004 (20H1 build 19041.264) and above. 

* ID 1614: Set _Turn On Virtualization Based Security_ to **Enabled**
	* ID 1615, ID 1616: Set _Select Plattform Security Level_ to **Secure Boot and DMA Protection**
	* ID 1617, ID 1619: Set _Credential Guard Configuration_ to **Enabled with UEFI lock**
	* ID 1618, ID 1620: Set _Virtualization Based Protection of Code Integrity_ to **Enabled with UEFI lock**
	* ID 1623: Set _Require UEFI Memory Attributes Table_ to **Enabled**
	* ID 1621: Set _Secure Launch Configuration_ to **Enabled**
* ID 1622: Use a Windows Defender Application Control policy

#### Early Launch Antimalware

* ID 1630: Set _Boot-Start Driver Initialization Policy_ to **Enabled: Good, unknown and bad but critical**

#### Group Policy 

* Set _Configure registry policy processing_ To **Enabled**
	* ID 1631: Set _Process even if the Group Policy objects have not changed_ to **True**
	* ID 1632: Set _Do not apply during periodic background processing_ to **False**

#### Internet Communication Management

* ID 1640: Set _Internet Communication settings\Turn off the Windows Messenger Customer Experience Improvement Program_ to **Enabled**
* ID 1641: Set _Internet Communication settings\Turn off downloading of print drivers over HTTP_ to **Enabled**
* ID 1642, ID 1643: Set _Internet Communication settings\Turn off Windows Error Reporting_ to **Enabled**
* ID 1644: Set _Internet Communication settings\Turn off Internet download for Web publishing and online ordering wizards_ to **Enabled**
* ID 1645: Set _Internet Communication settings\Turn off Windows Customer Experience Improvement Program_ to **Enabled**

#### Kernel DMA Protection

* ID 1650: Set _Enumeration policy for external devices incompatible with Kernel DMA Protection_ to **Enabled: Block all**

#### Logon

* ID 1660: Set _Turn on convenience PIN sign-in_ to **Disabled**
* ID 1661: Set _Turn off app notifications on the lock screen_ to **Enabled**
* ID 1662: Set _Do not display network selection UI_ to **Enabled**

#### Mitigation Options

* ID 1670: Set _Untrusted Font Blocking_ to **Enabled: Block untrusted fonts and log events**

#### OS Policies

* ID 1680: Set _Allow Clipboard synchronization across devices_ to **Disabled**

#### Power Management

* ID 1685: Set _Sleep Settings\Require a password when a computer wakes (plugged in)_ to **Enabled**
* ID 1686: Set _Sleep Settings\Require a password when a computer wakes (on battery)_ to **Enabled**
* ID 1687: Set _Sleep Settings\Allow standby states (S1-S3) when sleeping (plugged in)_ to **Disabled**
* ID 1688: Set _Sleep Settings\Allow standby states (S1-S3) when sleeping (on battery)_ to **Disabled**

#### Remote Assistance

* ID 1690: Set _Configure Offer Remote Assistance_ to **Disabled**
* ID 1691: Set _Configure Solicited Remote Assistance_ to **Disabled**

#### Remote Procedure Call

* ID 1692: Set _Enable RPC Endpoint Mapper Client Authentication_ to **Enabled**
* ID 1693: Set _Restrict Unauthenticated RPC clients_ to **Enabled: Authenticated without exceptions**

#### Service Control Manager Settings

* ID 1694: Set _Security Settings\Enable svchost.exe mitigation options_ to **Enabled**

#### Troubleshooting and Diagnostics

* ID 1695: Set _Windows Performance PerfTrack\Enable/Disable PerfTrack_ to **Disabled**

#### User Profiles

* ID 1696: Set _Turn off the advertising ID_ to **Enabled**

#### Windows Time Service

* ID 1697: Set _Time Providers\Enable Windows NTP Client_ to **Enabled**
* ID 1698: Set _Time Providers\Enable Windows NTP Server_ to **Disabled**

### Administrative Templates\Windows Components

#### App Package Deployment

* ID 1700: Set _Allow a Windows app to share application data between users_ to **Disabled**

#### App Privacy

* ID 1701: Set _Let Windows apps activate with voice while the system is locked_ to **Enabled: Force Deny**

#### App runtime

* ID 1702: Set _Block launching Universal Windows apps with Windows Runtime API access from hosted content_ to **Enabled**

#### Application Compatibility

* ID 1703: Set _Turn off Application Telemetry_ to **Enabled**

#### AutoPlay Policies

* ID 1704: Set _Turn off Autoplay_ to **Enabled: All drives**
* ID 1705: Set _Disallow Autoplay for non-volume devices_ to **Enabled**
* ID 1706: Set _Set the default behavior for AutoRun_ to **Enabled: Do not execute any autorun commands**

#### Biometrics

* ID 1707: Set _Allow the use of biometrics_ to **Disabled**
* ID 1773: Set _Facial Features: Configure enhanced anti-spoofing_ to **Enabled**

#### BitLocker Drive Encryption

* ID 1761: Set _Choose drive encryption method and cipher strength (for operating system drives)_ to **XTS-AES 128-bit**
* ID 1762: Check used _BitLocker drive encryption method (for operation system drives)_: **XtsAes128**
* ID 1709: Set _Disable new DMA devices when this computer is locked_ to **Enabled**
* ID 1710: Set _Operating System Drives\Allow Secure Boot for integrity validation_ to **Enabled**
* ID 1711: Set _Operating System Drives\Require additional authentication at startup_ to **Enabled**
	* ID 1715: Set _Allow BitLocker without a compatible TPM_ to **False**
	* ID 1716: Set _Configure TPM startup_ to **Do not allow TPM**
	* ID 1717: Set _Configure TPM startup PIN_ to **Require startup PIN with TPM**
	* ID 1718: Set _Configure TPM startup key_ to **Do not allow startup key with TPM**
	* ID 1719: Set _Configure TPM startup key and PIN_ to **Do not allow startup key and PIN with TPM**
* ID 1712: Set _Operating System Drives\Allow enhanced PINs for startup_ to **Enabled**
* ID 1713: Set _Operating System Drives\Configure use of hardware-based encryption for operating system drives_ to **Enabled**
	* ID 1714: Set _Use BitLocker software-based encryption when hardware encryption is not available_ to **True**
* ID 1763: Set _Operating System Drives: Configure minimum PIN length for startup_ to **8 or higher**

#### Cloud Content

* ID 1720: Set _Do not show Windows tips_ to **Enabled**
* ID 1721: Set _Turn off Microsoft consumer experiences_ to **Enabled**

#### Credential User Interface

* ID 1722: Set _Do not display the password reveal button_ to **Enabled**
* ID 1724: Set _Enumerate administrator accounts on elevation_ to **Disabled**

#### Data Collection and Preview Builds

* ID 1725: Set _Allow Telemetry_ to **Enabled: 0 - Security [Enterprise Only]** or **Enabled: 1 - Basic**
* ID 1726: Set _Allow device name to be sent in Windows diagnostic data_ to **Disabled**

#### Delivery Optimization

* ID 1727: Set _Download Mode_ to **Enabled: Simple (99)**

#### Event Log Service

* ID 1728: Set _Application\Specify the maximum log file size (KB)_ to **Enabled: 32768** or higher
* ID 1729: Set _Security\Specify the maximum log file size (KB)_ to **Enabled: 196608** or higher
* ID 1730: Set _System\Specify the maximum log file size (KB)_ to **Enabled: 32768** or higher
* ID 1774: Set _Microsoft-Windows-PowerShell/Operational\Specify the maximum log file size (KB)_ to **Enabled: 268435456** or higher
	* Add **MaxSize=dword:10000000** to _HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational_
* ID 1775: Set _PowerShellCore/Operational\Specify the maximum log file size (KB)_ to **Enabled: 268435456** or higher
	* Add **MaxSize=dword:10000000** to _HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PowerShellCore/Operational_

#### File Explorer

* ID 1731: Set _Allow the use of remote paths in file shortcut icons_ to **Disabled**

#### HomeGroup

* ID 1732: Set _Prevent the computer from joining a homegroup_ to **Enabled**

#### Microsoft Defender Antivirus 

* ID 1800: Set _Turn off Microsoft Defender Antivirus_ to **Disabled**
* ID 1826: Set _Enable Tamper Protection (Status)_ to **Enabled**
* ID 1801: Set _Configure detection for potentially unwanted applications_ to **Enabled: Audit Mode**
* ID 1806: Set _Exclusions\Extension Exclusions_ to **Disabled**
* ID 1807: Do not use exclusions for extensions: **empty list**
* ID 1808: Set _Exclusions\Path Exclusions_ to **Disabled**
* ID 1809: Do not use exclusions for paths: **empty list**
* ID 1810: Set _Exclusions\Process Exclusions_ to **Disabled**
* ID 1811: Do not use exclusions for processes: **empty list**
* ID 1816: Set _MAPS: Join Microsoft MAPS_ to **Enabled: Advanced MAPS**
* ID 1817: Set _MAPS: Configure the 'Block at First Sight' feature_ to **Enabled**
* ID 1818: Set _MAPS: Send file samples when further analysis is required_ to **Disabled** (Always prompt)
* ID 1819: Set _MpEngine: Enable file hash computation feature_ to **Enabled**
* ID 1820: Set _MpEngine: Select cloud protection level_ to **Enabled: High blocking level or higher**
* ID 1821: Set _Real-time Protection: Scan all downloaded files and attachments_ to **Enabled**
* ID 1822: Set _Real-time Protection: Turn off real-time protection_ to **Disabled**
* ID 1823: Set _Real-time Protection: Turn on behavior monitoring (Policy)_ to **Enabled**
* ID 1824: Set _Real-time Protection: Turn on script scanning_ to **Enabled**
* ID 1825: Set _Scan: Scan removable drives_ to **Enabled**
* ID 1812: Enable sandboxing for Microsoft Defender Antivirus
* ID 1900: Set _Microsoft Defender Exploit Guard\Attack Surface Reduction\Configure Attack Surface Reduction rules_ to **Enabled**
	* Apply these rules (Set 'Value' to '1' (Block Mode)
	* ID 1901: be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 - Block executable content from email client and webmail
	* ID 1902: d4f940ab-401b-4efc-aadc-ad5f3c50688a - Block Office applications from creating child processes
	* ID 1903: 3b576869-a4ec-4529-8536-b80a7769e899 - Block Office applications from creating executable content
	* ID 1904: 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 - Block Office applications from injecting into other processes
	* ID 1905: d3e037e1-3eb8-44c8-a917-57927947596d - Impede JavaScript and VBScript to launch executables
	* ID 1906: 5beb7efe-fd9a-4556-801d-275e5ffc04cc - Block execution of potentially obfuscated scripts
	* ID 1907: 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b - Block Win32 imports from Macro code in Office	
	* ID 1908: 01443614-cd74-433a-b99e-2ecdc07bfc25 - Block executable files from running unless they meet a prevalence, age, or trusted list criteria	
	* ID 1909: c1db55ab-c21a-4637-bb3f-a12568109d35 - Use advanced protection against ransomware
	* ID 1910: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 - Block credential stealing from the Windows local security authority subsystem (lsass.exe)
	* ID 1911: d1e49aac-8f56-4280-b9ba-993a6d77406c - Block process creations originating from PSExec and WMI commands
	* ID 1912: b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 - Block untrusted and unsigned processes that run from USB
	* ID 1913: 26190899-1602-49e8-8b27-eb1d0a1ce869 - Block Office communication applications from creating child processes
	* ID 1914: 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c - Block Adobe Reader from creating child processes
	* ID 1915: e6db77e5-3df2-4cf1-b95a-636979351e5b - Block persistence through WMI event subscription
	* ID 1930: 56a863a9-875e-4185-98a7-b882c64b5ce5 - Block abuse of exploited vulnerable signed drivers
* ID 1966: Set _Microsoft Defender Exploit Guard\Attack Surface Reduction\Exclude files and paths from Attack Surface Reduction Rules (Policy)_ to **Disabled**
* ID 1967: Do not use exclusions for ASR Rules: **empty list**
* ID 1965: Set _Microsoft Defender Exploit Guard\Network Protection\Prevent users and apps from accessing dangerous websites_ to **Block**

#### News and interests

* ID 1767: Set _Enable news and interests on the taskbar_ to **Disabled**

#### OneDrive

* ID 1733: Set _Prevent the usage of OneDrive for file storage_ to **Enabled**

#### Remote Desktop Services

* ID 1734: Set _Remote Desktop Connection Client\Do not allow passwords to be saved_ to **Enabled**
* ID 1735: Set _Remote Desktop Session Host\Connections\Allow users to connect remotely by using Remote Desktop Services_ to **Disabled**
* ID 1736: Set _Remote Desktop Session Host\Device and Resource Redirection\Do not allow drive redirection_ to **Enabled**
* ID 1737: Set _Remote Desktop Session Host\Security\Always prompt for password upon connection_ to **Enabled**
* ID 1738: Set _Remote Desktop Session Host\Security\Require secure RPC communication_ to **Enabled**
* ID 1739: Set _Remote Desktop Session Host\Security\Set client connection encryption level_ to **Enabled: High Level**

#### Search

* ID 1740: Set _Allow Cloud Search_ to **Disabled**
* ID 1741: Set _Allow Cortana_ to **Disabled**
* ID 1742: Set _Allow Cortana above lock screen_ to **Disabled**
* ID 1743: Set _Allow indexing of encrypted files_ to **Disabled**
* ID 1744: Set _Allow search and Cortana to use location_ to **Disabled**
* ID 1745: Set _Set what information is shared in Search_ to **Enabled: Anonymous info**

#### Windows Error Reporting

* ID 1746: Set _Disable Windows Error Reporting_ to **Enabled**

#### Windows Game Recording and Broadcasting

* ID 1747: Set _Enables or disables Windows Game Recording and Broadcasting_ to **Disabled**

#### Windows Ink Workspace

* ID 1748: Set _Allow Windows Ink Workspace_ to **Disabled**

#### Windows Installer

* ID 1749: Set _Always install with elevated privileges_ to **Disabled**
* ID 1750: Set _Allow user control over installs_ to **Disabled**
* ID 1751: Set _Prevent Internet Explorer security prompt for Windows Installer scripts_ to **Disabled**
* ID 1770: Disable Co-Installer (USB AutoInstall)
	* Add **DisableCoInstallers=dword:00000001** to _HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer_

#### Windows Logon Options

* ID 1752: Set _Sign-in and lock last interactive user automatically after a restart_ to **Disabled**

#### Windows Remote Management (WinRM)

* ID 1753: Set _WinRM Client\Allow Basic authentication_ to **Disabled**
* ID 1754: Set _WinRM Client\Allow unencrypted traffic_ to **Disabled**
* ID 1755: Set _WinRM Client\Disallow Digest authentication_ to **Enabled**
* ID 1756: Set _WinRM Service\Allow remote server management through WinRM_ to **Disabled**
* ID 1757: Set _WinRM Service\Allow Basic authentication_ to **Disabled**
* ID 1758: Set _WinRM Service\Allow unencrypted traffic_ to **Disabled**
* ID 1759: Set _WinRM Service\Disallow WinRM from storing RunAs credentials_ to **Enabled**

#### Windows Remote Shell

* ID 1760: Set _Allow Remote Shell Access_ to **Disabled**

#### Windows Defender SmartScreen

* ID 2000, ID 2001: Set _Explorer\Configure Windows Defender SmartScreen_ to **Enabled: Warn and prevent bypass**

#### Windows PowerShell

* ID 2105: Set _Turn on Module Logging_ to **Enabled**
* ID 2106: Set _Turn on Module Logging - Module Names_ to **\*** (Wildcard)
* ID 2100, ID 2101: Set _Turn on PowerShell Script Block Logging_ to **Enabled**
* ID 2102, 2107: Set _Turn on PowerShell Transcription_ to **Enabled**, Include invocation headers
* ID 2103, ID 2104: Remove PowerShell Version 2

### MS Security Guide

* ID 2200: Set _LSASS Protection Mode_ to **Enabled**
	* Add **RunAsPPL=dword:00000001** to _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_
* ID 2201: Set _LSASS Audit Mode_ to **Enabled**
	* Add **AuditLevel=dword:00000008** to _HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe_ 
* ID 2202: Set _NetBT NodeType configuration_ to **P-node**
	* Add **NodeType=dword:00000002** to _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters_
* ID 2203: Set _WDigest Authentication_ to **Disabled**
	* Add **UseLogonCredential=dword:00000000** to _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest_
* ID 2209: Set _Enable Structured Exception Handling Overwrite Protection (SEHOP)_ to **Enabled**
	* Add **DisableExceptionChainValidation=dword:00000000** to _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel_
* ID 2210: Set _Limits print driver installation to Administrators_ to **Enabled**
	* Add **RestrictDriverInstallationToAdministrators=dword:00000001** to _HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint_
* ID 2211: Set _Configure RPC packet level privacy setting for incoming connections_ to **Enabled**
	* Add **RpcAuthnLevelPrivacyEnabled=dword:00000001** to _HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print_
* ID 2212: Set _Manage processing of Queue-specific files_ to **Enabled**
	* Add **CopyFilesPolicy=dword:00000001** to _HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers_

### MSS (Legacy)

* ID 2204: Set _Enable Safe DLL search mode_ to **Enabled**
	* Add **SafeDLLSearchMode=dword:00000001** to _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager_
* ID 2205: Set _MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)_ to **Highest protection, source routing is completely disabled**
	* Add **DisableIPSourceRouting=dword:00000002** to _HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters_
* ID 2206: Set _MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)_ to **Highest protection, source routing is completely disabled**
	* Add **DisableIPSourceRouting=dword:00000002** to _HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters_
* ID 2207: Set _MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes_ to **Disabled**
	* Add **EnableICMPRedirect=dword:00000000** to _HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters_
* ID 2208: Set _MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers_ to **Enabled**
	* Add **NoNameReleaseOnDemand=dword:00000001** to _HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters_

## Scheduled Tasks

* ID 2400: **Disable** the task _XblGameSave Standby Task_

## Services

* ID 2411: **Disable** _mDNS_ in _Dnscache_ service
	* Add **EnableMDNS=dword:00000000** to _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters_
* ID 2401, 2402: **Disable** the service _Print Spooler (Spooler)_
* ID 2412, 2413: **Disable** the service _WebClient (WebClient)_
* ID 2403, 2404: **Disable** the service _Xbox Accessory Management Service (XboxGipSvc)_
* ID 2405, 2406: **Disable** the service _Xbox Live Auth Manager (XblAuthManager)_
* ID 2407, 2408: **Disable** the service _Xbox Live Game Save (XblGameSave)_
* ID 2409, 2410: **Disable** the service _Xbox Live Networking Service (XboxNetApiSvc)_

## Windows Security

### App & browser control / Exploit protection

#### System settings

* ID 1950: Set _Control flow guard (CFG)_ to **On by default**
* ID 1951, ID 1952: Set _Data Execution Prevention (DEP)_ to **On by default**
* ID 1954, ID 1955: Set _Force randomization for images (Mandatory ASLR)_ to **On by default**
* ID 1956, ID 1957: Set _Randomize memory allocations (Bottom-up ASLR)_ to **On by default**
* ID 1958, ID 1959: Set _High-entropy ASLR_ to **On by default**
* ID 1960, ID 1961, ID 1962: Set _Validate exception chains (SEHOP)_ to **On by default**
* ID 1963, ID 1964: Set _Validate heap integrity_ to **On by default**

These settings can be exported as an XML file and loaded via Group Policy _Computer Configuration\Administrative Templates\Windows Components\Windows Defender Exploit Guard\Exploit Protection\Use a common set of exploit protection settings_. It is also possible to configure policies per application.

Example of an XML configuration file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<MitigationPolicy>
  <SystemConfig>
    <DEP Enable="true" EmulateAtlThunks="false" />
    <ASLR ForceRelocateImages="true" RequireInfo="false" BottomUp="true" HighEntropy="true" />
    <ControlFlowGuard Enable="true" SuppressExports="false" />
    <Fonts DisableNonSystemFonts="true" AuditOnly="false" Audit="false" />
    <SEHOP Enable="true" TelemetryOnly="false" />
    <Heap TerminateOnError="true" />
  </SystemConfig>
</MitigationPolicy>
```

#### Enable Data Execution Prevention (DEP)

* ID 1953: Force the use of Data Execution Prevention (DEP): `bcdedit.exe /set nx AlwaysOn` (Default is _OptIn_)

## User Configuration

#### Administrative Templates\PowerShell Core

* ID 4307, ID 4308: Set _Turn on Module Logging_ to **Enabled**, Use Windows PowerShell Policy setting
* ID 4309: Set _Turn on Module Logging - Module Names_ to **\*** (Wildcard)
* ID 4310, ID 4311, ID 4312: Set _Turn on PowerShell Script Block Logging_ to **Enabled**, Log script block invocation, Use Windows PowerShell Policy setting
* ID 4313, ID 4314, ID 4315: Set _Turn on PowerShell Transcription_ to **Enabled**, Include invocation headers, Use Windows PowerShell Policy setting

### Administrative Templates\Start Menu and Taskbar

#### Notifications

* ID 4001: Set _Turn off toast notifications on the lock screen_ to **Enabled**

### Administrative Templates\System

#### Internet Communication Management

* ID 4100: Set _Internet Communication Settings\Turn off Help Experience Improvement Program_ to **Enabled**

### Administrative Templates\Windows Components

#### Cloud Content

* ID 4200: Set _Do not use diagnostic data for tailored experiences_ to **Enabled**
* ID 4201: Set _Do not suggest third-party content in Windows spotlight_ to **Enabled**

#### Windows AI

* ID 4203: Set _Turn off Saving Snapshots for Windows_ to **Enabled** (Recall)

#### Windows Installer

* ID 4202: Set _Always install with elevated privileges_ to **Disabled**

### Windows PowerShell

* ID 4304: Set _Turn on Module Logging_ to **Enabled**
* ID 4305: Set _Turn on Module Logging - Module Names_ to **\*** (Wildcard)
* ID 4300, ID 4301: Set _Turn on PowerShell Script Block Logging_ to **Enabled**
* ID 4302, ID 4306: Set _Turn on PowerShell Transcription_ to **Enabled**, Include invocation headers
* ID 4303: Use _ConstrainedLanguageMode_ for users who do not need PowerShell

### Office 2016 Hardening

For Office 365 Hardening, lists [Microsoft 365 Apps (Machine)](https://github.com/0x6d69636b/windows_hardening/blob/master/lists/finding_list_msft_security_baseline_microsoft_365_apps_v2103_machine.csv) and [Microsoft 365 Apps (User)](https://github.com/0x6d69636b/windows_hardening/blob/master/lists/finding_list_msft_security_baseline_microsoft_365_apps_v2103_user.csv) should be used. Only stricter recommendations and additional settings are listed here.

#### Security Settings

* ID 4400: Set _Macro Runtime Scan Scope_ to **Enable for all documents**

#### Excel

* ID 4401: Set _Always prevent untrusted Microsoft Query files from opening_ to **Enabled**
* ID 4405: Set _Don’t allow Dynamic Data Exchange (DDE) server launch in Excel_ to **Enabled**
* ID 4406: Set _Don’t allow Dynamic Data Exchange (DDE) server lookup in Excel_ to **Enabled**	
* ID 4407: Set _Block macros from running in Office files from the Internet_ to **Enabled**	
* ID 4408, ID 4409: Set _VBA Macro Notification Settings_ to **Disable all**	

#### PowerPoint

* ID 4411: Set _Block macros from running in Office files from the Internet_ to **Enabled**	
* ID 4412: Set _VBA Macro Notification Settings_ to **Disable all**	

#### Word

* ID 4415: Set _Block macros from running in Office files from the Internet_ to **Enabled**	
* ID 4416, ID 4417: Set _VBA Macro Notification Settings_ to **Disable all**	

#### Registry Keys

Apply the following registry settings for your main/working user(s)

* ID 4402, ID 4403, ID 4404, ID 4424: Excel registry settings
* ID 4410: OneNote registry settings
* ID 4413, ID 4414: Word registry settings

```
[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Options]
"DontUpdateLinks"=dword:00000001
"DDEAllowed"=dword:00000000
"DDECleaned"=dword:00000001

[HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security]
"PythonFunctionWarnings"=dword:00000002

[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\OneNote\Options]
"DisableEmbeddedFiles"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Options]
"DontUpdateLinks"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Options\WordMail]
"DontUpdateLinks"=dword:00000001
```

#### Office 365 Privacy

* ID 4418: Disable the Office 365 Telemetry module (undocumented)

```
[HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\clienttelemetry]
"DisableTelemetry"=dword:00000001
```

* ID 4419: Set _Allow the use of connected experiences in Office_ to **Disabled**

```
[HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\common\privacy]
"disconnectedstate"=dword:00000002
```

* ID 4420: Set _Allow the use of connected experiences that analyze content_ to **Disabled**

```
[HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\common\privacy]
"usercontentdisabled"=dword:00000002
```

* ID 4421: Set _Allow the use of connected experiences that download online content_ to **Disabled**

```
[HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\common\privacy]
"downloadcontentdisabled"=dword:00000002
```

* ID 4422: Set _Allow the use of additional optional connected experiences_ to **Disabled**

```
[HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\common\privacy]
"controllerconnectedservicesenabled"=dword:00000002
```

* ID 4423: Set _Configure the level of client software diagnostic data sent by Office to Microsoft_ to **Neither**

```
[HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\clienttelemetry]
"sendtelemetry"=dword:00000003
```

## Windows Settings

### System

#### Notification & actions

* Set _Show notification on the lock screen_ to **Off** (Already managed by Group policy)
* Set _Show reminders and incoming VoIP calls on the lock screen_ to **Off**
* ID 4500: Set _Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what's new and suggested_ to **Off**
* ID 4501: Set _Get tips, tricks, and suggestions as you use Windows_ to **Off**

#### Shared experiences

* ID 4502, ID 4503: Set _Shared across devices_ to **Off**

#### Clipboard

* Set _Clipboard history_ to **Off**
* Set _Sync across devices_ to **Off** (Already managed by Group policy)

### Devices

#### Typing

* ID 4504: Set _Autocorrect misspelled words_ to **Off**

#### AutoPlay

* ID 4505: Set _Use AutoPlay for all media and devices_ to **Off**

### Network & Internet

#### Wi-Fi

* Set _Random hardware addresses_ to **On**
* Set _Let me use Online Sign-Up to get connected_ to **Off**

#### Ethernet

* Go to _Change Adapter Options_
	* Disable _File and Printer Sharing for Microsoft Networks_ for each adapter
	* Disable _NetBIOS_ in _Advanced TCP/IP Settings_ for each adapter

### Personalization

#### Lock screen

* Set _Get fun facts, tips, tricks, and more on your lock screen_ to **Off**

#### Start

* Set _Show more tiles on Start_ to **Off**
* Set _Show suggestions occasionally in Start_ to **Off**

### Search

#### Permissions & History

* Set _Windows Cloud Search_ to **Off**

### Privacy

The basic recommendation is to deactivate all access. However, this should not limit the functionality, e.g. if an app needs the microphone, access should be granted. Be careful with the settings for _background apps_ as well, disabling anything can lead to unexpected behaviour.

#### General

* Set everything to **Off**

#### Speech

* Set everything to **Off**

#### Inking & typing personalization

* Set everything to **Off**

#### Diagnostics & feedback

* Set _Diagnostic data_ to **Basic** (Already managed by Group policy) 
* Set _Improve inking and typing_ to **Off** (Already managed by Group policy)
* Set _Tailored experiences_ to **Off**
* Set _View diagnostic data_ to **Off**
* Set _Windows should ask for my feedback_ to **Never**
* Set _Recommended troubleshooting_ to **Ask me before fixing problems**

#### Activity history

* Set everything to **Off**

#### Location

* Set everything to **Off**

#### Camera

* Set everything to **Off**

#### Microphone

* Set everything to **Off**

#### Voice activation

* Set everything to **Off**

#### Notifications

* Set everything to **Off**

#### Account info

* Set everything to **Off**

#### Contacts

* Set everything to **Off**

#### Calendar

* Set everything to **Off**

#### Phone calls

* Set everything to **Off**

#### Call history

* Set everything to **Off**

#### Email

* Set everything to **Off**

#### Tasks

* Set everything to **Off**

#### Messaging

* Set everything to **Off**

#### Radio

* Set everything to **Off**

#### Other devices

* Set everything to **Off**

#### Background apps

* Set everything to **Off**

#### App diagnostics

* Set everything to **Off**

#### Automatic file downloads

* Set _Allow downloads_ to **Do not allow**

#### Documents

* Set everything to **Off**

#### Pictures

* Set everything to **Off**

#### Videos

* Set everything to **Off**

#### File system

* Set everything to **Off**

### Update & Security

#### Delivery Optimization

* Set _Allow downloads from other PCs_ to **Off**

## Windows Apps

Remove all unnecessary Apps like Xbox* or YourPhone:

```powershell
Get-AppxPackage -Name Microsoft.XboxGameOverlay | Remove-AppxPackage
```

List of Apps (your mileage may vary):

* Microsoft.People
* Microsoft.XboxGameOverlay
* Microsoft.XboxIdentityProvider
* Microsoft.XboxGameCallableUI
* Microsoft.XboxGamingOverlay
* Microsoft.YourPhone

## Monitoring

* Install [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
	* Use your own configuration, mine is based on [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

## Firewall Rules

Add the following rules to _Computer Configuration\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security_

### Inbound Rules

#### Basic

ID    | Name                  | Type        | Rule applies to | Protocol | Local ports | IP addresses | Action | Profile 
------|--------------------- | ------------| --------------- | -------- | ----------- | ------------ |  ---------- | -----------
2300 | HardeningKitty-Block-TCP-NetBIOS | Custom Rule | All programs | TCP | 137-139 | Any | Block | All
2301 | HardeningKitty-Block-TCP-RDP | Custom Rule | All programs | TCP | 3389 | Any | Block | All
2302 | HardeningKitty-Block-TCP-RPC | Custom Rule | All programs | TCP | 135, 593 | Any | Block | All
2303 | HardeningKitty-Block-TCP-SMB | Custom Rule | All programs | TCP | 445 | Any | Block | All
2304 | HardeningKitty-Block-TCP-WinRM | Custom Rule | All programs | TCP | 5985, 5986 | Any | Block | All
2305 | HardeningKitty-Block-UDP-NetBIOS | Custom Rule | All programs | UDP | 137-139 | Any | Block | All
2306 | HardeningKitty-Block-UDP-RPC | Custom Rule | All programs | UDP | 135, 593 | Any | Block | All

#### Optional

ID    | Name                  | Type        | Rule applies to | Protocol | Local ports | IP addresses | Action | Profile 
------|--------------------- | ------------| --------------- | -------- | ----------- | ------------ |  ---------- | -----------
\- | HardeningKitty-Block-TCP-VMware-HTTPS | Custom Rule | All programs | TCP | 443 | Any | Block | All
\- | HardeningKitty-Block-TCP-VMware-authd | Custom Rule | All programs | TCP | 902, 912 | Any | Block | All

### Outbound Rules

Quote @cryps1s: _While not the most glamorous of defensive strategies, those applications are commonly abused by default behaviors for process migration and injection techniques._

#### Basic

ID    | Name                  | Type        | Rule applies to | Protocol | Local ports | IP addresses | Action | Profile 
------|--------------------- | ------------| --------------- | -------- | ----------- | ------------ |  ---------- | -----------
2307 | HardeningKitty-Block-calc-x64 | Custom Rule | _%SystemRoot%\System32\calc.exe_ | Any | Any | Any | Block | All
2308 | HardeningKitty-Block-calc-x86 | Custom Rule | _%SystemRoot%\Syswow64\calc.exe_ | Any | Any | Any | Block | All
2309 | HardeningKitty-Block-certutil-x64 | Custom Rule | _%SystemRoot%\System32\certutil.exe_ | Any | Any | Any | Block | All
2310 | HardeningKitty-Block-certutil-x86 | Custom Rule | _%SystemRoot%\Syswow64\certutil.exe_ | Any | Any | Any | Block | All
2311 | HardeningKitty-Block-conhost-x64 | Custom Rule | _%SystemRoot%\System32\conhost.exe_ | Any | Any | Any | Block | All
2312 | HardeningKitty-Block-conhost-x86 | Custom Rule | _%SystemRoot%\Syswow64\conhost.exe_ | Any | Any | Any | Block | All
2313 | HardeningKitty--Block-cscript-x64 | Custom Rule | _%SystemRoot%\System32\cscript.exe_ | Any | Any | Any | Block | All
2314 | HardeningKitty--Block-cscript-x86 | Custom Rule | _%SystemRoot%\Syswow64\cscript.exe_ | Any | Any | Any | Block | All
2315 | HardeningKitty--Block-mshta-x64 | Custom Rule | _%SystemRoot%\System32\mshta.exe_ | Any | Any | Any | Block | All
2316 | HardeningKitty--Block-mshta-x86 | Custom Rule | _%SystemRoot%\Syswow64\mshta.exe_ | Any | Any | Any | Block | All
2317 | HardeningKitty--Block-notepad-x64 | Custom Rule | _%SystemRoot%\System32\notepad.exe_ | Any | Any | Any | Block | All
2318 | HardeningKitty--Block-notepad-x86 | Custom Rule | _%SystemRoot%\Syswow64\notepad.exe_ | Any | Any | Any | Block | All
2319 | HardeningKitty--Block-RunScriptHelper-x64 | Custom Rule | _%SystemRoot%\System32\RunScriptHelper.exe_ | Any | Any | Any | Block | All
2320 | HardeningKitty--Block-RunScriptHelper-x86 | Custom Rule | _%SystemRoot%\Syswow64\RunScriptHelper.exe_ | Any | Any | Any | Block | All
2321 | HardeningKitty--Block-wscript-x64 | Custom Rule | _%SystemRoot%\System32\wscript.exe_ | Any | Any | Any | Block | All
2322 | HardeningKitty--Block-wscript-x86 | Custom Rule | _%SystemRoot%\Syswow64\wscript.exe_ | Any | Any | Any | Block | All
