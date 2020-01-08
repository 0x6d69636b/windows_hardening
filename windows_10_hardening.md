# Windows 10 Hardening

## Basic Hardening
* Use a separate local admin account
* Use BitLocker with Enhanced PIN
* Enable Windows Defender
* Disable SMBv1
	* Check Status: `Get-WindowsOptionalFeature -Online -FeatureName smb1protocol`
	* Disable: `Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol`

## Local Computer Policy - Computer Configuration 
### Windows Settings\Security Settings\Account Policies
* Set _Account Lockout Policy\Account lockout duration_ to **15 or more minute(s)**
* Set _Account Lockout Policy\Account lockout threshold_ to **10 or fewer invalid logon attempt(s), but not 0**
* Set _Account Lockout Policy\Reset account lockout counter after_ to **15 or more minute(s)**

### Windows Settings\Security Settings\Local Policies
#### Audit Policy
* _Audit account logon events_: **Failure**
* _Audit account management_: **Success and Failure**
* _Audit directory service access_: **No auditing**
* _Audit logon events_: **Failure**
* _Audit object access_: **Failure**
* _Audit policy change_: **Success and Failure**
* _Audit privilege use_: **Success and Failure**
* _Audit process tracking_: **No auditing**
* _Audit system events_: **Success and Failure**

#### User Rights Assignment
* Set _Access this computer from the network_ to **Administrators**
* Set _Allow log on locally_ to **Administrators, Users**
* Remove **Administrators** from _Debug programs_ (SeDebugPrivilege)
* Set _Deny access to this computer from the network_ to include **Guests, Local account**
* Set _Deny log on as a batch job_ to include **Guests**
* Set _Deny log on as a service_ to include **Guests**
* Set _Deny log on through Remote Desktop Services_ to include **Guests, Local account**

#### Security Options
##### Accounts
* Set _Accounts: Block Microsoft accounts_ to **Users can't add or log on with Microsoft accounts**

##### Interactive Logon
* Set _Interactive logon: Do not require CTRL+ALT+DEL_ to **Disabled**
* Set _Interactive logon: Don't display last signed-in_ to **Enabled**
* Set _Interactive logon: Don't display username at sign-in_ to **Enabled**

##### Microsoft Network Client/Server
* Set _Microsoft network client: Digitally sign communications (always)_ to **Enabled**
* Set _Microsoft network client: Digitally sign communications (if server agrees)_ to **Enabled**
* Set _Microsoft network server: Digitally sign communications (always)_ to **Enabled**
* Set _Microsoft network server: Digitally sign communications (if client agrees)_ to **Enabled**

##### Network Access
* Set _Network access: Do not allow anonymous enumeration of SAM accounts and shares_ to **Enabled**
* Set _Network access: Do not allow storage of passwords and credentials for network authentication_ to **Enabled**

##### Network Security
* Set _Network security: Allow LocalSystem NULL session fallback_ to **Disabled**
* Set _Network security: LAN Manager authentication level_ to **Send NTLMv2 response only. Refuse LM & NTLM**
* Set _Network security: LDAP client signing requirements_ to **Negotiate signing**
* Set _Network security: Minimum session security for NTLM SSP based (including secure RPC) clients_ to **Require NTLMv2 session security, Require 128-bit encryption**
* Set _Network security: Minimum session security for NTLM SSP based (including secure RPC) servers_ to **Require NTLMv2 session security, Require 128-bit encryption**
* Set _Network security: Restrict NTLM: Audit Incoming NTLM Traffic_ to **Enable auditing for all accounts**
* Set _Network security: Restrict NTLM: Audit NTLM authentication_ in this domain to **Enable all**
* Set _Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers_ to **Audit all**

##### Security Options
* Set _Shutdown: Allow system to be shut down without having to log on_ to **Disabled**

##### User Account Control
* Set _User Account Control: Admin Approval Mode for the Built-in Administrator account_ to **Enabled**
* Set _User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode_ to **Prompt for consent on the secure desktop**
* Set _User Account Control: Behavior of the elevation prompt for standard users_ to **Prompt for credentials on the secure desktop**

### Windows Settings\Security Settings\Windows Firewall With Advanced Security
* _Firewall State_: **On**
* _Inbound Connections_: **Block**
* _Outbound Connections_: **Allow**
* _Size limit_: **16384**
* _Log dropped packets_: **Yes**
* _Log successful connections_: **Yes**

### Windows Settings\Security Settings\Advanced Audit Policy Configuration
* _Account Logon\Audit Credential Validation_: **Success and Failure**
* _Account Management\Audit Security Group Management_: **Success**
* _Account Management\Audit User Account Management_: **Success and Failure**
* _Detailed Tracking\Audit PNP Activity_: **Success**
* _Detailed Tracking\Audit Process Creation_: **Success**
* _Logon/Logoff\Audit Account Lockout_: **Failure**
* _Logon/Logoff\Audit Group Membership_: **Success**
* _Logon/Logoff\Audit Logon_: **Success and Failure**
* _Logon/Logoff\Audit Other Logon/Logoff Events_: **Success and Failure**
* _Logon/Logoff\Audit Special Logon_: **Success**
* _Object Access\Audit Detailed File Share_: **Failure**
* _Object Access\Audit File Share_: **Success and Failure**
* _Object Access\Kernel Object_: **Success and Failure**
* _Object Access\Audit Other Object Access Events_: **Success and Failure**
* _Object Access\Audit Removable Storage_: **Success and Failure**
* _Object Access\Audit SAM_: **Success and Failure**
* _Policy Change\Audit Audit Policy Change_: **Success**
* _Policy Change\Audit Authentication Policy Change_: **Success**
* _Policy Change\Audit MPSSVC Rule-Level Policy Change_: **Success and Failure**
* _Policy Change\Audit Other Policy Change Events_: **Failure**
* _Privilege Use\Audit Sensitive Privilege Use_: **Success and Failure**
* _System\Audit Other System Events_: **Success and Failure**
* _System\Audit Security State Change_: **Success**
* _System\Audit Security System Extension_: **Success**
* _System\Audit System Integrity_: **Success and Failure**

### Administrative Templates\Control Panel
#### Personalization
* Set _Prevent enabling lock screen camera_ to **Enabled**

### Administrative Templates\Network
#### DNS Client
* Set _DNS Client\Turn off multicast name resolution_ (LLMNR) to **Enabled**

#### Lanman Workstation
* Set _Lanman Workstation\Enable insecure guest logons_ to **Disabled**

#### Microsoft Peer-to-Peer Networking Services
* Set _Turn off Microsoft Peer-to-Peer Networking Services_ to **Enabled**

#### WLAN Service
* Set _WLAN Service\WLAN Settings\Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services_ to **Disabled**

### Administrative Templates\Start Menu and Taskbar
#### Notifications
* Set _Turn off notifications network usage_ to **Enabled**

### Administrative Templates\System
#### Credentials Delegation
* Set _Credentials Delegation\Allow delegation default credentials_ to **Disabled** (tspkg)
* Set _Credentials Delegation\Encryption Oracle Remediation_ to **Enabled: Force Updated Clients**

#### Device Installation
* Set _Device Installation Restrictions\Prevent installation of devices that match any of these device IDs_ to **Enabled**
	* Set _Also apply to matching devices that are already installed_ to **True**
	* Device ID = **PCI\CC_0C0010** (Plug and Play compatible ID for a 1394 controller)
	* Device ID = **PCI\CC_0C0A** (Plug and Play compatible ID for a Thunderbolt controller)
	**Note**: Not required if Kernel DMA protection is active (check with `msinfo32.exe`)
* Set _Device Installation Restrictions\Prevent installation of devices using drivers that match these device setup classes_ to **Enabled**
	* Set _Also apply to matching devices that are already installed_ to **True**
	* GUID = **{d48179be-ec20-11d1-b6b8-00c04fa372a7}** (Plug and Play device setup class GUID for an SBP-2 drive)

#### Device Guard
**Warning**: Besides Virtualization Based Security, no other virtualization solution like VMware Workstation can be used at the moment.
* Set _Turn On Virtualization Based Security_ to **Enabled**
	* Set _Select Plattform Security Level_ to **Secure Boot and DMA Protection**
	* Set _Virtualization Based Protection of Code Integrity_ to **Enabled with UEFI lock**
	* Set _Credential Guard Configuration_ to **Enabled with UEFI lock**
	* Set _Secure Lunch Configuration_ to **Enabled**

#### Early Launch Antimalware
* Set _Boot-Start Driver Initialization Policy_ to **Good, unknown and bad but critical**

#### Group Policy 
* Set _Configure registry policy processing_ To **Enabled**
	* Set _Process even if the Group Policy objects have not changed_ to **True**
	* Set _Do not apply during periodic background processing_ to **False**

#### Internet Communication Management
* Set _Internet Communication settings\Turn off the Windows Messenger Customer Experience Improvement Program_ to **Enabled**
* Set _Internet Communication settings\Turn off downloading of print drivers over HTTP_ to **Enabled**
* Set _Internet Communication settings\Turn off Windows Error Reporting_ to **Enabled**
* Set _Internet Communication settings\Turn off Internet download for Web publishing and online ordering wizards_ to **Enabled**
* Set _Internet Communication settings\Turn off Windows Customer Experience Improvement Program_ to **Enabled**

#### Kernel DMA Protection
* Set _Enumeration policy for external devices incompatible with Kernel DMA Protection_ to **Block all**

#### Logon
* Set _Turn on convenience PIN sign-in_ to **Disabled**
* Set _Turn off app notifications on the lock screen_ to **Enabled**
* Set _Do not display network selection UI_ to **Enabled**

#### Mitigation Options
* Set _Untrusted Font Blocking_ to **Block untrusted fonts and log events**

#### OS Policies
* Set _Allow Clipboard synchronization across devices_ to **Disabled**

#### Power Management
* Set _Sleep Settings\Require a password when a computer wakes (plugged in)_ to **Enabled**
* Set _Sleep Settings\Allow standby states (S1-S3) when sleeping (on battery)_ to **Disabled**
* Set _Allow standby states (S1-S3) when sleeping (plugged in)_ to **Disabled**
* Set _Require a password when a computer wakes (on battery)_ to **Enabled**

#### Remote Assistance
* Set _Configure Offer Remote Assistance_ to **Disabled**
* Set _Configure Solicited Remote Assistance_ to **Disabled**

#### Remote Procedure Call
* Set _Enable RPC Endpoint Mapper Client Authentication_ to **Enabled**
* Set _Restrict Unauthenticated RPC clients_ to **Enabled: Authenticated without exceptions**

#### Service Control Manager Settings
* Set _Security Settings\Enable svchost.exe mitigation options_ to **Enabled**

#### Troubleshooting and Diagnostics
* Set _Windows Performance PerfTrack\Enable/Disable PerfTrack_ to **Disabled**

#### User Profiles
* Set _Turn of the advertising ID_ to **Enabled**

#### Windows Time Service
* Set _Enable Windows NTP Client_ to **Enabled**
* Set _Enable Windows NTP Server_ to **Disabled**

### Administrative Templates\Windows Components
#### App Package Deployment
* Set _Allow a Windows app to share application data between users_ to **Disabled**

#### App Privacy
* Set _Let Windows apps activate with voice while the system is locked_ to **Enabled: Force Deny**

#### App runtime
* Set _Block launching Windows Store apps with Windows Runtime API access from hosted content._ to **Enabled**

#### Application Compatibility
* Set _Turn off Application Telemetry_ to **Enabled**

#### AutoPlay Policies
* Set _Turn off Autoplay_ to **Enabled: All drives**
* Set _Disallow Autoplay for non-volume devices_ to **Enabled**
* Set _Set the default behavior for AutoRun_ to **Enabled: Do not execute any autorun commands**

#### Biometrics
* Set _Allow the use of biometrics_ to **Disabled**

#### BitLocker Drive Encryption
* Set _Disable new DMA devices when this computer is locked_ to **Enabled**
* Set _Operating System Drives\Allow Secure Boot for integrity validation_ to **Enabled**
* Set _Operating System Drives\Require additional authentication at startup_ to **Enabled**
	* Set _Allow BitLocker without a compatible TPM_ to **False**
	* Set _Configure TPM startup_ to **Do not allow TPM**
	* Set _Configure TPM startup PIN_ to **Require startup PIN with TPM**
	* Set _Configure TPM startup key_ to **Do not allow startup key with TPM**
	* Set _Configure TPM startup key and PIN_ to **Do not allow startup key and PIN with TPM**
* Set _Operating System Drives\Allow enhanced PINs for startup_ to **Enabled**
* Set _Configure use of hardware-based encryption for operating system drives_ to **Enabled**
	* Set _Use BitLocker software-based encryption when hardware encryption is not available_ to **True**

#### Cloud Content
* Set _Do not show Windows tips_ to **Enabled**
* Set _Turn off Microsoft consumer experiences_ to **Enabled**

#### Credential User Interface
* Set _Do not display the password reveal button_ to **Enabled**
* Set _Require trusted path for credential entry_ to **Enabled**
* Set _Enumerate administrator accounts on elevation_ to **Disabled**

#### Data Collection and Preview Builds
* Set _Allow Telemetry_ to **Enabled: 0 - Security [Enterprise Only]** or **Enabled: 1 - Basic**
* Set _Allow device name to be sent in Windows diagnostic data_ to **Disabled**

#### Delivery Optimization
* Set _Download Mode_ to **Disabled**

#### Event Log Service
* Set _Application\Specify the maximum log file size (KB)_ to **Enabled: 32768**
* Set _Security\Specify the maximum log file size (KB)_ to **Enabled: 196608**
* Set _System: Specify the maximum log file size (KB)_ to **Enabled: 32768**

#### File Explorer
* Set _Allow the use of remote paths in file shortcut icons_ to **Disabled**
* Set _Configure Windows Defender SmartScreen_ to **Enabled: Warn and prevent bypass**

#### HomeGroup
* Set _Prevent the computer from joining a homegroup_ to **Enabled**

#### OneDrive
* Set _Prevent the usage of OneDrive for file storage_ to **Enabled**

#### Remote Desktop Services
* Set _Remote Desktop Connection Client\Do not allow passwords to be saved_ to **Enabled**
* Set _Remote Desktop Session Host\Connections\Allow users to connect remotely by using Remote Desktop Services_ to **Disabled**
* Set _Remote Desktop Session Host\Device and Resource Redirection\Do not allow drive redirection_ to **Enabled**
* Set _Remote Desktop Session Host\Security\Always prompt for password upon connection_ to **Enabled**
* Set _Remote Desktop Session Host\Security\Require secure RPC communication_ to **Enabled**
* Set _Remote Desktop Session Host\Security\Set client connection encryption level_ to **High Level**

#### Search
* Set _Allow Cloud Search_ to **Disabled**
* Set _Allow Cortana_ to **Disabled**
* Set _Allow Cortana above lock screen_ to **Disabled**
* Set _Allow indexing of encrypted files_ to **Disabled**
* Set _Allow search and Cortana to use location_ to **Disabled**
* Set _Set what information is shared in Search_ to **Enabled: Anonymous info**

#### Windows Defender Antivirus
* Set _Turn off Windows Defender Antivirus_ to **Disabled**
* Set _Configure detection for potentially unwanted applications_ to **Audit Mode**
* Set _Windows Defender Exploit Guard\Attack Surface Reduction\Configure Attack Surface Reduction rules_ to **Enabled**
	* Apply these rules (Set 'Value' to '1' (Block Mode)
	* be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 - Block executable content from email client and webmail
	* d4f940ab-401b-4efc-aadc-ad5f3c50688a - Block Office applications from creating child processes
	* 3b576869-a4ec-4529-8536-b80a7769e899 - Block Office applications from creating executable content
	* 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 - Block Office applications from injecting into other processes
	* d3e037e1-3eb8-44c8-a917-57927947596d - Impede JavaScript and VBScript to launch executables
	* 5beb7efe-fd9a-4556-801d-275e5ffc04cc - Block execution of potentially obfuscated scripts
	* 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b - Block Win32 imports from Macro code in Office	
	* 01443614-cd74-433a-b99e-2ecdc07bfc25 - Block executable files from running unless they meet a prevalence, age, or trusted list criteria	
	* c1db55ab-c21a-4637-bb3f-a12568109d35 - Use advanced protection against ransomware
	* 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 - Block credential stealing from the Windows local security authority subsystem (lsass.exe)
	* d1e49aac-8f56-4280-b9ba-993a6d77406c - Block process creations originating from PSExec and WMI commands
	* b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 - Block untrusted and unsigned processes that run from USB
	* 26190899-1602-49e8-8b27-eb1d0a1ce869 - Block Office communication applications from creating child processes
	* 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c - Block Adobe Reader from creating child processes
	* e6db77e5-3df2-4cf1-b95a-636979351e5b - Block persistence through WMI event subscription

#### Windows Defender SmartScreen
* Set _Explorer\Configure Windows Defender SmartScreen_ to **Enabled: Warn and prevent bypass**

#### Windows Error Reporting
* Set _Disable Windows Error Reporting_ to **Enabled**

#### Windows Game Recording and Broadcasting
* Set _Enables or disables Windows Game Recording and Broadcasting_ to **Disabled**

#### Windows Ink Workspace
* Set _Allow Windows Ink Workspace_ to **Disabled**

#### Windows Installer
* Set _Always install with elevated privileges_ to **Disabled**
* Set _Allow user control over installs_ to **Disabled**
* Set _Prevent Internet Explorer security prompt for Windows Installer scripts_ to **Disabled**

#### Windows Logon Options
* Set _Sign-in and lock last interactive user automatically after a restart_ to **Disabled**

#### Windows PowerShell
* Set _Turn on PowerShell Script Block Logging_ to **Enabled**
* Set _Turn on PowerShell Transcription_ to **Enabled**

#### Windows Remote Management (WinRM)
* Set _WinRM Client\Allow Basic authentication_ to **Disabled**
* Set _WinRM Client\Allow unencrypted traffic_ to **Disabled**
* Set _WinRM Client\Disallow Digest authentication_ to **Enabled**
* Set _WinRM Service\Allow remote server management through WinRM_ to **Disabled**
* Set _WinRM Service\Allow Basic authentication_ to **Disabled**
* Set _WinRM Service\Allow unencrypted traffic_ to **Disabled**
* Set _WinRM Service\Disallow WinRM from storing RunAs credentials_ to **Enabled**

#### Windows Remote Shell
* Set _Allow Remote Shell Access_ to **Disabled**

## Local Computer Policy - User Configuration
### Administrative Templates\Start Menu and Taskbar
#### Notifications
* Set _Turn off toast notifications on the lock screen_ to **Enabled**

### Administrative Templates\System
#### Internet Communication Management
* Set _Internet Communication Settings\Turn off Help Experience Improvement Program_ to **Enabled**

### Administrative Templates\Windows Components
#### Cloud Content
* Set _Do not use diagnostic data for tailored experiences_ to **Enabled**
* Set _Do not suggest third-party content in Windows spotlight_ to **Enabled**

#### Windows Installer
* Set _Always install with elevated privileges_ to **Disabled**

## Registry
### NetBIOS
* Set _NetBT NodeType configuration_ to **P-node**
	* Add **NodeType=dword:00000002** to _HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters_

### Security Modules - WDigest
* Set _WDigest Authentication_ to **Disabled**
	* Add **UseLogonCredential=dword:00000000** to _HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest_

### LSASS
* Set _LSASS Audit Mode_ to **Enabled**
	* Add **AuditLevel=dword:00000008** to _HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe_ 
* Set _LSASS Protection Mode_ to **Enabled**
	* Add **RunAsPPL=dword:00000001** to _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_

### Office Hardening
* Apply the following registry settings for your main/working user(s)

```
[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Options]
"DontUpdateLinks"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Word\Options]
"DontUpdateLinks"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Word\Options]
"DontUpdateLinks"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Options\WordMail]
"DontUpdateLinks"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Word\Options\WordMail]
"DontUpdateLinks"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Word\Options\WordMail]
"DontUpdateLinks"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\OneNote\Options]
"DisableEmbeddedFiles"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\OneNote\Options]
"DisableEmbeddedFiles"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Options]
"DontUpdateLinks"=dword:00000001
"DDEAllowed"=dword:00000000
"DDECleaned"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Excel\Options]
"DontUpdateLinks"=dword:00000001
"DDEAllowed"=dword:00000000
"DDECleaned"=dword:00000001
"Options"=dword:00000117

[HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Excel\Options]
"DontUpdateLinks"=dword:00000001
"DDEAllowed"=dword:00000000
"DDECleaned"=dword:00000001
"Options"=dword:00000117
```
## Windows Settings
### System
#### Notification & actions
* Set _Show notification on the lock screen_ to **Off** (Already managed by Group policy)
* Set _Show reminders and incoming VoIP calls on the lock screen_ to **Off**
* Set _Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what's new and suggested_ to **Off**
* Set _Get tips, tricks, and suggestions as you use Windows_ to **Off**

#### Shared experiences
* Set _Shared across devices_ to **Off**

#### Clipboard
* Set _Clipboard history_ to **Off**
* Set _Sync across devices_ to **Off** (Already managed by Group policy)

### Devices
#### Typing
* Set _Autocorrect misspelled words_ to **Off**

#### AutoPlay
* Set _Use AutoPlay for all media and devices_ to **Off**

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

## Windows Security
### Virus & threat protection
* Set _Cloud-delivered protection_ to **On** (only works if _Join MAPS_ is not disabled)
* Set _Automatic sample submission_ to **Off**
* Set _Controlled folder access_ to **On**

## Monitoring
* Install [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
	* Use your own configuration, mine is based on [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

## Firewall Rules
Add the following rules to _Computer Configuration\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security_

### Inbound Rules
#### Basic

* GPO-Block-TCP-NetBIOS
  * Custom Rule
  * All programs
  * Protocol: TCP
  * Local ports: 137-139
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-TCP-RDP
  * Custom Rule
  * All programs
  * Protocol: TCP
  * Local ports: 3389
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-TCP-RPC
  * Custom Rule
  * All programs
  * Protocol: TCP
  * Local ports: 135, 593
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-TCP-SMB
  * Custom Rule
  * All programs
  * Protocol: TCP
  * Local ports: 445
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-TCP-WinRM
  * Custom Rule
  * All programs
  * Protocol: TCP
  * Local ports: 5985, 5986
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-UDP-NetBIOS
  * Custom Rule
  * All programs
  * Protocol: UDP
  * Local ports: 137-139
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-UDP-RPC
  * Custom Rule
  * All programs
  * Protocol: UDP
  * Local ports: 135, 593
  * Any IP addresses
  * Block
  * All profiles

#### Optional

* GPO-Block-TCP-VMware-HTTPS
  * Custom Rule
  * All programs
  * Protocol: TCP
  * Local ports: 443
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-TCP-VMware-authd
  * Custom Rule
  * All programs
  * Protocol: TCP
  * Local ports: 902, 912
  * Any IP addresses
  * Block
  * All profiles

### Outbound Rules
Quote @cryps1s: _While not the most glamorous of defensive strategies, those applications are commonly abused by default behaviors for process migration and injection techniques._

#### Basic

* GPO-Block-calc
  * Custom Rule
  * _%SystemRoot%\System32\calc.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-calc
  * Custom Rule
  * _%SystemRoot%\Syswow64\calc.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-certutil
  * Custom Rule
  * _%SystemRoot%\System32\certutil.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-certutil
  * Custom Rule
  * _%SystemRoot%\Syswow64\certutil.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-conhost
  * Custom Rule
  * _%SystemRoot%\System32\conhost.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-conhost
  * Custom Rule
  * _%SystemRoot%\Syswow64\conhost.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-cscript
  * Custom Rule
  * _%SystemRoot%\System32\cscript.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-cscript
  * Custom Rule
  * _%SystemRoot%\Syswow64\cscript.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-mshta
  * Custom Rule
  * _%SystemRoot%\System32\mshta.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-mshta
  * Custom Rule
  * _%SystemRoot%\Syswow64\mshta.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-notepad
  * Custom Rule
  * _%SystemRoot%\System32\notepad.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-notepad
  * Custom Rule
  * _%SystemRoot%\Syswow64\notepad.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-RunScriptHelper
  * Custom Rule
  * _%SystemRoot%\System32\RunScriptHelper.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-RunScriptHelper
  * Custom Rule
  * _%SystemRoot%\Syswow64\RunScriptHelper.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-wscript
  * Custom Rule
  * _%SystemRoot%\System32\wscript.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
* GPO-Block-wscript
  * Custom Rule
  * _%SystemRoot%\Syswow64\wscript.exe_
  * Any protocols
  * Any ports
  * Any IP addresses
  * Block
  * All profiles
