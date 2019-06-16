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
_Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Account lockout duration_
* Set _Account Lockout Policy\Account lockout threshold_ to **10 or fewer invalid logon attempt(s), but not 0**
_Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Account lockout threshold_
* Set _Account Lockout Policy\Reset account lockout counter after_ to **15 or more minute(s)**
_Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Reset account lockout counter after_

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
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access this computer from the network_
* Set _Allow log on locally_ to **Administrators, Users**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on locally_
* Set _Deny access to this computer from the network_ to include **Guests, Local account**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny access to this computer from the network_
* Set _Deny log on as a batch job_ to include **Guests**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a batch job_
* Set _Deny log on as a service_ to include **Guests**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a service_
* Set _Deny log on through Remote Desktop Services_ to include **Guests, Local account**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on through Remote Desktop Services_

#### Security Options
##### Accounts
* Set _Accounts: Block Microsoft accounts_ to **Users can't add or log on with Microsoft accounts**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Block Microsoft accounts_

##### Interactive Logon
* Set _Interactive logon: Do not require CTRL+ALT+DEL_ to **Disabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Do not require CTRL+ALT+DEL_
* Set _Interactive logon: Don't display last user name_ to **Enabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Don't display last user name_
* Set _Interactive logon: Don't display username at sign-in_ to **Enabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Don't display username at sign-in_

##### Microsoft Network Client/Server
* Set _Microsoft network client: Digitally sign communications (always)_ to **Enabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Digitally sign communications (always)_
* Set _Microsoft network client: Digitally sign communications (if server agrees)_ to **Enabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Digitally sign communications (if server agrees)_
* Set _Microsoft network server: Digitally sign communications (always)_ to **Enabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Digitally sign communications (always)_
* Set _Microsoft network server: Digitally sign communications (if client agrees)_ to **Enabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Digitally sign communications (if client agrees)_

##### Network Access
* Set _Network access: Do not allow anonymous enumeration of SAM accounts and shares_ to **Enabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow anonymous enumeration of SAM accounts and shares_
* Set _Network access: Do not allow storage of passwords and credentials for network authentication_ to **Enabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow storage of passwords and credentials for network authentication_

##### Network Security
* Set _Network security: Allow LocalSystem NULL session fallback_ to **Disabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Allow LocalSystem NULL session fallback_
* Set _Network security: LAN Manager authentication level_ to **Send NTLMv2 response only. Refuse LM & NTLM**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: LAN Manager authentication level_
* Set _Network security: LDAP client signing requirements_ to **Negotiate signing**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: LDAP client signing requirements_
* Set _Network security: Minimum session security for NTLM SSP based (including secure RPC) clients_ to **Require NTLMv2 session security, Require 128-bit encryption**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Minimum session security for NTLM SSP based (including secure RPC) clients_
* Set _Network security: Minimum session security for NTLM SSP based (including secure RPC) servers_ to **Require NTLMv2 session security, Require 128-bit encryption**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Minimum session security for NTLM SSP based (including secure RPC) servers_
* Set _Network security: Restrict NTLM: Audit Incoming NTLM Traffic_ to **Enable auditing for all accounts**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Restrict NTLM: Audit Incoming NTLM Traffic_
* Set _Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers_ to **Audit all**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers_

##### Security Options
* Set _Shutdown: Allow system to be shut down without having to log on_ to **Disabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Shutdown: Allow system to be shut down without having to log on_

##### User Account Control
* Set _User Account Control: Admin Approval Mode for the Built-in Administrator account_ to **Enabled**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Admin Approval Mode for the Built-in Administrator account_
* Set _User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode_ to **Prompt for consent on the secure desktop**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode_
* Set _User Account Control: Behavior of the elevation prompt for standard users_ to **Prompt for credentials on the secure desktop**
_Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for standard users_

### Windows Settings\Security Settings\Windows Firewall With Advanced Security
* _Firewall State_: **On**
* _Inbound Connections_: **Block**
* _Outbound Connections_: **Allow**
* _Size limit_: **16384**
* _Log dropped packets_: **Yes**
* _Log successful connections_: **Yes**

### Windows Settings\Security Settings\Advanced Audit Policy Configuration
* _Account Logon/Audit Credential Validation_: **Success and Failure**
* _Account Management/Audit Security Group Management_: **Success**
* _Account Management/Audit User Account Management_: **Success and Failure**
* _Detailed Tracking/Audit PNP Activity_: **Success**
* _Detailed Tracking/Audit Process Creation_: **Success**
* _Logon/Logoff/Audit Account Lockout_: **Failure**
* _Logon/Logoff/Audit Group Membership_: **Success**
* _Logon/Logoff/Audit Logon_: **Success and Failure**
* _Logon/Logoff/Audit Other Logon/Logoff Events_: **Success and Failure**
* _Logon/Logoff/Audit Special Logon_: **Success**
* _Object Access/Audit Detailed File Share_: **Failure**
* _Object Access/Audit File Share_: **Success and Failure**
* _Object Access/Audit Other Object Access Events_: **Success and Failure**
* _Object Access/Audit Removable Storage_: **Success and Failure**
* _Policy Change/Audit Audit Policy Change_: **Success**
* _Policy Change/Audit Authentication Policy Change_: **Success**
* _Policy Change/Audit MPSSVC Rule-Level Policy Change_: **Success and Failure**
* _Policy Change/Audit Other Policy Change Events_: **Failure**
* _Privilege Use/Audit Sensitive Privilege Use_: **Success and Failure**
* _System/Audit Other System Events_: **Success and Failure**
* _System/Audit Security State Change_: **Success**
* _System/Audit Security System Extension_: **Success**
* _System/Audit System Integrity_: **Success and Failure**

### Administrative Templates\Control Panel
#### Personalization
* Set _Prevent enabling lock screen camera_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization\Prevent enabling lock screen camera_

### Administrative Templates\Network
#### DNS Client
* Set _DNS Client\Turn off multicast name resolution_ (LLMNR) to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Network\DNS Client\Turn off multicast name resolution_

#### Lanman Workstation
* Set _Lanman Workstation\Enable insecure guest logons_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Enable insecure guest logons_

#### Microsoft Peer-to-Peer Networking Services
* Set _Turn off Microsoft Peer-to-Peer Networking Services_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Network\Microsoft Peer-to-Peer Networking Services\Turn off Microsoft Peer-to-Peer Networking Services_

#### WLAN Service
* Set _WLAN Service\WLAN Settings\Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Network\WLAN Service\WLAN Settings\Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services_

### Administrative Templates\Start Menu and Taskbar
#### Notifications
* Set _Turn off notifications network usage_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications\Turn off notifications network usage_

### Administrative Templates\System
#### Credentials Delegation
* Set _Credentials Delegation\Encryption Oracle Remediation_ to **Enabled: Force Updated Clients**
_Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Encryption Oracle Remediation_

#### Device Installation
* Set _Device Installation Restrictions\Prevent installation of devices that match any of these device IDs_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Device Installation\Device Installation Restrictions\Prevent installation of devices that match any of these device IDs_
	* Set _Also apply to matching devices that are already installed_ to **True**
	* Device ID = **PCI\CC_0C0010** (Plug and Play compatible ID for a 1394 controller)
	* Device ID = **PCI\CC_0C0A** (Plug and Play compatible ID for a Thunderbolt controller)
	**Note**: Not required if Kernel DMA protection is active (check with `msinfo32.exe`)
* Set _Device Installation Restrictions\Prevent installation of devices using drivers that match these device setup classes_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Device Installation\Device Installation Restrictions\Prevent installation of devices using drivers that match these device setup classes_
	* Set _Also apply to matching devices that are already installed_ to **True**
	* GUID = **{d48179be-ec20-11d1-b6b8-00c04fa372a7}** (Plug and Play device setup class GUID)

#### Device Guard
**Warning**: Besides Virtualization Based Security, no other virtualization solution like VMware Workstation can be used at the moment.
* Set _Turn On Virtualization Based Security_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security_
	* Set _Select Plattform Security Level_ to **Secure Boot and DMA Protection**
	* Set _Virtualization Based Protection of Code Integrity_ to **Enabled with UEFI lock**
	* Set _Credential Guard Configuration_ to **Enabled with UEFI lock**
	* Set _Secure Lunch Configuration_ to **Enabled**

#### Early Launch Antimalware
* Set _Boot-Start Driver Initialization Policy_ to **Good, unknown and bad but critical**
_Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware\Boot-Start Driver Initialization Policy_

#### Group Policy 
* Set _Configure registry policy processing_ To **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Group Policy\Configure registry policy processing_
	* Set _Process even if the Group Policy objects have not changed_ to **True**
	* Set _Do not apply during periodic background processing_ to **False**


#### Internet Communication Management
* Set _Internet Communication settings\Turn off the Windows Messenger Customer Experience Improvement Program_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off the Windows Messenger Customer Experience Improvement Program_
* Set _Internet Communication settings\Turn off downloading of print drivers over HTTP_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off downloading of print drivers over HTTP_
* Set _Internet Communication settings\Turn off Windows Error Reporting_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Windows Error Reporting_
* Set _Internet Communication settings\Turn off Internet download for Web publishing and online ordering wizards_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Internet download for Web publishing and online ordering wizards_
* Set _Internet Communication settings\Turn off Windows Customer Experience Improvement Program_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Windows Customer Experience Improvement Program_

#### Kernel DMA Protection
* Set _Enumeration policy for external devices incompatible with Kernel DMA Protection_ to **Block all**
_Computer Configuration\Policies\Administrative Templates\System\Kernel DMA Protection\Enumeration policy for external devices incompatible with Kernel DMA Protection_

#### Logon
* Set _Turn on convenience PIN sign-in_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\System\Logon\Turn on convenience PIN sign-in_
* Set _Turn off app notifications on the lock screen_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Logon\Turn off app notifications on the lock screen_
* Set _Do not display network selection UI_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Logon\Do not display network selection UI_

#### Mitigation Options
* Set _Untrusted Font Blocking_ to **Block untrusted fonts and log events**
_Computer Configuration\Policies\Administrative Templates\System\Mitigation Options\Untrusted Font Blocking_

#### OS Policies
* Set _Allow Clipboard synchronization across devices_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\System\OS Policies\Allow Clipboard synchronization across devices_

#### Power Management
* Set _Sleep Settings\Require a password when a computer wakes (plugged in)_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings\Require a password when a computer wakes (plugged in)_
* Set _Sleep Settings\Allow standby states (S1-S3) when sleeping (on battery)_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings\Allow standby states (S1-S3) when sleeping (on battery)_
* Set _Allow standby states (S1-S3) when sleeping (plugged in)_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings\Allow standby states (S1-S3) when sleeping (plugged in)_
* Set _Require a password when a computer wakes (on battery)_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings\Require a password when a computer wakes (on battery)_

#### Remote Assistance
* Set _Configure Offer Remote Assistance_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\System\Remote Assistance\Configure Offer Remote Assistance_
* Set _Configure Solicited Remote Assistance_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\System\Remote Assistance\Configure Solicited Remote Assistance_

#### Remote Procedure Call
* Set _Enable RPC Endpoint Mapper Client Authentication_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\Enable RPC Endpoint Mapper Client Authentication_
* Set _Restrict Unauthenticated RPC clients_ to **Enabled: Authenticated without exceptions**
_Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\Restrict Unauthenticated RPC clients_

#### Service Control Manager Settings
* Set _Security Settings\Enable svchost.exe mitigation options_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Service Control Manager Settings\Security Settings\Enable svchost.exe mitigation options_

#### Troubleshooting and Diagnostics
* Set _Windows Performance PerfTrack\Enable/Disable PerfTrack_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\System\Troubleshooting and Diagnostics\Windows Performance PerfTrack\Enable/Disable PerfTrack_

### User Profiles
* Set _Turn of the advertising ID_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\User Profiles\Turn of the advertising ID_

#### Windows Time Service
* Set _Enable Windows NTP Client_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers\Enable Windows NTP Client_
* Set _Enable Windows NTP Server_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers\Enable Windows NTP Server_

### Administrative Templates\Windows Components
#### App Package Deployment
* Set _Allow a Windows app to share application data between users_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment\Allow a Windows app to share application data between users_

#### App Privacy
* Set _Let Windows apps activate with voice while the system is locked_ to **Enabled: Force Deny**
_Computer Configuration\Policies\Administrative Templates\Windows Components\App Privacy\Let Windows apps activate with voice while the system is locked_

#### App runtime
* Set _Block launching Windows Store apps with Windows Runtime API access from hosted content._ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\App runtime\Block launching Windows Store apps with Windows Runtime API access from hosted content._

#### Application Compatibility
* Set _Turn off Application Telemetry_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility\Turn off Application Telemetry_

#### AutoPlay Policies
* Set _Turn off Autoplay_ to **Enabled: All drives**
_Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\Turn off Autoplay_
* Set _Disallow Autoplay for non-volume devices_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\Disallow Autoplay for non-volume devices_
* Set _Set the default behavior for AutoRun_ to **Enabled: Do not execute any autorun commands**
_Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\Set the default behavior for AutoRun_

#### Biometrics
* Set _Allow the use of biometrics_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Biometrics\Allow the use of biometrics_

#### BitLocker Drive Encryption
* Set _Disable new DMA devices when this computer is locked_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\BitLocker Drive Encryption\Disable new DMA devices when this computer is locked_
* Set _Operating System Drives\Allow Secure Boot for integrity validation_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives\Allow Secure Boot for integrity validation_
* Set _Operating System Drives\Require additional authentication at startup_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives\Require additional authentication at startup_
	* Set _Allow BitLocker without a compatible TPM_ to **False**
	* Set _Configure TPM startup_ to **Do not allow TPM**
	* Set _Configure TPM startup PIN_ to **Require startup PIN with TPM**
	* Set _Configure TPM startup key_ to **Do not allow startup key with TPM**
	* Set _Configure TPM startup key and PIN_ to **Do not allow startup key and PIN with TPM**
* Set _Operating System Drives\Allow enhanced PINs for startup_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives\Allow enhanced PINs for startup_
* Set _Configure use of hardware-based encryption for operating system drives_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives\Configure use of hardware-based encryption for operating system drives_
	* Set _Use BitLocker software-based encryption when hardware encryption is not available_ to **True**

#### Cloud Content
* Set _Do not show Windows tips_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Do not show Windows tips_
* Set _Turn off Microsoft consumer experiences_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Turn off Microsoft consumer experiences_

#### Credential User Interface
* Set _Do not display the password reveal button_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Do not display the password reveal button_
* Set _Require trusted path for credential entry_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Require trusted path for credential entry_
* Set _Enumerate administrator accounts on elevation_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\Enumerate administrator accounts on elevation_

#### Data Collection and Preview Builds
* Set _Allow Telemetry_ to **Enabled: 0 - Security [Enterprise Only]** or **Enabled: 1 - Basic**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Allow Telemetry_

#### Delivery Optimization
* Set _Download Mode_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Delivery Optimization\Download Mode_

#### Event Log Service
* Set _Application\Specify the maximum log file size (KB)_ to **Enabled: 32768**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application\Specify the maximum log file size (KB)_
* Set _Security\Specify the maximum log file size (KB)_ to **Enabled: 196608**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security\Specify the maximum log file size (KB)_
* Set _System: Specify the maximum log file size (KB)_ to **Enabled: 32768**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System\Specify the maximum log file size (KB)_

#### File Explorer
* Set _Allow the use of remote paths in file shortcut icons_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Allow the use of remote paths in file shortcut icons_
* Set _Configure Windows Defender SmartScreen_ to **Enabled: Warn and prevent bypass**
_Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\Configure Windows Defender SmartScreen_

#### HomeGroup
* Set _Prevent the computer from joining a homegroup_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\HomeGroup\Prevent the computer from joining a homegroup_

#### OneDrive
* Set _Prevent the usage of OneDrive for file storage_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\OneDrive\Prevent the usage of OneDrive for file storage_

#### Remote Desktop Services
* Set _Remote Desktop Connection Client\Do not allow passwords to be saved_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Connection Client\Do not allow passwords to be saved_
* Set _Remote Desktop Session Host\Connections\Allow users to connect remotely by using Remote Desktop Services_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Connections\Allow users to connect remotely by using Remote Desktop Services_
* Set _Remote Desktop Session Host\Device and Resource Redirection\Do not allow drive redirection_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow drive redirection_
* Set _Remote Desktop Session Host\Security\Always prompt for password upon connection_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Always prompt for password upon connection_
* Set _Remote Desktop Session Host\Security\Require secure RPC communication_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Require secure RPC communication_
* Set _Remote Desktop Session Host\Security\Set client connection encryption level_ to **High Level**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Set client connection encryption level_

#### Search
* Set _Allow Cloud Search_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow Cloud Search_
* Set _Allow Cortana_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow Cortana_
* Set _Allow Cortana above lock screen_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow Cortana above lock screen_
* Set _Allow indexing of encrypted files_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow indexing of encrypted files_
* Set _Allow search and Cortana to use location_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow search and Cortana to use location_
* Set _Set what information is shared in Search_ to **Enabled: Anonymous info**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Set what information is shared in Search_

#### Windows Defender
* Set _Turn off Windows Defender Antivirus_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender\Turn off Windows Defender Antivirus_
* Set _Configure detection for potentially unwanted applications_ to **Audit Mode**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender\Configure detection for potentially unwanted applications_
* Set _MAPS\Join Microsoft MAPS_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender\MAPS\Join Microsoft MAPS_
* Set _Windows Defender Exploit Guard\Attack Surface Reduction\Configure Attack Surface Reduction rules_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender\Windows Defender Exploit Guard\Attack Surface Reduction\Configure Attack Surface Reduction rules_
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

#### Windows Defender SmartScreen
* Set _Explorer\Configure Windows Defender SmartScreen_ to **Enabled: Warn and prevent bypass**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender SmartScreen\Explorer\Configure Windows Defender SmartScreen_

#### Windows Error Reporting
* Set _Disable Windows Error Reporting_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Error Reporting\Disable Windows Error Reporting_

#### Windows Game Recording and Broadcasting
* Set _Enables or disables Windows Game Recording and Broadcasting_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Game Recording and Broadcasting\Enables or disables Windows Game Recording and Broadcasting_

#### Windows Ink Workspace
* Set _Allow Windows Ink Workspace_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Ink Workspace\Allow Windows Ink Workspace_

#### Windows Installer
* Set _Always install with elevated privileges_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Always install with elevated privileges_
* Set _Allow user control over installs_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Allow user control over installs_
* Set _Prevent Internet Explorer security prompt for Windows Installer scripts_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Prevent Internet Explorer security prompt for Windows Installer scripts_

#### Windows Logon Options
* Set _Sign-in and lock last interactive user automatically after a restart_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options\Sign-in and lock last interactive user automatically after a restart_

#### Windows PowerShell
* Set _Turn on PowerShell Script Block Logging_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Script Block Logging_
* Set _Turn on PowerShell Transcription_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Transcription_

#### Windows Remote Management (WinRM)
* Set _WinRM Client\Allow Basic authentication_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Allow Basic authentication_
* Set _WinRM Client\Allow unencrypted traffic_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Allow unencrypted traffic_
* Set _WinRM Client\Disallow Digest authentication_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\Disallow Digest authentication_
* Set _WinRM Service\Allow remote server management through WinRM_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Allow remote server management through WinRM_
* Set _WinRM Service\Allow Basic authentication_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Allow Basic authentication_
* Set _WinRM Service\Allow unencrypted traffic_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Allow unencrypted traffic_
* Set _WinRM Service\Disallow WinRM from storing RunAs credentials_ to **Enabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\Disallow WinRM from storing RunAs credentials_

#### Windows Remote Shell
* Set _Allow Remote Shell Access_ to **Disabled**
_Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Shell\Allow Remote Shell Access_

## Local Computer Policy - User Configuration
### Administrative Templates\Start Menu and Taskbar
#### Notifications
* Set _Turn off toast notifications on the lock screen_ to **Enabled**
_User Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications\Turn off toast notifications on the lock screen_

### Administrative Templates\System
#### Internet Communication Management
* Set _Internet Communication Settings\Turn off Help Experience Improvement Program_ to **Enabled**
_User Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication Settings\Turn off Help Experience Improvement Program_

### Administrative Templates\Windows Components
#### Cloud Content
* Set _Do not use diagnostic data for tailored experiences_ to **Enabled**
_User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Do not use diagnostic data for tailored experiences_
* Set _Do not suggest third-party content in Windows spotlight_ to **Enabled**
_User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Do not suggest third-party content in Windows spotlight_

#### Windows Installer
* Set _Always install with elevated privileges_ to **Disabled**
_User Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\Always install with elevated privileges_

## Registry
### NetBIOS
* Set _NetBT NodeType configuration_ to **P-node**
Add **NodeType=dword:00000002** to _HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters_

### Security Modules - WDigest
* Set _WDigest Authentication_ to **Disabled**
Add **UseLogonCredential=dword:00000000** to _HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest_

### LSASS
* Set _LSASS Audit Mode_ to **Enabled**
Add **AuditLevel=dword:00000008** to _HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe_ 
* Set _LSASS Protection Mode_ to **Enabled**
Add **RunAsPPL=dword:00000001** to _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_

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
* Set _Show me the Windows welcome experience after updtaes and occasionally when I sign in to highlight what's new and suggested_ to **Off**
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
* Set _Occasionally show suggestions in Start_ to **Off**

### Search
#### Permissions & History
* Set _Windows Cloud Search_ to **Off**

### Privacy

#### General
* Set everything to **Off**

#### Speech
* Set everything to **Off**

#### Inking & typing personalization
* Set everything to **Off**

#### Diagnostic data
* Set _Diagnostic data_ to **Basic** (Already managed by Group policy) 
* Set _Improve inking and typing_ to **Off** (Already managed by Group policy)
* Set _Tailored experiences_ to **Off**
* Set _Windows should ask for my feedback_ to **Never**

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

#### Account Info
* Set everything to **Off**

#### Contacts
* Set everything to **Off**

#### Calendar
* Set everything to **Off**

#### Phone calls
* Set everything to **Off**

#### Call History
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

### Update & Security

#### Delivery Optimization
* Set _Allow downloads from other PCs_ to **Off**

## Windows Security
### Virus & threat protection
* Set _Automatic sample submission_ to **Off**
* Set _Controlled folder access_ to **On**

## Monitoring
* Install [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
	* Use your on configuration, mine is based on [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
