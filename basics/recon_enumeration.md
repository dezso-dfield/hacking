### ### Phase 1: Passive & Initial Reconnaissance (Zero Direct Contact)

**Goal:** Gather as much information as possible from public sources without alerting the target.

* **1.1. Define Scope:**
    * Identify target domains, IP ranges, and organizational names.
    * Example: `example.com`, `10.10.0.0/16`

* **1.2. OSINT (Open-Source Intelligence):**
    * **Whois Lookup:** Find domain registration, contacts, and nameservers.
        ```bash
        whois example.com
        ```
    * **DNS & Subdomain Enumeration (Passive):**
        * Use online tools: `DNSdumpster`, `VirusTotal`, `Censys`.
        * Use CLI tools that query public sources:
            ```bash
            subfinder -d example.com -silent
            amass enum -passive -d example.com
            ```
    * **Google Hacking (Dorking):**
        * `site:example.com -www` (Find subdomains)
        * `site:example.com filetype:pdf confidential` (Find sensitive documents)
        * `inurl:login site:example.com` (Find login pages)

---

### ### Phase 2: Active Network Scanning (Initial Contact)

**Goal:** Identify live hosts, open ports, service versions, and operating systems. The primary tool is **`nmap`**.

* **2.1. Host Discovery (Ping Sweep):**
    * Find live hosts within a target range.
        ```bash
        # -sn: Ping Scan (no port scan). -T4: Aggressive timing.
        nmap -sn 10.10.0.0/16 -oA nmap/host_discovery
        ```

* **2.2. Initial Port Scanning (Fast & Broad):**
    * Quickly scan live hosts for common open ports.
        ```bash
        # -F: Fast scan (top 100 ports). -iL: Input from a list of live hosts.
        nmap -F -iL live_hosts.txt -oN nmap/fast_scan
        ```

* **2.3. Detailed Service Scanning (The Deep Dive):**
    * This is the main, comprehensive scan on identified targets.
        ```bash
        # -p-: Scan all 65,535 TCP ports.
        # -sV: Determine service/version info.
        # -sC: Run default, safe scripts.
        # -O: Enable OS detection.
        # -oA <filename>: Output in All formats.
        nmap -p- -sV -sC -O -oA nmap/detailed_scan <TARGET_IP>
        ```
        

* **2.4. UDP Scanning (As Needed):**
    * Scan for common UDP services (DNS, SNMP, etc.). This is slow.
        ```bash
        # -sU: UDP scan. --top-ports 200: Scan the top 200 UDP ports.
        sudo nmap -sU --top-ports 200 <TARGET_IP>
        ```

---

### ### Phase 3: Service-Specific Enumeration (Drilling Down)

**Goal:** Based on `nmap` results, perform deep enumeration on each discovered service.

####   **Web Servers (HTTP/S - Ports 80, 443, 8080, etc.)**

* **3.1. Technology Fingerprinting:**
    * Identify server tech, CMS, frameworks.
        ```bash
        whatweb http://<TARGET_IP>
        nikto -h http://<TARGET_IP>
        # Browser Plugin: Wappalyzer
        ```

* **3.2. Directory & File Brute-Forcing:**
    * Find hidden content, login pages, and API endpoints.
        ```bash
        # ffuf is fast and modern. FUZZ is the placeholder.
        ffuf -w /path/to/wordlist.txt -u http://<TARGET_IP>/FUZZ

        # gobuster is another popular choice.
        gobuster dir -u http://<TARGET_IP> -w /path/to/wordlist.txt -x .php,.txt,.html
        ```

####   **Windows & Active Directory Environment**

*Your `nmap` scan will suggest an AD environment if you see ports 53 (DNS), 88 (Kerberos), 135 (RPC), 139/445 (SMB), and 389 (LDAP).*

* **3.3. SMB Enumeration (Port 445):**
    * Check for shares, user lists, and anonymous access.
        ```bash
        # List shares anonymously
        smbclient -L //<TARGET_IP> -N

        # Comprehensive enumeration with enum4linux-ng
        enum4linux-ng -A <TARGET_IP>

        # Use crackmapexec to check for null sessions or spray credentials
        crackmapexec smb <TARGET_IP> -u '' -p ''
        ```

* **3.4. Active Directory & LDAP Enumeration (Port 389):**
    * Query the domain controller for users, groups, and domain info.
        ```bash
        # Nmap LDAP scripts (safe)
        nmap -n -sV --script "ldap* and not brute" -p 389 <DC_IP>

        # Anonymous bind with ldapsearch to dump domain info
        ldapsearch -x -h <DC_IP> -b "DC=example,DC=local"
        ```

* **3.5. Kerberos Enumeration (Port 88):**
    * Identify valid domain usernames via Kerberos pre-authentication.
        ```bash
        # Use a wordlist of potential usernames
        kerbrute userenum --dc <DC_IP> -d example.local /path/to/users.txt
        ```

* **3.6. RPC Enumeration (Port 135):**
    * Connect to the RPC endpoint to enumerate users and domain information.
        ```bash
        # Connect anonymously and list domain users
        rpcclient -U "" -N <TARGET_IP>
        rpcclient $> enumdomusers
        ```

####   **Linux Environment**

* **3.7. NFS Enumeration (Port 2049):**
    * Check for network file shares that can be mounted.
        ```bash
        # -e: Show the server's export list.
        showmount -e <TARGET_IP>
        ```

* **3.8. SSH Enumeration (Port 22):**
    * Grab the banner to identify the version and check for weak supported algorithms.
        ```bash
        nmap -sV -p 22 --script ssh2-enum-algos <TARGET_IP>
        ```

* **3.9. FTP Enumeration (Port 21):**
    * The primary check is for anonymous login.
        ```bash
        ftp <TARGET_IP>
        # User: anonymous
        # Pass: anonymous
        ```

---

### ### Phase 4: Consolidate & Plan Next Steps

**Goal:** Review all findings to identify the most promising attack vectors.

* **Vulnerability Correlation:** Cross-reference all discovered service versions (`nmap -sV`) with exploit databases (`searchsploit <service_name> <version>`).
* **Identify Low-Hanging Fruit:**
    * Was anonymous/guest access allowed on SMB, NFS, or FTP?
    * Did a web scan reveal a default login page (`/admin`) or an exposed config file?
    * Did `kerbrute` identify valid usernames to use in a password spraying attack?
* **Prioritize Targets:** Based on the data, create a prioritized list of targets and potential vulnerabilities to investigate further in the vulnerability analysis and exploitation phases.
