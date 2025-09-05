## 🎫 Cheatsheet: Golden & Silver Ticket Attacks

Golden and Silver Ticket attacks are powerful post-exploitation techniques that abuse the Kerberos protocol. They allow an attacker to forge Kerberos tickets to impersonate users and maintain persistent, often undetectable, access to a network.

### **Prerequisites for Forging Tickets**
These are not initial access attacks. An attacker must first compromise:
* **For a Golden Ticket:** The `KRBTGT` account's NTLM hash (the "master key" of the domain). This is typically stolen from a Domain Controller.
* **For a Silver Ticket:** The NTLM hash of a *service account* (e.g., a computer account for a file server, or a user account running a SQL service).

---

### ## Golden Ticket Attack

**Overview:** A Golden Ticket is a forged Kerberos Ticket-Granting Ticket (TGT). Since it's signed with the domain's master `KRBTGT` hash, it can be used to impersonate **any user** (including Domain Administrators) and request access to **any service** in the domain. It is the ultimate "master key" to an Active Directory kingdom and provides long-term persistence.

#### **How It Works**
1.  An attacker compromises a Domain Controller and extracts the NTLM hash of the `KRBTGT` account.
2.  The attacker also obtains the Domain's SID.
3.  Using this information, the attacker crafts a fake TGT offline, often creating a ticket for a non-existent user but making them a member of the "Domain Admins" group.
4.  The attacker injects this ticket into their current session memory using a "Pass-the-Ticket" technique.
5.  With the forged ticket in memory, the attacker can now access any resource (file shares, domain controllers, etc.) as a Domain Admin.



#### **Execution Workflow (Conceptual)**

* **Step 1: Obtain the `KRBTGT` Hash (on a DC)**
    This requires Domain Admin privileges.
    ```powershell
    # Using Mimikatz on a Domain Controller
    mimikatz # lsadump::dcsync /domain:<your.domain> /user:krbtgt
    ```

* **Step 2: Forge the Golden Ticket**
    This is done on the attacker's machine.
    ```powershell
    # Using Mimikatz to create the ticket
    mimikatz # kerberos::golden /user:fakeadmin /domain:<your.domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /groups:512 /ptt
    # /groups:512 adds the user to the "Domain Admins" group
    # /ptt forges and injects the ticket in one step
    ```

* **Step 3: Use the Ticket**
    After injecting the ticket, simply access any resource.
    ```powershell
    # Access a file share on the Domain Controller
    dir \\dc01\C$
    ```

#### **🛡️ Detection & Remediation**

* **Detection:** Golden Tickets are very stealthy. Detection relies on identifying anomalies:
    * Kerberos tickets with an abnormally long lifetime (Mimikatz defaults to 10 years).
    * Network traffic analysis might spot a TGT signed with a weaker encryption algorithm (RC4) when AES is enforced.
    * A user logging in from an IP address that does not match their typical behavior.
* **Remediation:**
    * **Reset the `KRBTGT` Password TWICE:** This is the **only** effective way to invalidate all Golden Tickets. It must be done twice in a row with a waiting period in between that is longer than your domain's Kerberos ticket validation time.
    * **Protect Domain Controllers:** Treat DCs as the most critical assets. Severely limit who can log into them, use Privileged Access Workstations (PAWs), and aggressively monitor for credential dumping activity.
    * **Minimize Domain Admins:** Reduce the number of accounts in highly privileged groups.

---

### ## Silver Ticket Attack

**Overview:** A Silver Ticket is a forged Kerberos Ticket-Granting Service (TGS) ticket. Unlike a Golden Ticket, which grants domain-wide access, a Silver Ticket grants access to a **specific service** on a **specific server** (e.g., the CIFS file service on `FILESERVER01`). It's a "master key to a single room," not the entire building. This attack is stealthier because it does not require contacting the Domain Controller.

#### **How It Works**
1.  An attacker compromises a target server and extracts the password hash of the account running the desired service (e.g., the computer account's hash for the CIFS service).
2.  The attacker forges a TGS ticket offline, granting themselves access to that specific service as any user, often a Domain Admin.
3.  The attacker injects the ticket into their session.
4.  The attacker can now access the specific service on the target server, and the server will validate the ticket using the hash it knows, without ever checking with the DC.

#### **Execution Workflow (Conceptual)**

* **Step 1: Obtain the Service Account Hash**
    This can be done via Kerberoasting or by dumping hashes from the target server's memory.
    ```powershell
    # Using Mimikatz on a compromised member server
    mimikatz # sekurlsa::logonpasswords
    ```

* **Step 2: Forge the Silver Ticket**
    This is done on the attacker's machine.
    ```powershell
    # Using Mimikatz. Note the use of /service and /rc4 (the service account hash)
    mimikatz # kerberos::golden /user:fakeadmin /domain:<your.domain> /sid:<domain_sid> /target:fileserver01.your.domain /service:cifs /rc4:<service_account_hash> /ptt
    ```

* **Step 3: Use the Ticket**
    Access the specific service on the target server.
    ```powershell
    # Access the C$ share on the fileserver
    dir \\fileserver01\C$
    ```

#### **🛡️ Detection & Remediation**

* **Detection:** Extremely difficult as it generates no traffic to the Domain Controller. Detection relies heavily on host-based monitoring:
    * Log and monitor access to sensitive files and services on critical servers.
    * An endpoint security solution (EDR) might detect the injection of a Kerberos ticket into memory.
* **Remediation:**
    * **Use Group Managed Service Accounts (gMSAs):** These accounts have automatically rotated, complex passwords, making it very difficult for an attacker to obtain a useful long-term hash.
    * **Enable Windows Defender Credential Guard:** This uses virtualization-based security to protect NTLM hashes from being dumped from memory.
    * **Principle of Least Privilege:** Ensure service accounts only have the minimum permissions they need to function.
