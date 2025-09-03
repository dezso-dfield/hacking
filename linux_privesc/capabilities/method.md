## 🔑 Cheatsheet: Linux Capabilities Privilege Escalation

Linux capabilities are a security feature that divides the monolithic power of `root` into a set of distinct privileges. Instead of giving a program full root access with SUID, you can give it just the specific privilege it needs (e.g., the ability to bind to a low port). A vulnerability arises when an executable is granted a powerful or abusable capability that can be leveraged to gain a full root shell.

### ## What to Look For (Reconnaissance)

The primary goal is to find executables on the system that have any capabilities set.

* **Find All Binaries with Capabilities:**
    The `getcap` command is the main tool for this. The following command recursively searches the entire filesystem.
    ```bash
    getcap -r / 2>/dev/null
    ```
    * `-r`: Recursive search.
    * `/`: Start from the root directory.
    * `2>/dev/null`: Hide any "Permission denied" errors.

* **Interpreting the Output:**
    The output shows the binary and the capabilities it has in the "permitted" and "effective" sets.
    ```
    /usr/bin/ping = cap_net_raw+ep
    /usr/bin/python3.9 = cap_setuid+ep
    ```
    The `+ep` signifies that the capability is both effective (used by the process) and permitted (can be used by the process). A binary like `python` with `cap_setuid` is a huge red flag.

---

### ## Common Exploitable Scenarios & Payloads

The exploitation method depends entirely on the capability that has been assigned. **GTFOBins** is an essential resource for finding the exact exploitation commands.

#### **Scenario 1: `cap_setuid`**
This capability allows a process to change its user ID. It's one of the most powerful and is trivial to exploit.

* **Binary:** `/usr/bin/python3.9 = cap_setuid+ep`
* **Exploitation:** Use Python to call the `setuid(0)` function, which sets the current process's user ID to `0` (root), and then spawn a shell.
    ```bash
    /usr/bin/python3.9 -c 'import os; os.setuid(0); os.system("/bin/bash -p")'
    ```

#### **Scenario 2: `cap_sys_admin`**
This is the "god mode" of capabilities, granting a wide range of administrative privileges. It can be abused in numerous ways, such as mounting filesystems.

* **Binary:** `/usr/sbin/capsh = cap_sys_admin+ep`
* **Exploitation:** Use the tool's features to get a shell with the capability active, then perform a privileged action.

#### **Scenario 3: `cap_dac_read_search`**
This capability allows a process to bypass file read permission checks and directory read/execute permission checks.

* **Binary:** `/usr/bin/tcpdump = cap_dac_read_search+ep`
* **Exploitation:** Use the program to read sensitive files that would normally be inaccessible, like the shadow password file.
    ```bash
    /usr/bin/tcpdump -r /etc/shadow
    ```

#### **Scenario 4: `cap_chown`**
This capability allows a process to arbitrarily change file ownership.

* **Binary:** `/bin/tar = cap_chown+ep`
* **Exploitation:** An attacker can create a malicious SUID binary, then use `tar` to archive and extract it, making `root` the owner during extraction.

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **File Integrity Monitoring (FIM):** Monitor for changes to file capabilities on system binaries. A new capability being added to a file like `python` should be a high-priority alert.
* **Audit Logs:** Use `auditd` to monitor the use of capabilities. You can create rules to log any process that successfully uses a dangerous capability like `cap_setuid`.

#### **How to Prevent Capabilities Abuse**

* **Principle of Least Privilege:** This is the entire point of capabilities. When assigning them, be as granular as possible. If a web server only needs to bind to port 80, give it `cap_net_bind_service`, not `cap_net_admin` or `cap_sys_admin`.
* **Remove Unnecessary Capabilities:** Regularly audit your systems for binaries with capabilities. If a capability is not required for a program to function, remove it.
    ```bash
    # Command to remove all capabilities from a binary
    sudo setcap -r /path/to/binary

    # Command to set a specific, justified capability
    sudo setcap cap_net_raw+ep /usr/bin/ping
    ```
* **Avoid Overly Powerful Capabilities:** Be extremely cautious about granting `cap_setuid`, `cap_sys_admin`, `cap_dac_override`, and `cap_chown`. These are almost always abusable for full privilege escalation.
* **Regular Audits:** Periodically run `getcap -r /` and compare the output against a known-good baseline to identify any unauthorized changes.
