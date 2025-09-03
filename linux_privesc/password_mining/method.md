## 📜 Cheatsheet: Password Mining in Files

This is one of the most common and effective privilege escalation techniques. It involves searching the filesystem for credentials (passwords, API keys, private keys, connection strings) that have been carelessly left in scripts, configuration files, user history, or source code. Finding the password for a privileged user is often the fastest way to get root.

### ## What to Look For (Reconnaissance)

An attacker will systematically scour the filesystem for anything that looks like a secret. This can be done manually with tools like `grep` or with powerful automated scripts.

* **Manual Search Commands:**
    `grep` is the primary tool for this.
    ```bash
    # Search recursively for "password" in /etc, ignoring case and showing file names
    grep -rli "password" /etc

    # Find all files ending in .conf and search them for "pass"
    find / -name "*.conf" 2>/dev/null -exec grep -i "pass" {} \;

    # Search a user's entire home directory
    grep --color=auto -rli "pass" /home/user
    ```
    **Common keywords:** `password`, `pass`, `pwd`, `secret`, `token`, `api_key`, `key`, `credentials`, `connection_string`.

* **Key Files & Locations to Check:**
    * **Shell History:** Often contains passwords typed on the command line.
        * `~/.bash_history`, `~/.zsh_history`, `~/.ash_history`
    * **Configuration Files:** A goldmine for database and service credentials.
        * Web server configs: `apache2.conf`, `httpd.conf`, `.htaccess`
        * Application configs: `wp-config.php` (WordPress), `web.config`, `settings.py` (Django)
        * Custom scripts: `/etc/backup.sh`, `/var/scripts/deploy.py`
    * **SSH Keys:** Unprotected private keys can grant access to other systems.
        * `~/.ssh/id_rsa`, `~/.ssh/authorized_keys`
    * **User Directories & Logs:**
        * `/home/*` (check all user directories you can read)
        * `/var/log` (logs can sometimes contain sensitive data)
        * `/var/www/html` (web root often contains config files)

* **Automated Tools:**
    * **LinPEAS (`linpeas.sh`):** This is the go-to script for Linux enumeration. It has extensive checks for finding credentials in all the common (and uncommon) places.

---

### ## Common Exploitable Scenarios

* **Database Credentials in Web Configs:**
    You find a `wp-config.php` file containing:
    `define('DB_PASSWORD', 'MyPassword123!');`
    You can then try to use `MyPassword123!` for the `root` Linux user or for other services.

* **Password in Bash History:**
    You inspect `~/.bash_history` and find a line:
    `sudo -u admin /opt/app/run.sh -p 'AdminPass_4_real!'`
    You now have the password for the `admin` user.

* **Unprotected SSH Private Key:**
    You find an `id_rsa` file in `/home/user/.ssh/` that is not protected by a passphrase. You can copy this key to your machine and use it to SSH into other servers as `user`.
    `ssh -i id_rsa user@other-server.com`

---

### ## 🛡️ Detection & Remediation (For Defenders)

#### **How to Detect an Attempt**

* **Difficult to Detect:** This attack primarily involves reading files, which is normal system behavior. Detection usually happens after a compromise.
* **Auditing:** `auditd` can be configured to log read access to highly sensitive files (e.g., `wp-config.php`), but this can be very noisy.

#### **How to Prevent Credential Exposure**

* **NEVER Hardcode Credentials:** This is the most important rule. Passwords, tokens, and keys should **never** be stored in plaintext in scripts or config files.
* **Use a Secrets Management System:** The modern solution is to use a dedicated secrets vault.
    * Examples: **HashiCorp Vault**, **AWS Secrets Manager**, **Azure Key Vault**.
    * Applications should fetch secrets from these vaults at runtime.
* **Use Environment Variables:** For simpler applications, store secrets in environment variables that are loaded into the application's process. Ensure these variables are not saved to disk.
* **Enforce Strict File Permissions:** Config files with sensitive data must be owned by `root` or the service account and have permissions like `600` (`-rw-------`) so only the owner can read them.
* **Sanitize Command-Line History:**
    * Educate users not to type passwords on the command line.
    * Prefix commands with a **space** to prevent them from being written to history (this works on default Bash configs). `[space]mysql -u root -pMyPassword`
* **Always Use Passphrases for SSH Keys:** Encrypting your private keys is a critical security layer.
* **Proactive Secret Scanning:** Use tools like **`gitleaks`**, **`truffleHog`**, or **`git-secrets`** to scan your code repositories and file systems for accidentally committed secrets *before* they are exploited.
