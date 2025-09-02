# How to Test for a Stack Buffer Overflow 🧪

This guide provides a practical, step-by-step methodology for identifying and confirming a classic stack-based buffer overflow vulnerability. The process is foundational for both exploit development and defensive security analysis.

**Disclaimer:** This is for educational purposes only. Perform these steps exclusively in a controlled environment on a program you have created for this purpose.

---

### ## 1. Setup the Environment

Before testing, you need a vulnerable application and the right tools.

#### **A. The Vulnerable Program (`vuln.c`)**
This simple C program uses the unsafe `strcpy` function, which is our target.

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[100];
    strcpy(buffer, input); // Vulnerable line: no size check
}

int main(int argc, char **argv) {
    printf("Enter your input: ");
    fflush(stdout);
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
