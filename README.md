# SUPCOM

**SUPCOM (Suspicious Process and Command Monitor)** is a Python-based Windows security monitoring tool designed to detect potentially suspicious processes and command-line activity.

The project focuses on identifying suspicious command execution through a combination of:

- Process monitoring
- Rule-based command-line detection
- Base64-like string detection
- Repeated-command behavioral detection
- Severity classification
- Event logging

The project is being developed as a practical cybersecurity project with an emphasis on understanding how process monitoring and detection logic work.

---

## Project Status

**Current status:** Core detection engine implemented and tested.

The current version successfully detects:

- PowerShell encoded-command indicators
- Base64-like command-line strings
- Repeated suspicious command execution
- High-severity behavioral escalation
- Suspicious events suitable for logging

A limitation has also been identified in the current polling-based process monitoring approach: very short-lived processes can terminate before the monitor observes them.

The next planned improvement is to replace or improve the polling mechanism with Windows process-creation event monitoring.

---

## Features

### 1. Process Monitoring

SUPCOM uses `psutil` to inspect running Windows processes.

For newly observed processes, it retrieves:

- PID
- Process name
- Command line

Processes that cannot be accessed because of Windows permissions are skipped.

---

### 2. Encoded Command Detection

The detection engine looks for suspicious command-line indicators such as:

```text
-enc
base64
