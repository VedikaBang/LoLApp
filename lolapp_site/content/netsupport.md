---
title: "netsupport"
date: 2023-11-11
tags: ["Description", "IoCs", "TTPs", "Detection Rules"]
---

## netsupport

NetSupport is a software tool used for remote control, classroom management, and IT support.

## App Artifacts

| IoC | Observations | DFIR Relevance |
|:----|:-------------|:---------------|
| `C:\Program Files\NetSupport\` | Default installation directory | Indicates the presence of NetSupport for remote management. Unauthorized installations may suggest malicious use. |
| `NetSupportManager.exe` | Main executable file | Execution patterns can reveal abnormal or unauthorized remote management activities. |
| Configuration and Logs | `%AppData%\NetSupport\` | Stores configurations and logs, useful for identifying operational patterns and potentially unauthorized modifications. |
| Registry Key Configurations | `HKLM\SOFTWARE\NetSupport\` | Persistent settings in the registry can indicate configuration changes for unauthorized access or persistence. |
| Service Control Actions | Event ID 7035 | Logs the start and stop actions of NetSupport services, helpful in identifying unauthorized service manipulation. |
| Service Creation | Event ID 7045 | Logs the creation of new NetSupport services, indicating installation or modification. |
| Service Status Changes | Event ID 7036 | Tracks the status changes of NetSupport services, useful for understanding service operation and interruptions. |
| Process Creation Tracking | Event ID 4688 | Monitors when NetSupport processes are initiated, aiding in the detection of unexpected or unauthorized usage. |
| Special Privilege Assignments | Event ID 4672 | Logs instances of high privilege assignments to NetSupport processes, potentially indicating escalation of privileges. |

## MITRE ATT&CK References

1. **[T1569.002](https://attack.mitre.org/techniques/T1569/002/)**: System Services: Service Execution - Relates to NetSupport services initiation and manipulation.
2. **[T1543.003](https://attack.mitre.org/techniques/T1543/003/)**: Create or Modify System Process: Windows Service - Associated with NetSupport services installation and modification.
3. **[T1059.001](https://attack.mitre.org/techniques/T1059/001/)**: Command and Scripting Interpreter: PowerShell - Execution of PowerShell scripts via NetSupport for administrative tasks or malicious activities.
4. **[T1070.004](https://attack.mitre.org/techniques/T1070/004/)**: Indicator Removal on Host: File Deletion - NetSupport logs deletion or tampering as an attempt to hide activities.
5. **[T1573.001](https://attack.mitre.org/techniques/T1573/001/)**: Encrypted Channel: Symmetric Cryptography - NetSupport's use of encrypted channels for remote management.


## Sigma Rules

- Sigma rules for detecting suspicious NetSupport activities, including unauthorized service changes or abnormal network traffic patterns.

[def]: (Link to your Sigma rules repository)
