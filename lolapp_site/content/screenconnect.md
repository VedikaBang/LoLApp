---
title: "screenconnect"
date: 2023-11-11
tags: ["Description", "IoCs", "TTPs", "Detection Rules"]
---

## ScreenConnect

ScreenConnect is a tool designed for remote access, support, and meeting solutions.

## App Artifacts

| IoC | Observations | DFIR Relevance &nbsp;&nbsp;&nbsp;&nbsp;|
|:----|:-------------|:---------------|
| Screenconnect service installed with a part of the name being randomly generated, such as “ScreenConnect Client (429d9ba6e9123fb4)” | `source=system.evtx EventCode=7045`<br>Message = "ScreenConnect Client (\*)" | Indicates potential unauthorized remote access software installation, often a sign of compromise or insider threat. |
| A service running as SYSTEM was also recorded in a 4573 event in the Security Log indicating Sensitive Privilege Use (SeTcbPrivilege) | `source=system.evtx EventCode=4573`<br>Message = "ScreenConnect" AND Message = "SeTcbPrivilege" | Reflects elevated privileges being used, potentially for malicious purposes, requiring investigation of service behavior. |
| `https://<username>.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest` | Review EDR/Sysmon commandlines, DNS events, and/or, Proxy Logs for URLs with a pattern like:<br>`http*.screenconnect.com/`<br>`Bin/ScreenConnect*.exe*` | Indicates downloading of remote access tools, which could be used for unauthorized access or data exfiltration. |
| `ScreenConnect.ClientService.exe` | Filename indicator useful for reviewing process execution events. | Signifies the execution of a ScreenConnect client service, essential to check for unauthorized remote control activities. |
| `ScreenConnect.WindowsClient.exe` | Filename indicator useful for reviewing process execution events. | Indicates running of ScreenConnect Windows client, important to verify for unsanctioned remote access. |
| Cloud Account Administrator Connected | `source=Application.evtx`<br>`EventCode=100`<br>`Source=ScreenConnect`<br>Message="Cloud Account Administrator Connected" | Suggests remote access by a cloud account administrator, crucial for validating authorized access vs. account takeover. |
| Cloud Account Administrator Disconnected | `source=Application.evtx`<br>`EventCode=101`<br>`Source=ScreenConnect`<br>Message="Cloud Account Administrator Disconnected" | Indicates disconnection of a cloud account admin, necessary for tracking session durations and potential unauthorized activities. |
| `C:\Users\<user>\Documents\ConnectWiseControl\Temp` | Execution of any PE from this directory indicates it was likely provided by the ScreenConnect host. | Execution from this directory could indicate malicious use of legitimate software for unauthorized actions. |
| `C:\Users\<user>\Documents\ConnectWiseControl\Files` | `source=Application.evtx`<br>`EventCode=201`<br>`Source=ScreenConnect`<br>Message="transfer" | File transfers via ScreenConnect could point to data exfiltration or unauthorized file access. |
| `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -File C:\WINDOWS\TEMP\ScreenConnect\23.4.5.8571\f5955c63-3955-4c4a-ba98-672d4d6291eerun.ps1` | `Source=Microsoft-Windows-Powershell-Operational`<br>`EventID 4103`<br>Message=\*ScreenConnect\*.ps1\* | Execution of PowerShell scripts related to ScreenConnect could indicate automation of malicious activities or unauthorized changes. |

## MITRE ATT&CK References

1. **[T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219)**: This technique involves the use of legitimate remote access software like ScreenConnect for command and control.
    - Related sub-techniques...
2. **[T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)**: General technique for execution of commands and scripts.
3. **[T1136 - Create Account](https://attack.mitre.org/techniques/T1136)**: Creating new user accounts for persistent access.
4. **[T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)**: If obfuscation was used in payloads.
5. **[T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003)**: For accessing credentials stored in the operating system.

## Sigma Rules

1. **Access to Suspicious ScreenConnect URL**: Monitoring for access to URLs matching the pattern of ScreenConnect can be crucial for early detection of unauthorized remote access attempts.
   - [Sigma Rule for IoC 1][def]

[def]: https://github.com/VedikaBang/LoLApp/blob/main/detection_rules/screenconnect/ioc1.yaml