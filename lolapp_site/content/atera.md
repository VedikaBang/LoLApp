---
title: "atera"
date: 2023-11-11
tags: ["Description", "IoCs", "TTPs", "Detection Rules"]
---

## AnyDesk

AnyDesk is a tool designed for remote access, enabling users to connect to computers remotely.

## App Artifacts

| IoC | Observations | DFIR Relevance &nbsp;&nbsp;&nbsp;&nbsp;|
|:----|:-------------|:---------------|
| `C:\ProgramData\AnyDesk\` | Direct installation location | Indicates a potential unauthorized persistent installation of AnyDesk, often a sign of compromise or insider threat. |
| `C:\Users\<username>\AppData\Roaming\AnyDesk\` | Portable executable location | Suggests the presence of AnyDesk on the user's profile, which could be used for remote access by attackers. |
| `C:\Users\<username>\Downloads\`<br>`C:\Users\<username>\Desktop\` | Likely scammer installation locations | Presence of AnyDesk in these directories may indicate non-standard installation methods, often associated with social engineering or scamming activities. |
| `GCAPI.DLL` in:<br>`C:\Users\<username>\AppData\Roaming\AnyDesk\`<br>`C:\Users\<username>\AppData\Local\Temp\` | DLL required for AnyDesk | The presence of `GCAPI.DLL` in the executable directory or temp folders suggests AnyDesk activity and potential unauthorized access. |
| `Connection_trace.txt` in:<br>`C:\ProgramData\AnyDesk\` | Log file for incoming requests | Provides timestamps and IDs for incoming connections, aiding in identifying unauthorized access attempts. |
| `user.conf` in:<br>`C:\ProgramData\AnyDesk\` | AnyDesk configuration file | Altered configurations may indicate attacker tampering, such as enabling file transfers for data exfiltration. |
| `ad.trace` in:<br>`C:\ProgramData\AnyDesk\` | Verbose log file for AnyDesk | Contains detailed AnyDesk session information, including potential attacker IP addresses. |
| `ad_scv.trace` in:<br>`C:\ProgramData\AnyDesk\` | Log file for the AnyDesk service | Generated after a forced reboot, could indicate unauthorized changes or attempts at maintaining persistence. |

## MITRE ATT&CK References

1. **[CVE-2021-44426](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44426)**: Security flaw in AnyDesk that could be exploited in an attack.
2. **[T1553.002](https://attack.mitre.org/versions/v13/techniques/T1553/002/)**: Subvert Trust Controls: Code Signing - Attackers might leverage legitimate AnyDesk software for malicious purposes.
3. **[T1570](https://attack.mitre.org/versions/v13/techniques/T1570/)**: Lateral Tool Transfer - AnyDesk could be used to move tools or payloads across a compromised network.
4. **[T1219](https://attack.mitre.org/versions/v13/techniques/T1219/)**: Remote Access Software - AnyDesk is a legitimate remote access tool that could be abused by attackers for command and control.

## Sigma Rules

(Include any relevant Sigma rules for detecting suspicious AnyDesk activity, formatted as Markdown links)

[def]: (Include the link to your Sigma rules repository)