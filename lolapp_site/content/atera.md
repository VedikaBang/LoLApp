---
title: "Atera"
date: 2023-11-11
tags: ["Description", "IoCs", "TTPs", "Detection Rules"]
---

## Atera

Atera is an all-in-one remote monitoring and management (RMM) tool primarily used by IT professionals and Managed Service Providers (MSPs). It offers features like remote access, IT automation, reporting, and patch management.

## App Artifacts
| IoC | Observations | DFIR Relevance |
|:----|:-------------|:---------------|
| `C:\Program Files\Atera Networks\AteraAgent\` | Default installation directory | Presence of Atera Agent indicates remote management capability. Could be exploited for unauthorized access or persistence. |
| `AteraAgent.exe` in `C:\Program Files\Atera Networks\AteraAgent\` | Main executable file | Execution patterns of `AteraAgent.exe` can indicate abnormal or unauthorized remote management activities. |
| `%AppData%\Atera Networks\AteraAgent\` | Configuration and log files | Configurations and logs stored here can reveal operational patterns and potentially unauthorized or malicious modifications. |
| `AteraAgentService.log` in `C:\Program Files\Atera Networks\AteraAgent\` | Log file for the Atera Agent Service | Logs service activities, errors, and network connections, essential for investigating remote operations and diagnostics. |
| Registry Key: `HKLM\SOFTWARE\Atera Networks\` | Registry entries for configurations | Modifications in this registry path may suggest configuration changes for persistence or unauthorized access. |
| Network traffic to `*.atera.com` | Atera server communications | Unusual traffic patterns to Atera domains could indicate misuse for command and control or data exfiltration activities. |
| File Transfer Directories: | | |
| `C:\Users\<username>\Downloads\Atera\` | Download location for Atera files | Files downloaded via Atera might be located here; could indicate data exfiltration or tool transfer. |
| `C:\Users\<username>\Documents\Atera\` | Default directory for file transfers | Unusual files or modifications in this directory might suggest unauthorized data movement. |
| Amcache and Shellbags | | |
| `Amcache.hve` entries related to Atera | Records execution of Atera-related executables | Can provide historical execution details even after file deletion, indicating Atera usage or abuse. |


## MITRE ATT&CK References

1. **[T1133](https://attack.mitre.org/versions/v13/techniques/T1133/)**: External Remote Services - Atera, as a remote service, can be misused for persistent access.
2. **[T1199](https://attack.mitre.org/versions/v13/techniques/T1199/)**: Trusted Relationship - Attackers may exploit MSPs’ trusted relationships via Atera.
3. **[T1219](https://attack.mitre.org/versions/v13/techniques/T1219/)**: Remote Access Software - While legitimate, Atera can be used by attackers for remote operations.
4. **[T1569.002](https://attack.mitre.org/versions/v13/techniques/T1569/002/)**: System Services: Service Execution - Unauthorized service execution of Atera Agent for persistence.

## Sigma Rules

- Sigma rules to be formulated for detecting anomalies in Atera usage, such as unusual activity patterns, unexpected installation on critical systems, or abnormal network communications.
