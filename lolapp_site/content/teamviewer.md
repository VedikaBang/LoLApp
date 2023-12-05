---
title: "TeamViewer"
date: 2023-11-11
tags: ["Description", "IoCs", "TTPs", "Detection Rules"]
---

## TeamViewer

TeamViewer is a versatile remote access tool available on various platforms, used both legitimately and maliciously.

## App Artifacts

| IoC | Observations | DFIR Relevance |
|:----|:-------------|:---------------|
| `C:\Program Files\TeamViewer\` | Installation directory | Indicates TeamViewer's presence; check creation/modification dates for installation timeline. |
| `HKLM\SOFTWARE\TeamViewer\*` | Registry keys added during setup | Indicates installation of TeamViewer. |
| `HKU\<SID>\SOFTWARE\TeamViewer\*` | User-specific registry keys | Useful for identifying user-specific TeamViewer activities. |
| `C:\Program Files\TeamViewer\TeamViewer15_Logfile.log` | General log file | Logs connections with timestamps, hostnames, and TeamViewer IDs. |
| `C:\Program Files\TeamViewer\Connections_incoming.txt` | Connection log | Lists successful incoming connections with detailed info like TeamViewer ID and hostname. |
| Network Traffic | Communication with TeamViewer domains | Monitor traffic to domains like `router15.teamviewer.com:443`, `client.teamviewer.com:443`, and `taf.teamviewer.com:443`. |
| Executables | TeamViewer executable files | Check for `TeamViewer.exe`, `TeamViewer_Desktop.exe`, `TeamViewer_Service.exe`, `tv_w32.exe`, `tv_x64.exe`. |
| Prefetch Files | Execution evidence | `C:\Windows\Prefetch\TEAMVIEWER.EXE-[A-F0-9]{8}.pf` indicates execution of TeamViewer. |
| Startup Menu Entry | `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\TeamViewer.lnk` | Evidence of TeamViewer in startup items. |
| Mutexes/Sections/Events | Named mutexes like `TeamViewer_LogMutex` | Indicates running instances or activities of TeamViewer. |
| `%LOCALAPPDATA%\TeamViewer\Database\tvchatfilecache.db` | SQLite database | Stores TeamViewer chat cache. |
| `%LOCALAPPDATA%\TeamViewer\RemotePrinting\tvprint.db` | SQLite database (target side) | Stores TeamViewer print jobs. |
| Registry Keys (Client Side) | `HKLM\SOFTWARE\TeamViewer\ConnectionHistory` | Indicates client-side TeamViewer connections. |

## MITRE ATT&CK References

- [T1219](https://attack.mitre.org/versions/v13/techniques/T1219/): Remote Access Software
- [T1078](https://attack.mitre.org/versions/v13/techniques/T1078/): Valid Accounts
- [T1563.002](https://attack.mitre.org/versions/v13/techniques/T1563/002/): Remote Service Session Hijacking

## Sigma Rules

- Develop Sigma rules to detect unusual TeamViewer activities such as abnormal connection times, connections from atypical geographic locations, or unusual patterns in log entries.

[def]: (Link to your Sigma rules repository)
