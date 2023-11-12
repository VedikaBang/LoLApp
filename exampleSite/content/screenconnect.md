---
title: "ScreenConnect"
date: 2023-11-11
tags: ["Description", "IoCs", "TTPs", "Detection Rules"]
---

ScreenConnect is a tool designed for remote access, support, and meeting solutions. 

### IoCs

|IoC | Observations |
|---|---|
| Screenconnect service installed with a part of the name being randomly generated: “ScreenConnect Client (429d9ba6e9123fb4)” | source=system.evtx EventCode=7045<br>Message = "*ScreenConnect Cient (*)" |
|---|---|
| The service running as SYSTEM was also recorded in a 4573 event in the Security Log indicating Sensitive Privilege Use (SeTcbPrivilege) | source=system.evtx EventCode=4573<br>Message = "*ScreenConnect*" AND Message = "*SeTcbPrivilege*" |
|---|---|
| `https://<username>.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest` | Review EDR/Sysmon commandlines, DNS events, and/or, Proxy Logs for URLs with pattern like:<br>http\*.screenconnect.com/<br>Bin/ScreenConnect\*.exe\* |
|---|---|
| ScreenConnect.ClientService.exe | Filename indicator for use in reviewing process execution events. |
|---|---|
| ScreenConnect.WindowsClient.exe | Filename indicator for use in reviewing process execution events. |
|---|---|
| Cloud Account Administrator Connected | source=Application.evtx<br>EventCode=100<br>Source=ScreenConnect<br>Message="*Cloud Account Administrator Connected*" |
|---|---|
| Cloud Account Administrator Disconnected | source=Application.evtx<br>EventCode=101<br>Source=ScreenConnect<br>Message="Cloud Account Administrator Disconnected" |
|---|---|
| C:\Users\REM\Documents\ConnectWiseControl\Temp | Execution of any PE from this directory indicates it was likely provided by the ScreenConnect host. |
|---|---|
| C:\Users\REM\Documents\ConnectWiseControl\Files | source=Application.evtx<br>EventCode=201<br>Source=ScreenConnect<br>Message="*transfer*" |
|---|---|
| powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -File C:\WINDOWS\TEMP\ScreenConnect\23.4.5.8571\f5955c63-3955-4c4a-ba98-672d4d6291eerun.ps1 | Source=Microsoft-Windows-Powershell-Operational<br>EventID 4103<br>Message=*screenConnect\*.ps1\* |



## Footnotes

Markdown supports footnotes. Here's an example:

Here is some text with a footnote[^1].

[^1]: This is the footnote content.

## Horizontal Rule

You can insert a horizontal rule to separate sections. Here's an example:

---

That's all for now. I hope you find these advanced Markdown features helpful!
