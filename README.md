# Wazuh Detection Engineering Lab

## Overview

This project documents a hands-on detection engineering and SOC analysis lab built using Wazuh, Sysmon, Windows Event Logging, PowerShell logging, and Active Directory.

The goal of this project was not only to generate security alerts, but to understand the telemetry behind them, create custom detections, test those detections for weaknesses, and tune them to improve coverage.

During the lab, I:

- Configured Windows endpoints to send security telemetry to Wazuh.
- Used Sysmon to monitor process activity.
- Enabled PowerShell Script Block Logging.
- Investigated Windows authentication and process-related alerts.
- Created custom Wazuh detection rules.
- Mapped detections to MITRE ATT&CK techniques.
- Tested detection rules against different execution methods.
- Identified and corrected detection gaps.
- Performed false-positive analysis and detection tuning.

## Lab Environment

| Component | Purpose |
|---|---|
| Wazuh | SIEM, log analysis, alerting, and threat hunting |
| Sysmon | Enhanced Windows endpoint telemetry |
| Windows 10 | Monitored endpoint |
| Windows Server | Active Directory Domain Controller |
| PowerShell | Administration and controlled activity generation |
| Proxmox | Virtualization platform |
| MITRE ATT&CK | Detection technique mapping |

## Project Objectives

The primary objectives were to:

1. Collect Windows security telemetry in Wazuh.
2. Investigate endpoint and authentication events.
3. Understand process relationships using Sysmon.
4. Develop custom behavioral detection rules.
5. Test detections for false negatives and bypasses.
6. Tune detections based on testing results.
7. Map detections to the MITRE ATT&CK framework.

## Custom Detections

Two primary custom detections were developed during the project.

### Rule 100102 — Windows Account Discovery

Detects account discovery performed using `net.exe` or `net1.exe`.

**MITRE ATT&CK:** T1087 — Account Discovery

Examples detected:

```text
net user
net.exe user
NET USER
net1.exe user
net user administrator

### Rule 100103 — Privileged Group Discovery

Detects enumeration of the local Administrators group using `net.exe` or `net1.exe`.

**MITRE ATT&CK:** T1069.001 — Permission Groups Discovery: Local Groups

Examples detected:

```text
net localgroup administrators
net.exe localgroup administrators
net1.exe localgroup administrators
NET LOCALGROUP ADMINISTRATORS
