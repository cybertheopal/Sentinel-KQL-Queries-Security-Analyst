# Security Analyst Workflow KQL Queries for Microsoft Sentinel (Real-World Example)

These are practical KQL queries used in real-world Microsoft Sentinel environments for detecting suspicious behavior, attacker TTPs, and system anomalies.  

---

1. Suspicious PowerShell Use

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "IEX", "DownloadString", "Bypass", "EncodedCommand")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName
```

> Detects PowerShell used to download and run suspicious scripts.

---

2. Failed RDP Login Attempts (Brute Force)

```kql
SecurityEvent
| where EventID == 4625
| where LogonType == 10
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 5
```

> Alerts on too many failed Remote Desktop logins in a short time window.

---

3. Lateral Movement (PsExec, WMIC, WinRM)

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("wmic.exe", "psexec.exe", "winrm.vbs")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName
```

> Identifies use of tools frequently abused for lateral movement.

---

4. New Local Admin Account Created

```kql
SecurityEvent
| where EventID == 4720
| join kind=inner (
    SecurityEvent
    | where EventID == 4732
    | where TargetUserName contains "Administrators"
) on TargetUserSid
| project TimeGenerated, TargetUserName, SubjectUserName, Computer
```

> Detects new user accounts added to the local Administrators group.

---

5. Connections to Known Malicious IPs

```kql
DeviceNetworkEvents
| where RemoteIP in ("185.232.52.1", "89.45.67.123") // Replace with known bad IPs
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```

> Matches outbound traffic against known threat intel IPs.

---
6. File Renames Suggesting Ransomware

```kql
DeviceFileEvents
| where ActionType == "FileRenamed"
| where FileName endswith ".locked" or FileName endswith ".enc"
| project Timestamp, DeviceName, PreviousFileName, FileName, InitiatingProcessFileName
```

> Watch for suspicious extensions like `.enc`, `.locked` — typical of ransomware.

---

7. Multiple Login Geolocations for Same User

```kql
SigninLogs
| summarize Locations = make_set(Location) by UserPrincipalName
| where array_length(Locations) > 3
```

> Detects accounts logging in from multiple regions in a short time frame.

---

