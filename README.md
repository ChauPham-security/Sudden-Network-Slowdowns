
<img width="1139" alt="Screenshot 2025-06-11 at 11 29 33 AM" src="https://github.com/user-attachments/assets/15087750-a637-4021-b16a-a69a536ef9bf" />


# 🐢 Sudden Network Slowdowns

This project investigates a sudden internal network performance issue impacting legacy systems in the `10.0.0.0/16` range. After ruling out external DDoS activity, I suspected internal lateral movement or resource abuse. This threat hunt outlines the discovery of suspicious PowerShell activity, evidence of port scanning, and the mitigation steps taken.

---

## 🧭 Scenario Overview

### 🎯 Goal
The server team detected significant slowdowns across several legacy devices. The security team was engaged to determine whether:
- Internal systems were being used for unauthorized activity (e.g., scanning, downloads).
- There were signs of lateral movement or compromised services.
- Resource exhaustion from internal traffic was causing the performance drop.

### 🧠 Hypothesis
Given open internal traffic policies and unrestricted use of scripting tools (e.g., PowerShell), I suspected unauthorized scanning or lateral movement could be degrading the network.

---

## 🛠️ Threat Hunting Process

### 1. Preparation
- Scope: Devices within `10.0.0.0/16`.
- Key questions:
  - Is an internal host generating excessive failed connections?
  - Is there evidence of script-based scanning?
  - Was this triggered by a scheduled task, malware, or misconfiguration?

### 2. Data Collection
- Gathered logs from:
  - `DeviceNetworkEvents`
  - `DeviceProcessEvents`
  - `DeviceFileEvents` *(if needed for context)*

### 3. Data Analysis

#### ❗ Detected Excessive Failed Connections from `pham-vm`

```kql
DeviceNetworkEvents
| where DeviceName == 'pham-vm'
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

- `pham-vm` exhibited high volumes of failed connections. This is unusual for its expected behavior.
  <img width="664" alt="Screenshot 2025-06-10 at 6 39 38 PM" src="https://github.com/user-attachments/assets/8c09d11d-7a3c-4030-bd2f-989395f99d36" />

  

#### 🔍 Port Scanning Behavior from IP `10.0.0.167`: After observing failed connection requests from a suspected host (10.0.0.167) in chronological order, I noticed a port scan was taking place due to the sequential order of the ports. There were several port scans being conducted. 

```kql
// Observe all failed connections for the IP in question.
let IPInQuestion = "10.0.0.167";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

- Log review showed **sequential ports being scanned**, a typical indicator of service enumeration.
  <img width="661" alt="Screenshot 2025-06-10 at 6 40 32 PM" src="https://github.com/user-attachments/assets/2420b917-8872-45fa-9ecb-56e63b0b1924" />


#### 🧪 PowerShell-Based Port Scan Detected: I pivoted to the DeviceProcessEvents table to see if we could see anything that was suspicious around the time the post scan started. Then I noticed a PowerShell script named ‘portscan.ps1’ launch at 2025-05-30T01:17:00.6671694Z

```kql
// Observe DeviceProcessEvents for the past 10 minutes of the unusual activity found
let VMName = "pham-vm";
let specificTime = datetime(2025-05-30T01:17:17.9961338Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

- A PowerShell script named `portscan.ps1` was executed at `2025-05-30T01:17:00Z`.
- This directly correlated with the network anomalies observed in prior steps.
  <img width="710" alt="Screenshot 2025-06-10 at 6 43 38 PM" src="https://github.com/user-attachments/assets/a2fd2950-8a44-4d7f-b114-48ff3e370f0a" />


---

## 🧪 Local Investigation

- I logged into `pham-vm` and confirmed presence of the script used for scanning.
- **Unexpected finding**: The scan was executed under the `SYSTEM` account.
- This behavior was **not configured by admins** and suggested unauthorized use of privileged execution.

---

## 🧹 Response & Containment

### 🛡️ Actions Taken
- Isolated `pham-vm` from the network.
- I conducted a malware scan. And no immediate threats were identified.
- As a precaution, I submitted a ticket to **reimage** the VM to restore integrity.
- I also flagged SYSTEM-level PowerShell activity as a high-severity IOC.
- Implemented broader monitoring for SYSTEM-triggered scripting across endpoints.
  

### ✅ Why Reimage?
- SYSTEM-level script execution could imply persistence or task hijacking.
- Clean scans do not always rule out advanced threat presence.
- Reimaging ensures any unauthorized services, scripts, or implants are removed.

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique ID | Description |
|--------|--------------|-------------|
| Discovery | **T1046** | **Network Service Discovery** — Port scan behavior from `pham-vm` |
| Execution | **T1059.001** | **PowerShell** — Script `portscan.ps1` used for enumeration |
| Persistence / Privilege Abuse | **T1078** | **Valid Accounts** — SYSTEM-level script execution |
| Discovery | **T1082** | **System Information Discovery** *(possible pre- or post-scan behavior)* |
| Execution | **T1569.002** | **System Services: Service Execution** *(suspected if a service triggered the script)* |

---

## 📘 Lessons Learned & Recommendations

### What We Learned
- Internal scanning activity can go unnoticed without strict PowerShell auditing.
- SYSTEM-level processes should be continuously validated for integrity.
- Even if a malware scan comes back clean, unusual use of high-level privileges still needs to be investigated.

### What We Improved
- Improved telemetry on internal failed connection patterns.
- Enabled a more limited version of PowerShell for non-admin users to help prevent misuse.
- Created detection rules for unexpected SYSTEM-originated scripting.

---

## ✅ Summary

While external threats were ruled out, I discovered **unauthorized PowerShell-based port scanning activity** initiated from within the network. The behavior was traced to a VM running a script as `SYSTEM` without proper approval. The system was isolated, analyzed, and reimaged to restore trust. I also set up alerting rules to detect when PowerShell scripts are run by `SYSTEM` accounts in the future.
