# Log Clearing & Anti-Forensics — System Hacking Module Notes

**MITRE ATT&CK Reference:** [T1070 – Indicator Removal](https://attack.mitre.org/techniques/T1070/)
**Sub-techniques:** T1070.001 (Clear Windows Event Logs), T1070.002 (Clear Linux/Mac System Logs), T1070.003 (Clear Command History), T1070.004 (File Deletion), T1070.006 (Timestomp)

> Built for: Cybersecurity student career prep (CEH / OSCP / SOC Analyst track)
> Covers: attacker technique + **defender detection** (the part most tutorials skip, and the part interviewers actually ask about)

---

## 1. What is Log Clearing?

Attackers erase or manipulate system and application logs to remove evidence of their activity after gaining access or escalating privileges. Logs record logins, executed commands, system changes, and errors — clearing/tampering with them helps an attacker stay undetected and defeat forensic analysis.

**Why it matters:**
- Logs are the **first place** a security analyst / incident responder checks after an incident.
- Clean logs = hard to trace attacker origin, timeline, or scope (a.k.a. "covering tracks").
- It's a standard **post-exploitation** step, tested in CEH's "Covering Tracks" module and in OSCP privilege escalation labs.

**Where logs live:**

| OS | Log Locations |
|---|---|
| **Windows** | Event Viewer: `Security`, `System`, `Application` logs (`%SystemRoot%\System32\winevt\Logs\*.evtx`) |
| **Linux** | `/var/log/auth.log`, `/var/log/syslog`, `/var/log/messages`, shell history (`~/.bash_history`) |
| **Android** | `logcat` buffers (require root to clear) |

---

## 2. Attacker Techniques by OS

| OS | Common Technique |
|---|---|
| **Windows** | `wevtutil` commands, PowerShell scripts, or third-party tools to clear event logs. Example: `wevtutil cl Security` clears the Security log. |
| **Linux** | Manually deleting/truncating log files, clearing bash history, commands like `echo "" > /var/log/auth.log`. Also modifying timestamps ("timestomping"). |
| **Android** | Clearing logs via root access, e.g. `logcat -c`. |

### 2.1 Windows — `wevtutil`

`wevtutil.exe` is a built-in Windows CLI tool to query, export, archive, and clear event logs. Options are **not case-sensitive**. Introduced in Windows Vista.

```cmd
:: Clear all events from the Application log
wevtutil cl Application

:: Clear the Security log
wevtutil cl Security

:: List all log names + config (size, enabled, path)
wevtutil el

:: Get log configuration
wevtutil gl <LogName>

:: Query the most recent shutdown event (Event ID 1074) from System log
wevtutil query-events system "/q:*[System [(EventID=1074)]]" /rd:true

:: Export a log before clearing (forensics-safe / defender use)
wevtutil epl System C:\backup\system_backup.evtx
```

- PowerShell equivalent (more flexible): `Get-WinEvent`, `Clear-EventLog`, `Remove-EventLog`
- GUI equivalent: Event Viewer → right-click log → **Clear Log** → prompts "You can save the contents of this log before clearing it" (Save and Clear / Clear / Cancel)
- Full command reference: https://ss64.com/nt/wevtutil.html

**⚠️ Key detection gap attackers forget:** clearing the Security log with `wevtutil cl Security` **itself generates Event ID 1102** ("The audit log was cleared"). Clearing logs is *not* invisible — see Section 3.

### 2.2 Linux — manual log manipulation

```bash
# Truncate a specific log to zero bytes (keeps file, removes content)
sudo truncate -s 0 /var/log/auth.log

# Truncate ALL logs in /var/log at once (very noisy, very obvious)
sudo truncate -s 0 /var/log/*.log

# Overwrite a log with empty content
echo "" > /var/log/auth.log

# Clear current shell's command history
history -c        # clear in-memory history
history -w         # write (empty) history to disk
rm ~/.bash_history # delete history file directly

# Timestomping — modify file timestamps to blend in with legitimate files
touch -r /etc/hostname /var/log/auth.log   # match another file's mtime
```

- `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` — binary login/logout records, need special tools (`utmpdump`, `wtmpclean`) to selectively edit rather than wipe (wiping entirely is a huge red flag).
- Selectively deleting specific lines (rather than truncating the whole file) is a more advanced/harder-to-detect technique — e.g. `sed -i '/192.168.1.50/d' /var/log/auth.log` to remove lines referencing an attacker's IP.

### 2.3 Known tooling (awareness only)

- **ClearLogs** (SourceForge, Windows, last updated 2015) — legacy AV/forensics-evasion tool that wraps `wevtutil`-style clearing. Good to know it exists and what its signature looks like for detection engineering, not something to run against systems you don't own.
- Metasploit's `clearev` post-exploitation module (Meterpreter) — clears Application, System, and Security event logs on a compromised Windows host in one command. Reference: https://github.com/rapid7/metasploit-framework (search `clearev` in `modules/post/windows/manage/`)

---

## 3. Blue Team / Detection — the half most tutorials skip

This is the section that actually matters for a SOC/detection-engineering role, and for OSCP report write-ups on "detection & remediation."

### 3.1 Detect Windows log clearing

| Event ID | Meaning |
|---|---|
| **1102** | Security audit log was cleared |
| **104** | System log was cleared (System log source: Eventlog) |
| **1100** | Event logging service has shut down (can precede tampering) |

```powershell
# Query for log-clear events specifically
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102}
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104}
```

Best practice: **forward logs off-box in real time** (Windows Event Forwarding, Sysmon + a SIEM) so a local `wevtutil cl` can't destroy evidence that's already shipped elsewhere.

### 3.2 Detect Linux log tampering

- Monitor file integrity on `/var/log/*` with **auditd** rules or **AIDE / Tripwire**.
- Watch for `history -c`, `truncate`, `> /var/log/...` command patterns via **auditd** execve logging or shell logging (`script`, `auditd`, or a SIEM agent like Wazuh/OSSEC).
- Centralize logs via `rsyslog`/`syslog-ng` forwarding to a remote log collector — local tampering can't touch what's already off-host.
- Immutable log files: `chattr +a /var/log/auth.log` (append-only) makes truncation fail even as root, unless the attacker also removes the immutable flag (which is itself loggable/detectable).

### 3.3 SIEM / correlation concept

A **SIEM** (Security Information and Event Management — e.g. Splunk, Elastic/ELK, Wazuh) centralizes logs from many hosts so local log clearing on one machine doesn't erase the trail.

**Main SIEM features:** Threat detection · Investigation · Time to respond
**Additional features:** Basic security monitoring · Advanced threat detection · Forensics & incident response · Log collection · Normalisation · Notifications and alerts · Security incident detection · Threat response workflow

Reference: TryHackMe room *Windows Event Logs* — https://tryhackme.com/room/windowseventlogs (good hands-on lab for this exact topic)

---

## 4. GitHub Resources Worth Bookmarking

| Purpose | Link |
|---|---|
| MITRE ATT&CK technique data (T1070) — machine-readable, use for detection rule mapping | https://github.com/mitre-attack/attack-stix-data |
| Sigma — generic SIEM detection rules, includes rules for "Security Log Cleared" (Event 1102) and similar | https://github.com/SigmaHQ/sigma |
| Sysmon config (Swift On Security's well-known baseline) for better Windows telemetry before an attacker can wipe it | https://github.com/SwiftOnSecurity/sysmon-config |
| auditd rule sets incl. log-tampering detection (Neo23x0 / Florian Roth) | https://github.com/Neo23x0/auditd |
| Metasploit Framework (source for `clearev` and other post-exploitation modules — read-only study) | https://github.com/rapid7/metasploit-framework |
| LOLBAS — living-off-the-land Windows binaries (wevtutil is documented here) | https://github.com/LOLBAS-Project/LOLBAS |
| GTFOBins — Linux equivalent, useful for understanding privileged log manipulation via built-ins | https://github.com/GTFOBins/GTFOBins.github.io |
| Awesome Incident Response — curated list of IR/forensics tooling | https://github.com/meirwah/awesome-incident-response |
| Awesome Forensics — broader DFIR resource list | https://github.com/cugu/awesome-forensics |

---

## 5. Quick Reference Cheat Sheet

```text
WINDOWS
  wevtutil el                          # list all logs
  wevtutil cl <LogName>                # clear a log
  wevtutil epl <LogName> <path.evtx>   # export/backup before clearing
  Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102}   # detect clearing

LINUX
  sudo truncate -s 0 /var/log/auth.log # wipe a log's contents
  history -c && history -w             # clear shell history (memory + disk)
  chattr +a /var/log/auth.log          # defender: make log append-only

ANDROID
  logcat -c                            # clear logcat buffer (needs root)
```

---

## 6. Study / Practice Path

1. **TryHackMe** – *Windows Event Logs* room (hands-on, free): https://tryhackme.com/room/windowseventlogs
2. **TryHackMe** – *Windows Threat Hunting* module (paired room referenced in the tutorial)
3. Build a home lab: Kali attacker VM + Windows Server target → clear a log with `wevtutil`, then find Event ID 1102 in a forwarded copy of the log to prove detection works.
4. Repeat on a Linux VM: truncate `/var/log/auth.log`, then detect it via `auditd` watch rule.
5. Map every technique you practice back to its **MITRE ATT&CK ID** in your own notes — this is exactly how real detection engineering docs and OSCP reports are structured.

---

### Ethical & Legal Note
All of the above is standard, publicly documented pentesting/blue-team curriculum content (CEH, OSCP, TryHackMe, MITRE ATT&CK). Only practice log clearing / tampering on systems you own or are explicitly authorized to test — doing this on systems without authorization is illegal (Computer Fraud and Abuse Act in the US, IT Act 2000 in India, and equivalent laws elsewhere).
