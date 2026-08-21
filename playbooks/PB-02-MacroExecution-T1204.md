# SOC Standard Operating Procedure & Playbook
## PB-02: Weaponized Office Document & Malicious Macro Execution (MITRE ATT&CK: T1204 / T1059)

| Metadata | Details |
| :--- | :--- |
| **Playbook ID** | PB-SEC-02 |
| **Target Tactics** | Initial Access (TA0001), Execution (TA0002), Defense Evasion (TA0005) |
| **Techniques** | T1204.002 (User Execution: Malicious File), T1059.001 (PowerShell), T1027 (Obfuscation) |
| **Relevant Telemetry** | Sysmon Event ID `1` (Process Create), Windows PowerShell Event `4104` (ScriptBlock) |
| **Author** | SOC Detection & IR Team |
| **Version** | 2.0 (Production) |

---

### Phase 1: Preparation
- Attack Surface Reduction (ASR) rule enabled: *Block all Office applications from creating child processes*.
- Enhanced ScriptBlock logging enabled in Active Directory Group Policy (GPO).
- Splunk alert configured for parent process `WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE` spawning `powershell.exe`, `cmd.exe`, `wscript.exe`.

---

### Phase 2: Identification & Initial Triage
1. **Analyze Process Hierarchy in Splunk / Sysmon**:
   - Inspect `ParentCommandLine` to locate the source `.docm`, `.xlsm`, or `.zip` file.
   - Inspect `CommandLine` for Base64 strings, `-WindowStyle Hidden`, `DownloadString`, or `IEX`.
2. **Examine PowerShell ScriptBlock (Event ID 4104)**:
   - Extract C2 domains, IP addresses, staging URLs (`http://<domain>/stage2.ps1`), and loaded DLL reflection methods (`[System.Reflection.Assembly]::Load`).
3. **Check Network Telemetry (Sysmon Event ID 3 / Zeek)**:
   - Determine if the spawned child process successfully completed an outbound HTTP/HTTPS handshake to an external IP.

---

### Phase 3: Containment
1. **Immediate Endpoint Isolation**: Place affected workstation into EDR containment.
2. **Network Perimeter Block**: Add resolved C2 IP addresses and staging domains to firewall and DNS sinkhole.
3. **Email Gateway Quarantine**: Search email gateway logs (Proofpoint / M365 Defender) for sender of attachment, subject, and hash; purge all matching emails across tenant.

---

### Phase 4: Eradication
1. Terminate malicious process tree (`Stop-Process -Id <PID>`).
2. Delete malicious dropped files from `%TEMP%`, `%APPDATA%`, and `Downloads` folder.
3. Check for persistence:
   - Run autoruns audit / scan registry Run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
   - Query scheduled tasks (`schtasks /query`).

---

### Phase 5: Recovery & Verification
1. Re-scan endpoint with updated EDR definitions.
2. Restore endpoint network connectivity.
3. Notify user and document phishing vector details.

---

### Phase 6: Post-Incident Activity
- Update Yara rules and EDR custom blocking rules with weaponized document hashes (SHA256).
- Provide threat intelligence briefing to security awareness training team for targeted phishing simulations.
