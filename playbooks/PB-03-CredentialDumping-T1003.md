# SOC Standard Operating Procedure & Playbook
## PB-03: LSASS Memory Access & Credential Dumping (MITRE ATT&CK: T1003.001)

| Metadata | Details |
| :--- | :--- |
| **Playbook ID** | PB-SEC-03 |
| **Target Tactics** | Credential Access (TA0006) |
| **Techniques** | T1003.001 (OS Credential Dumping: LSASS Memory) |
| **Relevant Telemetry** | Sysmon Event ID `10` (ProcessAccess), Sysmon Event ID `11` (FileCreate), Event ID `4673` (Privileged Service) |
| **Author** | SOC Detection & IR Team |
| **Version** | 2.0 (Production) |

---

### Phase 1: Preparation
- Enable Windows Defender Credential Guard (Virtualization-Based Security / VBS).
- Deploy Sysmon configuration monitoring `TargetImage = *lsass.exe` with access rights including `0x10` (VM_READ) and `0x1fffff` (ALL_ACCESS).
- Baseline authorized security agents (Defender, CrowdStrike, CarbonBlack, Tanium).

---

### Phase 2: Identification & Triage
1. **Analyze Source Process**:
   - What binary opened the handle to `lsass.exe`? Is it an unsigned binary (`procdump.exe`, `mimikatz.exe`, `dumpert.exe`, `rundll32.exe comsvcs.dll`)?
   - Check `CallTrace` in Sysmon Event 10: does the call origin trace back to suspicious temporary directories?
2. **Inspect File Creation (Sysmon Event ID 11)**:
   - Search for memory dump files created around the same timestamp (e.g., `*.dmp`, `lsass.dmp`, `temp.bin`) in `C:\Windows\Temp\` or `C:\Users\*\AppData\Local\Temp\`.
3. **Severity Assessment**:
   - **Critical (P1)**: Credential dumping attempt executed with High / SYSTEM integrity. Assume all credentials cached in memory on this machine are compromised.

---

### Phase 3: Immediate Containment
1. **Host Isolation**: Sever all network connections to host immediately via EDR to prevent lateral movement using harvested credentials.
2. **Account Revocation**:
   - Identify all domain accounts logged into the host within the last 7 days.
   - Initiate immediate password reset & session revocation for all identified accounts.
   - If Domain Admin or Tier-0 service account was cached on host, initiate emergency Kerberos Double-Reset procedure for `krbtgt`.

---

### Phase 4: Eradication
1. Terminate the source process PID and parent process.
2. Securely wipe the memory dump artifact files using DOD 5220.22-M sanitation methods or file deletion.
3. Review Active Directory logs for any lateral movement authentication originating from the source host.

---

### Phase 5: Recovery
1. Re-image compromised endpoint (recommended for P1 credential dump incidents to ensure rootkit/backdoor elimination).
2. Validate Credential Guard and LSA Protection (`RunAsPPL = 1`) are active in registry.
3. Release host back into production.

---

### Phase 6: Post-Incident Review
- Audit privileged user logon behavior across the fleet (enforce Tiered Administration Model to prevent Tier-0 admins from logging into Tier-2 workstations).
