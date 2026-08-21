# SOC Standard Operating Procedure & Playbook
## PB-01: Authentication Brute-Force & Password Spraying (MITRE ATT&CK: T1110)

| Metadata | Details |
| :--- | :--- |
| **Playbook ID** | PB-SEC-01 |
| **Target Tactics** | Credential Access (TA0006) |
| **Techniques** | T1110.001 (Password Guessing), T1110.003 (Password Spraying), T1078 (Valid Accounts) |
| **Relevant Telemetry** | Windows Security Event IDs `4625` (Failed Logon), `4624` (Successful Logon), `4740` (Account Lockout) |
| **Author** | SOC Detection & IR Team |
| **Version** | 2.1 (Production) |

---

### Phase 1: Preparation
- **Logging Baseline**: Ensure Windows Advanced Audit Policy has *Audit Logon* enabled for Success and Failure across all Domain Controllers and critical Tier-0/1 servers.
- **Threshold Tuning**: Splunk correlation search active: `>= 10` failed attempts within 60 seconds from external/internal IP.
- **Whitelists**: Maintain `known_admin_service_accounts.csv` to suppress scheduled task password expirations.

---

### Phase 2: Identification & Triage
1. **Validate True vs. False Positive**:
   - Check `WorkstationName` and `IpAddress`. Is it an internal scan host (e.g. Tenable/Nessus) or an external IP via VPN / OWA?
   - Check `TargetUserName`. Is it a single user targeted sequentially (Brute Force) or 50+ distinct usernames with 1-2 attempts each (Password Spraying)?
   - Query Splunk for subsequent Event ID 4624 (Logon Type 3 or 10) from the same IP within 15 minutes of failed attempts.
2. **Severity Classification**:
   - **Low**: Isolated internal failure from an employee workstation with SubStatus `0xC000006A` (bad password typo).
   - **Medium**: External brute force (>20 attempts) targeting disabled or non-existent accounts (`0xC0000064`).
   - **Critical / High**: Multiple failed attempts followed by an Event ID 4624 (compromised account) or targeting Tier-0 Domain Admins.

---

### Phase 3: Containment
1. If account is actively being sprayed:
   - Temporarily disable the targeted Active Directory user account or enforce an immediate Kerberos ticket reset (`krbtgt`).
2. If source IP is external:
   - Submit an automated firewall block rule via Perimeter Firewall (Palo Alto / Fortinet / AWS WAF) for the offending IP address.
3. If source is an internal compromised host:
   - Isolate endpoint via EDR (CrowdStrike / Defender for Endpoint / SentinelOne).

---

### Phase 4: Eradication
1. Force password change with high-entropy requirements and revoke all active Refresh Tokens in Azure AD / Okta.
2. Verify no persistence was established (audit new scheduled tasks `Event 4698`, new service creations `Event 7045`, or added Domain Admins `Event 4728`).

---

### Phase 5: Recovery
1. Re-enable user account after out-of-band verification with the employee via phone/manager.
2. Remove EDR network isolation following clean full-disk scan.
3. Monitor user logon events for 48 hours.

---

### Phase 6: Lessons Learned & Metrics
- Calculate Mean Time to Detect (MTTD) and Mean Time to Remediate (MTTR).
- Update IP Threat Intelligence blocklists and adjust Splunk correlation search thresholds if novel evasion patterns were noted.
