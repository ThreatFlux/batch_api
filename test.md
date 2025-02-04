# Threat Model: Office Application Startup (T1137) in Microsoft 365 & Entra ID

## Overview
This threat model analyzes the various ways threat actors can abuse Microsoft Office application startup mechanisms for persistence, code execution, and defense evasion in Microsoft 365 and Entra ID environments. The model covers detection strategies using audit logs and provides example log entries for various attack scenarios.

## Attack Vectors

### 1. Office Template Macros (T1137.001)

#### Description
Adversaries abuse Office templates to maintain persistence by adding malicious macros that execute when a new document is created.

#### Attack Scenarios
- Global template modification (Normal.dotm)
- Workgroup template deployment
- Network startup locations compromise

#### Detection Fields
```json
{
  "Important Fields": {
    "Operation": ["FileModified", "FileAccessed"],
    "SourceFileName": ["*.dotm", "*.dotx", "*.xltx", "*.xltm"],
    "ClientIP": "string",
    "UserId": "string",
    "WorkloadName": "OneDrive",
    "ObjectId": "string",
    "TargetFilePath": "string"
  }
}
```

#### Example Audit Log
```json
{
  "CreationTime": "2025-01-30T15:22:33",
  "Id": "1234567890",
  "Operation": "FileModified",
  "OrganizationId": "0123456-0123-0123-0123-0123456789",
  "RecordType": 6,
  "UserKey": "i:0h.f|membership|user@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "OneDrive",
  "ClientIP": "192.168.1.100",
  "ObjectId": "https://contoso-my.sharepoint.com/personal/user_contoso_com/Documents/Normal.dotm",
  "UserId": "user@contoso.com",
  "SourceFileName": "Normal.dotm",
  "TargetFilePath": "/personal/user_contoso_com/Documents/"
}
```

### 2. Office Add-ins (T1137.002)

#### Description
Attackers deploy malicious Office add-ins for persistence and code execution.

#### Attack Scenarios
- COM add-in installation
- Office Store add-in compromise
- Sideloaded add-in deployment

#### Detection Fields
```json
{
  "Important Fields": {
    "Operation": [
      "Add-InActivated",
      "Add-InInstalled",
      "Add-InUninstalled"
    ],
    "ApplicationId": "string",
    "ClientAppId": "string",
    "UserId": "string",
    "AddinName": "string",
    "AddinVersion": "string"
  }
}
```

#### Example Audit Log
```json
{
  "CreationTime": "2025-01-30T16:45:12",
  "Operation": "Add-InInstalled",
  "ApplicationId": "efgh-5678-90ij-klmn",
  "ClientAppId": "abcd-1234-56ef-ghij",
  "UserId": "user@contoso.com",
  "AddinName": "SuspiciousAddin",
  "AddinVersion": "1.0.0",
  "ClientIP": "192.168.1.100",
  "DeviceName": "DESKTOP-ABC123",
  "ResultStatus": "Success"
}
```

### 3. Office Test (T1137.003)

#### Description
Adversaries abuse Office Test Registry key for persistence.

#### Attack Scenarios
- Registry key modification
- COM hijacking via test registry
- DLL injection through test locations

#### Detection Fields
```json
{
  "Important Fields": {
    "Operation": ["RegistryKeyModified", "ProcessCreated"],
    "RegistryKey": "string",
    "RegistryValueName": "string",
    "RegistryValueData": "string",
    "ProcessName": "string",
    "CommandLine": "string"
  }
}
```

#### Example Audit Log
```json
{
  "CreationTime": "2025-01-30T17:15:45",
  "Operation": "RegistryKeyModified",
  "DeviceName": "DESKTOP-ABC123",
  "RegistryKey": "HKEY_CURRENT_USER\\Software\\Microsoft\\Office Test\\Special\\Perf",
  "RegistryValueName": "PathToMaliciousDLL",
  "RegistryValueData": "C:\\Users\\Public\\malicious.dll",
  "InitiatingProcessAccountName": "user@contoso.com",
  "InitiatingProcessFileName": "WINWORD.EXE"
}
```

### 4. XLM Macros (T1137.004)

#### Description
Threat actors utilize legacy XLM macros for code execution and persistence.

#### Attack Scenarios
- Legacy macro injection
- Auto_Open macro implementation
- Worksheet-level macro execution

#### Detection Fields
```json
{
  "Important Fields": {
    "Operation": ["FileAccessed", "MacroEnabled", "MacroExecuted"],
    "SourceFileName": ["*.xls", "*.xlsm"],
    "MacroType": "string",
    "MacroName": "string",
    "WorksheetName": "string"
  }
}
```

#### Example Audit Log
```json
{
  "CreationTime": "2025-01-30T18:30:22",
  "Operation": "MacroExecuted",
  "SourceFileName": "Financial_Report.xlsm",
  "MacroType": "XLM",
  "MacroName": "Auto_Open",
  "WorksheetName": "Sheet1",
  "UserId": "user@contoso.com",
  "ClientIP": "192.168.1.100",
  "DeviceName": "DESKTOP-ABC123",
  "ResultStatus": "Success"
}
```

## Detection Strategies

### 1. Behavioral Analytics
- Monitor for unusual template modifications outside business hours
- Track frequency of add-in installations across users
- Analyze patterns of macro execution across departments

### 2. Baseline Deviations
- Document normal template usage patterns
- Establish add-in whitelists
- Monitor for unauthorized registry modifications

### 3. Correlation Rules
```sql
-- Example correlation rule for suspicious template modifications
SELECT *
FROM FileModification fm
JOIN UserActivity ua ON fm.UserId = ua.UserId
WHERE 
  fm.SourceFileName LIKE '%.dot%'
  AND ua.TimeOfDay NOT BETWEEN '09:00' AND '17:00'
  AND fm.ClientIP NOT IN (SELECT IP FROM TrustedIPList)
```

## Mitigation Strategies

1. Administrative Controls
- Implement strict add-in deployment policies
- Restrict template modification permissions
- Enable protected view for Office applications

2. Technical Controls
```json
{
  "Office365Settings": {
    "MacroExecution": "DisableWithoutNotification",
    "ProtectedView": "EnabledForAllFiles",
    "AddInDeployment": "RestrictToApprovedList"
  }
}
```

3. Monitoring Controls
- Enable detailed Office 365 audit logging
- Implement real-time alerting for suspicious modifications
- Deploy endpoint detection and response (EDR) solutions

## Incident Response Playbook

1. Initial Detection
- Identify affected users and systems
- Document timeline of events
- Preserve audit logs and forensic artifacts

2. Investigation Steps
```markdown
a. Template Analysis
- Hash comparison of modified templates
- Macro code review
- Creation/modification timestamp analysis

b. Add-in Investigation
- Publisher verification
- Permission scope review
- Network connection analysis

c. Registry Analysis
- Key modification history
- DLL verification
- Process lineage tracking
```

3. Containment Actions
- Disable affected add-ins
- Block suspicious templates
- Isolate compromised accounts

## References

1. MITRE ATT&CK
- T1137 - Office Application Startup
- T1137.001 - Office Template Macros
- T1137.002 - Office Add-ins
- T1137.003 - Office Test
- T1137.004 - XLM Macros

2. Microsoft Documentation
- Office 365 Security & Compliance Center
- Office Add-ins Platform Overview
- Microsoft 365 Defender Advanced Hunting Schema