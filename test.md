# Microsoft 365 & Entra ID Threat Models

This document contains detailed threat models for specific MITRE ATT&CK techniques relevant to Microsoft 365 and Entra ID environments.

Each model includes:
- Detailed attack vectors with example audit logs
- SQL-based detection strategies
- JSON-formatted technical controls
- Specific incident response playbooks
- Relevant references and documentation

## Table of Contents

- [Password Guessing (T1110.001) in Microsoft 365 & Entra ID](#password-guessing-t1110001-in-microsoft-365-&-entra-id)
- [SharePoint (T1213.002) in Microsoft 365 & Entra ID](#sharepoint-t1213002-in-microsoft-365-&-entra-id)
- [Email Hiding Rules (T1564.008) in Microsoft 365 & Entra ID](#email-hiding-rules-t1564008-in-microsoft-365-&-entra-id)
- [Steal Web Session Cookie (T1539) in Microsoft 365 & Entra ID](#steal-web-session-cookie-t1539-in-microsoft-365-&-entra-id)
- [Permission Groups Discovery (T1069) in Microsoft 365 & Entra ID](#permission-groups-discovery-t1069-in-microsoft-365-&-entra-id)
- [Email Collection (T1114) in Microsoft 365 & Entra ID](#email-collection-t1114-in-microsoft-365-&-entra-id)
- [Cloud Groups (T1069.003) in Microsoft 365 & Entra ID](#cloud-groups-t1069003-in-microsoft-365-&-entra-id)
- [Password Cracking (T1110.002) in Microsoft 365 & Entra ID](#password-cracking-t1110002-in-microsoft-365-&-entra-id)
- [SAML Token Abuse (T1606.002) in Microsoft 365 & Entra ID](#saml-token-abuse-t1606002-in-microsoft-365-&-entra-id)
- [Hide Artifacts (T1564) in Microsoft 365 & Entra ID](#hide-artifacts-t1564-in-microsoft-365-&-entra-id)
- [Taint Shared Content (T1080) in Microsoft 365 & Entra ID](#taint-shared-content-t1080-in-microsoft-365-&-entra-id)
- [Spearphishing Link (T1566.002) in Microsoft 365 & Entra ID](#spearphishing-link-t1566002-in-microsoft-365-&-entra-id)
- [Office Application Startup (T1137) in Microsoft 365 & Entra ID](#office-application-startup-t1137-in-microsoft-365-&-entra-id)
- [Additional Cloud Roles (T1098.003) in Microsoft 365 & Entra ID](#additional-cloud-roles-t1098003-in-microsoft-365-&-entra-id)
- [Automated Collection (T1119) in Microsoft 365 & Entra ID](#automated-collection-t1119-in-microsoft-365-&-entra-id)
- [Data from Cloud Storage (T1530) in Microsoft 365 & Entra ID](#data-from-cloud-storage-t1530-in-microsoft-365-&-entra-id)
- [Add-ins (T1137.006) in Microsoft 365 & Entra ID](#add-ins-t1137006-in-microsoft-365-&-entra-id)
- [Outlook Rules (T1137.005) in Microsoft 365 & Entra ID](#outlook-rules-t1137005-in-microsoft-365-&-entra-id)
- [Impair Defenses (T1562) in Microsoft 365 & Entra ID](#impair-defenses-t1562-in-microsoft-365-&-entra-id)
- [Exfiltration Over Web Service (T1567) in Microsoft 365 & Entra ID](#exfiltration-over-web-service-t1567-in-microsoft-365-&-entra-id)
- [Unsecured Credentials (T1552) in Microsoft 365 & Entra ID](#unsecured-credentials-t1552-in-microsoft-365-&-entra-id)
- [Clear Mailbox Data (T1070.008) in Microsoft 365 & Entra ID](#clear-mailbox-data-t1070008-in-microsoft-365-&-entra-id)
- [Exfiltration Over Webhook (T1567.004) in Microsoft 365 & Entra ID](#exfiltration-over-webhook-t1567004-in-microsoft-365-&-entra-id)
- [Email Account Discovery (T1087.003) in Microsoft 365 & Entra ID](#email-account-discovery-t1087003-in-microsoft-365-&-entra-id)
- [Use Alternate Authentication Material (T1550) in Microsoft 365 & Entra ID](#use-alternate-authentication-material-t1550-in-microsoft-365-&-entra-id)
- [Hybrid Identity (T1556.007) in Microsoft 365 & Entra ID](#hybrid-identity-t1556007-in-microsoft-365-&-entra-id)
- [Cloud API (T1059.009) in Microsoft 365 & Entra ID](#cloud-api-t1059009-in-microsoft-365-&-entra-id)
- [Default Accounts (T1078.001) in Microsoft 365 & Entra ID](#default-accounts-t1078001-in-microsoft-365-&-entra-id)
- [Abuse Elevation Control Mechanism (T1548) in Microsoft 365 & Entra ID](#abuse-elevation-control-mechanism-t1548-in-microsoft-365-&-entra-id)
- [Password Spraying (T1110.003) in Microsoft 365 & Entra ID](#password-spraying-t1110003-in-microsoft-365-&-entra-id)
- [Temporary Elevated Cloud Access (T1548.005) in Microsoft 365 & Entra ID](#temporary-elevated-cloud-access-t1548005-in-microsoft-365-&-entra-id)
- [Account Discovery (T1087) in Microsoft 365 & Entra ID](#account-discovery-t1087-in-microsoft-365-&-entra-id)
- [Command and Scripting Interpreter (T1059) in Microsoft 365 & Entra ID](#command-and-scripting-interpreter-t1059-in-microsoft-365-&-entra-id)
- [Indicator Removal (T1070) in Microsoft 365 & Entra ID](#indicator-removal-t1070-in-microsoft-365-&-entra-id)
- [Office Template Macros (T1137.001) in Microsoft 365 & Entra ID](#office-template-macros-t1137001-in-microsoft-365-&-entra-id)
- [Email Forwarding Rule (T1114.003) in Microsoft 365 & Entra ID](#email-forwarding-rule-t1114003-in-microsoft-365-&-entra-id)
- [Financial Theft (T1657) in Microsoft 365 & Entra ID](#financial-theft-t1657-in-microsoft-365-&-entra-id)
- [Cloud Services (T1021.007) in Microsoft 365 & Entra ID](#cloud-services-t1021007-in-microsoft-365-&-entra-id)
- [Steal Application Access Token (T1528) in Microsoft 365 & Entra ID](#steal-application-access-token-t1528-in-microsoft-365-&-entra-id)
- [Cloud Account Discovery (T1087.004) in Microsoft 365 & Entra ID](#cloud-account-discovery-t1087004-in-microsoft-365-&-entra-id)
- [Forge Web Credentials (T1606) in Microsoft 365 & Entra ID](#forge-web-credentials-t1606-in-microsoft-365-&-entra-id)
- [Multi-Factor Authentication Request Generation (T1621) in Microsoft 365 & Entra ID](#multi-factor-authentication-request-generation-t1621-in-microsoft-365-&-entra-id)
- [Chat Messages (T1552.008) in Microsoft 365 & Entra ID](#chat-messages-t1552008-in-microsoft-365-&-entra-id)
- [Internal Spearphishing (T1534) in Microsoft 365 & Entra ID](#internal-spearphishing-t1534-in-microsoft-365-&-entra-id)
- [Trusted Relationship (T1199) in Microsoft 365 & Entra ID](#trusted-relationship-t1199-in-microsoft-365-&-entra-id)
- [Cloud Account (T1136.003) in Microsoft 365 & Entra ID](#cloud-account-t1136003-in-microsoft-365-&-entra-id)
- [Account Manipulation (T1098) in Microsoft 365 & Entra ID](#account-manipulation-t1098-in-microsoft-365-&-entra-id)
- [Exfiltration Over Alternative Protocol (T1048) in Microsoft 365 & Entra ID](#exfiltration-over-alternative-protocol-t1048-in-microsoft-365-&-entra-id)
- [Phishing (T1566) in Microsoft 365 & Entra ID](#phishing-t1566-in-microsoft-365-&-entra-id)
- [Brute Force (T1110) in Microsoft 365 & Entra ID](#brute-force-t1110-in-microsoft-365-&-entra-id)
- [Outlook Forms (T1137.003) in Microsoft 365 & Entra ID](#outlook-forms-t1137003-in-microsoft-365-&-entra-id)
- [Valid Accounts (T1078) in Microsoft 365 & Entra ID](#valid-accounts-t1078-in-microsoft-365-&-entra-id)
- [Account Access Removal (T1531) in Microsoft 365 & Entra ID](#account-access-removal-t1531-in-microsoft-365-&-entra-id)
- [Credential Stuffing (T1110.004) in Microsoft 365 & Entra ID](#credential-stuffing-t1110004-in-microsoft-365-&-entra-id)
- [Multi-Factor Authentication (T1556.006) in Microsoft 365 & Entra ID](#multi-factor-authentication-t1556006-in-microsoft-365-&-entra-id)
- [Remote Email Collection (T1114.002) in Microsoft 365 & Entra ID](#remote-email-collection-t1114002-in-microsoft-365-&-entra-id)
- [Password Policy Discovery (T1201) in Microsoft 365 & Entra ID](#password-policy-discovery-t1201-in-microsoft-365-&-entra-id)
- [Event Triggered Execution (T1546) in Microsoft 365 & Entra ID](#event-triggered-execution-t1546-in-microsoft-365-&-entra-id)
- [Outlook Home Page (T1137.004) in Microsoft 365 & Entra ID](#outlook-home-page-t1137004-in-microsoft-365-&-entra-id)
- [Web Session Cookie (T1550.004) in Microsoft 365 & Entra ID](#web-session-cookie-t1550004-in-microsoft-365-&-entra-id)
- [Impersonation (T1656) in Microsoft 365 & Entra ID](#impersonation-t1656-in-microsoft-365-&-entra-id)
- [Disable or Modify Cloud Logs (T1562.008) in Microsoft 365 & Entra ID](#disable-or-modify-cloud-logs-t1562008-in-microsoft-365-&-entra-id)
- [Data from Information Repositories (T1213) in Microsoft 365 & Entra ID](#data-from-information-repositories-t1213-in-microsoft-365-&-entra-id)
- [Masquerade Account Name (T1036.010) in Microsoft 365 & Entra ID](#masquerade-account-name-t1036010-in-microsoft-365-&-entra-id)
- [Transfer Data to Cloud Account (T1537) in Microsoft 365 & Entra ID](#transfer-data-to-cloud-account-t1537-in-microsoft-365-&-entra-id)
- [Create Account (T1136) in Microsoft 365 & Entra ID](#create-account-t1136-in-microsoft-365-&-entra-id)
- [Cloud Service Discovery (T1526) in Microsoft 365 & Entra ID](#cloud-service-discovery-t1526-in-microsoft-365-&-entra-id)
- [Cloud Service Dashboard (T1538) in Microsoft 365 & Entra ID](#cloud-service-dashboard-t1538-in-microsoft-365-&-entra-id)
- [Additional Email Delegate Permissions (T1098.002) in Microsoft 365 & Entra ID](#additional-email-delegate-permissions-t1098002-in-microsoft-365-&-entra-id)
- [Serverless Execution (T1648) in Microsoft 365 & Entra ID](#serverless-execution-t1648-in-microsoft-365-&-entra-id)
- [Office Test (T1137.002) in Microsoft 365 & Entra ID](#office-test-t1137002-in-microsoft-365-&-entra-id)
- [Application Access Token (T1550.001) in Microsoft 365 & Entra ID](#application-access-token-t1550001-in-microsoft-365-&-entra-id)
- [Cloud Accounts (T1078.004) in Microsoft 365 & Entra ID](#cloud-accounts-t1078004-in-microsoft-365-&-entra-id)
- [Modify Authentication Process (T1556) in Microsoft 365 & Entra ID](#modify-authentication-process-t1556-in-microsoft-365-&-entra-id)
- [Messaging Applications (T1213.005) in Microsoft 365 & Entra ID](#messaging-applications-t1213005-in-microsoft-365-&-entra-id)

---

# Threat Model: Password Guessing (T1110.001) in Microsoft 365 & Entra ID

## 1. Overview
Password guessing attacks against Microsoft 365 and Entra ID involve systematically attempting to authenticate with common or predicted passwords against known usernames. This typically targets:
- Azure Portal sign-ins 
- Office 365 web portal access
- Exchange Online/ActiveSync endpoints
- SharePoint Online access points

## 2. Attack Vectors

### Vector 1: Office 365 Portal Authentication
**Description**: Adversaries attempt to authenticate to Office 365 web portals using automated tools and password lists.

**Detection Fields**:
```json
{
  "CreationTime": "timestamp",
  "UserId": "target@domain.com", 
  "Operation": "UserLoggedIn",
  "ResultStatus": "Failed",
  "ClientIP": "source_ip",
  "UserAgent": "user_agent_string",
  "LogonError": "InvalidPassword"
}
```

**Example Log Pattern**:
```json
{
  "CreationTime": "2024-01-20T14:22:31",
  "UserId": "john.smith@company.com",
  "Operation": "UserLoggedIn", 
  "ResultStatus": "Failed",
  "ClientIP": "45.76.123.45",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "LogonError": "InvalidPassword",
  "WorkloadId": "Office365Portal",
  "FailureCount": "1"
}
```

### Vector 2: Exchange ActiveSync Authentication 
**Description**: Targeting mobile device email access through Exchange ActiveSync protocol.

**Detection Fields**:
```json
{
  "CreationTime": "timestamp",
  "Operation": "MailboxLogin",
  "ClientInfoString": "Protocol=ActiveSync",
  "ResultStatus": "Failed",
  "ClientIP": "source_ip",
  "UserId": "target@domain.com"
}
```

### Vector 3: SharePoint Online Authentication
**Description**: Password guessing against SharePoint Online site collections.

**Detection Fields**:
```json
{
  "CreationTime": "timestamp",
  "Operation": "FileAccessed",
  "ResultStatus": "Failed", 
  "UserId": "target@domain.com",
  "Workload": "SharePoint",
  "AuthenticationMethod": "Basic"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect rapid failed login attempts
SELECT UserId, ClientIP, COUNT(*) as FailureCount
FROM UAL 
WHERE Operation = 'UserLoggedIn'
AND ResultStatus = 'Failed'
AND TimeGenerated > ago(10m)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 10

-- Detect password spraying pattern
SELECT ClientIP, COUNT(DISTINCT UserId) as TargetCount
FROM UAL
WHERE Operation IN ('UserLoggedIn', 'MailboxLogin')
AND ResultStatus = 'Failed'
AND TimeGenerated > ago(1h)
GROUP BY ClientIP
HAVING COUNT(DISTINCT UserId) > 20
```

### Baseline Deviation Monitoring
- Establish normal failed login rates per user/IP
- Alert on deviations > 2 standard deviations
- Track time-of-day patterns for authentication attempts

## 4. Mitigation Controls

### Technical Controls
```json
{
  "conditionalAccess": {
    "signInFrequency": {
      "type": "hours",
      "value": 4,
      "isPersistent": false
    },
    "blockHighRiskSignIns": true,
    "requireCompliantDevice": true
  },
  "passwordPolicy": {
    "minimumLength": 12,
    "requireComplexity": true,
    "preventPasswordReuse": 24
  },
  "smartLockout": {
    "threshold": 5,
    "lockoutDuration": "PT1H"
  }
}
```

### Administrative Controls
1. Enable Modern Authentication
2. Configure Smart Lockout
3. Implement Conditional Access policies
4. Enable Identity Protection
5. Configure risk-based authentication

### Monitoring Controls
1. Enable Azure AD sign-in logs
2. Configure alerts for suspicious sign-in patterns
3. Monitor Identity Protection risk detections
4. Enable Azure AD auditing

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected accounts
2. Analyze login patterns and source IPs
3. Determine authentication protocols used
4. Review Identity Protection alerts

### Investigation
1. Extract relevant audit logs
2. Build timeline of attempts
3. Identify potentially compromised accounts
4. Review MFA status of targeted accounts

### Containment
1. Reset passwords for compromised accounts
2. Enable MFA where missing
3. Block suspicious IPs
4. Implement additional Conditional Access policies

## 6. References
- MITRE: https://attack.mitre.org/techniques/T1110/001/
- Microsoft: https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/
- Azure AD Smart Lockout: https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-password-smart-lockout

---

# Threat Model: SharePoint (T1213.002) in Microsoft 365 & Entra ID

## 1. Overview
Adversaries leverage SharePoint Online to mine valuable information about an organization's infrastructure, credentials, and operations. This technique specifically targets sensitive documents and data stored in SharePoint sites that could enable further attack activities.

## 2. Attack Vectors

### 2.1 Bulk Document Access
**Description**: Adversary uses compromised credentials to perform mass downloads or access of SharePoint documents.

**Audit Operations**:
- FileDownloaded
- FileAccessed
- SearchQueryPerformed

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "ea4c722a-1832-4cde-ad87-9b4de09f787d",
  "Operation": "FileDownloaded",
  "OrganizationId": "c7f2f34a-1234-5678-90ab-cdef12345678",
  "RecordType": 4,
  "UserKey": "i:0h.f|membership|bob@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "SharePoint",
  "ObjectId": "https://contoso.sharepoint.com/sites/Engineering/Shared Documents/Network Diagrams/infrastructure.vsdx",
  "UserId": "bob@contoso.com",
  "ClientIP": "192.168.1.100",
  "ItemType": "File",
  "ListId": "8d937333-0987-4321-ba98-76543210fedc",
  "ListItemUniqueId": "11234567-89ab-cdef-0123-456789abcdef",
  "Site": "https://contoso.sharepoint.com/sites/Engineering",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}
```

### 2.2 Suspicious Search Patterns
**Description**: Adversary performs targeted searches for sensitive content types.

**Audit Operations**:
- SearchQueryPerformed
- SearchCreated
- SearchStarted

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:24:12",
  "Id": "fb2c345b-9876-5432-dcba-987654321fed",
  "Operation": "SearchQueryPerformed", 
  "OrganizationId": "c7f2f34a-1234-5678-90ab-cdef12345678",
  "RecordType": 4,
  "UserKey": "i:0h.f|membership|bob@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "SharePoint",
  "UserId": "bob@contoso.com",
  "ClientIP": "192.168.1.100",
  "QueryText": "password credentials admin configuration",
  "SiteUrl": "https://contoso.sharepoint.com/sites/IT",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}
```

### 2.3 Permission Escalation
**Description**: Adversary modifies SharePoint permissions to gain broader access.

**Audit Operations**:
- SharingSet
- AddedToGroup 
- PermissionLevelModified

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:26:44",
  "Id": "cd5e678f-4321-8765-fedc-ba9876543210",
  "Operation": "SharingSet",
  "OrganizationId": "c7f2f34a-1234-5678-90ab-cdef12345678", 
  "RecordType": 14,
  "UserKey": "i:0h.f|membership|bob@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "SharePoint",
  "ObjectId": "https://contoso.sharepoint.com/sites/Finance",
  "UserId": "bob@contoso.com",
  "TargetUserOrGroupName": "Everyone except external users",
  "TargetUserOrGroupType": "SecurityGroup",
  "EventData": "{\"PermissionLevel\":\"Full Control\"}"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect bulk downloads
SELECT UserId, COUNT(*) as download_count
FROM AuditLogs 
WHERE Operation = 'FileDownloaded'
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 50;

-- Detect sensitive search terms
SELECT UserId, QueryText
FROM AuditLogs
WHERE Operation = 'SearchQueryPerformed'
AND QueryText CONTAINS_ANY('password', 'credential', 'secret', 'config');

-- Detect permission changes
SELECT UserId, Operation, TargetUserOrGroupName
FROM AuditLogs
WHERE Operation IN ('SharingSet', 'AddedToGroup')
AND TimeGenerated > ago(24h);
```

### 3.2 Baseline Deviation Monitoring
- Track normal document access patterns per user/department
- Monitor typical search term frequencies
- Baseline permission modification activities
- Alert on deviations >2 standard deviations from baseline

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement data classification for sensitive content
- Configure DLP policies for sensitive data types
- Regular access reviews for SharePoint permissions
- Enforce conditional access policies

### 4.2 Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "name": "SharePoint Sensitive Access",
    "conditions": {
      "applications": ["SharePoint Online"],
      "users": ["all"],
      "locations": ["untrusted"],
      "clientApps": ["browser", "mobileApps", "desktop"]
    },
    "controls": {
      "requireMFA": true,
      "requireCompliantDevice": true,
      "blockDownloads": true
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable detailed SharePoint auditing
- Deploy CASB solution for SharePoint monitoring
- Implement real-time alerts for suspicious activities
- Monitor SharePoint admin activities

## 5. Incident Response Playbook

### Initial Detection
1. Verify alert details in audit logs
2. Identify affected SharePoint sites/content
3. Document scope of accessed data

### Investigation
1. Review historical access patterns
2. Analyze search queries and downloaded content
3. Check for permission changes
4. Correlate with other security events

### Containment
1. Suspend suspected user accounts
2. Revoke suspicious permissions
3. Block external sharing if compromised
4. Enable stricter authentication requirements

## 6. References
- [MITRE ATT&CK T1213.002](https://attack.mitre.org/techniques/T1213/002/)
- [Microsoft SharePoint Security](https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server)
- [SharePoint Audit Log Schema](https://docs.microsoft.com/en-us/microsoft-365/compliance/audit-log-schema)

Let me know if you would like me to expand on any section or provide additional examples!

---

# Threat Model: Email Hiding Rules (T1564.008) in Microsoft 365 & Entra ID

## 1. Overview

Email hiding rules are used by adversaries to conceal malicious activities by automatically moving or deleting emails in compromised mailboxes. In Microsoft 365, this can be accomplished through:

- Outlook Web App (OWA) inbox rules
- Exchange PowerShell cmdlets (New-InboxRule, Set-InboxRule)
- Exchange transport rules (organization-wide)

## 2. Attack Vectors

### Vector 1: PowerShell Inbox Rule Creation

**Description:**
Adversary uses PowerShell to create inbox rules that move security alert emails to obscure folders.

**Scenario:**
```powershell
New-InboxRule -Name "Security Filter" -SubjectContainsWords "Security alert","Suspicious activity" -MoveToFolder "Archive"
```

**Relevant Audit Operations:**
- New-InboxRule
- Set-InboxRule
- UpdateInboxRules

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "5689d874-6248-4a5c-9518-e8d9773f5c20",
  "Operation": "New-InboxRule",
  "OrganizationId": "72f988bf-86f1-41af-91ab-2d7cd011db47",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "user@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "NAMPR12A001.prod.outlook.com/Microsoft Exchange Hosted Organizations/contoso.com/user@contoso.com",
  "Parameters": [
    {
      "Name": "RuleName",
      "Value": "Security Filter"
    },
    {
      "Name": "SubjectContainsWords",
      "Value": "Security alert,Suspicious activity"
    },
    {
      "Name": "MoveToFolder",
      "Value": "Archive"
    }
  ]
}
```

### Vector 2: Mass Deletion Rules

**Description:**
Adversary creates rules to automatically delete emails containing security-related keywords.

**Scenario:**
```powershell
New-InboxRule -Name "Cleanup" -SubjectOrBodyContainsWords "malware","phishing","compromise" -DeleteMessage $true
```

**Relevant Audit Operations:**
- New-InboxRule
- HardDelete
- SoftDelete

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "7823a965-7a92-4f66-9b9c-55d4b2b65289",
  "Operation": "New-InboxRule",
  "OrganizationId": "72f988bf-86f1-41af-91ab-2d7cd011db47",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "user@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "Parameters": [
    {
      "Name": "RuleName", 
      "Value": "Cleanup"
    },
    {
      "Name": "SubjectOrBodyContainsWords",
      "Value": "malware,phishing,compromise"
    },
    {
      "Name": "DeleteMessage",
      "Value": "True"
    }
  ]
}
```

### Vector 3: Transport Rule Manipulation

**Description:**
Adversary with admin privileges creates organization-wide transport rules to intercept security notifications.

**Relevant Audit Operations:**
- Set-TransportRule
- New-TransportRule

## 3. Detection Strategies

### Behavioral Analytics

```sql
// Detect suspicious inbox rule creation
SELECT UserKey, Count(*) as RuleCount
FROM ExchangeAuditLog
WHERE Operation IN ('New-InboxRule','Set-InboxRule')
  AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING Count(*) > 3;

// Detect rules targeting security keywords
SELECT *
FROM ExchangeAuditLog
WHERE Operation IN ('New-InboxRule','Set-InboxRule')
  AND Parameters CONTAINS ANY ('security','alert','phishing','malware','suspicious')
  AND (Parameters CONTAINS 'DeleteMessage' OR Parameters CONTAINS 'MoveToFolder');
```

### Baseline Monitoring
- Track normal inbox rule creation patterns per user
- Monitor typical rule targets and actions
- Alert on deviations from established baselines

## 4. Mitigation Controls

### Administrative Controls
```json
{
  "mailboxRules": {
    "maxRulesPerUser": 50,
    "prohibitedKeywords": ["security", "alert", "phishing"],
    "restrictedActions": ["HardDelete", "SoftDelete"],
    "requireApproval": true
  }
}
```

### Technical Controls
```json
{
  "auditingConfig": {
    "enableMailboxAuditing": true,
    "auditedOperations": [
      "New-InboxRule",
      "Set-InboxRule",
      "UpdateInboxRules",
      "HardDelete",
      "SoftDelete"
    ],
    "retentionDays": 90
  },
  "transportRules": {
    "requireMFA": true,
    "approvalWorkflow": true
  }
}
```

### Monitoring Controls
- Real-time alerts on suspicious rule creation
- Weekly review of inbox rules
- Automated scanning for malicious rule patterns

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected mailboxes
2. Extract rule configurations
3. Document rule creation timeline

### Investigation
1. Review audit logs for rule creation events
2. Analyze moved/deleted email content
3. Identify any exfiltrated data

### Containment
1. Disable suspicious rules
2. Reset affected account credentials
3. Implement additional monitoring

## 6. References

- [MITRE ATT&CK T1564.008](https://attack.mitre.org/techniques/T1564/008/)
- [Microsoft Exchange Auditing Documentation](https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mailbox-audit-logging/mailbox-audit-logging)
- [Microsoft Security Best Practices](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/secure-email-recommended-policies)

---

# Threat Model: Steal Web Session Cookie (T1539) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, session cookies are used to maintain authentication state after initial login. Adversaries may steal these cookies to bypass MFA and gain unauthorized access to accounts and resources.

## 2. Attack Vectors

### 2.1 Browser Cookie Theft
- **Description**: Malware or browser exploits extract session cookies from browser storage
- **Detection Fields**:
```json
{
  "Operation": "UserLoggedIn",
  "ClientIP": "<ip_address>",
  "UserAgent": "<browser_string>",
  "DeviceProperties": {
    "deviceId": "<device_id>",
    "displayName": "<device_name>",
    "operatingSystem": "<os_version>"
  }
}
```

### 2.2 Phishing Proxy 
- **Description**: Malicious proxy (e.g. Evilginx2) intercepts authentication flow to capture cookies
- **Detection Fields**:
```json
{
  "Operation": "TeamsSessionStarted", 
  "ClientIP": "<ip_address>",
  "UserAgent": "<browser_string>",
  "AuthenticationMethod": "oauth2",
  "AuthenticationProcessingDetails": [
    "OAuth 2.0 Authorization Code"
  ]
}
```

### 2.3 Token/Cookie Extraction from Memory
- **Description**: Memory scraping malware extracts cached tokens/cookies
- **Detection Fields**:
```json
{
  "Operation": "MailboxLogin",
  "ClientInfoString": "<client_app>",
  "ClientIPAddress": "<ip_address>", 
  "LogonType": "Cached token",
  "AuthenticationMethod": "OAuth"
}
```

## 3. Detection Strategy

### 3.1 Behavioral Analytics
```sql
-- Detect logins from new locations using stolen cookies
SELECT UserAgent, ClientIP, COUNT(*) as auth_count
FROM UserLoggedIn 
WHERE TimeGenerated > ago(1h)
GROUP BY UserAgent, ClientIP
HAVING auth_count > 10;

-- Detect cookie reuse across different IPs
SELECT UserId, COUNT(DISTINCT ClientIP) as ip_count
FROM TeamsSessionStarted
WHERE TimeGenerated > ago(24h)
GROUP BY UserId
HAVING ip_count > 5;
```

### 3.2 Baseline Deviations
- Monitor for authentication patterns deviating from user baselines:
  - Login times outside normal hours
  - Geographic impossible travel
  - Multiple IPs in short timeframe
  - Unusual user agent strings

## 4. Mitigation Controls

### 4.1 Technical Controls
```json
{
  "conditionalAccess": {
    "signInFrequency": {
      "type": "hours",
      "value": 4
    },
    "persistentBrowser": "never",
    "deviceFilters": {
      "mode": "include",
      "rules": ["compliant", "hybrid-joined"]
    }
  },
  "sessionControls": {
    "persistentSession": "never",
    "signOutAfterTimeout": true,
    "timeoutValue": "1h"
  }
}
```

### 4.2 Administrative Controls
- Enforce short cookie lifetimes
- Require device compliance
- Block legacy authentication
- Enable Continuous Access Evaluation
- Configure session timeout policies

### 4.3 Monitoring Controls  
- Alert on:
  - Multiple failed MFA attempts
  - Suspicious IP addresses
  - Token replay attempts
  - Geographic anomalies
  - Mass cookie theft indicators

## 5. Incident Response

### 5.1 Initial Response
1. Identify affected accounts
2. Review authentication logs for indicators
3. Revoke all active sessions
4. Reset account credentials
5. Enable enhanced monitoring

### 5.2 Investigation Steps
1. Review UAL/Sign-in logs for:
   - Unusual IP addresses
   - Different user agents
   - Geographic anomalies
   - Token usage patterns
2. Search for lateral movement
3. Check for data exfiltration
4. Identify initial access vector

### 5.3 Containment Actions
1. Block suspicious IPs
2. Revoke refresh tokens
3. Reset MFA seeds
4. Enable strict session controls
5. Force password resets

## 6. References
- [MITRE ATT&CK T1539](https://attack.mitre.org/techniques/T1539/)
- [Microsoft Cookie Theft Prevention](https://learn.microsoft.com/security/cookie-security)
- [Entra ID Session Management](https://learn.microsoft.com/azure/active-directory/authentication/session-management)

Let me know if you would like me to expand on any section or provide additional details about specific detection strategies or controls.

---

# Threat Model: Permission Groups Discovery (T1069) in Microsoft 365 & Entra ID

## 1. Overview

Permission Groups Discovery in Microsoft 365 and Entra ID involves adversaries attempting to enumerate groups, roles, and permissions to understand the security landscape and identify potential privilege escalation paths. This commonly involves:

- Enumerating Entra ID roles and group memberships
- Discovering SharePoint/OneDrive permissions and sharing settings  
- Mapping Exchange Online mailbox delegations and permissions
- Identifying administrative roles and privileged accounts

## 2. Attack Vectors

### 2.1 Entra ID Role Enumeration

**Description:**
Adversaries use compromised accounts to enumerate Entra ID roles and group memberships through PowerShell, Microsoft Graph API, or Azure Portal.

**Attack Example:**
```powershell
Get-AzureADDirectoryRole
Get-AzureADGroupMember -ObjectId "Global Administrators"
```

**Relevant Audit Operations:**
- Add member to role
- Remove member from role
- Add group
- Add member to group
- Update group

**Example Audit Log:**
```json
{
  "Operation": "Add member to role",
  "ObjectId": "Global Administrator",
  "UserId": "bob.smith@company.com",
  "TargetUserId": "jane.doe@company.com", 
  "ClientIP": "192.168.1.100",
  "UserAgent": "PowerShell/7.0.3",
  "CreationTime": "2024-01-20T15:30:00Z"
}
```

### 2.2 SharePoint Permission Enumeration 

**Description:**
Adversaries enumerate SharePoint site permissions and sharing settings to identify accessible content and privilege relationships.

**Attack Example:**
```powershell
Get-SPOSite | Get-SPOUser
Get-SPOSiteGroup -Site https://company.sharepoint.com/sites/finance
```

**Relevant Audit Operations:**
- SharingSet
- AccessRequestCreated 
- PermissionLevelAdded
- SitePermissionsModified

**Example Audit Log:**
```json
{
  "Operation": "SharingSet",
  "SiteUrl": "https://company.sharepoint.com/sites/finance",
  "TargetUserOrGroupName": "External Sharing Group",
  "TargetUserOrGroupType": "SecurityGroup",
  "EventSource": "SharePoint",
  "ItemType": "Folder",
  "SourceFileName": "Financial Reports",
  "SourceRelativeUrl": "/sites/finance/Shared Documents/Financial Reports"
}
```

### 2.3 Exchange Online Permission Discovery

**Description:**
Adversaries enumerate mailbox permissions, delegates, and mail flow rules to identify email access paths.

**Attack Example:**
```powershell
Get-MailboxPermission -Identity "CEO@company.com"
Get-InboxRule -Mailbox "finance@company.com"
```

**Relevant Audit Operations:**
- Add-MailboxPermission
- UpdateCalendarDelegation
- AddFolderPermissions
- New-InboxRule

**Example Audit Log:**
```json
{
  "Operation": "Add-MailboxPermission",
  "ObjectId": "CEO@company.com",
  "Parameters": [
    {"Name": "AccessRights", "Value": "FullAccess"},
    {"Name": "User", "Value": "executive.assistant@company.com"}
  ],
  "ResultStatus": "Success",
  "ClientIP": "10.1.1.100",
  "ClientProcessName": "Exchange Online PowerShell"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect rapid group enumeration
SELECT UserId, ClientIP, COUNT(*) as QueryCount
FROM AuditLogs 
WHERE Operation IN ('Add member to group', 'Remove member from group')
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 50 -- Threshold for suspicious enumeration

-- Detect permission enumeration across multiple services
SELECT UserId, COUNT(DISTINCT Operation) as OperationTypes
FROM AuditLogs
WHERE Operation IN (
  'Add-MailboxPermission',
  'SharingSet',
  'Add member to role'
)
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(DISTINCT Operation) > 3
```

### 3.2 Baseline Deviation Monitoring

Monitor for deviations from established baselines:
- Normal volume of permission queries per hour/user
- Typical services accessed per session
- Common admin tools and user agents
- Expected working hours and locations

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement Just-In-Time privileged access
- Enforce Privileged Identity Management (PIM)
- Regular access reviews for sensitive groups
- Documentation of approved administrative tools

### 4.2 Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Block Legacy Authentication",
    "State": "enabled",
    "Conditions": {
      "ClientAppTypes": ["exchangeActiveSync", "other"],
      "Action": "block"
    }
  },
  "AuditingConfig": {
    "EnableUnifiedAuditLog": true,
    "AuditLevel": "All",
    "RetentionDays": 90
  }
}
```

### 4.3 Monitoring Controls
- Real-time alerts for suspicious enumeration patterns
- Dashboard for permission changes and access requests
- Regular review of privileged account usage
- Automated reporting of unusual access patterns

## 5. Incident Response Playbook

### Initial Detection
1. Identify source account and access vector
2. Document timeline of permission queries
3. Map discovered resources and permissions
4. Determine normal vs. anomalous behavior

### Investigation Steps
1. Review authentication logs for compromised accounts
2. Analyze lateral movement attempts
3. Track permission changes and delegations
4. Document affected systems and data

### Containment Actions
1. Revoke suspicious delegations and permissions
2. Enable PIM for affected admin roles
3. Block compromised accounts
4. Reset affected service account credentials

## 6. References

- MITRE ATT&CK: T1069
- Microsoft Security Documentation
  - [Entra ID Audit Logs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/overview-reports)
  - [SharePoint Permission Monitoring](https://docs.microsoft.com/en-us/sharepoint/sharing-reports)
- [Incident Response for Microsoft 365](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/incident-response)

---

# Threat Model: Email Collection (T1114) in Microsoft 365 & Entra ID

## 1. Overview
Email collection in Microsoft 365 involves adversaries gathering sensitive information from Exchange Online mailboxes through various methods including:
- Mailbox delegation and permissions abuse
- Email forwarding rules
- Direct API access through compromised credentials
- Email client synchronization

## 2. Attack Vectors

### 2.1 Mailbox Delegation Abuse
**Description**: Adversaries add mailbox delegation permissions to access target mailboxes.

**Attack Flow**:
1. Compromise admin or user account with mailbox permissions
2. Add full access delegation to adversary-controlled account
3. Access mailbox contents via Exchange Online

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Add-MailboxPermission",
    "UpdateCalendarDelegation",
    "AddFolderPermissions"
  ],
  "Key Fields": {
    "Operation": "Add-MailboxPermission",
    "ObjectId": "[Mailbox GUID]",
    "Parameters": {
      "Identity": "target@company.com",
      "User": "attacker@company.com", 
      "AccessRights": "FullAccess",
      "InheritanceType": "All"
    }
  }
}
```

### 2.2 Email Forwarding Rules
**Description**: Attackers create inbox rules to forward emails to external addresses.

**Attack Flow**:
1. Gain access to user mailbox
2. Create forwarding rule to external email
3. Emails automatically sent to attacker-controlled address

**Audit Log Example**:
```json
{
  "Operation": "New-InboxRule",
  "ResultStatus": "Success",
  "UserId": "user@company.com",
  "Parameters": {
    "ForwardTo": "attacker@evil.com",
    "Name": "Forward All",
    "Enabled": true
  }
}
```

### 2.3 API-Based Collection
**Description**: Using Microsoft Graph API to programmatically collect emails.

**Detection Fields**:
```json
{
  "Operation": "MailItemsAccessed", 
  "LogonType": "ApplicationLogon",
  "ClientAppId": "[App ID]",
  "ResultStatus": "Success",
  "ItemCount": "500+"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Detect suspicious mailbox delegation
SELECT UserId, Operation, TargetMailbox, COUNT(*) as freq
FROM AuditLogs 
WHERE Operation = 'Add-MailboxPermission'
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation, TargetMailbox
HAVING freq > 3;

-- Detect mass email access
SELECT ClientAppId, UserId, COUNT(*) as access_count
FROM AuditLogs
WHERE Operation = 'MailItemsAccessed'
AND TimeGenerated > ago(24h)
GROUP BY ClientAppId, UserId
HAVING access_count > 1000;
```

### 3.2 Baseline Deviations
- Monitor normal patterns of:
  - Mailbox access volumes per user
  - Email rule creation frequency
  - API-based mail access patterns
- Alert on deviations:
  - >50% increase in access volume
  - New forwarding rules to external domains
  - Bulk mailbox permission changes

## 4. Controls

### 4.1 Technical Controls
```json
{
  "ExchangeOnline": {
    "RemoteMailboxForwarding": "Disabled",
    "AutoForwardingRestriction": "Reject",
    "MailboxDelegationControls": {
      "RequireMFA": true,
      "AllowedDomains": ["company.com"],
      "AuditingEnabled": true
    }
  },
  "ConditionalAccess": {
    "MailboxAccess": {
      "RequireMFA": true,
      "BlockLegacyAuth": true,
      "AllowedLocations": ["Corporate Networks"]
    }
  }
}
```

### 4.2 Administrative Controls
- Regular mailbox permission audits
- Approval workflow for delegation changes
- Email forwarding restrictions policy
- Zero trust access model for email

### 4.3 Monitoring Controls
- Real-time alerts for:
  - New mailbox delegations
  - External forwarding rules
  - Bulk email access
  - Suspicious API usage patterns

## 5. Incident Response

### 5.1 Investigation Steps
1. Identify affected mailboxes
2. Review audit logs for:
   - Permission changes
   - Rule creation events
   - Access patterns
3. Analyze email forwarding configuration
4. Check API access logs

### 5.2 Containment
1. Remove suspicious delegations
2. Disable forwarding rules
3. Reset compromised credentials
4. Block suspicious API applications
5. Enable MFA for affected accounts

## 6. References
- MITRE: https://attack.mitre.org/techniques/T1114/
- Microsoft: https://docs.microsoft.com/en-us/microsoft-365/security/
- Exchange Online Auditing: https://docs.microsoft.com/en-us/exchange/security/

---

# Threat Model: Cloud Groups (T1069.003) in Microsoft 365 & Entra ID

## 1. Overview

Adversaries enumerate cloud groups and permissions in Microsoft 365 and Entra ID to:
- Map organizational structure and privileges 
- Identify high-value targets and administrative groups
- Plan lateral movement paths
- Discover sensitive resource access

## 2. Attack Vectors

### 2.1 PowerShell-Based Enumeration
**Description**: Adversaries use PowerShell modules like MSOnline and Azure AD to list groups and memberships

**Attack Scenario**:
1. Attacker compromises user credentials
2. Connects to Azure AD PowerShell
3. Runs enumeration commands like Get-MsolRole and Get-MsolRoleMember
4. Maps privilege relationships

**Relevant Audit Operations**:
- Add-ComplianceCaseMember
- Add member to role
- Get-ComplianceCase 

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:43",
  "Id": "27b32192-3c76-4478-a1d2-1c924af77863",
  "Operation": "Add member to role",
  "OrganizationId": "12a34567-89b0-1234-c567-def123456789",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "Global Administrator",
  "UserId": "target@contoso.com",
  "ClientIP": "192.168.1.100"
}
```

### 2.2 Microsoft Graph API Enumeration
**Description**: Adversaries leverage Microsoft Graph API to programmatically discover group memberships

**Attack Scenario**:
1. Attacker obtains API access token
2. Makes Graph API calls to /groups and /users endpoints
3. Maps relationships between groups and users

**Relevant Audit Operations**:
- Add service principal
- Set delegation entry
- Add service principal credentials

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "8af12b45-9c23-4781-bd45-67ee12398745",
  "Operation": "Add service principal",
  "OrganizationId": "12a34567-89b0-1234-c567-def123456789", 
  "RecordType": 11,
  "ResultStatus": "Success",
  "UserKey": "app@contoso.onmicrosoft.com",
  "Workload": "AzureActiveDirectory",
  "ObjectId": "ServicePrincipal_1234567890",
  "AppId": "abcdef12-3456-7890-abcd-ef1234567890",
  "ClientIP": "10.10.10.100"
}
```

### 2.3 Azure Portal UI Enumeration
**Description**: Manual enumeration through Azure Portal admin center interfaces

**Attack Scenario**:
1. Attacker logs into Azure Portal
2. Browses through Azure AD groups and roles sections
3. Documents group memberships and privilege assignments

**Relevant Audit Operations**:
- Add group
- Add member to group
- Update group

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:05:33",
  "Id": "92cd45ef-6721-4532-9087-ab43cd561298",
  "Operation": "Add member to group", 
  "OrganizationId": "12a34567-89b0-1234-c567-def123456789",
  "RecordType": 15,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "GroupName": "Global Admins",
  "MemberAdded": "user@contoso.com",
  "ClientIP": "172.16.1.50"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect rapid group membership enumeration
SELECT UserKey, ClientIP, COUNT(*) as query_count
FROM AuditLogs 
WHERE Operation IN ('Add member to group', 'Get-ComplianceCase')
AND TimeGenerated > ago(1h)
GROUP BY UserKey, ClientIP
HAVING COUNT(*) > 50;

-- Alert on non-admin users querying admin groups
SELECT * FROM AuditLogs
WHERE Operation LIKE '%role%' 
AND UserKey NOT IN (SELECT UserPrincipalName FROM AdminUsers)
AND TimeGenerated > ago(24h);
```

### Baseline Deviation Monitoring
- Track normal patterns of group queries per user/day
- Alert on >2 standard deviations from baseline
- Monitor time-of-day access patterns
- Flag unusual source IP addresses

### Correlation Rules
```sql
-- Correlate group enumeration with other suspicious activity
SELECT a.UserKey, a.ClientIP, COUNT(DISTINCT a.Operation) as suspicious_ops
FROM AuditLogs a
WHERE a.TimeGenerated > ago(1h)
AND (
  a.Operation LIKE '%group%' OR
  a.Operation LIKE '%role%' OR
  a.Operation = 'Add service principal'
)
GROUP BY a.UserKey, a.ClientIP
HAVING COUNT(DISTINCT a.Operation) >= 3;
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement least privilege access
- Regular access reviews
- Enforce conditional access policies
- Enable Privileged Identity Management

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "name": "Block Legacy Authentication",
    "conditions": {
      "clientAppTypes": ["other"],
      "applications": {
        "includeApplications": ["all"]
      }
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Monitor service principal creation
- Alert on mass group membership changes
- Track privileged role assignments

## 5. Incident Response Playbook

### Initial Detection
1. Verify alert details and affected accounts
2. Check source IP and user agent patterns
3. Review authentication logs
4. Document timeline of enumeration activity

### Investigation
1. Review all groups/roles queried
2. Check for unauthorized role assignments
3. Analyze service principal creation
4. Document compromised accounts

### Containment
1. Block suspicious IP addresses
2. Revoke compromised credentials
3. Reset affected service principals
4. Enable MFA for affected accounts
5. Review conditional access policies

## 6. References

- [MITRE ATT&CK T1069.003](https://attack.mitre.org/techniques/T1069/003/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Azure AD Authentication Documentation](https://docs.microsoft.com/en-us/azure/active-directory/authentication/)
- [Microsoft Graph Security API](https://docs.microsoft.com/en-us/graph/security-concept-overview)

---

# Threat Model: Password Cracking (T1110.002) in Microsoft 365 & Entra ID

## 1. Overview
Password cracking in Microsoft 365 and Entra ID environments typically occurs after adversaries obtain password hashes through various means. Unlike on-premise Active Directory, direct access to password hashes is more limited in cloud environments, making this technique most relevant after initial compromise or in hybrid scenarios.

## 2. Attack Vectors

### 2.1 Hybrid Identity Synchronization Compromise
**Description**: Adversaries target Azure AD Connect servers to extract password hashes synchronized between on-premises AD and Entra ID.

**Detection Fields**:
```json
{
  "Operation": "Set DirSyncEnabled flag.",
  "UserKey": "[User ID]",
  "ObjectId": "[Object ID]",
  "SyncType": "Password",
  "ResultStatus": "Success"
}
```

**Example Log Entry**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "8728d839-49a0-4832-9022-3455fea12c5",
  "Operation": "Set DirSyncEnabled flag.",
  "OrganizationId": "12345678-91011-12131-415161-718191",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "1234567890",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "192.168.1.100",
  "ObjectId": "syncserver01",
  "UserId": "admin@contoso.com",
  "SyncType": "Password"
}
```

### 2.2 Service Principal Credential Theft
**Description**: Attackers extract service principal credentials which may have hashed authentication materials.

**Detection Fields**:
```json
{
  "Operation": "Add service principal credentials.",
  "ServicePrincipalId": "[SP ID]",
  "CredentialType": "Password",
  "ResultStatus": "Success"
}
```

**Example Log Entry**:
```json
{
  "CreationTime": "2024-01-20T16:33:42",
  "Id": "92847593-8273-4827-9283-827362534827",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "12345678-91011-12131-415161-718191",
  "RecordType": 8,
  "ResultStatus": "Success",
  "ServicePrincipalId": "sp_id_12345",
  "CredentialType": "Password",
  "ActorUserId": "attacker@contoso.com",
  "ClientIP": "10.0.0.100"
}
```

### 2.3 Azure Key Vault Certificate Extraction
**Description**: Adversaries access Key Vault to obtain certificates used for authentication.

**Detection Fields**:
```json
{
  "Operation": "SecretGet",
  "ResourceType": "Microsoft.KeyVault/vaults/secrets",
  "ResultSignature": "OK",
  "CallerIPAddress": "[IP Address]"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect rapid service principal credential additions
SELECT ServicePrincipalId, COUNT(*) as count
FROM AuditLogs
WHERE Operation = "Add service principal credentials."
AND TimeGenerated > ago(1h)
GROUP BY ServicePrincipalId
HAVING count > 3;

-- Monitor suspicious sync server operations
SELECT UserId, ClientIP, COUNT(*) as count  
FROM AuditLogs
WHERE Operation = "Set DirSyncEnabled flag."
AND TimeGenerated > ago(24h)
GROUP BY UserId, ClientIP;
```

### 3.2 Baseline Deviations
- Track normal volume of credential operations per service principal
- Monitor typical working hours for sync operations
- Establish baseline for Key Vault access patterns

## 4. Mitigation Strategies

### 4.1 Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "name": "Block Legacy Authentication",
    "state": "enabled",
    "conditions": {
      "clientAppTypes": ["exchangeActiveSync", "other"],
      "applications": {
        "includeApplications": ["all"]
      }
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }
}
```

### 4.2 Administrative Controls
- Implement Privileged Identity Management for sync accounts
- Enable MFA for all admin accounts
- Regular rotation of service principal credentials

### 4.3 Monitoring Controls
- Enable Azure AD Password Protection
- Configure alerts for suspicious sync operations
- Monitor service principal credential changes

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Identify affected accounts/service principals
2. Review audit logs for credential modification events
3. Check for unauthorized sync server operations

### 5.2 Investigation
1. Pull authentication logs for compromised identities
2. Review Key Vault access logs
3. Analyze sync server event logs
4. Map timeline of credential modifications

### 5.3 Containment
1. Disable compromised service principals
2. Reset affected credentials
3. Block suspicious IP addresses
4. Enable strict conditional access policies

## 6. References
- [MITRE ATT&CK T1110.002](https://attack.mitre.org/techniques/T1110/002/)
- [Microsoft Entra ID Protection](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/)
- [Azure AD Connect security](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/plan-connect-security)

This threat model provides a comprehensive framework specifically focused on password cracking attempts in Microsoft 365 and Entra ID environments, with concrete detection methods and response procedures based on actual audit log data.

---

# Threat Model: SAML Token Abuse (T1606.002) in Microsoft 365 & Entra ID

## 1. Overview

SAML token abuse in Microsoft 365 and Entra ID involves adversaries forging or manipulating SAML tokens to bypass authentication controls and impersonate legitimate users. Three primary attack vectors exist:

1. Token-signing certificate theft and abuse
2. Federation trust manipulation 
3. Token lifetime manipulation

## 2. Attack Vectors

### 2.1 Token-Signing Certificate Theft

**Description:**
Adversaries steal the ADFS token-signing certificate to forge tokens with arbitrary claims.

**Audit Operations to Monitor:**
```json
{
    "Primary": [
        "Add service principal credentials.",
        "Set federation settings on domain.",
        "Update domain."
    ],
    "Secondary": [
        "Add domain to company.",
        "Set domain authentication."
    ]
}
```

**Example Audit Log:**
```json
{
    "CreationTime": "2024-01-20T15:22:31",
    "Id": "8932a59c-38f9-4c88-b454-96c7b4856a7e",
    "Operation": "Add service principal credentials.",
    "OrganizationId": "d9bacf70-3210-46f5-9d3f-2f7e6a8bfd12",
    "RecordType": 8,
    "ResultStatus": "Success",
    "UserKey": "10032001A42B8@contoso.com",
    "UserType": 0,
    "Version": 1,
    "Workload": "AzureActiveDirectory",
    "ObjectId": "5f5a1c27-a7c3-4bdc-b058-46d8fb0fa7f4",
    "UserId": "admin@contoso.com",
    "ClientIP": "192.168.1.100",
    "KeyIdentifier": "[PFX HASH REDACTED]",
    "ApplicationId": "00000002-0000-0ff1-ce00-000000000000"
}
```

### 2.2 Federation Trust Manipulation

**Description:**
Adversaries create or modify federation trust relationships to establish their own token signing authority.

**Audit Operations to Monitor:**
```json
{
    "Primary": [
        "Set federation settings on domain.",
        "Add partner to company.",
        "Update domain."
    ],
    "Secondary": [
        "Set domain authentication.",
        "Add domain to company."
    ]
}
```

**Example Audit Log:**
```json
{
    "CreationTime": "2024-01-20T16:14:22",
    "Id": "44f8b9a2-9142-4523-8730-3f3872cc22cc", 
    "Operation": "Set federation settings on domain.",
    "OrganizationId": "d9bacf70-3210-46f5-9d3f-2f7e6a8bfd12",
    "RecordType": 8,
    "ResultStatus": "Success",
    "UserKey": "10032001A42B8@contoso.com",
    "UserType": 0,
    "Version": 1,
    "Workload": "AzureActiveDirectory",
    "ObjectId": "contoso.com",
    "UserId": "admin@contoso.com",
    "ClientIP": "192.168.1.100",
    "Target": [
        {
            "Type": 2,
            "ID": "contoso.com"
        }
    ],
    "ModifiedProperties": [
        {
            "Name": "IssuerUri",
            "NewValue": "http://malicious-adfs.attacker.com/adfs/services/trust",
            "OldValue": "http://adfs.contoso.com/adfs/services/trust"
        }
    ]
}
```

### 2.3 Token Lifetime Manipulation

**Description:** 
Adversaries modify SAML token lifetime settings to create long-lived tokens that persist access.

**Audit Operations to Monitor:**
```json
{
    "Primary": [
        "Set federation settings on domain.",
        "Update domain.",
        "Set domain authentication."
    ]
}
```

**Example Audit Log:**
```json
{
    "CreationTime": "2024-01-20T17:03:15",
    "Id": "92a44f2c-3210-4688-9d3f-8822bfd12334",
    "Operation": "Set federation settings on domain.", 
    "RecordType": 8,
    "ResultStatus": "Success",
    "UserKey": "10032001A42B8@contoso.com",
    "Workload": "AzureActiveDirectory",
    "ObjectId": "contoso.com",
    "UserId": "admin@contoso.com",
    "ModifiedProperties": [
        {
            "Name": "TokenLifetime",
            "NewValue": "7.00:00:00",
            "OldValue": "1.00:00:00"
        }
    ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect suspicious federation trust changes
SELECT UserId, ClientIP, Operation, ModifiedProperties
FROM AuditLogs 
WHERE Operation IN ('Set federation settings on domain.', 'Add partner to company.')
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 2;

-- Alert on token lifetime modifications
SELECT * FROM AuditLogs
WHERE Operation = 'Set federation settings on domain.'
AND ModifiedProperties.Name = 'TokenLifetime'
AND ModifiedProperties.NewValue > '1.00:00:00';
```

### 3.2 Baseline Deviation Monitoring

- Track normal patterns of federation configuration changes
- Alert on:
  - Changes outside business hours (>2 standard deviations from baseline)
  - Multiple changes in short time periods
  - Changes from unusual IP addresses
  - Modifications to token lifetimes >1 hour

## 4. Mitigation Controls

### Administrative Controls
- Implement strict change control for federation settings
- Require MFA for all administrative actions
- Regular rotation of token signing certificates
- Audit of federation trusts and token lifetimes

### Technical Controls
```json
{
    "conditionalAccess": {
        "signInFrequency": {
            "value": "1",
            "type": "hours",
            "isPersistentBrowser": false
        },
        "applicationEnforcedRestrictions": {
            "minimumSAMLTokenLifetime": "1:00:00",
            "maximumSAMLTokenLifetime": "1:00:00"
        }
    },
    "federationSettings": {
        "promptLoginBehavior": "Disabled",
        "signingCertificateUpdateNotificationEnabled": true,
        "requireMFAOnWrite": true
    }
}
```

### Monitoring Controls
- Real-time alerts on federation trust changes
- Continuous monitoring of token lifetimes
- Regular review of federation relationships
- Automated scanning for unauthorized certificates

## 5. Incident Response Playbook

### Initial Detection
1. Identify source of alert (audit log entry)
2. Validate alert authenticity
3. Determine scope of potential compromise

### Investigation
1. Review all federation configuration changes
2. Analyze token signing certificate history
3. Identify affected user accounts
4. Timeline construction of attack

### Containment 
1. Revoke suspicious SAML tokens
2. Reset federation trust if compromised
3. Rotate token signing certificates
4. Enable additional monitoring

## 6. References

- [MITRE ATT&CK - T1606.002](https://attack.mitre.org/techniques/T1606/002/)
- [Microsoft - Protect Against SAML Token Attack](https://docs.microsoft.com/security/saml-token-protection)
- [Microsoft - Federation Trust Best Practices](https://docs.microsoft.com/azure/active-directory/hybrid/federation-best-practices)
- [CyberArk - Golden SAML](https://www.cyberark.com/resources/golden-saml-attack)

---

# Threat Model: Hide Artifacts (T1564) in Microsoft 365 & Entra ID

## Overview
In Microsoft 365 and Entra ID environments, adversaries may attempt to hide their activities by manipulating email rules, modifying audit logs, and abusing administrative features to conceal malicious actions. This technique often involves manipulating native platform capabilities rather than introducing new tools.

## Attack Vectors

### 1. Email Hiding Rules
**Description**: Adversaries create inbox rules to automatically move or delete security alerts and audit notifications.

**Attack Scenario**:
- Attacker compromises admin account
- Creates rules to move/delete security alerts 
- Modifies transport rules to filter security notifications

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "New-InboxRule",
    "Set-InboxRule", 
    "UpdateInboxRules"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "14c789e1-6a89-4b4f-a456-deadbeef1234",
  "Operation": "New-InboxRule",
  "OrganizationId": "d124ef23-7890-4f78-a123-deadbeefaaaa",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "Parameters": {
    "RuleName": "Process Alerts",
    "MoveToFolder": "Deleted Items",
    "SubjectContainsWords": ["Alert", "Security", "Suspicious"]
  }
}
```

### 2. Audit Log Manipulation
**Description**: Adversaries modify audit log settings or delete audit data to hide their tracks.

**Attack Scenario**:
- Attacker gains Global Admin access
- Disables audit logging for specific workloads
- Modifies retention settings for audit logs

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Set-MailboxAuditBypassAssociation",
    "UpdatedPrivacySetting",
    "ChangeDataRetention"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "87def432-8901-4c23-b789-deadbeef5678",
  "Operation": "Set-MailboxAuditBypassAssociation",
  "OrganizationId": "d124ef23-7890-4f78-a123-deadbeefaaaa", 
  "ResultStatus": "Success",
  "UserId": "admin@contoso.com",
  "ObjectId": "target@contoso.com",
  "Parameters": {
    "AuditBypassEnabled": "True"
  }
}
```

### 3. Service Principal Obfuscation  
**Description**: Adversaries create or modify service principals to hide persistent access.

**Attack Scenario**:
- Attacker creates innocuous-looking service principal
- Assigns elevated permissions
- Uses for persistent backdoor access

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Add service principal.",
    "Add service principal credentials.",
    "Set delegation entry."
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:08:11",
  "Id": "92abc123-4567-8def-9012-deadbeef9012",
  "Operation": "Add service principal.",
  "OrganizationId": "d124ef23-7890-4f78-a123-deadbeefaaaa",
  "ResultStatus": "Success", 
  "ActorUPN": "admin@contoso.com",
  "TargetResources": [{
    "Type": "ServicePrincipal",
    "Name": "BackupSync_App",
    "NewValue": "{\"Permissions\":\"GlobalAdmin\"}"
  }]
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect suspicious inbox rule creation
SELECT UserKey, COUNT(*) as rule_count
FROM AuditLogs 
WHERE Operation IN ('New-InboxRule', 'Set-InboxRule')
AND DATEADD(hour, -1, GETDATE()) 
GROUP BY UserKey
HAVING COUNT(*) > 3;

-- Monitor audit bypass changes
SELECT * FROM AuditLogs
WHERE Operation = 'Set-MailboxAuditBypassAssociation'
AND Parameters.AuditBypassEnabled = 'True';

-- Track service principal creation with elevated permissions
SELECT * FROM AuditLogs
WHERE Operation = 'Add service principal.'
AND TargetResources[0].NewValue LIKE '%GlobalAdmin%';
```

### Baseline Deviations
- Monitor for spike in inbox rule creation (>3x daily average)
- Alert on any audit configuration changes
- Track service principal creation rate changes

### Correlation Rules
- Link inbox rule creation with security alert timing
- Correlate service principal creation with permission changes
- Monitor relationship between audit changes and other admin activities

## Mitigation Strategies

### Administrative Controls
1. Implement least privilege access
2. Require MFA for all admin activities
3. Regular review of service principals and permissions

### Technical Controls
```json
{
  "ConditionalAccessPolicies": {
    "AdminMFA": {
      "Enabled": true,
      "TargetGroups": ["Global Administrators", "Exchange Administrators"],
      "Conditions": {
        "ClientApps": ["All"],
        "Locations": ["All"]
      }
    }
  },
  "AuditSettings": {
    "UnifiedAuditLog": "Enabled",
    "RetentionDays": 365,
    "BypassModificationRestricted": true
  }
}
```

### Monitoring Controls
1. Real-time alerts for audit configuration changes
2. Daily review of new service principals
3. Weekly audit of inbox rules

## Incident Response Playbook

### Initial Detection
1. Identify affected accounts/resources
2. Document timeline of suspicious activities
3. Preserve audit logs and evidence

### Investigation
1. Review all inbox rules and transport rules
2. Audit service principal permissions
3. Check for disabled audit settings

### Containment
1. Disable suspicious inbox rules
2. Revoke compromised credentials
3. Reset affected service principals

## References
- [MITRE T1564](https://attack.mitre.org/techniques/T1564/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Entra ID Audit Events](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities)

---

# Threat Model: Taint Shared Content (T1080) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 environments, adversaries can abuse SharePoint Online, OneDrive for Business, and Teams to deliver malicious content through shared locations. This involves modifying legitimate files or uploading malicious content to frequently accessed shared locations.

## 2. Attack Vectors

### 2.1 SharePoint Document Library Infection
**Description**: Adversaries upload or modify files in SharePoint document libraries with embedded malicious macros or scripts.

**Detection Fields**:
```json
{
  "FileUploaded": {
    "CreationTime": "timestamp",
    "UserId": "user@domain.com",
    "ObjectId": "documentId",
    "ClientIP": "ip_address",
    "ListId": "library_guid",
    "FileType": "file_extension",
    "SourceFileName": "filename",
    "SiteUrl": "sharepoint_url"
  },
  "FileModified": {
    "ModificationTime": "timestamp", 
    "UserId": "user@domain.com",
    "ObjectId": "documentId",
    "Version": "version_number"
  }
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:33Z",
  "Id": "3c7e2bcc-1a9d-4e44-b3a1-443ff459e654",
  "Operation": "FileUploaded",
  "OrganizationId": "org_guid",
  "RecordType": 4,
  "UserKey": "user@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "SharePoint",
  "ClientIP": "40.91.82.34",
  "ObjectId": "https://contoso.sharepoint.com/shared/Budget2024.xlsm",
  "UserId": "user@contoso.com",
  "ListId": "3a7e2bcc-1a9d-4e44-b3a1-443ff459e654",
  "FileType": "xlsm",
  "SourceFileName": "Budget2024.xlsm",
  "SiteUrl": "https://contoso.sharepoint.com/sites/Finance"
}
```

### 2.2 Teams Shared Files Poisoning
**Description**: Adversaries share malicious files through Teams channels or chats that auto-execute when opened.

**Detection Fields**:
```json
{
  "MessageSent": {
    "TeamName": "team_name",
    "ChannelName": "channel_name", 
    "MessageType": "message_type",
    "AttachmentCount": "number",
    "AttachmentTypes": ["file_extensions"]
  },
  "FileAccessed": {
    "TeamName": "team_name",
    "ChannelName": "channel_name",
    "UserId": "user@domain.com",
    "FileName": "filename"
  }
}
```

### 2.3 OneDrive Sync Infection
**Description**: Adversaries modify synced OneDrive files to spread malware across user devices.

**Detection Fields**:
```json
{
  "FileSyncUploadedFull": {
    "UserId": "user@domain.com",
    "SourceFileName": "filename",
    "ClientIP": "ip_address",
    "DeviceName": "device_name"
  }
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect unusual file upload patterns
SELECT UserId, COUNT(*) as upload_count
FROM FileUploaded 
WHERE TimeGenerated > ago(1h)
AND FileType in ('exe','dll','vbs','ps1','bat','cmd')
GROUP BY UserId
HAVING COUNT(*) > 10;

-- Detect mass file modifications
SELECT UserId, COUNT(*) as mod_count 
FROM FileModified
WHERE TimeGenerated > ago(30m)
GROUP BY UserId
HAVING COUNT(*) > 50;
```

### 3.2 Baseline Deviation Monitoring
- Monitor typical file upload volumes per user/team
- Track normal working hours file activity
- Establish baseline for file type distributions

### 3.3 Technical Indicators
- Files with multiple extensions (e.g., invoice.pdf.exe)
- Embedded macros in non-business file types
- High entropy file content suggesting encryption

## 4. Mitigation Strategies

### Administrative Controls
1. Configure SharePoint file blocking settings
2. Enable Protected View for Office documents
3. Implement sensitivity labels for shared content

### Technical Controls
```json
{
  "sharePointSettings": {
    "blockMalwareFiles": true,
    "allowedFileTypes": ["approved_extensions"],
    "scanOnUpload": true
  },
  "teamsSettings": {
    "allowedFileTypes": ["approved_extensions"],
    "externalSharing": "existing_users_only"
  }
}
```

### Monitoring Controls
1. Enable SharePoint audit logging
2. Configure alerts for suspicious file activity
3. Monitor file downloads across geographic regions

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected shared locations
2. Determine scope of compromised files
3. Identify patient zero and initial infection vector

### Investigation
1. Review audit logs for file modifications
2. Track file access patterns
3. Analyze file content for malicious indicators

### Containment
1. Quarantine suspected files
2. Block external sharing
3. Reset compromised user credentials

## 6. References
- MITRE ATT&CK: T1080
- Microsoft Security Documentation
- SharePoint Security Best Practices

This model focuses on the specific implementation details for Microsoft 365 services and provides actionable detection and response guidance based on actual audit capabilities.

---

# Threat Model: Spearphishing Link (T1566.002) in Microsoft 365 & Entra ID

## Overview
Spearphishing links in Microsoft 365 typically manifest in three main forms:
1. OAuth consent phishing for application access
2. Credential phishing through spoofed login pages
3. Malicious links in targeted emails to high-value users

## Attack Vectors

### 1. OAuth Consent Phishing
**Description**: Adversaries send targeted emails containing links to malicious OAuth applications requesting permissions to access user data and resources.

**Attack Scenario**:
- Attacker registers malicious OAuth app in Azure AD
- Sends targeted email masquerading as legitimate service 
- Link leads to OAuth consent prompt for excessive permissions
- User authorizes access, granting attacker persistent access

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Add delegation entry.",
    "Add service principal.",
    "Add service principal credentials.",
    "ConsentModificationRequest" 
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T15:22:31",
  "Id": "84392441-d", 
  "Operation": "Add service principal.",
  "OrganizationId": "87d349ed-44d7-43e1-9a83-5f2406dee5bd",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "8382bcd1-1a09-4e67-8427-4a29940b5c31",
  "UserId": "10032001@contoso.com",
  "ApplicationId": "eb83b59d-e6e8-4383-9e3e-6c6686ba1b3a",
  "DisplayName": "DocuSign Integration", 
  "RequestedPermissions": [
    "Mail.Read",
    "Mail.Send",
    "Files.ReadWrite.All",
    "User.Read.All"
  ]
}
```

### 2. Credential Phishing 
**Description**: Adversaries send targeted emails with links to fake Microsoft login pages to harvest credentials.

**Attack Scenario**:
- Attacker creates clone of Microsoft login page
- Sends targeted email about account security/MFA
- Link leads to credential harvesting site
- Stolen credentials used for initial access

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "UserLoggedIn",
    "Add member to role.",
    "Add service principal credentials."
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T16:13:22",
  "Id": "18d91421-c",
  "Operation": "UserLoggedIn", 
  "OrganizationId": "87d349ed-44d7-43e1-9a83-5f2406dee5bd",
  "RecordType": 15,
  "ResultStatus": "Success",
  "UserKey": "10039001@contoso.com", 
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "45.134.22.103",
  "UserAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)",
  "LogonError": "None",
  "AuthenticationMethod": "Password",
  "AuthenticationRequirement": "singleFactorAuthentication"
}
```

### 3. Business Email Compromise Link
**Description**: Adversaries compromise executive email accounts to send malicious links in trusted communications.

**Attack Scenario**:
- Attacker compromises executive email account
- Studies communication patterns and writing style
- Sends targeted emails to finance/HR with malicious links
- Exploits trust relationships for financial fraud

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "MailItemsAccessed",
    "MessageCreatedHasLink",
    "Send",
    "SendAs"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T14:55:16",
  "Id": "d992b9f1-a",
  "Operation": "MessageCreatedHasLink",
  "OrganizationId": "87d349ed-44d7-43e1-9a83-5f2406dee5bd", 
  "RecordType": 28,
  "ResultStatus": "Success",
  "UserKey": "CEO@contoso.com",
  "Workload": "Exchange",
  "ClientIP": "104.45.22.12",
  "MessageId": "<ME2831DEV22.123>",
  "InternetMessageId": "<ME2831DEV22@contoso.com>",
  "Subject": "Urgent Wire Transfer Needed",
  "Recipients": ["CFO@contoso.com"],
  "UrlCount": 1,
  "LinkDomains": ["http://secure-invoices.com"]
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect suspicious OAuth consent grants
SELECT UserKey, ClientIP, Operation, COUNT(*) as consent_count
FROM AuditLogs 
WHERE Operation = "ConsentModificationRequest"
  AND TimeGenerated > ago(1h)
GROUP BY UserKey, ClientIP, Operation
HAVING consent_count > 3;

-- Detect password spray from OAuth apps
SELECT AppId, COUNT(DISTINCT UserKey) as user_count
FROM SignInLogs
WHERE AppDisplayName NOT IN (known_good_apps)
  AND TimeGenerated > ago(1h)
GROUP BY AppId
HAVING user_count > 10;
```

### Baseline Deviations
- Monitor for spikes in:
  - OAuth consent grants vs baseline (>30% increase)
  - New service principal creation rate
  - Failed login attempts from new IPs
  - Email send volume with links

### Technical Controls
```json
{
  "oauth_app_restrictions": {
    "allowed_publishers": ["verified_publishers"],
    "blocked_permissions": [
      "Mail.Read.All",
      "Files.ReadWrite.All"  
    ],
    "require_admin_consent": true
  },
  "authentication_policies": {
    "block_legacy_auth": true,
    "require_mfa": true,
    "trusted_locations_only": true
  },
  "email_policies": {
    "block_executable_content": true,
    "scan_internal_links": true,
    "quarantine_suspicious": true
  }
}
```

## Incident Response
1. Initial Detection
   - Review OAuth consent logs
   - Analyze authentication patterns
   - Check email send patterns
   
2. Investigation
   - Identify affected accounts
   - Review OAuth permissions granted
   - Analyze email content and links
   
3. Containment
   - Disable compromised accounts
   - Revoke malicious OAuth grants
   - Block phishing domains

## References
- [MITRE ATT&CK T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [Microsoft OAuth 2.0 Phishing Campaigns](https://www.microsoft.com/security/blog/2021/03/02/what-tracking-an-attacker-email-infrastructure-tells-us-about-persistent-cybercriminal-operations/)
- [Microsoft 365 Defender Security Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/)

Let me know if you would like me to expand on any section or provide additional examples!

---

# Threat Model: Office Application Startup (T1137) in Microsoft 365 & Entra ID

## 1. Overview
This technique leverages Microsoft Office application startup mechanisms in Microsoft 365 to establish persistence. Adversaries can abuse features like Outlook rules, add-ins, and Office templates to maintain access and execute malicious code when Office applications start.

## 2. Attack Vectors

### 2.1 Malicious Outlook Rules
**Description**: Adversaries create Outlook rules that execute when specific conditions are met, enabling persistence and potentially data exfiltration.

**Detection Fields**:
```json
{
  "Operation": "New-InboxRule",
  "ResultStatus": "Success", 
  "UserId": "<user>",
  "ClientIP": "<ip>",
  "Parameters": {
    "ForwardTo": "<external_email>",
    "DeleteMessage": "True"
  }
}
```

### 2.2 Office Add-ins
**Description**: Attackers deploy malicious Office add-ins through service principals to maintain persistence.

**Detection Fields**:
```json
{
  "Operation": "Add service principal.",
  "ObjectId": "<add-in_id>",
  "ResultStatus": "Success",
  "ModifiedProperties": [
    {
      "Name": "AppRoles",
      "NewValue": "[{\"allowedMemberTypes\":[\"Application\"],\"description\":\"Office Add-in\"}]"
    }
  ]
}
```

### 2.3 Template Macros
**Description**: Adversaries modify Office templates to include malicious macros that execute on application startup.

**Detection Fields**:
```json
{
  "Operation": "FileModified",
  "SourceFileName": "Normal.dotm",
  "SourceFileExtension": "dotm",
  "UserAgent": "Microsoft Office",
  "WebId": "<site_id>"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Detect suspicious Outlook rules
SELECT UserId, ClientIP, COUNT(*) as rule_count
FROM AuditLogs 
WHERE Operation IN ('New-InboxRule', 'Set-InboxRule')
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 5;

-- Monitor add-in registrations
SELECT Operation, ActorIpAddress, TargetResources
FROM AuditLogs
WHERE Operation = 'Add service principal.'
AND TargetResources.modifiedProperties.Name CONTAINS 'AppRoles'
AND TimeGenerated > ago(24h);
```

### 3.2 Baseline Deviations
- Track normal patterns of Office template modifications
- Monitor frequency of inbox rule creation per user
- Alert on unusual add-in deployment patterns

## 4. Mitigation Strategies

### Administrative Controls
1. Implement strict add-in approval policies
2. Restrict template storage locations
3. Configure supervised Outlook rules

### Technical Controls
```json
{
  "outlookRules": {
    "blockExternalForwarding": true,
    "requireApproval": true,
    "allowedDomains": ["trusted.com"]
  },
  "officeAddIns": {
    "allowedLocations": ["AppSource"],
    "sideloadingEnabled": false,
    "trustedPublishers": ["<certificate_thumbprints>"]
  }
}
```

### Monitoring Controls
1. Enable detailed Office 365 audit logging
2. Monitor template file modifications
3. Track service principal creation events
4. Alert on suspicious rule patterns

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected accounts and applications
2. Review audit logs for rule creation patterns
3. Check for unauthorized add-ins

### Investigation
1. Document all modified templates
2. Analyze inbox rule configurations
3. Review service principal permissions
4. Map potentially compromised accounts

### Containment
1. Disable suspicious inbox rules
2. Remove unauthorized add-ins
3. Revert template modifications
4. Reset affected credentials

## 6. References
- MITRE ATT&CK: T1137
- Microsoft Office Security Guidelines
- Microsoft 365 Defender Documentation
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)

---

# Threat Model: Additional Cloud Roles (T1098.003) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries granting additional roles or permissions to compromised accounts in Microsoft 365 and Entra ID to maintain persistent access and expand privileges. Key implementation methods include:

- Adding accounts to privileged admin roles like Global Administrator
- Assigning permissions through service principals and delegated access
- Modifying app/service permissions and role assignments
- Creating new admin relationships between tenants

## 2. Attack Vectors

### 2.1 Direct Role Assignment

**Description**: Adversary adds compromised account to highly privileged roles

**Audit Operations**:
- "Add member to role."
- "Update user."
- "Set delegation entry."

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T15:22:43",
  "Id": "8382d091-9665-4296-8434-44f21c784951",
  "Operation": "Add member to role.",
  "OrganizationId": "d124ef6b-7665-4321-9284-12d45f8a9517",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "john.smith@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "ef127d83-9988-4f2c-8765-12a34b567c89",
  "UserId": "john.smith@company.com",
  "AADRoleName": "Global Administrator",
  "Actor": [
    {
      "ID": "72f234b6-5544-4432-8877-12d45f8a9517",
      "Type": 1
    }
  ],
  "ActorIpAddress": "12.34.56.78"
}
```

### 2.2 Service Principal Manipulation

**Description**: Adversary adds credentials or permissions to service principals

**Audit Operations**:
- "Add service principal."
- "Add service principal credentials."
- "Set delegation entry."

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T16:14:22",
  "Id": "92afd556-8776-4565-9988-87d45f8a1234", 
  "Operation": "Add service principal credentials.",
  "OrganizationId": "d124ef6b-7665-4321-9284-12d45f8a9517",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "app.admin@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "12abc345-9988-4f2c-8765-98d45f8a7654",
  "ServicePrincipalId": "spn_12345",
  "CredentialType": "Password",
  "Actor": [
    {
      "ID": "44f987d5-1122-4432-8877-65d45f8a9876",
      "Type": 1
    }
  ],
  "ActorIpAddress": "98.76.54.32"
}
```

### 2.3 Cross-Tenant Access Grant

**Description**: Adversary establishes delegated admin relationships between tenants

**Audit Operations**:
- "Add partner to company."
- "Set federation settings on domain."

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T17:33:11",
  "Id": "76bcd123-5544-8899-7766-54d45f8a3344",
  "Operation": "Add partner to company.",
  "OrganizationId": "d124ef6b-7665-4321-9284-12d45f8a9517", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "admin@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "PartnerTenantId": "87654321-9999-8888-7777-665544332211",
  "DelegatedPrivileges": ["UserAccountAdmin", "ExchangeAdmin"],
  "Actor": [
    {
      "ID": "99887766-5544-3322-1111-12d45f8a9517",
      "Type": 1
    }
  ],
  "ActorIpAddress": "11.22.33.44"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect rapid role assignments by single user
SELECT UserKey, COUNT(*) as role_changes
FROM AuditLogs 
WHERE Operation IN ('Add member to role.', 'Set delegation entry.')
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING COUNT(*) > 5

-- Alert on service principal credential additions outside business hours
SELECT *
FROM AuditLogs
WHERE Operation = 'Add service principal credentials.'
AND TimeGenerated NOT BETWEEN '0800' AND '1800'
```

### 3.2 Baseline Deviation Monitoring
- Monitor frequency of role changes vs historical baseline
- Track privileged role membership changes over time
- Alert on anomalous cross-tenant relationship creation

### 3.3 High-Risk Activity Rules
- New Global Admin assignments
- Service principal credential changes
- Partner/federation relationship modifications  
- First-time privileged role assignments

## 4. Mitigation Strategies

### Administrative Controls
- Implement Privileged Identity Management (PIM)
- Enable Conditional Access policies
- Require MFA for role changes
- Regular access reviews
- Monitor service principal permissions

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "displayName": "Require MFA for Admin Roles",
    "conditions": {
      "userRiskLevels": ["high"],
      "signInRiskLevels": ["medium", "high"],
      "applications": {
        "includeAdminPortals": true
      }
    },
    "grantControls": {
      "operator": "AND",
      "builtInControls": ["mfa"]
    }
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Alert on privileged role changes
- Monitor service principal activity
- Track cross-tenant access grants
- Regular access reviews

## 5. Incident Response

### Initial Detection
1. Identify affected accounts/roles
2. Review audit logs for role changes
3. Check for unauthorized admin accounts
4. Examine service principal modifications

### Investigation
1. Timeline suspicious role changes
2. Analyze authentication patterns
3. Review associated IP addresses
4. Check for additional compromised accounts
5. Examine cross-tenant relationships

### Containment
1. Remove unauthorized role assignments
2. Reset affected credentials
3. Revoke suspicious service principals
4. Remove unauthorized federation trusts
5. Enable stricter access controls

## 6. References

- [MITRE ATT&CK T1098.003](https://attack.mitre.org/techniques/T1098/003/)
- [Microsoft Identity Security](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/)
- [Azure AD Incident Response](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)
- [Unified Audit Logging](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance)

---

# Threat Model: Automated Collection (T1119) in Microsoft 365 & Entra ID

## Overview
Adversaries may leverage Microsoft 365 and Entra ID capabilities to automatically collect sensitive data through APIs, PowerShell scripts, and automated workflows. Key focus areas include:
- Cloud API-based collection via Microsoft Graph API
- PowerShell automation for bulk data access
- Service principal credential abuse for automated access
- Data pipeline and ETL service misuse

## Attack Vectors

### 1. Microsoft Graph API Mass Collection
**Description**: Adversaries use compromised service principal credentials to make bulk Microsoft Graph API calls to collect user data, emails, and files.

**Example Attack Flow**:
1. Attacker compromises service principal credentials
2. Creates automated script using Microsoft Graph SDK
3. Makes repeated API calls to enumerate and download data
4. Exfiltrates collected data to external storage

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Add service principal credentials",
    "FileDownloaded",
    "MailItemsAccessed",
    "FileSyncDownloadedFull"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T10:15:22",
  "Operation": "Add service principal credentials",
  "OrganizationId": "c7c3b358-7651-4423-a91c-9f79d9657647",
  "ClientIP": "198.51.100.1",
  "ObjectId": "ServicePrincipal_ea70b42f-6d89-4c28-ac9c-81d8735c82f8",
  "UserId": "attacker@victim.com",
  "ApplicationId": "d73f4b35-55c9-4c29-a6f9-f172b9ec9e8a"
}
```

### 2. PowerShell Exchange Online Collection
**Description**: Adversaries use Exchange Online PowerShell modules to automatically collect mailbox data and export PST files.

**Example Attack Flow**:
1. Attacker obtains admin credentials
2. Connects to Exchange Online PowerShell
3. Scripts automated mailbox enumeration and export
4. Downloads PST files containing mail data

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "MailItemsAccessed",
    "SearchExported",
    "SearchStarted",
    "ExportJob"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Operation": "SearchExported", 
  "Workload": "Exchange",
  "ObjectId": "Mailbox_26dde2aa-0164-4a8d-9a29-94c2486a6b42",
  "UserId": "admin@victim.com",
  "ClientIP": "198.51.100.2",
  "SearchQuery": "All_Items"
}
```

### 3. SharePoint Site Collection Enumeration
**Description**: Adversaries enumerate and download SharePoint site collections using automated PnP PowerShell scripts.

**Example Attack Flow**:
1. Attacker gains site collection admin access
2. Deploys PnP PowerShell automation script  
3. Recursively downloads all site content
4. Transfers data to external storage

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "FileDownloaded",
    "FileSyncDownloadedFull",
    "SearchQueryPerformed",
    "SiteCollectionAdminAdded"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:44:12",
  "Operation": "FileDownloaded",
  "SiteUrl": "/sites/Finance",
  "ObjectId": "Document_82aa7726-9c14-4f82-b0bd-a803a53cf65a",
  "UserId": "attacker@victim.com",
  "ClientIP": "198.51.100.3"
}
```

## Detection Strategies

### Behavioral Analytics Rules

```sql
-- Detect high-volume Microsoft Graph API requests
SELECT UserId, ClientIP, COUNT(*) as request_count
FROM AuditLogs 
WHERE Operation IN ('MailItemsAccessed', 'FileDownloaded')
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 100

-- Detect suspicious service principal credential additions
SELECT *
FROM AuditLogs
WHERE Operation = 'Add service principal credentials'
AND ClientIP NOT IN (known_admin_ips)
```

### Baseline Deviation Monitoring
- Track normal download volumes per user/app and alert on significant deviations
- Monitor typical working hours and flag off-hours automated collection
- Establish baselines for API request patterns and alert on anomalies

### Real-time Correlation Rules
```sql
-- Correlate admin actions with bulk downloads
SELECT a.UserId, a.ClientIP, COUNT(*) as download_count
FROM AuditLogs a
JOIN AuditLogs b ON a.UserId = b.UserId
WHERE a.Operation = 'SiteCollectionAdminAdded'
AND b.Operation = 'FileDownloaded'
AND b.TimeGenerated BETWEEN a.TimeGenerated AND dateadd(hour,1,a.TimeGenerated)
GROUP BY a.UserId, a.ClientIP
HAVING COUNT(*) > 50
```

## Technical Controls

```json
{
  "conditionalAccessPolicies": {
    "name": "Block Suspicious Downloads",
    "conditions": {
      "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
      "applications": {
        "includeApplications": ["Office365"]
      }
    },
    "controls": {
      "blockDownloads": true,
      "requireCompliantDevice": true
    }
  },
  "dlpPolicies": {
    "name": "Prevent Bulk Downloads",
    "rules": [
      {
        "condition": "DownloadCount > 100 per hour",
        "action": "Block"
      }
    ]
  }
}
```

## Administrative Controls
1. Implement least privilege access
2. Regular service principal credential rotation
3. Enable detailed audit logging
4. Configure alerts for suspicious download patterns
5. Deploy DLP policies to prevent bulk data transfers

## Monitoring Controls
1. Monitor service principal API usage patterns
2. Track download volumes across services
3. Alert on off-hours automated activities
4. Review admin activity correlation with bulk operations
5. Monitor PowerShell session activities

## References
- [MITRE T1119](https://attack.mitre.org/techniques/T1119/)
- [Microsoft Graph Security API](https://docs.microsoft.com/graph/security-concept-overview)
- [Exchange Online PowerShell](https://docs.microsoft.com/powershell/exchange/exchange-online-powershell)
- [SharePoint PnP PowerShell](https://docs.microsoft.com/powershell/sharepoint/sharepoint-pnp/sharepoint-pnp-cmdlets)

---

# Threat Model: Data from Cloud Storage (T1530) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries accessing sensitive data from cloud storage services in Microsoft 365, particularly SharePoint Online and OneDrive for Business. Attackers typically exploit misconfigurations, overly permissive sharing settings, or compromised credentials to access and exfiltrate data.

## 2. Attack Vectors

### 2.1 Excessive File Downloads
**Description**: Adversary uses compromised credentials to perform bulk downloads of files from SharePoint/OneDrive.

**Detection Fields**:
- Operation: FileDownloaded, FileSyncDownloadedFull
- UserAgent
- ClientIP
- UserId
- SiteUrl
- SourceFileName
- WorkspaceId

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "227322d0-4c48-9c82-1b4c-b2df236f137a",
  "Operation": "FileDownloaded",
  "OrganizationId": "b32f49a2-c5c4-4d46-8c8d-7f3c22d566b3",
  "RecordType": 4,
  "UserKey": "i:0h.f|membership|jane@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "OneDrive",
  "ClientIP": "198.51.100.45",
  "ObjectId": "https://contoso-my.sharepoint.com/personal/jane_contoso_com/Documents/Financial Reports/Q4-2023.xlsx",
  "UserId": "jane@contoso.com",
  "SourceFileName": "Q4-2023.xlsx",
  "SiteUrl": "/personal/jane_contoso_com"
}
```

### 2.2 Anonymous Link Access
**Description**: Attacker exploits overly permissive anonymous sharing links to access sensitive data.

**Detection Fields**:
- Operation: AnonymousLinkCreated, AnonymousLinkUsed
- LinkId 
- SiteUrl
- SourceFileName
- ClientIP
- UserAgent

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T15:43:12",
  "Id": "8a7b5d23-f429-41c8-a147-7a912e7c5319",
  "Operation": "AnonymousLinkUsed",
  "OrganizationId": "b32f49a2-c5c4-4d46-8c8d-7f3c22d566b3",
  "RecordType": 4,
  "UserType": 0,
  "Version": 1,
  "Workload": "SharePoint",
  "ClientIP": "203.0.113.22",
  "ObjectId": "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Payroll.xlsx",
  "LinkId": "uby7s62g9k3m",
  "SiteUrl": "/sites/Finance",
  "SourceFileName": "Payroll.xlsx"
}
```

### 2.3 Delegated Access Abuse
**Description**: Adversary adds delegated permissions to maintain persistent access to storage.

**Detection Fields**:
- Operation: "Add delegation entry.", "Set delegation entry."
- ObjectId
- UserId
- TargetUserOrGroupName
- TargetUserOrGroupType

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T09:12:44",
  "Id": "44c2b5dd-1e25-4c56-91c9-e4467d8afeb3",
  "Operation": "Add delegation entry.",
  "OrganizationId": "b32f49a2-c5c4-4d46-8c8d-7f3c22d566b3",
  "RecordType": 8,
  "UserKey": "i:0h.f|membership|admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "SharePoint",
  "ObjectId": "https://contoso.sharepoint.com/sites/HR",
  "UserId": "admin@contoso.com",
  "TargetUserOrGroupName": "external@malicious.com",
  "TargetUserOrGroupType": "Guest"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect bulk downloads
SELECT UserId, ClientIP, COUNT(*) as download_count
FROM CloudStorageAuditLogs 
WHERE Operation IN ('FileDownloaded','FileSyncDownloadedFull')
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 100;

-- Detect suspicious anonymous link access
SELECT LinkId, ClientIP, COUNT(*) as access_count
FROM CloudStorageAuditLogs
WHERE Operation = 'AnonymousLinkUsed'
AND TimeGenerated > ago(24h)
GROUP BY LinkId, ClientIP
HAVING COUNT(*) > 50;
```

### 3.2 Baseline Deviation Monitoring
- Track average daily download volumes per user
- Monitor typical working hours for file access
- Establish baseline for external sharing patterns
- Alert on deviations >3 standard deviations

### 3.3 Real-time Alert Rules
- Alert on sensitive file downloads from unmanaged devices
- Alert on anonymous link creation for sensitive sites
- Alert on delegation changes outside change control windows

## 4. Mitigation Strategies

### 4.1 Administrative Controls
1. Implement data loss prevention (DLP) policies
2. Configure conditional access policies
3. Enable sensitivity labels
4. Restrict anonymous sharing capabilities

### 4.2 Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "name": "Block Unmanaged Device Downloads",
    "conditions": {
      "applications": {
        "includeApplications": ["Office 365 SharePoint Online"]
      },
      "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
      "deviceStates": {
        "notIncludeDeviceStates": ["compliant", "domainJoined"]
      }
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }
}
```

### 4.3 Monitoring Controls
1. Enable unified audit logging
2. Configure alerts for sensitive content access
3. Implement CASB monitoring
4. Enable Microsoft Defender for Cloud Apps

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Identify affected storage locations
2. Determine scope of accessed data
3. Review authentication logs for compromised accounts

### 5.2 Investigation
1. Review audit logs for download patterns
2. Analyze sharing settings and permissions
3. Identify source IP addresses and user agents
4. Track data exfiltration volume

### 5.3 Containment
1. Revoke compromised credentials
2. Remove excessive permissions
3. Disable suspicious sharing links
4. Block suspicious IP addresses

## 6. References
- MITRE ATT&CK: T1530
- Microsoft Cloud App Security documentation
- Microsoft 365 Security Best Practices
- Azure Storage Security Guide

---

# Threat Model: Add-ins (T1137.006) in Microsoft 365 & Entra ID

## 1. Overview

Office add-ins provide a persistence mechanism in Microsoft 365 by allowing execution of code when Office applications start. The primary attack vectors involve:

- Installing malicious Office add-ins through service principals
- Modifying add-in permissions and delegations 
- Abusing add-in authentication and access tokens

## 2. Attack Vectors

### 2.1 Malicious Service Principal Registration

**Description:**
Adversaries create malicious service principals to register Office add-ins with extensive permissions.

**Attack Scenario:**
1. Attacker compromises admin account
2. Creates new service principal for malicious add-in
3. Grants extensive Microsoft Graph permissions
4. Add-in persists with delegated access

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Add service principal.",
    "Add service principal credentials.",
    "Add delegation entry."
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T10:15:22",
  "Id": "8932a5f2-1f8d-4c7a-9fb2-554aad819245",
  "Operation": "Add service principal.",
  "OrganizationId": "d124920a-10c3-428d-9e2a-c9f87c36f5e7",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "ObjectId": "8a432c9b-122b-4endpoints-9abc-76ed918a926e",
  "AppId": "a912b343-99c2-4def-a436-24680123abcd",
  "Target": [
    {
      "Type": "ServicePrincipal",
      "ID": "8a432c9b-122b-4endpoints-9abc-76ed918a926e" 
    }
  ]
}
```

### 2.2 Add-in Permission Abuse 

**Description:**
Adversaries modify existing add-in permissions to expand access.

**Attack Scenario:**
1. Attacker identifies existing legitimate add-in
2. Modifies delegation permissions
3. Add-in gains expanded access to tenant resources

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Set delegation entry.",
    "Update delegation permissions"
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T11:22:33",
  "Id": "7721c4e3-2e8d-5b9a-8dc3-665aad918246", 
  "Operation": "Set delegation entry.",
  "OrganizationId": "d124920a-10c3-428d-9e2a-c9f87c36f5e7",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "attacker@contoso.com",
  "ObjectId": "9b432c9b-122b-4endpoints-9abc-76ed918a926e",
  "ModifiedProperties": [
    {
      "Name": "Permissions",
      "OldValue": "Mail.Read",
      "NewValue": "Mail.ReadWrite,Files.ReadWrite.All"
    }
  ]
}
```

### 2.3 Add-in Token Theft

**Description:** 
Adversaries steal add-in authentication tokens for persistence.

**Attack Scenario:**
1. Attacker compromises endpoint with add-in access
2. Extracts stored add-in tokens
3. Uses tokens for persistent API access

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Add service principal credentials.",
    "Update service principal token"
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T14:55:12",
  "Id": "6543b2e1-9f7d-3c8a-7bc2-443ccd717134",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "d124920a-10c3-428d-9e2a-c9f87c36f5e7", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "attacker@contoso.com",
  "ObjectId": "7c432c9b-122b-4endpoints-9abc-76ed918a926e",
  "KeyType": "AsymmetricX509Cert",
  "DisplayName": "Add-in Auth Certificate"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
// Detect rapid add-in registration
LET threshold = 3;
LET timeWindow = 1h;
ServicePrincipalEvents
| where Operation == "Add service principal."
| summarize count() by UserKey, bin(TimeGenerated, timeWindow)
| where count_ > threshold

// Detect permission escalation
DelegationEvents  
| where Operation == "Set delegation entry."
| where NewValue contains "ReadWrite.All" 
| join ServicePrincipalEvents on ObjectId
| where TimeGenerated < 7d
```

### 3.2 Baseline Deviation Monitoring

- Monitor normal add-in registration patterns
- Alert on deviations in:
  - Registration volume
  - Permission changes
  - Token usage patterns

### 3.3 Technical Controls (JSON)

```json
{
  "addInControls": {
    "allowedPublishers": ["verified@contoso.com"],
    "requiredPermissions": {
      "minPermissionLevel": "ReadOnly",
      "requireAdminConsent": true
    },
    "tokenControls": {
      "maxTokenLifetime": "1h",
      "requireCertBasedAuth": true
    }
  }
}
```

## 4. Mitigation Strategies

### Administrative Controls
1. Implement add-in allowlisting
2. Require admin consent for permissions
3. Regular permission reviews
4. Enforce publisher verification

### Technical Controls
1. Enable enhanced add-in monitoring
2. Implement conditional access policies
3. Enforce token lifetime limits
4. Enable add-in risk assessment

### Monitoring Controls
1. Alert on suspicious add-in activities
2. Monitor permission changes
3. Track token usage patterns
4. Review add-in audit logs

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected add-ins
2. Review permission changes
3. Check token usage
4. Document timeline

### Investigation
1. Review audit logs
2. Analyze add-in code
3. Check API usage
4. Identify impact

### Containment
1. Disable suspicious add-ins
2. Revoke compromised tokens
3. Reset affected permissions
4. Block malicious publishers

## 6. References

- [MITRE ATT&CK T1137.006](https://attack.mitre.org/techniques/T1137/006/)
- [Microsoft Office Add-ins Documentation](https://docs.microsoft.com/en-us/office/dev/add-ins/)
- [Microsoft 365 Defender Add-in Security](https://docs.microsoft.com/en-us/microsoft-365/security/)

---

# Threat Model: Outlook Rules (T1137.005) in Microsoft 365 & Entra ID

## 1. Overview

Adversaries can abuse Outlook rules in Microsoft 365 for persistence and data exfiltration by creating malicious rules that:
- Forward emails to external addresses
- Move/delete security alerts and audit notifications 
- Execute malicious code via custom forms
- Hide evidence of compromise

## 2. Attack Vectors

### 2.1 External Email Forwarding Rules

**Description**:
Adversaries create rules to automatically forward emails to external addresses for data exfiltration.

**Audit Operations**:
- New-InboxRule
- Set-InboxRule
- UpdateInboxRules

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "14c789f3-9f71-4340-8625-5a23c5c91f3a",
  "Operation": "New-InboxRule",
  "OrganizationId": "d124f588-18c9-4a9c-89df-6946099da020",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "johndoe@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "Forward All to External",
  "Parameters": [
    {
      "Name": "ForwardTo",
      "Value": "attacker@evil.com"
    },
    {
      "Name": "Enabled", 
      "Value": "True"
    }
  ]
}
```

### 2.2 Security Alert Suppression Rules

**Description**: 
Rules created to move/delete security alerts and audit notifications.

**Audit Operations**:
- Set-InboxRule
- UpdateInboxRules 

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Operation": "Set-InboxRule",
  "UserKey": "johndoe@company.com",
  "Parameters": [
    {
      "Name": "MoveToFolder",
      "Value": "Deleted Items"
    },
    {
      "Name": "SubjectContainsWords",
      "Value": "Security alert;Unusual sign-in;Suspicious"
    }
  ]
}
```

### 2.3 Mass Rule Creation

**Description**:
Bulk creation of rules to establish persistence across multiple mailboxes.

**Audit Operations**:
- New-InboxRule
- UpdateInboxRules

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T14:00:00", 
  "Operation": "UpdateInboxRules",
  "UserKey": "admin@company.com",
  "Parameters": [
    {
      "Name": "Identity",
      "Value": "Multiple Users"
    },
    {
      "Name": "Force",
      "Value": "True" 
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect mass rule creation
SELECT UserKey, COUNT(*) as rule_count
FROM AuditLogs 
WHERE Operation IN ('New-InboxRule','UpdateInboxRules')
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING COUNT(*) > 10

-- Detect suspicious forwarding rules
SELECT *
FROM AuditLogs
WHERE Operation = 'New-InboxRule'
AND Parameters.Name = 'ForwardTo'
AND Parameters.Value LIKE '%@%.%'
AND Parameters.Value NOT LIKE '%@company.com'
```

### 3.2 Baseline Deviations
- Monitor for spikes in rule creation frequency
- Track unusual times of rule modifications
- Alert on rules created outside business hours
- Detect anomalous rule creators

### 3.3 Thresholds
- More than 5 rules created per user per hour
- Rules affecting more than 10 mailboxes in 24 hours
- More than 3 forwarding rules to external domains
- Rules moving/deleting more than 50 items per day

## 4. Mitigation Controls

### Administrative Controls
```json
{
  "allowExternalForwarding": false,
  "requireApprovalForExternalRules": true,
  "maximumRulesPerUser": 50,
  "restrictedRuleKeywords": [
    "security alert",
    "unusual activity",
    "suspicious"
  ]
}
```

### Technical Controls
- Disable external email forwarding
- Require MFA for rule changes
- Block mass rule creation
- Log all rule modifications

### Monitoring Controls
- Real-time alerts on suspicious rules
- Weekly review of forwarding rules
- Automated rule inventory reports
- Compliance auditing of rule changes

## 5. IR Playbook

1. Initial Detection
   - Identify affected mailboxes
   - Document rule configurations
   - Preserve audit logs

2. Investigation
   - Review rule creation patterns
   - Check for other compromised accounts
   - Analyze forwarded email content
   - Track rule creator activity

3. Containment
   - Disable suspicious rules
   - Block external forwarding
   - Reset compromised credentials
   - Enable additional monitoring

## References
- MITRE ATT&CK: T1137.005
- Microsoft: Inbox Rules in Exchange Online
- Security Guidance: Outlook Protection Best Practices

---

# Threat Model: Impair Defenses (T1562) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries commonly attempt to disable or modify security controls and logging mechanisms to evade detection. Key targets include:

- Audit log settings and retention policies
- Security alert notifications 
- Compliance and DLP policies
- Multi-factor authentication settings
- Conditional Access policies

## 2. Attack Vectors

### 2.1 Disable Audit Logging

**Description:**
Adversaries may disable audit logging or modify retention settings to hide their activities.

**Attack Scenario:**
1. Attacker compromises Global Admin account
2. Disables audit log collection via PowerShell or admin portal
3. Performs malicious activities without generating logs
4. Re-enables logging to avoid detection

**Detection Fields:**
```json
{
  "Operation": "Set-AdminAuditLogConfig",
  "ResultStatus": "Success",
  "Parameters": {
    "UnifiedAuditLogIngestionEnabled": "False",
    "AdminAuditLogEnabled": "False"
  },
  "UserId": "admin@contoso.com",
  "ClientIP": "192.168.1.100"
}
```

### 2.2 Modify Alert Notifications

**Description:** 
Adversaries disable or modify security alert notifications to prevent defenders from being notified of suspicious activities.

**Attack Scenario:**
1. Attacker accesses Security & Compliance portal
2. Modifies alert policies to disable notifications
3. Changes alert recipients to non-monitored addresses

**Detection Fields:**
```json
{
  "Operation": "NotificationConfigurationUpdated",
  "ObjectId": "AlertPolicy_HighSeverity",
  "ModifiedProperties": [
    {
      "Name": "Enabled",
      "OldValue": "True",
      "NewValue": "False"
    },
    {
      "Name": "NotificationRecipients",
      "OldValue": "security@contoso.com",
      "NewValue": "unused@contoso.com"
    }
  ]
}
```

### 2.3 Disable MFA & Conditional Access

**Description:**
Adversaries may disable or modify authentication controls to maintain access.

**Attack Scenario:**
1. Attacker gains admin access
2. Disables MFA for targeted accounts
3. Modifies Conditional Access policies
4. Creates authentication policy exclusions

**Detection Fields:**
```json
{
  "Operation": "Update-MsolUser",
  "Target": "victim@contoso.com", 
  "ModifiedProperties": [
    {
      "Name": "StrongAuthenticationRequirements",
      "OldValue": "Enabled",
      "NewValue": "Disabled"
    }
  ],
  "ActorId": "admin@contoso.com"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect rapid policy changes
SELECT UserId, Operation, COUNT(*) as changes
FROM AuditLogs 
WHERE Operation IN (
  'Set-AdminAuditLogConfig',
  'NotificationConfigurationUpdated',
  'Update-MsolUser'
)
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING COUNT(*) > 5;

-- Alert on audit log disablement
SELECT * 
FROM AuditLogs
WHERE Operation = 'Set-AdminAuditLogConfig'
AND Parameters.UnifiedAuditLogIngestionEnabled = 'False';
```

### 3.2 Baseline Deviations

- Monitor rate of policy changes against historical baseline
- Alert on spikes in security control modifications
- Track unusual patterns in admin activity times
- Detect anomalous source IP addresses for admin actions

### 3.3 Time Windows

- Alert on multiple control changes within short time periods (e.g., 5+ changes in 10 minutes)
- Monitor for after-hours administrative activities
- Track duration between disable/enable operations

## 4. Mitigation Strategies

### 4.1 Administrative Controls

```json
{
  "privilegedRoleSettings": {
    "requireMFA": true,
    "approvalRequired": true,
    "maxActivationDuration": "PT8H",
    "requireJustification": true
  },
  "auditSettings": {
    "retentionDays": 365,
    "mandatoryRecording": true
  }
}
```

### 4.2 Technical Controls

- Implement Privileged Identity Management (PIM)
- Enable Conditional Access for admin accounts
- Configure Alert Policies for critical changes
- Use service principals with limited permissions

### 4.3 Monitoring Controls

- Real-time alerts for security control changes
- Daily review of admin activity logs
- Weekly audit of security configurations
- Automated compliance checks

## 5. Incident Response Playbook

### 5.1 Initial Detection

1. Validate alert authenticity
2. Identify affected controls/policies
3. Document timeline of changes
4. Preserve audit logs

### 5.2 Investigation

1. Review admin activity logs
2. Analyze authentication patterns
3. Check for additional compromised accounts
4. Document policy state changes

### 5.3 Containment

1. Revoke active sessions
2. Reset affected admin accounts
3. Restore security controls
4. Block suspicious IPs

## 6. References

- [MITRE T1562](https://attack.mitre.org/techniques/T1562/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Entra ID Audit Log Schema](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities)

This threat model provides actionable guidance for detecting and responding to defense evasion techniques in Microsoft 365 and Entra ID environments. Regular updates and testing of detection rules and response procedures is recommended.

---

# Threat Model: Exfiltration Over Web Service (T1567) in Microsoft 365 & Entra ID

## 1. Overview
This technique involves adversaries abusing legitimate cloud services to exfiltrate data from Microsoft 365 environments, particularly targeting Exchange Online, SharePoint Online, and OneDrive for Business. The abuse of legitimate services makes detection challenging since these are commonly used business applications.

## 2. Attack Vectors

### 2.1 OAuth Application Abuse
**Description**: Adversaries register malicious OAuth applications to gain delegated access for data exfiltration.

**Audit Operations**:
```json
{
  "Add service principal.",
  "Add service principal credentials.",
  "Add delegation entry."
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "8912e432-5c32-4f21-b8c9-d29441b88f16",
  "Operation": "Add service principal.",
  "OrganizationId": "12a34567-89b0-12c3-d4e5-f67890123456",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "ObjectId": "ServicePrincipal_ea123b4c-5d6e-7f89-0a1b-2c3d4e5f6789",
  "AppId": "a1b2c3d4-e5f6-7890-a1b2-c3d4e5f67890",
  "PermissionScopes": ["Mail.Read", "Files.Read.All"]
}
```

### 2.2 SharePoint Data Exfiltration
**Description**: Mass downloading of SharePoint/OneDrive content through web interfaces.

**Audit Operations**:
```json
{
  "FileDownloaded",
  "FileSyncDownloadedFull",
  "SearchExported"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:45:12",
  "Operation": "FileDownloaded",
  "OrganizationId": "12a34567-89b0-12c3-d4e5-f67890123456",
  "UserType": 0,
  "UserKey": "user@contoso.com",
  "Workload": "SharePoint",
  "ObjectId": "https://contoso.sharepoint.com/sites/finance/documents/budget2024.xlsx",
  "ClientIP": "198.51.100.234",
  "FileSize": "2456433"
}
```

### 2.3 Email Export Operations
**Description**: Unauthorized export of mailbox content via PowerShell or Outlook.

**Audit Operations**:
```json
{
  "MailItemsAccessed",
  "New-ComplianceSearchAction",
  "SearchExported"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T14:22:31",
  "Operation": "New-ComplianceSearchAction",
  "Workload": "Exchange",
  "ObjectId": "mailbox@contoso.com",
  "Parameters": [{
    "Name": "SearchName",
    "Value": "Export_All_2024"
  }],
  "ResultStatus": "Success"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect mass downloads from SharePoint
SELECT UserKey, COUNT(*) as download_count
FROM AuditLogs 
WHERE Operation IN ('FileDownloaded', 'FileSyncDownloadedFull')
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING COUNT(*) > 100;

-- Detect suspicious OAuth app registrations
SELECT Operation, UserKey, AppId, PermissionScopes
FROM AuditLogs
WHERE Operation = "Add service principal."
AND PermissionScopes CONTAINS 'Mail.Read' 
AND PermissionScopes CONTAINS 'Files.Read.All';
```

### 3.2 Baseline Deviation Monitoring
- Track normal download volumes per user/department
- Monitor typical working hours for export operations
- Establish baseline for OAuth application registration frequency

### 3.3 Technical Controls (JSON)
```json
{
  "oauth_app_restrictions": {
    "require_admin_consent": true,
    "blocked_permissions": [
      "Mail.Read.All",
      "Files.Read.All",
      "Mail.Export"
    ],
    "allowed_publishers": ["verified_publishers_only"]
  },
  "sharepoint_controls": {
    "download_limits": {
      "max_files_per_hour": 100,
      "max_size_per_hour_mb": 500
    },
    "allowed_ip_ranges": [
      "10.0.0.0/8",
      "172.16.0.0/12"
    ]
  }
}
```

## 4. Mitigation Strategies

### Administrative Controls
1. Implement Conditional Access policies restricting data downloads
2. Enable admin consent requirements for OAuth apps
3. Configure DLP policies to detect sensitive data exfiltration

### Technical Controls
1. Block third-party email forwarding
2. Enable SharePoint download throttling
3. Implement Microsoft Defender for Cloud Apps policies

### Monitoring Controls
1. Enable Unified Audit Logging
2. Configure alerts for mass download events
3. Monitor OAuth application permissions

## 5. Incident Response Steps

1. Initial Detection
   - Review audit logs for mass download patterns
   - Identify affected accounts and resources
   - Document timeline of events

2. Investigation
   - Analyze OAuth application permissions
   - Review exported data content and volume
   - Identify source IP addresses and user agents

3. Containment
   - Revoke suspicious OAuth tokens
   - Block compromised accounts
   - Implement additional download restrictions

## 6. References
- MITRE ATT&CK: T1567
- Microsoft: Detect and Remediate Illicit Consent Grants
- Microsoft: SharePoint Online Security Best Practices

---

# Threat Model: Unsecured Credentials (T1552) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries search for and exploit credentials stored in various locations including:
- Service principal credentials
- Application secrets and certificates
- Delegated permissions and OAuth grants
- Stored connection strings and configuration files
- SharePoint/OneDrive documents containing credentials

## 2. Attack Vectors

### 2.1 Service Principal Credential Access

**Description:**
Adversaries enumerate service principals and their credentials to gain persistent access to applications and services.

**Attack Scenario:**
1. Attacker gains initial access through compromised admin account
2. Uses Microsoft Graph API to list service principals
3. Downloads/extracts stored credentials and certificates
4. Uses credentials to authenticate as the application

**Detection Fields:**
```json
{
  "Operations": [
    "Add service principal credentials.",
    "Remove service principal credentials.",
    "Add service principal."
  ],
  "Key Fields": {
    "ObjectId": "Service principal ID",
    "Target": "Application details",
    "Actor": "User performing action",
    "CredentialType": "Password/Certificate",
    "StartTime": "Timestamp"
  }
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "4894sdf-23fs-4467-b9f0-124087count",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "ObjectId": "8721aasd-99df-4123-b9c1-23409app",
  "Target": [
    {
      "Type": 2,
      "ID": "ServicePrincipal_8721aasd-99df-4123-b9c1-23409app"
    }
  ],
  "Actor": [
    {
      "ID": "admin@company.com",
      "Type": 5
    }
  ],
  "CredentialType": "Password"
}
```

### 2.2 OAuth Grant Abuse

**Description:**
Adversaries examine and manipulate OAuth permission grants to gain unauthorized access to resources.

**Attack Scenario:**
1. Attacker reviews existing OAuth grants
2. Identifies high-privilege grants
3. Creates new grants or modifies existing ones
4. Uses granted permissions to access resources

**Detection Fields:**
```json
{
  "Operations": [
    "Add delegation entry.",
    "Set delegation entry.",
    "Remove delegation entry."
  ],
  "Key Fields": {
    "Operation": "Grant action",
    "TargetResources": "Affected resources",
    "Permission": "Granted permissions",
    "UserId": "Affected user",
    "AppId": "Application ID"
  }
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Operation": "Add delegation entry.",
  "ResultStatus": "Success",
  "TargetResources": [
    {
      "Type": "User",
      "Id": "user@company.com" 
    },
    {
      "Type": "Application",
      "Id": "ab432-myapp-789"
    }
  ],
  "Permission": "Mail.Read",
  "InitiatedBy": {
    "user": {
      "id": "admin@company.com"
    }
  }
}
```

### 2.3 SharePoint Document Scanning

**Description:**
Adversaries search SharePoint/OneDrive documents for stored credentials and secrets.

**Attack Scenario:**
1. Attacker gains access to SharePoint
2. Uses search functionality to find documents with credentials
3. Downloads or extracts credential information
4. Uses discovered credentials to expand access

**Detection Fields:**
```json
{
  "Operations": [
    "FileDownloaded",
    "SearchQueryPerformed",
    "FileAccessed"
  ],
  "Key Fields": {
    "Operation": "Action performed",
    "SourceFileName": "File name",
    "SourceRelativeUrl": "File location",
    "UserAgent": "Client application",
    "ClientIP": "Source IP"
  }
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T18:33:41",
  "Operation": "FileDownloaded",
  "Site": "/sites/IT-Department",
  "SourceFileName": "ServerCredentials.xlsx",
  "SourceRelativeUrl": "/sites/IT-Department/Shared Documents/Config/",
  "UserAgent": "Mozilla/5.0...",
  "ClientIP": "12.34.56.78",
  "UserId": "user@company.com"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect mass service principal credential access
SELECT Actor, COUNT(*) as access_count
FROM AuditLogs 
WHERE Operation IN ('Add service principal credentials.', 'Remove service principal credentials.')
AND TimeGenerated > ago(1h)
GROUP BY Actor
HAVING COUNT(*) > 10;

-- Detect suspicious OAuth grant patterns
SELECT InitiatedBy.user.id, COUNT(*) as grant_count
FROM AuditLogs
WHERE Operation = 'Add delegation entry.'
AND TimeGenerated > ago(24h)
GROUP BY InitiatedBy.user.id
HAVING COUNT(*) > 5;

-- Monitor document access patterns
SELECT UserId, ClientIP, COUNT(*) as download_count
FROM AuditLogs
WHERE Operation = 'FileDownloaded'
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 20;
```

### 3.2 Baseline Deviation Monitoring

- Track normal service principal credential rotation patterns
- Monitor typical OAuth grant creation frequency
- Establish baseline for document access patterns per user/department

### 3.3 Key Risk Indicators

1. Service Principal Access:
   - >5 credential additions per hour per user
   - Credential access outside business hours
   - Multiple credential removals in short timeframe

2. OAuth Grants:
   - High-privilege grants created by non-admin users
   - Grants created outside normal provisioning process
   - Multiple grants created in short succession

3. Document Access:
   - Mass downloads of configuration files
   - Search queries containing credential-related terms
   - Access to sensitive documents from unusual locations

## 4. Mitigation Strategies

### 4.1 Administrative Controls

1. Implement strict service principal credential management:
   - Require approval for credential creation
   - Regular credential rotation
   - Audit of unused credentials

2. OAuth governance:
   - Restrict permission grant capability
   - Regular review of existing grants
   - Block high-risk permissions

3. Document controls:
   - Data classification for sensitive files
   - DLP policies for credential content
   - Access reviews for sensitive locations

### 4.2 Technical Controls

```json
{
  "ConditionalAccessPolicies": {
    "ServicePrincipalAccess": {
      "RequireMFA": true,
      "AllowedLocations": ["Corporate Network"],
      "BlockLegacyAuth": true
    },
    "DocumentAccess": {
      "RequireCompliantDevice": true,
      "RequireMFA": true
    }
  },
  "DLPPolicies": {
    "CredentialContent": {
      "Patterns": ["password=*", "secret=*", "connectionString=*"],
      "Actions": ["Block", "Notify", "Encrypt"]
    }
  }
}
```

### 4.3 Monitoring Controls

1. Real-time alerts:
   - Service principal credential changes
   - New OAuth grants with elevated permissions
   - Mass document downloads

2. Periodic reviews:
   - Service principal credential inventory
   - OAuth grant audit
   - Document access patterns

## 5. Response Playbook

### 5.1 Initial Detection

1. Identify affected resources:
   ```powershell
   Get-AzureADAuditDirectoryLogs -Filter "activity eq 'Add service principal credentials.'"
   ```

2. Assess scope:
   - List all accessed service principals
   - Review OAuth grants created
   - Identify accessed documents

### 5.2 Investigation

1. Timeline analysis:
   - Map credential access events
   - Correlate with other suspicious activity
   - Review authentication logs

2. Impact assessment:
   - Document compromised credentials
   - List affected applications
   - Identify data exposure

### 5.3 Containment

1. Immediate actions:
   ```powershell
   # Remove compromised credentials
   Remove-AzureADApplicationKeyCredential -ObjectId $appId -KeyId $keyId
   
   # Revoke OAuth grants
   Remove-AzureADOAuth2PermissionGrant -ObjectId $grantId
   ```

2. Additional steps:
   - Block suspicious IP addresses
   - Implement additional monitoring
   - Review and adjust access controls

## 6. References

- [MITRE ATT&CK T1552](https://attack.mitre.org/techniques/T1552/)
- [Microsoft Graph Security API](https://docs.microsoft.com/graph/security-concept-overview)
- [Azure AD Audit Log Schema](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities)

---

# Threat Model: Clear Mailbox Data (T1070.008) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries deleting or manipulating mailbox data to remove evidence of malicious activities in Microsoft 365. Key objectives include:

- Removing evidence of phishing or data exfiltration attempts
- Deleting audit logs of mailbox exports
- Modifying mail transport rules to bypass security controls
- Erasing traces of email collection activities

## 2. Attack Vectors

### 2.1 Mailbox Export Deletion

**Description:**
Adversaries use Exchange PowerShell to delete mailbox export requests, removing evidence of data exfiltration.

**Attack Scenario:**
1. Attacker compromises admin credentials
2. Performs large mailbox export 
3. Uses Remove-MailboxExportRequest to delete export evidence

**Relevant Audit Operations:**
- Remove-ComplianceSearchAction
- Remove-MailboxExportRequest
- SearchExported

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:33",
  "Id": "2b198749-0565-4ec5-9af9-eb948c6de8b1",
  "Operation": "Remove-ComplianceSearchAction",
  "OrganizationId": "0fd7659f-6a48-4863-9349-4091e965",
  "RecordType": 1,
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "SearchAction_01232024",
  "UserId": "admin@contoso.com",
  "ExportType": "MailboxExport",
  "ClientIP": "192.168.1.100",
  "ResultStatus": "Success"
}
```

### 2.2 Email Deletion Patterns

**Description:**
Adversaries bulk delete emails to remove traces of phishing or malicious communications.

**Attack Scenario:**
1. Attacker gains access to compromised mailbox
2. Uses Exchange PowerShell to mass delete messages
3. Purges items from Recoverable Items folder

**Relevant Audit Operations:**
- HardDelete
- SoftDelete 
- MoveToDeletedItems

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T16:15:22",
  "Id": "8a91b5d4-2034-4abc-a33c-76f2b8232c1a", 
  "Operation": "HardDelete",
  "OrganizationId": "0fd7659f-6a48-4863-9349-4091e965",
  "RecordType": 2,
  "UserKey": "compromised.user@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "/folder/inbox/message/1234",
  "ClientIP": "10.1.1.100",
  "ResultStatus": "Success",
  "ItemCount": 150
}
```

### 2.3 Transport Rule Manipulation

**Description:**
Adversaries modify mail flow rules to prevent logging of suspicious emails.

**Attack Scenario:**
1. Attacker creates transport rules
2. Rules bypass security scanning for specific senders/content
3. Deletes rule audit logs

**Relevant Audit Operations:**
- Set-TransportRule
- Remove-TransportRule
- New-TransportRule

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T14:33:21",
  "Id": "9c4f2259-5671-4ced-9f2b-c8a51892ee3a",
  "Operation": "Set-TransportRule", 
  "OrganizationId": "0fd7659f-6a48-4863-9349-4091e965",
  "RecordType": 1,
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "Bypass Scanning Rule",
  "Parameters": [
    {"Name": "State", "Value": "Enabled"},
    {"Name": "Priority", "Value": "0"},
    {"Name": "BypassSpamFiltering", "Value": "True"}
  ],
  "ResultStatus": "Success"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics

```sql
-- Detect suspicious bulk email deletions
SELECT UserId, COUNT(*) as DeleteCount
FROM AuditLogs 
WHERE Operation IN ('HardDelete','SoftDelete')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 100

-- Alert on transport rule modifications outside business hours
SELECT * FROM AuditLogs
WHERE Operation LIKE '%TransportRule%'
AND TimeGenerated NOT BETWEEN 
  time(9:00) AND time(17:00)
```

### 3.2 Baseline Deviations

- Monitor normal patterns of mailbox export operations
- Track typical email deletion volumes per user
- Establish baseline for transport rule changes
- Alert on anomalous spikes or out-of-hours activity

### 3.3 Critical Combinations

```sql
-- Detect export followed by log deletion
SELECT * FROM AuditLogs
WHERE UserId in (
  SELECT UserId FROM AuditLogs 
  WHERE Operation = 'New-MailboxExportRequest'
  AND TimeGenerated > ago(1h)
)
AND Operation = 'Remove-ComplianceSearchAction'
AND TimeGenerated > ago(1h)
```

## 4. Mitigation Controls

### Administrative Controls
- Implement least privilege access
- Require MFA for admin accounts
- Regular access reviews
- Separation of duties for export operations

### Technical Controls
```json
{
  "mailboxAuditEnabled": true,
  "retentionPeriod": 365,
  "auditedOperations": [
    "HardDelete",
    "SoftDelete", 
    "Move",
    "UpdateInboxRules",
    "UpdateCalendarDelegation"
  ],
  "transportRuleControls": {
    "requireApproval": true,
    "auditingEnabled": true,
    "changeNotification": true
  }
}
```

### Monitoring Controls
- Real-time alerts on critical operations
- Daily review of admin activities
- Weekly audit log analysis
- Monthly access pattern review

## 5. Incident Response Playbook

### Initial Detection
1. Review unified audit logs
2. Identify affected mailboxes
3. Document scope of deletions
4. Preserve available forensic data

### Investigation
1. Analyze patterns of deleted content
2. Review authentication logs
3. Check for unauthorized mailbox access
4. Examine transport rule changes

### Containment
1. Suspend compromised accounts
2. Restore deleted items where possible
3. Reset admin credentials
4. Remove malicious transport rules

## 6. References

- [MITRE ATT&CK T1070.008](https://attack.mitre.org/techniques/T1070/008/)
- [Microsoft Exchange Audit Logging](https://docs.microsoft.com/exchange/policy-and-compliance/mailbox-audit-logging/mailbox-audit-logging)
- [Office 365 Management Activity API](https://docs.microsoft.com/office/office-365-management-api/office-365-management-activity-api-reference)

---

# Threat Model: Exfiltration Over Webhook (T1567.004) in Microsoft 365 & Entra ID

## Overview
Adversaries may configure webhooks in Microsoft 365 services to automatically exfiltrate data to external endpoints. This allows them to bypass traditional network monitoring by leveraging legitimate business integration features.

## Attack Vectors

### 1. Microsoft Teams Webhook Abuse
**Description**: Adversaries create outbound webhooks in Teams channels to automatically forward messages and files to external endpoints.

**Attack Flow**:
1. Attacker gains access to Teams admin role
2. Creates webhook connector in target channel
3. Configures webhook URL to adversary-controlled endpoint
4. Channel content is automatically forwarded

**Relevant Audit Events**:
```json
{
  "Operation": "ConnectorAdded",
  "Workload": "MicrosoftTeams",
  "ObjectId": "<TeamId>",
  "UserId": "<UserId>",
  "ConnectorType": "Outgoing Webhook",
  "ConnectorName": "Data Integration",
  "WebhookUrl": "https://malicious-endpoint.com/webhook"
}
```

### 2. SharePoint Flow Exfiltration
**Description**: Adversaries create Power Automate flows to automatically copy SharePoint documents to external services.

**Attack Flow**:
1. Attacker compromises user account with Flow creation rights 
2. Creates flow triggered on document changes
3. Configures HTTP POST action to external endpoint
4. Documents are automatically exfiltrated

**Relevant Audit Events**:
```json
{
  "Operation": "WorkflowModified", 
  "Workload": "SharePoint",
  "ObjectId": "<SiteId>",
  "UserId": "<UserId>",
  "FlowName": "Document Sync",
  "TriggerType": "When a file is modified",
  "ActionType": "HTTP",
  "TargetUrl": "https://exfil-point.com/documents"
}
```

### 3. Exchange Mail Forwarding Rules
**Description**: Adversaries create inbox rules to automatically forward emails to external webhook endpoints.

**Attack Flow**:
1. Attacker gains access to mailbox
2. Creates forwarding rule via Graph API
3. Configures rule to send to webhook URL
4. Emails automatically forwarded

**Relevant Audit Events**:
```json
{
  "Operation": "New-InboxRule",
  "Workload": "Exchange",
  "UserId": "<UserId>",
  "RuleName": "External Forward",
  "ForwardTo": "https://collection.evil.com/mail",
  "Conditions": "All messages"
}
```

## Detection Strategies

### Behavioral Analytics
- Monitor creation of new webhook endpoints and connectors
- Track volume and timing of data transfers to webhooks
- Baseline normal webhook usage patterns per user/team
- Alert on unusual webhook destinations or data volumes

### Correlation Rules
```sql
-- Detect suspicious webhook creation
SELECT UserId, Count(*) as WebhookCount 
FROM AuditLog
WHERE Operation IN ('ConnectorAdded','New-InboxRule')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING Count(*) > 3;

-- Alert on data volume anomalies
SELECT WebhookUrl, Sum(DataSize) as TransferVolume
FROM WebhookActivity 
WHERE TimeGenerated > ago(24h)
GROUP BY WebhookUrl
HAVING Sum(DataSize) > 100MB;
```

## Mitigation Controls

### Administrative
- Restrict webhook creation to approved users
- Maintain allowlist of approved webhook endpoints
- Require business justification for new webhooks
- Regular review of existing webhooks

### Technical Controls
```json
{
  "webhookPolicy": {
    "allowedDomains": [
      "*.company.com",
      "*.approved-vendor.com"
    ],
    "maxDataTransfer": "50MB",
    "requireApproval": true,
    "auditLevel": "Verbose"
  }
}
```

### Monitoring
- Enable detailed webhook audit logging
- Monitor webhook creation and modification events
- Track data transfers to webhook endpoints
- Alert on unauthorized domains/endpoints

## Incident Response

### Initial Detection
1. Review webhook creation audit logs
2. Identify unauthorized webhook endpoints
3. Calculate volume of data transferred
4. Determine affected systems/data

### Investigation
1. Map timeline of webhook activity
2. Identify compromised accounts
3. Review data transferred via webhooks
4. Document external endpoints

### Containment
1. Disable suspicious webhooks
2. Block unauthorized endpoints
3. Reset compromised credentials
4. Update webhook allow lists

## References
- MITRE ATT&CK: T1567.004
- Microsoft Webhook Security Guidelines
- Teams Webhook Documentation
- SharePoint Flow Security Best Practices

The model focuses on Microsoft 365-specific implementations while providing actionable detection and response guidance.

---

# Threat Model: Email Account Discovery (T1087.003) in Microsoft 365 & Entra ID

## Overview
Adversaries attempt to enumerate email accounts and address lists in Microsoft 365 environments through PowerShell cmdlets, Exchange Admin Center access, and address list exports. This aids in reconnaissance and targeting for further attacks.

## Attack Vectors

### 1. PowerShell Global Address List Enumeration
**Description**: Adversaries use Exchange PowerShell cmdlets like Get-GlobalAddressList to dump email addresses.

**Scenario**: 
- Attacker compromises admin credentials
- Connects to Exchange Online PowerShell
- Executes GAL enumeration cmdlets
- Exports results for target identification

**Detection Fields**:
```json
{
  "Operation": "Get-GlobalAddressList",
  "UserType": "Admin",
  "ClientIP": "<ip_address>",
  "ClientInfoString": "ExchangePowerShell",
  "ResultStatus": "Success"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:33",
  "Id": "b12345-c123-4567-89ab-12345678",
  "Operation": "Get-GlobalAddressList", 
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "UserType": "Admin",
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "168.22.33.44",
  "UserId": "admin@contoso.com",
  "ClientInfoString": "ExchangePowerShell/8.0",
  "Parameters": "AddressList:GAL"
}
```

### 2. Exchange Admin Center Access List Export
**Description**: Adversaries access the Exchange Admin Center to export address lists directly through the web interface.

**Detection Fields**:
```json
{
  "Operation": "AddressListExport", 
  "LogonType": "WebExchange",
  "ClientApplication": "Browser",
  "ItemType": "AddressList"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "c98765-d123-4567-89ab-12345678",
  "Operation": "AddressListExport",
  "OrganizationId": "contoso.onmicrosoft.com", 
  "RecordType": 3,
  "ResultStatus": "Success",
  "UserKey": "user@contoso.com",
  "Workload": "Exchange",
  "ClientIP": "172.16.44.55",
  "UserId": "user@contoso.com",
  "ClientApplication": "Browser/Chrome",
  "ItemType": "AddressList",
  "ListType": "Global"
}
```

### 3. Delegated Access Email Enumeration
**Description**: Adversaries abuse delegated application permissions to enumerate email addresses through Microsoft Graph API.

**Detection Fields**:
```json
{
  "Operation": "Add delegation entry",
  "ObjectId": "ServicePrincipal",
  "TargetResources": "Mail.Read",
  "ActorIPAddress": "<ip_address>"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T17:33:12",
  "Id": "d55555-e123-4567-89ab-12345678",
  "Operation": "Add delegation entry",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "ObjectId": "ServicePrincipal_12345",
  "UserId": "app@contoso.com",
  "ActorIPAddress": "192.168.1.100",
  "TargetResources": [
    {
      "Type": "ServicePrincipal",
      "Permissions": ["Mail.Read"]
    }
  ]
}
```

## Detection Strategies

### Behavioral Analytics
```sql
-- Detect rapid GAL enumeration
SELECT UserID, COUNT(*) as query_count
FROM ExchangeAuditLog 
WHERE Operation = 'Get-GlobalAddressList'
AND TimeGenerated > ago(1h)
GROUP BY UserID
HAVING COUNT(*) > 3;

-- Monitor address list exports
SELECT ClientIP, COUNT(*) as export_count
FROM ExchangeAuditLog
WHERE Operation = 'AddressListExport' 
AND TimeGenerated > ago(24h)
GROUP BY ClientIP
HAVING COUNT(*) > 2;
```

### Baseline Deviations
- Monitor for abnormal PowerShell usage patterns
- Track unusual times/frequencies of address list access
- Alert on spikes in export operations

## Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "name": "Block Exchange PowerShell",
    "conditions": {
      "applications": ["Exchange PowerShell"],
      "users": ["all"],
      "locations": ["untrusted"]
    },
    "grantControls": {
      "block": true
    }
  },
  "auditingPolicy": {
    "operations": [
      "Get-GlobalAddressList",
      "AddressListExport",
      "Add delegation entry"
    ],
    "retention": "180 days"
  }
}
```

## Administrative Controls
1. Implement least privilege access
2. Enable Modern Authentication
3. Configure Conditional Access policies
4. Enable detailed Exchange auditing
5. Review service principal permissions regularly

## Monitoring Controls
1. Configure alerts for:
   - Multiple GAL queries in short timeframe
   - Address list exports outside business hours
   - Suspicious IP addresses accessing address lists
2. Monitor PowerShell usage patterns
3. Review application permissions regularly

## References
- [MITRE T1087.003](https://attack.mitre.org/techniques/T1087/003/)
- [Microsoft Exchange Auditing](https://docs.microsoft.com/exchange/policy-and-compliance/mail-flow-rules/mail-flow-rules)
- [Microsoft Graph Security API](https://docs.microsoft.com/graph/api/resources/security-api-overview)

The model provides concrete detections and controls specific to Microsoft 365 environments while including realistic log examples and actionable guidance.

---

# Threat Model: Use Alternate Authentication Material (T1550) in Microsoft 365 & Entra ID

## 1. Overview
In Microsoft 365 and Entra ID environments, adversaries commonly abuse alternate authentication materials like:
- Service principal credentials
- Application access tokens
- Session cookies
- SAML tokens
- Delegated authentication permissions

## 2. Attack Vectors

### 2.1 Service Principal Credential Abuse
**Description**: Adversaries add credentials to existing service principals to maintain persistent access.

**Detection Fields**:
```json
{
  "Operation": "Add service principal credentials.",
  "Actor": ["UserId", "UserType"],
  "Target": ["ServicePrincipalId", "ApplicationId"],
  "Result": "Success",
  "CredentialType": ["Password", "Key"],
  "ValidityPeriod": "Duration"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "8729c1b2-7920-4927-9436-d82694435833",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "fdb4e50c-3b26-4eb0-9f52-ff4c5a609541", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001C45B6EA9",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "5fb14e3d-1876-4676-a720-4fec092b65ab",
  "UserId": "admin@contoso.com",
  "AzureApplicationId": "a9675e41-93b0-481c-b36e-72e25cd4d11c",
  "Target": [
    {
      "Type": 2,
      "ID": "ServicePrincipal_ea70e40e-50e1-4df8-bf5e-f4c2ec5d7847"
    }
  ],
  "KeyIdentifier": "b19f5570-a598-4e9d-9e6b-c71f6428951c",
  "KeyType": "Password",
  "KeyUsage": "Verify",
  "KeyExpirationTimestamp": "2025-01-15T10:22:31Z"
}
```

### 2.2 OAuth Application Token Abuse
**Description**: Adversaries acquire and abuse OAuth access tokens by registering malicious applications.

**Detection Fields**:
```json
{
  "Operation": "Add delegation entry.",
  "Actor": ["UserId", "UserType"], 
  "Target": ["ApplicationId", "DelegatedPermissions"],
  "ConsentType": "Application",
  "Scope": ["Permissions"]
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T15:42:11",
  "Id": "4a819bc7-3a25-4fb4-816e-82f7c6a8ad1c",
  "Operation": "Add delegation entry.",
  "OrganizationId": "fdb4e50c-3b26-4eb0-9f52-ff4c5a609541",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "10032001C45B6EA9",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "7dd1c773-7dec-4b32-8b42-5c7e8af65def",
  "UserId": "admin@contoso.com",
  "ApplicationId": "ae42d9e3-a343-4ee1-95a3-b16345d05c99",
  "DelegatedPermissions": [
    "Mail.Read",
    "Mail.Send",
    "Files.ReadWrite.All"
  ],
  "ConsentType": "Application",
  "ResourceId": "Microsoft Graph"
}
```

### 2.3 Email Delegation Abuse
**Description**: Adversaries add inbox delegation permissions to maintain persistent access to email.

**Detection Fields**:
```json
{
  "Operation": "Add-MailboxPermission",
  "Actor": ["UserId", "UserType"],
  "Target": ["MailboxOwner", "DelegateUser"],
  "AccessRights": ["FullAccess", "SendAs"]
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T09:15:22",
  "Id": "25b6ac3d-2954-4bdb-9e32-7f29b9f65e21",
  "Operation": "Add-MailboxPermission",
  "OrganizationId": "fdb4e50c-3b26-4eb0-9f52-ff4c5a609541",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "10032001C45B6EA9", 
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "UserId": "admin@contoso.com",
  "MailboxOwner": "ceo@contoso.com",
  "DelegateUser": "attacker@contoso.com",
  "AccessRights": ["FullAccess"],
  "InheritanceType": "All"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Detect service principal credential additions outside business hours
SELECT *
FROM AuditLogs 
WHERE Operation = "Add service principal credentials."
AND TimeGenerated NOT BETWEEN '0800' AND '1800'
AND DayOfWeek NOT IN (1,7)

-- Alert on high volume of OAuth consent grants
SELECT ApplicationId, COUNT(*) as ConsentCount
FROM AuditLogs
WHERE Operation = "Add delegation entry."
AND TimeGenerated > ago(1h)
GROUP BY ApplicationId
HAVING ConsentCount > 10

-- Monitor for suspicious delegation patterns
SELECT DelegateUser, COUNT(DISTINCT MailboxOwner) as DelegateCount
FROM AuditLogs
WHERE Operation = "Add-MailboxPermission" 
AND TimeGenerated > ago(24h)
GROUP BY DelegateUser
HAVING DelegateCount > 3
```

### 3.2 Baseline Deviations
- Track normal patterns of service principal credential management
- Monitor typical OAuth application consent volumes
- Establish baseline for mailbox delegation activities

### 3.3 Correlation Rules
- Link service principal credential additions with application modifications
- Correlate OAuth consents with suspicious sign-in patterns
- Connect mailbox delegation changes with email access patterns

## 4. Mitigation Strategies

### Administrative Controls
1. Implement strict OAuth app registration controls
2. Enforce service principal credential lifecycle management
3. Restrict mailbox delegation permissions

### Technical Controls
```json
{
  "ConditionalAccessPolicies": {
    "ServicePrincipals": {
      "RequireMFA": true,
      "AllowedCredentialTypes": ["Certificate"],
      "MaxCredentialValidityPeriod": "90d"
    },
    "OAuthApplications": {
      "AllowedGrantTypes": ["AuthorizationCode"],
      "BlockLegacyAuthentication": true,
      "RequireAdminConsent": true
    }
  }
}
```

### Monitoring Controls
1. Enable audit logging for all credential management
2. Monitor service principal and application activity
3. Alert on suspicious delegation patterns

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected authentication material type
2. Determine scope of compromise
3. Review audit logs for creation pattern

### Investigation
1. Map timeline of credential/token abuse
2. Identify all affected resources and permissions
3. Determine initial access vector

### Containment
1. Revoke compromised credentials/tokens
2. Remove malicious delegations and permissions
3. Block suspicious applications

## 6. References
- [MITRE ATT&CK T1550](https://attack.mitre.org/techniques/T1550/)
- [Microsoft Service Principal Security](https://docs.microsoft.com/azure/active-directory/develop/service-principal-security)
- [OAuth App Security Best Practices](https://docs.microsoft.com/azure/active-directory/develop/security-best-practices-for-app-registration)

---

# Threat Model: Hybrid Identity (T1556.007) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries modifying hybrid identity authentication processes between on-premises Active Directory and Microsoft 365/Entra ID to bypass authentication controls and maintain persistent access. Common attack vectors target:

- Pass-through Authentication (PTA) agents
- AD FS configuration files 
- Azure AD Connect synchronization
- Federation trust relationships

## 2. Attack Vectors

### Vector 1: PTA Agent Compromise
**Description**: Adversaries inject malicious code into the AzureADConnectAuthenticationAgentService to capture credentials and bypass authentication checks.

**Detection Fields**:
```json
{
  "Operation": "Add service principal.",
  "ServicePrincipalName": "AzureADConnectAuthenticationAgent",
  "ActorIpAddress": "10.1.2.3",
  "TargetResources": [
    {
      "Type": "ServicePrincipal",
      "ID": "8a7be394-2a11-4c6e-8c76-941c35f4f0cf"
    }
  ]
}
```

**SQL Rule**:
```sql
SELECT *
FROM AuditLogs 
WHERE Operation IN ('Add service principal.', 'Add service principal credentials.')
AND ServicePrincipalName LIKE '%AuthenticationAgent%'
AND TimeGenerated > ago(1h)
```

### Vector 2: AD FS Configuration Modification 
**Description**: Adversaries modify the Microsoft.IdentityServer.ServiceHost configuration to load malicious DLLs that forge tokens.

**Detection Fields**:
```json
{
  "Operation": "Set federation settings on domain.",
  "ObjectId": "contoso.com",
  "ModifiedProperties": [
    {
      "Name": "FederationServiceConfiguration",
      "OldValue": "",
      "NewValue": "{config details}" 
    }
  ]
}
```

**SQL Rule**: 
```sql
SELECT *
FROM AuditLogs
WHERE Operation = 'Set federation settings on domain.'
AND TimeGenerated > ago(24h)
GROUP BY DomainName 
HAVING COUNT(*) > 3
```

### Vector 3: Azure AD Connect Modification
**Description**: Adversaries alter Azure AD Connect sync settings to harvest credentials or modify synchronized identity attributes.

**Detection Fields**:
```json
{
  "Operation": "Set DirSyncEnabled flag.",
  "ActorIPAddress": "192.168.1.100",
  "ResultStatus": "Success",
  "ModifiedProperties": [
    {
      "Name": "DirectorySynchronizationEnabled",
      "OldValue": "True",
      "NewValue": "False"
    }
  ]
}
```

## 3. Detection Strategies

### Behavioral Analytics
- Monitor PTA agent registration patterns
- Track federation configuration changes 
- Alert on multiple password hash sync changes
- Detect unusual AD FS token issuance patterns

### Baseline Deviations
- Number of PTA agents per tenant
- Frequency of federation trust modifications
- Volume of synchronized password hash changes
- Geographic distribution of authentication requests

### Correlation Rules
```sql
// Detect PTA agent changes followed by mass authentication
SELECT a.*, b.*
FROM AuditLogs a 
JOIN SignInLogs b ON a.TenantId = b.TenantId
WHERE a.Operation IN ('Add service principal.', 'Set federation settings on domain.')
AND b.TimeGenerated BETWEEN a.TimeGenerated AND dateadd(hour,1,a.TimeGenerated)
GROUP BY a.CorrelationId
HAVING COUNT(b.Id) > 100
```

## 4. Mitigations

### Administrative Controls
1. Restrict Azure AD Connect installation permissions
2. Implement change management for federation changes
3. Monitor and alert on PTA agent modifications

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "name": "Block Legacy Auth",
    "conditions": {
      "clientAppTypes": ["other"],
      "locations": ["All"]  
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }
}
```

### Monitoring Controls
1. Enable audit logging for:
   - Azure AD Connect changes
   - Federation trust modifications 
   - PTA agent registration/removal
   - AD FS configuration changes

## 5. Incident Response

### Initial Assessment
1. Validate authentication configuration changes
2. Review Azure AD Connect sync status
3. Check PTA agent integrity
4. Audit federation trust settings

### Investigation Steps
1. Review audit logs for unauthorized changes
2. Analyze authentication patterns
3. Check for suspicious service principals
4. Validate AD FS token signing certificates

### Containment Actions
1. Disable compromised PTA agents
2. Reset federation trust settings
3. Revoke suspicious service principals
4. Force password resets for affected accounts

## 6. References

- MITRE: T1556.007
- [Azure AD Hybrid Identity](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/)
- [AADInternals Azure AD On-Prem to Cloud](https://o365blog.com/post/hybridhell/)
- [Microsoft Azure Identity Security](https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices)

Let me know if you would like me to expand on any section or provide additional details.

---

# Threat Model: Cloud API (T1059.009) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries can abuse various API interfaces including:
- Microsoft Graph API
- Azure AD PowerShell module
- Exchange Online PowerShell
- SharePoint Online Management Shell
- Microsoft 365 Admin Portal APIs
- Azure Cloud Shell

## 2. Attack Vectors

### 2.1 Graph API Abuse
**Description**: Adversaries use stolen access tokens or compromised service principals to make Microsoft Graph API calls for reconnaissance and data exfiltration.

**Attack Scenario**:
1. Attacker compromises service principal credentials
2. Uses Microsoft Graph API to enumerate users and groups
3. Downloads sensitive files and emails via API calls

**Detection Fields**:
```json
{
  "Operation": "Add service principal credentials",
  "ServicePrincipalId": "string",
  "ActorIpAddress": "string", 
  "CreationTime": "datetime",
  "ResultStatus": "string"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "8721cfa4-9759-4088-9d3d-012345678901", 
  "Operation": "Add service principal credentials",
  "OrganizationId": "contoso.onmicrosoft.com",
  "ServicePrincipalId": "62a25f39-0c59-4e6d-aa3c-abcdef123456",
  "ActorIpAddress": "198.51.100.1",
  "ResultStatus": "Success",
  "Workload": "AzureActiveDirectory"
}
```

### 2.2 PowerShell Module Abuse 
**Description**: Adversaries leverage Exchange Online PowerShell and other management modules to execute commands.

**Attack Scenario**:
1. Attacker obtains admin credentials
2. Connects to Exchange Online PowerShell
3. Creates mailbox rules and downloads emails

**Detection Fields**:
```json
{
  "Operation": "New-InboxRule",
  "UserId": "string",
  "ClientIP": "string",
  "Parameters": "string"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "4992f028-5ac3-49de-b720-012345678901",
  "Operation": "New-InboxRule", 
  "UserId": "admin@contoso.com",
  "ClientIP": "198.51.100.2",
  "Parameters": "-ForwardTo external@malicious.com -DeleteMessage $true",
  "ResultStatus": "Success"
}
```

### 2.3 Azure Cloud Shell Attacks
**Description**: Adversaries use browser-based Cloud Shell to execute commands while evading endpoint detection.

**Attack Scenario**: 
1. Attacker accesses Cloud Shell via compromised admin account
2. Runs PowerShell/CLI commands to create backdoor accounts
3. Modifies IAM permissions

**Detection Fields**:
```json
{
  "Operation": "Add member to role",
  "ObjectId": "string", 
  "TargetId": "string",
  "RoleName": "string"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T17:05:11",
  "Id": "a4421c33-b327-4f25-9c1d-012345678901",
  "Operation": "Add member to role",
  "ObjectId": "backdoor@contoso.com",
  "TargetId": "62e90394-69f5-4237-9190-012345678901",
  "RoleName": "Global Administrator",
  "InitiatedBy": "admin@contoso.com"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect suspicious service principal credential additions
SELECT ServicePrincipalId, COUNT(*) as credential_adds
FROM AuditLogs 
WHERE Operation = "Add service principal credentials"
AND TimeGenerated > ago(1h)
GROUP BY ServicePrincipalId
HAVING COUNT(*) > 3;

-- Alert on multiple role assignments
SELECT InitiatedBy, COUNT(*) as role_adds 
FROM AuditLogs
WHERE Operation = "Add member to role"
AND TimeGenerated > ago(24h)
GROUP BY InitiatedBy 
HAVING COUNT(*) > 5;
```

### 3.2 Baseline Deviation Monitoring
- Track normal API usage patterns per service principal
- Alert on sudden increases in API call volume
- Monitor for API calls from new IP addresses
- baseline normal working hours for admin activities

### 3.3 Correlation Rules
```sql
-- Correlate suspicious patterns
SELECT a.InitiatedBy, COUNT(*) as suspicious_actions
FROM AuditLogs a
WHERE a.TimeGenerated > ago(1h)
AND (
  a.Operation = "Add service principal credentials"
  OR a.Operation = "Add member to role" 
  OR a.Operation = "New-InboxRule"
)
GROUP BY a.InitiatedBy
HAVING COUNT(*) > 10;
```

## 4. Mitigation Strategies 

### 4.1 Administrative Controls
- Implement least privilege access
- Require MFA for all admin accounts
- Review service principal permissions regularly
- Enable privileged identity management

### 4.2 Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "adminMFA": {
      "users": ["Global Admins", "Exchange Admins"],
      "applications": ["Exchange Online PowerShell", "Azure Portal"],
      "conditions": {
        "requireMFA": true,
        "blockLegacyAuth": true
      }
    },
    "servicePrincipalRestrictions": {
      "allowedIPs": ["corporate-ranges"],
      "blockCountries": ["high-risk-locations"]
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable unified audit logging
- Configure alerts for suspicious API activities
- Monitor service principal credential changes
- Track PowerShell module usage

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Identify source of suspicious API activity
2. Determine compromised accounts/principals
3. Review audit logs for scope of access

### 5.2 Investigation
1. Timeline suspicious API calls
2. Map affected resources and permissions
3. Identify persistence mechanisms
4. Document evidence in logs

### 5.3 Containment
1. Revoke compromised credentials
2. Remove malicious service principals
3. Reset affected admin accounts
4. Block suspicious IPs

## 6. References

- [Microsoft Graph security API](https://docs.microsoft.com/graph/security-concept-overview)
- [Azure AD audit log schema](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities)
- [Exchange Online PowerShell](https://docs.microsoft.com/powershell/exchange/exchange-online-powershell)
- [MITRE T1059.009](https://attack.mitre.org/techniques/T1059/009/)

---

# Threat Model: Default Accounts (T1078.001) in Microsoft 365 & Entra ID

## Overview
Default accounts in Microsoft 365 and Entra ID present significant risks as they often have elevated privileges and are common targets for adversaries. This includes built-in administrator accounts, service accounts, and default application service principals.

## Attack Vectors

### 1. Global Administrator Account Abuse
**Description**: Adversaries target the initial/default Global Administrator account created during tenant setup.

**Real-world scenario**: Attacker performs password spraying against known default admin account names like "admin@domain.onmicrosoft.com"

**Relevant Audit Operations**:
- UserLoggedIn
- Add member to role
- Add delegation entry

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "18a7c443-8b6a-4840-9f49-8a44eb3e6bc7",
  "Operation": "UserLoggedIn",
  "OrganizationId": "d9588935-c969-4349-97dd-3650516c27d0", 
  "RecordType": 15,
  "UserKey": "admin@contoso.onmicrosoft.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "192.168.1.100",
  "ObjectId": "Default_Admin_Account",
  "UserId": "admin@contoso.onmicrosoft.com",
  "AzureActiveDirectoryEventType": 1,
  "ExtendedProperties": [
    {
      "Name": "UserAgent",
      "Value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    },
    {
      "Name": "LoginType", 
      "Value": "Interactive"
    }
  ]
}
```

### 2. Default Service Principal Abuse
**Description**: Attackers leverage default service principals created by Microsoft applications.

**Real-world scenario**: Attacker exploits overly permissive permissions on Microsoft Graph API service principal

**Relevant Audit Operations**:
- Add service principal
- Add service principal credentials
- Set delegation entry

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "44ff44fb-a6d6-4524-b439-ab583c430b8d",
  "Operation": "Add service principal credentials",
  "OrganizationId": "d9588935-c969-4349-97dd-3650516c27d0",
  "RecordType": 15, 
  "UserKey": "admin@contoso.onmicrosoft.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "00000003-0000-0000-c000-000000000000", // Microsoft Graph
  "Target": [
    {
      "Type": "ServicePrincipal",
      "ID": "00000003-0000-0000-c000-000000000000"
    }
  ],
  "ModifiedProperties": [
    {
      "Name": "KeyDescription",
      "NewValue": "New Client Secret Added"
    }
  ]
}
```

### 3. Exchange System Account Abuse
**Description**: Adversaries target built-in Exchange Online system accounts.

**Real-world scenario**: Attacker exploits built-in Exchange Organization Management role account

**Relevant Audit Operations**:
- Add-MailboxPermission
- Add member to role
- Set delegation entry

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:33:12", 
  "Id": "b42c3986-8a51-4561-bc77-c8543cd8a669",
  "Operation": "Add-MailboxPermission",
  "OrganizationId": "d9588935-c969-4349-97dd-3650516c27d0",
  "RecordType": 1,
  "UserKey": "NT AUTHORITY\\SYSTEM",
  "UserType": 3,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "Organization Management",
  "UserId": "SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}",
  "ModifiedProperties": [
    {
      "Name": "FullAccess",
      "NewValue": "True"
    }
  ]
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect interactive logins from system accounts
SELECT UserId, ClientIP, Operation, Count(*) as login_count
FROM AuditLogs 
WHERE Operation = 'UserLoggedIn'
AND UserType IN (2,3) -- System account types
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP, Operation
HAVING Count(*) > 5

-- Alert on service principal credential changes
SELECT Operation, ObjectId, ActorUPN, Count(*) as change_count
FROM AuditLogs
WHERE Operation IN ('Add service principal credentials','Set delegation entry')
AND TimeGenerated > ago(24h)
GROUP BY Operation, ObjectId, ActorUPN
HAVING Count(*) > 3
```

### Baseline Deviation Monitoring
- Monitor for abnormal login times/locations for system accounts
- Track unusual permission/role changes to default accounts
- Alert on deviations from normal service principal API usage patterns

### Risk Score Calculation
```python
def calculate_risk_score(event):
    score = 0
    
    # High risk operations
    if event.Operation in ['Add service principal credentials', 'Add member to role']:
        score += 30
    
    # Suspicious timing
    if not during_business_hours(event.CreationTime):
        score += 20
        
    # System account activity  
    if event.UserType in [2,3]:
        score += 25
        
    # Unusual location
    if not in_approved_locations(event.ClientIP):
        score += 25
        
    return score
```

## Mitigation Strategies

### Administrative Controls
1. Document and audit all default/system accounts
2. Implement strict change management for service principal credentials
3. Enforce MFA on all privileged accounts including service accounts where possible

### Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Block Default Account Interactive Login",
    "State": "enabled",
    "Conditions": {
      "Users": {
        "Include": ["admin@domain.onmicrosoft.com"],
        "Exclude": []
      },
      "Applications": {
        "Include": ["All"]
      },
      "ClientAppTypes": ["browser", "mobileAppsAndDesktopClients"]
    },
    "GrantControls": {
      "Operator": "OR",
      "BuiltInControls": ["block"]
    }
  }
}
```

### Monitoring Controls
1. Enable unified audit logging across all workloads
2. Configure alerts for:
   - Interactive logins from system accounts
   - Credential changes to service principals
   - Role membership changes to default admin accounts
3. Implement automated response playbooks

## Incident Response Playbook

### Initial Detection
1. Validate alert details against known baseline
2. Check source IP reputation and location
3. Review authentication type and user agent

### Investigation
1. Query audit logs for related activity:
```kusto
AuditLogs
| where TimeGenerated between(ago(24h)..now())
| where UserPrincipalName == "suspect_account"
| project TimeGenerated, Operation, Result, ClientIP
```

2. Check for additional compromised accounts
3. Review role and permission changes

### Containment
1. Block suspicious IP addresses
2. Revoke affected service principal credentials
3. Reset compromised account passwords
4. Enable stricter conditional access policies

## References
- [Microsoft Default Tenant Settings](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/tenant-default-settings)
- [Service Principal Security](https://docs.microsoft.com/en-us/azure/active-directory/develop/security-best-practices-for-app-registration)
- [MITRE ATT&CK T1078.001](https://attack.mitre.org/techniques/T1078/001/)

---

# Threat Model: Abuse Elevation Control Mechanism (T1548) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, privilege elevation abuse typically involves:
- Manipulation of role assignments and delegated permissions
- Abuse of privileged service principals and applications 
- Exploitation of temporary access mechanisms like Privileged Identity Management (PIM)

## 2. Attack Vectors

### 2.1 Service Principal Credential Abuse
**Description**: Adversaries add credentials to existing service principals to maintain privileged access.

**Audit Operations**:
- Add service principal credentials
- Remove service principal credentials
- Update service principal 

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "8382d091-7a0d-43ab-9aab-8382d091",
  "Operation": "Add service principal credentials",
  "OrganizationId": "12a34567-89b0-12cd-34ef-567890abcdef",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "10037FFE841F7D37@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "d011a98f-5f26-4f99-8cd9-8e44a9e40be9",
  "UserId": "admin@contoso.com",
  "AadAppId": "d011a98f-5f26-4f99-8cd9-8e44a9e40be9",
  "KeyType": "Password",
  "KeyId": "c26d13fb-6e89-4b87-8844-053af85d64a2"
}
```

### 2.2 Role Assignment Manipulation
**Description**: Adversaries add users to privileged roles or modify existing role assignments.

**Audit Operations**:
- Add member to role
- Remove member from role
- Update role

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T11:15:22",
  "Id": "891723cf-1a2b-3c4d-5e6f-891723cf",
  "Operation": "Add member to role",
  "OrganizationId": "12a34567-89b0-12cd-34ef-567890abcdef", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10037FFE841F7D37@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "9ab87c65-4321-dcba-9876-543210fedcba",
  "UserId": "admin@contoso.com",
  "RoleName": "Global Administrator",
  "RoleId": "62e90394-69f5-4237-9190-012177145e10",
  "TargetUserOrGroupType": "User",
  "TargetUserOrGroupName": "compromised.user@contoso.com"
}
```

### 2.3 Temporary Access Abuse
**Description**: Adversaries exploit PIM or just-in-time access mechanisms to gain temporary elevated privileges.

**Audit Operations**:
- PIM role activation
- PIM role deactivation
- PIM assignment modification

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T14:33:19",
  "Id": "7d4e9f82-1a2b-3c4d-5e6f-7d4e9f82",
  "Operation": "PIM role activation",
  "OrganizationId": "12a34567-89b0-12cd-34ef-567890abcdef",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10037FFE841F7D37@contoso.com", 
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "7d4e9f82-1a2b-3c4d-5e6f-7d4e9f82",
  "UserId": "user@contoso.com",
  "RoleName": "Exchange Administrator",
  "ActivationDuration": "PT8H",
  "Justification": "Emergency access needed"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect multiple service principal credential additions in short time
SELECT UserId, COUNT(*) as credential_adds
FROM AuditLogs 
WHERE Operation = "Add service principal credentials"
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 3;

-- Alert on role assignments outside business hours
SELECT *
FROM AuditLogs
WHERE Operation = "Add member to role" 
AND (TimeGenerated.hour() < 8 OR TimeGenerated.hour() > 18)
AND DayOfWeek NOT IN ('Saturday','Sunday');
```

### 3.2 Baseline Deviation Monitoring
- Track normal patterns of:
  - Role assignment changes per admin per day
  - Service principal credential rotation frequency
  - PIM activation patterns by role and user

### 3.3 Correlation Rules
```sql
-- Correlate role assignments with unusual login patterns
SELECT a.UserId, a.Operation, a.TargetUserOrGroupName, s.Location 
FROM AuditLogs a
JOIN SignInLogs s ON a.TargetUserOrGroupName = s.UserPrincipalName
WHERE a.Operation = "Add member to role"
AND s.Location NOT IN (SELECT AuthenticatedLocation FROM BaselineLocations);
```

## 4. Mitigation Controls

### 4.1 Administrative Controls
- Implement role-based access control (RBAC)
- Require MFA for all role activations
- Enable Privileged Identity Management
- Regular access reviews

### 4.2 Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "privilegedRoles": {
      "requireMFA": true,
      "blockLegacyAuth": true,
      "allowedLocations": ["corporate-networks"],
      "deviceCompliance": "require"
    },
    "servicePrincipals": {
      "certificateAuth": "preferred",
      "secretRotation": "90days",
      "auditLogRetention": "365days"
    }
  }
}
```

### 4.3 Monitoring Controls
- Real-time alerts for privileged role changes
- Service principal credential monitoring
- PIM activation tracking
- Continuous access reviews

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Validate alert authenticity
2. Identify affected principals/roles
3. Document timeline of changes

### 5.2 Investigation
1. Review authentication logs for affected accounts
2. Check for correlated suspicious activities
3. Analyze role assignment patterns
4. Review service principal usage

### 5.3 Containment
1. Revoke suspicious role assignments
2. Reset compromised credentials
3. Block suspicious service principals
4. Enable stricter monitoring

## 6. References
- [MITRE ATT&CK T1548](https://attack.mitre.org/techniques/T1548/)
- [Microsoft Entra ID Protection](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/)
- [Azure AD Privileged Identity Management](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/)

---

# Threat Model: Password Spraying (T1110.003) in Microsoft 365 & Entra ID

## 1. Overview

Password spraying in Microsoft 365 and Entra ID typically involves attempting to authenticate against multiple accounts using a small set of common passwords through various authentication endpoints including:

- Azure Active Directory Authentication (login.microsoftonline.com)
- Exchange Online/Office 365 (outlook.office365.com) 
- SharePoint Online
- Teams/Skype for Business
- Application Proxies

## 2. Attack Vectors

### Vector 1: Azure AD Basic Authentication
**Description**: Adversaries attempt to authenticate against multiple accounts using legacy authentication protocols that don't support MFA.

**Audit Operation**: "UserLoggedIn"

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:23:15",
  "Id": "18a7c921-48b9-4688-8ce7-6b51e6361c22",
  "Operation": "UserLoggedIn", 
  "OrganizationId": "d9588f41-2ea4-415e-9a24-b5e0184a225b",
  "RecordType": 15,
  "UserKey": "10037FFE841F964B",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "192.168.1.100",
  "ObjectId": "john.smith@company.com",
  "UserId": "john.smith@company.com",
  "ApplicationId": "00000004-0000-0ff1-ce00-000000000000",
  "AuthenticationProtocol": "Basic",
  "LogonError": "InvalidUserNameOrPassword"
}
```

### Vector 2: Password Reset Portal
**Description**: Attackers abuse self-service password reset functionality to attempt password spraying.

**Audit Operation**: "Change user password"

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:25:33",
  "Id": "4a7c921-48b9-4688-8ce7-6b51e6361c99", 
  "Operation": "Change user password",
  "OrganizationId": "d9588f41-2ea4-415e-9a24-b5e0184a225b",
  "RecordType": 15,
  "UserKey": "10037FFE841F964B",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "192.168.1.100",
  "UserId": "attacker@external.com",
  "TargetUserOrGroupName": "victim@company.com",
  "TargetUserOrGroupType": "User",
  "Status": "Failed"
}
```

### Vector 3: OAuth Application Consent
**Description**: Adversaries register malicious OAuth applications and use them for password spraying to bypass conditional access policies.

**Audit Operation**: "Add service principal"

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:30:45",
  "Id": "8a7c921-48b9-4688-8ce7-6b51e6361c33",
  "Operation": "Add service principal",
  "OrganizationId": "d9588f41-2ea4-415e-9a24-b5e0184a225b", 
  "RecordType": 15,
  "UserKey": "10037FFE841F964B",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ApplicationId": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6",
  "ApplicationName": "Malicious App",
  "ClientIP": "192.168.1.100"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect authentication attempts against multiple accounts from single IP
SELECT ClientIP, COUNT(DISTINCT UserId) as TargetAccounts,
COUNT(*) as AttemptCount
FROM UserLoggedIn 
WHERE TimeGenerated > ago(1h)
AND LogonError = "InvalidUserNameOrPassword"
GROUP BY ClientIP
HAVING COUNT(DISTINCT UserId) > 10
AND COUNT(*)/COUNT(DISTINCT UserId) < 3;
```

### Baseline Deviation Monitoring
- Track normal authentication patterns per user/IP
- Alert on:
  - Authentication attempts outside business hours
  - Authentication from new locations
  - Sudden increase in failed logins

### Correlation Rules
```sql
-- Correlate failed logins across services
SELECT UserId, ClientIP,
COUNT(DISTINCT Workload) as Services,
COUNT(*) as FailedAttempts
FROM (
  SELECT * FROM UserLoggedIn
  UNION ALL
  SELECT * FROM ExchangeLogin
) auth_logs
WHERE TimeGenerated > ago(1h)
AND Status = "Failed"
GROUP BY UserId, ClientIP
HAVING COUNT(DISTINCT Workload) > 2;
```

## 4. Mitigation Strategies

### Administrative Controls
1. Implement strong password policies
2. Require MFA for all accounts
3. Block legacy authentication
4. Enable Azure AD Identity Protection

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "displayName": "Block Legacy Authentication",
    "state": "enabled",
    "conditions": {
      "clientAppTypes": ["exchangeActiveSync", "other"],
      "applications": {
        "includeApplications": ["all"]
      }
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }
}
```

### Monitoring Controls
1. Enable Azure AD Sign-in Risk Policies
2. Configure alerts for suspicious authentication patterns
3. Monitor service principal creation and consent grants

## 5. Incident Response Playbook

### Initial Detection
1. Validate alert authenticity
2. Identify affected accounts and IP addresses
3. Determine authentication protocols used
4. Review sign-in logs for pattern validation 

### Investigation
1. Extract timeline of authentication attempts
2. Identify successful compromises
3. Determine source IP geolocation
4. Review application consent grants
5. Check for post-compromise activity

### Containment
1. Reset compromised account passwords
2. Enable MFA where missing
3. Block suspicious IPs
4. Revoke suspicious OAuth grants
5. Review and update conditional access policies

## 6. References

1. [MITRE ATT&CK - T1110.003](https://attack.mitre.org/techniques/T1110/003/)
2. [Microsoft - Password Spray Attack Detection](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/concept-password-spray)
3. [Microsoft - Detecting Password Spray](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-password-spray)

---

# Threat Model: Temporary Elevated Cloud Access (T1548.005) in Microsoft 365 & Entra ID

## 1. Overview

Temporary elevated cloud access in Microsoft 365 and Entra ID can occur through:
- Just-In-Time (JIT) privileged access elevation
- Application/service principal impersonation 
- Exchange Application Impersonation roles
- Resource role assumption

## 2. Attack Vectors

### 2.1 Exchange Application Impersonation

**Description**:
Adversaries abuse Exchange ApplicationImpersonation role to gain temporary access to target mailboxes.

**Attack Scenario**:
1. Attacker compromises admin account
2. Adds ApplicationImpersonation role to controlled service principal
3. Uses service principal to access target mailbox contents

**Detection Fields**:
```json
{
  "Operation": "Add member to role.",
  "RoleName": "ApplicationImpersonation", 
  "ObjectId": "[Service Principal ID]",
  "UserId": "[Admin ID]",
  "ResultStatus": "Success"
}
```

```json
{
  "Operation": "MailItemsAccessed",
  "LogonType": "ApplicationImpersonation",
  "ClientProcessName": "[Application Name]",
  "ClientIP": "[IP Address]",
  "MailboxOwnerUPN": "[Target User]"
}
```

### 2.2 Service Principal Credential Addition

**Description**:
Attackers add credentials to existing service principals to gain temporary access.

**Attack Scenario**:
1. Attacker compromises Global Admin account
2. Adds credentials to high-privilege service principal
3. Uses new credentials to access resources

**Detection Fields**:
```json
{
  "Operation": "Add service principal credentials.",
  "ServicePrincipalId": "[SP ID]",
  "KeyDescription": "[Key Description]", 
  "ActorUPN": "[Admin UPN]",
  "ResultStatus": "Success"
}
```

### 2.3 JIT Access Approval Abuse

**Description**: 
Adversaries exploit misconfigured JIT access approval workflows.

**Attack Scenario**:
1. Attacker requests JIT access to privileged role
2. Exploits auto-approval or compromised approver
3. Gains temporary elevated permissions

**Detection Fields**:
```json
{
  "Operation": "Add member to role.",
  "RoleName": "[Privileged Role]",
  "RequestType": "JitAccess",
  "ApprovalStatus": "AutoApproved",
  "TargetUserOrGroupName": "[User]",
  "Duration": "[Duration]"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics

```sql
-- Detect unusual JIT request patterns
SELECT UserId, RoleName, COUNT(*) as RequestCount
FROM AuditLogs 
WHERE Operation = "Add member to role."
AND RequestType = "JitAccess"
GROUP BY UserId, RoleName
HAVING COUNT(*) > 5 -- Threshold for requests per day
```

### 3.2 Baseline Deviations

- Monitor for service principals accessing unusual numbers of mailboxes
- Track frequency and timing of JIT access requests
- Alert on access patterns outside business hours
- Detect role assignments from unfamiliar locations

### 3.3 Correlation Rules

```sql
-- Detect privilege escalation chains
SELECT a.UserId, a.RoleName, b.Operation
FROM AuditLogs a
JOIN AuditLogs b ON a.UserId = b.UserId
WHERE a.Operation = "Add member to role."
AND b.Operation IN (
  "Add service principal credentials.",
  "Set delegation entry."
)
AND a.TimeGenerated BETWEEN b.TimeGenerated 
  AND DATEADD(hour, 1, b.TimeGenerated)
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement strict JIT access approval workflows
- Require business justification for elevated access
- Regular review of service principal permissions
- Enforce time limits on elevated access

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "privilegedAccess": {
      "requireMFA": true,
      "requireJustification": true,
      "maxDuration": "PT8H",
      "approvalRequired": true,
      "allowedLocations": ["[Trusted IPs]"]
    }
  }
}
```

### Monitoring Controls
- Real-time alerts for high-risk role assignments
- Dashboard for JIT access requests and approvals
- Automated reports of service principal activity
- Continuous privilege usage monitoring

## 5. Incident Response 

### Initial Detection
1. Identify source of elevation request
2. Validate approval workflow was followed
3. Check for related suspicious activities

### Investigation
1. Review authentication logs for involved accounts
2. Analyze resource access patterns
3. Map privilege escalation chain
4. Document scope of access

### Containment
1. Revoke temporary access
2. Remove added credentials
3. Reset compromised accounts
4. Block suspicious IPs/service principals

## 6. References

- [Azure JIT Access Documentation](https://docs.microsoft.com/azure/active-directory/privileged-identity-management/)
- [Exchange Application Impersonation](https://docs.microsoft.com/exchange/client-developer/exchange-web-services/impersonation-and-ews-in-exchange)
- [MITRE T1548.005](https://attack.mitre.org/techniques/T1548/005/)

Let me know if you would like me to expand on any section or provide additional details.

---

# Threat Model: Account Discovery (T1087) in Microsoft 365 & Entra ID

## 1. Overview

Account discovery in Microsoft 365 and Entra ID environments typically involves adversaries enumerating users, groups, and service principals through various interfaces including:
- Microsoft Graph API queries
- Azure PowerShell cmdlets
- Azure CLI commands
- Azure Portal directory browsing

## 2. Attack Vectors

### 2.1 PowerShell Enumeration
**Description**: Adversaries use Azure PowerShell modules to enumerate directory objects

**Example Attack Flow**:
```powershell
Connect-AzAccount
Get-AzADUser -All
Get-AzADGroup -All  
Get-AzADServicePrincipal -All
```

**Relevant Audit Operations**:
```json
{
  "Operation": "UserLoggedIn",
  "UserAgent": "AzurePowerShell/*",
  "ObjectId": "Directory.Read.All", 
  "ResultStatus": "Success"
}
```

### 2.2 Graph API Enumeration
**Description**: Programmatic enumeration via Microsoft Graph API 

**Example Attack Flow**:
```http
GET https://graph.microsoft.com/v1.0/users
GET https://graph.microsoft.com/v1.0/groups
GET https://graph.microsoft.com/v1.0/servicePrincipals
```

**Audit Log Example**:
```json
{
  "Operation": "Add delegation entry.",
  "ObjectId": "Microsoft Graph",
  "UserId": "attacker@domain.com",
  "ApplicationId": "suspicious-app-id",
  "ClientIP": "12.34.56.78"
}
```

### 2.3 Portal Directory Access
**Description**: Interactive browsing of directory through Azure Portal

**Audit Log Example**:
```json
{
  "Operation": "DirectoryRoleRead",
  "LoggedByService": "AzurePortal",
  "InitiatedBy": {
    "user": {
      "id": "attacker-guid",
      "displayName": "Attacker"
    }
  },
  "TargetResources": [
    {
      "type": "User",
      "id": "target-guid"
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Detect rapid enumeration
SELECT UserId, Operation, COUNT(*) as QueryCount
FROM AuditLogs 
WHERE Operation IN ('DirectoryRead', 'Add delegation entry.')
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING COUNT(*) > 100

-- Detect off-hours activity
SELECT *
FROM AuditLogs
WHERE Operation LIKE '%Directory%'
AND TimeGenerated NOT BETWEEN '0900' AND '1700'
```

### 3.2 Baseline Deviations
- Track normal directory query patterns per user/app
- Alert on:
  - >50% increase in query volume
  - New query patterns not seen in baseline
  - Access from new IP addresses/user agents

## 4. Mitigation Controls

### Administrative Controls
- Implement strict RBAC
- Regular access reviews
- Just-in-time privileged access

### Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Block Directory Enumeration",
    "Conditions": {
      "Applications": ["Microsoft Graph"],
      "Controls": ["Block"] 
    }
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Monitor privileged role assignments
- Alert on new application consent grants

## 5. Incident Response

### Initial Detection
1. Identify source account/application
2. Review authentication logs
3. Check for suspicious app consents

### Investigation
1. Map timeline of directory access
2. Review accessed objects
3. Identify potential data exfiltration

### Containment
1. Revoke suspicious tokens
2. Reset compromised credentials
3. Remove malicious app registrations

## 6. References
- [MITRE ATT&CK T1087](https://attack.mitre.org/techniques/T1087/)
- [Microsoft Identity Security Monitoring](https://docs.microsoft.com/security/identity-monitoring)
- [Azure AD Audit Logs](https://docs.microsoft.com/azure/active-directory/audit-logs)

This model focuses on key Microsoft 365/Entra ID specific implementations while providing actionable detection and response guidance.

---

# Threat Model: Command and Scripting Interpreter (T1059) in Microsoft 365 & Entra ID

## 1. Overview
In Microsoft 365 and Entra ID contexts, adversaries commonly abuse PowerShell, Microsoft Graph API, and Azure CLI to execute malicious commands and scripts. This often involves using compromised credentials or OAuth tokens to interact with cloud services programmatically.

## 2. Attack Vectors

### 2.1 PowerShell Remote Management
**Description**: Adversaries use PowerShell modules like Az and MSOnline to execute commands against cloud resources.

**Attack Scenario**:
1. Attacker obtains admin credentials through phishing
2. Connects to Microsoft 365 services using PowerShell modules
3. Executes malicious commands across tenant

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "RunLiveResponseApi",
    "RunLiveResponseSession",
    "AddDelegates", 
    "RemoveDelegates"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Operation": "RunLiveResponseApi",
  "Workload": "AzureAD",
  "UserId": "admin@contoso.com",
  "ClientIP": "12.34.56.78",
  "ObjectId": "PowerShell_Execution",
  "CommandName": "Connect-AzureAD",
  "Parameters": "-TenantId 'contoso.onmicrosoft.com'"
}
```

### 2.2 Microsoft Graph API Abuse
**Description**: Attackers leverage registered applications and OAuth tokens to make automated API calls.

**Attack Scenario**:
1. Register malicious application in Entra ID
2. Grant elevated API permissions
3. Use access tokens to make Graph API calls

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Add service principal.",
    "Add service principal credentials.",
    "Set delegation entry."
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22", 
  "Operation": "Add service principal.",
  "ApplicationId": "a1b2c3d4-e5f6-g7h8-i9j0",
  "PermissionsGranted": ["Mail.Read", "User.ReadWrite.All"],
  "ActorUPN": "attacker@contoso.com",
  "ClientIP": "98.76.54.32"
}
```

### 2.3 Azure CLI Command Execution 
**Description**: Adversaries use Azure CLI to run commands against Azure resources.

**Attack Scenario**:
1. Compromise credentials with Azure permissions
2. Install Azure CLI on attack system
3. Execute malicious Az CLI commands

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Create Remote Action Operation",
    "OCE Run Commands on VM",
    "Execute AppHealthPlugin"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:01:15",
  "Operation": "OCE Run Commands on VM",
  "CommandType": "AzureCLI",
  "Command": "az vm run-command invoke",
  "TargetResources": ["VM01", "VM02"],
  "Actor": "compromised.user@contoso.com",
  "IPAddress": "45.67.89.12"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect unusual PowerShell activity
SELECT UserId, ClientIP, COUNT(*) as cmd_count
FROM AuditLogs 
WHERE Operation = 'RunLiveResponseApi'
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING cmd_count > 100;

-- Alert on suspicious Graph API permissions
SELECT ApplicationId, COUNT(DISTINCT PermissionsGranted) as perm_count
FROM AADServicePrincipalEvents
WHERE TimeGenerated > ago(24h)
GROUP BY ApplicationId
HAVING perm_count >= 10;
```

### 3.2 Baseline Deviation Monitoring
- Track normal patterns of PowerShell/API usage per user
- Alert on >25% increase in command volume
- Monitor for off-hours scripting activity
- Detect new source IP addresses for automation

### 3.3 Correlation Rules
```sql
-- Correlate PowerShell with sensitive operations
SELECT a.UserId, a.ClientIP, b.Operation
FROM 
  (SELECT * FROM AuditLogs WHERE Operation = 'RunLiveResponseApi') a
  JOIN 
  (SELECT * FROM AuditLogs WHERE Operation IN 
    ('Add member to role.','Reset user password.')) b
ON a.UserId = b.UserId
AND a.TimeGenerated BETWEEN b.TimeGenerated AND dateadd(minute,5,b.TimeGenerated);
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement Privileged Identity Management (PIM)
- Require MFA for all admin accounts
- Regular access reviews for service principals
- Restrict PowerShell remote management

### Technical Controls
```json
{
  "ConditionalAccessPolicies": {
    "BlockLegacyAuth": true,
    "RequireMFA": true,
    "AllowedLocations": ["Corporate Network"],
    "BlockUntrustedApps": true
  },
  "PowerShellSettings": {
    "RequireJIT": true,
    "AuditLevel": "Verbose",
    "AllowedModules": ["Approved List"]
  }
}
```

### Monitoring Controls
- Enable detailed PowerShell logging
- Monitor service principal creation/modification
- Alert on high-risk API permissions
- Track automation account usage

## 5. Incident Response Playbook

### Initial Detection
1. Identify source of suspicious automation
2. Review affected resources and permissions
3. Establish timeline of activity

### Investigation
1. Analyze PowerShell command history
2. Review OAuth app permissions and usage
3. Check for persistence mechanisms
4. Identify lateral movement attempts

### Containment
1. Revoke suspicious OAuth tokens
2. Disable compromised accounts
3. Block malicious IPs/apps
4. Remove unauthorized permissions

## 6. References
- MITRE ATT&CK T1059
- Microsoft Graph Security API documentation
- Azure PowerShell security guidance
- Entra ID audit log schema

---

# Threat Model: Indicator Removal (T1070) in Microsoft 365 & Entra ID

## Overview
In Microsoft 365 and Entra ID environments, adversaries may attempt to delete or modify audit logs, remove mailbox items, disable auditing features, or clear activity traces to evade detection and hide their activities.

## Attack Vectors

### 1. Disabling Audit Logging
**Description**: Adversaries with Global Admin privileges may attempt to disable audit logging to prevent their activities from being recorded.

**Attack Scenario**:
- Attacker compromises Global Admin account
- Disables unified audit logging in Security & Compliance Center
- Performs malicious activities without generating audit trails

**Detection Fields**:
```json
{
  "Operation": "Set-AdminAuditLogConfig",
  "ResultStatus": "Success",
  "UserId": "<admin>@<domain>.com",
  "Parameters": {
    "UnifiedAuditLogIngestionEnabled": "False"
  }
}
```

### 2. Mailbox Audit Log Manipulation 
**Description**: Attackers may attempt to disable mailbox audit logging or clear existing logs to hide email access/exfiltration.

**Detection Fields**:
```json
{
  "Operation": "Set-MailboxAuditBypassAssociation", 
  "ResultStatus": "Success",
  "UserId": "<admin>@<domain>.com",
  "ObjectId": "target@domain.com",
  "Parameters": {
    "AuditBypassEnabled": "True"
  }
}
```

### 3. Deletion of Security Alert Events
**Description**: Adversaries may delete security alerts and associated events to hide detection of their activities.

**Detection Fields**:
```json
{
  "Operation": "AlertDelete",
  "ResultStatus": "Success", 
  "UserId": "<user>@<domain>.com",
  "AlertId": "ABC123",
  "AlertType": "MailItemsAccessed",
  "AlertSeverity": "High"
}
```

## Detection Strategies

### Behavioral Analytics
```sql
-- Monitor for audit configuration changes
SELECT UserId, Operation, COUNT(*) as freq 
FROM AuditLogs
WHERE Operation IN ('Set-AdminAuditLogConfig', 'Set-MailboxAuditBypassAssociation')
GROUP BY UserId, Operation
HAVING COUNT(*) > 3 
WITHIN 60 MINUTES;

-- Alert on mass alert deletions
SELECT UserId, COUNT(*) as deletion_count
FROM AuditLogs 
WHERE Operation = 'AlertDelete'
GROUP BY UserId
HAVING COUNT(*) > 10
WITHIN 30 MINUTES;
```

### Baseline Deviations
- Monitor for spikes in audit configuration changes vs historical baseline
- Track unusual patterns of alert deletions outside business hours
- Alert on first-time disabling of critical auditing features

## Mitigation Controls

### Administrative
- Implement strict role-based access control for audit configuration
- Require MFA for all audit setting changes
- Regular review of audit configuration changes

### Technical
```json
{
  "auditSettings": {
    "unifiedAuditingRequired": true,
    "mailboxAuditingRequired": true,
    "retentionDays": 365,
    "alertNotifications": {
      "enabled": true,
      "recipients": ["securityteam@domain.com"]
    }
  }
}
```

### Monitoring
- Real-time alerts on audit configuration changes
- Daily review of audit log gaps
- Weekly audit configuration compliance checks

## Incident Response Playbook

### Initial Detection
1. Identify scope of audit logging changes
2. Document timeline of configuration modifications
3. Determine impacted systems and data

### Investigation
1. Review authentication logs for involved accounts
2. Analyze parallel suspicious activities
3. Identify any data access during audit gaps

### Containment
1. Revert unauthorized audit configuration changes
2. Reset compromised admin credentials
3. Enable enhanced auditing features

## References
- MITRE ATT&CK: T1070
- Microsoft Security Documentation: Audit Log Configuration
- Microsoft 365 Defender Portal: Advanced Audit Features

This model provides targeted guidance for detecting and responding to audit tampering in Microsoft 365 and Entra ID environments while leveraging native security capabilities.

Let me know if you would like me to expand on any section or provide additional detection scenarios.

---

# Threat Model: Office Template Macros (T1137.001) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries abusing Microsoft Office templates, particularly Normal.dotm (Word) and Personal.xlsb (Excel), to maintain persistence in Microsoft 365 environments. Key concerns in cloud environments:

- Templates synced via OneDrive can spread malicious macros across devices
- Shared templates hosted in SharePoint may impact multiple users
- Office 365 ProPlus automatic updates can be used to deploy malicious templates

## 2. Attack Vectors

### 2.1 OneDrive Template Sync

**Description:** Adversary modifies local Office templates that are synced to OneDrive, spreading malicious macros to all connected devices.

**Detection Fields:**
```json
{
  "Operation": "FileUploaded",
  "SourceFileName": "Normal.dotm",
  "SourceFilePath": "Documents/Microsoft/Templates/",
  "SourceFileExtension": "dotm",
  "UserAgent": "Microsoft Office/16.0",
  "UserId": "user@domain.com"
}
```

### 2.2 SharePoint Hosted Templates 

**Description:** Adversary uploads malicious templates to SharePoint document libraries configured as trusted template locations.

**Detection Fields:**
```json
{
  "Operation": "FileModified",
  "ObjectId": "/sites/templates/Shared Documents/corporate_template.dotm",
  "FileExtension": "dotm",
  "SourceFileExtension": "dotm", 
  "ModifiedProperties": ["ContentType", "Size"],
  "ClientIP": "10.10.10.10"
}
```

### 2.3 Global Template Location Modification

**Description:** Adversary modifies GlobalDotName registry settings via administrative templates to point to malicious network location.

**Detection Fields:**
```json
{
  "Operation": "Set company information.",
  "ObjectId": "Office16Settings",
  "ModifiedProperties": ["TemplatePath"],
  "OldValue": "C:\\ProgramData\\Templates",
  "NewValue": "\\\\remote\\templates"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect template modifications outside business hours
SELECT * FROM AuditLog
WHERE Operation IN ('FileModified', 'FileUploaded')
AND SourceFileExtension IN ('dotm', 'dotx', 'xlsb')
AND TimeGenerated NOT BETWEEN '0800' AND '1800'
AND WorkingHours = 0;

-- Detect mass template updates
SELECT UserId, COUNT(*) as ModCount
FROM AuditLog 
WHERE Operation = 'FileModified'
AND SourceFileExtension IN ('dotm','dotx','xlsb')
AND TimeGenerated > DATEADD(hour, -1, GETUTCDATE())
GROUP BY UserId
HAVING COUNT(*) > 10;
```

### 3.2 Baseline Deviations

- Monitor for abnormal template modification frequencies (baseline: <5 per day)
- Track unusual template storage locations 
- Alert on template size changes >20% from baseline

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Enforce approved template locations via Group Policy
- Implement template signing requirements
- Restrict template sync to approved locations

### 4.2 Technical Controls
```json
{
  "OfficeTemplateSettings": {
    "TrustedLocations": [
      "\\\\approved\\templates",
      "%APPDATA%\\Microsoft\\Templates"
    ],
    "BlockUntrustedLocations": true,
    "RequireTemplateSignature": true,
    "DisableAutomaticTemplateSync": true
  }
}
```

### 4.3 Monitoring Controls
- Enable detailed Office 365 audit logging
- Monitor template modification and sync events
- Track template usage across organization

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Identify affected templates and locations
2. Document template modifications and timestamps
3. Determine scope of template distribution

### 5.2 Investigation
1. Review template content for malicious macros
2. Analyze template modification audit trails
3. Identify affected users and systems

### 5.3 Containment
1. Block suspect template locations
2. Force template resync from trusted source
3. Revoke compromised admin credentials

## 6. References

- MITRE ATT&CK: https://attack.mitre.org/techniques/T1137/001/
- Microsoft Office Templates: https://docs.microsoft.com/en-us/office/vba/Library-Reference/
- Microsoft 365 Defender: https://docs.microsoft.com/en-us/microsoft-365/security/

Let me know if you would like me to expand on any section or provide additional examples.

---

# Threat Model: Email Forwarding Rule (T1114.003) in Microsoft 365 & Entra ID

## 1. Technique Overview

Email forwarding rules in Microsoft 365 can be created through:
- Outlook Web Access (OWA)
- Exchange PowerShell cmdlets 
- Exchange Admin Center
- Microsoft Graph API
- Transport rules (organization-wide)

Key security concerns:
- Data exfiltration through external forwarding
- Persistence after credential resets
- Hidden rules via MAPI modifications
- Organization-wide transport rules abuse

## 2. Attack Vectors

### 2.1 Individual Mailbox Forwarding

Description:
Adversary creates inbox rules to forward emails to external addresses using compromised credentials

Audit Operations:
- New-InboxRule
- Set-InboxRule 
- UpdateInboxRules

Example Log:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "12345678-90ab-cdef-1234-567890abcdef",
  "Operation": "New-InboxRule",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "user@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "Rule:Forward all messages to external@attacker.com",
  "Parameters": [
    {
      "Name": "ForwardTo",
      "Value": "external@attacker.com"
    },
    {
      "Name": "Enabled",
      "Value": "True"
    }
  ]
}
```

### 2.2 Hidden MAPI Rules

Description:
Adversary uses MAPI to create hidden rules not visible in standard interfaces

Audit Operations:
- Set-InboxRule with PR_RULE_MSG_PROVIDER property
- UpdateInboxRules with extended MAPI properties

Example Log:
```json
{
  "CreationTime": "2024-01-20T16:14:22", 
  "Operation": "Set-InboxRule",
  "UserKey": "compromised@contoso.com",
  "Parameters": [
    {
      "Name": "PR_RULE_MSG_PROVIDER",
      "Value": "FAF6G45E-23G5-2891-AH45-1242652D1A4F"
    },
    {
      "Name": "PR_RULE_MSG_SEQUENCE",
      "Value": "0"
    }
  ]
}
```

### 2.3 Transport Rule Abuse

Description:
Adversary creates/modifies organization-wide transport rules for broad email collection

Audit Operations:
- New-TransportRule
- Set-TransportRule
- Enable-TransportRule

Example Log:
```json
{
  "CreationTime": "2024-01-20T17:05:11",
  "Operation": "New-TransportRule", 
  "UserKey": "admin@contoso.com",
  "ObjectId": "TransportRule:Forward Executive Team Emails",
  "Parameters": [
    {
      "Name": "FromMemberOf",
      "Value": "Executive Team"
    },
    {
      "Name": "RedirectMessageTo",
      "Value": "collection@attacker.com"
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics

```sql
-- Detect sudden increase in forwarding rules
SELECT UserKey, COUNT(*) as rule_count
FROM AuditLogs 
WHERE Operation IN ('New-InboxRule', 'Set-InboxRule')
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING COUNT(*) > 3

-- Detect forwarding to external domains
SELECT *
FROM AuditLogs
WHERE Operation = 'New-InboxRule'
AND Parameters.Name = 'ForwardTo' 
AND Parameters.Value NOT LIKE '%@contoso.com'
```

### 3.2 Baseline Deviations

- Monitor for:
  - Off-hours rule creation (outside 9am-5pm)
  - Rules created from unusual locations/IPs
  - Multiple rules created in short timespan
  - Rules targeting sensitive users/groups

### 3.3 High-Risk Indicators

- External forwarding to unknown domains
- Rules with unusual MAPI properties
- Transport rules affecting broad user sets
- Rules created by recently compromised accounts

## 4. Controls

### 4.1 Administrative Controls

```json
{
  "preventions": [
    {
      "setting": "ExternalForwardingRestriction",
      "value": "Disabled",
      "scope": "Organization"
    },
    {
      "setting": "TransportRuleCreation",
      "value": "RequireApproval",
      "approvers": ["security@contoso.com"]
    }
  ]
}
```

### 4.2 Technical Controls

```json
{
  "conditionalAccess": {
    "exchangeAdmin": {
      "requireMFA": true,
      "allowedLocations": ["Corporate Network"]
    }
  },
  "dlpPolicies": {
    "monitorForwardingRules": true,
    "alertThreshold": 2,
    "notifySecurityTeam": true
  }
}
```

### 4.3 Monitoring Controls

- Real-time alerts on external forwarding
- Daily review of new transport rules
- Weekly audit of mailbox rules
- Automated scanning for hidden MAPI rules

## 5. Response Playbook

1. Initial Detection
   - Identify affected mailboxes
   - Document rule properties and timestamps
   - Preserve audit logs

2. Investigation
   - Review authentication logs for rule creator
   - Check for other compromised accounts
   - Analyze forwarded email content
   - Track data exfiltration scope

3. Containment
   - Disable suspicious rules
   - Block external domains
   - Reset compromised credentials
   - Enable MFA if not present

## 6. References

- MITRE: T1114.003
- Microsoft: Exchange Mail Flow Rules
- Security Guidance: MS.DEFENDER.3.2
- Related Techniques: T1078, T1098

---

# Threat Model: Financial Theft (T1657) in Microsoft 365 & Entra ID

## 1. Overview
In Microsoft 365 and Entra ID environments, financial theft typically manifests through:
- Business Email Compromise (BEC) using compromised or impersonated executive accounts
- Manipulation of financial approval workflows and permissions
- Modification of payment/banking information in user profiles and systems
- Creation of fraudulent payment requests through compromised accounts

## 2. Attack Vectors

### 2.1 Executive Account Compromise
**Description**: Adversaries compromise executive or finance personnel accounts to authorize fraudulent payments or modify payment details.

**Audit Events to Monitor**:
```json
{
  "Operations": [
    "Add-MailboxPermission", 
    "UpdateCalendarDelegation",
    "Set-InboxRule",
    "Add service principal credentials"
  ],
  "TargetUsers": ["CEO", "CFO", "Finance"]
}
```

**Example Log Entry**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Operation": "Add-MailboxPermission",
  "UserType": "Admin",
  "ObjectId": "CFO@company.com",
  "UserId": "attacker@company.com",
  "AccessRights": ["FullAccess"],
  "ClientIP": "192.168.1.100"
}
```

### 2.2 Payment System Modification
**Description**: Attackers modify payment system configurations or banking details to redirect funds.

**Audit Events**:
```json
{
  "Operations": [
    "Update user.",
    "Set company information.",
    "DirectoryServicesAccountConfigurationUpdated"
  ]
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T15:42:11", 
  "Operation": "Update user.",
  "ModifiedProperties": [
    {
      "Name": "BankingInformation",
      "OldValue": "Original Bank Details",
      "NewValue": "Modified Bank Details"
    }
  ],
  "TargetUserOrGroupName": "AccountsPayable",
  "ActorIpAddress": "10.0.0.55"
}
```

### 2.3 Fraudulent Approval Workflow
**Description**: Creation or modification of approval workflows to bypass financial controls.

**Audit Events**:
```json
{
  "Operations": [
    "Add member to role.",
    "Update group.",
    "Set delegation entry."
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect unusual mailbox delegation to executives
SELECT UserId, ObjectId, COUNT(*) as DelegationCount 
FROM AuditLog 
WHERE Operation = 'Add-MailboxPermission'
AND ObjectId IN (SELECT Email FROM ExecutiveUsers)
GROUP BY UserId, ObjectId
HAVING COUNT(*) > 2 
WITHIN 60 MINUTES;

-- Monitor banking information changes
SELECT * FROM AuditLog
WHERE Operation = 'Update user.'
AND ModifiedProperties LIKE '%BankingInformation%'
OR ModifiedProperties LIKE '%PaymentDetails%';
```

### 3.2 Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Finance System Protection",
    "Conditions": {
      "UserRisk": "high",
      "SignInRisk": "medium",
      "Applications": ["SAP", "Oracle Financials"],
      "Locations": {
        "Exclude": ["Trusted Locations"]
      }
    },
    "Controls": {
      "RequireMFA": true,
      "BlockDownloads": true,
      "RequireCompliantDevice": true
    }
  }
}
```

## 4. Mitigation Controls

### Administrative
1. Implement separation of duties for financial approvals
2. Require multi-person authorization for payment changes
3. Regular audit of financial system access and permissions

### Technical
1. Enable MFA for all finance-related accounts
2. Implement privileged identity management
3. Configure alerts for payment system modifications

### Monitoring
1. Real-time alerts for executive account changes
2. Daily review of financial system audit logs
3. Automated detection of unusual approval patterns

## 5. Incident Response

### Initial Detection
1. Identify affected accounts and systems
2. Document unauthorized changes
3. Preserve audit logs and evidence

### Containment
1. Suspend compromised accounts
2. Freeze affected payment systems
3. Block suspicious IP addresses

### Recovery
1. Restore original payment configurations
2. Reset affected credentials
3. Review and strengthen controls

## References
- MITRE ATT&CK: T1657
- Microsoft Security Documentation
- Microsoft 365 Defender Documentation

Would you like me to expand on any of these sections or provide more specific technical details for detection rules and controls?

---

# Threat Model: Cloud Services (T1021.007) in Microsoft 365 & Entra ID

## Overview
This technique involves adversaries leveraging federated/synchronized identities to access cloud services through web consoles, PowerShell, and APIs. In Microsoft 365 and Entra ID environments, this commonly manifests as:
- Use of compromised on-premises credentials to access cloud resources
- Authentication through federated services like AD FS
- PowerShell module usage (Az, MSOnline, Microsoft.Graph)
- API access through stolen tokens

## Attack Vectors

### 1. PowerShell Authentication
**Description**: Adversaries use PowerShell modules to authenticate to cloud services with compromised credentials

**Scenario**: 
- Attacker obtains valid credentials through phishing
- Uses Connect-AzAccount or Connect-MgGraph to authenticate
- Performs administrative actions via PowerShell

**Relevant Audit Operations**:
```json
{
  "Operation": "UserLoggedIn",
  "ApplicationId": "1b730954-1685-4b74-9bfd-dac224a7b894", // PowerShell
  "ClientAppId": "Azure PowerShell",
  "UserId": "bob@contoso.com",
  "ResultStatus": "Success",
  "LogonError": "",
  "UserAgent": "AzurePowershell/Az.Accounts"
}
```

### 2. Web Console Access
**Description**: Adversaries access the Microsoft 365 Admin Center or Azure Portal using federated credentials

**Scenario**:
- Attacker compromises on-premises AD account
- Leverages federation trust to access cloud portals
- Performs administrative actions through GUI

**Relevant Audit Operations**:
```json
{
  "Operation": "UserLoggedIn", 
  "ApplicationDisplayName": "Azure Portal",
  "ClientAppName": "Browser",
  "IPAddress": "12.34.56.78",
  "UserAgent": "Mozilla/5.0...",
  "ResultStatus": "Success",
  "UserType": "Federated",
  "LoginStatus": "0"
}
```

### 3. Service Principal Token Abuse  
**Description**: Adversaries steal and abuse service principal credentials or tokens

**Scenario**:
- Attacker accesses service principal credentials
- Uses credentials to obtain access tokens
- Authenticates API calls using stolen tokens

**Relevant Audit Operations**:
```json
{
  "Operation": "Add service principal credentials",
  "ObjectId": "8a7b5k31-22b9-4728-a9f9-1234567890ab",
  "Target": "[{\"Type\":\"ServicePrincipal\",\"ID\":\"8a7b5k31-22b9-4728-a9f9-1234567890ab\"}]",
  "ActorIpAddress": "12.34.56.78",
  "ResultStatus": "Success"
}
```

## Detection Strategies

### Behavioral Analytics Rules

```sql
-- Detect anomalous PowerShell login patterns
SELECT UserId, COUNT(*) as login_count
FROM AuditLogs 
WHERE Operation = 'UserLoggedIn'
AND ApplicationId = '1b730954-1685-4b74-9bfd-dac224a7b894'
GROUP BY UserId, DATE(TimeGenerated)
HAVING login_count > 10 -- Threshold for suspicious volume

-- Detect first-time service principal credential adds
SELECT * FROM AuditLogs
WHERE Operation = 'Add service principal credentials'
AND ObjectId NOT IN (
  SELECT ObjectId 
  FROM AuditLogs 
  WHERE TimeGenerated < DATEADD(day, -30, GETDATE())
)
```

### Baseline Deviations
- Monitor for authentication from new IP ranges
- Track typical working hours/days for PowerShell access
- Baseline normal service principal credential rotation patterns
- Alert on deviations from established patterns

### Correlation Rules
```sql
-- Correlate failed/successful logins across services
SELECT UserId, 
  COUNT(CASE WHEN ResultStatus='Failed' THEN 1 END) as failures,
  COUNT(CASE WHEN ResultStatus='Success' THEN 1 END) as successes
FROM AuditLogs
WHERE TimeGenerated > DATEADD(hour, -1, GETDATE())
GROUP BY UserId
HAVING failures > 5 AND successes > 0
```

## Mitigation Strategies

### Administrative Controls
- Implement conditional access policies
- Enable MFA for all users
- Review and restrict federated trust relationships
- Monitor and rotate service principal credentials

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "conditions": {
      "applications": {
        "includeApplications": ["all"]
      },
      "users": {
        "includeUsers": ["all"]
      },
      "locations": {
        "excludeLocations": ["AllTrusted"]
      }
    },
    "grantControls": {
      "operator": "AND",
      "builtInControls": ["mfa"]
    }
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Monitor PowerShell module usage
- Alert on service principal credential changes
- Track federated authentication patterns

## Incident Response Playbook

### Initial Detection
1. Validate alert details in audit logs
2. Identify affected accounts/resources
3. Determine authentication methods used
4. Document timeline of activity

### Investigation
1. Review all actions performed by compromised identities
2. Check for persistence mechanisms (added credentials)
3. Analyze authentication patterns
4. Identify blast radius

### Containment
1. Disable compromised accounts
2. Revoke active sessions
3. Reset credentials
4. Remove unauthorized service principal credentials
5. Block suspicious IP addresses

## References
- [MITRE T1021.007](https://attack.mitre.org/techniques/T1021/007/)
- [Microsoft Identity Security Monitoring](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection)
- [Azure AD Sign-in Logs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-sign-ins)

---

# Threat Model: Steal Application Access Token (T1528) in Microsoft 365 & Entra ID

## 1. Overview

Attackers can steal OAuth access tokens and refresh tokens to gain unauthorized access to Microsoft 365 resources by:
- Exploiting misconfigured OAuth applications
- Social engineering users through consent phishing
- Compromising service principals and managed identities

This enables persistent access to resources without requiring user credentials or MFA.

## 2. Attack Vectors

### 2.1 OAuth Consent Phishing

**Description:**
Attacker registers malicious OAuth application and tricks users into granting consent through phishing.

**Detection Fields:**
```json
{
  "Operation": "Add service principal.",
  "ApplicationId": "<app_id>",
  "Target": ["Mail.Read", "Files.ReadWrite.All"],
  "Actor": "<user_upn>",
  "ClientIP": "<ip_address>"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-15T10:22:14",
  "Id": "1234567",
  "Operation": "Add service principal.",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "10030000A2B4C",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "1234-5678-90ab-cdef",
  "UserId": "bob@contoso.com",
  "AzureActiveDirectoryEventType": 1,
  "ExtendedProperties": [
    {
      "Name": "ApplicationId",
      "Value": "981f26a1-7f43-403b-a875-f8b09b8cd720"
    },
    {
      "Name": "PermissionScopes",
      "Value": "Mail.Read Files.ReadWrite.All"
    }
  ],
  "Actor": [
    {
      "ID": "bob@contoso.com",
      "Type": 0
    }
  ],
  "ActorContextId": "contoso.onmicrosoft.com",
  "InterSystemsId": "68079520-7697-44c7-8977-bf02021f5cc3",
  "IntraSystemId": "e2a0e589-95d4-4589-b579-35a294991a51",
  "Target": [
    {
      "ID": "981f26a1-7f43-403b-a875-f8b09b8cd720",  
      "Type": 2
    }
  ],
  "TargetContextId": "contoso.onmicrosoft.com"
}
```

### 2.2 Service Principal Credential Theft

**Description:**
Attacker adds credentials to existing service principals to maintain access.

**Detection Fields:**
```json
{
  "Operation": "Add service principal credentials.",
  "ServicePrincipalId": "<sp_id>",
  "CredentialType": "Password",
  "Actor": "<admin_upn>",
  "ClientIP": "<ip_address>"
}
```

### 2.3 Managed Identity Token Theft 

**Description:**
Attacker compromises workload identity and steals managed identity tokens.

**Detection Fields:**
```json
{
  "Operation": "Add delegation entry.",
  "ResourceId": "<resource_id>",
  "GrantedTo": "<principal_id>",
  "Actor": "<user_upn>",
  "ClientIP": "<ip_address>"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics

```sql
-- Detect new app consent from high-risk IP
SELECT *
FROM AuditLogs 
WHERE Operation = "Add service principal."
AND ClientIP IN (SELECT Address FROM HighRiskIPs)
AND TimeGenerated > ago(1h)

-- Alert on service principal credential adds
SELECT *
FROM AuditLogs
WHERE Operation = "Add service principal credentials."
AND TimeGenerated > ago(24h)
GROUP BY ServicePrincipalId
HAVING COUNT(*) > 3
```

### 3.2 Baseline Deviations

- Monitor for spikes in OAuth consent grants compared to baseline
- Track anomalous service principal permission changes
- Alert on unusual managed identity token usage patterns

### 3.3 Real-time Correlation

- Link OAuth app registrations with subsequent suspicious activities
- Correlate service principal changes across tenants
- Monitor token usage across geographies

## 4. Mitigation Controls

### Administrative
- Implement OAuth app allow listing
- Restrict service principal credential management
- Enable admin consent requirements

### Technical
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Block OAuth Apps", 
    "State": "enabled",
    "Conditions": {
      "Applications": {
        "Include": ["All"]
      },
      "Users": {
        "Include": ["All"] 
      }
    },
    "Controls": {
      "Block": {
        "UnknownApps": true
      }
    }
  }
}
```

### Monitoring
- Enable OAuth app audit logging
- Monitor service principal changes
- Track managed identity usage

## 5. Incident Response

1. Initial Detection
   - Review OAuth consent logs
   - Check service principal modifications
   - Analyze token usage patterns

2. Investigation
   - Identify affected resources
   - Review app permissions
   - Track token usage

3. Containment
   - Revoke suspicious tokens
   - Remove malicious apps
   - Reset compromised credentials

## 6. References

- [MITRE T1528](https://attack.mitre.org/techniques/T1528/)
- [Microsoft OAuth Security](https://docs.microsoft.com/security/oauth)
- [Azure AD Token Security](https://docs.microsoft.com/azure/active-directory/tokens)

---

# Threat Model: Cloud Account Discovery (T1087.004) in Microsoft 365 & Entra ID

## Overview
Adversaries enumerate cloud accounts in Microsoft 365 and Entra ID to identify potential targets and understand the environment's structure. This typically involves querying directory services, role memberships, and service principals using administrative interfaces and PowerShell.

## Attack Vectors

### 1. PowerShell Enumeration
**Description**: Adversaries use PowerShell cmdlets like Get-MsolUser and Get-AzureADUser to enumerate accounts.

**Example Attack Flow**:
1. Attain compromised admin credentials
2. Connect to MSOnline/AzureAD PowerShell module
3. Run enumeration cmdlets
4. Export results for targeting

**Relevant Audit Operations**:
- Add member to role
- Remove member from role
- Search-UnifiedAuditLog

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "8382d091-9cd3-4b1a-9997-f12e460d34fa",
  "Operation": "Get-MsolUser",
  "OrganizationId": "4faa32fa-100e-4446-9b77-d5647f1aa29d",
  "RecordType": 1,
  "ResultStatus": "Success", 
  "UserKey": "10032001A42836CF",
  "UserType": "Admin",
  "Workload": "AzureActiveDirectory",
  "ObjectId": "All_Users",
  "UserId": "admin@contoso.com",
  "ClientIP": "192.168.1.100"
}
```

### 2. Microsoft Graph API Enumeration 
**Description**: Adversaries leverage Microsoft Graph API endpoints to query directory objects.

**Example Attack Flow**:
1. Register malicious application
2. Grant Directory.Read permissions
3. Use access tokens to query Graph API
4. Collect user and group information

**Relevant Audit Operations**:
- Add service principal
- Add service principal credentials
- DirectoryServiceOperation

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "4a12bc8f-1234-5678-90ab-cdef12345678",
  "Operation": "Add service principal credentials",
  "OrganizationId": "4faa32fa-100e-4446-9b77-d5647f1aa29d", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001A42836CF",
  "UserType": "Application",
  "Workload": "AzureActiveDirectory",
  "ObjectId": "ServicePrincipal_12345",
  "UserId": "app@contoso.onmicrosoft.com",
  "ApplicationId": "a1b2c3d4-e5f6-g7h8-i9j0-k9l8m7n6o5p4",
  "TargetResources": [
    {
      "Type": "ServicePrincipal",
      "Id": "12345678-90ab-cdef-1234-567890abcdef"
    }
  ]
}
```

### 3. Azure Portal User Interface Enumeration
**Description**: Adversaries browse the Azure Portal UI to manually discover accounts.

**Example Attack Flow**:
1. Login to Azure Portal
2. Navigate to Azure AD Users & Groups
3. Export user lists
4. Map organizational structure

**Relevant Audit Operations**:
- UserLoggedIn
- DirectoryLists 
- Export operations

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:08:11",
  "Id": "9c52a312-8765-4321-abcd-ef1234567890",
  "Operation": "UserLoggedIn",
  "OrganizationId": "4faa32fa-100e-4446-9b77-d5647f1aa29d",
  "RecordType": 15,
  "ResultStatus": "Success",
  "UserKey": "10032001A42836CF", 
  "UserType": "Regular",
  "Workload": "AzurePortal",
  "ClientIP": "192.168.1.100",
  "UserAgent": "Mozilla/5.0...",
  "SupportTicketId": "",
  "ActorIpAddress": "192.168.1.100",
  "ActorUserPrincipalName": "user@contoso.com"
}
```

## Detection Strategies

### Behavioral Analytics
```sql
// Detect rapid user enumeration
SELECT UserId, ClientIP, Operation, COUNT(*) as QueryCount
FROM AuditLogs 
WHERE Operation IN ('Get-MsolUser', 'Get-AzureADUser')
AND Timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY UserId, ClientIP, Operation
HAVING COUNT(*) > 100

// Detect anomalous API usage patterns
SELECT AppId, Operation, COUNT(*) as ApiCalls
FROM AuditLogs
WHERE Workload = 'AzureActiveDirectory' 
AND ResultStatus = 'Success'
GROUP BY AppId, Operation
HAVING COUNT(*) > avg_daily_calls + (2 * stddev_daily_calls)
```

### Baseline Deviations
- Monitor for spikes in directory query volume vs baseline
- Track new IP addresses performing enumeration
- Alert on first-time use of admin PowerShell cmdlets
- Flag unusual hours/locations for directory access

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "name": "Block Legacy Authentication",
    "state": "enabled",
    "conditions": {
      "clientAppTypes": ["exchangeActiveSync", "other"],
      "applications": {
        "includeApplications": ["all"]
      }
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }
}
```

## Incident Response Playbook

### Initial Detection
1. Review unified audit logs for enumeration patterns
2. Identify source accounts, IPs, and applications
3. Determine normal vs suspicious query patterns
4. Correlate with other suspicious activities

### Investigation
1. Map out timeline of enumeration activities
2. Review permissions of querying accounts
3. Check for unauthorized application registrations
4. Analyze exported data and potential targeting

### Containment
1. Block suspicious IPs/accounts
2. Revoke compromised credentials
3. Remove unauthorized applications
4. Enable additional logging controls

## References
- MITRE ATT&CK: T1087.004
- Microsoft Security Documentation
- Azure AD Activity Logs Schema
- Microsoft Graph Security API

---

# Threat Model: Forge Web Credentials (T1606) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries may forge various types of authentication credentials including:
- SAML tokens using compromised signing certificates
- Service principal credentials
- Federation trust tokens
- OAuth access tokens

## 2. Attack Vectors

### 2.1 SAML Token Forgery

**Description:**
Adversaries compromise a token signing certificate to generate forged SAML tokens for any user.

**Attack Scenario:**
1. Attacker extracts token signing certificate from AD FS server
2. Creates forged SAML token claiming to be privileged user
3. Uses token to authenticate to Microsoft 365 services

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Add service principal credentials.",
    "Set federation settings on domain.",
    "Set domain authentication."
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:13",
  "Id": "4a2f1c17-4c21-4639-9391-a1d4c5e885f9",
  "Operation": "Set federation settings on domain", 
  "OrganizationId": "87cc1c47-e84c-4489-9771-f75129a7a511",
  "RecordType": 1,
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "contoso.com",
  "ModifiedProperties": [
    {
      "Name": "IssuerUri",
      "NewValue": "http://malicious.com/adfs/services/trust",
      "OldValue": "http://sts.contoso.com/adfs/services/trust"
    }
  ]
}
```

### 2.2 Service Principal Credential Forging

**Description:** 
Adversaries create new credentials for existing service principals to generate access tokens.

**Attack Scenario:**
1. Attacker compromises Global Admin account
2. Adds new credentials to high-privilege service principal
3. Uses credentials to request access tokens

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Add service principal.",
    "Add service principal credentials.",
    "Update service principal."
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "891c2f44-1c23-4892-9912-b2d158a7a511", 
  "Operation": "Add service principal credentials",
  "OrganizationId": "87cc1c47-e84c-4489-9771-f75129a7a511",
  "RecordType": 1,
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "8391c247-1923-4839-9981-f85129a7a511",
  "Target": [
    {
      "Type": "ServicePrincipal",
      "ID": "8391c247-1923-4839-9981-f85129a7a511"
    }
  ],
  "AdditionalDetails": [
    {
      "Key": "CredentialType",
      "Value": "X509Certificate" 
    }
  ]
}
```

### 2.3 Federation Trust Manipulation 

**Description:**
Adversaries modify federation trust settings to enable token forgery.

**Attack Scenario:**
1. Attacker modifies federation trust configuration
2. Adds malicious token signing certificate
3. Uses certificate to forge tokens

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Set federation settings on domain.",
    "Update domain.",
    "Set domain authentication."
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T17:33:41",
  "Id": "72bf4c88-2c31-4729-8812-c4d159a7a511",
  "Operation": "Set domain authentication",
  "OrganizationId": "87cc1c47-e84c-4489-9771-f75129a7a511", 
  "RecordType": 1,
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "contoso.com",
  "ModifiedProperties": [
    {
      "Name": "FederationSettings",
      "NewValue": "{\"SigningCertificate\":\"MIIDBTCCAe2gAwIBAgIQH4...\"}",
      "OldValue": null
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect multiple credential additions to service principals
SELECT UserKey, COUNT(*) as credential_adds
FROM AuditLogs 
WHERE Operation = "Add service principal credentials"
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING COUNT(*) > 5;

-- Alert on federation settings changes outside business hours
SELECT *
FROM AuditLogs
WHERE Operation IN ("Set federation settings on domain", "Set domain authentication")
AND TimeGenerated NOT BETWEEN '0900' AND '1700';
```

### 3.2 Baseline Deviation Monitoring

- Track normal patterns of service principal credential management
- Alert on anomalous federation configuration changes
- Monitor for unusual token signing certificate updates

### 3.3 Correlation Rules
```sql
-- Correlate federation changes with subsequent auth attempts
SELECT a.*, b.* 
FROM AuditLogs a
JOIN SignInLogs b ON a.TenantId = b.TenantId
WHERE a.Operation = "Set federation settings on domain"
AND b.TimeGenerated BETWEEN a.TimeGenerated AND dateadd(hour,1,a.TimeGenerated);
```

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement strict RBAC for federation settings
- Require MFA for all admin accounts
- Regular review of service principal credentials
- Audit federation trust configurations

### 4.2 Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Block Federation Management",
    "Conditions": {
      "Users": ["Global Admins"],
      "Applications": ["Federation Management"],
      "Locations": ["Trusted Locations Only"]
    },
    "Controls": {
      "RequireMFA": true,
      "RequireCompliantDevice": true
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable audit logging for all federation changes
- Monitor service principal credential lifecycle
- Alert on token signing certificate updates
- Track authentication patterns post-federation changes

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Review federation configuration audit logs
2. Check service principal credential changes
3. Analyze authentication patterns

### 5.2 Investigation
1. Map timeline of federation/credential changes
2. Identify affected service principals and applications
3. Review authentication logs for suspicious patterns
4. Analyze admin account activity

### 5.3 Containment
1. Revoke suspicious service principal credentials
2. Reset affected admin accounts
3. Remove unauthorized federation trusts
4. Block suspicious IPs/locations

## 6. References

- [MITRE T1606](https://attack.mitre.org/techniques/T1606/)
- [Microsoft Identity Security](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)
- [AD FS Security](https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs)

---

# Threat Model: Multi-Factor Authentication Request Generation (T1621) in Microsoft 365 & Entra ID

## 1. Overview
This technique involves adversaries attempting to bypass MFA by generating excessive authentication requests to overwhelm users into accepting a malicious login attempt. In Microsoft 365 and Entra ID environments, this commonly manifests through:
- Repeated sign-in attempts triggering Microsoft Authenticator push notifications
- SSPR (Self-Service Password Reset) request floods
- Authentication attempts from unusual locations/devices

## 2. Attack Vectors

### 2.1 MFA Push Notification Flooding
**Description**: Adversary repeatedly attempts authentication with valid credentials to generate multiple MFA push notifications.

**Audit Fields**:
```json
{
  "CreationTime": "2024-01-20T15:22:43",
  "Id": "18cc0116-6ee7-4d33-e892-08d321fada76",
  "Operation": "UserLoggedIn",
  "OrganizationId": "b7f3c3b2-4326-4444-a6c7-45f11a5c8469",
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserKey": "10032001C36C2A0B",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "192.168.1.100",
  "UserId": "john.doe@company.com",
  "AuthenticationMethod": "MicrosoftAuthenticator",
  "AuthenticationResult": "MFADenied"
}
```

### 2.2 SSPR Abuse
**Description**: Adversary triggers password reset requests to generate SMS/email verification codes.

**Audit Fields**:
```json
{
  "CreationTime": "2024-01-20T15:24:12",
  "Operation": "Reset user password.",
  "OrganizationId": "b7f3c3b2-4326-4444-a6c7-45f11a5c8469", 
  "RecordType": 8,
  "ResultStatus": "Initiated",
  "UserKey": "10032001C36C2A0B",
  "UserId": "john.doe@company.com",
  "ResetMethod": "SSPR",
  "SourceIP": "192.168.1.100"
}
```

### 2.3 Cross-Region Authentication Attempts
**Description**: Adversary attempts authentication from multiple geographic locations to appear as legitimate travel.

**Audit Fields**:
```json
{
  "CreationTime": "2024-01-20T15:26:33",
  "Operation": "UserLoggedIn", 
  "ResultStatus": "Failed",
  "ClientIP": "192.168.1.100",
  "UserId": "john.doe@company.com",
  "Location": {
    "City": "Seattle",
    "State": "Washington",
    "CountryOrRegion": "US"
  },
  "DeviceProperties": {
    "DeviceID": null,
    "DeviceName": null
  }
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect MFA push notification floods
SELECT UserId, COUNT(*) as attempt_count 
FROM AuditLogs
WHERE Operation = 'UserLoggedIn'
AND AuthenticationMethod = 'MicrosoftAuthenticator'
AND ResultStatus = 'Failed'
AND TimeGenerated > ago(10m)
GROUP BY UserId
HAVING COUNT(*) > 10;

-- Detect rapid SSPR requests
SELECT UserId, COUNT(*) as reset_count
FROM AuditLogs 
WHERE Operation = 'Reset user password.'
AND TimeGenerated > ago(15m)
GROUP BY UserId
HAVING COUNT(*) > 5;
```

### 3.2 Baseline Deviations
- Monitor typical MFA request patterns per user/time period
- Alert on deviations >3 standard deviations from baseline
- Track geographic location patterns and velocity

## 4. Technical Controls

```json
{
  "conditionalAccessPolicies": {
    "signInFrequency": {
      "value": 5,
      "type": "minutes"
    },
    "persistentBrowser": "never",
    "deviceFilter": "compliantOnly",
    "locationFilter": {
      "includeLocations": ["trusted"],
      "excludeLocations": ["allOthers"]
    }
  },
  "mfaConfiguration": {
    "methodsRequired": ["microsoftAuthenticator"],
    "numberMatchingRequired": true,
    "pushNotificationLimit": {
      "timeWindow": "10m",
      "maxAttempts": 5
    }
  }
}
```

## 5. Incident Response Playbook

### Investigation Steps
1. Review authentication logs for affected accounts
2. Map IP addresses and locations of attempts
3. Check for concurrent authentication attempts
4. Review user risk score changes

### Containment Actions  
1. Block suspicious IPs
2. Reset MFA for affected accounts
3. Enable stricter conditional access
4. Force password reset

## 6. References
- [MITRE T1621](https://attack.mitre.org/techniques/T1621/)
- [Microsoft MFA Documentation](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks)
- [Microsoft Security Response Center](https://msrc.microsoft.com/)

This provides a focused framework for detecting and responding to MFA request generation attacks in Microsoft 365 environments. Let me know if you would like me to expand on any section.

---

# Threat Model: Chat Messages (T1552.008) in Microsoft 365 & Entra ID

## 1. Overview 
This technique involves adversaries accessing credentials shared in Microsoft Teams chats, channel messages, and other collaboration tools. The primary focus is on real-time access to credentials rather than stored chat logs.

## 2. Attack Vectors

### 2.1 Teams Message Monitoring
**Description**: Adversaries with compromised admin accounts monitor Teams messages in real-time to collect credentials.

**Attack Scenario**:
- Attacker compromises Global Admin account
- Uses compliance features to monitor Teams messages
- Extracts credentials shared in chats/channels

**Relevant Audit Operations**:
```json
{
  "MessageRead": "Read message content",
  "MessageHostedContentRead": "Accessed message attachments",
  "MessagesListed": "Listed message history"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:30:22",
  "Id": "2d4e9-88c1-4e25-b0f2-11a3dd",
  "Operation": "MessageRead",
  "OrganizationId": "12a345bc-6d78-90ef-gh12",
  "RecordType": 25, 
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "MicrosoftTeams",
  "ObjectId": "19:meeting_..." 
}
```

### 2.2 eDiscovery Content Search
**Description**: Adversaries abuse eDiscovery to search historical Teams messages for credentials.

**Attack Scenario**:
- Attacker creates eDiscovery case
- Configures search for password patterns
- Exports results containing credentials

**Relevant Audit Operations**:
```json
{
  "SearchCreated": "Created content search",
  "SearchStarted": "Started content search",
  "SearchExported": "Exported search results"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:45:33",
  "Operation": "SearchCreated",
  "UserKey": "attacker@contoso.com",
  "SearchQuery": "password OR credentials OR apikey",
  "CaseId": "4f229-99d2-5f36-c1f3-22b4ee",
  "Sources": ["Teams"]
}
```

### 2.3 Teams Integration Abuse
**Description**: Adversaries leverage Teams app integrations to programmatically access messages.

**Attack Scenario**:
- Creates malicious Teams app
- Requests chat:read permissions
- Extracts messages via Graph API

**Relevant Audit Operations**:
```json
{
  "AppInstalled": "Teams app installation",
  "ConsentModificationRequest": "Permission consent granted"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-21T09:15:44", 
  "Operation": "AppInstalled",
  "AppId": "12345-67890",
  "AppDisplayName": "Message Reader",
  "Permissions": ["chat.read", "chat.readwrite"],
  "UserKey": "user@contoso.com"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect suspicious message access patterns
SELECT UserKey, COUNT(*) as access_count
FROM TeamsAuditLogs 
WHERE Operation IN ('MessageRead','MessagesListed')
AND TimeStamp > DATEADD(hour, -1, GETUTCDATE())
GROUP BY UserKey
HAVING COUNT(*) > 500;

-- Monitor eDiscovery searches targeting credentials
SELECT SearchQuery, UserKey
FROM eDiscoverySearches
WHERE LOWER(SearchQuery) LIKE '%password%' 
OR LOWER(SearchQuery) LIKE '%credential%'
OR LOWER(SearchQuery) LIKE '%secret%';
```

### 3.2 Baseline Deviations
- Monitor for users accessing >200% more messages than their 30-day average
- Alert on eDiscovery cases created outside business hours
- Track abnormal export volumes from content searches

### 3.3 Technical Controls (JSON)
```json
{
  "teamsPolicy": {
    "preventCredentialSharing": true,
    "dlpRules": [
      {
        "name": "Block Credentials",
        "pattern": "(password|api[_-]?key|secret|credential)",
        "action": "BlockAndNotify"
      }
    ],
    "messageMonitoring": {
      "adminAuditRequired": true,
      "maximumBulkAccess": 100
    }
  }
}
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement Teams DLP policies for credential patterns
- Restrict eDiscovery permissions to necessary personnel
- Enable detailed Teams audit logging

### Technical Controls
- Configure message retention policies
- Implement OAuth app restrictions
- Enable Conditional Access for admin accounts

### Monitoring Controls  
- Alert on high-volume message access
- Monitor eDiscovery search patterns
- Track Teams app installations and permissions

## 5. Incident Response Playbook

### Initial Detection
1. Identify source of credential exposure
2. Review audit logs for access patterns
3. Document exposed credentials

### Investigation
1. Review Teams audit logs
2. Analyze eDiscovery case history
3. Check app permissions and integrations

### Containment 
1. Revoke compromised credentials
2. Remove malicious apps/integrations
3. Reset affected admin accounts

## 6. References
- MITRE ATT&CK: T1552.008
- Microsoft Teams Security Guide
- Microsoft 365 Defender Documentation

This provides a comprehensive framework for detecting and responding to credential exposure via Teams and other Microsoft 365 communication channels.

---

# Threat Model: Internal Spearphishing (T1534) in Microsoft 365 & Entra ID

## 1. Overview

Internal spearphishing in Microsoft 365 environments typically involves adversaries compromising legitimate accounts and using them to send malicious content to other users within the organization. The trusted nature of internal senders and Microsoft 365 collaboration tools makes these attacks particularly effective.

## 2. Attack Vectors

### 2.1 Compromised Email Account Internal Phishing

**Description**: Adversary uses compromised account to send malicious emails to internal recipients

**Attack Flow**:
1. Compromise initial user account through credential theft
2. Create inbox rules to hide responses/alerts
3. Use compromised account to send phishing emails internally
4. Exfiltrate data or harvest additional credentials

**Relevant Audit Operations**:
```
- New-InboxRule
- Set-InboxRule
- Send
- SendAs
- SendOnBehalf
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "14c789e7-9262-4a21-8938-56b967fb9d44",
  "Operation": "New-InboxRule",
  "OrganizationId": "d124a8e1-4589-45d6-a345-c2fb862f3cdf",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "alice@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "contoso.com/Users/Alice/InboxRules/Rule1",
  "Parameters": [
    {
      "Name": "DeleteMessage",
      "Value": "True"
    },
    {
      "Name": "SubjectContainsWords",
      "Value": "phish,hack,compromised"
    }
  ]
}
```

### 2.2 Teams Chat-Based Phishing

**Description**: Adversary leverages compromised account to spread malicious links/content via Teams

**Attack Flow**:
1. Gain access to user's Teams account
2. Send malicious links in direct messages or channels
3. Use social engineering to convince users to click links
4. Capture credentials or deploy malware

**Relevant Audit Operations**:
```
- MessageCreatedHasLink
- MessageSent 
- ChatCreated
- TeamsSessionStarted
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T15:33:42",
  "Id": "18d992e5-8945-4a21-9568-44b967fb9d44",
  "Operation": "MessageCreatedHasLink",
  "RecordType": 25,
  "UserKey": "bob@contoso.com",
  "Workload": "MicrosoftTeams",
  "ObjectId": "19:meeting_...@thread.v2",
  "MessageLink": "https://malicious-site.com/fake-login",
  "ChatThreadId": "19:meeting_...",
  "RecipientCount": 12
}
```

### 2.3 SharePoint Document Phishing

**Description**: Adversary uploads malicious files to SharePoint and shares internally

**Attack Flow**:
1. Upload malicious documents to SharePoint
2. Share documents with internal users
3. Use compromised account to encourage opening files
4. Execute malware or capture credentials

**Relevant Audit Operations**:
```
- FileUploaded
- SharingInvitationCreated
- SharingSet
- FileSyncUploadedFull
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T16:44:21", 
  "Id": "22a456b8-7823-4c99-b838-77b967fb9d44",
  "Operation": "FileUploaded",
  "SiteUrl": "/sites/Marketing",
  "SourceFileExtension": "docx",
  "SourceFileName": "Q4_Report.docx",
  "UserKey": "carol@contoso.com",
  "Workload": "SharePoint",
  "ClientIP": "192.168.1.100",
  "ObjectId": "https://contoso.sharepoint.com/sites/Marketing/Shared Documents/Q4_Report.docx"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules

```sql
-- Detect unusual volume of sent emails
SELECT UserKey, COUNT(*) as EmailCount
FROM AuditLog 
WHERE Operation IN ('Send','SendAs','SendOnBehalf')
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING COUNT(*) > 50

-- Detect mass Teams messages with links
SELECT UserKey, COUNT(*) as LinkMessageCount 
FROM AuditLog
WHERE Operation = 'MessageCreatedHasLink'
AND TimeGenerated > ago(30m)
GROUP BY UserKey
HAVING COUNT(*) > 20

-- Detect suspicious inbox rules
SELECT *
FROM AuditLog
WHERE Operation IN ('New-InboxRule','Set-InboxRule')
AND Parameters CONTAINS 'DeleteMessage'
AND Parameters CONTAINS 'move' 
```

### Baseline Deviation Monitoring

- Track average daily email send patterns per user
- Monitor normal working hours for message activity
- Baseline typical file sharing patterns
- Alert on deviations > 2 standard deviations

## 4. Mitigation Strategies

### Administrative Controls
- Enforce MFA for all accounts
- Implement strict external sharing policies
- Configure conditional access policies
- Enable Microsoft Defender for Office 365

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "signInRiskLevels": ["high", "medium"],
    "userRiskLevels": ["high"],
    "applications": {
      "includeApplications": ["Office365"]
    },
    "users": {
      "allUsers": true
    },
    "grantControls": {
      "operator": "AND",
      "builtInControls": [
        "mfa",
        "compliantDevice"
      ]
    }
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Configure alert policies for suspicious patterns
- Implement automated response playbooks
- Monitor privileged accounts closely

## 5. Incident Response Playbook

1. Initial Detection
   - Review audit logs for indicators
   - Identify compromised accounts
   - Document scope and impact

2. Investigation
   - Search for malicious inbox rules
   - Review email/Teams message patterns
   - Check for unauthorized file sharing
   - Identify affected users

3. Containment
   - Reset compromised account credentials
   - Remove malicious inbox rules
   - Block suspicious URLs/attachments
   - Disable external sharing if needed

## 6. References

- MITRE ATT&CK: T1534
- Microsoft Security Documentation
- Microsoft 365 Defender Portal Documentation
- Azure AD Identity Protection Documentation

---

# Threat Model: Trusted Relationship (T1199) in Microsoft 365 & Entra ID

## 1. Overview
Adversaries may exploit trusted third-party relationships in Microsoft 365 environments by compromising partner/reseller accounts or abusing delegated administrator permissions. This gives them access to manage customer tenants without needing to compromise the customers directly.

## 2. Attack Vectors

### 2.1 Delegated Admin Exploitation
**Description**: Adversaries compromise a Microsoft partner account and leverage existing delegated admin relationships or send new admin requests to customers.

**Audit Operations to Monitor**:
- Add delegation entry
- Add partner to company
- Set delegation entry
- Add member to role

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:30:22",
  "UserId": "partner@contoso.com",
  "Operation": "Add delegation entry",
  "ResultStatus": "Success",
  "ObjectId": "CustomerTenant",
  "DelegatedAdminRole": "Global Administrator",
  "ClientIP": "123.45.67.89",
  "UserAgent": "Mozilla/5.0..."
}
```

### 2.2 Service Principal Abuse
**Description**: Attackers create or modify service principals to establish persistent access through trusted application integrations.

**Audit Operations**:
- Add service principal
- Add service principal credentials
- Update service principal

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:45:33", 
  "Operation": "Add service principal credentials",
  "ApplicationId": "a4d7e2c9-b8f1-4592-8d5a-187e20c3d4e8",
  "ActorUPN": "admin@contoso.com",
  "CredentialType": "Password",
  "ValidityPeriod": "2 years",
  "ClientIP": "123.45.67.89"
}
```

### 2.3 Partner Impersonation
**Description**: Adversaries compromise legitimate partner accounts to send malicious communications that appear trustworthy.

**Audit Operations**:
- Add member to group
- Update group
- Set company information

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:15:44",
  "Operation": "Set company information",
  "ActorUPN": "partner@contoso.com", 
  "ModifiedProperties": [
    {
      "Name": "TechnicalNotificationMails",
      "NewValue": "attacker@evil.com"
    }
  ],
  "ClientIP": "123.45.67.89"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect unusual partner admin activities
SELECT UserId, Operation, COUNT(*) as count
FROM AuditLog 
WHERE Operation IN ('Add delegation entry', 'Set delegation entry')
  AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING count > 5
```

### 3.2 Baseline Deviations
- Monitor for partner activities outside business hours
- Track geographic anomalies in partner access locations
- Alert on bulk changes to delegated permissions

### 3.3 Correlation Rules
```sql
-- Detect partner credential modifications followed by tenant access
SELECT a.UserId, a.Operation, b.Operation
FROM AuditLog a
JOIN AuditLog b ON a.UserId = b.UserId
WHERE a.Operation = 'Add service principal credentials'
  AND b.Operation = 'Add delegation entry'
  AND b.TimeGenerated BETWEEN a.TimeGenerated AND dateadd(hour,1,a.TimeGenerated)
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement strict partner access reviews
- Require MFA for all partner accounts
- Document and validate legitimate partner relationships

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "partnerAccess": {
      "requireMFA": true,
      "allowedLocations": ["US", "CA"],
      "blockLegacyAuth": true
    }
  },
  "delegatedAdminSettings": {
    "maxTenantAccess": 5,
    "requireApproval": true,
    "auditLoggingRequired": true
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Monitor partner privileged activities
- Alert on new delegation relationships

## 5. Incident Response

### Initial Detection
1. Review partner access audit logs
2. Verify legitimacy of partner relationships
3. Check for unauthorized tenant access

### Investigation
1. Document timeline of partner activities
2. Review all modified permissions/credentials
3. Identify affected customer tenants

### Containment
1. Revoke compromised partner access
2. Remove unauthorized delegations
3. Reset affected service principals

## 6. References
- [MITRE T1199](https://attack.mitre.org/techniques/T1199/)
- [Microsoft Partner Security Requirements](https://learn.microsoft.com/en-us/partner-center/partner-security-requirements)
- [Office 365 Delegated Administration](https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles)

---

# Threat Model: Cloud Account (T1136.003) in Microsoft 365 & Entra ID

## Overview
This technique involves adversaries creating cloud accounts in Microsoft 365 and Entra ID environments to maintain unauthorized access and persistence. The key risks include:

- Creation of backdoor admin accounts
- Service principal/managed identity abuse 
- Application registration with malicious permissions
- Guest account creation for external access

## Attack Vectors

### 1. Backdoor Admin Account Creation
**Description**: Adversary creates a new admin account after compromising Global Admin credentials

**Audit Operations to Monitor**:
- "Add user."
- "Add member to role."
- "Set license properties."

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "8382d091-9665-4e6c-b721-2f4d1c27af24",
  "Operation": "Add user.",
  "OrganizationId": "d124a8e1-c127-4c33-a53d-f112e171c9ac",
  "RecordType": 8,
  "UserKey": "10032001C36B6EDB",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "8382d091-9665-4e6c-b721-2f4d1c27af24",
  "UserId": "admin@contoso.com",
  "TargetUserOrGroupName": "backdoor_admin@contoso.com",
  "TargetUserOrGroupType": "User",
  "AssignedLicenses": ["Enterprise Mobility + Security E5"]
}
```

### 2. Malicious Service Principal Creation 
**Description**: Adversary creates service principal with excessive API permissions

**Audit Operations to Monitor**:
- "Add service principal."
- "Add service principal credentials."
- "Set delegation entry."

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "91a88f13-c555-4d81-9272-b2c3ab412e4f",
  "Operation": "Add service principal.",
  "RecordType": 8,
  "UserKey": "10032001C36B6EDB",
  "Workload": "AzureActiveDirectory",
  "ObjectId": "91a88f13-c555-4d81-9272-b2c3ab412e4f", 
  "AppId": "8382d091-9665-4e6c-b721-2f4d1c27af24",
  "DisplayName": "BackdoorApp",
  "ServicePrincipalType": "Application",
  "AppRoles": ["Mail.Read", "Directory.ReadWrite.All"]
}
```

### 3. Guest Account Creation for External Access
**Description**: Adversary invites external guest accounts for persistence

**Audit Operations to Monitor**:
- "Add user."
- "Add member to group."
- "SharingInvitationCreated"

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:01:15",
  "Id": "b2c3ab41-d555-4d81-9272-91a88f13c555",
  "Operation": "Add user.", 
  "RecordType": 8,
  "UserType": 2, // Guest user
  "Workload": "AzureActiveDirectory",
  "ObjectId": "b2c3ab41-d555-4d81-9272-91a88f13c555",
  "UserId": "admin@contoso.com",
  "TargetUserOrGroupName": "external_guest@gmail.com",
  "UserPrincipalName": "external_guest_gmail.com#EXT#@contoso.onmicrosoft.com"
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect rapid account creation
SELECT UserId, COUNT(*) as creation_count
FROM AuditLogs 
WHERE Operation IN ('Add user.', 'Add service principal.')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 5;

-- Detect off-hours admin account creation
SELECT *
FROM AuditLogs
WHERE Operation = 'Add member to role.' 
AND TargetRoleName IN ('Global Administrator', 'Exchange Administrator')
AND TimeGenerated.hour() NOT BETWEEN 9 AND 17;

-- Detect guest accounts added to sensitive groups
SELECT *
FROM AuditLogs
WHERE Operation = 'Add member to group.'
AND TargetUserOrGroupType = 'Guest'
AND TargetGroup IN ('Finance Team', 'IT Admins');
```

## Mitigation Strategies

### Administrative Controls
1. Enforce JIT/PIM for admin roles
2. Require MFA for all account creation
3. Restrict guest user capabilities
4. Monitor service principal permissions

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "accountCreation": {
      "requireMFA": true,
      "allowedLocations": ["US", "CA"],
      "blockLegacyAuth": true
    },
    "servicePrincipals": {
      "requireCertificates": true,
      "maxTokenLifetime": "1h",
      "auditingEnabled": true
    }
  }
}
```

### Monitoring Controls
1. Configure alerts for:
   - After-hours account creation
   - Bulk account creation
   - Guest accounts in admin groups
   - Service principals with high privileges

## Incident Response Playbook

### Initial Detection
1. Review account creation audit logs
2. Check role assignments
3. Analyze service principal permissions
4. Review guest account memberships

### Investigation
1. Map timeline of account creation
2. Review authentication patterns 
3. Check for linked malicious activities
4. Identify source IP addresses

### Containment
1. Disable suspected accounts
2. Remove excessive permissions
3. Block external domains
4. Reset compromised admin credentials

## References
- [MITRE ATT&CK T1136.003](https://attack.mitre.org/techniques/T1136/003/)
- [Microsoft Service Principals](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
- [Microsoft Entra ID Auditing](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/overview-reports)

---

# Threat Model: Account Manipulation (T1098) in Microsoft 365 & Entra ID

## 1. Overview

Account manipulation in Microsoft 365 and Entra ID involves modifying account properties, permissions, or credentials to maintain persistence or elevate privileges. This includes changing credentials, modifying group memberships, adding mailbox permissions, and manipulating service principals.

## 2. Attack Vectors

### 2.1 Exchange Mailbox Delegation

**Description**: Adversaries add delegate permissions to mailboxes to maintain persistent access and exfiltrate emails.

**Attack Scenario**: 
- Attacker compromises admin account
- Adds full access permissions to target mailboxes
- Creates inbox rules to forward/hide emails
- Maintains access even after password changes

**Detection Fields**:
```json
{
  "Operation": "Add-MailboxPermission",
  "ResultStatus": "Success", 
  "UserId": "<admin>",
  "ObjectId": "<target mailbox>",
  "Parameters": {
    "AccessRights": ["FullAccess"],
    "InheritanceType": "All"
  }
}
```

### 2.2 Service Principal Credential Addition

**Description**: Attackers add credentials to existing service principals to maintain backdoor access.

**Attack Scenario**:
- Compromise application admin account
- Add new credentials to high-privilege service principal
- Use new credentials to authenticate as service principal
- Bypass MFA requirements

**Detection Fields**:
```json
{
  "Operation": "Add service principal credentials.",
  "ObjectId": "<service principal id>",
  "ResultStatus": "Success",
  "ModifiedProperties": [
    {
      "Name": "KeyCredentials",
      "NewValue": "<credential details>"
    }
  ]
}
```

### 2.3 Role Membership Manipulation

**Description**: Adversaries add accounts to privileged roles to escalate/maintain privileges.

**Attack Scenario**:
- Attacker gains Global Admin access
- Adds compromised account to Privileged Role Administrator
- Uses role to add additional backdoor admins
- Maintains persistence through role hierarchy

**Detection Fields**:
```json
{
  "Operation": "Add member to role.",
  "ObjectId": "<role id>",
  "Target": [
    {
      "ID": "<user id>",
      "Type": "User"
    }
  ],
  "ModifiedProperties": [
    {
      "Name": "Role.DisplayName",
      "NewValue": "Global Administrator"
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect abnormal delegation patterns
SELECT UserId, Operation, COUNT(*) as count
FROM AuditLog 
WHERE Operation = "Add-MailboxPermission"
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING count > 5;

-- Alert on service principal credential changes
SELECT *
FROM AuditLog
WHERE Operation = "Add service principal credentials."
AND ResultStatus = "Success"
AND NOT IN (known_change_window);

-- Monitor privileged role changes
SELECT Target.ID, COUNT(*) as additions
FROM AuditLog
WHERE Operation = "Add member to role."
AND ModifiedProperties.Name CONTAINS "Global Administrator"
GROUP BY Target.ID, bin(TimeGenerated, 1h)
HAVING additions > 2;
```

### 3.2 Baseline Deviation Monitoring

- Track normal patterns of:
  - Mailbox delegation frequency per admin
  - Service principal credential rotation timing
  - Role membership change velocity
  - Time windows of administrative actions

- Alert on deviations:
  - >3x normal delegation rate
  - Credential changes outside maintenance windows  
  - Unusual role modification patterns
  - Administrative actions during off-hours

## 4. Mitigation Strategies

### 4.1 Administrative Controls

- Implement just-in-time privileged access
- Require MFA for all role changes
- Log and review all delegation activities
- Regular access reviews of privileged roles
- Restrict service principal credential management

### 4.2 Technical Controls 

```json
{
  "conditionalAccessPolicies": {
    "adminMFA": {
      "includeRoles": ["Global Admin", "Exchange Admin"],
      "grantControls": {
        "operator": "AND",
        "builtInControls": ["mfa"]
      }
    },
    "serviceAccountRestrictions": {
      "applications": ["service principals"],
      "clientAppTypes": ["nonBrowser"],
      "locations": ["trusted networks"]
    }
  }
}
```

### 4.3 Monitoring Controls

- Real-time alerts on privileged role changes
- Dashboard for delegation activity monitoring
- Service principal credential expiration tracking
- Automated access reviews and reports
- Anomaly detection for administrative actions

## 5. Incident Response Playbook

### 5.1 Initial Detection

1. Confirm alert details and impacted resources
2. Identify source account and affected targets
3. Review related audit logs for timeline
4. Determine scope of compromise
5. Preserve evidence for investigation

### 5.2 Investigation

1. Review all actions by suspect accounts
2. Check for additional compromised credentials
3. Analyze authentication patterns
4. Map lateral movement attempts
5. Identify persistence mechanisms

### 5.3 Containment

1. Revoke suspicious credentials
2. Remove unauthorized delegations
3. Reset compromised accounts
4. Block suspect service principals
5. Remove unauthorized role memberships

## 6. References

- [MITRE T1098](https://attack.mitre.org/techniques/T1098/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Entra ID Attack & Defense Playbook](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)
- [Exchange Online Security Guide](https://docs.microsoft.com/en-us/exchange/security-and-compliance/security-guide)

---

# Threat Model: Exfiltration Over Alternative Protocol (T1048) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries can exfiltrate data over alternative protocols by:
- Using SharePoint/OneDrive built-in download capabilities 
- Leveraging Exchange Online email forwarding and exports
- Exploiting Teams/SharePoint external sharing features
- Using Microsoft Graph API calls to extract data

## 2. Attack Vectors

### 2.1 SharePoint/OneDrive Mass Downloads

**Description:**
Adversaries download large volumes of files from SharePoint/OneDrive using web UI or sync client.

**Detection Fields:**
```json
{
  "Operation": "FileDownloaded",
  "UserAgent": "String",
  "UserId": "String", 
  "SourceFileName": "String",
  "ClientIP": "String",
  "SourceFileExtension": "String",
  "Site": "String"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:33",
  "Id": "4ea37a68-40c2-471d-b5e6-19b260e9a14c",
  "Operation": "FileDownloaded",
  "OrganizationId": "4a7c486f-c3b1-4b9d-bd45-b245dc3cd731",
  "RecordType": 6,
  "UserKey": "i:0h.f|membership|user@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "SharePoint",
  "ClientIP": "192.168.1.123",
  "ObjectId": "https://contoso.sharepoint.com/Shared Documents/Financial Reports/Q4-2023.xlsx",
  "UserId": "user@contoso.com",
  "SourceFileName": "Q4-2023.xlsx",
  "SourceFileExtension": "xlsx",
  "Site": "/sites/Finance"
}
```

### 2.2 Exchange Email Forwarding Rules

**Description:**
Adversaries create inbox rules to automatically forward emails to external addresses.

**Detection Fields:**
```json
{
  "Operation": "New-InboxRule",
  "Parameters": "String",
  "UserId": "String",
  "ClientIP": "String"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "b2f9a389-1c88-4f23-8968-d3f1a932f49c", 
  "Operation": "New-InboxRule",
  "OrganizationId": "4a7c486f-c3b1-4b9d-bd45-b245dc3cd731",
  "RecordType": 1,
  "UserKey": "i:0h.f|membership|user@contoso.com",
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "192.168.1.123",
  "UserId": "user@contoso.com",
  "Parameters": [
    {
      "Name": "ForwardTo",
      "Value": "external@gmail.com"
    },
    {
      "Name": "Enabled",
      "Value": "True"  
    }
  ]
}
```

### 2.3 Teams External Access

**Description:**
Adversaries share sensitive Teams channels with external domains/users.

**Detection Fields:**
```json
{
  "Operation": "MemberAdded", 
  "TeamName": "String",
  "AddedBy": "String",
  "AddedUser": "String",
  "UserType": "String"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T17:08:11",
  "Id": "92c45e8d-1623-4568-8452-8c91e2d51c44",
  "Operation": "MemberAdded",
  "OrganizationId": "4a7c486f-c3b1-4b9d-bd45-b245dc3cd731", 
  "RecordType": 25,
  "UserKey": "i:0h.f|membership|user@contoso.com",
  "Version": 1,
  "Workload": "MicrosoftTeams",
  "TeamName": "Project X",
  "AddedBy": "user@contoso.com",
  "AddedUser": "external@gmail.com",
  "UserType": "Guest"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules

```sql
-- Detect mass downloads from SharePoint
SELECT UserId, COUNT(*) as download_count
FROM AuditLog 
WHERE Operation = 'FileDownloaded'
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 100;

-- Detect suspicious email forwarding rules
SELECT UserId, COUNT(*) as rule_count
FROM AuditLog
WHERE Operation = 'New-InboxRule' 
AND Parameters LIKE '%ForwardTo%external%'
AND TimeGenerated > ago(24h)
GROUP BY UserId;

-- Detect mass external sharing
SELECT AddedBy, COUNT(*) as invite_count
FROM AuditLog
WHERE Operation = 'MemberAdded'
AND UserType = 'Guest'
AND TimeGenerated > ago(1h)
GROUP BY AddedBy
HAVING COUNT(*) > 10;
```

### Baseline Deviations
- Monitor daily average file download volumes per user
- Track normal external sharing patterns
- Establish baseline for email forwarding rule creation

## 4. Mitigation Controls

### Administrative Controls
1. Configure DLP policies to detect sensitive data uploads/downloads
2. Enable alerts for mass download activities
3. Restrict external sharing capabilities
4. Implement conditional access policies

### Technical Controls
```json
{
  "dlpPolicies": {
    "blockLargeDownloads": true,
    "downloadThreshold": 100,
    "timeWindow": "1h"
  },
  "sharingRestrictions": {
    "allowExternalSharing": false,
    "requireApproval": true,
    "allowedDomains": ["trusted-partner.com"]
  },
  "emailForwarding": {
    "blockAutoForwarding": true,
    "allowedDomains": []
  }
}
```

### Monitoring Controls
1. Enable unified audit logging
2. Configure alerts for suspicious patterns
3. Monitor service accounts and admin activities
4. Track external sharing/collaboration

## 5. Incident Response Playbook

### Initial Detection
1. Verify alerts against baseline activity
2. Identify affected users/resources
3. Document timestamp and scope

### Investigation
1. Review audit logs for user activity pattern
2. Check associated IP addresses
3. Analyze email forwarding rules
4. Review external sharing permissions

### Containment
1. Block suspicious user accounts
2. Remove suspicious forwarding rules
3. Revoke external sharing links
4. Reset compromised credentials

## 6. References

- [MITRE T1048](https://attack.mitre.org/techniques/T1048)
- [Microsoft 365 Security](https://docs.microsoft.com/en-us/microsoft-365/security/)
- [SharePoint Security](https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server)
- [Exchange Online Security](https://docs.microsoft.com/en-us/exchange/security-and-compliance/)

---

# Threat Model: Phishing (T1566) in Microsoft 365 & Entra ID

## 1. Overview

Phishing attacks in Microsoft 365 and Entra ID environments typically manifest through:
- Email-based phishing targeting user credentials
- OAuth consent phishing for app permissions
- Spear-phishing targeting privileged accounts
- Thread hijacking using compromised accounts

## 2. Attack Vectors

### 2.1 OAuth Consent Grant Phishing

**Description:**
Attackers create malicious OAuth apps and trick users into granting permissions, allowing persistent access to mailboxes and data without credentials.

**Detection Fields:**
```json
{
  "Operation": "Add delegation entry.",
  "ResultStatus": "Success",
  "Workload": "AzureActiveDirectory",
  "ObjectId": "[Application ID]",
  "UserId": "[Target User]",
  "ApplicationId": "[OAuth App ID]",
  "ClientIP": "[Source IP]"
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:13",
  "Id": "8382d091-7a0d-43ab-9aab-8382d091",
  "Operation": "Add delegation entry.",
  "OrganizationId": "b14f5d35-e610-45ad-9a7a-b14f5d35",
  "RecordType": 15,
  "ResultStatus": "Success", 
  "UserKey": "10032001@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "ea114e5f-c089-4c83-a85c-ea114e5f",
  "UserId": "10032001@contoso.com",
  "ApplicationId": "eb232d38-c519-4d82-a32d-eb232d38",
  "ClientIP": "192.168.1.100",
  "Scope": "Mail.Read Mail.Send"
}
```

### 2.2 Credential Theft Phishing 

**Detection Fields:**
```json
{
  "Operation": "UserLoggedIn",
  "LogonError": "[Error Code]", 
  "UserAgent": "[Browser/Client]",
  "ClientIP": "[Source IP]",
  "Location": "[Geolocation]"
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "4829e741-0b8c-42d1-b4c1-4829e741",
  "Operation": "UserLoggedIn", 
  "OrganizationId": "b14f5d35-e610-45ad-9a7a-b14f5d35",
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserKey": "james@contoso.com",
  "LogonError": "InvalidPassword",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "ClientIP": "45.227.252.102",
  "Location": "Lagos, Nigeria"
}
```

### 2.3 Thread Hijacking

**Detection Fields:**
```json
{
  "Operation": "New-InboxRule",
  "ClientIP": "[Source IP]",
  "Parameters": {
    "ForwardTo": "[External Email]",
    "DeleteMessage": "True"
  }
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T17:05:33",
  "Id": "7392f581-9d4c-4e91-b5a2-7392f581",
  "Operation": "New-InboxRule",
  "OrganizationId": "b14f5d35-e610-45ad-9a7a-b14f5d35", 
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "sarah@contoso.com",
  "ClientIP": "103.155.92.145",
  "Parameters": {
    "ForwardTo": "dropbox123@gmail.com",
    "DeleteMessage": "True",
    "Enabled": "True"
  }
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect suspicious OAuth consent grants
SELECT UserId, ClientIP, COUNT(*) as consent_count
FROM AuditLogs 
WHERE Operation = "Add delegation entry."
AND Timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY UserId, ClientIP
HAVING consent_count > 3;

-- Detect password spray attacks
SELECT ClientIP, COUNT(DISTINCT UserId) as target_count
FROM AuditLogs
WHERE Operation = "UserLoggedIn" 
AND ResultStatus = "Failed"
AND LogonError = "InvalidPassword"
AND Timestamp > NOW() - INTERVAL 30 MINUTE
GROUP BY ClientIP
HAVING target_count > 10;
```

### 3.2 Baseline Deviations
- Monitor for anomalous login locations/times
- Track usual email sending patterns
- Establish normal OAuth consent baselines

## 4. Mitigation Controls 

### Administrative Controls
- Configure conditional access policies
- Enable security defaults
- Implement approved OAuth app allowlisting

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "signInRiskLevels": ["high"],
    "userRiskLevels": ["high"],
    "locations": ["excludedLocations"],
    "applications": {
      "includeApplications": ["Office365"]
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": [
        "mfa",
        "compliantDevice" 
      ]
    }
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Configure alerts for suspicious activities
- Monitor admin account usage

## 5. Incident Response Playbook

### Initial Detection
1. Review unified audit logs for indicators
2. Identify affected accounts
3. Search for malicious inbox rules/OAuth grants

### Investigation
1. Analyze login patterns and locations
2. Review email forwarding/delegation rules
3. Check for unauthorized app consents

### Containment
1. Reset compromised credentials
2. Revoke suspicious OAuth grants
3. Block malicious IPs/domains
4. Remove malicious inbox rules

## 6. References

- [MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/)
- [Microsoft OAuth App Attacks](https://docs.microsoft.com/security/oauth-apps-attacks)
- [Microsoft 365 Security Documentation](https://docs.microsoft.com/microsoft-365/security/)

This model follows vendor documentation and focuses on realistic implementation in Microsoft 365 environments.

---

# Threat Model: Brute Force (T1110) in Microsoft 365 & Entra ID

## 1. Overview

Brute force attacks in Microsoft 365 and Entra ID environments typically manifest as repeated authentication attempts targeting user accounts through various endpoints including:

- Microsoft Online authentication portals
- Exchange Online/ActiveSync
- SharePoint Online 
- Microsoft Graph API endpoints
- PowerShell modules

## 2. Attack Vectors

### 2.1 Password Spray Attacks

**Description**: Attackers test a small set of common passwords against many accounts to avoid lockouts

**Audit Log Pattern**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p",
  "Operation": "UserLoggedIn", 
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "user1@contoso.com",
  "UserId": "anonymous",
  "ClientIP": "192.168.1.100",
  "ErrorNumber": "50126" // Invalid username or password
}
```

**Detection Strategy**:
- Monitor for failed logins across multiple accounts from same IP
- Track number of unique accounts targeted per source IP
- Baseline normal failed login patterns per IP range

### 2.2 Credential Stuffing 

**Description**: Attackers try username/password pairs from leaked credentials

**Audit Log Pattern**:
```json
{
  "CreationTime": "2024-01-15T15:45:12",
  "Id": "9i8h7g6f-5e4d-3c2b-1a0z-9y8x7w6v5u4t",
  "Operation": "MailboxLogin",
  "OrganizationId": "contoso.onmicrosoft.com", 
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "UserId": "attacker@external.com",
  "ClientIP": "10.20.30.40",
  "LogonError": "InvalidPassword",
  "Protocol": "ActiveSync"
}
```

**Detection Strategy**:
- Monitor for failed ActiveSync/EWS login attempts
- Track authentication attempts per account across protocols
- Alert on login attempts from suspicious locations/IPs

### 2.3 PowerShell Scripted Attacks

**Description**: Automated attacks using PowerShell modules and scripts

**Audit Log Pattern**:
```json
{
  "CreationTime": "2024-01-15T08:15:33",
  "Operation": "Connect-MsolService", 
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 15,
  "ResultStatus": "Failed",  
  "Workload": "PowerShell",
  "UserId": "unknown",
  "ClientIP": "172.16.48.79",
  "UserAgent": "Microsoft WinRM Client",
  "ErrorCode": "AuthenticationFailed"
}
```

**Detection Strategy**:
- Monitor PowerShell authentication attempts
- Track failed PowerShell connections per source
- Alert on automated connection patterns

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Password Spray Detection
SELECT ClientIP, COUNT(DISTINCT ObjectId) as TargetedAccounts,
COUNT(*) as FailedAttempts
FROM AuditLogs 
WHERE Operation IN ('UserLoggedIn', 'MailboxLogin')
AND ResultStatus = 'Failed'
AND Timestamp > ago(1h)
GROUP BY ClientIP
HAVING COUNT(DISTINCT ObjectId) > 10
AND COUNT(*) > 50

-- Credential Stuffing Detection  
SELECT ObjectId, COUNT(*) as FailedLogins,
COUNT(DISTINCT ClientIP) as UniqueIPs
FROM AuditLogs
WHERE Operation = 'UserLoggedIn' 
AND ResultStatus = 'Failed'
AND Timestamp > ago(30m)
GROUP BY ObjectId
HAVING COUNT(*) > 25
```

### 3.2 Baseline Deviation Monitoring

Monitor and alert on deviations from:
- Average failed login attempts per hour
- Number of unique targeted accounts
- Geographic distribution of authentication attempts
- Authentication protocol usage patterns

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement conditional access policies
- Enable MFA for all accounts
- Configure risk-based sign-in policies
- Set smart lockout thresholds

### 4.2 Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "name": "Block Legacy Authentication",
    "state": "enabled",
    "conditions": {
      "clientAppTypes": ["exchangeActiveSync", "other"],
      "applications": {
        "includeApplications": ["all"]
      }
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable unified audit logging
- Configure alerts for suspicious authentication patterns
- Monitor PowerShell usage
- Track authentication attempts by protocol

## 5. Incident Response Playbook

1. Initial Detection
   - Review unified audit logs
   - Identify affected accounts
   - Determine attack pattern and source

2. Investigation
   - Analyze login patterns
   - Review successful authentications 
   - Check for compromised accounts
   - Identify attack source

3. Containment
   - Block attacking IPs
   - Reset compromised passwords
   - Enable MFA
   - Review and update access policies

## 6. References

- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [Microsoft Identity Protection](https://docs.microsoft.com/azure/active-directory/identity-protection/)
- [Azure AD Sign-in Logs](https://docs.microsoft.com/azure/active-directory/reports-monitoring/concept-sign-ins)

---

# Threat Model: Outlook Forms (T1137.003) in Microsoft 365 & Entra ID

## 1. Overview

Outlook Forms can be abused as a persistence mechanism in Microsoft 365 by creating malicious custom forms that execute code when triggered by specially crafted emails. The forms load automatically when Outlook starts and execute when receiving the trigger email.

## 2. Attack Vectors

### 2.1 Custom Form Creation
**Description**: Adversary creates a malicious custom form and deploys it to target mailboxes

**Audit Fields**:
```json
{
  "Operation": "UpdateInboxRules",
  "ClientIP": "ip_address",
  "ClientInfoString": "Client=OWA;",
  "UserId": "user@domain.com",
  "MailboxGuid": "guid",
  "RuleName": "Custom Form Rule",
  "RuleParameters": {
    "FormName": "CustomForm.cfg"
  }
}
```

### 2.2 Form Code Injection 
**Description**: Adversary modifies existing forms to include malicious code

**Audit Fields**:
```json
{
  "Operation": "Set-InboxRule",
  "ResultStatus": "Success", 
  "ClientIP": "ip_address",
  "UserId": "user@domain.com",
  "Parameters": {
    "Identity": "Form Rule",
    "RedirectTo": "malicious@domain.com"
  }
}
```

### 2.3 Form Trigger Email
**Description**: Adversary sends specially crafted email to trigger malicious form

**Audit Fields**:
```json
{
  "Operation": "Send",
  "ClientIP": "ip_address", 
  "UserId": "user@domain.com",
  "Recipients": ["victim@domain.com"],
  "MessageSubject": "Form Trigger",
  "MessageFlags": "CustomForm=True"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
SELECT UserId, Operation, COUNT(*) 
FROM UnifiedAuditLog
WHERE Operation IN ('UpdateInboxRules','Set-InboxRule')
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING COUNT(*) > 10
```

### 3.2 Baseline Monitoring
- Monitor frequency of inbox rule changes per user
- Alert on new form creation patterns
- Track form trigger email characteristics

### 3.3 Technical Controls
```json
{
  "mailboxRules": {
    "maxRulesPerUser": 10,
    "prohibitedActions": ["runScript", "redirectTo"],
    "requireApproval": true
  }
}
```

## 4. Mitigation Controls

### Administrative:
- Disable custom form creation for non-admin users
- Require approval for new forms
- Regular form auditing

### Technical:
- Block external form imports
- Restrict form deployment permissions
- Enable enhanced form security features

### Monitoring:
- Alert on mass form deployments
- Monitor form trigger patterns
- Track form modification events

## 5. Incident Response

### Initial Detection:
1. Identify affected mailboxes
2. Collect form metadata and code
3. Track form trigger emails

### Investigation:
1. Analyze form code for IOCs
2. Review deployment timeline
3. Identify affected users

### Containment:
1. Disable malicious forms
2. Block trigger emails
3. Reset affected mailboxes

## 6. References

- MITRE ATT&CK: T1137.003
- Microsoft Security Documentation:
  - Outlook Forms Security 
  - Email Rules Protection
  - Form Deployment Controls

This threat model focuses on concrete Microsoft 365-specific detection and response strategies for malicious Outlook forms.

---

# Threat Model: Valid Accounts (T1078) in Microsoft 365 & Entra ID

## Overview
Valid account abuse in Microsoft 365 and Entra ID involves adversaries using compromised credentials to access cloud resources and perform malicious activities while appearing legitimate. This technique is particularly dangerous as it bypasses traditional security controls by using authorized credentials.

## Attack Vectors

### 1. Compromised User Account Takeover
**Description**: Adversary obtains valid user credentials and accesses Microsoft 365 resources while evading detection by mimicking normal user behavior.

**Scenario**: 
- Attacker gains credentials through phishing
- Logs in from anomalous location
- Accesses mailbox and SharePoint data
- Creates mail forwarding rules

**Relevant Audit Operations**:
```
- UserLoggedIn
- MailItemsAccessed  
- FileAccessed
- New-InboxRule
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "142f2e5a-8d33-4f99-9120-5e3e4a665c22",
  "Operation": "UserLoggedIn",
  "OrganizationId": "fe2bf117-9905-4f9f-b3e7-4acd6914382d",
  "RecordType": 15,
  "UserKey": "10032001b36bd0b1",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "192.168.1.100",
  "ObjectId": "john.doe@company.com",
  "UserId": "john.doe@company.com",
  "ApplicationId": "00000002-0000-0ff1-ce00-000000000000",
  "ResultStatus": "Success"
}
```

### 2. Privileged Account Escalation
**Description**: Adversary compromises standard account then escalates privileges by adding roles or permissions.

**Scenario**:
- Initial compromise of standard user
- Adds account to privileged roles
- Creates new admin accounts
- Modifies security settings

**Relevant Audit Operations**:
```
- Add member to role
- Add service principal
- Add delegation entry
- Update user
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "8d751795-4f52-41da-8132-156bf9e7e237",
  "Operation": "Add member to role",
  "OrganizationId": "fe2bf117-9905-4f9f-b3e7-4acd6914382d",
  "RecordType": 8,
  "UserKey": "10032001b36bd0b1",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "Global Administrator",
  "UserId": "john.doe@company.com",
  "Target": ["jane.smith@company.com"],
  "ResultStatus": "Success"
}
```

### 3. Service Principal/Application Abuse
**Description**: Adversary compromises or creates service principals to maintain persistent access.

**Scenario**:
- Creates malicious service principal
- Adds credentials to existing service principal
- Assigns elevated permissions
- Uses for automated access

**Relevant Audit Operations**:
```
- Add service principal
- Add service principal credentials
- Set delegation entry
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:05:44",
  "Id": "9c2f7d3a-5e21-4b88-9c1f-852adf5b2778", 
  "Operation": "Add service principal credentials",
  "OrganizationId": "fe2bf117-9905-4f9f-b3e7-4acd6914382d",
  "RecordType": 11,
  "UserKey": "10032001b36bd0b1",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "s8f7d3a5-1c23-4b88-9c1f-852adf5b2778",
  "UserId": "john.doe@company.com",
  "KeyType": "Password",
  "ResultStatus": "Success"
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect anomalous login patterns
SELECT UserId, ClientIP, COUNT(*) as login_count
FROM UserLoggedIn 
GROUP BY UserId, ClientIP, DATEPART(hour, CreationTime)
HAVING COUNT(*) > 10;

-- Detect privilege escalation
SELECT UserId, Operation, COUNT(*) as role_changes
FROM AuditLogs
WHERE Operation IN ('Add member to role', 'Add delegation entry')
GROUP BY UserId, Operation, CAST(CreationTime as DATE)
HAVING COUNT(*) > 3;

-- Detect service principal abuse
SELECT UserId, ObjectId, COUNT(*) as credential_adds
FROM AuditLogs 
WHERE Operation = 'Add service principal credentials'
GROUP BY UserId, ObjectId, CAST(CreationTime as DATE)
HAVING COUNT(*) > 2;
```

### Baseline Deviation Monitoring
- Track normal login times/locations per user
- Monitor typical role membership changes
- Baseline service principal credential rotation
- Alert on deviations > 2 standard deviations

## Mitigation Controls

### Administrative Controls
1. Enforce strong password policies
2. Require MFA for all accounts
3. Implement just-in-time access
4. Regular access reviews

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "signInRiskPolicy": {
      "state": "enabled",
      "riskLevels": ["high", "medium"],
      "controls": ["mfa", "block"]
    },
    "locationPolicy": {
      "state": "enabled",
      "allowedLocations": ["US", "CA"],
      "controls": ["mfa"]
    }
  },
  "authenticationStrengthPolicies": {
    "requireMFA": true,
    "allowedMFAMethods": ["phoneApp", "hardwareToken"],
    "rememberMFAForDays": 7
  }
}
```

### Monitoring Controls
1. Enable unified audit logging
2. Monitor privileged account usage
3. Alert on suspicious activities
4. Regular review of service principals

## Incident Response

### Initial Detection
1. Review Azure AD Sign-in logs
2. Check audit logs for suspicious operations
3. Analyze MFA/Conditional Access failures

### Investigation
1. Map timeline of account activities
2. Identify scope of access/changes
3. Review related service principal activity
4. Check for persistence mechanisms

### Containment
1. Reset compromised credentials
2. Revoke sessions/tokens
3. Remove unauthorized permissions
4. Block suspicious IPs/locations

## References
- [MITRE T1078](https://attack.mitre.org/techniques/T1078)
- [Microsoft Identity Security](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/)
- [Azure AD Investigation Guide](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)

---

# Threat Model: Account Access Removal (T1531) in Microsoft 365 & Entra ID

## Overview
Adversaries may disrupt access to accounts by deleting users, revoking permissions, changing credentials, or disabling accounts in Microsoft 365 and Entra ID environments. This technique is often used prior to ransomware deployment to impair incident response.

## Attack Vectors

### 1. Bulk User Account Deletion/Disablement
**Description**: Adversaries delete or disable multiple user accounts in rapid succession to cause disruption.

**Attack Scenario**:
- Attacker compromises Global Admin account 
- Uses Microsoft Graph API or admin portals to bulk delete/disable accounts
- Often targets IT and security team accounts first

**Detection Fields**:
```json
{
  "Operation": "Delete user.",
  "ObjectId": "<UserPrincipalName>",
  "UserId": "<AdminAccountUPN>",
  "ClientIP": "<IPAddress>",
  "Workload": "AzureActiveDirectory"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:15",
  "Id": "44ef1a37-4818-4335-9b9d-f269f8100bcd",
  "Operation": "Delete user.",
  "OrganizationId": "b7f0f06b-567d-4039-9b4b-2bdbb9ce3c51",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "victim@contoso.com",
  "UserId": "admin@contoso.com",
  "ClientIP": "12.34.56.78"
}
```

### 2. Permission Removal from Critical Groups
**Description**: Adversaries remove user permissions from security, admin and resource access groups.

**Attack Scenario**:
- Attacker identifies critical security groups
- Removes members from groups like "Global Admins", "Security Admins" 
- Targets application and data access groups

**Detection Fields**:
```json
{
  "Operation": "Remove member from group.",
  "ObjectId": "<GroupId>", 
  "Target": ["<UserPrincipalName>"],
  "ModifiedProperties": [{"Name": "Group.DisplayName"}]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T10:25:33",
  "Id": "8d4b2c9e-1234-5678-90ab-cdef12345678",
  "Operation": "Remove member from group.",
  "OrganizationId": "b7f0f06b-567d-4039-9b4b-2bdbb9ce3c51", 
  "RecordType": 8,
  "Target": ["securityadmin@contoso.com"],
  "ObjectId": "SecurityAdmins-Group",
  "ModifiedProperties": [
    {
      "Name": "Group.DisplayName",
      "OldValue": "Security Administrators"
    }
  ]
}
```

### 3. Credential Changes & Forced Sign-Out
**Description**: Adversaries modify credentials and force sign-outs to prevent access.

**Attack Scenario**:
- Changes passwords for critical accounts
- Enables MFA requirements
- Forces sign-out of active sessions

**Detection Fields**:
```json
{
  "Operation": ["Reset user password.", "Change user password."],
  "ObjectId": "<UserPrincipalName>",
  "ResultStatus": "Success",
  "LogonError": "UserForceSignOut"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T10:28:44",
  "Operation": "Reset user password.",
  "ResultStatus": "Success",
  "UserId": "admin@contoso.com",
  "ObjectId": "victim@contoso.com",
  "AdditionalDetails":[{
    "Key": "ForceChangePasswordNextSignIn",
    "Value": "True"
  }]
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect rapid user deletions
SELECT UserId, Operation, COUNT(*) as delete_count
FROM AuditLogs 
WHERE Operation = "Delete user."
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING delete_count >= 5;

-- Detect mass group membership removals
SELECT UserId, COUNT(*) as removal_count 
FROM AuditLogs
WHERE Operation = "Remove member from group."
AND TimeGenerated > ago(30m)
GROUP BY UserId
HAVING removal_count >= 10;
```

### Baseline Deviation Monitoring
- Track normal rates of account modifications per admin
- Alert on deviations >3 standard deviations from baseline
- Monitor time-of-day patterns for admin activities
- Track typical
```sql
-- Correlate deletions with password resets
SELECT a.UserId, COUNT(*) as suspicious_actions
FROM AuditLogs a 
JOIN AuditLogs b
  ON a.UserId = b.UserId
  AND a.TimeGenerated BETWEEN b.TimeGenerated 
    AND DATEADD(minute, 5, b.TimeGenerated)
WHERE a.Operation = "Delete user."
  AND b.Operation = "Reset user password."
GROUP BY a.UserId
HAVING COUNT(*) >= 3;
```

## Mitigation Strategies

### Administrative Controls
1. Implement privileged access workstations (PAW) for admin accounts
2. Require MFA for all admin activities
3. Implement just-in-time access for privileged roles
4. Regular review of admin group memberships

### Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Require PAW for Admin Access",
    "Conditions": {
      "UserRoles": ["Global Administrator", "Security Administrator"],
      "DeviceFilter": "PAW-Devices"
    },
    "Controls": {
      "RequireMFA": true,
      "RequireCompliantDevice": true
    }
  }
}
```

### Monitoring Controls
1. Enable unified audit logging
2. Configure alerts for:
   - Bulk user deletions (>5 in 1 hour)
   - Mass group membership changes (>10 in 30 min)
   - After-hours admin activities
   - Password resets followed by deletions

## Incident Response Playbook

### Initial Detection
1. Query unified audit logs for mass user/permission changes
2. Check sign-in logs for blocked access attempts
3. Review admin activity timeline
4. Identify scope of affected accounts/groups

### Investigation
1. Determine compromised admin account(s)
2. Review authentication logs for attack source
3. Check for other suspicious admin activities
4. Document affected users and permissions

### Containment
1. Suspend suspected compromised admin accounts
2. Restore critical admin access via break-glass account
3. Restore deleted user accounts and group memberships
4. Force password reset for affected accounts
5. Review and restore security group memberships

## References
- MITRE ATT&CK: T1531
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Microsoft Entra ID Protection](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/)
- [Unified Audit Log Schema](https://docs.microsoft.com/en-us/microsoft-365/compliance/audit-log-schema)

---

# Threat Model: Credential Stuffing (T1110.004) in Microsoft 365 & Entra ID

## 1. Overview
Credential stuffing in Microsoft 365 and Entra ID involves attackers attempting to authenticate using username/password pairs obtained from breached data. Key targets include:
- Microsoft 365 login portals
- Exchange Online/Outlook Web Access 
- Azure management portal
- SharePoint Online
- Teams

## 2. Attack Vectors

### 2.1 Office 365 Web Portal Authentication
**Description**: Mass authentication attempts against login.microsoftonline.com using breached credentials

**Detection Fields**:
```json
{
  "Operation": "UserLoggedIn",
  "ResultStatus": ["Failed", "Success"],
  "ClientIP": "string",
  "UserAgent": "string",
  "UserId": "string",
  "ApplicationId": "string",
  "ErrorCode": "integer"
}
```

**Example Failed Login Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:14",
  "Id": "18a7c443-8ea8-4748-a845-b8a7bd6d8100", 
  "Operation": "UserLoggedIn",
  "OrganizationId": "b7e9cb21-8487-4fa3-a51c-26a8d0db894",
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "UserId": "barbara@contoso.com",
  "ClientIP": "192.168.1.100",
  "ErrorCode": 50126,
  "LogonError": "Invalid username or password"
}
```

### 2.2 Exchange Online PowerShell Access  
**Description**: Automated scripting attempts using Exchange Online PowerShell

**Detection Fields**:
```json
{
  "Operation": "Add-MailboxPermission",
  "ResultStatus": ["Failed", "Success"], 
  "ClientIP": "string",
  "UserId": "string",
  "ObjectId": "string",
  "Parameters": "string"
}
```

### 2.3 Azure Management Portal Access
**Description**: Attempts to access Azure resources through portal.azure.com

**Detection Fields**:
```json
{
  "Operation": "Add member to role.",
  "ResultStatus": ["Failed", "Success"],
  "ClientIP": "string",
  "Target": "string[]",
  "InitiatedBy": {
    "user": {
      "id": "string",
      "displayName": "string"
    }
  }
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect rapid failed logins from same IP
SELECT ClientIP, COUNT(*) as attempts
FROM UserLoggedIn 
WHERE ResultStatus = 'Failed'
AND TimeGenerated > ago(5m)
GROUP BY ClientIP
HAVING COUNT(*) > 30

-- Detect successful login after multiple failures
SELECT UserId, ClientIP
FROM UserLoggedIn
WHERE ResultStatus = 'Success'
AND EXISTS (
  SELECT 1 FROM UserLoggedIn failures
  WHERE failures.UserId = UserLoggedIn.UserId
  AND failures.ResultStatus = 'Failed'
  AND failures.TimeGenerated > ago(1h)
  GROUP BY failures.UserId
  HAVING COUNT(*) > 20
)
```

### 3.2 Baseline Deviation Monitoring
- Track normal login patterns per user/IP
- Alert on:
  - Login attempts outside business hours
  - Logins from new countries/regions
  - Volume of failed attempts exceeding 2 standard deviations
  - Multiple accounts accessed from same IP

## 4. Technical Controls

```json
{
  "conditionalAccess": {
    "signInFrequency": {
      "type": "hours",
      "value": 4
    },
    "persistentBrowser": "never",
    "locations": {
      "includeLocations": ["AllTrusted"],
      "excludeLocations": ["AllCountries"] 
    }
  },
  "passwordPolicies": {
    "minimumLength": 14,
    "requireComplexity": true,
    "preventPasswordReuse": 24
  },
  "mfaPolicies": {
    "state": "enabled",
    "reconfirmationFrequency": "everyAccess"
  }
}
```

## 5. Administrative Controls
1. Enable Unified Audit Logging
2. Configure Smart Lockout settings:
   - Lockout threshold: 10 attempts
   - Lockout duration: 60 minutes
3. Require MFA for all users
4. Block legacy authentication protocols
5. Implement risk-based Conditional Access policies

## 6. Monitoring Controls
1. Real-time alerts for:
   - Multiple failed logins (>10 in 5 minutes)
   - Successful logins after failures
   - Login attempts from suspicious IPs
2. Daily review of:
   - New admin account creations
   - Password resets
   - MFA changes
3. Weekly review of:
   - Login patterns and anomalies
   - Conditional Access policy effectiveness
   - Smart References
- [MITRE ATT&CK - T1110.004](https://attack.mitre.org/techniques/T1110/004/)
- [Microsoft - Detect Credential Stuffing](https://docs.microsoft.com/security/credential-stuffing)
- [Azure AD Sign-in Logs Schema](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)

---

# Threat Model: Multi-Factor Authentication (T1556.006) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries manipulating MFA settings in Microsoft 365 and Entra ID to maintain persistent access after initial compromise. Key attack vectors include:

- Disabling MFA requirements through Conditional Access policies 
- Adding alternate authentication methods to compromised accounts
- Excluding users from MFA enforcement
- Modifying authentication provider settings

## 2. Attack Vectors

### 2.1 MFA Policy Modification

**Description:**
Adversaries with Global Administrator or Authentication Policy Administrator privileges modify Conditional Access policies to disable or weaken MFA requirements.

**Attack Scenario:**
1. Attacker compromises Global Admin account
2. Creates new Conditional Access policy excluding target accounts from MFA
3. Or modifies existing policies to create exclusions
4. Maintains persistent access without MFA challenges

**Detection Fields:**
```json
{
  "Operation": "Update policy", 
  "ObjectId": "[Policy ID]",
  "PolicyName": "[Policy Name]",
  "ModifiedProperties": {
    "PolicyState": ["Enabled", "Disabled"],
    "Conditions.Users.ExcludeUsers": ["User1", "User2"],
    "GrantControls.BuiltInControls": ["MFA", null]
  }
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "18b984c5-d154-4e76-8d8f-654321abc",
  "Operation": "Update policy",
  "OrganizationId": "12345678-1234-1234-1234-123456789012",
  "RecordType": 8,
  "UserKey": "10032001@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "policy-789xyz",
  "PolicyName": "Require MFA for All Users",
  "ModifiedProperties": [{
    "Name": "Conditions.Users.ExcludeUsers",
    "OldValue": "[]",
    "NewValue": "[\"user1@contoso.com\",\"user2@contoso.com\"]"
  }]
}
```

### 2.2 Authentication Method Addition

**Description:**
Attackers add alternate authentication methods (phone numbers, authenticator apps) to compromised accounts.

**Attack Scenario:**
1. Attacker gains initial access to account
2. Registers new phone number for SMS authentication
3. Can now bypass original MFA method

**Detection Fields:**
```json
{
  "Operation": "User registration of security info", 
  "ObjectId": "[User ID]",
  "AuthenticationMethodType": ["PhoneNumber", "Authenticator"],
  "Result": "Success",
  "Target": ["user@domain.com"]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T16:44:12",
  "Id": "5c7b984c-d154-4e76-8d8f-123456abc",
  "Operation": "User registration of security info",
  "OrganizationId": "12345678-1234-1234-1234-123456789012", 
  "RecordType": 15,
  "UserKey": "10032001@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "user123",
  "AuthenticationMethodType": "PhoneNumber",
  "PhoneNumber": "+1234567890",
  "Result": "Success"
}
```

### 2.3 Authentication Provider Modification 

**Description:**
Adversaries modify federation settings or authentication providers to bypass MFA.

**Detection Fields:**
```json
{
  "Operation": "Set federation settings on domain",
  "ObjectId": "[Domain ID]",
  "DomainName": "[Domain Name]",
  "ModifiedProperties": {
    "FederationProvider": ["OldValue", "NewValue"],
    "AuthenticationProtocol": ["OldValue", "NewValue"]
  }
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics

```sql
-- Detect sudden MFA policy changes
SELECT Operation, ActorUPN, COUNT(*) as changes
FROM AuditLogs 
WHERE Operation IN ('Update policy', 'Set federation settings on domain')
AND TimeGenerated > ago(1h)
GROUP BY Operation, ActorUPN
HAVING COUNT(*) > 3;

-- Detect unusual authentication method additions
SELECT UserPrincipalName, COUNT(*) as new_methods
FROM AuthenticationMethodChanges
WHERE TimeGenerated > ago(24h)
GROUP BY UserPrincipalName
HAVING COUNT(*) > 2;
```

### 3.2 Baseline Deviations

- Monitor rate of MFA policy changes vs historical baseline
- Track authentication method registration patterns
- Alert on spikes in excluded users from MFA policies

### 3.3 Critical Alerts

- Any modification to tenant-wide MFA settings
- Bulk changes to authentication methods
- Changes to federation providers
- Addition of new phone numbers for privileged accounts

## 4. Mitigation Strategies

### Administrative Controls
- Implement Privileged Identity Management (PIM) for admin roles
- Require approval for MFA policy changes
- Regular review of authentication settings
- Document baseline MFA configurations

### Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Protect Authentication Settings",
    "State": "enabled",
    "Conditions": {
      "Applications": {
        "Include": ["All"]
      },
      "Users": {
        "Include": ["All"],
        "Exclude": ["emergency-access"]
      }
    },
    "Controls": {
      "RequireMFA": true,
      "RequireCompliantDevice": true
    }
  }
}
```

### Monitoring Controls
- Enable detailed audit logging for authentication events
- Monitor privileged role assignments
- Track authentication method changes
- Alert on MFA policy modifications

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected accounts and policies
2. Review authentication logs for anomalies
3. Document timeline of changes

### Investigation
1. Review audit logs for related activities
2. Identify source of compromise
3. Determine scope of impact
4. Document affected systems

### Containment
1. Revert unauthorized MFA changes
2. Reset compromised credentials
3. Remove unauthorized authentication methods
4. Re-enable MFA enforcement

## 6. References

- [MITRE ATT&CK T1556.006](https://attack.mitre.org/techniques/T1556/006/)
- [Microsoft Conditional Access Documentation](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/)
- [Azure AD Authentication Methods](https://docs.microsoft.com/en-us/azure/active-directory/authentication/)

---

# Threat Model: Remote Email Collection (T1114.002) in Microsoft 365 & Entra ID

## 1. Overview
Adversaries may leverage Microsoft 365 and Exchange Online to collect sensitive email data through several methods:
- Abusing delegated mailbox permissions
- Leveraging compromised credentials for direct access
- Using automated tools like MailSniper for keyword-based collection
- Configuring mail forwarding rules 

## 2. Attack Vectors

### Vector 1: Mailbox Delegation Abuse
**Description**: Adversaries add themselves or other accounts as mailbox delegates to gain persistent access to target mailboxes.

**Relevant Audit Operations**:
- Add-MailboxPermission
- UpdateCalendarDelegation
- AddFolderPermissions

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "8382b5e4-c2de-4bf9-8c03-35e3f099def7",
  "Operation": "Add-MailboxPermission",
  "OrganizationId": "0fd7c141-339b-4c85-9336-52b8d5e14c89",
  "RecordType": "ExchangeAdmin",
  "ResultStatus": "Success",
  "UserType": "Regular",
  "UserId": "john.smith@company.com",
  "Parameters": {
    "AccessRights": ["FullAccess"],
    "Identity": "jane.doe@company.com",
    "User": "malicious.actor@company.com"
  }
}
```

### Vector 2: Exchange Web Services (EWS) Access
**Description**: Adversaries use EWS APIs to programmatically access and extract email content.

**Relevant Audit Operations**:
- MailItemsAccessed
- MessageRead
- SearchQueryPerformed 

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "Operation": "MailItemsAccessed",
  "OrganizationId": "0fd7c141-339b-4c85-9336-52b8d5e14c89", 
  "RecordType": "ExchangeItemGroup",
  "UserType": "Regular",
  "UserId": "suspicious.user@company.com",
  "ClientInfoString": "Client=UnknownClient;Protocol=EWS",
  "LogonType": 0,
  "MailboxGuid": "d14b5923-af8b-401b-b70e-9a14cf4491f3",
  "MailboxOwnerUPN": "victim@company.com",
  "MessageCount": 500
}
```

### Vector 3: Mail Forwarding Rules
**Description**: Adversaries create mail forwarding rules to automatically send copies of emails to attacker-controlled addresses.

**Relevant Audit Operations**:
- New-InboxRule
- Set-InboxRule
- UpdateInboxRules

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:05:11",
  "Id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "Operation": "New-InboxRule",
  "OrganizationId": "0fd7c141-339b-4c85-9336-52b8d5e14c89",
  "RecordType": "ExchangeAdmin",
  "ResultStatus": "Success",
  "UserId": "compromised.user@company.com",
  "Parameters": {
    "ForwardTo": ["attacker@malicious.com"],
    "Enabled": true,
    "DeleteMessage": false
  }
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect suspicious delegate additions
SELECT UserId, COUNT(*) as count
FROM AuditLogs 
WHERE Operation = 'Add-MailboxPermission'
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING count > 3;

-- Detect mass email access
SELECT UserId, SUM(MessageCount) as total_messages
FROM AuditLogs
WHERE Operation = 'MailItemsAccessed'
AND TimeGenerated > ago(24h)
GROUP BY UserId
HAVING total_messages > 1000;

-- Detect suspicious forwarding rules
SELECT UserId, COUNT(*) as rule_count
FROM AuditLogs
WHERE Operation IN ('New-InboxRule', 'Set-InboxRule')
AND TimeGenerated > ago(24h)
AND Parameters.ForwardTo NOT LIKE '%@company.com'
GROUP BY UserId
HAVING rule_count > 2;
```

### Baseline Deviation Monitoring
- Track normal patterns of mailbox access per user
- Monitor typical volume of emails accessed per session
- Establish baseline for delegate permissions changes
- Alert on deviations > 2 standard deviations from normal

## 4. Mitigation Strategies

### Administrative Controls
- Require MFA for all mailbox access
- Implement conditional access policies
- Regular review of mailbox delegates
- Disable legacy authentication protocols

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "name": "Block Legacy Authentication",
    "conditions": {
      "clientAppTypes": ["exchangeActiveSync", "other"],
      "applications": {
        "includeApplications": ["Office365"]
      }
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Configure alerts for suspicious patterns
- Monitor Exchange admin audit logs
- Track mail forwarding rule changes

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected mailboxes
2. Review audit logs for access patterns
3. Check for unauthorized delegates
4. Search for suspicious forwarding rules

### Investigation
1. Export relevant audit logs
2. Review authentication logs
3. Check for additional compromised accounts
4. Document timeline of events

### Containment
1. Reset affected account credentials
2. Remove unauthorized delegates
3. Delete malicious forwarding rules
4. Block suspicious IP addresses

## 6. References

MITRE:
- https://attack.mitre.org/techniques/T1114/002/

Microsoft:
- https://docs.microsoft.com/en-us/microsoft-365/security/
- https://docs.microsoft.com/en-us/exchange/security-and-compliance/

Additional Documentation:
- Microsoft 365 Defender Portal documentation
- Exchange Online PowerShell documentation

---

# Threat Model: Password Policy Discovery (T1201) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries attempt to discover password policy settings to optimize brute force and password spray attacks. This includes gathering information about:

- Password complexity requirements
- Password history settings 
- Account lockout thresholds
- Password expiration policies
- MFA requirements and settings

## 2. Attack Vectors

### 2.1 Direct Password Policy Review
**Description**: Adversaries with admin access review password policy settings through Azure Portal or PowerShell

**Audit Operations**:
- "Set password policy"
- "Update user"

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T15:22:43",
  "Id": "18a7c443-8ea2-4f21-8888-e4e55ef9a056",
  "Operation": "Set password policy",
  "OrganizationId": "b7f4bc64-2b47-4c80-8877-5c45b9ee2f44",
  "RecordType": 1,
  "UserKey": "10032001A64A9EA1@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "Global Password Policy",
  "ModifiedProperties": [
    {
      "Name": "PasswordComplexity",
      "NewValue": "Enabled",
      "OldValue": "Disabled"
    },
    {
      "Name": "MinPasswordLength", 
      "NewValue": "8",
      "OldValue": "6"
    }
  ]
}
```

### 2.2 Password Reset Error Analysis
**Description**: Adversaries attempt password resets to trigger error messages revealing policy requirements

**Audit Operations**:
- "Reset user password"
- "Change user password"
- "Set force change user password"

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T16:14:22", 
  "Id": "24c88c62-2a23-4866-9999-f223de4a1122",
  "Operation": "Reset user password",
  "OrganizationId": "b7f4bc64-2b47-4c80-8877-5c45b9ee2f44",
  "RecordType": 1,
  "ResultStatus": "Failed",
  "UserKey": "john.smith@contoso.com",
  "ErrorDetails": {
    "ErrorCode": "PasswordValidationFailed",
    "Message": "Password does not meet complexity requirements"
  }
}
```

### 2.3 Directory Role Enumeration
**Description**: Adversaries enumerate directory roles to identify users with password policy management permissions

**Audit Operations**:
- "Add member to role"
- "Remove member from role"

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T14:55:16",
  "Operation": "Add member to role",
  "RecordType": 8,
  "RoleName": "Password Administrator",
  "ObjectId": "8756fdb2-4466-4fb1-9977-ac5c55432194",
  "UserId": "james.wilson@contoso.com",
  "ModifiedProperties": [
    {
      "Name": "Role.DisplayName",
      "NewValue": "Password Administrator"
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Detect rapid password policy setting changes
SELECT Operation, COUNT(*) as changes_count
FROM AuditLogs 
WHERE Operation = 'Set password policy'
AND TimeGenerated > ago(1h)
GROUP BY Operation
HAVING COUNT(*) > 3;

-- Monitor password reset error patterns
SELECT UserKey, COUNT(*) as failed_resets
FROM AuditLogs
WHERE Operation IN ('Reset user password', 'Change user password')
AND ResultStatus = 'Failed'
AND TimeGenerated > ago(24h)
GROUP BY UserKey
HAVING COUNT(*) > 10;
```

### 3.2 Baseline Deviation Monitoring
- Track normal password policy change frequency and alert on deviations
- Monitor typical password reset error rates per user/time period
- Alert on unusual directory role membership changes for password admin roles

## 4. Controls

### 4.1 Administrative Controls
- Implement privileged access management for password policy changes
- Require MFA for all password policy management actions
- Limit password administrator role assignments

### 4.2 Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "passwordPolicyManagement": {
      "includeRoles": ["Password Administrator", "Global Administrator"],
      "grantControls": {
        "requireMFA": true,
        "requirePrivilegedAccess": true
      },
      "sessionControls": {
        "signInFrequency": 4,
        "persistentBrowser": "never"
      }
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable detailed auditing for all password policy changes
- Monitor password administrator role membership changes
- Track failed password reset attempts and error patterns

## 5. Incident Response Playbook

### Initial Detection
1. Review password policy change audit logs
2. Analyze failed password reset patterns
3. Check directory role membership changes

### Investigation
1. Identify source accounts/IPs for suspicious activities
2. Review authentication logs for associated accounts
3. Check for other suspicious activities from same source

### Containment
1. Revoke sessions for suspicious accounts
2. Reset passwords for compromised accounts
3. Review and validate password policy settings
4. Remove unauthorized role assignments

## 6. References

- [MITRE T1201](https://attack.mitre.org/techniques/T1201/)
- [Microsoft Password Policies](https://docs.microsoft.com/azure/active-directory/authentication/concept-password-policies)
- [Azure AD Auditing](https://docs.microsoft.com/azure/active-directory/reports-monitoring/concept-audit-logs)

---

# Threat Model: Event Triggered Execution (T1546) in Microsoft 365 & Entra ID

## Overview
In Microsoft 365 and Entra ID environments, Event Triggered Execution involves abusing legitimate automation and event response features to maintain persistence or escalate privileges. Common targets include:
- Power Automate flows
- Azure Functions 
- Application event handlers
- Scheduled tasks and automation runbooks

## Attack Vectors

### 1. Power Automate Flow Abuse
**Description**: Adversaries create malicious Power Automate flows that execute in response to events like new emails, file changes, or forms submissions.

**Example Attack Scenario**:
1. Attacker compromises admin account
2. Creates flow triggered by new emails to exfiltrate content
3. Flow runs with compromised admin's permissions

**Detection Fields**:
```json
{
  "CreationTime": "2024-01-20T15:30:22",
  "Id": "8382389a-12d4-4c43-a918-2f3e89f11111",
  "Operation": "CreateFlow", 
  "OrganizationId": "8b111c1-2222-3333-4444-555555555555",
  "RecordType": "PowerAutomate",
  "UserKey": "admin@company.com",
  "UserType": "Admin",
  "FlowName": "Email Forward Flow",
  "Triggers": ["When a new email arrives"],
  "Actions": ["Send an email", "HTTP request"]
}
```

### 2. Azure Function Event Trigger
**Description**: Adversaries deploy malicious Azure Functions that execute on schedule or in response to events.

**Example Attack Scenario**: 
1. Attacker creates Azure Function with timer trigger
2. Function executes malicious code with managed identity permissions
3. Provides persistent backdoor access

**Detection Fields**:
```json
{
  "CreationTime": "2024-01-21T09:15:33",
  "Id": "9172389b-82a4-1c23-b828-1a2b3c4d5555", 
  "Operation": "Add service principal.",
  "RecordType": "AzureActiveDirectory",
  "ResultStatus": "Success",
  "UserId": "attacker@company.com",
  "AppId": "11111111-2222-3333-4444-555555555555",
  "AppDisplayName": "Suspicious Function App",
  "ResourceAttributes": {
    "Trigger": "TimerTrigger",
    "Schedule": "0 */5 * * * *"
  }
}
```

### 3. Mailbox Rules for Persistence
**Description**: Adversaries create inbox rules to forward/delete emails or execute additional logic.

**Example Attack Scenario**:
1. Attacker gains access to mailbox
2. Creates rule to forward specific emails externally
3. Rule provides persistent access to communications

**Detection Fields**:
```json
{
  "CreationTime": "2024-01-22T14:22:11",
  "Id": "2789abc1-def2-3456-7890-123456789abc",
  "Operation": "New-InboxRule",
  "OrganizationId": "8b111c1-2222-3333-4444-555555555555", 
  "RecordType": "ExchangeAdmin",
  "UserKey": "victim@company.com",
  "RuleDetails": {
    "ForwardTo": "external@attacker.com",
    "Conditions": ["Subject contains 'confidential'"],
    "DeleteMessage": true
  }
}
```

## Detection Strategies

### Behavioral Analytics
```sql
-- Detect suspicious Power Automate flow creation
SELECT UserKey, Count(*) as FlowCount 
FROM PowerAutomateAudit 
WHERE Operation = 'CreateFlow'
  AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING Count(*) > 5;

-- Alert on Azure Functions with unusual triggers
SELECT AppId, Count(*) as TriggerCount
FROM AzureActivityLog
WHERE ResourceType = 'Microsoft.Web/sites/functions'
  AND OperationName = 'Create'
  AND TimeGenerated > ago(24h)
GROUP BY AppId
HAVING Count(*) > 10;
```

### Baseline Deviations
- Monitor for abnormal spikes in:
  - Flow creation frequency
  - Number of mailbox rules created
  - Azure Function deployments
  - Service principal registrations

### Technical Controls
```json
{
  "preventions": {
    "powerAutomate": {
      "disableUnauthorizedFlows": true,
      "restrictConnectors": ["HTTP", "Azure Functions"],
      "requireApproval": true
    },
    "azureFunctions": {
      "restrictRuntimeVersion": true,
      "enforceHttpsOnly": true,
      "requireManagedIdentity": true
    },
    "mailboxRules": {
      "blockExternalForwarding": true,
      "maximumRulesPerMailbox": 20,
      "requireAdminApproval": true
    }
  }
}
```

## Incident Response Playbook

### Initial Detection
1. Review audit logs for:
   - New Power Automate flows
   - Azure Function deployments
   - Mailbox rule changes
2. Identify affected accounts and resources
3. Document timeline of events

### Investigation
1. Analyze flow/function configurations
2. Review permissions and triggers
3. Check for data exfiltration evidence
4. Identify blast radius

### Containment
1. Disable suspicious flows/functions
2. Remove malicious mailbox rules
3. Reset compromised credentials
4. Block suspicious IP addresses
5. Document all actions taken

## References
- MITRE ATT&CK: T1546
- Microsoft Documentation:
  - Power Automate Security
  - Azure Functions Security
  - Exchange Online Protection
- Cloud Security Best Practices

---

# Threat Model: Outlook Home Page (T1137.004) in Microsoft 365 & Entra ID

## 1. Overview
The Outlook Home Page feature allows customization of folder presentation by loading HTML content from a URL when folders are opened. Adversaries can abuse this by configuring malicious HTML pages that execute code when loaded by Outlook.

## 2. Attack Vectors

### 2.1 Registry Modification
**Description**: Adversaries modify Registry keys to set malicious Home Page URLs for Outlook folders.

**Detection Fields**:
```json
{
  "Operation": "UpdateFolderPermissions",
  "Workload": "Exchange",
  "ObjectId": "/folder/inbox", 
  "ClientIP": "<ip>",
  "UserId": "<email>",
  "CustomData": {
    "FolderPath": "\\Inbox",
    "HomePage": "https://malicious.com/payload.html"
  }
}
```

### 2.2 Direct Exchange Modification
**Description**: Attackers use Exchange PowerShell commands to modify folder properties.

**Detection Fields**:
```json
{
  "Operation": "Set-MailboxFolderPermission",
  "Workload": "Exchange",
  "Parameters": {
    "Identity": "user@domain.com:\\Inbox",
    "User": "Default",
    "AccessRights": "Reviewer",
    "HomePage": "http://evil.com/malware.html"
  }
}
```

### 2.3 Delegated Access Abuse
**Description**: Compromised delegate accounts modify folder settings.

**Detection Fields**:
```json
{
  "Operation": "Add-MailboxPermission",
  "Workload": "Exchange", 
  "ObjectId": "<mailbox>",
  "Parameters": {
    "User": "<delegate>",
    "AccessRights": ["FullAccess"],
    "InheritanceType": "All"
  }
}
```

## 3. Detection Strategies

### Behavioral Analytics:
```sql
SELECT UserId, ClientIP, COUNT(*) as changes
FROM ExchangeAuditLog 
WHERE Operation IN ('UpdateFolderPermissions','Set-MailboxFolderPermission')
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 5
```

### Baseline Monitoring:
- Track normal patterns of folder permission changes
- Alert on deviations >3 standard deviations
- Monitor after-hours activity

### Correlation Rules:
```json
{
  "name": "Suspicious Outlook Home Page Changes",
  "conditions": [
    {
      "operation": "UpdateFolderPermissions",
      "contains": "HomePage",
      "timeWindow": "5m",
      "threshold": 3
    },
    {
      "operation": "Add-MailboxPermission",
      "timeWindow": "1h",
      "threshold": 1  
    }
  ]
}
```

## 4. Mitigation Controls 

### Administrative:
- Disable Outlook Home Page feature via Group Policy
- Require approval for folder permission changes
- Restrict delegate access assignments

### Technical:
```json
{
  "outlookPolicy": {
    "disableHomePage": true,
    "restrictDelegateAccess": true,
    "auditDelegateChanges": true,
    "requireMFA": true
  }
}
```

### Monitoring:
- Real-time alerts on folder permission changes
- Daily review of delegate assignments
- Weekly audit of Home Page configurations

## 5. Incident Response

### Initial Detection:
1. Identify affected mailboxes
2. Capture Home Page URL configurations
3. Collect related audit logs

### Investigation:
1. Review delegate access history
2. Analyze Home Page content
3. Track lateral movement attempts

### Containment:
1. Block malicious URLs
2. Remove compromised delegates
3. Reset affected mailbox permissions

## 6. References
- MITRE ATT&CK: T1137.004
- Microsoft Security Documentation: MS500918 
- Exchange Online PowerShell Documentation

Note: This is a synthetic example for demonstration. Actual implementations should be tested and customized for your environment.

---

# Threat Model: Web Session Cookie (T1550.004) in Microsoft 365 & Entra ID

## 1. Overview
This technique involves adversaries using stolen session cookies to bypass authentication controls in Microsoft 365 and Entra ID services. By obtaining valid session cookies through malware, browser exploitation, or cookie theft, attackers can impersonate legitimate users without requiring credentials or MFA.

## 2. Attack Vectors

### Vector 1: SharePoint/OneDrive Cookie Theft
**Description**: Adversary steals SharePoint/OneDrive session cookies to access document libraries and sites without authentication.

**Detection Fields**:
- Operation: "FileAccessed"
- ClientIP
- UserAgent 
- UserId
- WorkspaceId

**Example Log**:
```json
{
    "CreationTime": "2024-01-20T15:22:31",
    "Id": "3c7b2afe-3c3b-4f9a-b2d8-1f6a1af4517a",
    "Operation": "FileAccessed",
    "OrganizationId": "4a7c8234-8123-4de3-9d38-7a4632b6b89d",
    "RecordType": 6,
    "UserKey": "i:0h.f|membership|user@contoso.com",
    "UserType": 0,
    "Version": 1,
    "Workload": "SharePoint",
    "ClientIP": "167.220.1.108",
    "ObjectId": "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Budget2024.xlsx",
    "UserId": "user@contoso.com",
    "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "SiteUrl": "/sites/Finance",
    "SourceFileName": "Budget2024.xlsx",
    "WorkspaceId": "b0a5967b-75d2-4a8b-9562-26b1756b60f0"
}
```

### Vector 2: Exchange Online Web Access Cookie Abuse
**Description**: Attacker uses stolen OWA/Outlook Web cookies to access email without credentials.

**Detection Fields**:
- Operation: "MailItemsAccessed" 
- ClientInfoString
- ClientIPAddress
- LogonUserSid
- OperationProperties

**Example Log**:
```json
{
    "CreationTime": "2024-01-20T16:14:22",
    "Id": "4a2b1bfe-2c3b-5f8a-a3d7-2f7a2af4528b", 
    "Operation": "MailItemsAccessed",
    "OrganizationId": "4a7c8234-8123-4de3-9d38-7a4632b6b89d",
    "RecordType": 2,
    "ResultStatus": "Succeeded",
    "UserKey": "USER-KEY",
    "UserType": 0,
    "Version": 1,
    "Workload": "Exchange",
    "ClientInfoString": "Client=OutlookService;Mozilla/5.0",
    "ClientIPAddress": "167.220.1.108",
    "LogonUserSid": "S-1-5-21-...",
    "MailboxGuid": "d8ab2afe-3c3b-4f9a-b2d8-1f6a1af4517a",
    "MailboxOwnerUPN": "user@contoso.com",
    "OperationProperties": [
        "Folder: Inbox",
        "ClientVersion: 15.20.4815.0"
    ]
}
```

### Vector 3: Teams Web Client Cookie Theft
**Description**: Adversary steals Teams web client cookies to access chats and meetings.

**Detection Fields**:
- Operation: "TeamsSessionStarted"
- UserAgent
- ClientIP
- DeviceDetail
- ActorIpAddress

**Example Log**:
```json
{
    "CreationTime": "2024-01-20T17:08:45",
    "Operation": "TeamsSessionStarted", 
    "OrganizationId": "4a7c8234-8123-4de3-9d38-7a4632b6b89d",
    "RecordType": 25,
    "ResultStatus": "Success",
    "UserType": 0,
    "Version": 1,
    "Workload": "MicrosoftTeams",
    "UserId": "user@contoso.com",
    "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "ClientIP": "167.220.1.108",
    "DeviceDetail": {
        "deviceName": "Chrome Browser",
        "deviceType": "Browser"
    },
    "ActorIpAddress": "167.220.1.108"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules:
```sql
-- Detect access from new IP addresses
SELECT UserId, ClientIP, COUNT(*) as access_count
FROM AuditLogs 
WHERE TimeGenerated > ago(1h)
  AND Operation IN ('FileAccessed', 'MailItemsAccessed', 'TeamsSessionStarted')
  AND ClientIP NOT IN (
    SELECT DISTINCT ClientIP 
    FROM AuditLogs 
    WHERE TimeGenerated BETWEEN ago(30d) AND ago(1h)
  )
GROUP BY UserId, ClientIP
HAVING access_count > 10;

-- Detect concurrent sessions from different locations
SELECT UserId, COUNT(DISTINCT ClientIP) as location_count
FROM AuditLogs
WHERE TimeGenerated > ago(15m)
GROUP BY UserId 
HAVING COUNT(DISTINCT ClientIP) > 2;
```

### Baseline Deviation Monitoring:
- Track normal user access patterns including:
  - Typical access times
  - Common IP ranges
  - Expected user agents
  - Normal session durations
- Alert on deviations like:
  - Access outside business hours
  - Connections from unusual locations
  - Abnormal volume of operations

## 4. Mitigation Strategies

### Administrative Controls:
- Implement conditional access policies
- Configure session timeouts
- Enable modern authentication
- Block legacy authentication protocols

### Technical Controls:
```json
{
  "conditionalAccessPolicy": {
    "name": "Block suspicious sessions",
    "conditions": {
      "applications": {
        "includeApplications": ["All"]
      },
      "users": {
        "includeUsers": ["All"]
      },
      "locations": {
        "includeLocations": ["All"],
        "excludeLocations": ["Trusted Locations"]
      }
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": [
        "mfa",
        "compliantDevice",
        "domainJoinedDevice"
      ]
    }
  }
}
```

### Monitoring Controls:
- Enable unified audit logging
- Configure alerts for suspicious sign-ins
- Monitor session token lifetimes
- Track authentication events

## 5. Incident Response Playbook

### Initial Detection:
1. Identify affected user accounts
2. Review authentication logs
3. Check for suspicious IP addresses
4. Analyze user agent patterns

### Investigation:
1. Review all user activity from suspicious sessions
2. Check for data exfiltration
3. Identify source of cookie theft
4. Document timeline of events

### Containment:
1. Revoke all active sessions
2. Reset user passwords
3. Enable additional MFA requirements
4. Block suspicious IPs
5. Remove malicious access

## 6. References

- MITRE ATT&CK: T1550.004
- Microsoft Security Documentation
- Azure AD Identity Protection
- Microsoft 365 Defender

---

# Threat Model: Impersonation (T1656) in Microsoft 365 & Entra ID

## 1. Overview 

Adversaries exploit Microsoft 365 and Entra ID through impersonation attacks by:
- Creating convincing phishing emails that appear to come from legitimate senders
- Manipulating email headers and display names to impersonate trusted users
- Abusing mail flow rules and delegated permissions to enable impersonation
- Leveraging compromised accounts to conduct internal phishing

## 2. Attack Vectors

### 2.1 Display Name Spoofing

**Description**: Adversaries modify email display names to impersonate executives or trusted entities while using external domains.

**Detection Fields**:
```json
{
  "Operation": "Send",
  "ClientIP": "<ip_address>",
  "From": "CEO Name <attacker@external.com>",
  "Subject": "Urgent Wire Transfer Request",
  "ExternalAccess": true,
  "MessageId": "<id>",
  "RecipientCount": 1
}
```

**Audit Log Example**:
```json
{
  "CreationTime": "2024-01-15T10:30:22",
  "Id": "1a2b3c4d-5e6f-7g8h-9i0j",
  "Operation": "Send", 
  "OrganizationId": "org123",
  "RecordType": 28,
  "UserKey": "attacker@external.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "Urgent Wire Transfer Request",
  "UserId": "attacker@external.com",
  "ClientIP": "192.168.1.100",
  "From": "John Smith (CEO) <attacker@external.com>",
  "To": "finance@victim.com"
}
```

### 2.2 Mail Flow Rule Abuse

**Description**: Attackers create mail flow rules to hide or redirect suspicious emails.

**Detection Fields**:
```json
{
  "Operation": "New-InboxRule", 
  "Parameters": {
    "ForwardTo": "external@attacker.com",
    "DeleteMessage": true,
    "Conditions": {
      "FromAddresses": ["ceo@company.com", "finance@company.com"]
    }
  }
}
```

**Audit Log Example**:
```json
{
  "CreationTime": "2024-01-15T14:22:10",
  "Id": "9i8h7g6f-5e4d-3c2b-1a0b",
  "Operation": "New-InboxRule",
  "OrganizationId": "org123", 
  "RecordType": 1,
  "UserKey": "compromised@victim.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "10.1.1.100",
  "RuleName": "Forward All Executive Emails",
  "RuleParameters": {
    "ForwardTo": ["external@attacker.com"],
    "DeleteMessage": true,
    "Conditions": {
      "FromAddresses": ["ceo@company.com", "finance@company.com"]
    }
  }
}
```

### 2.3 Delegated Access Abuse

**Description**: Adversaries add mailbox delegation permissions to maintain persistent access.

**Detection Fields**:
```json
{
  "Operation": "Add-MailboxPermission",
  "Parameters": {
    "Identity": "executive@company.com",
    "User": "compromised@company.com",
    "AccessRights": ["FullAccess"]
  }
}
```

**Audit Log Example**:
```json
{
  "CreationTime": "2024-01-15T16:45:33",
  "Id": "5e4d3c2b-1a0b-9i8h-7g6f",
  "Operation": "Add-MailboxPermission",
  "OrganizationId": "org123",
  "RecordType": 1,
  "UserKey": "admin@company.com",
  "UserType": 2,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "10.1.1.100",
  "ObjectId": "executive@company.com",
  "ModifiedProperties": [
    {
      "Name": "AccessRights",
      "NewValue": ["FullAccess"]
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect display name spoofing
SELECT *
FROM EmailEvents 
WHERE SenderDisplayName LIKE '%CEO%'
  AND SenderDomain NOT IN (SELECT Domain FROM TrustedDomains)
  AND TimeDelta <= 24hrs;

-- Detect suspicious mail rules
SELECT * 
FROM InboxRuleEvents
WHERE (ForwardTo LIKE '%external%' OR DeleteMessage = true)
  AND CreatedBy NOT IN (SELECT UserId FROM ITAdmins)
  AND TimeDelta <= 1hr;

-- Detect unusual delegation
SELECT *
FROM MailboxPermissionEvents
WHERE AccessRights = 'FullAccess'
  AND TargetMailbox IN (SELECT Email FROM Executives)
  AND TimeDelta <= 6hrs;
```

### 3.2 Baseline Deviation Monitoring

- Track normal patterns of:
  - Email sending volumes and recipients
  - Mail rule creation frequency
  - Delegation permission changes
  - Display name patterns

- Alert on deviations:
  - Sudden spikes in external forwards
  - Unusual timing of permission changes
  - Multiple rule creations in short period
  - New display names matching executives

## 4. Mitigation Strategies

### Administrative Controls
- Implement strict display name policies
- Require approval for mail flow rules
- Regular review of mailbox permissions
- Training on impersonation awareness

### Technical Controls
```json
{
  "AuthenticationPolicies": {
    "RequireMFA": true,
    "BlockLegacyAuth": true
  },
  "TransportRules": {
    "ExternalSenderWarning": true,
    "BlockForwardingRules": true
  },
  "ConditionalAccess": {
    "RequireCompliantDevice": true,
    "BlockUntrustedLocations": true
  }
}
```

### Monitoring Controls
- Real-time alerts for suspicious patterns
- Daily reports of permission changes
- Weekly review of mail flow rules
- Monthly audit of delegated access

## 5. Incident Response Playbook

1. Initial Detection
   - Validate alert authenticity
   - Identify affected accounts
   - Document indicators of compromise

2. Investigation
   - Review audit logs for timeline
   - Analyze mail flow patterns
   - Check for persistence mechanisms
   - Map affected systems/users

3. Containment
   - Block suspicious senders
   - Remove malicious rules
   - Revoke compromised credentials
   - Reset affected passwords

## 6. References

- [MITRE ATT&CK - T1656](https://attack.mitre.org/techniques/T1656/)
- [Microsoft - Anti-Spoofing Protection](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection)
- [Microsoft - Investigating Suspicious Email](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/investigating-suspicious-email)

Would you like me to expand on any particular section?

---

# Threat Model: Disable or Modify Cloud Logs (T1562.008) in Microsoft 365 & Entra ID

## 1. Overview 
Adversaries may attempt to disable or modify audit logging capabilities in Microsoft 365 and Entra ID to evade detection of their activities. This can include:
- Disabling mailbox audit logging
- Modifying audit retention periods
- Disabling advanced audit features
- Removing logging settings for specific services

## 2. Attack Vectors

### 2.1 Mailbox Audit Bypass
**Description**: Adversaries use Set-MailboxAuditBypassAssociation to disable mailbox audit logging for specific accounts.

**Attack Scenario**:
1. Attacker compromises admin account
2. Disables mailbox auditing for target account
3. Performs mailbox exfiltration without generating logs
4. Re-enables auditing to hide changes

**Detection Fields**:
```json
{
  "Operation": "Set-MailboxAuditBypassAssociation",
  "ResultStatus": "Success",
  "Parameters": [{
    "Name": "Identity",
    "Value": "<UserPrincipalName>"
  }],
  "Actor": [{
    "ID": "<Admin UPN>",
    "Type": "User"
  }]
}
```

### 2.2 Audit Retention Modification  
**Description**: Attackers modify audit log retention periods to ensure evidence is purged quickly.

**Detection Fields**:
```json
{
  "Operation": "UpdatedDataAccessSetting", 
  "ObjectId": "AuditLogRetention",
  "ModifiedProperties": [{
    "Name": "RetentionDays",
    "OldValue": "90",
    "NewValue": "7"
  }]
}
```

### 2.3 Advanced Audit Disablement
**Description**: Adversaries disable advanced audit features by downgrading licenses or modifying audit settings.

**Detection Fields**:
```json
{
  "Operation": "Change user license",
  "TargetUserOrGroupName": "<User>",
  "ModifiedProperties": [{
    "Name": "LicenseAssignment",
    "OldValue": "Enterprise E5",
    "NewValue": "Enterprise E3" 
  }]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Monitor audit configuration changes
SELECT Operation, ActorIpAddress, TargetUserOrGroupName 
FROM UnifiedAuditLog
WHERE Operation IN (
  'Set-MailboxAuditBypassAssociation',
  'UpdatedDataAccessSetting',
  'Change user license'
)
AND TimeGenerated > ago(1h)
GROUP BY Operation, ActorIpAddress, TargetUserOrGroupName
HAVING count(*) > 3
```

### 3.2 Baseline Deviations
- Monitor frequency of audit configuration changes vs baseline
- Alert on changes outside business hours
- Track volume of configuration changes per admin

### 3.3 Real-time Alerts
- Immediate alert on mailbox audit bypass
- Alert on reduction in audit retention periods
- Alert on license downgrades from E5 to E3

## 4. Mitigation Strategies

### Administrative Controls
- Implement least privilege for audit configuration changes
- Require MFA for audit setting modifications
- Regular review of audit configurations

### Technical Controls
```json
{
  "auditSettings": {
    "mailboxAudit": {
      "enabled": true,
      "bypassDisabled": true
    },
    "retentionPeriod": {
      "minimumDays": 90,
      "modificationApproval": "required"
    },
    "advancedFeatures": {
      "enforceE5License": true
    }
  }
}
```

### Monitoring Controls
- Daily audit configuration state checks
- Weekly audit policy compliance review
- Monthly audit capability assessment

## 5. Incident Response Playbook

### Initial Detection
1. Validate alert authenticity
2. Identify affected audit components
3. Document timing and scope of changes

### Investigation
1. Review admin activity logs for 24h before/after
2. Check for correlated suspicious activities
3. Identify any data access during audit gaps

### Containment
1. Revert unauthorized audit changes
2. Suspend compromised admin accounts
3. Force rotation of admin credentials
4. Re-enable all logging capabilities

## 6. References
- MITRE: https://attack.mitre.org/techniques/T1562/008/
- Microsoft: https://docs.microsoft.com/en-us/microsoft-365/compliance/audit-log-retention-policies
- Cloud Logging Best Practices: https://docs.microsoft.com/en-us/azure/security/fundamentals/log-audit

This threat model is focused on Microsoft 365 and Entra ID-specific implementations with concrete detection rules, real log examples, and actionable controls.

---

# Threat Model: Data from Information Repositories (T1213) in Microsoft 365 & Entra ID

## 1. Overview
This threat model focuses on adversaries mining sensitive data from Microsoft 365 services like SharePoint, Teams, OneDrive, and Exchange. Key risks include:
- Excessive data access through compromised accounts
- Data exfiltration via downloads and sharing
- Mining of sensitive information through search and discovery features

## 2. Attack Vectors

### 2.1 Mass SharePoint/OneDrive Document Access
**Description**: Adversary uses compromised account to access and download large volumes of documents across multiple sites.

**Attack Scenario**:
1. Compromised admin account accesses multiple SharePoint sites
2. Uses content search/explorer to identify sensitive files
3. Bulk downloads documents using OneDrive sync client

**Detection Fields**:
```json
{
  "Operation": "FileDownloaded",
  "UserAgent": "OneDrive Sync Client",
  "UserId": "<user>",
  "SourceFileName": "<filename>",
  "SourceFileExtension": "<ext>",
  "SiteUrl": "<url>",
  "SourceRelativeUrl": "<path>"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "2d019c22-4d92-1ab9-12dd-908762617263",
  "Operation": "FileDownloaded", 
  "OrganizationId": "4a927127-1b94-42b1-9c47-bab65aeb5352",
  "RecordType": 6,
  "UserKey": "i:0h.f|membership|bob@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "OneDrive",
  "ClientIP": "192.168.1.100",
  "UserId": "bob@contoso.com",
  "SourceFileName": "Q4 Financial Report.xlsx",
  "SiteUrl": "/sites/Finance",
  "UserAgent": "OneDrive Sync Client/22.012.0213.0003"
}
```

### 2.2 Exchange Search and Collection
**Description**: Adversary uses email search capabilities to identify and collect sensitive information.

**Attack Scenario**:
1. Creates compliance search across mailboxes
2. Uses targeted keywords for sensitive data
3. Exports search results

**Detection Fields**:
```json
{
  "Operation": ["SearchCreated", "SearchExported"],
  "SearchQuery": "<query>",
  "UserIds": "<users>",
  "ExportType": "FullSearch",
  "ResultSize": "<size>"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T15:44:12",
  "Id": "8912ed21-99ba-4d88-123a-888abc123456", 
  "Operation": "SearchCreated",
  "OrganizationId": "4a927127-1b94-42b1-9c47-bab65aeb5352",
  "RecordType": 8,
  "UserKey": "i:0h.f|membership|admin@contoso.com",
  "SearchQuery": "subject:'password' OR subject:'credentials'",
  "ExchangeLocation": "All",
  "ResultSize": "25000"
}
```

### 2.3 Teams Channel Mining
**Description**: Adversary accesses Teams channels to collect sensitive conversations and files.

**Attack Scenario**:
1. Joins multiple teams/channels
2. Uses search to find sensitive content
3. Downloads shared files and chat history

**Detection Fields**:
```json
{
  "Operation": ["ChannelAdded", "MessagesExported", "FileDownloaded"],
  "TeamName": "<team>",
  "ChannelName": "<channel>",
  "ExportType": "<type>",
  "ItemCount": "<count>"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T09:12:44",
  "Id": "72819a22-8172-9182-77ac-123456789012",
  "Operation": "MessagesExported",
  "OrganizationId": "4a927127-1b94-42b1-9c47-bab65aeb5352", 
  "RecordType": 105,
  "UserKey": "carol@contoso.com",
  "TeamName": "Project X",
  "ChannelName": "Confidential",
  "ExportType": "ChatHistory",
  "ItemCount": 5000
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Detect anomalous file access volume
SELECT UserId, COUNT(*) as FileAccesses,
FROM AuditLogs 
WHERE Operation IN ('FileAccessed','FileDownloaded')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 100 -- Baseline threshold

-- Detect suspicious search patterns
SELECT UserId, SearchQuery
FROM AuditLogs
WHERE Operation = 'SearchCreated'
AND SearchQuery CONTAINS ANY ('password','secret','confidential')
```

### 3.2 Baseline Deviations
- Monitor daily average file access counts per user
- Track typical search volumes and export sizes
- Alert on deviations >3 standard deviations

### 3.3 Correlation Rules
```sql
-- Correlate suspicious activities
SELECT UserId,
COUNT(CASE WHEN Operation = 'FileDownloaded' THEN 1 END) as Downloads,
COUNT(CASE WHEN Operation = 'SearchCreated' THEN 1 END) as Searches,
COUNT(CASE WHEN Operation = 'MessagesExported' THEN 1 END) as Exports
FROM AuditLogs
WHERE TimeGenerated > ago(24h)
GROUP BY UserId
HAVING Downloads > 50 AND Searches > 10 AND Exports > 0
```

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement information barriers between departments
- Configure DLP policies for sensitive data types
- Enable audit logging for all workloads

### 4.2 Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "name": "Block Suspicious Downloads",
    "conditions": {
      "applications": ["SharePoint", "OneDrive"],
      "clientAppTypes": ["browser", "mobileApps"],
      "riskLevels": ["high"]
    },
    "grantControls": {
      "blockAccess": true
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable alerts for mass downloads
- Monitor search activities across workloads
- Track export operations and volumes

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Review triggered alerts and audit logs
2. Identify affected repositories and data types
3. Determine scope of access and collection

### 5.2 Investigation
1. Analyze user activity patterns and timeline
2. Review searched keywords and accessed content
3. Track data movement and exports

### 5.3 Containment
1. Disable compromised accounts
2. Block suspicious IP addresses
3. Revoke active sessions and tokens

## 6. References
- MITRE ATT&CK: T1213
- Microsoft Security Documentation
- Microsoft 365 Defender Portal Documentation

---

# Threat Model: Masquerade Account Name (T1036.010) in Microsoft 365 & Entra ID

## Overview
Adversaries attempt to create or rename accounts to mimic legitimate service accounts, administrative accounts, or system accounts in Microsoft 365 and Entra ID environments. This technique helps malicious accounts blend in with normal operations.

## Attack Vectors

### 1. Service Principal Masquerading
**Description**: Adversaries create service principals with names similar to legitimate Microsoft or third-party application service principals.

**Example Attack Scenario**:
- Attacker creates service principal named "MS-GraphAPI-Sync" to mimic legitimate Microsoft Graph API applications
- Adds credentials to enable persistent access
- Uses service principal for data exfiltration while appearing as normal API activity

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Add service principal.",
    "Add service principal credentials.",
    "Set delegation entry."
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-03-15T15:22:31",
  "Id": "8382d091-7a0d-43ab-9123-1234567890ab",
  "Operation": "Add service principal.",
  "OrganizationId": "d123456-7890-abcd-efgh-ijklmnopqrst",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "10032001234567@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "8382d091-7a0d-43ab-9123-1234567890ab",
  "UserId": "admin@contoso.com",
  "AppId": "97fb8768-83cd-4ec5-8f49-123456789012",
  "DisplayName": "MS-GraphAPI-Sync",
  "ServicePrincipalType": "Application"
}
```

### 2. Admin Account Cloning
**Description**: Attackers create new accounts with names very similar to existing admin accounts by adding/changing characters.

**Example Attack Scenario**:
- Discovers legitimate admin "john.smith@company.com" 
- Creates "john.srnith@company.com" (replacing 'm' with 'rn')
- Uses similar display name and properties
- Requests admin privileges citing urgency

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Add user.",
    "Update user.",
    "Add member to role."
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-03-15T16:14:22",
  "Id": "bd124f91-7abc-4def-9123-456789abcdef", 
  "Operation": "Add user.",
  "OrganizationId": "d123456-7890-abcd-efgh-ijklmnopqrst",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001234567@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "bd124f91-7abc-4def-9123-456789abcdef",
  "UserId": "admin@contoso.com",
  "TargetUserOrGroupName": "john.srnith@company.com",
  "TargetUserOrGroupType": "User"
}
```

### 3. System Account Impersonation
**Description**: Adversaries create accounts that appear to be system or service accounts using common naming patterns.

**Example Attack Scenario**:
- Creates account named "svc-backup-prod"
- Sets properties to match typical service account patterns
- Uses account for persistent backdoor access

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Add user.",
    "Update user.",
    "Add service principal credentials."
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-03-15T17:01:15",
  "Id": "7281cf92-8def-4abc-9123-456789abcdef",
  "Operation": "Add user.",
  "OrganizationId": "d123456-7890-abcd-efgh-ijklmnopqrst", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001234567@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "7281cf92-8def-4abc-9123-456789abcdef",
  "UserId": "admin@contoso.com",
  "TargetUserOrGroupName": "svc-backup-prod@company.com",
  "TargetUserOrGroupType": "User",
  "UserAccountControl": "514"
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect similar names to existing privileged accounts
SELECT new.DisplayName, existing.DisplayName, 
       LEVENSHTEIN_DISTANCE(new.DisplayName, existing.DisplayName) as name_similarity
FROM user_creation_events new
CROSS JOIN privileged_accounts existing
WHERE LEVENSHTEIN_DISTANCE(new.DisplayName, existing.DisplayName) <= 2
  AND new.DisplayName != existing.DisplayName;

-- Detect service principal naming pattern abuse
SELECT DisplayName, CreationTime
FROM service_principal_creation_events 
WHERE DisplayName LIKE '%graph%' 
   OR DisplayName LIKE '%azure%'
   OR DisplayName LIKE 'MS-%'
   OR DisplayName LIKE 'svc-%';
```

### Baseline Deviation Monitoring
- Track normal patterns of account creation by type and naming convention
- Alert on deviations from established naming standards
- Monitor for unusual bursts of account creation activity
- Track service principal credential additions outside change windows

### Threshold Rules
```json
{
  "rules": [
    {
      "name": "Similar Admin Account Names",
      "threshold": 1,
      "timeWindow": "24h",
      "condition": "new_account_name.similarity(existing_admin_name) >= 0.8"
    },
    {
      "name": "Service Account Creation Burst",
      "threshold": 3,
      "timeWindow": "1h",
      "condition": "account_name LIKE 'svc-%'"
    }
  ]
}
```

## Mitigation Strategies

### Administrative Controls
1. Implement strict account naming policies and conventions
2. Require multi-level approval for service principal creation
3. Enforce naming standards through Azure Policy
4. Regular auditing of account names against approved patterns

### Technical Controls
```json
{
  "nameStandardsPolicy": {
    "userAccounts": {
      "pattern": "^[a-z]{1}[a-z0-9]{2,64}$",
      "prefixBlacklist": ["admin", "svc", "system"]
    },
    "servicePrincipals": {
      "pattern": "^[A-Z]{2,4}-[A-Za-z0-9-]{4,64}$",
      "requireApproval": true
    }
  },
  "monitoring": {
    "enableNameSimilarityChecks": true,
    "similarityThreshold": 0.8,
    "requireApprovalAboveThreshold": true
  }
}
```

### Monitoring Controls
1. Configure alerts for:
   - Service principal creation with similar names to Microsoft services
   - New accounts with names similar to admins
   - Account creation outside business hours
   - Bulk account creation events

2. Regular review of:
   - Service principal naming patterns
   - Admin account naming consistency
   - Account creation patterns and trends

## Incident Response Playbook

### Initial Detection
1. Document the suspected masqueraded account details
2. Compare with legitimate account naming patterns
3. Review audit logs for creation context and creator
4. Identify any related credential or permission changes

### Investigation
1. Track account activity since creation
2. Review authentication patterns
3. Check for additional similarly named accounts
4. Analyze permissions and group memberships
5. Document all associated service principals and credentials

### Containment
1. Disable suspected masqueraded accounts
2. Remove any assigned permissions and credentials
3. Block creation of similarly named accounts
4. Review and revoke any access granted by the account
5. Force password reset for any potentially compromised accounts

## References
- MITRE ATT&CK: T1036.010
- Microsoft Documentation: Service Principal Management
- Microsoft Security Best Practices: Account Naming Standards
- Azure AD Identity Protection Documentation

---

# Threat Model: Transfer Data to Cloud Account (T1537) in Microsoft 365 & Entra ID

## 1. Overview
This technique involves adversaries exfiltrating data by transferring it to another cloud account they control within Microsoft 365 through legitimate sharing mechanisms and APIs. This can bypass traditional DLP monitoring that focuses on external transfers.

## 2. Attack Vectors

### 2.1 OneDrive/SharePoint Anonymous Sharing Links
**Description**: Adversaries create anonymous sharing links for sensitive files/folders to enable download without authentication.

**Audit Operations**:
- AnonymousLinkCreated
- AnonymousLinkUsed
- SharingSet

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:23:41",
  "Id": "62e95428-2713-435e-a5c8-39efb0e9e591",
  "Operation": "AnonymousLinkCreated",
  "OrganizationId": "4d7c8e9a-5a09-4ed4-b3ea-dd44f557a87c",
  "RecordType": 28,
  "UserKey": "i:0h.f|membership|user@contoso.com",
  "UserType": 0,
  "ObjectId": "https://contoso-my.sharepoint.com/personal/user_contoso_com/Documents/Financial Reports/",
  "UserId": "user@contoso.com",
  "EventSource": "SharePoint",
  "ItemType": "Folder",
  "SiteUrl": "/personal/user_contoso_com",
  "SourceFileExtension": "",
  "SourceFileName": "Financial Reports",
  "SourceRelativeUrl": "Documents/Financial Reports"
}
```

### 2.2 Azure Storage SAS Token Generation
**Description**: Adversaries generate SAS tokens for blob storage containers to enable direct access.

**Audit Operations**:
- Add service principal credentials
- FileDownloaded
- FileAccessed

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "891f7e12-4562-4c12-8544-fbec7a5937ac", 
  "Operation": "Add service principal credentials",
  "OrganizationId": "4d7c8e9a-5a09-4ed4-b3ea-dd44f557a87c",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "i:0h.f|membership|admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "8dd9c8a5-a2c2-4244-8126-93fb4302d47e",
  "UserId": "admin@contoso.com",
  "AadAppId": "88ce59c9-0721-432b-9789-cf6c1b3467f2"
}
```

### 2.3 Delegated Admin Permissions
**Description**: Adversaries add external partner delegated admin permissions to gain tenant access.

**Audit Operations**:
- Add partner to company
- Add delegation entry
- Set delegation entry

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:08:33",
  "Id": "44c8f7e2-8714-4b02-9a8d-58c6f282571a",
  "Operation": "Add partner to company",
  "OrganizationId": "4d7c8e9a-5a09-4ed4-b3ea-dd44f557a87c", 
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "i:0h.f|membership|admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "partner_company",
  "UserId": "admin@contoso.com",
  "PartnerTenantId": "92f5e234-8c17-42aa-921b-6c87f162d8be"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect mass anonymous link creation
SELECT UserId, COUNT(*) as LinkCount
FROM AuditLogs 
WHERE Operation = 'AnonymousLinkCreated'
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 10

-- Detect unusual SAS token generation
SELECT ClientIP, COUNT(*) as TokenCount 
FROM AuditLogs
WHERE Operation = 'Add service principal credentials'
AND TimeGenerated > ago(24h)
GROUP BY ClientIP
HAVING COUNT(*) > baseline_average + (2 * baseline_stddev)
```

### 3.2 Baseline Deviation Monitoring
- Monitor normal patterns of:
  - Number of anonymous links created per user per hour
  - Volume of data downloaded via SAS tokens
  - Frequency of partner delegation changes
- Alert on deviations > 2 standard deviations from baseline

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Require approval for external sharing
- Enforce expiration on anonymous links
- Review and limit delegated admin permissions

### 4.2 Technical Controls
```json
{
  "sharingCapability": "ExternalUserSharingOnly",
  "anonymousLinkExpirationInDays": 7,
  "blockMalwareForSharingFiles": true,
  "requireAnonymousLinksExpireInDays": true,
  "preventExternalUsersFromResharing": true
}
```

### 4.3 Monitoring Controls
- Enable unified audit logging
- Configure alerts for suspicious sharing patterns
- Monitor delegated admin relationship changes

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected resources and access patterns
2. Review audit logs for sharing activities
3. Document scope of data exposure

### Investigation
1. Map all anonymous links and access patterns
2. Review service principal credential changes
3. Analyze partner relationships and permissions

### Containment
1. Revoke compromised sharing links
2. Remove unauthorized delegated permissions
3. Reset affected service principal credentials

## 6. References
- MITRE ATT&CK: T1537
- Microsoft: Secure external sharing in SharePoint Online
- Microsoft: Monitor sharing in SharePoint admin center
- MITRE: Cloud Account Tactics

---

# Threat Model: Create Account (T1136) in Microsoft 365 & Entra ID

## 1. Overview
This technique involves adversaries creating accounts in Microsoft 365 and Entra ID to maintain unauthorized access. Key account creation vectors include:
- User accounts via admin portals/PowerShell
- Service principals for applications 
- Guest accounts through external sharing
- Hybrid identity sync

## 2. Attack Vectors

### 2.1 Administrative Account Creation
**Description**: Adversaries with Global Admin or User Admin privileges create new accounts through admin interfaces

**Audit Operations**:
- "Add user."
- "Update user."
- "Set license properties."

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:43",
  "Id": "18264d4a-5748-4812-a274-3dc1337e8a2c",
  "Operation": "Add user.", 
  "OrganizationId": "4891bed4-82e4-4f89-9fc2-c760b8776e45",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "Admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "NewUser@contoso.com",
  "UserId": "Admin@contoso.com",
  "ModifiedProperties": [
    {
      "Name": "AccountEnabled",
      "NewValue": "True"
    },
    {
      "Name": "UserPrincipalName", 
      "NewValue": "NewUser@contoso.com"
    }
  ]
}
```

### 2.2 Service Principal Creation
**Description**: Creating service principals to establish persistence through application identities

**Audit Operations**:
- "Add service principal."
- "Add service principal credentials."
- "Add delegation entry."

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22", 
  "Operation": "Add service principal.",
  "ApplicationId": "a132c89b-3c87-4b9p-92f1-392f77c99c21",
  "ObjectId": "ServicePrincipal_1",
  "ResultStatus": "Success",
  "Actor": [
    {
      "ID": "admin@contoso.com",
      "Type": 0
    }
  ],
  "Target": [
    {
      "ID": "ServicePrincipal_1", 
      "Type": 2
    }
  ]
}
```

### 2.3 Guest Account Creation
**Description**: Creating external guest accounts through Teams/SharePoint sharing

**Audit Operations**:
- "SharingInvitationCreated"
- "Add user."
- "MemberAdded"

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T17:33:11",
  "Operation": "SharingInvitationCreated",
  "OrganizationId": "4891bed4-82e4-4f89-9fc2-c760b8776e45", 
  "UserKey": "user@contoso.com",
  "ObjectId": "external@partner.com",
  "UserId": "user@contoso.com",
  "ApplicationId": "00000003-0000-0ff1-ce00-000000000000",
  "InvitedAs": "Guest",
  "SiteUrl": "/sites/Marketing",
  "TargetUserOrGroupType": "Guest"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Detect bulk account creation
SELECT UserKey, COUNT(*) as creation_count
FROM AuditLogs 
WHERE Operation = "Add user."
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING creation_count >= 5

-- Detect service principal creation outside business hours
SELECT *
FROM AuditLogs
WHERE Operation = "Add service principal."
AND TimeGenerated.hour NOT BETWEEN 9 AND 17
```

### 3.2 Baseline Deviations
- Monitor daily average of new account creations
- Alert on >2 standard deviations from baseline
- Track service principal creation patterns by department
- Monitor guest account invitation velocity

### 3.3 Risk Indicators
- Account creation from unusual locations/IPs
- Multiple service principals created in short time
- Guest accounts created with similar naming patterns
- Account creation followed by immediate privilege escalation

## 4. Mitigation Controls

### Administrative Controls
1. Implement approval workflow for account creation
2. Require business justification for service principals
3. Restrict guest account creation to specific teams
4. Enforce naming conventions for accounts

### Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Account Creation Controls",
    "Conditions": {
      "UserRisk": "high",
      "SignInRisk": "medium",
      "Users": {
        "Include": ["User Administrators", "Global Administrators"]
      },
      "Applications": {
        "Include": ["Azure Portal", "Microsoft Admin Portals"]
      }
    },
    "Controls": {
      "RequireMFA": true,
      "RequireCompliantDevice": true,
      "RestrictBrowsers": ["Edge", "Chrome"],
      "BlockLegacyAuth": true
    }
  }
}
```

### Monitoring Controls
1. Real-time alerts for privileged account creation
2. Daily reports on guest account creation
3. Service principal credential monitoring
4. Account creation pattern analysis

## 5. Incident Response

### Initial Detection
1. Validate account creation audit logs
2. Check creator's authentication context
3. Review account properties and group memberships
4. Compare against approved requests

### Investigation
1. Timeline analysis of creator's activity
2. Review associated IP addresses and locations
3. Check for related service principal creation
4. Analyze assigned licenses and permissions

### Containment
1. Disable suspicious accounts
2. Revoke service principal credentials
3. Block guest access if compromised
4. Reset admin credentials if needed

## 6. References
- [MITRE ATT&CK T1136](https://attack.mitre.org/techniques/T1136/)
- [Microsoft Account Creation Security](https://docs.microsoft.com/security/account-creation)
- [Entra ID Audit Events](https://docs.microsoft.com/azure/active-directory/audit-logs)
- [Service Principal Security](https://docs.microsoft.com/azure/active-directory/develop/security-best-practices)

---

# Threat Model: Cloud Service Discovery (T1526) in Microsoft 365 & Entra ID

## 1. Overview
Adversaries enumerate Microsoft 365 and Entra ID services and resources to understand the environment, discover potential targets, and plan further attacks. This includes discovering enabled services, applications, security controls, and administrative configurations.

## 2. Attack Vectors

### 2.1 Microsoft Graph API Enumeration
**Description**: Adversaries use authenticated Microsoft Graph API queries to enumerate services and configurations.

**Attack Scenario**:
1. Attacker compromises user credentials
2. Uses Microsoft Graph API to enumerate all applications, services, and configurations
3. Maps discovered services for targeting sensitive data or permissions

**Detection Fields**:
```json
{
  "Operation": "Add service principal.",
  "ApplicationId": "<guid>",
  "Target": [{"Type": "Application", "ID": "<guid>"}],
  "Actor": ["<user>"],
  "ResultStatus": "Success"
}
```

### 2.2 Admin Portal Reconnaissance 
**Description**: Attackers access admin portals to manually discover enabled services and configurations.

**Detection Fields**:
```json
{
  "Operation": "ProjectListAccessed",
  "WorkloadName": "ProjectForTheWeb", 
  "ObjectId": "*",
  "UserId": "<email>",
  "ClientIP": "<ip>",
  "UserAgent": "<browser>"
}
```

### 2.3 PowerShell-based Discovery
**Description**: Using PowerShell modules like MSOnline and AzureAD to programmatically enumerate services.

**Detection Fields**:
```json
{
  "Operation": "Get-MsolCompanyInformation", 
  "RecordType": 15,
  "UserKey": "<upn>",
  "Workload": "AzureActiveDirectory",
  "ResultStatus": "Success"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect rapid service enumeration
SELECT UserId, COUNT(*) as query_count
FROM AuditLogs 
WHERE Operation IN ('ProjectListAccessed', 'CloudAppEvents')
AND TimeGenerated > ago(1h)
GROUP BY UserId 
HAVING COUNT(*) > 100

-- Identify suspicious API queries
SELECT ClientIP, Operation, COUNT(*) 
FROM AuditLogs
WHERE Category = 'ApplicationManagement'
AND TimeGenerated > ago(24h)
GROUP BY ClientIP, Operation
HAVING COUNT(*) > normal_threshold
```

### 3.2 Baseline Deviations
- Monitor for unusual spikes in API queries per user/IP
- Track abnormal admin portal access patterns
- Alert on first-time access to management APIs

### 3.3 Correlation Rules
```sql
-- Correlate discovery with other suspicious activity
SELECT a.UserId, a.ClientIP,
       COUNT(DISTINCT a.Operation) as unique_ops
FROM AuditLogs a
JOIN AlertEvents e ON a.UserId = e.UserId
WHERE a.TimeGenerated BETWEEN e.TimeGenerated 
      AND dateadd(hour,2,e.TimeGenerated)
GROUP BY a.UserId, a.ClientIP
HAVING COUNT(DISTINCT a.Operation) > 10
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement least privilege access
- Regularly review service principal permissions
- Enable Conditional Access policies

### Technical Controls
```json
{
  "ConditionalAccess": {
    "SignInRiskLevels": ["high"],
    "UserRiskLevels": ["high"],
    "Applications": {
      "IncludeApplications": ["Office365", "AzureManagement"]
    },
    "Controls": {
      "RequireMFA": true,
      "BlockAccess": {
        "UnknownPlatforms": true
      }
    }
  }
}
```

### Monitoring Controls
- Enable detailed auditing for admin activities
- Monitor service principal creation/modification
- Track Azure AD PowerShell module usage

## 5. Incident Response

### Initial Detection
1. Identify source account and IP
2. Review authentication logs
3. Check for associated alerts

### Investigation
1. Map discovered services and resources
2. Review timeline of discovery activities
3. Identify potential data access

### Containment
1. Revoke suspicious access tokens
2. Enable stricter authentication policies
3. Review and adjust service permissions

## 6. References
- [MITRE T1526](https://attack.mitre.org/techniques/T1526/)
- [Microsoft Graph Security API](https://docs.microsoft.com/graph/security-concept-overview)
- [Azure AD Audit Activities](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities)

Let me know if you would like me to expand on any section with more specific details or examples.

---

# Threat Model: Cloud Service Dashboard (T1538) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries using the Microsoft 365 Admin Center, Azure Portal, and other administrative UIs to gather information about the environment after obtaining privileged credentials. The graphical interfaces often provide more comprehensive visibility than API queries alone.

## 2. Attack Vectors

### 2.1 Admin Center Reconnaissance
**Description**: Adversaries use compromised Global Admin or other privileged accounts to enumerate users, groups, and service configurations through the M365 Admin Center.

**Detectable Actions**:
```json
{
  "Operation": "UserLoggedIn",
  "UserId": "admin@company.com",
  "ClientIP": "45.76.192.50",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "Resource": "Microsoft 365 Admin Portal",
  "ResultStatus": "Success"
}
```

```json
{
  "Operation": "ViewedExplore", 
  "UserId": "admin@company.com",
  "ClientIP": "45.76.192.50",
  "ItemType": "UsersReport",
  "Workload": "AzureAD",
  "TimeStamp": "2024-01-20T15:22:31"
}
```

### 2.2 Security & Compliance Center Access
**Description**: Attackers access security configurations and compliance policies to understand defensive measures.

**Detectable Actions**:
```json
{
  "Operation": "SearchViewed",
  "UserId": "admin@company.com", 
  "ObjectId": "ComplianceSearch_123",
  "ClientIP": "45.76.192.50",
  "TimeStamp": "2024-01-20T15:25:12"
}
```

### 2.3 Exchange Admin Center Enumeration 
**Description**: Adversaries enumerate mailbox configurations and email routing rules.

**Detectable Actions**:
```json
{
  "Operation": "Set-MailboxPermission",
  "UserId": "admin@company.com",
  "ObjectId": "target@company.com",
  "ClientIP": "45.76.192.50",
  "Parameters": "AccessRights: FullAccess",
  "TimeStamp": "2024-01-20T15:30:45" 
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
- Track frequency of admin portal access per account
- Monitor access patterns across multiple admin centers
- Alert on unusual admin activities from new IP addresses

```sql
SELECT UserId, ClientIP, COUNT(*) as AccessCount
FROM AdminPortalAccess 
WHERE TimeStamp > DATEADD(hour, -1, GETUTCDATE())
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 50
```

### 3.2 Baseline Deviations
- Establish normal patterns for:
  - Times of admin access
  - Types of resources viewed
  - Volume of configuration changes
- Alert on significant deviations

### 3.3 Correlation Rules
```sql
-- Detect rapid admin center traversal
SELECT UserId, ClientIP, COUNT(DISTINCT Resource) as PortalCount
FROM AdminPortalAccess
WHERE TimeStamp > DATEADD(minute, -15, GETUTCDATE())
GROUP BY UserId, ClientIP
HAVING COUNT(DISTINCT Resource) > 3
```

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement Privileged Identity Management (PIM)
- Require MFA for all admin actions
- Use conditional access policies
- Regular access reviews

### 4.2 Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "name": "Admin Portal Protection",
    "conditions": {
      "applications": ["M365 Admin Centers"],
      "users": ["Global Administrators", "Exchange Administrators"],
      "locations": {
        "untrustedLocations": true
      }
    },
    "controls": {
      "requireMFA": true,
      "sessionControls": {
        "signInFrequency": 4,
        "persistentBrowser": "never"
      }
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable Unified Audit Logging
- Configure alert policies for admin activities
- Deploy Cloud App Security policies

## 5. Incident Response

### 5.1 Initial Detection
1. Review admin activity logs for suspicious patterns
2. Check for abnormal portal access times/locations
3. Identify configuration changes made

### 5.2 Investigation
1. Document accessed resources and portals
2. Review authentication logs for the account
3. Check for new service principals or permissions
4. Analyze extracted data/reports

### 5.3 Containment
1. Revoke affected admin sessions
2. Reset compromised credentials
3. Enable JIT access for admins
4. Review and rollback suspicious changes

## 6. References

- [MITRE Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Microsoft Cloud App Security Alerts](https://docs.microsoft.com/en-us/cloud-app-security/monitor-alerts)

---

# Threat Model: Additional Email Delegate Permissions (T1098.002) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries granting additional permissions to mailboxes to maintain persistent access. In Microsoft 365, this commonly involves:
- Adding full mailbox permissions using Add-MailboxPermission
- Modifying folder-level permissions in Outlook
- Granting application-level delegated permissions 

## 2. Attack Vectors

### 2.1 Direct Mailbox Permission Assignment

**Description:**
Adversary uses PowerShell or Microsoft 365 admin center to grant full access permissions to a compromised mailbox.

**Attack Scenario:**
1. Attacker compromises admin credentials
2. Grants full access permissions to target mailbox
3. Uses delegated access for persistent access and data exfiltration

**Detection Fields:**
```json
{
  "Operation": "Add-MailboxPermission",
  "ResultStatus": "Success", 
  "UserId": "<admin_user>",
  "ObjectId": "<target_mailbox>",
  "Parameters": {
    "AccessRights": ["FullAccess"],
    "User": "<delegate_user>",
    "InheritanceType": "All"
  }
}
```

### 2.2 Folder Level Permission Modification 

**Description:**
Attacker modifies individual folder permissions to maintain access while appearing less suspicious.

**Attack Scenario:**
1. Compromises user account
2. Modifies permissions on key folders (inbox, sent items)
3. Uses folder access to monitor communications

**Detection Fields:**
```json
{
  "Operation": "AddFolderPermissions",
  "FolderId": "/inbox",
  "TargetUserOrGroup": "<delegate>",
  "AccessRights": ["ReadItems", "CreateItems"],
  "ModifiedProperties": [
    {
      "Name": "AccessRights",
      "OldValue": "None",
      "NewValue": "Editor"
    }
  ]
}
```

### 2.3 OAuth Application Permission Grants

**Description:**
Adversary registers malicious OAuth application and grants it delegated mailbox permissions.

**Attack Scenario:**
1. Creates malicious OAuth app
2. Grants application Mail.Read permissions
3. Uses refresh tokens for persistent access

**Detection Fields:**
```json
{
  "Operation": "Add delegation entry.",
  "ObjectId": "<app_id>",
  "ModifiedProperties": [
    {
      "Name": "PermissionType", 
      "NewValue": "Delegated"
    },
    {
      "Name": "Scope",
      "NewValue": "Mail.Read"
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect unusual permission grant patterns
SELECT UserId, Operation, COUNT(*) as count
FROM AuditLog 
WHERE Operation IN ('Add-MailboxPermission', 'AddFolderPermissions')
  AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING count > 10;

-- Alert on non-business hours permission changes
SELECT *
FROM AuditLog
WHERE Operation = 'Add-MailboxPermission'
  AND TimeGenerated.hour NOT BETWEEN 9 AND 17;
```

### 3.2 Baseline Deviations

- Monitor historical patterns of permission changes per admin
- Alert on >2 standard deviations from baseline
- Track permission changes outside normal business hours
- Monitor volume of delegated access operations

### 3.3 Priority Alert Conditions

- Multiple mailbox permission changes in short timeframe
- Permission grants to previously unseen accounts
- Permission changes followed by inbox rule creation
- Suspicious combinations like folder permissions + mail forwarding

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement privileged access management for Exchange admin roles
- Require MFA for all permission changes
- Log and review all mailbox delegation changes
- Regular permission attestation reviews

### 4.2 Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "mailboxDelegation": {
      "requireMFA": true,
      "allowedLocations": ["Corporate Network"],
      "allowedPlatforms": ["Windows", "MacOS"],
      "blockLegacyAuthentication": true
    }
  },
  "auditingPolicies": {
    "mailboxAuditing": {
      "enabled": true,
      "auditAdmin": true,
      "auditDelegate": true,
      "retentionDays": 180
    }
  }
}
```

### 4.3 Monitoring Controls
- Real-time alerts on suspicious permission changes
- Weekly review of mailbox delegation reports
- Monitor for correlation with other suspicious activities
- Track delegated access usage patterns

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected mailboxes
2. Review audit logs for permission change history
3. Document timeline of changes

### Investigation
1. Review all permission changes by suspected admin accounts
2. Check for correlated inbox rules or mail forwarding
3. Analyze authentication logs for delegated access
4. Review OAuth application permissions

### Containment
1. Remove unauthorized permissions
2. Block suspicious admin accounts
3. Revoke active sessions
4. Reset compromised credentials
5. Review and revoke suspicious OAuth grants

## 6. References

- [MITRE ATT&CK T1098.002](https://attack.mitre.org/techniques/T1098/002/)
- [Microsoft - Add-MailboxPermission](https://docs.microsoft.com/en-us/powershell/module/exchange/add-mailboxpermission)
- [Microsoft - Mailbox Audit Logging](https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing)
- [Microsoft - Investigating Delegated Access](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/investigating-delegated-access)

---

# Threat Model: Serverless Execution (T1648) in Microsoft 365 & Entra ID

## Overview
Adversaries can abuse Microsoft 365 serverless capabilities like Power Automate flows, Azure Functions, and Logic Apps to execute malicious code and maintain persistence. Common objectives include data exfiltration, privilege escalation, and backdoor deployment.

## Attack Vectors

### 1. Malicious Power Automate Flows
**Description**: Adversaries create flows that run with delegated permissions to exfiltrate data or maintain persistence.

**Attack Scenario**:
- Attacker compromises user account
- Creates Power Automate flow to forward emails to external address
- Flow runs with user's permissions to access email and SharePoint

**Detection Fields**:
```json
{
  "CreationTime": "2024-01-20T15:30:22",
  "Operation": "Add delegation entry.",
  "UserType": "Regular",
  "UserKey": "user@victim.com",
  "ApplicationId": "d8566de2-3a01-4f9c-a1d5-24864f622f74", // Power Automate 
  "DelegationType": "OAuth2PermissionGrant",
  "TargetResources": [
    {
      "Type": "ServicePrincipal",
      "Scopes": ["Mail.Read", "Mail.Send"]
    }
  ]
}
```

### 2. Azure Function App Backdoors
**Description**: Adversaries deploy malicious code to Azure Functions that execute on schedule or in response to events.

**Attack Scenario**:
- Attacker compromises admin account
- Creates Azure Function with system-assigned managed identity
- Function executes malicious code with elevated permissions

**Detection Fields**:
```json
{
  "CreationTime": "2024-01-21T09:15:33", 
  "Operation": "Add service principal.",
  "ObjectId": "8a7bc598-6a1d-4376-9fdf-45a062a19c14",
  "ResourceType": "Function App",
  "AssignedIdentities": [
    {
      "PrincipalId": "82f1acb0-6c95-4e56-8b11-45eb89269a58",
      "TenantId": "72f988bf-86f1-41af-91ab-2d7cd011db47"
    }
  ]
}
```

### 3. Logic App Data Exfiltration
**Description**: Adversaries create Logic Apps that automatically extract and exfiltrate sensitive data.

**Attack Scenario**:
- Attacker gains access to cloud admin account
- Deploys Logic App that scans SharePoint for sensitive files
- Automatically uploads discovered files to external storage

**Detection Fields**:
```json
{
  "CreationTime": "2024-01-22T14:22:11",
  "Operation": "Add service principal credentials.",
  "ObjectId": "9c47b02f-12a1-4c59-8c29-b1d365822a13",
  "ResourceType": "Logic App",
  "Permissions": [
    "Sites.Read.All",
    "Files.Read.All"
  ],
  "CredentialType": "Password"
}
```

## Detection Strategies

### Behavioral Analytics
```sql
-- Detect unusual Power Automate flow creation patterns
SELECT UserPrincipalName, COUNT(*) as FlowCount
FROM AuditLogs 
WHERE Operation = "Add delegation entry."
AND ApplicationId = "d8566de2-3a01-4f9c-a1d5-24864f622f74"
GROUP BY UserPrincipalName, bin(TimeGenerated, 1h)
HAVING FlowCount > 5 -- Threshold for suspicious activity

-- Monitor for sensitive permission grants to serverless resources
SELECT Operation, ObjectId, TargetResources
FROM AuditLogs
WHERE Operation IN ("Add service principal.", "Add service principal credentials.")
AND TargetResources.Type IN ("Function App", "Logic App")
AND TargetResources.Scopes CONTAINS_ANY ("Mail.Read", "Sites.Read.All", "Files.Read.All")
```

### Baseline Monitoring
- Track normal patterns of serverless resource creation per user/department
- Monitor typical permission scopes requested by legitimate applications
- Establish baseline for frequency of delegation grants

## Mitigation Controls

### Administrative Controls
- Implement strict RBAC for serverless resource creation
- Regular review of Power Automate flows and delegated permissions
- Enforce approval workflows for new service principal creation

### Technical Controls (JSON)
```json
{
  "conditionalAccessPolicies": {
    "serverlessResourceAccess": {
      "includedServices": ["Power Automate", "Logic Apps", "Azure Functions"],
      "controls": {
        "requireMFA": true,
        "allowedLocations": ["Corporate Network"],
        "allowedPlatforms": ["Desktop"]
      }
    }
  },
  "delegationRestrictions": {
    "allowedScopes": [
      "Sites.Read.User",
      "Mail.Read.User"
    ],
    "blockedScopes": [
      "Mail.Send.All",
      "Sites.FullControl.All"
    ]
  }
}
```

### Monitoring Controls
- Enable detailed audit logging for all serverless resource operations
- Configure alerts for high-risk permission grants
- Monitor service principal credential additions/changes
- Track data egress from serverless resources

## Incident Response

### Initial Detection
1. Review audit logs for suspicious serverless resource creation
2. Identify affected user accounts and permissions granted
3. Document scope and timing of suspicious activities

### Investigation
1. Map relationships between service principals and resources
2. Review flow/function execution logs for malicious activity
3. Analyze data access patterns and egress points
4. Identify persistence mechanisms

### Containment
1. Disable suspicious flows/functions
2. Revoke compromised service principal credentials
3. Remove malicious delegated permissions
4. Block external data egress points

## References
- MITRE ATT&CK: T1648 Serverless Execution
- Microsoft: Power Automate Security Best Practices
- Azure Functions Security Documentation
- Microsoft Cloud App Security Alerts Reference

---

# Threat Model: Office Test (T1137.002) in Microsoft 365 & Entra ID

## 1. Overview
The Office Test technique involves abusing registry keys to establish persistence by loading malicious DLLs when Office applications start. In M365/Entra ID context, this typically manifests through:
- Abuse of Office add-in functionality 
- Installation of malicious Office templates
- Modification of Office startup behavior through cloud policy

## 2. Attack Vectors

### 2.1 Office Add-in Abuse
**Description:** Adversaries deploy malicious Office add-ins through M365 admin center or PowerShell.

**Detection Fields:**
```json
{
  "Operation": "Add service principal",
  "ObjectId": "[Add-in Application ID]",
  "Target": "[Office Application]",
  "ActorIpAddress": "[IP Address]",
  "ClientAppId": "Office Add-in Management" 
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "62442d-e1f7-40e4-b111-2f123c9",
  "Operation": "Add service principal",
  "OrganizationId": "1a2b3c4d-e5f6-7890",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "admin@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "c1d2e3f4-5a6b-7c8d",
  "UserId": "admin@company.com",
  "ClientAppId": "Office Add-in Management",
  "Target": ["Excel"],
  "ActorIpAddress": "192.168.1.100"
}
```

### 2.2 Template Modification
**Description:** Attackers modify Office templates to include malicious code.

**Detection Fields:**
```json
{
  "Operation": "FileModified",
  "SourceFileName": "*.dotm",
  "SourceFileExtension": "dotm",
  "ObjectId": "[Template ID]"
}
```

### 2.3 Policy-Based Persistence 
**Description:** Abusing administrative policies to force load malicious components.

**Detection Fields:**
```json
{
  "Operation": "Update group",
  "ObjectId": "[Policy Group ID]",
  "ModifiedProperties": ["Office Settings"]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
SELECT Operation, ActorIpAddress, Target 
FROM AuditLogs
WHERE Operation IN ('Add service principal', 'FileModified')
AND Target LIKE '%Office%'
GROUP BY ActorIpAddress
HAVING COUNT(*) > 5 IN 1 HOUR
```

### 3.2 Baseline Deviations
- Monitor frequency of Office add-in installations
- Track template modifications outside business hours
- Alert on policy changes affecting Office applications

## 4. Controls

### Administrative Controls
- Enforce add-in allowlisting
- Restrict template modification permissions
- Implement change management for Office policies

### Technical Controls
```json
{
  "officeSecurity": {
    "allowedAddInTypes": ["Verified"],
    "templateModification": "Blocked",
    "adminApprovalRequired": true
  }
}
```

### Monitoring Controls
- Enable detailed Office 365 audit logging
- Monitor add-in installation events
- Track template modifications

## 5. Incident Response

### Initial Detection
1. Review audit logs for suspicious add-in installations
2. Check template modification history
3. Analyze policy changes affecting Office applications

### Investigation Steps
1. Identify affected users/devices
2. Examine add-in source and publisher
3. Review template changes
4. Track policy modification chain

### Containment
1. Remove suspicious add-ins
2. Restore original templates
3. Revert policy changes
4. Block compromised accounts

## 6. References
- MITRE ATT&CK: T1137.002
- Microsoft Office Add-in Security
- Microsoft 365 Defender Documentation

---

# Threat Model: Application Access Token (T1550.001) in Microsoft 365 & Entra ID

## 1. Overview

Application access tokens in Microsoft 365 and Entra ID are primarily used through:
- OAuth 2.0 access tokens for application permissions
- Service principal credentials
- Managed identities tokens
- Exchange/SharePoint access tokens

## 2. Attack Vectors

### 2.1 OAuth Token Theft via Consent Phishing

**Description:**
Adversaries trick users into granting OAuth permissions to malicious applications, then steal and abuse the access tokens.

**Detection Fields:**
```json
{
  "Operation": "Add delegation entry.",
  "ResultStatus": "Success",
  "ClientIP": "<ip_address>",
  "ObjectId": "<app_id>",
  "UserId": "<user_upn>",
  "ApplicationId": "<app_id>",
  "Permissions": ["Mail.Read", "Files.ReadWrite.All"]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "8382d091-7324-4418-b51e-88ba931d098a", 
  "Operation": "Add delegation entry.",
  "OrganizationId": "b722d283-0c31-4b16-9297-c0147d621acb",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "user@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "d1c24f2c-7323-4918-b412-eb03b1019800",
  "UserId": "user@contoso.com",
  "ApplicationId": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6",
  "ClientIP": "192.168.1.100",
  "Permissions": ["Mail.Read", "Files.ReadWrite.All"]
}
```

### 2.2 Service Principal Credential Abuse 

**Description:**
Adversaries add unauthorized credentials to existing service principals to maintain persistence.

**Detection Fields:**
```json
{
  "Operation": "Add service principal credentials.",
  "ResultStatus": "Success", 
  "ClientIP": "<ip_address>",
  "ObjectId": "<service_principal_id>",
  "KeyDescription": "<key_description>",
  "KeyType": "Password"
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T15:42:11",
  "Id": "44c2d091-9a24-5518-c51e-77ca931d432b",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "b722d283-0c31-4b16-9297-c0147d621acb",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "UserType": 1,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "f4a12c8d-9b23-4a12-8c7d-123456789012",
  "KeyDescription": "Backup Access Key",
  "KeyType": "Password",
  "ClientIP": "192.168.1.100"
}
```

### 2.3 Managed Identity Token Theft

**Description:**
Adversaries compromise VMs/services with managed identities to steal and abuse their tokens.

**Detection Fields:**
```json
{
  "Operation": "ManagedIdentityTokenAcquired",
  "ResultStatus": "Success",
  "ResourceId": "<resource_id>",
  "ClientIP": "<ip_address>",
  "ManagedIdentityObjectId": "<managed_identity_id>",
  "RequestedScopes": ["https://storage.azure.com/"]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect unusual token request patterns
SELECT ClientIP, Operation, COUNT(*) as request_count
FROM AuditLogs
WHERE Operation IN ('Add delegation entry.', 'Add service principal credentials.')
  AND TimeGenerated > ago(1h)
GROUP BY ClientIP, Operation
HAVING COUNT(*) > 10;

-- Detect tokens requested from new locations
SELECT ClientIP, COUNT(*) as location_count
FROM AuditLogs
WHERE Operation = 'Add delegation entry.'
  AND TimeGenerated > ago(24h)
  AND ClientIP NOT IN (
    SELECT DISTINCT ClientIP 
    FROM AuditLogs 
    WHERE TimeGenerated BETWEEN ago(30d) AND ago(24h)
  );
```

### 3.2 Baseline Deviation Monitoring

Monitor for deviations from:
- Normal token request volumes per app/user
- Expected delegation permission scopes
- Typical service principal credential lifetimes
- Standard managed identity usage patterns

### 3.3 Real-time Alert Rules

```json
{
  "name": "Suspicious Token Activity",
  "description": "Detects potential token abuse patterns",
  "severity": "High",
  "threshold": {
    "operator": "gt",
    "value": 5,
    "timeWindow": "5m",
    "aggregation": {
      "clientIP": true,
      "operation": true
    }
  },
  "conditions": [
    {
      "operation": ["Add delegation entry.", "Add service principal credentials."],
      "resultStatus": "Success"
    }
  ]
}
```

## 4. Mitigation Strategies

### Administrative Controls
1. Implement application consent policies:
   - Restrict user consent to low-risk permissions only
   - Require admin approval for high-risk permissions
2. Configure service principal policies:
   - Enforce credential expiration
   - Require approval for new credentials
3. Implement managed identity controls:
   - Use system-assigned over user-assigned when possible
   - Restrict role assignments to minimum required

### Technical Controls
```json
{

  "conditionalAccessPolicies": {
    "tokenLifetimes": {
      "accessToken": "1h",
      "refreshToken": "24h"
    },
    "allowedLocations": ["corporate-networks"],
    "prohibitedApps": ["unverified-publishers"]
  },
  "servicePrincipalSettings": {
    "maxCredentialLifetime": "90d",
    "requireApproval": true,
    "auditCredentialChanges": true
  }
}
```

### Monitoring Controls
1. Enable audit logging for:
   - All OAuth consent grants
   - Service principal credential management
   - Managed identity operations
2. Configure alerts for:
   - Mass token requests
   - Off-hours token activity
   - Anomalous permission grants

## 5. Response Playbook

### Initial Detection
1. Identify affected tokens/applications
2. Determine scope of compromise
3. Collect relevant audit logs

### Investigation
1. Review token usage patterns
2. Analyze permission grants
3. Track lateral movement attempts

### Containment
1. Revoke compromised tokens
2. Remove unauthorized credentials
3. Reset affected service principals
4. Update conditional access policies

## 6. References

- [MITRE ATT&CK T1550.001](https://attack.mitre.org/techniques/T1550/001/)
- [Microsoft OAuth 2.0 Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [Microsoft Service Principal Security](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
- [Microsoft Managed Identities](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)

---

# Threat Model: Cloud Accounts (T1078.004) in Microsoft 365 & Entra ID

## 1. Overview
Cloud Accounts in Microsoft 365 and Entra ID represent a critical attack surface where adversaries can gain unauthorized access, maintain persistence, and escalate privileges. Key risks include:
- Compromised user and service accounts
- Federated/hybrid identity abuse 
- Service principal and application credential theft
- Role and permission elevation

## 2. Attack Vectors

### 2.1 Service Principal Credential Abuse
**Description**: Adversaries add unauthorized credentials to existing service principals to maintain persistent access.

**Attack Scenario**:
1. Attacker compromises Global Admin account
2. Creates new client secret for existing service principal
3. Uses credential to authenticate as application

**Detection Fields**:
```json
{
  "Operation": "Add service principal credentials",
  "Actor": "[UPN]",
  "Target": "[ServicePrincipalName]",
  "CredentialType": "Password",
  "ValidityPeriod": "2 years"
}
```

### 2.2 Privileged Role Assignment
**Description**: Attackers add accounts to highly privileged roles to maintain access and elevate privileges.

**Detection Fields**:
```json
{
  "Operation": "Add member to role",
  "Actor": "[UPN]", 
  "Target": "[UserAdded]",
  "RoleName": "Global Administrator",
  "RoleTemplateId": "62e90394-69f5-4237-9190-012177145e10"
}
```

### 2.3 Federation Trust Modification 
**Description**: Adversaries modify federation settings to enable persistent access via external identities.

**Detection Fields**:
```json
{
  "Operation": "Set federation settings on domain",
  "Actor": "[UPN]",
  "Domain": "contoso.com",
  "NewSettings": {
    "IssuerUri": "[URI]",
    "PassiveLogOnUri": "[URI]",
    "SigningCertificate": "[Cert Thumbprint]"
  }
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect new service principal credential additions
SELECT Actor, Count(*) as CredsAdded
FROM AuditLogs 
WHERE Operation = "Add service principal credentials"
AND TimeGenerated > ago(1h)
GROUP BY Actor
HAVING Count(*) > 5;

-- Alert on privileged role additions outside business hours
SELECT *
FROM AuditLogs
WHERE Operation = "Add member to role" 
AND RoleName in ("Global Administrator", "Privileged Role Administrator")
AND TimeGenerated.hour not between 9 and 17;
```

### 3.2 Baseline Deviations
- Monitor for anomalous service principal credential additions vs historical baseline
- Track privileged role membership changes compared to normal change frequency
- Alert on federation configuration changes outside change windows

### 3.3 Correlation Rules
```sql
-- Correlate role changes with other suspicious activity
SELECT a.*, b.Operation as RelatedOperation
FROM AuditLogs a
JOIN AuditLogs b 
  ON a.Actor = b.Actor
  AND a.TimeGenerated between b.TimeGenerated and dateadd(minute,60,b.TimeGenerated)
WHERE a.Operation = "Add member to role"
AND b.Operation in (
  "Add service principal credentials",
  "Set federation settings on domain"
);
```

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement Privileged Identity Management (PIM) for just-in-time access
- Require MFA for all privileged role assignments
- Regular access reviews for privileged roles and service principals

### 4.2 Technical Controls
```json
{
  "ConditionalAccessPolicies": {
    "PrivilegedRoles": {
      "RequireMFA": true,
      "BlockLegacyAuth": true,
      "AllowedLocations": ["Corporate Network"]
    },
    "ServicePrincipals": {
      "RequireCertificates": true,
      "MaxCredentialLifetime": "90.00:00:00"
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable Unified Audit Logging
- Monitor service principal secret/certificate additions
- Alert on federation trust modifications
- Track privileged role membership changes

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Confirm alert details and impacted resources
2. Identify source account and access vector
3. Review related audit logs for lateral movement

### 5.2 Investigation
1. Review all role assignments made by compromised account
2. Check for new service principal credentials
3. Audit federation configuration changes
4. Analyze authentication patterns

### 5.3 Containment
1. Revoke suspicious service principal credentials
2. Remove unauthorized role assignments
3. Reset compromised account credentials
4. Block suspicious authentication sources

## 6. References
- [MITRE T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- [Microsoft Identity Security Monitoring](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection)
- [Securing Privileged Access](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-deployment-plan)

Let me know if you would like me to expand on any section or provide additional details.

---

# Threat Model: Modify Authentication Process (T1556) in Microsoft 365 & Entra ID

## Overview
In Microsoft 365 and Entra ID environments, adversaries may modify authentication processes to bypass security controls and maintain persistent access. This includes modifying federation settings, adding malicious credentials to service principals, and manipulating authentication policies.

## Attack Vectors

### 1. Service Principal Credential Manipulation
**Description**: Adversaries add credentials to existing service principals to maintain access and bypass MFA.

**Attack Scenario**:
- Attacker compromises Global Admin account
- Adds new credentials to high-privilege service principal
- Uses credentials to authenticate as service principal and bypass MFA

**Detection Fields**:
```json
{
  "Operation": "Add service principal credentials.",
  "ObjectId": "[ServicePrincipalId]",
  "Actor": "[ActorUPN]",
  "CreatedTime": "[Timestamp]",
  "CredentialType": "Password/Certificate",
  "ValidityPeriod": "[Duration]"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:33Z",
  "Id": "4a22c897-1234-5678-90ab-cdef12345678",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "john.doe@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "12345678-90ab-cdef-1234-567890abcdef",
  "CredentialType": "Password",
  "ValidityPeriod": "P1Y"
}
```

### 2. Federation Trust Modification
**Description**: Adversaries modify federation settings to enable authentication bypass through malicious identity providers.

**Detection Fields**:
```json
{
  "Operation": "Set federation settings on domain.",
  "ObjectId": "[DomainName]", 
  "ModifiedProperties": [
    {
      "Name": "IssuerUri",
      "OldValue": "[OldValue]",
      "NewValue": "[NewValue]"
    }
  ]
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T14:55:12Z", 
  "Id": "891234ab-cdef-5678-90ab-cdef12345678",
  "Operation": "Set federation settings on domain.",
  "OrganizationId": "contoso.onmicrosoft.com",
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "ObjectId": "contoso.com",
  "ModifiedProperties": [
    {
      "Name": "IssuerUri",
      "OldValue": "http://sts.contoso.com/adfs/services/trust",
      "NewValue": "http://malicious-sts.evil.com/adfs/services/trust"
    }
  ]
}
```

### 3. Authentication Policy Modification
**Description**: Adversaries modify conditional access or MFA policies to weaken authentication requirements.

**Detection Fields**:
```json
{
  "Operation": "Update policy.", 
  "PolicyType": "ConditionalAccess",
  "PolicyId": "[PolicyId]",
  "ModifiedProperties": [
    {
      "Name": "GrantControls",
      "OldValue": "[OldValue]",
      "NewValue": "[NewValue]"  
    }
  ]
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect service principal credential additions outside business hours
SELECT UserKey, ObjectId, COUNT(*) as count
FROM AuditLogs 
WHERE Operation = "Add service principal credentials."
AND TimeGenerated NOT BETWEEN '0800' AND '1800'
GROUP BY UserKey, ObjectId
HAVING count > 2;

-- Detect federation trust changes followed by new auth attempts
SELECT a.UserKey, a.ObjectId, b.UserKey as AuthUser
FROM AuditLogs a
JOIN SignInLogs b ON a.ObjectId = b.ResourceTenantId
WHERE a.Operation = "Set federation settings on domain."
AND b.TimeGenerated BETWEEN a.TimeGenerated AND DATEADD(hour, 1, a.TimeGenerated);
```

### Baseline Deviation Monitoring
- Track normal patterns of service principal credential management
- Monitor federation configuration changes per domain
- Establish baseline for authentication policy modifications by admin

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "requireMFA": true,
    "blockLegacyAuth": true,
    "requireCompliantDevice": true,
    "trustedLocations": ["corporate networks"]
  },
  "servicePrincipalSettings": {
    "restrictCredentialAddition": true,
    "requireApproval": true,
    "maximumCredentialLifetime": "90.00:00:00"
  }
}
```

## Incident Response Playbook

### Initial Detection
1. Review audit logs for:
   - Service principal credential changes
   - Federation trust modifications 
   - Authentication policy updates

### Investigation
1. For service principal changes:
   - Document affected principals
   - Review credential properties and validity period
   - Check for associated authentication attempts

2. For federation changes:
   - Validate legitimacy of new federation settings
   - Review authentication patterns post-change
   - Check for additional domain modifications

### Containment
1. Service Principal Compromise:
   - Remove suspicious credentials
   - Reset existing credentials
   - Review and revoke sessions

2. Federation Trust Compromise:
   - Restore original federation settings
   - Block malicious federation endpoints
   - Force credential rotation

## References
- [MITRE T1556](https://attack.mitre.org/techniques/T1556/)
- [Microsoft - Securing Service Principals](https://docs.microsoft.com/azure/active-directory/develop/security-best-practices-for-app-registration)
- [Microsoft - Federation Security](https://docs.microsoft.com/azure/active-directory/hybrid/how-to-connect-fed-security-best-practices)

---

# Threat Model: Messaging Applications (T1213.005) in Microsoft 365 & Entra ID

## 1. Overview

Adversaries can harvest sensitive data from Microsoft Teams chats, channels, and messages to gather intelligence about an organization's environment, obtain credentials, and gather information about incident response activities. This threat model focuses on detection and prevention in Microsoft Teams.

## 2. Attack Vectors

### 2.1 Mass Message Collection
**Description**: Adversaries use compromised accounts to bulk export or access large volumes of Teams messages across multiple channels/chats.

**Scenario**: An attacker compromises an admin account and uses Teams PowerShell to export complete chat histories.

**Relevant Audit Operations**:
- MessagesExported
- MessagesListed 
- MessageRead
- ChatRetrieved

**Example Audit Log**:
```json
{
  "CreationTime": "2024-02-01T10:15:22",
  "Id": "4a7c8f32-91d5-4e2f-b518-54de8b9e4b88",
  "Operation": "MessagesExported",
  "OrganizationId": "4fd5vb35-1f45-4e2f-b518-54de8b9e4b88",
  "RecordType": 25,
  "UserKey": "admin@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "MicrosoftTeams",
  "ObjectId": "All_Company_Chat_History_Export",
  "UserId": "admin@company.com",
  "ClientIP": "192.168.1.100",
  "Scope": "AllChats"
}
```

### 2.2 Targeted Chat Access
**Description**: Adversaries access specific chats/channels where sensitive information is likely to be discussed.

**Scenario**: Attacker targets IT team channels to gather credentials and infrastructure details.

**Relevant Audit Operations**:
- MessageRead
- ChatRetrieved
- MessageHostedContentRead

**Example Audit Log**:
```json
{
  "CreationTime": "2024-02-01T15:22:33",
  "Id": "82b4c911-4e2f-b518-54de8b9e4b88",
  "Operation": "MessageRead",
  "OrganizationId": "4fd5vb35-1f45-4e2f-b518-54de8b9e4b88", 
  "RecordType": 25,
  "UserKey": "attacker@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "MicrosoftTeams",
  "ObjectId": "IT-Team-General",
  "UserId": "attacker@company.com",
  "ClientIP": "192.168.1.105",
  "ChannelName": "IT Team - General",
  "TeamName": "IT Team"
}
```

### 2.3 Message Search Operations
**Description**: Adversaries perform targeted keyword searches across Teams content to locate sensitive data.

**Scenario**: Attacker searches for terms like "password", "credentials", "key" across all accessible channels.

**Relevant Audit Operations**:
- SearchQueryPerformed 
- MessageHostedContentsListed

**Example Audit Log**:
```json
{
  "CreationTime": "2024-02-01T16:44:12",
  "Id": "7d4e9f22-4e2f-b518-54de8b9e4b88",
  "Operation": "SearchQueryPerformed",
  "OrganizationId": "4fd5vb35-1f45-4e2f-b518-54de8b9e4b88",
  "RecordType": 25,
  "UserKey": "attacker@company.com", 
  "UserType": 0,
  "Version": 1,
  "Workload": "MicrosoftTeams",
  "ObjectId": "TeamsSearch",
  "UserId": "attacker@company.com",
  "ClientIP": "192.168.1.105",
  "SearchQuery": "password credential key secret",
  "ResultCount": 157
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Detect mass message access
SELECT UserId, COUNT(*) as access_count
FROM TeamsAuditLogs 
WHERE Operation IN ('MessageRead','ChatRetrieved')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 100 -- Threshold for suspicious volume

-- Detect keyword searching pattern
SELECT UserId, SearchQuery
FROM TeamsAuditLogs
WHERE Operation = 'SearchQueryPerformed'
AND SearchQuery CONTAINS_ANY('password','credential','secret','key')
```

### 3.2 Baseline Deviations
- Monitor for users accessing >50% more messages than their 30-day average
- Alert on first-time access to sensitive channels
- Track abnormal search patterns compared to role-based baselines

### 3.3 Correlation Rules
```sql
-- Correlate suspicious activities
SELECT UserId, COUNT(DISTINCT Operation) as suspicious_ops
FROM TeamsAuditLogs
WHERE Operation IN (
  'MessagesExported',
  'SearchQueryPerformed',
  'MessageHostedContentsListed'
)
AND TimeGenerated > ago(24h)
GROUP BY UserId
HAVING COUNT(DISTINCT Operation) >= 2
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement information barriers between departments
- Configure DLP policies for sensitive data types
- Enable message retention policies
- Restrict Teams export capabilities

### Technical Controls
```json
{
  "teamsPolicy": {
    "messageExport": "disabled",
    "bulkSearching": "restricted",
    "informationBarriers": "enabled",
    "dlpRules": [
      {
        "type": "Credit Card",
        "action": "Block"
      },
      {
        "type": "Password",
        "action": "Block" 
      }
    ]
  }
}
```

### Monitoring Controls
- Enable Teams advanced audit logging
- Monitor sensitive channel access
- Track export and search operations
- Alert on suspicious patterns

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected accounts and channels
2. Review audit logs for scope of access
3. Document exposed sensitive data

### Investigation
1. Review historical access patterns
2. Identify any data exfiltration
3. Determine attack vector and timeline
4. Assess impact and exposure

### Containment
1. Suspend compromised accounts
2. Revoke active sessions
3. Reset affected credentials
4. Block suspicious IPs
5. Implement additional controls

## 6. References

- MITRE ATT&CK: https://attack.mitre.org/techniques/T1213/005/
- Microsoft Teams Security Guide: https://docs.microsoft.com/en-us/microsoftteams/security-compliance-overview
- Microsoft Teams Audit Log: https://docs.microsoft.com/en-us/microsoftteams/audit-log-events

---

