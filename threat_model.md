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
- [SharePoint Collection (T1213.002) in Microsoft 365 & Entra ID](#sharepoint-collection-t1213002-in-microsoft-365-&-entra-id)
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
Password guessing attacks in Microsoft 365 and Entra ID typically target authentication endpoints including:
- Azure AD authentication portal (login.microsoftonline.com)
- Exchange Online (outlook.office365.com)
- SharePoint Online 
- Microsoft Teams
- Legacy authentication protocols

## 2. Attack Vectors

### 2.1 Basic Authentication Password Guessing
**Description:** Attackers attempt to authenticate using legacy/basic authentication protocols that don't support MFA.

**Scenario:**
Attacker uses automated tools to attempt logins via IMAP/POP3/SMTP targeting multiple accounts with common passwords.

**Detection Fields:**
```json
{
  "Operation": "UserLoggedIn", 
  "ClientAppId": "Legacy Authentication Client",
  "ResultStatus": "Failed",
  "LogonError": "Invalid password",
  "UserAgent": "Microsoft Office/16.0 (Windows NT 10.0...)",
  "ClientIP": "<ip_address>",
  "UserId": "<target_email>"
}
```

### 2.2 Password Spray Attack 
**Description:** Attacker tries one password against many accounts to avoid lockouts.

**Scenario:**
Attacker attempts to authenticate with "Spring2024!" password across 500 accounts over 2 hours.

**Detection Fields:**
```json
{
  "Operation": "UserLoginFailed",
  "ErrorCode": 50126,
  "ClientIP": "<ip_address>", 
  "UserAgent": "Python-urllib/3.7",
  "ResultStatus": "Failed",
  "UserId": "<varying_users>",
  "FailureReason": "Invalid username or password"
}
```

### 2.3 Targeted Account Guessing
**Description:** Focused password guessing against specific high-value accounts.

**Scenario:** 
Attacker targets executive/admin accounts with customized password lists.

**Detection Fields:**
```json
{
  "Operation": "UserLoggedIn",
  "UserId": "ceo@company.com",
  "ClientIP": "<ip_address>",
  "ResultStatus": "Failed", 
  "LogonError": "Invalid password",
  "RiskLevel": "High",
  "RiskState": "confirmedCompromised",
  "RiskDetail": "anonymousIpAddress"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Password spray detection
SELECT ClientIP, COUNT(DISTINCT UserId) as targeted_users,
COUNT(*) as attempt_count
FROM SignInLogs 
WHERE TimeGenerated > ago(2h)
AND ResultStatus == "Failed" 
GROUP BY ClientIP
HAVING COUNT(DISTINCT UserId) > 50
AND COUNT(*)/COUNT(DISTINCT UserId) < 3;

-- Single account brute force
SELECT UserId, ClientIP, COUNT(*) as failures
FROM SignInLogs
WHERE TimeGenerated > ago(30m)
AND ResultStatus == "Failed"
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 20;
```

### 3.2 Baseline Deviations
- Monitor for authentication attempts >2 standard deviations from baseline
- Track failed/successful ratio per IP/user/hour
- Alert on new user agents/IPs attempting authentication
- Monitor geographic anomalies in authentication patterns

### 3.3 Technical Detection Rules
```json
{
  "rules": [{
    "name": "Password Spray Detection",
    "criteria": {
      "timeWindow": "2h",
      "minUniqueAccounts": 50,
      "maxAttemptsPerAccount": 3,
      "triggerThreshold": 100
    }
  },
  {
    "name": "Brute Force Detection", 
    "criteria": {
      "timeWindow": "30m",
      "failedAttempts": 20,
      "sameUserAgent": true,
      "sameIP": true
    }
  }]
}
```

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Disable legacy authentication protocols
- Implement conditional access policies
- Require MFA for all accounts
- Set smart lockout thresholds
- Block high-risk sign-ins

### 4.2 Technical Controls
```json
{
  "conditionalAccess": {
    "blockLegacyAuth": true,
    "requireMFA": true,
    "blockHighRiskSignIns": true,
    "allowedLocations": ["US", "CA"],
    "smartLockout": {
      "threshold": 10,
      "duration": "1h" 
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable unified audit logging
- Configure alert policies for suspicious sign-ins
- Monitor Identity Protection risk detections
- Enable sign-in risk policies
- Track authentication patterns

## 5. Incident Response

### 5.1 Initial Detection
1. Review unified audit logs for failed sign-in patterns
2. Check Identity Protection for risky sign-ins
3. Analyze authentication attempts by IP/user agent
4. Review conditional access policy reports

### 5.2 Investigation
1. Identify targeted accounts
2. Review authentication patterns
3. Check for successful compromises
4. Analyze attack source(s)
5. Review MFA/conditional access bypass attempts

### 5.3 Containment
1. Block attacking IPs
2. Enable stricter conditional access
3. Force password resets
4. Enable MFA
5. Disable compromised accounts

## 6. References
- [Microsoft - Password Spray Attack Detection](https://docs.microsoft.com/security/...)
- [MITRE - T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [Microsoft Identity Protection](https://docs.microsoft.com/azure/active-directory/identity-protection/...)
- [Azure AD Sign-in Logs Schema](https://docs.microsoft.com/azure/active-directory/reports-monitoring/...)

---

# Threat Model: SharePoint Collection (T1213.002) in Microsoft 365 & Entra ID

## 1. Overview
In Microsoft 365 environments, adversaries can abuse SharePoint Online to collect sensitive organizational data stored in document libraries, lists, and sites. SharePoint often contains high-value information like network diagrams, credentials, and technical documentation that can enable further attacks.

## 2. Attack Vectors

### 2.1 Mass Document Download
**Description**: Adversary downloads large volumes of documents from SharePoint sites using browser or sync client

**Audit Fields**:
- Operation: FileDownloaded, FileSyncDownloadedFull
- UserAgent: Browser/Sync client details
- UserId: Account performing download
- SiteUrl: SharePoint site location
- SourceFileName: Document name

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:10",
  "UserId": "john.smith@company.com",
  "Operation": "FileDownloaded",
  "SiteUrl": "/sites/TechnicalDocumentation",
  "SourceFileName": "NetworkDiagram.vsdx",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "ClientIP": "192.168.1.100",
  "CorrelationId": "bef12a89-66dd-4cfa-91f9-3b5c2b8f1d55"
}
```

### 2.2 Expanded Site Access
**Description**: Adversary modifies permissions or creates sharing links to access restricted sites

**Audit Fields**:
- Operation: SharingInvitationCreated, PermissionLevelAdded
- TargetUserOrGroupName: User granted access
- PermissionLevel: Level of access granted
- SiteUrl: Site affected

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22", 
  "UserId": "admin@company.com",
  "Operation": "PermissionLevelAdded",
  "TargetUserOrGroupName": "external@gmail.com",
  "PermissionLevel": "Full Control",
  "SiteUrl": "/sites/Projects",
  "ClientIP": "192.168.1.100"
}
```

### 2.3 Search Query Mining
**Description**: Adversary uses SharePoint search to locate sensitive content

**Audit Fields**:
- Operation: SearchQueryPerformed
- SearchQuery: Search terms used
- ClientIP: Source IP
- UserId: Account performing search

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T17:05:33",
  "UserId": "jane.doe@company.com", 
  "Operation": "SearchQueryPerformed",
  "SearchQuery": "password confidential credentials",
  "ClientIP": "192.168.1.100",
  "WorkLoad": "SharePoint",
  "ResultCount": "143"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Detect mass downloads
SELECT UserId, COUNT(*) as download_count
FROM AuditLogs
WHERE Operation IN ('FileDownloaded','FileSyncDownloadedFull')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 100 -- Threshold for suspicious downloads

-- Detect suspicious permission changes
SELECT TargetUserOrGroupName, COUNT(*) as permission_changes
FROM AuditLogs 
WHERE Operation IN ('PermissionLevelAdded','SharingInvitationCreated')
AND TimeGenerated > ago(24h)
GROUP BY TargetUserOrGroupName
HAVING COUNT(*) > 10 -- Threshold for suspicious permission activity
```

### 3.2 Baseline Deviation Monitoring
- Monitor daily download volumes per user, alert on >2 standard deviations
- Track search query patterns for sensitive terms
- Alert on permission changes outside business hours

## 4. Mitigation Strategies

### Administrative Controls
1. Implement data classification and retention policies
2. Configure sensitivity labels for sensitive content
3. Review and limit SharePoint admin permissions

### Technical Controls
```json
{
  "sharingRestrictions": {
    "externalSharing": "existingExternalUserOnly",
    "requireSignIn": true,
    "preventExternalUsersFromSharing": true
  },
  "downloadRestrictions": {
    "preventDownload": true,
    "blockSyncForUnmanagedDevices": true
  },
  "auditSettings": {
    "enableAuditLog": true,
    "retentionDays": 180
  }
}
```

### Monitoring Controls
1. Enable alerts for mass downloads
2. Monitor search queries containing sensitive terms
3. Review permission changes daily

## 5. Incident Response Playbook

### Initial Detection 
1. Identify affected SharePoint sites
2. Review audit logs for scope of access
3. Analyze data exfiltration volume

### Investigation
1. Document timeline of compromise
2. Identify compromised accounts
3. Review permission changes
4. Track data access patterns

### Containment
1. Revoke suspicious permissions
2. Block compromised accounts
3. Remove external sharing links
4. Enable versioning for affected libraries

## 6. References
- [MITRE T1213.002](https://attack.mitre.org/techniques/T1213/002/)
- [Microsoft SharePoint Security](https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/)
- [SharePoint Audit Log Reference](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance)

---

# Threat Model: Email Hiding Rules (T1564.008) in Microsoft 365 & Entra ID

## 1. Overview
Email hiding rules in Microsoft 365 can be created through Outlook clients, OWA, or PowerShell to manipulate email flow and visibility. Adversaries abuse this functionality to hide evidence of compromise and avoid detection.

## 2. Attack Vectors

### 2.1 PowerShell Rule Creation
**Description**: Adversaries use PowerShell cmdlets to create inbox rules programmatically.

**Scenario**: An attacker with compromised admin credentials creates rules to hide security alerts.

**Relevant Audit Operations**:
- New-InboxRule
- Set-InboxRule 
- UpdateInboxRules

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:30:22",
  "Id": "1a2b3c4d-5e6f-7g8h-9i0j",
  "Operation": "New-InboxRule",
  "OrganizationId": "org123",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "attacker@victim.com",
  "ObjectId": "/InboxRule:Hide_Security_Alerts",
  "Parameters": {
    "SubjectContainsWords": ["security alert", "suspicious", "compromised"],
    "MoveToFolder": "Deleted Items",
    "StopProcessingRules": true
  }
}
```

### 2.2 Transport Rule Manipulation
**Description**: Attackers modify organization-wide transport rules to suppress security notifications.

**Scenario**: Adversary creates transport rules to delete phishing warnings.

**Relevant Audit Operations**:
- Set-TransportRule
- New-TransportRule
- Remove-TransportRule

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:45:33", 
  "Id": "9i8h7g6f-5e4d-3c2b-1a0b",
  "Operation": "New-TransportRule",
  "OrganizationId": "org123",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "admin@victim.com",
  "ObjectId": "TransportRule:Block_Security_Notifications",
  "Parameters": {
    "MessageContainsWords": ["phishing detected", "malware found"],
    "DeleteMessage": true
  }
}
```

### 2.3 Client-Side Rule Creation
**Description**: Attackers use Outlook/OWA interfaces to create rules.

**Relevant Audit Operations**:
- UpdateInboxRules
- Set-InboxRule

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:15:44",
  "Id": "5e4d3c2b-1a0b-9i8h-7g6f",
  "Operation": "UpdateInboxRules", 
  "OrganizationId": "org123",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "user@victim.com",
  "ClientIP": "192.168.1.100",
  "RuleName": "Move_Security_Emails",
  "FolderPath": "\\Deleted Items"
}
```

## 3. Detection Strategy

### 3.1 Behavioral Analytics Rules
```sql
-- Detect mass rule creation
SELECT UserKey, COUNT(*) as RuleCount
FROM AuditLogs 
WHERE Operation IN ('New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules')
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING COUNT(*) > 5

-- Detect suspicious rule patterns
SELECT * FROM AuditLogs
WHERE Operation IN ('New-InboxRule', 'Set-InboxRule')
AND Parameters CONTAINS ANY ('security', 'phishing', 'suspicious', 'alert')
AND (Parameters CONTAINS 'DeleteMessage' OR Parameters CONTAINS 'MoveToFolder')
```

### 3.2 Baseline Deviation Monitoring
- Track normal rate of rule creation per user/day
- Alert on deviations >2 standard deviations
- Monitor for rules created outside business hours
- Track rule creation from unusual IP addresses

### 3.3 Key Detection Metrics
- Rule creation velocity (rules/hour)
- Percentage of rules with security-related keywords
- Number of rules targeting security folders
- Volume of moved/deleted messages per rule

## 4. Mitigation Controls

### 4.1 Administrative Controls
```json
{
  "rulePolicies": {
    "maxRulesPerUser": 50,
    "prohibitedKeywords": ["security", "alert", "phishing"],
    "restrictedFolders": ["Security Alerts", "Phishing"],
    "requireApproval": true,
    "auditRuleChanges": true
  }
}
```

### 4.2 Technical Controls
- Enable Advanced Audit Logging
- Implement transport rule change approval workflow
- Restrict PowerShell rule creation capabilities
- Regular rule audit reviews

### 4.3 Monitoring Controls
- Real-time alerts for suspicious rule creation
- Daily rule change reports
- Security team notifications for mass rule changes
- Automated rule inventory scanning

## 5. References
- MITRE ATT&CK: T1564.008
- Microsoft Security Documentation: Exchange Online Protection
- Microsoft 365 Defender Portal: Advanced Hunting Queries
- Cloud App Security: Activity Monitoring

---

# Threat Model: Steal Web Session Cookie (T1539) in Microsoft 365 & Entra ID

## 1. Overview 
Adversaries may steal web session cookies used for authentication to Microsoft 365 and Entra ID services to bypass MFA and gain unauthorized access to user accounts and resources. This attack targets service cookies from supported browsers (Edge, Chrome, Firefox) and applications that interact with Microsoft cloud services.

## 2. Attack Vectors

### 2.1 Browser Cookie Theft
**Description**: Malware or malicious browser extensions extract authentication cookies from browser storage or memory.

**Audit Events**:
```json
{
  "Operation": "UserLoggedIn",
  "CreationTime": "2024-01-20T15:22:13",
  "UserId": "bob@company.com",
  "ClientIP": "198.51.100.1", 
  "UserAgent": "Mozilla/5.0...",
  "DeviceName": "DESKTOP-ABC123",
  "AuthenticationMethod": "PrimaryRefreshToken",
  "ResultStatus": "Success"
}
```

**Detection Fields**:
- Operation: UserLoggedIn
- AuthenticationMethod
- ClientIP
- DeviceName 
- UserAgent

### 2.2 Network Proxy Interception
**Description**: Adversary-in-the-middle attack using tools like Evilginx2 to capture session cookies during authentication.

**Audit Events**: 
```json
{
  "Operation": "UserLoggedIn", 
  "CreationTime": "2024-01-20T16:14:22",
  "UserId": "bob@company.com",
  "IPAddress": "198.51.100.2",
  "UserAgent": "Mozilla/5.0...",
  "AuthenticationRequirement": "multiFactorAuthentication",
  "ConditionalAccessStatus": "success",
  "NetworkLocationDetails": {
    "TrustedNamedLocation": false,
    "IPAddress": "198.51.100.2"
  }
}
```

**Detection Fields**:
- NetworkLocationDetails
- ConditionalAccessStatus
- AuthenticationRequirement
- IPAddress

### 2.3 Application Token Extraction
**Description**: Malware extracts stored session tokens from Microsoft 365 desktop applications.

**Audit Events**:
```json
{
  "Operation": "Add service principal credentials",
  "CreationTime": "2024-01-20T17:11:33", 
  "ObjectId": "ServicePrincipal_123",
  "TargetId": "bob@company.com",
  "ActorId": "attacker@external.com",
  "CredentialType": "Password",
  "ResultStatus": "Success"
}
```

**Detection Fields**:
- Operation
- CredentialType
- ActorId vs TargetId
- ObjectId

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect authentication from new locations
SELECT UserId, IPAddress, COUNT(*) as auth_count
FROM UserLoggedIn 
WHERE TimeGenerated > ago(1h)
  AND NOT EXISTS (
    SELECT 1 FROM UserLoggedIn hist 
    WHERE hist.IPAddress = UserLoggedIn.IPAddress
    AND hist.TimeGenerated BETWEEN ago(30d) AND ago(1h)
  )
GROUP BY UserId, IPAddress
HAVING auth_count > 3;

-- Detect concurrent sessions from different locations
SELECT UserId, COUNT(DISTINCT IPAddress) as ip_count
FROM UserLoggedIn
WHERE TimeGenerated > ago(1h)
GROUP BY UserId 
HAVING ip_count > 2;
```

### 3.2 Baseline Deviation Monitoring
- Track normal authentication patterns per user:
  - Typical login times
  - Common IP addresses/ranges
  - Expected user agents
  - Geographic locations
- Alert on deviations:
  - Authentication outside business hours
  - Logins from unauthorized countries
  - Unexpected device/browser combinations

### 3.3 Technical Controls (JSON)
```json
{
  "conditionalAccess": {
    "signInFrequency": {
      "type": "hours",
      "value": 4
    },
    "persistentBrowser": "never",
    "locations": {
      "includeLocations": ["trusted locations"],
      "excludeLocations": ["blocked countries"]
    }
  },
  "applicationPolicies": {
    "modernAuth": true,
    "tokenLifetime": 3600,
    "refreshTokens": {
      "maxInactiveTime": "90.00:00:00"
    }
  }
}
```

## 4. Mitigation Strategies

### Administrative Controls
1. Enforce shortest viable token lifetimes
2. Implement device compliance requirements
3. Configure conditional access policies
4. Enable modern authentication
5. Block legacy authentication protocols

### Technical Controls  
1. Deploy Microsoft Defender for Cloud Apps
2. Enable continuous access evaluation
3. Implement session controls
4. Configure risk-based conditional access
5. Enable token protection features

### Monitoring Controls
1. Monitor authentication patterns
2. Track service principal credential changes
3. Alert on suspicious token usage
4. Review conditional access policy changes
5. Monitor for exposed credentials

## 5. Incident Response Steps

1. Initial Assessment
   - Validate alert authenticity
   - Identify affected accounts
   - Document suspicious activity 

2. Investigation
   - Review authentication logs 
   - Analyze IP addresses and locations
   - Check for related compromised accounts
   - Examine device compliance status

3. Containment
   - Reset affected user passwords
   - Revoke active sessions
   - Block suspicious IPs
   - Disable compromised service principals
   - Enable stricter authentication policies

## 6. References
- [MITRE ATT&CK T1539](https://attack.mitre.org/techniques/T1539/)
- [Microsoft - Detect Token Theft](https://docs.microsoft.com/security/token-theft)
- [Microsoft - Session Management](https://docs.microsoft.com/azure/active-directory/session-management)
- [MISC Protection Guidance](https://docs.microsoft.com/security/cookie-protection)

---

# Threat Model: Permission Groups Discovery (T1069) in Microsoft 365 & Entra ID

## 1. Overview

Permission Groups Discovery in Microsoft 365 and Entra ID involves adversaries attempting to enumerate groups, roles, and permissions to understand the security structure and identify potential privilege escalation paths. Common techniques include:

- Enumerating Microsoft 365 Groups and distribution lists
- Discovering Entra ID role assignments 
- Mapping SharePoint/OneDrive permissions
- Identifying conditional access policies

## 2. Attack Vectors

### 2.1 Azure PowerShell Group Enumeration

**Description:**
Adversaries use Azure PowerShell modules to enumerate groups and memberships.

**Example Attack:**
```powershell
Connect-AzAccount
Get-AzADGroup -All
Get-AzRoleAssignment
```

**Relevant Audit Operations:**
- Add member to group
- Remove member from group 
- Add group
- Update group

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "8382d091-9665-4723-8539-4b12c132d85f",
  "Operation": "Add member to group",
  "OrganizationId": "b36a28a8-c8e4-4492-ab8f-74c0d3272133",
  "RecordType": 8,
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "ProjectManagers",
  "UserId": "user@contoso.com",
  "AuditResult": "Success"
}
```

### 2.2 SharePoint Permission Enumeration 

**Description:**
Adversaries query SharePoint site permissions and sharing settings.

**Example Attack:**
```powershell
Get-SPOSite | Get-SPOUser
Get-SPOSiteGroup
```

**Relevant Audit Operations:**
- SharingSet
- AddedToGroup
- GroupAdded
- PermissionLevelModified

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T16:14:22", 
  "Operation": "SharingSet",
  "Site": "/sites/Finance",
  "ObjectId": "https://contoso.sharepoint.com/sites/Finance",
  "UserId": "attacker@contoso.com",
  "TargetUserOrGroupName": "External Sharing Group",
  "TargetUserOrGroupType": "SecurityGroup",
  "EventSource": "SharePoint",
  "ItemType": "Site",
  "ListItemUniqueId": "1234-5678-91011",
  "SiteUrl": "https://contoso.sharepoint.com/sites/Finance"
}
```

### 2.3 Role Assignment Discovery

**Description:** 
Adversaries enumerate role assignments in Entra ID to identify privileged accounts.

**Example Attack:**
```powershell
Get-AzRoleAssignment -SignInName user@contoso.com
Get-AzureADDirectoryRole | Get-AzureADDirectoryRoleMember
```

**Relevant Audit Operations:**
- Add member to role
- Remove member from role
- Update role

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T17:33:12",
  "Operation": "Add member to role.", 
  "RoleName": "Global Administrator",
  "RoleId": "62e90394-69f5-4237-9190-012177145e10",
  "TargetUserOrGroupName": "attacker@contoso.com",
  "ActorUPN": "admin@contoso.com",
  "Category": "RoleManagement",
  "ResultStatus": "Success"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect rapid group enumeration
SELECT UserId, COUNT(*) as QueryCount 
FROM AuditLogs
WHERE Operation IN ('Add member to group', 'Remove member from group')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 50

-- Alert on off-hours role enumeration
SELECT *
FROM AuditLogs 
WHERE Operation LIKE '%role%'
AND TimeGenerated NOT BETWEEN '0900' AND '1700'
```

### 3.2 Baseline Deviation Monitoring

- Establish baseline for normal group/role query patterns per user
- Monitor for deviations in:
  - Query volume
  - Query timing
  - Types of groups/roles queried
  - Source IP addresses/locations

### 3.3 Correlation Rules

```json
{
  "name": "Suspicious Permission Discovery Pattern",
  "description": "Detects suspicious sequence of permission enumeration activities",
  "query": "let threshold = 30min;
    let suspicious_ops = dynamic(['Add member to group', 'Get-AzRoleAssignment', 'SharingSet']);
    AuditLogs
    | where Operation in (suspicious_ops)
    | summarize count() by UserId, bin(TimeGenerated, threshold)
    | where count_ > 10"
}
```

## 4. Mitigation Strategies

### 4.1 Administrative Controls

- Implement just-in-time access for administrative tasks
- Require MFA for all role/group management activities
- Review and limit service account permissions
- Implement role-based access control (RBAC)

### 4.2 Technical Controls

```json
{
  "conditionalAccessPolicies": [
    {
      "displayName": "Require MFA for Group Management",
      "conditions": {
        "applications": {
          "includeApplications": ["Office 365"]
        },
        "users": {
          "includeRoles": ["Groups Administrator"]
        }
      },
      "grantControls": {
        "operator": "AND",
        "builtInControls": ["mfa"]
      }
    }
  ]
}
```

### 4.3 Monitoring Controls

- Enable unified audit logging
- Configure alerts for suspicious permission enumeration
- Monitor service principal activities
- Track changes to role assignments

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Review unified audit logs for enumeration patterns
2. Identify source accounts and IP addresses
3. Check for concurrent suspicious activities

### 5.2 Investigation
1. Map timeline of permission discovery activities
2. Review changes to group memberships and role assignments
3. Analyze authentication patterns of suspect accounts
4. Check for exfiltration indicators

### 5.3 Containment
1. Reset compromised credentials
2. Remove suspicious role assignments
3. Enable stricter conditional access policies
4. Block suspicious IP addresses

## 6. References

- [MITRE ATT&CK T1069](https://attack.mitre.org/techniques/T1069/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Azure AD Audit Log Schema](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities)
- [Microsoft 365 Defender](https://docs.microsoft.com/en-us/microsoft-365/security/)

---

# Threat Model: Email Collection (T1114) in Microsoft 365 & Entra ID

## 1. Overview
Adversaries may target Microsoft 365 email systems to collect sensitive information through various methods including:
- Mailbox delegation and permissions abuse
- Email forwarding rules
- Direct API access using stolen credentials
- Mail client access using compromised accounts

## 2. Attack Vectors

### 2.1 Mailbox Delegation
**Description**: Adversaries add mailbox delegation permissions to gain persistent access to target mailboxes.

**Attack Scenario**:
1. Attacker compromises admin account
2. Adds Full Access permissions to target executive mailboxes
3. Uses delegated access to extract emails containing sensitive data

**Detection Fields**:
```json
{
  "Operation": "Add-MailboxPermission",
  "ResultStatus": "Success", 
  "UserId": "[Actor Email]",
  "ObjectId": "[Target Mailbox]",
  "Parameters": {
    "AccessRights": ["FullAccess"],
    "User": "[Delegate User]",
    "InheritanceType": "All"
  }
}
```

### 2.2 Email Forwarding Rules
**Description**: Creation of hidden inbox rules to automatically forward emails to attacker-controlled addresses.

**Attack Scenario**:
1. Attacker gains access to user account
2. Creates forwarding rule via Microsoft Graph API
3. Emails are silently forwarded to external address

**Detection Fields**:
```json
{
  "Operation": "New-InboxRule",
  "ResultStatus": "Success",
  "UserId": "[Actor Email]",
  "Parameters": {
    "ForwardTo": "*@external-domain.com",
    "Enabled": true,
    "DeleteMessage": false
  }
}
```

### 2.3 Direct API Access
**Description**: Using stolen credentials or tokens to access mailboxes via Microsoft Graph API.

**Attack Scenario**:
1. Attacker obtains access token
2. Makes API calls to download emails
3. Extracts data through automated collection

**Detection Fields**:
```json
{
  "Operation": "MailItemsAccessed", 
  "LogonType": "OAuth",
  "ClientIP": "[IP Address]",
  "UserId": "[Actor Email]",
  "MailboxGuid": "[Target GUID]",
  "FolderPathAccessed": ["Inbox", "Sent Items"]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect anomalous mailbox delegation
SELECT UserId, Count(*) as count
FROM AuditLogs 
WHERE Operation = 'Add-MailboxPermission'
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING count > 3;

-- Detect suspicious forwarding rules
SELECT UserId, Parameters.ForwardTo
FROM AuditLogs
WHERE Operation = 'New-InboxRule'
AND Parameters.ForwardTo NOT LIKE '%@companydomain.com';
```

### 3.2 Baseline Deviations
- Monitor for spikes in email access volume per user
- Track unusual access patterns outside business hours
- Alert on first-time delegation assignments
- Monitor for new external domains in forwarding rules

### 3.3 Real-time Alerting Rules
```json
{
  "name": "Suspicious Email Forwarding Rule",
  "description": "Detects creation of forwarding rules to external domains",
  "severity": "High",
  "threshold": {
    "operation": "New-InboxRule",
    "conditions": [
      {"ForwardTo": "external_domain"},
      {"RuleEnabled": true}
    ],
    "timeWindow": "5m"
  }
}
```

## 4. Mitigation Controls

### 4.1 Administrative Controls
- Implement approval workflow for mailbox delegation changes
- Restrict email forwarding to approved domains only
- Enable MFA for all email access
- Regular review of mailbox permissions

### 4.2 Technical Controls
```json
{
  "mailbox_settings": {
    "external_forwarding": "blocked",
    "delegation": {
      "approval_required": true,
      "allowed_domains": ["company.com"],
      "mfa_required": true
    },
    "api_access": {
      "conditional_access": true,
      "ip_restrictions": ["corporate_ranges"]
    }
  }
}
```

### 4.3 Monitoring Controls
- Real-time alerts on delegation changes
- Daily reports of forwarding rules
- API access monitoring dashboard
- Regular permission audit reports

## 5. Incident Response

### 5.1 Initial Detection
1. Validate alert details and impacted mailboxes
2. Review authentication logs for suspect accounts
3. Check for additional compromise indicators

### 5.2 Investigation
1. Analyze audit logs for scope of access
2. Review collected email content
3. Identify data exfiltration methods
4. Document timeline of events

### 5.3 Containment
1. Remove malicious forwarding rules
2. Revoke unauthorized delegations
3. Reset compromised credentials
4. Block suspicious IPs/domains

## 6. References
- MITRE ATT&CK: T1114
- Microsoft Security Documentation:
  - Exchange Online Audit Logging
  - Microsoft Graph Mail API Security
  - Email Forwarding Controls

This threat model provides Microsoft 365-specific detection and response guidance for email collection activities.

---

# Threat Model: Cloud Groups (T1069.003) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries enumerating and discovering cloud groups and permissions in Microsoft 365 and Entra ID environments to understand the security structure and identify potential targets. Common methods include:

- Using PowerShell cmdlets like Get-MsolRole
- Leveraging Azure CLI commands
- Querying Microsoft Graph API
- Enumerating group memberships and permissions

## 2. Attack Vectors

### 2.1 PowerShell Enumeration
**Description**: Adversaries use PowerShell to enumerate roles and group memberships

**Attack Scenario**:
1. Attacker compromises user credentials
2. Uses PowerShell to connect to Entra ID/Microsoft 365
3. Runs Get-MsolRole and Get-MsolRoleMember commands
4. Maps organizational structure and permissions

**Audit Fields**:
```json
{
    "CreationTime": "2024-01-20T15:30:00",
    "Id": "<GUID>",
    "Operation": "Add member to group.",
    "OrganizationId": "<GUID>",
    "RecordType": 8,
    "ResultStatus": "Success",
    "UserKey": "<GUID>",
    "UserType": "Regular",
    "Version": 1,
    "Workload": "AzureActiveDirectory",
    "ObjectId": "<Group_GUID>",
    "UserId": "attacker@domain.com",
    "CommandName": "Get-MsolRoleMember"
}
```

### 2.2 Azure Portal Enumeration 
**Description**: Adversaries browse Azure Portal to discover groups and permissions

**Attack Fields**:
```json
{
    "CreationTime": "2024-01-20T15:35:00", 
    "Operation": "GroupViewed",
    "RecordType": 15,
    "UserKey": "<GUID>",
    "GroupName": "Global Admins",
    "ClientIP": "12.34.56.78",
    "UserAgent": "Mozilla/5.0...",
    "ViewCount": 1
}
```

### 2.3 Microsoft Graph API Abuse
**Description**: Automated queries to Microsoft Graph API to map permissions

**Attack Fields**:
```json
{
    "CreationTime": "2024-01-20T15:40:00",
    "Operation": "Add service principal.",
    "ApplicationId": "<GUID>",
    "ClientAppId": "<GUID>", 
    "ApiEndpoint": "/groups",
    "QueryCount": 50,
    "QueryInterval": 10
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
// Detect rapid group enumeration
SELECT UserId, COUNT(*) as QueryCount
FROM AuditLogs 
WHERE Operation IN ('Add member to group.','Update group.')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 50 // Threshold for suspicious activity

// Detect off-hours enumeration
SELECT UserId, Operation, TimeGenerated
FROM AuditLogs
WHERE TimeGenerated NOT BETWEEN '09:00' AND '17:00'
AND Operation LIKE '%group%'
```

### 3.2 Baseline Deviations
- Monitor normal group query patterns per user/role
- Alert on deviations >25% from baseline
- Track typical working hours and locations
- Flag unusual source IP addresses or user agents

## 4. Mitigation Controls

### Administrative Controls
- Implement just-in-time privileged access
- Require MFA for all role changes
- Regular access reviews
- Document legitimate group enumeration needs

### Technical Controls
```json
{
    "conditionalAccessPolicy": {
        "name": "Block Group Enumeration",
        "conditions": {
            "applications": ["Office 365", "Azure Portal"],
            "clientApps": ["Browser", "PowerShell"],
            "locations": ["Untrusted"]
        },
        "controls": {
            "requireMFA": true,
            "blockPowerShell": true
        }
    }
}
```

### Monitoring Controls
- Enable unified audit logging
- Set up alerts for suspicious group operations
- Monitor PowerShell and Graph API usage
- Track group membership changes

## 5. Incident Response

### Initial Detection
1. Review unified audit logs for group enumeration
2. Identify source accounts and IP addresses
3. Check for correlation with other suspicious activity

### Investigation
1. Map affected groups and permissions
2. Review authentication logs for compromised accounts
3. Check for unauthorized group changes
4. Analyze PowerShell and API usage patterns

### Containment
1. Block suspicious IP addresses
2. Revoke affected access tokens
3. Reset compromised credentials
4. Remove unauthorized group members

## 6. References

- MITRE: https://attack.mitre.org/techniques/T1069/003/
- Microsoft Security Documentation
- Entra ID Audit Log Schema
- PowerShell Security Documentation

This threat model provides specific, actionable guidance for Microsoft 365 and Entra ID environments while focusing on realistic detection and response scenarios.

---

# Threat Model: Password Cracking (T1110.002) in Microsoft 365 & Entra ID

## Overview
Password cracking in Microsoft 365 and Entra ID typically occurs after adversaries obtain password hashes through credential dumps or misconfigurations. The cracked passwords are then used for authenticated access to services like Exchange Online, SharePoint, and Teams.

## Attack Vectors

### 1. Hash Extraction from Entra ID Connect
**Description**: Adversaries compromise the Entra ID Connect server to extract synchronized password hashes.

**Detection Fields**:
```json
{
  "Workload": "AzureActiveDirectory",
  "Operation": "Set DirSyncEnabled flag.",
  "Actor": {
    "ID": "admin@contoso.com",
    "Type": "User"
  },
  "ObjectId": "DirectorySynchronizationAccount", 
  "ResultStatus": "Success"
}
```

**Example Attack Pattern**:
- Compromise of AD Connect server
- Extraction of stored credentials
- Offline cracking of obtained hashes
- Authentication attempts with cracked passwords

### 2. Legacy Authentication Hash Exposure 
**Description**: Password hashes exposed through legacy authentication protocols like NTLM.

**Detection Fields**:
```json
{
  "Workload": "AzureActiveDirectory",
  "Operation": "UserLoggedIn",
  "Actor": {
    "ID": "compromised@contoso.com",
    "Type": "User"
  },
  "AuthenticationProtocol": "NTLM",
  "ResultStatus": "Success",
  "ClientIP": "10.1.2.3"
}
```

### 3. Password Hash Synchronization Misconfiguration
**Description**: Misconfigured PHS settings allowing unintended hash synchronization.

**Detection Fields**:
```json
{
  "Workload": "AzureActiveDirectory", 
  "Operation": "Set federation settings on domain.",
  "Actor": {
    "ID": "admin@contoso.com",
    "Type": "User"
  },
  "ModifiedProperties": [
    {
      "Name": "PasswordHashSync",
      "NewValue": "True" 
    }
  ]
}
```

## Detection Strategies

### Behavioral Analytics
```sql
SELECT UserPrincipalName, COUNT(*) as AuthCount,
  COUNT(DISTINCT ClientIP) as IPCount
FROM AuditLogs 
WHERE TimeGenerated > ago(1h)
  AND Operation = 'UserLoggedIn'
  AND ResultStatus = 'Success'
GROUP BY UserPrincipalName
HAVING COUNT(*) > 10 AND COUNT(DISTINCT ClientIP) > 3
```

### Baseline Deviations
- Track typical authentication patterns per user
- Alert on deviations > 2 standard deviations from baseline
- Monitor for unusual time windows or source locations

### Technical Controls
```json
{
  "conditionalAccess": {
    "signInFrequency": {
      "value": 4,
      "type": "hours",
      "enforced": true
    },
    "persistentBrowser": "never",
    "devicePlatforms": ["all"],
    "locations": ["allLocations"],
    "controls": ["mfa"]
  }
}
```

## Incident Response

### Initial Detection
1. Review UnifiedAuditLog for suspicious authentication patterns
2. Analyze AADConnect server logs for unauthorized access
3. Check PHS configuration changes in Entra ID

### Investigation Steps
1. Identify affected accounts through correlation of:
   - Failed authentication attempts
   - Successful logins from new IPs
   - Changes to authentication settings
2. Review Azure AD Sign-in logs for:
   - Authentication protocol usage
   - IP address patterns
   - Temporal analysis

### Containment Actions
1. Force password reset for affected accounts
2. Enable MFA
3. Block legacy authentication
4. Review and update PHS configurations
5. Implement conditional access policies

## References
- [MITRE ATT&CK T1110.002](https://attack.mitre.org/techniques/T1110/002/)
- [Microsoft Password Hash Sync Security](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-password-hash-synchronization)
- [Azure AD Connect Security](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-security)

Let me know if you would like me to expand any section or provide additional details.

---

# Threat Model: SAML Token Abuse (T1606.002) in Microsoft 365 & Entra ID

## 1. Overview

SAML token abuse in Microsoft 365 and Entra ID involves adversaries forging SAML tokens to bypass authentication controls and impersonate privileged users. This typically occurs through:
- Compromising SAML token-signing certificates
- Establishing malicious federation trusts
- Modifying token lifetimes and claims

## 2. Attack Vectors

### 2.1 Token-Signing Certificate Theft

**Description:**
Adversaries steal or export the token-signing certificate to generate forged SAML tokens.

**Detection Fields:**
```json
{
  "Operation": "Set federation settings on domain",
  "ObjectId": "domain.com",
  "UserId": "<user>",
  "ClientIP": "<ip>",
  "TokenSigningCertificate": "<cert thumbprint>"
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "8382d091-7a0f-45f7-b421-c7560db93259",
  "Operation": "Set federation settings on domain", 
  "OrganizationId": "b7e9cb21-8a19-4799-b419-f4007b2a23a2",
  "RecordType": 1,
  "UserType": 2,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "contoso.com",
  "UserId": "admin@contoso.com",
  "TokenSigningCertificate": "8382d091-7a0f-45f7-b421-c7560db93259",
  "ClientIP": "192.168.1.100",
  "Scope": "Domain"
}
```

### 2.2 Malicious Federation Trust 

**Description:**
Adversaries establish new federation trust relationships with attacker-controlled ADFS servers.

**Detection Fields:**
```json
{
  "Operation": "Add domain to company",
  "ObjectId": "<domain>", 
  "TargetFederationTrust": "<trust>",
  "UserId": "<user>",
  "ClientIP": "<ip>"
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T11:15:22",
  "Id": "92f4d093-1b2c-4567-98fe-72560fe91234",
  "Operation": "Add domain to company",
  "OrganizationId": "b7e9cb21-8a19-4799-b419-f4007b2a23a2", 
  "RecordType": 1,
  "UserType": 2,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "malicious.com",
  "UserId": "admin@contoso.com",
  "TargetFederationTrust": "malicious.com",
  "ClientIP": "192.168.1.100",
  "SupportedProtocols": ["SAMLP"]
}
```

### 2.3 Token Lifetime Modification

**Description:** 
Adversaries modify SAML token lifetimes to extend persistence.

**Detection Fields:**
```json
{
  "Operation": "Set federation settings on domain",
  "ModifiedProperties": ["TokenLifetime"],
  "OldValue": "<old>",
  "NewValue": "<new>",
  "UserId": "<user>"
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T14:33:11",
  "Operation": "Set federation settings on domain",
  "OrganizationId": "b7e9cb21-8a19-4799-b419-f4007b2a23a2",
  "RecordType": 1,
  "ModifiedProperties": [{
    "Name": "TokenLifetime",
    "OldValue": ["3600"],
    "NewValue": ["604800"]
  }],
  "UserId": "admin@contoso.com",
  "ObjectId": "contoso.com"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect sudden federation trust changes
SELECT UserId, COUNT(*) as changes
FROM AuditLogs 
WHERE Operation IN ('Add domain to company', 'Set federation settings on domain')
AND Timestamp > DATEADD(hour, -1, GETUTCDATE())
GROUP BY UserId
HAVING COUNT(*) > 3;

-- Alert on token lifetime increases
SELECT * FROM AuditLogs
WHERE Operation = 'Set federation settings on domain'
AND ModifiedProperties LIKE '%TokenLifetime%'
AND CAST(JSON_VALUE(NewValue, '$') as int) > 
    CAST(JSON_VALUE(OldValue, '$') as int) * 2;

-- Monitor certificate changes
SELECT * FROM AuditLogs
WHERE Operation = 'Set federation settings on domain'
AND TokenSigningCertificate IS NOT NULL
AND Timestamp > DATEADD(day, -1, GETUTCDATE());
```

### 3.2 Baseline Deviations
- Track normal federation configuration change patterns
- Alert on changes outside business hours
- Monitor for unusual source IP addresses
- Track typical token lifetimes

## 4. Mitigation Controls

### Administrative Controls
- Require MFA for all federation changes
- Implement strict change control for federation settings
- Regular auditing of federation trusts
- Limit federation admin privileges

### Technical Controls
```json
{
  "tokenLifetimePolicy": {
    "maxLifetime": "1h",
    "requireMFA": true,
    "allowedIssuers": ["trusted-issuer-1", "trusted-issuer-2"]
  },
  "federationSettings": {
    "allowedDomains": ["contoso.com"],
    "requireApproval": true,
    "certificateRotation": {
      "enabled": true,
      "rotationInterval": "90d"
    }
  }
}
```

### Monitoring Controls
- Real-time alerts on federation changes
- Certificate expiration monitoring
- Token usage analytics
- Regular federation trust review

## 5. Incident Response

### Initial Detection
1. Identify affected domains and trusts
2. Review recent federation configuration changes
3. Check certificate validity and history
4. Analyze token lifetime modifications

### Investigation
1. Extract and analyze SAML tokens
2. Review authentication patterns
3. Check for additional compromised credentials
4. Map timeline of federation changes

### Containment
1. Revoke compromised certificates
2. Reset federation trusts
3. Force token expiration
4. Block suspicious IPs
5. Enable strict token policies

## 6. References
- [MITRE T1606.002](https://attack.mitre.org/techniques/T1606/002/)
- [Microsoft SAML Token Protection](https://docs.microsoft.com/security/saml-token-protection)
- [Azure AD Federation Security](https://docs.microsoft.com/azure/active-directory/hybrid/security)
- [CyberArk Golden SAML](https://www.cyberark.com/resources/golden-saml)

---

# Threat Model: Hide Artifacts (T1564) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries attempt to hide their activities by:
- Creating email rules to hide security notifications and alerts
- Manipulating audit logging settings
- Hiding malicious actions through delegated permissions
- Using service principals to obscure activity

## 2. Attack Vectors

### 2.1 Email Rule Manipulation

**Description**: Adversaries create inbox rules to automatically move or delete security notifications, alerts, and audit messages.

**Attack Scenario**:
1. Attacker compromises admin account
2. Creates rules to move/delete security alerts
3. Rules target keywords like "security", "suspicious", "alert"

**Detection Fields**:
```json
{
  "Operation": "New-InboxRule",
  "ObjectId": "[RuleId]",
  "Parameters": {
    "MoveToFolder": "DeletedItems",
    "SubjectContainsWords": ["alert", "security", "suspicious"],
    "DeleteMessage": "True"
  },
  "UserId": "[Username]"
}
```

### 2.2 Audit Log Manipulation 

**Description**: Attackers disable or modify audit logging settings to avoid detection.

**Attack Scenario**:
1. Attacker gains Global Admin access
2. Disables audit logging for specific services
3. Modifies retention periods

**Detection Fields**:
```json
{
  "Operation": "Set-AdminAuditLogConfig", 
  "Parameters": {
    "UnifiedAuditLogIngestionEnabled": "False",
    "LogRetentionDays": "1"
  },
  "ResultStatus": "Success",
  "ClientIP": "[IP]",
  "UserId": "[Admin]"
}
```

### 2.3 Service Principal Abuse

**Description**: Attackers create and abuse service principals to mask activities.

**Attack Scenario**:
1. Create new service principal
2. Grant elevated permissions
3. Use for malicious actions

**Detection Fields**:
```json
{
  "Operation": "Add service principal.",
  "ServicePrincipalId": "[ID]",
  "Permissions": ["Directory.ReadWrite.All"],
  "CreatedBy": "[UserId]",
  "AuthenticationMethod": "OAuth2" 
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect suspicious email rules
SELECT UserId, Operation, COUNT(*) as RuleCount
FROM AuditLogs 
WHERE Operation = 'New-InboxRule'
  AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING COUNT(*) > 5;

-- Monitor audit configuration changes
SELECT *
FROM AuditLogs
WHERE Operation IN (
  'Set-AdminAuditLogConfig',
  'Disable-AuditDataRecordIngestion'
)
AND TimeGenerated > ago(24h);
```

### 3.2 Baseline Deviations 

- Monitor rate of inbox rule creation vs baseline
- Track frequency of audit configuration changes
- Alert on abnormal service principal creation patterns

### 3.3 Correlation Rules

```sql
-- Correlate admin actions with audit changes
SELECT a.UserId, a.Operation, b.Operation
FROM AuditLogs a
JOIN AuditLogs b 
  ON a.UserId = b.UserId
WHERE a.TimeGenerated BETWEEN b.TimeGenerated 
  AND DATEADD(minute, 5, b.TimeGenerated)
AND a.Operation LIKE '%Audit%'
AND b.Operation IN ('Add service principal','New-InboxRule');
```

## 4. Mitigation Strategies

### Administrative Controls
- Enforce MFA for all admin accounts
- Implement least privilege access
- Regular permission reviews
- Mandatory audit logging policies

### Technical Controls
```json
{
  "auditConfig": {
    "isEnabled": true,
    "retentionDays": 90,
    "ingestionEnabled": true
  },
  "inboxRules": {
    "maxRulesPerUser": 20,
    "prohibitedActions": [
      "DeleteMessage",
      "MoveToDeletedItems"  
    ]
  },
  "servicePrincipals": {
    "requireApproval": true,
    "restrictedPermissions": [
      "Directory.ReadWrite.All",
      "AuditLog.Read.All"
    ]
  }
}
```

### Monitoring Controls
- Real-time alerts on audit configuration changes
- Daily review of new service principals
- Weekly audit of inbox rules

## 5. Incident Response Playbook

1. Initial Detection
   - Review audit logs for indicators
   - Identify affected accounts/resources
   - Document timeline of events

2. Investigation 
   - Analyze inbox rules and filters
   - Review service principal permissions
   - Check audit configuration history

3. Containment
   - Reset compromised credentials
   - Remove malicious inbox rules
   - Restore audit logging settings
   - Revoke suspicious service principals

## 6. References

- [MITRE T1564](https://attack.mitre.org/techniques/T1564/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Azure AD Audit Log Schema](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities)

---

# Threat Model: Taint Shared Content (T1080) in Microsoft 365 & Entra ID

## 1. Overview
In Microsoft 365, adversaries can compromise shared content through several vectors:
- SharePoint document libraries and shared folders
- OneDrive for Business shared files 
- Teams shared files and channels
- Microsoft 365 Groups shared resources

## 2. Attack Vectors

### Vector 1: SharePoint Document Library Compromise
**Description**: Adversary uploads malicious files to commonly accessed SharePoint document libraries

**Scenario**:
1. Attacker gains access to SharePoint site through compromised account
2. Uploads malware-infected documents to frequently accessed libraries
3. Modifies existing documents to include malicious macros/scripts
4. Legitimate users open infected files, executing malware

**Detection Fields**:
```json
{
  "Operation": "FileUploaded",
  "ObjectId": "/sites/team/Shared Documents/file.docx",
  "UserId": "user@domain.com",
  "ClientIP": "1.2.3.4",
  "UserAgent": "Browser/Version",
  "SourceFileName": "original.docx",
  "TargetFileName": "modified.docx"
}
```

### Vector 2: Teams Channel File Poisoning 
**Description**: Adversary modifies shared files in Teams channels to include malicious content

**Scenario**:
1. Attacker accesses Teams channel through compromised account
2. Modifies commonly referenced files to include malware
3. Updates file names/descriptions to appear legitimate
4. Team members access poisoned files through Teams interface

**Detection Fields**:
```json
{
  "Operation": "FileModified",
  "TeamName": "Finance Team",
  "ChannelName": "General",
  "FilePath": "/files/budget.xlsx",
  "ModifiedBy": "user@domain.com",
  "ClientIP": "1.2.3.4",
  "ModificationType": "ContentUpdate"
}
```

### Vector 3: OneDrive Link Sharing Abuse
**Description**: Adversary leverages shared OneDrive links to distribute malicious content

**Scenario**:
1. Attacker compromises user account with OneDrive access
2. Uploads malware to OneDrive location
3. Creates sharing links to malicious content
4. Distributes links through legitimate channels

**Detection Fields**:
```json
{
  "Operation": "CompanyLinkCreated",
  "ObjectId": "/personal/user/Documents/file.pdf",
  "SharingType": "Organization", 
  "CreatedBy": "user@domain.com",
  "Recipients": ["all@domain.com"],
  "LinkId": "xyz123"
}
```

## 3. Detection Strategies

### Behavioral Analytics
```sql
-- Detect unusual file upload patterns
SELECT UserId, COUNT(*) as upload_count
FROM AuditLogs 
WHERE Operation = 'FileUploaded'
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING upload_count > 20;

-- Detect mass file modifications
SELECT ModifiedBy, COUNT(*) as mod_count
FROM AuditLogs
WHERE Operation IN ('FileModified', 'FileUpdateContent')
AND TimeGenerated > ago(30m)
GROUP BY ModifiedBy
HAVING mod_count > 15;
```

### Baseline Deviations
- Monitor for spikes in file operations vs historical baselines
- Track sharing link creation rates per user/department
- Alert on abnormal file access patterns outside business hours

## 4. Mitigation Controls

### Technical Controls
```json
{
  "sharingPolicies": {
    "blockExternalSharing": true,
    "requireAuthentication": true,
    "restrictFileTypes": [".exe", ".vbs", ".ps1"],
    "scanAttachments": true
  },
  "documentLibrarySettings": {
    "requireCheckout": true,
    "versionHistory": true,
    "virusScan": true
  }
}
```

### Administrative Controls
- Implement strict file type restrictions 
- Enable protected view for downloaded files
- Configure ATP Safe Attachments policies
- Require approval for external sharing

### Monitoring Controls
- Enable detailed file operation auditing
- Monitor sharing activities in real-time
- Track file download patterns
- Alert on suspicious file types

## 5. Incident Response

### Initial Detection
1. Identify affected content locations
2. Review audit logs for malicious patterns
3. Determine scope of compromise

### Investigation Steps
1. Track file lineage and modifications
2. Identify compromised accounts
3. Review sharing history
4. Analyze file content changes

### Containment
1. Block access to affected content
2. Revoke active sharing links
3. Reset compromised accounts
4. Restore clean file versions

## 6. References
- MITRE: T1080
- Microsoft Security Documentation
- Microsoft 365 Defender Portal Guides
- SharePoint Security Best Practices

---

# Threat Model: Spearphishing Link (T1566.002) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 environments, spearphishing link attacks commonly manifest through:
- OAuth consent phishing targeting Microsoft 365 service permissions
- URL-based credential theft targeting Entra ID credentials 
- Email-embedded links to malware or malicious applications

## 2. Attack Vectors

### 2.1 OAuth Consent Phishing

**Description**: Adversaries send emails with links to malicious OAuth applications requesting permissions to Microsoft 365 services.

**Attack Scenario**:
1. Attacker creates malicious OAuth app in a separate tenant
2. Sends targeted email with app consent URL to victim
3. Victim authorizes app access, granting persistence to their account
4. Attacker uses granted permissions to access mail, files, etc.

**Relevant Audit Operations**:
```
- Add delegation entry
- Add service principal
- Add service principal credentials 
- ConsentModificationRequest
```

**Example Audit Log**:
```json
{
  "CreationTime": "2023-11-01T10:15:22",
  "Id": "8734fd52-8f1a-4d1a-9944-a9e3b64144f2",
  "Operation": "Add service principal",
  "OrganizationId": "55124c45-5d34-4ebc-8345-c8e4433847b2",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserType": 0,
  "ObjectId": "a4367d5a-718f-4c45-8dd2-8234f456789a",
  "UserId": "victim@contoso.com",
  "ApplicationId": "malicious_app_id",
  "ScopesRequested": ["Mail.Read", "Files.ReadWrite.All"],
  "ClientIP": "12.34.56.78",
  "UserAgent": "Mozilla/5.0..."
}
```

### 2.2 Credential Theft Links

**Description**: Adversaries send emails containing links to phishing sites that harvest Entra ID credentials.

**Attack Scenario**:
1. Attacker creates clone of Microsoft login page
2. Sends targeted email with urgent pretext and login link
3. Victim enters credentials on fake page
4. Attacker captures and uses credentials for initial access

**Relevant Audit Operations**:
```
- UserLoggedIn 
- Add user
- Update user
- Reset user password
```

**Example Audit Log**:
```json
{
  "CreationTime": "2023-11-01T14:22:33",
  "Id": "92847365-9876-4321-abcd-123456789012", 
  "Operation": "UserLoggedIn",
  "OrganizationId": "55124c45-5d34-4ebc-8345-c8e4433847b2",
  "RecordType": 15,
  "ResultStatus": "Success",
  "UserKey": "victim@contoso.com",
  "UserType": 0,
  "ClientIP": "198.51.100.234",
  "UserAgent": "Mozilla/5.0...",
  "LogonError": "InvalidUserNameOrPassword",
  "AuthenticationMethod": "Password"
}
```

### 2.3 Malicious Application Links 

**Description**: Adversaries send links to malicious applications that request excessive Microsoft Graph API permissions.

**Attack Scenario**:
1. Attacker develops malicious Teams/Office add-in
2. Sends targeted email with link to install add-in
3. Victim installs add-in granting Graph API access
4. Attacker uses add-in permissions to access data

**Relevant Audit Operations**:
```
- AppInstalled
- Add service principal
- AppPublishedToCatalog
```

**Example Audit Log**:
```json
{
  "CreationTime": "2023-11-02T09:11:23",
  "Id": "7263548d-87ab-4569-9123-87654321cdef",
  "Operation": "AppInstalled", 
  "OrganizationId": "55124c45-5d34-4ebc-8345-c8e4433847b2",
  "RecordType": 18,
  "ResultStatus": "Success",
  "UserKey": "victim@contoso.com",
  "ApplicationId": "suspicious_app_id",
  "ApplicationName": "Document Viewer Pro",
  "RequestedPermissions": ["Sites.ReadWrite.All", "User.Read.All"]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect suspicious OAuth consent patterns
SELECT UserId, ClientIP, COUNT(*) as consent_count
FROM AuditLogs 
WHERE Operation = "ConsentModificationRequest"
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING consent_count >= 3;

-- Detect password spray from new IPs
SELECT UserPrincipalName, ClientIP, COUNT(*) as failed_count
FROM SigninLogs
WHERE ResultType = "50126" -- Invalid username or password
AND TimeGenerated > ago(1h)
GROUP BY UserPrincipalName, ClientIP
HAVING failed_count >= 10;
```

### 3.2 Baseline Deviation Monitoring

- Monitor for abnormal spikes in:
  - OAuth application consents (>2 std dev from baseline)
  - Failed login attempts from new IPs
  - App installation rates per user/department
  - Graph API permission grants

### 3.3 Correlation Rules

```json
{
  "name": "Potential OAuth Phishing Campaign",
  "description": "Detects multiple users consenting to same new OAuth app",
  "severity": "High",
  "threshold": {
    "timeWindow": "1h",
    "minMatchCount": 3,
    "correlationRules": [
      {
        "operation": "Add service principal",
        "newApplication": true,
        "multipleUsers": true,
        "suspiciousScopes": ["Mail.Read", "Files.ReadWrite.All"]
      }
    ]
  }
}
```

## 4. Mitigation Strategies

### Administrative Controls
- Configure permitted redirect URIs for OAuth apps
- Enable admin consent requirements for high-risk permissions
- Block consumer app tenant access
- Implement strict app publisher verification requirements

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "signInRiskPolicy": {
      "state": "enabled",
      "riskLevels": ["high", "medium"],
      "controls": ["block", "mfa"]
    },
    "newAppConsent": {
      "state": "enabled", 
      "requireAdminApproval": true,
      "excludedPermissions": [
        "User.Read",
        "profile"
      ]
    }
  }
}
```

### Monitoring Controls
- Enable Unified Audit Log for all users
- Monitor OAuth app consents in Microsoft Cloud App Security
- Enable alerts for new external app publishers
- Track impossible travel scenarios for authentications

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected users and OAuth applications
2. Review consent grant audit logs
3. Check authentication patterns from suspicious IPs
4. Search for related phishing emails

### Investigation
1. Review application permissions and publisher
2. Analyze authentication logs for credential theft
3. Search email traces for phishing messages
4. Review mailbox rules and delegations

### Containment
1. Revoke suspicious OAuth application consents
2. Reset compromised account credentials
3. Block malicious URLs and IPs
4. Remove malicious inbox rules

## 6. References
- MITRE ATT&CK: T1566.002
- Microsoft: OAuth 2.0 Consent Phishing
- Microsoft: Defending Against OAuth App Phishing
- Microsoft: Detect and Remediate Illicit Consent Grants

---

# Threat Model: Office Application Startup (T1137) in Microsoft 365 & Entra ID

## 1. Overview

Office Application Startup persistence in Microsoft 365 focuses on abusing legitimate features like Outlook rules, add-ins, and templates to maintain access. The key risk areas are:

- Outlook inbox rules for email forwarding/deletion
- Office add-ins registered via Entra ID applications
- Custom forms and templates in SharePoint/OneDrive

## 2. Attack Vectors

### 2.1 Malicious Outlook Rules

**Description:**
Adversaries create inbox rules to forward emails, delete security alerts, or execute actions on messages.

**Attack Scenario:**
1. Attacker compromises user account
2. Creates rule to forward emails to external address
3. Configures rule to delete security notifications

**Detection Fields:**
```json
{
  "Operation": "New-InboxRule",
  "UserIds": ["user@domain.com"],
  "Parameters": {
    "RuleName": "External Forward",
    "ForwardTo": "attacker@evil.com",
    "DeleteMessage": true
  }
}
```

### 2.2 Office Add-in Registration

**Description:** 
Attackers register malicious Office add-ins as Azure applications to persist access.

**Attack Scenario:**
1. Register new Azure application
2. Configure Office add-in permissions
3. Deploy malicious add-in payload

**Detection Fields:**
```json
{
  "Operation": "Add service principal.",
  "TargetResources": [{
    "Type": "ServicePrincipal",
    "RequiredResourceAccess": [
      "Office.ReadWrite.All",
      "Mail.Read" 
    ]
  }],
  "InitiatedBy": {
    "user": {
      "id": "attacking-user-id",
      "displayName": "Attack User"
    }
  }
}
```

### 2.3 SharePoint Template Injection

**Description:**
Malicious code is embedded in Office templates stored in SharePoint.

**Attack Scenario:**
1. Upload infected template to SharePoint
2. Set as default document template
3. Template executes on document creation

**Detection Fields:**
```json
{
  "Operation": "FileUploaded",
  "SourceFileName": "template.dotm",
  "TargetLibraryUrl": "/sites/team/Templates",
  "ObjectId": "template-id",
  "UserAgent": "suspicious-user-agent"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics

```sql
-- Detect suspicious inbox rule creation
SELECT UserId, COUNT(*) as rule_count
FROM AuditLogs 
WHERE Operation = "New-InboxRule"
  AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING rule_count > 3;

-- Monitor add-in registration patterns
SELECT InitiatedBy.user.id, COUNT(*) as app_count
FROM AuditLogs
WHERE Operation = "Add service principal."
  AND TimeGenerated > ago(24h)
GROUP BY InitiatedBy.user.id
HAVING app_count > 2;
```

### 3.2 Baseline Deviations

- Normal: 0-1 inbox rules created per user per day
- Normal: 1-2 Office add-ins registered per month
- Alert on: >3 rules created in 1 hour
- Alert on: Add-in registration from new/suspicious IPs

## 4. Mitigation Strategies

### Administrative Controls
- Enforce app registration restrictions
- Block external email forwarding
- Require admin approval for add-ins

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "applications": {
      "officeAddIns": {
        "requireApproval": true,
        "allowedPublishers": ["verified-publishers"]
      }
    },
    "mailFlowRules": {
      "externalForwarding": "Block",
      "deleteRules": "Audit"
    }
  }
}
```

### Monitoring Controls
- Enable mailbox audit logging
- Monitor template file modifications
- Track service principal creation

## 5. Incident Response

### Initial Detection
1. Review audit logs for rule creation
2. Check registered Office add-ins
3. Scan SharePoint templates

### Investigation
1. Document affected accounts
2. Identify rule/add-in creation patterns
3. Review authentication logs
4. Analyze template modifications

### Containment
1. Disable suspicious rules
2. Remove unauthorized add-ins
3. Block compromised accounts
4. Quarantine infected templates

## 6. References

- MITRE: https://attack.mitre.org/techniques/T1137/
- Microsoft: https://docs.microsoft.com/en-us/microsoft-365/security/
- Entra ID: https://docs.microsoft.com/en-us/azure/active-directory/

Let me know if you would like me to expand on any section or provide additional examples.

---

# Threat Model: Additional Cloud Roles (T1098.003) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries adding additional roles or permissions to compromised accounts in Microsoft 365 and Entra ID to maintain persistent access and potentially escalate privileges. Common scenarios include:

- Adding Global Administrator roles
- Granting additional Microsoft 365 service admin roles
- Creating new service principals with elevated permissions
- Modifying existing application permissions

## 2. Attack Vectors

### 2.1 Global Administrator Role Addition

**Description:**
Adversary adds Global Administrator role to a compromised account to gain persistent tenant-wide access.

**Audit Operations:**
- "Add member to role."
- "Update user."

**Example Log:**
```json
{
  "CreationTime": "2024-01-15T15:22:31",
  "Id": "8721cfa4-5b85-4e19-a035-79c88742aaf8",
  "Operation": "Add member to role.",
  "OrganizationId": "536f5c89-eabc-4894-9d58-c45c75f4d83a",
  "RecordType": "RoleManagement", 
  "ResultStatus": "Success",
  "UserKey": "10032001A38CAAA1@contoso.com",
  "UserType": "Regular",
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "admin@contoso.com",
  "RoleName": "Global Administrator",
  "RoleGuid": "62e90394-69f5-4237-9190-012177145e10"
}
```

### 2.2 Service Principal Credential Addition

**Description:**
Adversary adds credentials to existing service principals to maintain persistent access.

**Audit Operations:**
- "Add service principal credentials."
- "Add delegation entry."

**Example Log:**
```json
{
  "CreationTime": "2024-01-15T16:45:12",
  "Id": "952f1a21-d9ef-4abc-9876-ff123456789",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "536f5c89-eabc-4894-9d58-c45c75f4d83a",
  "RecordType": "AzureActiveDirectory",
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "ServicePrincipalId": "a912b3c4-d5e6-f7g8-h9i0-jk1234567890",
  "CredentialType": "Password",
  "KeyId": "bc123456-d7e8-f9g0-h1i2-jk3456789012"
}
```

### 2.3 Exchange Admin Role Assignment

**Description:**
Adversary grants Exchange Administrator role for persistent email access.

**Audit Operations:**
- "Add member to role."
- "Update user."

**Example Log:**
```json
{
  "CreationTime": "2024-01-15T17:15:33",
  "Id": "7651caf9-9abc-4de5-b678-901234567890",
  "Operation": "Add member to role.",
  "OrganizationId": "536f5c89-eabc-4894-9d58-c45c75f4d83a",
  "RecordType": "RoleManagement",
  "ResultStatus": "Success", 
  "UserKey": "attacker@contoso.com",
  "UserType": "Regular",
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "user@contoso.com",
  "RoleName": "Exchange Administrator",
  "RoleGuid": "29232cdf-9323-42fd-ade2-1d097af3e4de"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect rapid role assignments
SELECT UserKey, COUNT(*) as role_changes
FROM AuditLogs 
WHERE Operation = "Add member to role."
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING COUNT(*) >= 3;

-- Alert on sensitive role assignments outside business hours
SELECT *
FROM AuditLogs
WHERE Operation = "Add member to role."
AND RoleName IN ('Global Administrator', 'Exchange Administrator', 'SharePoint Administrator')
AND TimeGenerated NOT BETWEEN '0800' AND '1800';
```

### 3.2 Baseline Deviations

- Monitor for spikes in role assignment operations compared to typical baseline
- Track unusual patterns of service principal credential additions
- Alert on role assignments from unusual IP addresses or locations

### 3.3 Correlation Rules

```sql
-- Correlate role changes with other suspicious activity
SELECT a.UserKey, a.Operation, b.Operation
FROM AuditLogs a
JOIN AuditLogs b ON a.UserKey = b.UserKey
WHERE a.Operation = "Add member to role."
AND b.Operation IN ('Update user.', 'Add service principal credentials.')
AND a.TimeGenerated BETWEEN b.TimeGenerated 
    AND DATEADD(minute, 30, b.TimeGenerated);
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement Privileged Identity Management (PIM) for just-in-time access
- Require MFA for all role assignments
- Regular review of role memberships
- Document approval process for privileged role assignments

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "privilegedRoles": {
      "requireMFA": true,
      "blockLegacyAuthentication": true,
      "requireCompliantDevice": true,
      "allowedLocations": ["corporate network"]
    },
    "servicePrincipals": {
      "credentialLifetime": "90days",
      "requireCertificateAuth": true
    }
  }
}
```

### Monitoring Controls
- Enable audit logging for all role management activities
- Configure alerts for sensitive role assignments
- Monitor service principal credential additions
- Review role changes during security reviews

## 5. IR Playbook

### Initial Detection
1. Validate alert details in audit logs
2. Determine scope of role changes
3. Identify affected accounts and applications

### Investigation
1. Review authentication logs for affected accounts
2. Check for additional suspicious role assignments
3. Analyze geographic patterns of activity
4. Review service principal permissions

### Containment
1. Revoke unauthorized role assignments
2. Reset affected account credentials
3. Remove unauthorized service principal credentials
4. Enable PIM for affected roles

## 6. References

- MITRE: https://attack.mitre.org/techniques/T1098/003/
- Microsoft: https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts
- Microsoft Security Blog: https://www.microsoft.com/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/

---

# Threat Model: Automated Collection (T1119) in Microsoft 365 & Entra ID

## Overview
Adversaries may use automated methods to collect data from Microsoft 365 and Entra ID environments through APIs, PowerShell modules, and administrative interfaces. This often involves scripted/programmatic access to collect emails, files, and other sensitive data.

## Attack Vectors

### 1. Programmatic Email Collection

**Description**:
Adversaries use Microsoft Graph API or Exchange Online PowerShell to automatically collect emails matching specific criteria.

**Scenario**:
- Attacker compromises admin account
- Uses Microsoft Graph API to query mailboxes
- Downloads emails matching keywords or date ranges
- Executes collection at regular intervals

**Detection Fields**:
- Operation: "MailItemsAccessed"
- ClientAppId: [Application ID]
- ResultStatus
- LogonType
- ClientIP
- UserId

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "25b2416d-1527-4518-9359-c9927e7893e6",
  "Operation": "MailItemsAccessed",
  "OrganizationId": "d124f588-18d9-4799-8d6c-b42f99847c31", 
  "RecordType": 2,
  "UserKey": "john.doe@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "40.84.135.211",
  "UserId": "john.doe@company.com",
  "ClientAppId": "a0c73c16-a7e3-4564-9a95-2bdf47383716",
  "ResultStatus": "Succeeded",
  "LogonType": 2,
  "MailboxGuid": "35ee0fb1-890e-44c5-b475-5d0666b259e5",
  "MailboxOwnerUPN": "victim@company.com",
  "FolderPathAccessed": "/Inbox",
  "ClientInfoString": "GraphAPI/1.0",
  "OperationCount": 247
}
```

### 2. SharePoint Mass Download

**Description**: 
Using SharePoint APIs or sync clients to automatically download large volumes of files.

**Detection Fields**:
- Operation: "FileDownloaded", "FileSyncDownloadedFull" 
- SourceFileName
- SourceRelativeUrl
- ClientIP
- UserAgent
- WebId

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "4a2c4380-f800-4142-9b93-42213d4b3a7c",
  "Operation": "FileDownloaded",
  "OrganizationId": "d124f588-18d9-4799-8d6c-b42f99847c31",
  "RecordType": 4, 
  "UserType": 0,
  "Version": 1,
  "Workload": "SharePoint",
  "ClientIP": "40.84.135.211",
  "ObjectId": "https://company.sharepoint.com/sites/finance/Shared Documents/Q4 Report.xlsx",
  "UserId": "john.doe@company.com",
  "CorrelationId": "1a2b3c4d-1234-5678-90ab-cdef12345678",
  "EventSource": "SharePoint",
  "ItemType": "File",
  "ListId": "1234b5cd-12ab-34cd-56ef-789012345678",
  "ListItemUniqueId": "a1b2c3d4-e5f6-g7h8-i9j0-k9l8m7n6o5p4",
  "Site": "https://company.sharepoint.com/sites/finance",
  "UserAgent": "Microsoft.SharePoint.Client/16.0",
  "WebId": "9876fedc-ba98-7654-3210-fedcba987654"
}
```

### 3. Teams Chat Export

**Description**:
Automated collection of Teams chat messages and channel content using Graph API.

**Detection Fields**:
- Operation: "MessagesExported"
- DataExportType
- ExportedObjectCount
- ExportedBy
- TargetUsers

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T17:45:11",
  "Id": "7d8e9f10-a1b2-4c3d-9e8f-1a2b3c4d5e6f",
  "Operation": "MessagesExported",
  "OrganizationId": "d124f588-18d9-4799-8d6c-b42f99847c31",
  "RecordType": 25,
  "UserType": 0,
  "Version": 1,
  "Workload": "Teams",
  "ClientIP": "40.84.135.211",
  "UserId": "john.doe@company.com",
  "DataExportType": "ChatMessages",
  "ExportedObjectCount": 1562,
  "ExportedBy": "john.doe@company.com",
  "TargetUsers": ["sales@company.com", "finance@company.com"],
  "ExportStartTime": "2024-01-20T17:45:00",
  "ExportEndTime": "2024-01-20T17:45:11"
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect high volume email access
SELECT UserId, ClientIP, COUNT(*) as access_count
FROM AuditLogs 
WHERE Operation = 'MailItemsAccessed'
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 100

-- Detect mass file downloads
SELECT UserId, ClientIP, COUNT(*) as download_count
FROM AuditLogs
WHERE Operation IN ('FileDownloaded','FileSyncDownloadedFull')
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 50
```

### Baseline Deviation Monitoring
- Track normal patterns of:
  - API calls per hour per user
  - File downloads per session
  - Email access patterns
  - Teams export frequency
- Alert on deviations > 2 standard deviations

## Mitigation Strategies

### Administrative Controls
1. Implement conditional access policies
2. Enable MFA for all admin accounts
3. Review and limit API permissions
4. Configure DLP policies

### Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Block Suspicious API Access",
    "Conditions": {
      "Applications": ["Microsoft Graph API", "Exchange Online PowerShell"],
      "Users": ["All Users"],
      "Controls": {
        "RequireMFA": true,
        "BlockDownloads": true,
        "AllowedLocations": ["Corporate Network"]
      }
    }
  }
}
```

### Monitoring Controls
1. Enable Unified Audit Logging
2. Configure alerts for:
   - Bulk operations
   - Off-hours activity
   - Anomalous IP addresses
   - High-volume downloads

## References
- [MITRE ATT&CK T1119](https://attack.mitre.org/techniques/T1119)
- [Microsoft Graph Security API](https://docs.microsoft.com/graph/security-concept-overview)
- [Microsoft 365 Defender](https://docs.microsoft.com/microsoft-365/security/defender/microsoft-365-defender)

Would you like me to continue with the incident response playbook section?

---

# Threat Model: Data from Cloud Storage (T1530) in Microsoft 365 & Entra ID

## 1. Overview
This technique focuses on adversaries accessing sensitive data from Microsoft 365 cloud storage services, particularly SharePoint Online and OneDrive for Business. Common attack patterns include:
- Abuse of overly permissive sharing settings
- Exploitation of misconfigured permissions
- Mass downloading of documents using compromised credentials
- Direct API access bypassing normal application controls

## 2. Attack Vectors

### 2.1 Mass Document Download
**Description**: Adversary uses compromised credentials to bulk download documents from SharePoint/OneDrive

**Audit Operations to Monitor**:
- FileDownloaded
- FileSyncDownloadedFull
- DownloadDocument

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "3c7e2bce-9a4a-47d3-94d5-f2231ac2c456",
  "Operation": "FileDownloaded",
  "OrganizationId": "4a7c8a2e-3d5b-4f6a-9c2d-1e5f3b9a8d7c",
  "RecordType": 6,
  "UserKey": "i:0h.f|membership|bob@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "OneDrive",
  "ObjectId": "https://contoso-my.sharepoint.com/personal/bob_contoso_com/Documents/Financial Reports/Q4 2023.xlsx",
  "UserId": "bob@contoso.com",
  "ClientIP": "192.168.1.100",
  "UserAgent": "OneDrive Sync Client"
}
```

### 2.2 Anonymous Link Access
**Description**: Adversary exploits overly permissive anonymous sharing links

**Audit Operations to Monitor**:
- AnonymousLinkCreated
- AnonymousLinkUsed 
- SharingInvitationCreated

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T14:33:12",
  "Operation": "AnonymousLinkUsed",
  "OrganizationId": "4a7c8a2e-3d5b-4f6a-9c2d-1e5f3b9a8d7c",
  "SiteUrl": "https://contoso.sharepoint.com/sites/Finance",
  "SourceFileName": "Executive_Salaries.xlsx",
  "SourceRelativeUrl": "/sites/Finance/Shared Documents/HR",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "ClientIP": "203.0.113.100",
  "ObjectId": "https://contoso.sharepoint.com/sites/Finance/Shared Documents/HR/Executive_Salaries.xlsx"
}
```

### 2.3 API-Based Collection
**Description**: Adversary uses Microsoft Graph API to programmatically extract data

**Audit Operations to Monitor**:
- FileSyncUploadedFull
- DataAccessRequestOperation
- FileAccessedExtended

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T09:15:44", 
  "Operation": "DataAccessRequestOperation",
  "OrganizationId": "4a7c8a2e-3d5b-4f6a-9c2d-1e5f3b9a8d7c",
  "RecordType": 11,
  "UserKey": "app:sp_sync@contoso.onmicrosoft.com",
  "Workload": "MicrosoftGraph",
  "ApplicationId": "97c73bfd-d967-4f32-b9b2-9e56149a907c",
  "ApplicationDisplayName": "Custom Sync App",
  "ClientIP": "40.113.200.201",
  "Resource": "/users/documents",
  "RequestType": "GET"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect mass downloads
SELECT UserId, COUNT(*) as download_count
FROM AuditLogs 
WHERE Operation IN ('FileDownloaded', 'FileSyncDownloadedFull')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 100 -- Threshold for suspicious download volume

-- Detect anonymous link abuse
SELECT ClientIP, COUNT(*) as anon_access_count
FROM AuditLogs
WHERE Operation = 'AnonymousLinkUsed'
AND TimeGenerated > ago(24h)
GROUP BY ClientIP
HAVING COUNT(*) > 50 -- Threshold for suspicious anonymous access
```

### 3.2 Baseline Deviation Monitoring
- Monitor average daily document access patterns per user
- Track normal working hours access vs. off-hours
- Establish baseline for download volumes and API usage
- Alert on deviations >3 standard deviations from normal

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Enforce Conditional Access policies for SharePoint/OneDrive access
- Implement data loss prevention (DLP) policies
- Configure sensitivity labels for automatic protection
- Disable anonymous link sharing organization-wide

### 4.2 Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "name": "Block Unmanaged Device Downloads",
    "conditions": {
      "applications": ["Office 365 SharePoint Online"],
      "devicePlatforms": ["all"],
      "locations": ["All locations"]
    },
    "controls": {
      "blockDownloads": true,
      "requireCompliantDevice": true
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable unified audit logging
- Configure alerts for:
  - Mass downloads (>100 files/hour)
  - Off-hours access patterns
  - Anonymous link creation
  - Multiple failed access attempts

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Validate alert authenticity
2. Identify affected user accounts and data
3. Review audit logs for scope of access
4. Document timeline of events

### 5.2 Investigation
1. Review authentication logs for compromised credentials
2. Analyze data access patterns
3. Identify any data exfiltration
4. Determine impact and scope

### 5.3 Containment
1. Block suspicious IP addresses
2. Revoke active sessions
3. Reset compromised credentials
4. Remove unauthorized sharing links
5. Enable MFA if not already required

## 6. References
- [MITRE T1530](https://attack.mitre.org/techniques/T1530/)
- [Microsoft SharePoint Security Guidelines](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/sharepoint-security-guides)
- [Microsoft Cloud App Security Alerts](https://learn.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy)

---

# Threat Model: Add-ins (T1137.006) in Microsoft 365 & Entra ID

## 1. Overview

Office add-ins provide persistence by executing code when Office applications start. In M365/Entra ID context, attackers can abuse:
- Outlook add-ins deployed via Exchange/M365 admin center
- Add-ins registered as service principals in Entra ID
- COM add-ins deployed via Group Policy/Intune
- Add-ins installed through Office Store

## 2. Attack Vectors

### 2.1 Malicious Outlook Add-in Registration

**Description:**
Attacker registers malicious Outlook add-in using compromised admin credentials

**Scenario:**
1. Attacker compromises Global Admin account
2. Creates new service principal for add-in
3. Grants OAuth permissions for mail access
4. Deploys add-in organization-wide

**Audit Fields:**
```json
{
  "Operation": "Add service principal.",
  "ObjectId": "[ServicePrincipalId]",
  "AppId": "[AppId]",
  "Permissions": ["Mail.Read", "Mail.Send"],
  "AdminConsent": true,
  "Actor": "[AdminUPN]"
}
```

### 2.2 Add-in Permission Abuse

**Description:** 
Escalate privileges by modifying existing add-in permissions

**Scenario:**
1. Compromise app developer account
2. Modify OAuth permissions of legitimate add-in
3. Request admin consent for elevated permissions

**Audit Fields:**
```json
{
  "Operation": "Set delegation entry.",
  "ObjectId": "[ServicePrincipalId]", 
  "ModifiedProperties": [
    {
      "Name": "OAuth2Permissions",
      "OldValue": ["Mail.Read"],
      "NewValue": ["Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All"]
    }
  ]
}
```

### 2.3 Backdoored COM Add-in

**Description:**
Deploy malicious COM add-in via Intune policy

**Scenario:**
1. Compromise Intune admin account
2. Create policy to deploy backdoored Office add-in
3. Target specific user groups

**Audit Fields:**
```json
{
  "Operation": "Create new configuration policy",
  "PolicyType": "Office Add-in", 
  "TargetedGroups": ["[GroupId]"],
  "AddInDetails": {
    "ProgId": "Malicious.OutlookAddin",
    "Path": "[URL]"
  }
}
```

## 3. Detection Strategies

### Behavioral Analytics:
```sql
-- Suspicious add-in registration patterns
SELECT Actor, COUNT(*) as add_in_count 
FROM AuditLogs
WHERE Operation = "Add service principal."
AND TimeGenerated > ago(1h)
GROUP BY Actor
HAVING add_in_count > 3;

-- Abnormal permission changes
SELECT *
FROM AuditLogs 
WHERE Operation = "Set delegation entry."
AND ModifiedProperties.NewValue CONTAINS "Mail.ReadWrite.All"
```

### Baseline Deviations:
- Monitor for spikes in add-in registration events
- Track changes to existing add-in permissions
- Alert on new add-ins requesting high-risk permissions

### Correlation Rules:
```sql
-- Add-in registration followed by mass deployment
SELECT a.*, b.*
FROM (
  SELECT * FROM AuditLogs 
  WHERE Operation = "Add service principal."
) a
JOIN (
  SELECT * FROM AuditLogs
  WHERE Operation = "Update organization setting"
  AND Setting = "OrganizationAddInDeployment" 
) b
ON a.Actor = b.Actor
WHERE b.TimeGenerated BETWEEN a.TimeGenerated AND dateadd(minute,5,a.TimeGenerated)
```

## 4. Mitigation Strategies

### Administrative Controls:
1. Restrict add-in deployment to specific admin roles
2. Enable admin consent requirements for API permissions
3. Block third-party Office Store add-ins
4. Implement add-in allowlisting

### Technical Controls:
```json
{
  "officePolicies": {
    "allowThirdPartyAddIns": false,
    "requiredAdminApproval": true,
    "allowedAddInPublishers": ["[Approved Publisher IDs]"],
    "blockedAddInTypes": ["COM", "Unsanctioned"]
  },
  "entraIDPolicies": {
    "adminConsentRequired": true,
    "allowedApplicationPermissions": ["restricted"],
    "addInRegistrationRestricted": true
  }
}
```

### Monitoring Controls:
1. Alert on new service principal creation
2. Monitor add-in permission changes
3. Track organization-wide add-in deployments
4. Audit admin consent grants

## 5. Incident Response 

### Initial Detection:
1. Identify affected add-in and associated service principal
2. Review audit logs for registration/modification events
3. Check permissions granted to add-in
4. Identify impacted users/groups

### Investigation:
1. Review admin activities around add-in deployment
2. Check for suspicious permission changes
3. Analyze add-in source and publisher
4. Identify any data access/exfiltration

### Containment:
1. Disable suspicious add-in
2. Remove service principal
3. Revoke OAuth permissions
4. Block deployment policy
5. Reset compromised admin accounts

## 6. References

- [MITRE ATT&CK T1137.006](https://attack.mitre.org/techniques/T1137/006)
- [Microsoft Office Add-ins Documentation](https://docs.microsoft.com/office/dev/add-ins/)
- [Microsoft Add-in Security](https://docs.microsoft.com/office/dev/add-ins/concepts/privacy-and-security)
- [Entra ID Service Principal Management](https://docs.microsoft.com/azure/active-directory/develop/app-objects-and-service-principals)

---

# Threat Model: Outlook Rules (T1137.005) in Microsoft 365 & Entra ID

## Overview
Adversaries abuse Outlook rules to establish persistence and automate malicious actions when specific emails are received. In Microsoft 365, rules can be created via Exchange Online PowerShell, Outlook clients, or the Outlook Web App (OWA).

## Attack Vectors

### 1. Hidden Forward Rules
**Description**: Adversaries create rules to secretly forward emails to external addresses for data exfiltration.

**Scenario**: 
- Attacker compromises user account
- Creates rule to forward emails containing keywords like "confidential", "password" to external address
- Hides rule from user view using Exchange PowerShell

**Audit Operations**:
```json
{
  "Operations": ["New-InboxRule", "Set-InboxRule", "UpdateInboxRules"],
  "Target": "ForwardTo, DeleteMessage",
  "LogFields": {
    "Operation": "New-InboxRule",
    "ClientIP": "1.2.3.4",
    "UserId": "user@domain.com",
    "RuleName": "Archive",
    "RuleParameters": {
      "ForwardTo": "external@domain.com",
      "DeleteMessage": "True",
      "Enabled": "True"
    }
  }
}
```

### 2. Email Auto-Delete Rules
**Description**: Rules created to automatically delete security alerts or phishing reports.

**Scenario**:
- Attacker creates rules targeting security notification subjects
- Messages are deleted before user can see them
- Often combined with other persistence mechanisms

**Audit Fields**:
```json
{
  "Operation": "Set-InboxRule",
  "RuleConfiguration": {
    "DeleteMessage": "True", 
    "SubjectContainsWords": [
      "Security Alert",
      "Suspicious Sign-in",
      "MFA Request"
    ]
  },
  "ClientInfo": {
    "ClientIPAddress": "1.2.3.4",
    "ClientProcessName": "Exchange PowerShell"
  }
}
```

### 3. Delegation Rules
**Description**: Attacker adds delegated permissions to maintain access.

**Example Log**:
```json
{
  "Operation": "Add-MailboxPermission",
  "ResultStatus": "Success",
  "Parameters": {
    "Identity": "victim@domain.com",
    "User": "attacker@domain.com", 
    "AccessRights": ["FullAccess"],
    "InheritanceType": "All"
  },
  "ClientIP": "1.2.3.4",
  "Timestamp": "2024-01-20T15:30:00Z"
}
```

## Detection Strategies

### Behavioral Analytics
```sql
-- Detect suspicious rule creation patterns
SELECT UserId, Count(*) as RuleCount
FROM AuditLogs 
WHERE Operation IN ('New-InboxRule', 'Set-InboxRule')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING Count(*) > 3 -- Threshold for rules/hour
```

### Baseline Monitoring
- Monitor for deviations from typical rule creation patterns
- Alert on rules created outside business hours
- Track rule creation from unusual IP addresses

### Key Risk Indicators
1. Rules forwarding to external domains
2. Rules with delete actions on security alerts
3. Multiple rules created in short timeframe
4. Rules created via PowerShell
5. Rules targeting sensitive keywords

## Technical Controls
```json
{
  "TransportRules": {
    "BlockExternalForwarding": true,
    "ExceptionsRequired": true,
    "NotifyAdminOnForward": true
  },
  "AuditConfig": {
    "UnifiedAuditLogEnabled": true,
    "MailboxAuditEnabled": true,
    "AuditRetentionDays": 180,
    "DetailedTracking": true
  }
}
```

## Administrative Controls
1. Require MFA for all rule changes
2. Restrict PowerShell access to Exchange Online
3. Enable mailbox auditing
4. Regular review of forwarding rules
5. Block automatic forwarding to external domains

## Monitoring Controls
1. Real-time alerts for suspicious rule creation
2. Daily reports of new forwarding rules
3. Automated scanning for mass-delete rules
4. Monitoring for PowerShell rule modifications

## Incident Response

### Initial Detection
1. Identify affected mailboxes
2. Export rule configurations
3. Capture audit logs
4. Document rule creation timeline

### Investigation Steps
1. Review rule creation patterns
2. Check for associated compromised accounts
3. Analyze PowerShell activity
4. Track email flow for data exfiltration

### Containment Actions
1. Disable suspicious rules
2. Block external forwarding
3. Reset affected account credentials
4. Enable additional auditing

## References
- MITRE ATT&CK: T1137.005
- MS Article: "How to Configure Mailbox Auditing"
- Exchange Online PowerShell Documentation

---

# Threat Model: Impair Defenses (T1562) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries attempt to disable or modify security controls, auditing capabilities, and defensive mechanisms to evade detection. Common targets include:

- Audit log settings and retention policies
- Security and compliance policies
- Multi-factor authentication settings
- Conditional Access policies
- Alert notifications and reporting

## 2. Attack Vectors

### 2.1 Disable Cloud Audit Logging

**Description:**
Adversaries attempt to disable or modify audit logging settings to hide their activities.

**Attack Scenario:**
1. Attacker compromises Global Admin account
2. Disables audit log collection via PowerShell or admin portal
3. Performs malicious activities without generating audit trails
4. Re-enables logging to avoid detection

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Set-AdminAuditLogConfig",
    "UpdatedOrganizationSettings",
    "Set-UnifiedAuditLogRetentionPolicy"
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "8382d091-7324-4d8b-9140-d92f23b53d3c",
  "Operation": "Set-AdminAuditLogConfig",
  "OrganizationId": "b7f3cc19-9713-4d94-b32e-f4d3d4583f4a",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "admin@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "Organization",
  "ModifiedProperties": [
    {
      "Name": "UnifiedAuditLogIngestionEnabled",
      "OldValue": "True",
      "NewValue": "False" 
    }
  ]
}
```

### 2.2 Modify MFA and Conditional Access

**Description:**
Attackers modify authentication requirements to maintain persistent access.

**Attack Scenario:**
1. Attacker gains admin access
2. Disables MFA for specific accounts
3. Modifies Conditional Access policies to bypass location/device restrictions
4. Creates authentication policy exclusions

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Update-MsolUserPrincipal", 
    "Set-MsolUser",
    "New-ConditionalAccessPolicy",
    "Set-ConditionalAccessPolicy"
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T15:44:12",
  "Id": "441ef0c9-3b4a-4d3f-b524-272cd5e26c2f",
  "Operation": "Set-MsolUser",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "admin@company.com",
  "Workload": "AzureActiveDirectory",
  "ObjectId": "victim@company.com",
  "ModifiedProperties": [
    {
      "Name": "StrongAuthenticationRequirements",
      "OldValue": "[{\"StrongAuthenticationRequirement\":true}]",
      "NewValue": "[]"
    }
  ]
}
```

### 2.3 Disable Security Alerts

**Description:**
Adversaries disable or modify security alert configurations to avoid detection.

**Attack Scenario:**
1. Attacker accesses Security & Compliance center
2. Modifies alert policies and notification settings
3. Disables specific alert types
4. Changes alert thresholds

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Set-ProtectionAlert",
    "Remove-ProtectionAlert",
    "UpdateAlertPolicy",
    "NotificationConfigurationUpdated"
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T09:12:55",
  "Id": "9a4e2c77-8f3b-4d89-90a1-bc412b26ae3c",
  "Operation": "Set-ProtectionAlert",
  "RecordType": 18,
  "ResultStatus": "Success",
  "UserId": "admin@company.com",
  "Workload": "SecurityComplianceCenter",
  "ObjectId": "Global Administrator Activity Alert",
  "ModifiedProperties": [
    {
      "Name": "Disabled",
      "OldValue": "False",
      "NewValue": "True"
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect audit log configuration changes
SELECT UserId, Operation, COUNT(*) as count
FROM AuditLogs 
WHERE Operation IN ('Set-AdminAuditLogConfig', 'UpdatedOrganizationSettings')
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING count > 2;

-- Monitor MFA changes
SELECT UserId, Operation, ObjectId, COUNT(*) as count
FROM AuditLogs
WHERE Operation LIKE '%MsolUser%'
AND ModifiedProperties LIKE '%StrongAuthenticationRequirements%'
AND TimeGenerated > ago(24h)
GROUP BY UserId, Operation, ObjectId
HAVING count > 3;
```

### 3.2 Baseline Deviation Monitoring

- Monitor frequency of security configuration changes against historical baseline
- Alert on unusual patterns of administrative activities
- Track changes to security policies outside business hours
- Monitor volume of disabled security features

### 3.3 Correlation Rules

```sql
-- Detect coordinated defense impairment
SELECT a.UserId, COUNT(DISTINCT a.Operation) as unique_ops
FROM AuditLogs a
WHERE a.TimeGenerated > ago(1h)
AND a.Operation IN (
  'Set-AdminAuditLogConfig',
  'Set-MsolUser',
  'Set-ProtectionAlert'
)
GROUP BY a.UserId
HAVING unique_ops >= 2;
```

## 4. Mitigation Strategies 

### 4.1 Administrative Controls

- Implement Privileged Identity Management (PIM) for admin roles
- Require approval for security configuration changes
- Document and regularly review security settings
- Maintain backup admin accounts with MFA enabled

### 4.2 Technical Controls

```json
{
  "ConditionalAccessPolicies": {
    "AdminMFA": {
      "Users": "All Administrators",
      "Applications": "All cloud apps",
      "Conditions": {
        "RequireMFA": true,
        "SignInRiskLevels": ["high", "medium"]
      }
    },
    "SecuritySettingsChanges": {
      "Operations": ["security configuration changes"],
      "RequireApproval": true,
      "ApproverGroups": ["Security Admins"]
    }
  }
}
```

### 4.3 Monitoring Controls

- Enable detailed audit logging for all admin activities
- Configure real-time alerts for security setting changes
- Implement automated policy compliance checks
- Monitor service health and configuration states

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Review audit logs for security configuration changes
2. Identify affected settings and services
3. Document timeline of modifications

### 5.2 Investigation
1. Determine scope of compromised accounts
2. Review authentication logs for suspect access
3. Analyze related configuration changes
4. Map affected security controls

### 5.3 Containment
1. Revoke active sessions for suspect accounts
2. Reset affected security configurations
3. Enable emergency audit logging
4. Block compromised admin accounts

## 6. References

- [MITRE ATT&CK - T1562](https://attack.mitre.org/techniques/T1562/)
- [Microsoft - Audit Log Search](https://docs.microsoft.com/microsoft-365/compliance/audit-log-search)
- [Microsoft - Security Monitoring](https://docs.microsoft.com/security/defender-365/security-monitoring)

---

# Threat Model: Exfiltration Over Web Service (T1567) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries may abuse legitimate web services for data exfiltration, particularly through:
- OAuth applications that request broad permissions
- Custom service principals with delegated access
- SharePoint/OneDrive external sharing
- Microsoft Teams external data sharing

## 2. Attack Vectors

### 2.1 OAuth Application Abuse
**Description**: Adversaries register malicious OAuth applications requesting broad permissions to access and exfiltrate data.

**Audit Operations**:
```json
{
  "Add service principal.",
  "Add service principal credentials.",
  "Add delegation entry."
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:15",
  "Id": "8721a8c9-54db-43c1-b556-793b31252a76",
  "Operation": "Add service principal.",
  "OrganizationId": "d95474cc-1234-5678-90ab-cdef12345678",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001@example.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "ef283401-9999-4321-9876-543210fedcba",
  "AppId": "a1b2c3d4-5678-90ef-fedc-ba0987654321",
  "Target": "[{\"ID\":\"Application\",\"Type\":0}]"
}
```

### 2.2 SharePoint External Sharing 
**Description**: Adversaries leverage SharePoint external sharing to exfiltrate data through anonymous or company-wide links.

**Audit Operations**:
```json
{
  "AnonymousLinkCreated",
  "CompanyLinkCreated",
  "SharingInvitationCreated"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T15:45:22",
  "Operation": "AnonymousLinkCreated", 
  "Site": "/sites/confidential",
  "ObjectId": "document1.docx",
  "UserType": "Regular",
  "UserKey": "john@example.com",
  "ClientIP": "192.168.1.100",
  "LinkType": "Anonymous",
  "Expiration": "2024-02-15T00:00:00"
}
```

### 2.3 Teams External Access
**Description**: Adversaries abuse Microsoft Teams external access capabilities to share data with external organizations.

**Audit Operations**:
```json
{
  "MessageSent",
  "FileShared",
  "ChatCreated"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T09:15:30",
  "Operation": "FileShared",
  "TeamName": "Project X",
  "ChannelName": "General",
  "FileName": "financial_report.xlsx",
  "UserKey": "alice@example.com",
  "ExternalUser": "partner@external.com",
  "SharingType": "ExternalSharing"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect suspicious OAuth app registrations
SELECT UserKey, COUNT(*) as app_count
FROM AuditLogs 
WHERE Operation = "Add service principal."
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING app_count > 3;

-- Monitor high volume external sharing
SELECT UserKey, COUNT(*) as share_count
FROM AuditLogs
WHERE Operation IN ("AnonymousLinkCreated", "CompanyLinkCreated")
AND TimeGenerated > ago(24h)
GROUP BY UserKey
HAVING share_count > 50;
```

### 3.2 Baseline Deviations
- Track normal patterns of:
  - OAuth app registration frequency per user/day
  - External sharing volume per department
  - Teams external collaboration patterns
- Alert on deviations > 2 standard deviations

## 4. Technical Controls
```json
{
  "preventions": {
    "oauth_apps": {
      "admin_consent_required": true,
      "allowed_domains": ["trusted-partners.com"],
      "blocked_permissions": ["Files.ReadWrite.All", "Mail.ReadWrite.All"]
    },
    "sharepoint": {
      "external_sharing": "existing_guests_only",
      "link_expiration_required": true,
      "max_link_duration_days": 30
    },
    "teams": {
      "external_access": "allowed_domains_only",
      "guest_file_sharing": false
    }
  }
}
```

## 5. Monitoring Controls
1. Enable unified audit logging
2. Configure alerts for:
   - New OAuth app registrations
   - Mass external sharing events
   - Unusual file download patterns
   - External domain communications

## 6. Incident Response
1. Initial Actions:
   - Identify affected accounts/resources
   - Review OAuth app permissions
   - Check external sharing patterns

2. Containment:
   - Revoke suspicious OAuth tokens
   - Disable compromised accounts
   - Block suspicious external domains

3. Recovery:
   - Review and update sharing policies
   - Implement additional DLP rules
   - Enhance monitoring controls

## References
- MITRE ATT&CK: T1567
- Microsoft Security Documentation
- Microsoft 365 Defender Portal Guide

---

# Threat Model: Unsecured Credentials (T1552) in Microsoft 365 & Entra ID

## Overview
In Microsoft 365 and Entra ID environments, adversaries search for credentials stored in various locations including:
- Service principal credentials and certificates
- Application registration secrets
- SharePoint/OneDrive documents containing passwords
- Teams messages with credentials
- Exchange mailboxes with stored credentials

## Attack Vectors

### 1. Service Principal Credential Access

**Description:**
Adversaries enumerate service principals and extract stored credentials/certificates.

**Attack Scenario:**
1. Attacker compromises admin account
2. Lists service principals using Graph API
3. Downloads credentials and certificates
4. Uses stolen materials to authenticate as service principal

**Detection Fields:**
```json
{
  "Operation": "Add service principal credentials.",
  "UserId": "[User UPN]",
  "ObjectId": "[Service Principal ID]",
  "Target": "[Service Principal Name]",
  "ResultStatus": "Success"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:43",
  "Id": "8382d091-7324-4418-b51f-88b863f69496",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "b967c48f-29e7-4d28-9e58-3a7c49d32c78", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001C36C2A18@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "8382d091-7324-4418-b51f-88b863f69496",
  "UserId": "admin@contoso.com",
  "AzureActiveDirectoryEventType": 1,
  "ExtendedProperties": [
    {
      "Name": "CredentialType", 
      "Value": "X509Certificate"
    }
  ]
}
```

### 2. SharePoint Document Enumeration

**Description:**  
Scans SharePoint/OneDrive documents for credentials stored in files.

**Attack Scenario:**
1. Attacker gains access to SharePoint
2. Uses search APIs to find documents with passwords
3. Downloads documents containing credentials

**Detection Fields:**
```json
{
  "Operation": "SearchQueryPerformed",
  "UserType": "Regular",
  "ObjectId": "[Document ID]",
  "SiteUrl": "[SharePoint Site]",
  "SearchQuery": "[Search Terms]"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "4c82fd1a-a207-4a25-8b76-44332de75d94",
  "Operation": "SearchQueryPerformed", 
  "OrganizationId": "b967c48f-29e7-4d28-9e58-3a7c49d32c78",
  "RecordType": 4,
  "UserType": "Regular",
  "UserKey": "i:0h.f|membership|user@contoso.com",
  "Workload": "SharePoint",
  "SiteUrl": "https://contoso.sharepoint.com/sites/Finance",
  "SourceRelativeUrl": "/sites/Finance/Shared Documents",
  "SearchQuery": "password credentials secret key",
  "ClientIP": "192.168.1.100"
}
```

### 3. Teams Message Mining

**Description:**
Searches Teams chat history for shared credentials.

**Attack Scenario:**
1. Attacker compromises user account
2. Exports Teams chat history 
3. Searches messages for credentials

**Detection Fields:**
```json
{
  "Operation": "MessagesExported",
  "UserId": "[User UPN]",
  "ChatId": "[Teams Chat ID]",  
  "MessageCount": "[Number of Messages]"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T17:33:12",
  "Id": "2a95e6a0-d8e4-4d84-a6c1-f99e8b2d46f2",
  "Operation": "MessagesExported",
  "OrganizationId": "b967c48f-29e7-4d28-9e58-3a7c49d32c78",
  "RecordType": 25,
  "UserType": "Regular", 
  "UserId": "user@contoso.com",
  "Workload": "MicrosoftTeams",
  "ChatId": "19:meeting_NzJkZDg3NDYtNGY0Mi00ZmFhLTk5YzAtYzk3YWQ4NWM0NjJh@thread.v2",
  "MessageCount": 5000,
  "ExportType": "ChatHistory",
  "ClientIP": "192.168.1.100"
}
```

## Detection Strategies

### Behavioral Analytics Rules

```sql
-- Detect excessive service principal credential access
SELECT UserId, COUNT(*) as access_count
FROM AuditLogs 
WHERE Operation = "Add service principal credentials."
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING access_count > 10

-- Alert on suspicious search queries
SELECT UserId, SearchQuery
FROM AuditLogs
WHERE Operation = "SearchQueryPerformed"
AND SearchQuery LIKE '%password%' 
OR SearchQuery LIKE '%credential%'
OR SearchQuery LIKE '%secret%'

-- Monitor large Teams exports
SELECT UserId, SUM(MessageCount) as total_messages
FROM AuditLogs
WHERE Operation = "MessagesExported" 
AND TimeGenerated > ago(24h)
GROUP BY UserId
HAVING total_messages > 10000
```

### Baseline Deviation Monitoring

- Track normal patterns of:
  - Service principal credential access per user
  - Document search volume and terms
  - Teams message export sizes
- Alert on deviations >2 standard deviations

## Mitigation Strategies

### Administrative Controls
1. Implement role-based access control (RBAC)
2. Enable conditional access policies
3. Enforce MFA for all users
4. Regular access reviews

### Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Block Service Principal Credential Access",
    "Conditions": {
      "Applications": ["Microsoft Graph API"],
      "ClientAppTypes": ["All"],
      "Locations": ["All"],
      "Users": ["All"]
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
2. Configure alerts for credential access
3. Monitor service principal activities
4. Track document access patterns

## Incident Response Playbook

### Initial Detection
1. Identify affected accounts/resources
2. Review audit logs for scope
3. Document timeline of events

### Investigation
1. Analyze credential access patterns
2. Review downloaded content
3. Check for lateral movement
4. Identify compromised credentials

### Containment
1. Reset affected credentials
2. Revoke suspicious tokens
3. Block compromised accounts
4. Update conditional access policies

## References
- [MITRE ATT&CK T1552](https://attack.mitre.org/techniques/T1552/)
- [Microsoft Service Principal Security](https://docs.microsoft.com/azure/active-directory/develop/app-objects-and-service-principals)
- [Microsoft Teams Audit Logging](https://docs.microsoft.com/microsoftteams/audit-log-events)
- [SharePoint Data Security](https://docs.microsoft.com/sharepoint/security-baseline)

---

# Threat Model: Clear Mailbox Data (T1070.008) in Microsoft 365 & Entra ID

## Overview
Adversaries may attempt to clear mailbox data and logs to hide their activities in Microsoft 365. This includes deleting emails, audit logs, and mailbox access trails that could reveal phishing, data exfiltration, or account compromise.

## Attack Vectors

### 1. Deletion of Export Requests
**Description:**
Adversaries remove evidence of mailbox exports by deleting export requests using Exchange PowerShell.

**Scenario:**
After exporting mailbox content for data theft, attacker removes export request history:
```powershell
Remove-MailboxExportRequest -Identity "Export_User1_20231125"
```

**Relevant Audit Operations:**
- Remove-ComplianceSearchAction
- Remove-MailboxExportRequest 

**Example Audit Log:**
```json
{
  "CreationTime": "2023-11-25T15:22:31",
  "Id": "27c2d214-8e9b-4d6e-a9e2-13d12345abcd",
  "Operation": "Remove-ComplianceSearchAction", 
  "OrganizationId": "b7d03e21-5d23-4846-b903-12345abcdef",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "i:0h.f|membership|bob@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "Export_User1_20231125",
  "UserId": "bob@contoso.com",
  "ClientIP": "192.168.1.100"
}
```

### 2. Mass Email Deletion
**Description:** 
Adversaries use hard delete operations to permanently remove emails from mailboxes.

**Scenario:**
Attacker performs bulk deletion of emails to remove phishing evidence:
- Uses Hard Delete operation
- Targets Sent Items and Deleted Items folders
- Occurs outside business hours

**Relevant Audit Operations:**
- HardDelete
- SoftDelete
- MoveToDeletedItems

**Example Audit Log:**
```json
{
  "CreationTime": "2023-11-25T02:15:44",
  "Id": "8af62de4-9b71-4ca2-b512-12345abcdef",
  "Operation": "HardDelete",
  "OrganizationId": "b7d03e21-5d23-4846-b903-12345abcdef",
  "RecordType": 2, 
  "ResultStatus": "Success",
  "UserKey": "i:0h.f|membership|attacker@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "10.1.2.3",
  "ObjectId": "/folder/inbox",
  "ItemCount": 547,
  "LogonUserSid": "S-1-5-21..."
}
```

### 3. Transport Rule Manipulation
**Description:**
Adversaries modify mail flow rules to automatically delete suspicious emails.

**Scenario:**
Attacker creates transport rules to delete emails containing security alert keywords.

**Relevant Audit Operations:**
- New-TransportRule
- Set-TransportRule
- Remove-TransportRule

**Example Audit Log:**
```json
{
  "CreationTime": "2023-11-26T18:33:12",
  "Id": "92e71d45-6c22-4d9a-ae45-12345abcdef",
  "Operation": "New-TransportRule",
  "OrganizationId": "b7d03e21-5d23-4846-b903-12345abcdef", 
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "i:0h.f|membership|admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "Parameters": [
    {"Name": "Name", "Value": "Delete Security Alerts"},
    {"Name": "DeleteMessage", "Value": "True"},
    {"Name": "SubjectContainsWords", "Value": "Security Alert;Compromise;Suspicious"}
  ]
}
```

## Detection Strategies

### Behavioral Analytics Rules
1. Mass Deletion Detection:
```sql
SELECT UserId, ClientIP, COUNT(*) as DeleteCount
FROM AuditLog 
WHERE Operation IN ('HardDelete','SoftDelete') 
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 100
```

2. After-Hours Activity:
```sql
SELECT * FROM AuditLog
WHERE Operation IN ('Remove-MailboxExportRequest','HardDelete')
AND TimeGenerated.hour NOT BETWEEN 9 AND 17
```

3. Transport Rule Changes:
```sql
SELECT * FROM AuditLog
WHERE Operation LIKE '%TransportRule%'
AND Parameters CONTAINS 'DeleteMessage'
```

### Baseline Deviation Monitoring
- Track average daily email deletion rates per user
- Monitor frequency of export request deletions
- Alert on transport rule modifications affecting security-related emails

### Technical Controls
```json
{
  "auditingControls": {
    "unifiedAuditingEnabled": true,
    "mailboxAuditingEnabled": true,
    "retentionPeriod": 365,
    "auditedOperations": [
      "HardDelete",
      "SoftDelete",
      "Remove-MailboxExportRequest",
      "New-TransportRule"
    ]
  },
  "preventiveControls": {
    "requireApprovalForBulkDelete": true,
    "restrictTransportRuleModification": "AdminsOnly",
    "preserveDeletedItems": 30,
    "enableLitigationHold": true
  }
}
```

## Incident Response Playbook

### Initial Detection
1. Review unified audit logs for mass deletions
2. Check for deleted export requests
3. Examine transport rule modifications

### Investigation Steps
1. Correlate deletion patterns with user activity
2. Review authentication logs for suspicious logins
3. Check email gateway logs for filtered messages
4. Analyze PowerShell command history

### Containment Actions
1. Suspend user account if compromise confirmed
2. Disable suspicious transport rules
3. Enable litigation hold on affected mailboxes
4. Block suspicious IP addresses
5. Reset affected user credentials

## References
- MITRE ATT&CK: T1070.008
- Microsoft Documentation: Exchange Audit Logging
- Microsoft Security Blog: Exchange Online Protection
- Microsoft 365 Defender Portal Documentation

---

# Threat Model: Exfiltration Over Webhook (T1567.004) in Microsoft 365 & Entra ID

## Overview
Adversaries may abuse webhook functionality in Microsoft 365 services like Teams, SharePoint, and Power Automate to exfiltrate data by creating authorized data flows to external endpoints. This provides a way to extract data while blending in with legitimate collaboration service traffic.

## Attack Vectors

### 1. Teams Webhook Abuse
**Description**: Adversaries create outbound webhooks in Teams channels to post sensitive messages and files to external endpoints

**Attack Flow**:
1. Attacker gains Team Owner permissions
2. Creates outbound webhook connector in Teams channel
3. Configures webhook to post to attacker-controlled endpoint
4. Channel messages and files are automatically forwarded

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "ConnectorAdded",
    "ConnectorUpdated", 
    "MessagesExported"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:13",
  "Id": "5d4c8f35-66e2-4c24-8db1-4fea1c172034",
  "Operation": "ConnectorAdded",
  "OrganizationId": "02e5d3fa-4d40-4aa1-aa48-4781ad71a282",
  "RecordType": 25, 
  "UserType": 0,
  "UserKey": "admin@company.com",
  "Version": 1,
  "Workload": "MicrosoftTeams",
  "ObjectId": "19:channel_id@thread.skype",
  "ConnectorType": "Outgoing Webhook",
  "ConnectorEndpoint": "https://attacker.com/webhook",
  "TeamName": "Finance Team",
  "ChannelName": "General"
}
```

### 2. Power Automate Data Exfiltration
**Description**: Adversaries create automated flows to periodically export data to external services

**Attack Flow**:
1. Attacker creates Power Automate flow
2. Configures SharePoint/Teams trigger
3. Adds HTTP POST action to external webhook
4. Flow automatically exports data on schedule

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "CreateFlow",
    "UpdateFlow",
    "FlowExecuted"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T18:14:22", 
  "Id": "44f8b9e5-1515-4527-a052-6fb8e91e7425",
  "Operation": "CreateFlow",
  "RecordType": 68,
  "UserType": 0,
  "UserKey": "user@company.com",
  "FlowName": "Document Sync",
  "TriggerType": "SharePoint",
  "ActionType": "HTTP",
  "ActionEndpoint": "https://webhook.site/abc123",
  "FlowSchedule": "Every 1 hour"
}
```

### 3. SharePoint External Sync
**Description**: Adversaries configure SharePoint document libraries to sync to external services

**Attack Flow**:
1. Attacker gets site collection admin access
2. Configures external sync connector
3. Points sync to attacker webhook
4. Documents automatically sync externally

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "SendToConnectionAdded",
    "FileUploaded",
    "FileSyncUploadedFull"
  ]
}
```

## Detection Strategies

### Behavioral Analytics
```sql
-- Detect suspicious webhook creation patterns
SELECT UserKey, ConnectorEndpoint, COUNT(*) as count
FROM TeamsAuditLog 
WHERE Operation = "ConnectorAdded"
  AND TimeGenerated > ago(1h)
GROUP BY UserKey, ConnectorEndpoint
HAVING count >= 3;

-- Monitor webhook data volume
SELECT FlowId, SUM(DataSize) as total_bytes
FROM PowerAutomateAuditLog
WHERE Operation = "FlowExecuted" 
  AND ActionType = "HTTP"
GROUP BY FlowId
HAVING total_bytes > 50000000; -- 50MB threshold
```

### Baseline Deviations
- Monitor for spikes in webhook creation events vs baseline
- Track increased data transfer volume to external endpoints
- Alert on new webhook endpoints never seen before
- Detect unusual times of webhook activity

### Technical Controls
```json
{
  "teamsWebhookPolicy": {
    "allowOutboundWebhooks": false,
    "allowedDomains": ["*.company.com"],
    "requireApproval": true
  },
  "powerAutomatePolicy": {
    "disableHttpConnector": true,
    "allowedHttpEndpoints": ["internal.company.com"]
  }
}
```

### Administrative Controls
1. Restrict webhook creation to approved users
2. Require business justification for external webhooks
3. Implement webhook allowlist policy
4. Regular review of webhook configurations
5. DLP policies for sensitive data

### Monitoring Controls
1. Alert on new webhook registrations
2. Monitor webhook data transfer volumes
3. Track failed webhook deliveries
4. Log webhook configuration changes
5. Alert on sensitive data in webhook payloads

## Response Playbook

### Detection
1. Review webhook audit logs
2. Identify suspicious endpoints
3. Check data volumes transferred
4. Analyze webhook creation patterns

### Investigation  
1. Map affected systems/data
2. Review webhook configurations
3. Analyze webhook traffic patterns
4. Identify compromised accounts

### Containment
1. Disable suspicious webhooks
2. Block malicious endpoints
3. Revoke compromised credentials
4. Implement stricter webhook policies

## References
- MITRE: https://attack.mitre.org/techniques/T1567/004
- Microsoft Teams Security Guide
- Microsoft Power Automate Security Documentation
- SharePoint Online Security Best Practices

Let me know if you would like me to expand on any section or add more specific implementation details.

---

# Threat Model: Email Account Discovery (T1087.003) in Microsoft 365 & Entra ID

## Overview
Adversaries attempt to discover email accounts within Microsoft 365/Exchange Online by accessing global address lists (GAL), executing PowerShell cmdlets, or abusing Exchange Web Services (EWS) and Graph API endpoints.

## Attack Vectors

### 1. PowerShell Global Address List Enumeration
**Description**: Attacker uses PowerShell cmdlets like Get-GlobalAddressList to enumerate user email addresses.

**Real-world scenario**:
```powershell
Connect-ExchangeOnline
Get-GlobalAddressList | Select-Object Name, RecipientFilter
Get-Recipient -ResultSize Unlimited | Select-Object Name,EmailAddresses
```

**Relevant Audit Operations**:
- MailItemsAccessed
- Add-MailboxPermission 
- SendAs
- SendOnBehalf

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T10:15:22",
  "Operation": "MailItemsAccessed",
  "UserType": "Regular",
  "ClientIP": "192.168.1.100",
  "UserId": "john.smith@company.com",
  "ClientInfoString": "Microsoft Exchange PowerShell",
  "ResultStatus": "Succeeded",
  "MailboxGuid": "*",
  "MailboxOwnerUPN": "*",
  "LogonType": "Admin"
}
```

### 2. Exchange Web Services Address Book Access 
**Description**: Attacker uses EWS APIs to query address lists and contact folders.

**Audit Operations**:
- FileAccessed
- SearchQueryPerformed
- MessageRead

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T11:22:33",
  "Operation": "SearchQueryPerformed", 
  "ObjectId": "/address-book/gal",
  "UserId": "attacker@company.com",
  "ClientIP": "10.1.2.3",
  "ClientAppId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
  "ResultStatus": "Succeeded",
  "SearchQuery": "users?$select=mail,displayName"
}
```

### 3. Graph API Directory Enumeration
**Description**: Attacker abuses Microsoft Graph API permissions to list users.

**Audit Operations**:
- Add service principal
- Add service principal credentials
- DirectoryServicesAccountConfigurationUpdated

**Example Log**: 
```json
{
  "CreationTime": "2024-01-20T14:55:21",
  "Operation": "Add service principal",
  "ApplicationId": "a1b2c3d4-e5f6-g7h8-i9j0",
  "ServicePrincipalId": "sp_123456",
  "PermissionGrants": ["User.Read.All", "Directory.Read.All"],
  "Actor": "admin@company.com",
  "ActorIpAddress": "10.10.10.10"
}
```

## Detection Strategy

### Behavioral Analytics Rules
```sql
-- Detect excessive GAL queries
SELECT UserId, ClientIP, COUNT(*) as query_count
FROM AuditLogs 
WHERE Operation IN ('MailItemsAccessed', 'SearchQueryPerformed')
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 100;

-- Detect enumeration from new/suspicious IPs
SELECT UserId, ClientIP, Operation
FROM AuditLogs
WHERE Operation IN ('Add service principal', 'SearchQueryPerformed')
AND ClientIP NOT IN (SELECT IP FROM known_admin_ips)
AND TimeGenerated > ago(24h);
```

### Baseline Deviations
- Monitor for spikes in GAL queries vs historical baseline
- Track new IP addresses performing directory queries
- Alert on first-time PowerShell usage for GAL access

### Correlation Rules
- Link GAL queries with subsequent phishing/spam activity
- Correlate address book access with authentication events
- Monitor service principal creation followed by directory queries

## Mitigation Controls

### Administrative Controls
1. Implement strict RBAC for Exchange/Graph permissions
2. Require justification for directory access permissions
3. Regular access reviews for service principals

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "exchangeOnline": {
      "blockLegacyAuthentication": true,
      "requireMFA": true,
      "allowedLocations": ["corporate-networks"]
    },
    "graphAPI": {
      "applicationPermissions": {
        "restrictDirectoryAccess": true,
        "requireJustification": true
      }
    }
  }
}
```

### Monitoring Controls
1. Enable unified audit logging
2. Monitor Exchange admin audit logging
3. Track service principal permission changes
4. Alert on bulk directory queries

## Incident Response

### Initial Detection
1. Review unified audit logs for suspicious patterns
2. Identify source IPs and affected resources
3. Determine authentication methods used

### Investigation
1. Map timeline of directory access events
2. Review service principal configurations
3. Check for associated data exfiltration
4. Analyze PowerShell command history

### Containment
1. Revoke suspicious service principal credentials
2. Block malicious IP addresses
3. Enforce MFA for all directory access
4. Reset compromised account credentials

## References
- MITRE: https://attack.mitre.org/techniques/T1087/003/
- Microsoft: https://learn.microsoft.com/exchange/address-books/address-lists/address-lists
- Microsoft Graph Security: https://learn.microsoft.com/graph/security-concept-overview

---

# Threat Model: Use Alternate Authentication Material (T1550) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries can bypass authentication controls by stealing and reusing:
- OAuth access tokens 
- SAML tokens
- Session cookies
- Delegation/service principal credentials

## 2. Attack Vectors

### 2.1 Service Principal Credential Abuse

**Description:**
Adversaries add credentials to existing service principals to maintain persistent access and bypass MFA.

**Attack Scenario:**
1. Attacker compromises Global Admin account
2. Adds new credentials to high-privilege service principal 
3. Uses credentials to authenticate as service principal

**Detection Fields:**
```json
{
  "Operation": "Add service principal credentials.",
  "Actor": "[UPN]",
  "ActorIpAddress": "[IP]",
  "ServicePrincipalId": "[ID]",
  "KeyType": "Password/Certificate",
  "StartTime": "[Timestamp]"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "8721fb2c-657f-4c10-8648-0321cda89762",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "8b6fe9f1-035e-4bec-b9eb-176af6876321",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "8721fb2c-657f-4c10-8648-0321cda89762",
  "UserId": "admin@contoso.com",
  "AadAppId": "8721fb2c-657f-4c10-8648-0321cda89762",
  "ActorIpAddress": "192.168.1.100",
  "ActorUserType": "Admin",
  "KeyType": "Password"
}
```

### 2.2 OAuth Token Theft

**Description:**
Adversaries steal and reuse OAuth access tokens to maintain access without credentials.

**Attack Scenario:**
1. Attacker compromises user mailbox
2. Extracts OAuth tokens from email
3. Uses tokens to access resources

**Detection Fields:**
```json
{
  "Operation": "MailItemsAccessed", 
  "LogonType": "OAuth",
  "ClientInfoString": "[Client App]",
  "ClientIP": "[IP]",
  "UserId": "[UPN]"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "4a8cf1f0-ccb9-4379-9578-12bea7e69623",
  "Operation": "MailItemsAccessed",
  "OrganizationId": "8b6fe9f1-035e-4bec-b9eb-176af6876321", 
  "RecordType": 2,
  "ResultStatus": "Success",
  "UserKey": "victim@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "192.168.1.100",
  "ClientInfoString": "OAuth2:Graph API",
  "LogonType": "OAuth",
  "MailboxGuid": "4a8cf1f0-ccb9-4379-9578-12bea7e69623"
}
```

### 2.3 Delegation Permission Abuse

**Description:**
Adversaries add delegation permissions to maintain access to resources.

**Attack Scenario:**
1. Attacker compromises admin account
2. Adds mail delegation permissions
3. Uses delegated access to access mailboxes

**Detection Fields:**
```json
{
  "Operation": "Add delegation entry.",
  "ObjectId": "[Target ID]",
  "UserId": "[Actor UPN]",
  "ActorIpAddress": "[IP]",
  "DelegationType": "[Permission Type]"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "4a8cf1f0-ccb9-4379-9578-12bea7e69623",
  "Operation": "Add delegation entry.",
  "OrganizationId": "8b6fe9f1-035e-4bec-b9eb-176af6876321",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "admin@contoso.com",
  "ObjectId": "victim@contoso.com",
  "UserId": "admin@contoso.com",
  "ActorIpAddress": "192.168.1.100",
  "DelegationType": "FullAccess"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect sudden spike in service principal credential additions
SELECT COUNT(*) as count, ActorIpAddress, Actor
FROM AuditLogs 
WHERE Operation = "Add service principal credentials."
AND Timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY ActorIpAddress, Actor
HAVING count > 3;

-- Detect OAuth token reuse across IPs
SELECT COUNT(DISTINCT ClientIP) as ip_count, UserId
FROM AuditLogs
WHERE Operation = "MailItemsAccessed" 
AND LogonType = "OAuth"
AND Timestamp > NOW() - INTERVAL 24 HOUR
GROUP BY UserId
HAVING ip_count > 5;
```

### 3.2 Baseline Deviation Monitoring

- Monitor for abnormal patterns:
  - Service principal credential additions outside business hours
  - Delegation permissions added to sensitive mailboxes
  - OAuth tokens used from new locations/devices

### 3.3 Risk Scoring

```python
risk_score = 0

if operation == "Add service principal credentials.":
    risk_score += 40
if actor_ip not in known_admin_ips:
    risk_score += 30
if time_of_day not in business_hours:
    risk_score += 20
if target_object in sensitive_accounts:
    risk_score += 50
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement just-in-time access for admin accounts
- Require MFA for all service principal credential management
- Regular review of delegation permissions
- Monitor service principal credential expiration

### Technical Controls
```json
{
  "ConditionalAccessPolicies": {
    "ServicePrincipalCredentials": {
      "RequireMFA": true,
      "AllowedLocations": ["corporate networks"],
      "AllowedTimes": ["business hours"]
    },
    "DelegatedPermissions": {
      "RequireApproval": true,
      "MaxDurationDays": 30,
      "AllowedDelegates": ["approved admins"]
    }
  }
}
```

### Monitoring Controls
- Real-time alerts on service principal credential additions
- Daily reports of new delegation permissions
- OAuth token usage analysis
- Service principal secret rotation monitoring

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected identities and resources
2. Collect all relevant audit logs
3. Document timeline of credential/token additions

### Investigation
1. Review authentication patterns 
2. Map lateral movement attempts
3. Identify compromised credentials
4. Analyze service principal permissions

### Containment
1. Revoke suspicious service principal credentials
2. Remove unauthorized delegation permissions  
3. Force token refresh for affected users
4. Block suspicious IPs/locations

## 6. References

- [MITRE ATT&CK T1550](https://attack.mitre.org/techniques/T1550)
- [Microsoft Service Principal Security](https://docs.microsoft.com/azure/active-directory/develop/app-objects-and-service-principals)
- [OAuth Best Practices](https://docs.microsoft.com/azure/active-directory/develop/security-best-practices-for-app-registration)

---

# Threat Model: Hybrid Identity (T1556.007) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries compromising or manipulating hybrid identity components to bypass authentication and gain persistent access. Primary attack targets include:

- Azure AD Connect with Password Hash Sync (PHS)
- Pass-through Authentication (PTA) agents
- AD FS infrastructure 
- Federation trust relationships

## 2. Attack Vectors

### 2.1 Malicious PTA Agent Registration

**Description:**
Adversary registers an unauthorized PTA agent using compromised Global Admin credentials to intercept authentication attempts.

**Audit Fields to Monitor:**
```json
{
  "Operation": "Add service principal.",
  "ObjectId": "PTA_Agent_ServicePrincipal",
  "ResultStatus": "Success",
  "ActorIpAddress": "<ip>",
  "ActorUPN": "<admin_upn>",
  "TargetResources": [{
    "Type": "ServicePrincipal",
    "Name": "Azure AD Connect Authentication Agent"
  }]
}
```

### 2.2 Federation Trust Modification 

**Description:**
Adversary modifies existing federation trust settings to add malicious token signing certificates.

**Audit Fields to Monitor:**
```json
{
  "Operation": "Set federation settings on domain.",
  "ObjectId": "<domain_name>",  
  "ModifiedProperties": [{
    "Name": "IssuerUri",
    "NewValue": "<new_issuer>"
  },{
    "Name": "SigningCertificate", 
    "NewValue": "<cert_thumbprint>"
  }]
}
```

### 2.3 Azure AD Connect Credential Theft

**Description:**
Adversary extracts Azure AD Connect sync account credentials from on-premises servers.

**Audit Fields to Monitor:**
```json
{
  "Operation": "Set DirSyncEnabled flag.",
  "ObjectId": "Sync_Account",
  "ResultStatus": "Success", 
  "ModifiedProperties": [{
    "Name": "PasswordHash",
    "NewValue": "[Modified]"
  }]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect new PTA agent registration from unusual location
SELECT *
FROM AuditLogs 
WHERE Operation = "Add service principal"
AND TargetResources.Type = "ServicePrincipal" 
AND TargetResources.Name = "Azure AD Connect Authentication Agent"
AND ActorIpAddress NOT IN (SELECT TrustedIP FROM KnownLocations)

-- Alert on federation trust changes
SELECT * 
FROM AuditLogs
WHERE Operation = "Set federation settings on domain"
AND ModifiedProperties.Name IN ("IssuerUri", "SigningCertificate")
```

### 3.2 Baseline Monitoring

- Monitor baseline number of PTA agents per tenant
- Track normal federation configuration change patterns
- Establish baseline for sync account authentication locations

## 4. Controls 

### Administrative Controls
```json
{
  "RequiredControls": {
    "PTA": {
      "RestrictAgentRegistration": true,
      "RequireApproval": true,
      "AllowedLocations": ["<ip_ranges>"]
    },
    "Federation": {
      "RestrictTrustModification": true,
      "EnforceMFA": true
    }
  }
}
```

### Technical Controls
```json
{
  "ConditionalAccess": {
    "SyncAccounts": {
      "RequireMFA": true,
      "AllowedLocations": ["<data_centers>"],
      "BlockLegacyAuth": true
    },
    "FederationManagement": {
      "RequirePrivilegedAccess": true,
      "RequirePAWWorkstation": true
    }
  }
}
```

## 5. Incident Response

### Initial Detection
1. Identify unauthorized PTA agents
2. Review federation trust changes
3. Check sync account access patterns

### Investigation
1. Correlate admin activities around time of changes
2. Review authentication logs for impacted identities  
3. Analyze on-premises logs for related activity

### Containment
1. Disable suspect PTA agents
2. Revert unauthorized federation changes
3. Reset compromised credentials
4. Block malicious IPs/locations

## 6. References

- [Azure AD Connect Security](https://docs.microsoft.com/azure/active-directory/hybrid/reference-connect-security)
- [MITRE T1556.007](https://attack.mitre.org/techniques/T1556/007/)
- [Federation Trust Security](https://docs.microsoft.com/azure/active-directory/hybrid/whatis-fed)

---

# Threat Model: Cloud API (T1059.009) in Microsoft 365 & Entra ID

## 1. Technique Overview 
Cloud API abuse in Microsoft 365 and Entra ID involves adversaries leveraging legitimate API interfaces to execute malicious commands through:
- Microsoft Graph API
- Azure PowerShell modules
- Azure Cloud Shell
- Microsoft 365 Management API

## 2. Attack Vectors

### 2.1 Service Principal Token Abuse
**Description**: Adversaries create malicious service principals or steal existing tokens to make API calls

**Scenario**: Attacker compromises service principal credentials and uses Microsoft Graph API to enumerate users and exfiltrate data

**Relevant Audit Operations**:
```json
{
  "Add service principal.",
  "Add service principal credentials.",
  "Remove service principal.",
  "Set delegation entry."
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "8932d4aa-1234-5678-90ab-cd1234567890",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "12ab34cd-5678-90ef-ghij-klmnopqrstuv",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "10.10.10.10",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "ServicePrincipal_12345",
  "UserId": "admin@contoso.com",
  "ClientIP": "10.10.10.10",
  "UserAgent": "Mozilla/5.0..."
}
```

### 2.2 Graph API Permission Escalation  
**Description**: Adversaries exploit overly permissive Graph API application permissions to elevate privileges

**Scenario**: Attacker modifies application permissions to gain admin access

**Relevant Audit Operations**:
```json
{
  "Add delegation entry.",
  "Set delegation entry.",
  "Add member to role."
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22", 
  "Operation": "Add delegation entry.",
  "TargetResources": [{
    "Type": "ServicePrincipal",
    "Id": "1234-5678-90ab",
    "ModifiedProperties": [{
      "Name": "AppRole",
      "NewValue": "Directory.ReadWrite.All"
    }]
  }],
  "InitiatedBy": {
    "User": {
      "Id": "admin@contoso.com"  
    }
  }
}
```

### 2.3 PowerShell Module Abuse
**Description**: Adversaries leverage Azure PowerShell modules to execute commands

**Scenario**: Attacker uses Az PowerShell modules to run commands with elevated privileges

**Relevant Audit Operations**:
```json
{
  "RunLiveResponseApi",
  "RunLiveResponseSession",
  "Add member to role."
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:08:33",
  "Operation": "RunLiveResponseSession",
  "RecordType": 15,
  "UserType": 0,
  "ClientIP": "10.10.10.10", 
  "UserId": "admin@contoso.com",
  "ObjectId": "PowerShell_Session_12345"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect suspicious service principal creation followed by permission changes
SELECT sp.CreationTime, sp.Operation, perm.Operation
FROM AuditLogs sp
JOIN AuditLogs perm ON sp.ObjectId = perm.ObjectId
WHERE sp.Operation = 'Add service principal.'
AND perm.Operation = 'Add delegation entry.'
AND DATEDIFF(minute, sp.CreationTime, perm.CreationTime) < 5
```

### 3.2 Baseline Deviation Monitoring
- Track normal API usage patterns per identity:
  - Average daily API calls
  - Common operations performed
  - Typical working hours
- Alert on deviations:
  - >25% increase in API call volume
  - Operations outside normal pattern
  - Activity outside business hours

### 3.3 Real-time Correlation Rules
```sql
-- Alert on privilege escalation attempts
SELECT UserId, COUNT(*) as attempts
FROM AuditLogs 
WHERE Operation IN (
  'Add delegation entry.',
  'Add member to role.',
  'Set delegation entry.'
)
GROUP BY UserId 
HAVING COUNT(*) > 3
AND DATEDIFF(minute, MIN(CreationTime), MAX(CreationTime)) < 10
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement least privilege access
- Regular access reviews
- Enforce MFA for API access
- Monitor service principal credentials

### Technical Controls
```json
{
  "ConditionalAccessPolicies": {
    "ApiAccess": {
      "RequireMFA": true,
      "BlockLegacyAuth": true,
      "AllowedLocations": ["Corporate Network"],
      "RequireCompliantDevice": true
    }
  },
  "ServicePrincipalSettings": {
    "RequireUserAssignment": true,
    "RestrictedPermissionGrants": true,
    "ExpirationTimeRequired": true
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Monitor service principal creation
- Track permission changes
- Alert on suspicious API patterns

## 5. Incident Response

### Initial Detection
1. Review unified audit logs
2. Identify affected service principals
3. Check permission changes
4. Analyze API call patterns

### Investigation
1. Map timeline of events
2. Review all affected resources
3. Identify compromise scope
4. Document attack chain

### Containment
1. Revoke compromised credentials
2. Remove malicious permissions
3. Block suspicious IPs
4. Reset affected accounts

## 6. References

- [MITRE ATT&CK - T1059.009](https://attack.mitre.org/techniques/T1059/009/)
- [Microsoft Graph Security API](https://docs.microsoft.com/graph/security-concept-overview)
- [Azure PowerShell Security](https://docs.microsoft.com/powershell/azure/security)
- [Microsoft Cloud App Security](https://docs.microsoft.com/cloud-app-security/)

---

# Threat Model: Default Accounts (T1078.001) in Microsoft 365 & Entra ID

## Overview
Default accounts in Microsoft 365 and Entra ID include built-in service accounts, admin accounts created during tenant setup, and default application service principals. Adversaries may target these accounts due to their predictable names and elevated privileges.

## Attack Vectors

### 1. Default Service Principal Abuse
**Description**: Adversaries exploit default service principals created during app registrations or system integrations.

**Attack Scenario**:
- Attacker identifies default service principal name pattern (e.g. "Microsoft Graph")
- Exploits misconfigured permissions or credentials to access service principal
- Adds new credentials to maintain persistence

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
  "CreationTime": "2024-01-20T15:22:33",
  "Id": "4a21498b-1234-5678-90ab-cd1234567890",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "84c31ca0-1234-5678-90ab-cd1234567890",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "10032001@contoso.com",
  "UserType": 0,
  "ObjectId": "4f4c2057-1234-5678-90ab-cd1234567890",
  "AppId": "00000003-0000-0000-c000-000000000000",
  "AdditionalDetails": [
    {"key": "CredentialType", "value": "Certificate"},
    {"key": "KeyId", "value": "bc87c142-1234-5678-90ab-cd1234567890"}
  ]
}
```

### 2. Built-in Admin Account Takeover
**Description**: Targeting of default Global Administrator account created during tenant setup.

**Attack Scenario**:
- Attacker identifies default admin account pattern
- Attempts password spray or credential stuffing
- Modifies MFA settings to maintain access

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Change user password.",
    "Reset user password.", 
    "Update user.",
    "UserLoggedIn"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:33:44",
  "Id": "8b123456-1234-5678-90ab-cd1234567890", 
  "Operation": "Change user password.",
  "UserId": "admin@contoso.onmicrosoft.com",
  "UserKey": "1003200",
  "UserType": 0,
  "ResultStatus": "Success",
  "ClientIP": "198.51.100.1",
  "ExtendedProperties": [
    {"Name": "TargetUserOrGroupType", "Value": "User"},
    {"Name": "TargetUserOrGroupName", "Value": "admin@contoso.onmicrosoft.com"}
  ]
}
```

### 3. Default App Registration Exploitation
**Description**: Abuse of default app registrations and their associated service principals.

**Attack Scenario**:
- Identifies default app registrations (e.g. "Azure Portal")
- Adds malicious redirect URIs
- Uses redirect to intercept auth tokens

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Add delegation entry.",
    "Set delegation entry.",
    "Update application." 
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:44:55",
  "Id": "7c654321-1234-5678-90ab-cd1234567890",
  "Operation": "Update application.",
  "OrganizationId": "84c31ca0-1234-5678-90ab-cd1234567890", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001@contoso.com",
  "ObjectId": "2a4b6c8d-1234-5678-90ab-cd1234567890",
  "ModifiedProperties": [
    {
      "Name": "RedirectUris",
      "NewValue": "[\"https://malicious.com/auth\"]",
      "OldValue": "[]"
    }
  ]
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect anomalous service principal credential additions
SELECT sp.DisplayName, COUNT(*) as credential_count
FROM AuditLogs 
WHERE Operation = "Add service principal credentials."
AND TimeGenerated > ago(1h)
GROUP BY sp.DisplayName
HAVING credential_count > 3;

-- Monitor default admin account activity outside business hours
SELECT UserId, ClientIP, Operation
FROM SignInLogs
WHERE UserId LIKE '%admin@%'
AND TimeGenerated NOT BETWEEN '0800' AND '1800'
AND ResultType = 'Success';
```

### Baseline Deviation Monitoring
- Track normal patterns of service principal credential management
- Monitor default admin account usage patterns
- Alert on deviations from established baselines

### Correlation Rules
```sql
-- Correlate password changes with suspicious IPs
SELECT a.UserId, a.ClientIP, a.Operation
FROM AuditLogs a
JOIN SignInLogs s ON a.UserId = s.UserId
WHERE a.Operation IN ('Change user password.', 'Reset user password.')
AND s.RiskLevel = 'high'
AND a.TimeGenerated BETWEEN s.TimeGenerated AND dateadd(minute,5,s.TimeGenerated);
```

## Mitigation Strategies

### Administrative Controls
1. Implement custom admin roles instead of using built-in Global Admin
2. Require PIM/JIT for privileged role activation
3. Regular review of service principal permissions and credentials

### Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Restrict Default Admin Access",
    "Conditions": {
      "Users": ["admin@domain.com"],
      "Applications": ["All"],
      "Locations": ["All"],
      "Controls": {
        "RequireMFA": true,
        "AllowedLocations": ["Corporate Network"],
        "SessionControls": {
          "SignInFrequency": "1 hour",
          "PersistentBrowser": "never"
        }
      }
    }
  }
}
```

### Monitoring Controls
1. Enable auditing for all service principal modifications
2. Configure alerts for default account usage patterns
3. Monitor service principal credential lifecycle

## Incident Response Playbook

### Initial Detection
1. Review audit logs for affected account/principal
2. Determine authentication patterns and source IPs
3. Identify any credential or permission changes

### Investigation
1. Map timeline of account activity
2. Review all associated service principals and permissions
3. Check for additional compromised accounts
4. Analyze authentication methods used

### Containment
1. Disable suspected compromised accounts
2. Revoke active sessions and tokens
3. Reset credentials and remove suspicious additions
4. Implement additional access restrictions

## References
- [Microsoft Entra ID Built-in Roles](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference)
- [Service Principal Security](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
- [MITRE T1078.001](https://attack.mitre.org/techniques/T1078/001/)

---

# Threat Model: Abuse Elevation Control Mechanism (T1548) in Microsoft 365 & Entra ID

## 1. Overview
In Microsoft 365 and Entra ID environments, adversaries can abuse built-in elevation mechanisms to gain higher privileges through:
- Service principal credential manipulation 
- Role assignment modifications
- Privileged authentication manipulation

## 2. Attack Vectors

### 2.1 Service Principal Credential Abuse
**Description**: Adversaries add credentials to existing service principals to maintain privileged access.

**Attack Scenario**:
1. Attacker compromises Global Admin account
2. Adds new credentials to existing privileged service principal 
3. Uses new credentials to maintain persistent admin access

**Detection Fields**:
```json
{
  "Operation": "Add service principal credentials",
  "ObjectId": "[ServicePrincipalId]",
  "ResultStatus": "Success",
  "ActorId": "[ActorUPN]",
  "CredentialType": "Password" 
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T15:23:44", 
  "Id": "8382d091-9665-4e90-b9c8-56d4e21b6d",
  "Operation": "Add service principal credentials",
  "OrganizationId": "12a34567-89b0-12d3-e456-789012345678",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "s8f7e654-32b1-0c9a-8d76-543210fedcba",
  "UserId": "admin@contoso.com",
  "CredentialType": "Password",
  "AppId": "a1b2c3d4-e5f6-g7h8-i9j0-k9l8m7n6o5p4"
}
```

### 2.2 Role Assignment Manipulation
**Description**: Adversaries modify role assignments to escalate privileges.

**Attack Scenario**:
1. Attacker compromises privileged account
2. Adds themselves to Global Admin role
3. Uses elevated access to compromise additional resources

**Detection Fields**:
```json
{
  "Operation": "Add member to role",
  "RoleName": "Global Administrator", 
  "TargetUserOrGroupName": "[Target]",
  "ActorUPN": "[Actor]",
  "Result": "Success"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T16:42:11",
  "Id": "9874d123-8776-4590-c8b7-45d3e12a5d67", 
  "Operation": "Add member to role",
  "OrganizationId": "12a34567-89b0-12d3-e456-789012345678",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "RoleName": "Global Administrator",
  "TargetUserOrGroupName": "attacker@contoso.com",
  "ActorUPN": "compromised.admin@contoso.com"
}
```

### 2.3 Privileged Authentication Manipulation
**Description**: Adversaries modify authentication settings to bypass controls.

**Attack Scenario**: 
1. Attacker gains admin access
2. Disables MFA requirements for privileged roles
3. Uses compromised credentials without MFA

**Detection Fields**:
```json
{
  "Operation": "UpdatedAuthenticationPolicy",
  "ModifiedProperties": ["MFARequired"],
  "ObjectId": "[PolicyId]",
  "ActorUPN": "[Actor]"
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T17:15:33",
  "Id": "7123e982-5446-4990-a7c6-34d2e13b4d56",
  "Operation": "UpdatedAuthenticationPolicy", 
  "OrganizationId": "12a34567-89b0-12d3-e456-789012345678",
  "RecordType": 8,
  "ResultStatus": "Success",
  "ObjectId": "p9o8i7u6-y5t4-r3e2-w1q0-987654321012",
  "ModifiedProperties": [
    {
      "Name": "MFARequired",
      "OldValue": "True",
      "NewValue": "False"
    }
  ],
  "ActorUPN": "attacker@contoso.com"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect rapid role assignment changes
SELECT ActorUPN, Operation, COUNT(*) as changes
FROM AuditLogs 
WHERE Operation = "Add member to role"
AND TimeGenerated > ago(1h)
GROUP BY ActorUPN, Operation
HAVING changes > 5

-- Alert on privileged service principal modifications
SELECT *
FROM AuditLogs
WHERE Operation in ("Add service principal credentials", "Add service principal")
AND ObjectId in (
  SELECT ObjectId 
  FROM ServicePrincipals
  WHERE AppRoleAssignments.RoleName in ("Global Administrator", "Privileged Role Administrator")
)
```

### 3.2 Baseline Deviation Monitoring
- Track normal patterns of role assignments per admin
- Alert on unusual spikes in privilege changes
- Monitor service principal credential additions outside business hours
- Detect abnormal authentication policy modifications

### 3.3 Correlation Rules
```sql
-- Correlate role changes with other suspicious activity
SELECT a.ActorUPN, a.Operation as role_change, b.Operation as auth_change
FROM AuditLogs a
JOIN AuditLogs b 
  ON a.ActorUPN = b.ActorUPN
  AND a.TimeGenerated BETWEEN b.TimeGenerated AND dateadd(hour,1,b.TimeGenerated)
WHERE a.Operation = "Add member to role"
AND b.Operation = "UpdatedAuthenticationPolicy"
```

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement Privileged Identity Management (PIM)
- Require approval for privileged role activation
- Enforce time-bound role assignments
- Regular access reviews for privileged roles

### 4.2 Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Require MFA for Privileged Roles",
    "State": "enabled",
    "Conditions": {
      "UserRiskLevels": ["low", "medium", "high"],
      "SignInRiskLevels": ["low", "medium", "high"],
      "Applications": {
        "IncludeApplications": ["All"]
      },
      "Users": {
        "IncludeRoles": [
          "Global Administrator",
          "Privileged Role Administrator",
          "Application Administrator"
        ]
      }
    },
    "GrantControls": {
      "BuiltInControls": ["mfa"]
    }
  }
}
```

### 4.3 Monitoring Controls
- Enable detailed auditing for role changes
- Monitor service principal credential management
- Alert on authentication policy modifications
- Track privileged role membership changes

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Review audit logs for role assignment changes
2. Check service principal credential modifications 
3. Analyze authentication policy alterations
4. Identify affected accounts and resources

### 5.2 Investigation
1. Document timeline of privilege escalation
2. Identify initial access vector
3. Review related authentication events
4. Map scope of compromise
5. Determine blast radius

### 5.3 Containment
1. Revoke compromised credentials
2. Remove unauthorized role assignments
3. Reset affected service principal secrets
4. Enable stricter authentication policies
5. Block suspicious actors

## 6. References
- [MITRE ATT&CK T1548](https://attack.mitre.org/techniques/T1548/)
- [Microsoft Service Principal Security](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
- [Entra ID Privileged Role Management](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure)

---

# Threat Model: Password Spraying (T1110.003) in Microsoft 365 & Entra ID

## 1. Overview
Password spraying in Microsoft 365 and Entra ID environments typically targets authentication endpoints including:
- Azure AD Authentication endpoints (login.microsoftonline.com)
- Exchange Online (outlook.office365.com) 
- SharePoint Online
- Teams

The attack tries common passwords against many accounts to avoid triggering account lockout policies.

## 2. Attack Vectors

### Vector 1: Basic Authentication Endpoints
**Description**: Attacking legacy authentication endpoints that support basic authentication

**Scenario**: Attacker attempts to authenticate to Exchange Online using basic auth with common passwords

**Relevant Audit Operations**:
- MailboxLogin
- UserLoggedIn 
- UserLoggedOff

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T10:15:22",
  "Id": "44c4e932-dd1c-4125-b725-569d7a5691d2",
  "Operation": "MailboxLogin",
  "OrganizationId": "12345678-1234-1234-1234-123456789012",
  "RecordType": 2,
  "ResultStatus": "Failed",
  "UserKey": "john.smith@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "192.168.1.100",
  "AuthenticationType": "Basic",
  "LogonError": "InvalidPassword"
}
```

### Vector 2: Modern Authentication 
**Description**: Attacking OAuth-based authentication flows

**Scenario**: Attacker attempts OAuth authentication against multiple accounts using common enterprise passwords

**Relevant Audit Operations**:
- Add member to role
- Update user
- UserLoggedIn

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T10:15:30",
  "Id": "8af75cf7-df9b-4246-a435-49c607fd568d", 
  "Operation": "UserLoggedIn",
  "OrganizationId": "12345678-1234-1234-1234-123456789012",
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserKey": "sarah.jones@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "192.168.1.100",
  "AuthenticationProtocol": "OAuth2.0",
  "ErrorCode": "50126"
}
```

### Vector 3: Federated Authentication
**Description**: Attacking federated authentication endpoints 

**Scenario**: Attacker attempts to exploit ADFS endpoints with password spraying

**Relevant Audit Operations**:
- Set federation settings on domain
- Add domain to company
- UserLoggedIn

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T10:15:40",
  "Id": "92c58f3a-5c9d-42c7-b5e9-61c347a9e543",
  "Operation": "UserLoggedIn", 
  "OrganizationId": "12345678-1234-1234-1234-123456789012",
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserKey": "robert.wilson@company.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "192.168.1.100",
  "AuthenticationProtocol": "WsFed",
  "ErrorCode": "50126"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect authentication attempts from single IP to multiple accounts
SELECT ClientIP, COUNT(DISTINCT UserKey) as UniqueUsers, 
       COUNT(*) as TotalAttempts,
       SUM(CASE WHEN ResultStatus = 'Failed' THEN 1 ELSE 0 END) as FailedAttempts
FROM AuditLogs 
WHERE Operation IN ('UserLoggedIn', 'MailboxLogin')
  AND Timestamp > DATEADD(hour, -1, GETUTCDATE())
GROUP BY ClientIP
HAVING COUNT(DISTINCT UserKey) > 20
  AND SUM(CASE WHEN ResultStatus = 'Failed' THEN 1 ELSE 0 END) > 50;
```

### Baseline Deviation Monitoring
- Track normal authentication patterns per IP/location
- Alert on:
  - >25% increase in unique account attempts per hour
  - >40% failed authentication rate
  - Authentication attempts outside business hours
  - Geographic anomalies

### Correlation Rules
```sql
-- Detect sequential alphabetical account targeting
WITH LoginAttempts AS (
  SELECT UserKey, ClientIP, CreationTime,
         LAG(UserKey) OVER (PARTITION BY ClientIP ORDER BY CreationTime) as PrevUser
  FROM AuditLogs
  WHERE Operation = 'UserLoggedIn'
    AND ResultStatus = 'Failed'
)
SELECT ClientIP, COUNT(*) as SequentialAttempts
FROM LoginAttempts 
WHERE LOWER(UserKey) > LOWER(PrevUser)
GROUP BY ClientIP
HAVING COUNT(*) > 10;
```

## 4. Mitigation Strategies

### Administrative Controls
1. Enforce MFA for all accounts
2. Implement conditional access policies
3. Block legacy authentication 
4. Enable Azure AD Password Protection
5. Configure account lockout policies

### Technical Controls 
```json
{
  "conditionalAccessPolicy": {
    "name": "Block Legacy Authentication",
    "state": "enabled",
    "conditions": {
      "clientAppTypes": ["other"],
      "applications": {"includeAllApps": true}
    },
    "grantControls": {"operator": "OR", "builtInControls": ["block"]}
  },
  "passwordPolicy": {
    "minimumLength": 12,
    "complexityEnabled": true,
    "lockoutThreshold": 10,
    "lockoutDurationMinutes": 30
  }
}
```

### Monitoring Controls
1. Enable unified audit logging
2. Configure Azure AD Identity Protection
3. Enable Azure AD sign-in risk policies
4. Set up alerts for suspicious sign-in patterns
5. Monitor service principal authentication

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected accounts
2. Review authentication logs for patterns
3. Determine attack source IPs
4. Assess successful compromises

### Investigation
1. Review audit logs for post-compromise activity
2. Check for mailbox rules and forwarding
3. Search for new service principals/app registrations
4. Examine conditional access policy changes

### Containment
1. Force password reset for affected accounts
2. Enable MFA
3. Block suspicious IPs
4. Revoke refresh tokens
5. Review and update conditional access policies

## 6. References
- [MITRE ATT&CK T1110.003](https://attack.mitre.org/techniques/T1110/003/)
- [Microsoft Identity Security](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/)
- [Azure AD Sign-in Logs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-sign-ins)

---

# Threat Model: Temporary Elevated Cloud Access (T1548.005) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries abusing temporary elevation mechanisms in M365/Entra ID to gain unauthorized privileged access, including:

- Just-in-Time (JIT) access requests
- Application/service principal impersonation  
- Exchange delegation permissions
- Resource role assumption

## 2. Attack Vectors

### 2.1 Exchange Application Impersonation

**Description:**
Adversaries abuse Exchange ApplicationImpersonation role to gain temporary access to mailboxes.

**Attack Scenario:**
1. Attacker compromises admin account
2. Adds ApplicationImpersonation role to malicious service principal
3. Uses service principal to access target mailboxes

**Detection Fields:**
```json
{
  "Operation": "Add-MailboxPermission",
  "ObjectId": "ServicePrincipal_ID", 
  "Parameters": {
    "Identity": "target@domain.com",
    "AccessRights": ["FullAccess"],
    "InheritanceType": "All"
  },
  "ResultStatus": "Success"
}
```

### 2.2 Service Principal Credential Abuse

**Description:** 
Adversaries add credentials to existing service principals to gain temporary elevated access.

**Attack Scenario:**
1. Attacker compromises Global Admin
2. Adds credentials to high-privilege service principal
3. Uses credentials to access resources

**Detection Fields:**
```json
{
  "Operation": "Add service principal credentials.",
  "ObjectId": "ServicePrincipal_ID",
  "ModifiedProperties": [
    {
      "Name": "KeyDescription",
      "NewValue": ["New client secret added"]
    }
  ],
  "ActorIpAddress": "1.2.3.4"
}
```

### 2.3 Delegation Permission Changes

**Description:**
Adversaries modify delegation permissions to enable temporary access elevation.

**Detection Fields:**
```json
{
  "Operation": "Add delegation entry.",
  "ObjectId": "Application_ID",
  "ModifiedProperties": [
    {
      "Name": "DelegatedPermissionGrants", 
      "NewValue": ["Mail.Read", "Mail.Send"]
    }
  ],
  "ActorUPN": "admin@domain.com"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect rapid permission changes
SELECT ActorUPN, Operation, COUNT(*) as changes
FROM AuditLogs 
WHERE Operation IN ('Add delegation entry.', 'Add service principal credentials.')
  AND TimeGenerated > ago(1h)
GROUP BY ActorUPN, Operation
HAVING COUNT(*) > 10

-- Alert on new application impersonation
SELECT *
FROM AuditLogs
WHERE Operation = 'Add-MailboxPermission' 
  AND Parameters.AccessRights CONTAINS 'ApplicationImpersonation'
```

### 3.2 Baseline Monitoring

- Track normal patterns of:
  - Service principal credential additions per day
  - Delegation permission changes per admin
  - Application impersonation grant frequency
  - Time windows of elevation requests

### 3.3 Correlation Rules

```json
{
  "name": "Suspicious Elevation Chain",
  "description": "Detects elevation followed by sensitive operations",
  "query": "
    let elevation = AuditLogs
    | where Operation in ('Add delegation entry.', 'Add service principal credentials.');
    let sensitive = AuditLogs  
    | where Operation in ('MailItemsAccessed', 'FileDownloaded');
    elevation 
    | join kind=inner sensitive on $left.ActorUPN == $right.ActorUPN
    | where sensitive.TimeGenerated between(elevation.TimeGenerated .. 1h)
  "
}
```

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement approval workflows for elevation requests
- Document legitimate elevation use cases
- Regular access reviews of service principals
- Just-in-Time access policies

### 4.2 Technical Controls

```json
{
  "conditional_access": {
    "name": "Block High-Risk Elevation",
    "conditions": {
      "users": ["All"],
      "applications": ["ServicePrincipals", "Exchange"],
      "controls": [
        "Block when risk level = high",
        "Require MFA",
        "Device must be compliant"
      ]
    }
  }
}
```

### 4.3 Monitoring Controls
- Alert on:
  - New service principal credential adds
  - Application impersonation role grants
  - Delegation permission changes 
  - Elevation requests outside business hours

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Identify affected identities/resources
2. Document timeline of elevation events
3. Determine method of elevation

### 5.2 Investigation
1. Review audit logs for:
   - Associated credential adds
   - Permission changes
   - Resource access
2. Map attack chain
3. Identify compromised accounts

### 5.3 Containment
1. Remove malicious credentials
2. Revoke temporary access
3. Reset affected service principals
4. Block suspicious IPs/accounts
5. Enable stricter conditional access

## 6. References

- MITRE: https://attack.mitre.org/techniques/T1548/005/
- Microsoft: 
  - https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/
  - https://docs.microsoft.com/en-us/exchange/permissions/

This detailed model focuses on Microsoft 365/Entra ID specific implementations while providing actionable detection and response guidance.

Let me know if you would like me to expand on any particular section.

---

# Threat Model: Account Discovery (T1087) in Microsoft 365 & Entra ID

## Overview
In Microsoft 365 and Entra ID environments, adversaries attempt to enumerate valid accounts using legitimate admin interfaces, PowerShell modules, and API calls. This helps identify targets for further attacks like password spraying or phishing.

## Attack Vectors

### 1. PowerShell Enumeration Using Microsoft.Graph Module
**Description**: Adversaries use PowerShell with Microsoft Graph API to list users and roles
**Attack Scenario**: Attacker with compromised admin credentials runs `Get-MgUser` to dump user directory

**Detection Fields**:
- Operation: "User added" 
- RecordType: AuditLogRecordType.AzureActiveDirectory
- Application: "Microsoft Graph PowerShell"
- CommandName: "Get-MgUser", "Get-MgDirectoryRole"

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "UserId": "john.smith@company.com",
  "Operation": "User Query Executed", 
  "RecordType": "AzureActiveDirectory",
  "AppDisplayName": "Microsoft Graph PowerShell",
  "CommandName": "Get-MgUser",
  "ResultCount": 500,
  "ClientIP": "192.168.1.100"
}
```

### 2. Admin Portal User Enumeration 
**Description**: Use of Microsoft 365 Admin Portal to browse users and groups
**Attack Scenario**: Attacker accesses admin portal to manually browse directory

**Detection Fields**:
- Operation: "User viewed"
- Portal: "Microsoft 365 Admin Portal"
- ItemType: "User", "Group"
- SearchQuery: Present

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Operation": "UserViewed",
  "Portal": "Microsoft 365 Admin Portal",
  "ItemType": "User",  
  "SearchQuery": "*",
  "UserId": "admin@company.com",
  "ClientIP": "10.10.10.50"
}
```

### 3. Microsoft Graph API Directory Queries
**Description**: Direct API calls to enumerate directory objects
**Attack Scenario**: Automated script using access token to query Graph API

**Detection Fields**:
- Operation: "List users API called"
- Application: "Microsoft Graph API"
- ResourceUrl: "/users", "/groups"
- ResultCount: Number of records returned

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T17:05:11",
  "Operation": "List users API called",
  "Application": "Microsoft Graph API",
  "ResourceUrl": "/v1.0/users",
  "ResultCount": 1000,
  "ClientId": "a7d9f6e2-1b5c-4d8e-9c3a-2f5d8e1b9a4c",
  "ClientIP": "172.16.5.25"
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect high volume user enumeration
SELECT UserId, Operation, COUNT(*) as QueryCount
FROM AuditLogs 
WHERE TimeGenerated > ago(1h)
AND Operation IN ('User Query Executed', 'UserViewed')
GROUP BY UserId, Operation
HAVING COUNT(*) > 100

-- Detect enumeration from new IP addresses
SELECT ClientIP, Operation
FROM AuditLogs
WHERE TimeGenerated > ago(24h)
AND Operation LIKE '%User%'
AND ClientIP NOT IN (
  SELECT DISTINCT ClientIP 
  FROM AuditLogs 
  WHERE TimeGenerated BETWEEN ago(30d) AND ago(24h)
)
```

### Baseline Deviation Monitoring
- Track normal daily patterns of directory queries per admin
- Alert on >2 standard deviations from baseline
- Monitor for queries outside normal business hours
- Track typical result set sizes and alert on anomalies

### Correlation Rules
- Link directory queries to subsequent password spraying attempts
- Correlate enumeration with new external IP addresses
- Match enumeration with suspicious sign-in patterns

## Mitigation Strategies

### Administrative Controls
1. Implement JIT/PIM for admin access
2. Require MFA for all directory queries
3. Limit number of global admin accounts
4. Regular access reviews

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "conditions": {
      "applications": {
        "includeApplications": ["Microsoft Graph API"]
      },
      "users": {
        "includeRoles": ["Global Administrator", "User Administrator"]
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
1. Enable unified audit logging
2. Monitor Graph API usage 
3. Track PowerShell command execution
4. Alert on bulk directory operations

## Incident Response Playbook

### Initial Detection
1. Identify source IP and user account
2. Determine query patterns and volume
3. Check for related suspicious activities

### Investigation
1. Review historical activity from source
2. Check for credential compromise indicators
3. Analyze query patterns and targeted data
4. Review Azure AD sign-in logs

### Containment
1. Block source IP if external
2. Revoke suspicious access tokens
3. Reset compromised credentials
4. Enable stricter authentication controls

## References
- [MITRE ATT&CK T1087](https://attack.mitre.org/techniques/T1087/)
- [Microsoft Graph Security API](https://docs.microsoft.com/graph/security-concept-overview)
- [Azure AD Audit Log Schema](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities)

---

# Threat Model: Command and Scripting Interpreter (T1059) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries can abuse various scripting interfaces to execute malicious commands, particularly through:
- PowerShell cmdlets for Microsoft 365/Entra ID administration
- Microsoft Graph API calls
- Azure Cloud Shell
- Custom applications using delegated permissions

## 2. Attack Vectors

### 2.1 PowerShell Command Execution

**Description**: Adversaries use PowerShell to execute commands against M365/Entra ID services using stolen admin credentials or access tokens.

**Attack Scenario**: 
- Attacker obtains Global Admin credentials
- Uses Connect-AzureAD and Exchange Online PowerShell modules
- Executes commands to manipulate user accounts and permissions

**Detection Fields**:
```json
{
  "Operation": "Add service principal credentials",
  "ApplicationId": "string",
  "ClientAppId": "string", 
  "UserId": "string",
  "CommandName": "string",
  "PowerShellVersion": "string",
  "ResultStatus": "string"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "18279f40-981d-4296-8aba-423b219f8abc",
  "Operation": "Add service principal credentials",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "40.91.222.212",
  "ObjectId": "8c267015-99db-4321-9a99-f74c508f276c",
  "UserId": "admin@contoso.com",
  "ApplicationId": "1b730954-1685-4b74-9bfd-dac224a7b894",
  "ClientAppId": "Microsoft Azure PowerShell",
  "CommandName": "New-AzureADServicePrincipalKeyCredential"
}
```

### 2.2 Graph API Abuse

**Description**: Attackers utilize Microsoft Graph API calls to programmatically execute commands.

**Attack Scenario**:
- Attacker creates malicious application registration
- Grants application high-privilege API permissions
- Uses access tokens to make Graph API calls

**Detection Fields**:
```json
{
  "Operation": "Add delegation entry",
  "ApplicationId": "string",
  "ResourceId": "string",
  "TargetResources": [
    {
      "Type": "string",
      "Id": "string",
      "ModifiedProperties": []
    }
  ]
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T15:33:22",
  "Id": "457f8a22-5c82-4a6a-9864-0e7c1d429abc",
  "Operation": "Add delegation entry",
  "OrganizationId": "contoso.onmicrosoft.com", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "app@contoso.com",
  "UserType": 2,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "104.45.128.122",
  "ObjectId": "1b2a4567-1234-5678-abcd-1234567890ab",
  "ApplicationId": "df2f1cd2-8112-42bb-9f23-9cfaf1234567",
  "ResourceId": "Microsoft Graph",
  "TargetResources": [
    {
      "Type": "ServicePrincipal",
      "Id": "8b4a5c32-1234-5678-90ab-1234567890ab",
      "ModifiedProperties": [
        {
          "Name": "AppRole",
          "NewValue": "Directory.ReadWrite.All"
        }
      ]
    }
  ]
}
```

### 2.3 Cloud Shell Command Execution 

**Description**: Adversaries leverage Azure Cloud Shell to execute commands directly in the browser.

**Attack Scenario**:
- Attacker gains access to admin account
- Opens Cloud Shell in Azure portal
- Executes PowerShell/CLI commands

**Detection Fields**:
```json
{
  "Operation": "RunLiveResponseApi",
  "ApplicationName": "string",
  "CommandLine": "string",
  "Resource": "string",
  "ResultStatus": "string" 
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T18:44:12",
  "Id": "92c56318-76d4-42aa-9c7b-783d441aabc",
  "Operation": "RunLiveResponseApi",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 15,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzurePortal",
  "ClientIP": "40.91.222.212",
  "ApplicationName": "Azure Cloud Shell",
  "CommandLine": "Get-AzureADUser -All $true | Export-Csv users.csv",
  "Resource": "/subscriptions/12345678-90ab-cdef-1234-567890abcdef"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect high volume of PowerShell commands
SELECT UserId, COUNT(*) as cmd_count
FROM AuditLogs 
WHERE TimeGenerated > ago(1h)
AND ApplicationId IN ('Microsoft Azure PowerShell', 'Azure Cloud Shell')
GROUP BY UserId
HAVING COUNT(*) > 100

-- Alert on sensitive Graph API operations
SELECT *
FROM AuditLogs
WHERE Operation IN ('Add delegation entry', 'Add service principal credentials')
AND ApplicationId NOT IN (known_admin_tools)
```

### 3.2 Baseline Deviation Monitoring

- Track normal patterns of PowerShell/API usage per admin
- Alert on deviations > 2 standard deviations from baseline
- Monitor for off-hours command execution
- Track new IP addresses for admin operations

### 3.3 Technical Controls (JSON)

```json
{
  "conditionalAccessPolicies": {
    "adminAccess": {
      "users": "adminGroup",
      "applications": ["Azure PowerShell", "Graph API"],
      "conditions": {
        "locations": "namedLocations",
        "deviceStates": "compliant",
        "signInRisk": "low"
      },
      "grantControls": ["mfa", "compliantDevice"]
    }
  },
  "auditingSettings": {
    "retentionDays": 90,
    "operationsToAudit": [
      "Add service principal",
      "Add delegation entry",
      "RunLiveResponseApi"
    ]
  }
}
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement Privileged Identity Management (PIM) for just-in-time access
- Enforce MFA for all admin accounts
- Use Conditional Access to restrict admin access to trusted locations
- Regular review of service principal permissions

### Technical Controls
- Enable detailed auditing for PowerShell and Graph API operations
- Implement network restrictions for admin access
- Use client app restrictions in Conditional Access policies
- Enable Microsoft Defender for Cloud Apps policies

### Monitoring Controls
- Real-time alerts for suspicious command patterns
- Regular review of service principal credential additions
- Monitor for new application permissions grants
- Track admin activity outside business hours

## 5. Incident Response Playbook

1. Initial Detection
   - Identify source account and IP address
   - Review command history and operations performed
   - Check for related service principal or permission changes

2. Investigation
   - Pull full audit logs for affected time period
   - Review authentication logs for compromised account
   - Check for persistence mechanisms (new service principals, etc.)
   - Analyze scope of access and potential data exfiltration

3. Containment
   - Revoke suspicious service principal credentials
   - Reset affected admin account credentials
   - Remove malicious application permissions
   - Block suspicious IP addresses in Conditional Access

## 6. References

- [MITRE T1059](https://attack.mitre.org/techniques/T1059/)
- [Microsoft Graph Security API](https://docs.microsoft.com/graph/security-concept-overview)
- [Azure AD Audit Log Schema](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities)
- [PowerShell Security Features](https://docs.microsoft.com/powershell/scripting/security/security-features)

---

# Threat Model: Indicator Removal (T1070) in Microsoft 365 & Entra ID

## Overview
Adversaries attempt to delete or modify audit trails, logs, and other indicators of their activity within Microsoft 365 and Entra ID environments to evade detection and complicate forensics. This commonly involves tampering with audit logging settings, modifying retention policies, and deleting audit records.

## Attack Vectors

### 1. Disable Unified Audit Logging
**Description**: Adversaries with Global Administrator rights can disable unified audit logging to prevent the recording of their activities.

**Attack Scenario**:
- Attacker compromises Global Admin account
- Disables unified audit logging via PowerShell
- Performs malicious activities without generating logs
- Re-enables logging to avoid detection

**Detection Fields**:
```json
{
  "Operation": "Set-AdminAuditLogConfig",
  "Parameters": {
    "UnifiedAuditLogIngestionEnabled": "False"
  },
  "UserId": "admin@contoso.com",
  "ClientIP": "192.168.1.100"
}
```

### 2. Modify Retention Policies
**Description**: Attackers modify retention policies to purge audit logs and evidence prematurely.

**Detection Fields**:
```json
{
  "Operation": "Set-RetentionCompliancePolicy",
  "PolicyName": "Global Audit Log Policy", 
  "Parameters": {
    "RetentionDuration": "1",
    "RetentionAction": "Delete"
  },
  "ModifiedProperties": [
    {
      "Name": "RetentionDuration",
      "OldValue": "365",
      "NewValue": "1" 
    }
  ]
}
```

### 3. Purge eDiscovery Cases
**Description**: Adversaries delete eDiscovery cases and search results containing evidence of their activities.

**Detection Fields**:
```json
{
  "Operation": "Remove-ComplianceCase",
  "CaseName": "SecurityIncident-2024",
  "UserId": "admin@contoso.com",
  "ResultStatus": "Success",
  "ClientIP": "192.168.1.100",
  "Timestamp": "2024-01-20T15:30:00Z"
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect rapid deletion of multiple eDiscovery cases
SELECT UserId, COUNT(*) as delete_count
FROM UnifiedAuditLog 
WHERE Operation = 'Remove-ComplianceCase'
AND Timestamp > DATEADD(hour, -1, GETUTCDATE())
GROUP BY UserId
HAVING COUNT(*) > 5;

-- Alert on audit config changes outside business hours
SELECT * FROM UnifiedAuditLog
WHERE Operation = 'Set-AdminAuditLogConfig'
AND DATEPART(hour, Timestamp) NOT BETWEEN 9 AND 17;
```

### Baseline Deviation Monitoring
- Track normal patterns of retention policy modifications
- Alert on unusual spikes in case/search deletions
- Monitor for audit configuration changes outside change windows

### Correlation Rules
```json
{
  "name": "Potential Audit Log Tampering",
  "description": "Detects sequence of suspicious audit-related activities",
  "rule": {
    "timeWindow": "1h",
    "threshold": 3,
    "sequence": [
      "Set-AdminAuditLogConfig",
      "Remove-ComplianceCase",
      "Set-RetentionCompliancePolicy"
    ]
  }
}
```

## Mitigation Strategies

### Administrative Controls
1. Implement strict role-based access control for audit settings
2. Require MFA for all audit configuration changes
3. Document legitimate audit policy modifications in change management

### Technical Controls
```json
{
  "conditionalAccessPolicies": [
    {
      "name": "Audit Config Protection",
      "assignments": {
        "operations": ["Set-AdminAuditLogConfig", "Set-RetentionPolicy"],
        "users": ["Global Administrators"]
      },
      "conditions": {
        "requireMFA": true,
        "allowedLocations": ["Corporate Network"],
        "allowedTimes": ["0900-1700"]
      }
    }
  ]
}
```

### Monitoring Controls
1. Configure alerts for audit setting modifications
2. Enable out-of-band logging to a SIEM
3. Implement automated compliance checks for retention policies

## Incident Response Playbook

### Initial Detection
1. Identify source account and IP of audit changes
2. Review timeline of modifications
3. Document affected audit settings and policies

### Investigation
1. Review authentication logs for compromised accounts
2. Check for other suspicious activity from same source
3. Analyze changes to retention policies and eDiscovery cases

### Containment
1. Revoke sessions for suspicious accounts
2. Reset audit configurations to baseline
3. Restore required retention policies
4. Enable enhanced monitoring

## References
- [MITRE T1070](https://attack.mitre.org/techniques/T1070/)
- [Microsoft 365 Audit Log Search](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log)
- [Unified Audit Logging](https://docs.microsoft.com/en-us/microsoft-365/compliance/audit-log-retention-policies)

---

# Threat Model: Office Template Macros (T1137.001) in Microsoft 365 & Entra ID

## 1. Technique Overview

Office template macros represent a persistence mechanism where adversaries embed malicious VBA code into Office templates that execute when applications start. In Microsoft 365, this threat is amplified by:

- Cloud-synced templates via OneDrive for Business
- Shared templates in SharePoint document libraries 
- Enterprise-wide template deployment capabilities
- Integration with Microsoft 365 Apps management

## 2. Attack Vectors

### 2.1 OneDrive Template Sync

**Description:**
Adversaries modify local Office templates that sync to OneDrive, allowing the malicious macros to persist and spread across a user's devices.

**Detection Fields:**
```json
{
  "Operation": "FileModified",
  "SourceFileName": "Normal.dotm",
  "SourceFileExtension": "dotm",
  "SourceFilePath": "/personal/user_domain_com/Documents/Custom Office Templates/",
  "ClientIP": "<ip_address>",
  "UserAgent": "<user_agent>"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-15T10:23:45",
  "Id": "3eb31fed-4bc1-4751-af24-a19501c1d2b8",
  "Operation": "FileModified",
  "OrganizationId": "b34e4567-e89b-12d3-a456-426614174000",
  "RecordType": 6,
  "UserKey": "i:0h.f|membership|user@domain.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "OneDrive",
  "ClientIP": "192.168.1.100",
  "ObjectId": "https://tenant-my.sharepoint.com/personal/user_domain_com/Documents/Custom Office Templates/Normal.dotm",
  "UserId": "user@domain.com",
  "SourceFileName": "Normal.dotm",
  "SourceFileExtension": "dotm"
}
```

### 2.2 SharePoint Template Library

**Description:**
Attackers upload malicious templates to shared document libraries configured as trusted template locations.

**Detection Fields:**
```json
{
  "Operation": "FileUploaded",
  "SourceFileName": ["*.dotm", "*.dotx", "*.xltx", "*.xltm"],
  "SiteUrl": "/sites/*/TemplateLibrary",
  "UserAgent": "<user_agent>",
  "WebId": "<web_id>"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-15T14:12:33",
  "Id": "4ac42bed-5bc2-4752-bf24-a19501c1d3c9", 
  "Operation": "FileUploaded",
  "OrganizationId": "b34e4567-e89b-12d3-a456-426614174000",
  "RecordType": 4,
  "UserKey": "i:0h.f|membership|user@domain.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "SharePoint",
  "SiteUrl": "/sites/Marketing/TemplateLibrary",
  "SourceFileName": "Corporate-Template.dotm",
  "SourceFileExtension": "dotm",
  "WebId": "8d34f6ae-1c35-4aa9-8e72-5a19bc6f54321"
}
```

### 2.3 GlobalDotName Registry Modification

**Description:** 
Adversaries modify Office application settings through administrative templates to redirect template loading to malicious locations.

**Detection Fields:**
```json
{
  "Operation": "Set-OrganizationConfig",
  "Parameters": ["GlobalDotName", "TemplatePath"],
  "ModifiedProperties": ["Office Templates Path"],
  "Actor": ["Admin", "System"]
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-15T16:45:22",
  "Id": "5bd52ced-6bc3-4753-cf24-a19501c1d4d0",
  "Operation": "Set-OrganizationConfig",
  "RecordType": 1,
  "UserKey": "i:0h.f|membership|admin@domain.com",
  "UserType": 2,
  "Version": 1,
  "Workload": "Exchange",
  "Parameters": [
    {
      "Name": "GlobalDotName",
      "Value": "\\\\remote-server\\templates\\Normal.dotm"
    }
  ],
  "ModifiedProperties": [
    {
      "Name": "Office Templates Path",
      "OldValue": "C:\\Users\\Default\\AppData\\Roaming\\Microsoft\\Templates",
      "NewValue": "\\\\remote-server\\templates"
    }
  ]
}
```

## 3. Detection Strategy

### 3.1 Behavioral Analytics Rules

```sql
-- Detect template modifications outside business hours
SELECT UserAgent, ClientIP, Operation, Timestamp 
FROM AuditLogs
WHERE Operation IN ('FileModified', 'FileUploaded')
AND SourceFileExtension IN ('dotm', 'dotx', 'xltm', 'xltx')
AND HOUR(Timestamp) NOT BETWEEN 8 AND 18;

-- Detect mass template modifications
SELECT UserId, COUNT(*) as ModCount
FROM AuditLogs 
WHERE Operation = 'FileModified'
AND SourceFileExtension IN ('dotm', 'dotx')
GROUP BY UserId, DATE(Timestamp)
HAVING ModCount > 5;
```

### 3.2 Baseline Deviations

- Monitor template modification frequency per user/department
- Track unusual template access patterns
- Alert on template modifications from unexpected locations
- Monitor for unusual Office application settings changes

### 3.3 Technical Controls

```json
{
  "OfficeTemplatePolicy": {
    "TrustedLocations": [
      "\\\\internal-server\\approved-templates",
      "%APPDATA%\\Microsoft\\Templates"
    ],
    "BlockUntrustedLocations": true,
    "DisableVBAMacros": "UserDefinedTemplatesOnly",
    "RequireAdminApproval": true
  }
}
```

## 4. Mitigation Strategy

### Administrative Controls
- Implement template change management process
- Restrict template modification permissions
- Regular template inventory and audit
- Document approved template sources

### Technical Controls
- Block macros in templates from untrusted sources
- Enable Protected View for templates
- Implement application allowlisting
- Monitor template file integrity

### Monitoring Controls
- Template modification alerts
- Office application settings changes
- Suspicious macro execution patterns
- Template sync activity monitoring

## 5. Incident Response

1. Immediate Actions:
   - Isolate affected systems
   - Block suspicious template locations
   - Disable template sync temporarily

2. Investigation Steps:
   - Review template modification audit logs
   - Analyze modified templates for malicious code
   - Track template distribution scope
   - Identify compromise timeline

3. Containment:
   - Remove compromised templates
   - Reset Office application settings
   - Block unauthorized template sources
   - Review and revoke excessive permissions

## 6. References

- MITRE ATT&CK: T1137.001
- Microsoft 365 Defender: Office Templates Security
- Microsoft Documentation: Office Templates Management
- Security Guidance for Office Templates in Microsoft 365

---

# Threat Model: Email Forwarding Rule (T1114.003) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries creating email forwarding rules in Microsoft 365 to automatically redirect email content to external addresses or maintain persistent access to mailbox data. Key risk factors include:

- Forwarding rules can be created via Outlook Web App, PowerShell, or Exchange Admin Center
- Rules can be hidden from user view using MAPI modifications
- Both user-level and organization-wide (transport) rules can be abused
- Rules persist even after password resets unless explicitly removed

## 2. Attack Vectors

### 2.1 User Mailbox Forwarding Rules

**Description:**
Adversary creates inbox rules to forward emails to external addresses using compromised credentials.

**Audit Operations to Monitor:**
- New-InboxRule
- Set-InboxRule 
- UpdateInboxRules

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "14c789e7-9542-4ab5-9c4b-06b88b87444f",
  "Operation": "New-InboxRule",
  "OrganizationId": "d6419b50-56a4-402b-9973-b6b6d3c80b86",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "john@contoso.com",
  "Parameters": [
    {
      "Name": "ForwardTo", 
      "Value": "attacker@malicious.com"
    },
    {
      "Name": "Enabled",
      "Value": "True" 
    }
  ]
}
```

### 2.2 Hidden MAPI Rules

**Description:**  
Adversary uses MAPI to create hidden rules not visible in standard interfaces.

**Audit Operations to Monitor:**
- Add-MailboxPermission
- UpdateInboxRules
- Set-InboxRule

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T16:14:22", 
  "Id": "18ff98c2-7845-4a2c-b0f2-55e9d6f094ea",
  "Operation": "Set-InboxRule",
  "RecordType": 1,
  "UserKey": "john@contoso.com",
  "Parameters": [
    {
      "Name": "RuleHidden",
      "Value": "True"
    },
    {
      "Name": "ForwardAsAttachmentTo",
      "Value": "external@domain.com"
    }
  ]
}
```

### 2.3 Transport Rule Abuse

**Description:**
Adversary with admin rights creates organization-wide mail flow rules.

**Audit Operations to Monitor:**
- New-TransportRule
- Set-TransportRule
- Remove-TransportRule

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T17:08:11",
  "Operation": "New-TransportRule",
  "RecordType": 1, 
  "UserKey": "admin@contoso.com",
  "Parameters": [
    {
      "Name": "RedirectMessageTo",
      "Value": "collector@attacker.com"
    },
    {
      "Name": "FromScope",
      "Value": "InOrganization" 
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics

```sql
-- Detect multiple forwarding rules created in short time
SELECT UserKey, COUNT(*) as RuleCount
FROM AuditLogs 
WHERE Operation IN ('New-InboxRule','Set-InboxRule')
AND Timestamp > DATEADD(hour, -1, GETUTCDATE())
GROUP BY UserKey
HAVING COUNT(*) > 3;

-- Identify hidden rules
SELECT * FROM AuditLogs
WHERE Operation = 'Set-InboxRule'
AND Parameters LIKE '%RuleHidden%:True%';

-- Monitor external forwarding destinations
SELECT DISTINCT Parameters.Value as ExternalDomain
FROM AuditLogs
WHERE Operation IN ('New-InboxRule','Set-TransportRule')
AND Parameters.Name IN ('ForwardTo','RedirectMessageTo')
AND Parameters.Value NOT LIKE '%@contoso.com';
```

### 3.2 Baseline Deviations

- Track normal rate of rule creation per user/day
- Monitor typical business hours for rule changes
- Baseline common internal forwarding patterns
- Alert on anomalous external domains

### 3.3 Risk Scoring
```json
{
  "risk_factors": {
    "hidden_rule": 80,
    "external_domain": 60,
    "multiple_rules": 40,
    "outside_hours": 30,
    "sensitive_mailbox": 50
  },
  "thresholds": {
    "high": 120,
    "medium": 80,
    "low": 40
  }
}
```

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement policy restricting external email forwarding
- Require approval for new transport rules
- Regular review of existing mail flow rules
- Monitor privileged Exchange role assignments

### 4.2 Technical Controls
```json
{
  "exchange_settings": {
    "disable_automatic_forwarding": true,
    "block_high_risk_domains": true,
    "require_rule_approval": true,
    "max_rules_per_user": 10,
    "forbidden_rule_actions": [
      "RedirectMessageTo",
      "ForwardAsAttachmentTo"  
    ]
  },
  "monitoring_settings": {
    "audit_retention_days": 180,
    "alert_on_hidden_rules": true,
    "log_rule_changes": true
  }
}
```

### 4.3 Monitoring Controls
- Enable unified audit logging
- Configure alerts for suspicious rule creation
- Review forwarding rules weekly
- Monitor Exchange admin activity

## 5. Incident Response

### 5.1 Initial Response
1. Identify affected mailboxes
2. Document all forwarding rules
3. Preserve audit logs
4. Block suspicious domains

### 5.2 Investigation 
1. Review rule creation audit trail
2. Identify rule creator accounts
3. Check for other compromised accounts
4. Search for exfiltrated data

### 5.3 Containment
1. Remove malicious rules
2. Reset affected account credentials
3. Block external forwarding domains
4. Review admin role assignments

## 6. References

- MITRE: https://attack.mitre.org/techniques/T1114/003/
- Microsoft: Configure email forwarding settings
- Microsoft: Exchange transport rules
- US-CERT: TA18-068A

---

# Threat Model: Financial Theft (T1657) in Microsoft 365 & Entra ID

## Overview
Financial theft in Microsoft 365 commonly manifests through business email compromise (BEC), phishing attacks targeting financial departments, and manipulation of email forwarding rules to intercept financial communications. Adversaries leverage compromised accounts and mailbox access to impersonate executives and authorize fraudulent transactions.

## Attack Vectors

### 1. Business Email Compromise via Mailbox Delegation

**Description:**
Attackers gain access to executive mailboxes through delegation to conduct financial fraud.

**Detection Fields:**
- Operation: Add-MailboxPermission, Add delegation entry
- Target Object: Executive mailbox
- Modified Properties: AccessRights
- Parameters: FullAccess permissions

**Example Audit Log:**
```json
{
  "CreationTime": "2024-02-01T10:15:22",
  "Id": "5689d3a2-1234-5678-90ab-cdef12345678",
  "Operation": "Add-MailboxPermission",
  "OrganizationId": "0123tenant",
  "RecordType": 1,
  "ResultStatus": "Success", 
  "UserKey": "attacker@domain.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ObjectId": "CEO@company.com",
  "UserId": "attacker@domain.com",
  "Parameters": [
    {
      "Name": "AccessRights",
      "Value": "FullAccess"
    }
  ]
}
```

### 2. Email Forwarding Rules for Payment Interception 

**Description:**
Attackers create inbox rules to forward financial emails to external addresses.

**Detection Fields:**
- Operation: New-InboxRule
- Rules Properties: ForwardTo
- External Recipients
- Rule Conditions: Subject/Body keywords

**Example Audit Log:**
```json
{
  "CreationTime": "2024-02-01T14:22:33",
  "Id": "92847593-1234-5678-90ab-cdef12345678",
  "Operation": "New-InboxRule",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "compromised@company.com",
  "Workload": "Exchange",
  "Parameters": [
    {
      "Name": "ForwardTo",
      "Value": "external@attacker.com"
    },
    {
      "Name": "SubjectContainsWords",  
      "Value": "invoice,payment,wire,transfer"
    }
  ]
}
```

### 3. Sensitive File Exfiltration from Finance SharePoint Sites

**Description:**
Attackers access and download sensitive financial documents.

**Detection Fields:**
- Operation: FileDownloaded, FileAccessed 
- Site URL: Finance team sites
- File Types: Financial documents
- Volume of downloads

**Example Audit Log:**
```json
{
  "CreationTime": "2024-02-01T16:45:12",
  "Operation": "FileDownloaded",
  "SiteUrl": "/sites/Finance",
  "ObjectId": "https://company.sharepoint.com/sites/Finance/Shared Documents/Wire Instructions.xlsx",
  "UserId": "suspicious@company.com",
  "ClientIP": "192.168.1.100",
  "UserAgent": "Browser",
  "ItemType": "File",
  "ListItemUniqueId": "87654321-abcd-efgh-ijkl-123456789012"
}
```

## Detection Strategy

### Behavioral Analytics Rules
```sql
-- Detect suspicious mailbox delegation
SELECT UserKey, ObjectId, COUNT(*) as delegation_count
FROM AuditLogs 
WHERE Operation = 'Add-MailboxPermission'
  AND TimeGenerated > ago(1h)
GROUP BY UserKey, ObjectId
HAVING COUNT(*) >= 3;

-- Monitor external email forwarding rules
SELECT UserId, COUNT(*) as rule_count
FROM AuditLogs
WHERE Operation = 'New-InboxRule' 
  AND Parameters LIKE '%external%'
  AND TimeGenerated > ago(24h)
GROUP BY UserId
HAVING COUNT(*) > 1;
```

### Baseline Deviations
- Monitor daily volume of downloaded financial files vs 30-day baseline
- Track after-hours mailbox access patterns
- Alert on anomalous geographic access locations

## Technical Controls
```json
{
  "conditionalAccess": {
    "signInRiskLevels": ["high"],
    "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
    "locations": ["excludeAllTrusted"],
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["mfa", "compliantDevice"]
    }
  },
  "mailboxAuditSettings": {
    "AuditEnabled": true,
    "AuditLogAgeLimit": 365,
    "Operations": ["Create", "HardDelete", "MailboxLogin", "Update"]
  }
}
```

## Administrative Controls
1. Configure Privileged Identity Management for finance roles
2. Enable MFA for all users with financial authorization 
3. Restrict external email forwarding to approved domains
4. Implement DLP policies for financial data

## Monitoring Controls
1. Real-time alerts for:
   - New mailbox delegation to executive accounts
   - External forwarding rules creation
   - Bulk file downloads from finance sites
2. Weekly review of:
   - Mailbox audit logs
   - SharePoint access patterns
   - Authentication events from unknown locations

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1657/
- Microsoft Security Documentation:
  - Exchange Audit Logging
  - SharePoint Security Monitoring
  - Microsoft Defender for Office 365

Would you like me to provide more details on any section or expand the detection strategies further?

---

# Threat Model: Cloud Services (T1021.007) in Microsoft 365 & Entra ID

## Overview
This technique involves adversaries leveraging federated/synchronized identities to access cloud services in Microsoft 365 and Entra ID environments. Key risks include:
- Abuse of hybrid identity configurations 
- Unauthorized access to cloud management interfaces
- Lateral movement between on-premises and cloud resources

## Attack Vectors

### 1. PowerShell Authentication to Cloud Services
**Description**: Adversaries authenticate to cloud services using PowerShell modules and stored credentials

**Scenario**:
```powershell
# Adversary using stolen credentials
Connect-AzAccount -Credential $creds
Connect-MgGraph -Credential $creds
# Access cloud resources
Get-AzVM
Get-MgUser
```

**Detection Fields**:
```json
{
  "CreationTime": "2024-01-20T15:30:22",
  "Id": "<GUID>",
  "Operation": "Add service principal credentials",
  "OrganizationId": "<TenantID>",
  "RecordType": "AzureActivity",
  "ResultStatus": "Success", 
  "LogonType": "AzurePowerShell",
  "UserAgent": "AzurePowerShell/1.2.3",
  "UserId": "attacker@domain.com"
}
```

### 2. Access Through Web Console
**Description**: Adversaries access cloud services through web portals using compromised credentials

**Scenario**:
```
1. Attacker logs into portal.azure.com with stolen credentials
2. Accesses administrative interfaces
3. Creates new admin accounts
```

**Detection Fields**:
```json
{
  "CreationTime": "2024-01-20T16:45:13",
  "Id": "<GUID>", 
  "Operation": "UserLoggedIn",
  "RecordType": "AzureAD",
  "ResultStatus": "Success",
  "LogonType": "WebPortal", 
  "IPAddress": "192.168.1.100",
  "UserAgent": "Mozilla/5.0...",
  "UserId": "attacker@domain.com"
}
```

### 3. Token-based Access  
**Description**: Adversaries steal and reuse access tokens to authenticate to cloud services

**Detection Fields**:
```json
{
  "CreationTime": "2024-01-20T17:15:44",
  "Operation": "Add service principal.",
  "ApplicationId": "<AppID>",
  "TokenType": "JWT Bearer",
  "ResourceId": "/subscriptions/<SubID>",
  "ResultStatus": "Success",
  "UserId": "attacker@domain.com"
}
```

## Detection Strategies

### Behavioral Analytics
```sql
-- Detect anomalous PowerShell usage
SELECT UserId, COUNT(*) as auth_count
FROM AuditLogs 
WHERE Operation = 'Add service principal credentials'
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 10;

-- Alert on suspicious web console access 
SELECT IPAddress, COUNT(DISTINCT UserId) as user_count
FROM SignInLogs
WHERE LogonType = 'WebPortal'
AND TimeGenerated > ago(1h)
GROUP BY IPAddress
HAVING COUNT(DISTINCT UserId) > 5;
```

### Baseline Deviations
- Monitor for access from new IP addresses/locations
- Track changes in authentication patterns
- Alert on first-time PowerShell usage

## Technical Controls
```json
{
  "conditionalAccess": {
    "signInRiskLevels": ["high", "medium"],
    "clientAppTypes": ["modern", "legacy"],
    "locations": ["trusted", "untrusted"],
    "controls": {
      "blockHighRisk": true,
      "mfaRequired": true,
      "compliantDeviceRequired": true
    }
  }
}
```

## Administrative Controls
1. Implement JIT access for admin accounts
2. Regular access reviews
3. Monitor privileged identity management
4. Restrict PowerShell access

## Monitoring Controls
1. Enable detailed audit logging
2. Monitor service principal creation
3. Track federated authentication events
4. Alert on suspicious token usage

## Incident Response
1. Initial Triage
   - Validate authentication source
   - Check for new service principals
   - Review access patterns

2. Investigation
   - Analyze audit logs for lateral movement
   - Check for persistence mechanisms
   - Review token usage

3. Containment
   - Revoke suspicious tokens
   - Reset compromised credentials
   - Block malicious IPs

## References
- [MITRE T1021.007](https://attack.mitre.org/techniques/T1021/007/)
- [Microsoft Identity Security](https://docs.microsoft.com/security/identity)
- [Azure AD Sign-in Logs](https://docs.microsoft.com/azure/active-directory/reports-monitoring/)

Let me know if you would like me to expand on any section in more detail.

---

# Threat Model: Steal Application Access Token (T1528) in Microsoft 365 & Entra ID

## Overview
Adversaries steal application access tokens to authenticate to Microsoft 365 and Entra ID services by:
- Compromising OAuth 2.0 flows through malicious applications
- Stealing refresh tokens to maintain persistent access 
- Extracting tokens from application configurations and storage
- Social engineering users to grant token permissions

## Attack Vectors

### 1. Malicious OAuth Application Registration

**Description:**
Adversary creates malicious Azure AD application registration and tricks users into granting OAuth consent, allowing token theft.

**Detection Fields:**
```json
{
  "Operation": "Add service principal.",
  "ObjectId": "<app_id>",
  "ApplicationId": "<application_id>",
  "ServicePrincipalNames": ["<app_name>"],
  "UserAgent": "<user_agent>",
  "ClientIP": "<ip_address>",
  "ActorUPN": "<actor_email>"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "2b198745-d82f-4f24-9517-c244b9e2b51a", 
  "Operation": "Add service principal.",
  "OrganizationId": "8b6ce428-caa6-4c59-9fbb-18196b4c2e94",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "965f6ca4-0419-46c6-8826-42fb6d46f2f9",
  "UserId": "admin@contoso.com",
  "ApplicationId": "f02897d4-9d1e-4c50-89b1-2c2ab32ea85d",
  "ServicePrincipalNames": ["SuspiciousApp"],
  "UserAgent": "Mozilla/5.0...",
  "ClientIP": "192.168.1.100",
  "ActorUPN": "attacker@contoso.com",
  "Permissions": ["Mail.Read", "Files.ReadWrite.All"]
}
```

### 2. Application Permission Abuse

**Description:**  
Adversary modifies existing application permissions to gain elevated access token capabilities.

**Detection Fields:**
```json
{
  "Operation": "Set delegation entry.",
  "TargetResources": [{
    "Type": "ServicePrincipal",
    "Id": "<principal_id>",
    "ModifiedProperties": [{
      "Name": "AppRoles",
      "NewValue": "<new_permissions>"
    }]
  }]
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "4a21a831-c598-4871-9e34-d2c5a11f2530",
  "Operation": "Set delegation entry.",
  "OrganizationId": "8b6ce428-caa6-4c59-9fbb-18196b4c2e94", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "TargetResources": [{
    "Type": "ServicePrincipal",
    "Id": "965f6ca4-0419-46c6-8826-42fb6d46f2f9",
    "ModifiedProperties": [{
      "Name": "AppRoles",
      "OldValue": "Mail.Read",
      "NewValue": "Mail.ReadWrite.All, Files.ReadWrite.All"
    }]
  }],
  "ActorUPN": "attacker@contoso.com",
  "ClientIP": "192.168.1.100"
}
```

### 3. Token Refresh Abuse

**Description:**
Adversary steals refresh tokens to maintain persistent access by generating new access tokens.

**Detection Fields:**
```json
{
  "Operation": "UserLoggedIn",
  "AppId": "<app_id>",
  "ClientAppUsed": "RefreshToken",
  "DeviceDetail": {
    "Browser": "<browser>",
    "DeviceId": "<device_id>"
  }
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T17:03:15",
  "Operation": "UserLoggedIn", 
  "OrganizationId": "8b6ce428-caa6-4c59-9fbb-18196b4c2e94",
  "AppId": "965f6ca4-0419-46c6-8826-42fb6d46f2f9",
  "ClientAppUsed": "RefreshToken",
  "DeviceDetail": {
    "Browser": "Chrome/120.0.0.0",
    "DeviceId": "b2384a12-9f4e-42dc-9c4a-d1844d8d2c10",
    "OS": "Windows 10"
  },
  "UserAgent": "Mozilla/5.0...", 
  "ClientIP": "192.168.1.100",
  "UserId": "victim@contoso.com",
  "TokenIssuerType": "AzureAD"
}
```

## Detection Strategies

### Behavioral Analytics Rules

```sql
-- Detect suspicious app registration patterns
SELECT ActorUPN, COUNT(*) as app_count
FROM AuditLogs 
WHERE Operation = "Add service principal."
AND TimeGenerated > ago(1h)
GROUP BY ActorUPN
HAVING app_count >= 3;

-- Detect abnormal permission changes
SELECT TargetResources.Id, COUNT(*) as change_count
FROM AuditLogs
WHERE Operation = "Set delegation entry."
AND TimeGenerated > ago(24h)
GROUP BY TargetResources.Id
HAVING change_count >= 5;

-- Monitor refresh token usage from new locations
SELECT UserId, ClientIP, COUNT(*) as refresh_count
FROM SignInLogs
WHERE ClientAppUsed = "RefreshToken"
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING refresh_count >= 10;
```

### Baseline Deviations
- Monitor for sudden increases in:
  - New application registrations (>3x daily average)
  - Permission changes to existing applications (>5x daily average)
  - Refresh token usage from new IP addresses (>10x per hour)
  - OAuth consent grants to new applications (>2x daily average)

## Mitigation Controls

### Technical Controls
```json
{
  "conditionalAccess": {
    "applicationEnforcementMode": "enforced",
    "conditions": {
      "applications": {
        "includeApplications": ["all"]
      },
      "users": {
        "includeRoles": ["Application Administrator", "Global Administrator"]
      }
    },
    "grantControls": {
      "builtInControls": ["mfa"],
      "customAuthenticationFactors": [],
      "operator": "AND",
      "termsOfUse": []
    }
  },
  "appConsentPolicy": {
    "isEnabled": true,
    "notifyOnAppConsent": true,
    "requireAdminConsentForSpecificScopes": [
      "Mail.Read",
      "Files.ReadWrite.All",
      "Directory.ReadWrite.All"
    ]
  }
}
```

### Administrative Controls
1. Implement strict application registration approval process
2. Regular review of application permissions and consent grants
3. Monitor and audit token lifetimes and refresh token validity
4. Enable risk-based conditional access policies

### Monitoring Controls
1. Alert on suspicious application registration patterns
2. Monitor for permission elevation in existing applications
3. Track refresh token usage patterns and anomalies
4. Review OAuth consent grants, especially for sensitive scopes

## Incident Response Playbook

### Initial Detection
1. Identify affected application and compromised tokens
2. Determine scope of access granted through stolen tokens
3. Review audit logs for associated suspicious activities
4. Document timestamps and affected resources

### Investigation
1. Map token usage patterns and access history
2. Review application permission changes
3. Analyze OAuth consent grants
4. Identify any data accessed using stolen tokens

### Containment
1. Revoke compromised refresh tokens
2. Remove suspicious application registrations
3. Reset affected user credentials
4. Block suspicious IP addresses
5. Review and restrict application permissions

## References
- [Microsoft OAuth 2.0 Authorization Code Flow](https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [Microsoft Identity Platform Best Practices](https://docs.microsoft.com/azure/active-directory/develop/identity-platform-integration-checklist)
- [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)
- [Azure AD Token Lifetime Policy](https://docs.microsoft.com/azure/active-directory/develop/active-directory-configurable-token-lifetimes)

---

# Threat Model: Cloud Account Discovery (T1087.004) in Microsoft 365 & Entra ID

## 1. Overview 
Adversaries enumerate cloud accounts in Microsoft 365 and Entra ID to identify targets for compromise and understand the environment's structure. This typically involves querying directory objects through PowerShell, Graph API, or admin portals.

## 2. Attack Vectors

### Vector 1: PowerShell Enumeration
**Description**: Adversaries use Microsoft 365/Azure PowerShell modules to enumerate users and roles.

**Scenario**:
- Attacker obtains credentials for a standard user account
- Connects to MSOnline/Azure AD PowerShell modules
- Runs cmdlets like Get-MsolUser and Get-MsolRole to enumerate accounts

**Detection Fields**:
```json
{
  "Operation": "UserLoggedIn",
  "ActorId": "user@domain.com",
  "Application": "MSOnline PowerShell",
  "ClientIP": "ip_address",
  "ResultStatus": "Success"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "4a38c447-9f89-4a52-9c4d-ac7bd435c24d",
  "Operation": "Get directory members", 
  "OrganizationId": "4a782057-1234-5678-90ab-cdef12345678",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001A64R5486@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "All_Users",
  "UserId": "admin@contoso.com",
  "AzureActiveDirectoryEventType": 1,
  "ExtendedProperties": [
    {
      "Name": "UserAgent",
      "Value": "MSOnline PowerShell/1.0"
    }
  ],
  "ModifiedProperties": []
}
```

### Vector 2: Graph API Enumeration
**Description**: Adversaries leverage Microsoft Graph API to query directory objects programmatically.

**Scenario**:
- Attacker registers malicious OAuth application
- Uses application permissions to query Graph API users endpoint
- Collects user information including roles and permissions

**Detection Fields**:
```json
{
  "Operation": "Add service principal.",
  "ServicePrincipalId": "application_id",
  "Permissions": ["Directory.Read.All"],
  "ClientIP": "ip_address"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Id": "5c44d8b2-4512-4322-a2be-8d7ce54c2789",
  "Operation": "Add service principal.",
  "OrganizationId": "4a782057-1234-5678-90ab-cdef12345678", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "ServicePrincipalId": "a149b828-4312-4d53-9cb9-123456789012",
  "ServicePrincipalName": "Suspicious App",
  "Permissions": ["Directory.Read.All"],
  "ClientIP": "192.168.1.100",
  "UserAgent": "Python/3.9 GraphAPI/1.0",
  "UserId": "attacker@contoso.com"
}
```

### Vector 3: Admin Portal Enumeration
**Description**: Adversaries browse admin portals to manually discover accounts and roles.

**Detection Fields**:
```json
{
  "Operation": "UserLoggedIn",
  "ApplicationDisplayName": "Microsoft 365 Admin Portal",
  "ClientIP": "ip_address",
  "UserAgent": "browser_info"
}
```

## 3. Detection Strategies

### Behavioral Analytics
```sql
-- Detect rapid user enumeration via PowerShell
SELECT UserId, ClientIP, COUNT(*) as query_count
FROM AuditLogs 
WHERE Operation IN ('Get directory members', 'Get user', 'Get role members')
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 100

-- Detect suspicious application registrations
SELECT * FROM AuditLogs
WHERE Operation = 'Add service principal.'
AND Permissions CONTAINS 'Directory.Read.All'
AND ServicePrincipalName NOT IN (allowed_apps)
```

### Baseline Deviations
- Monitor for anomalous spikes in directory query operations
- Track unusual patterns in admin portal access
- Alert on new service principals requesting directory access

### Thresholds
- >100 directory queries per hour from single source
- >3 failed authentication attempts for Graph API
- New service principals with sensitive permissions

## 4. Mitigation Strategies

### Administrative Controls
- Implement Conditional Access policies
- Enable Identity Protection
- Enforce MFA for all admin accounts

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "name": "Block Legacy Authentication",
    "conditions": {
      "clientAppTypes": ["exchangeActiveSync", "other"],
      "actions": "block"
    }
  },
  "graphAPIPermissions": {
    "requireAdminConsent": true,
    "restrictedPermissions": [
      "Directory.Read.All",
      "User.Read.All"
    ]
  }
}
```

### Monitoring Controls
- Enable Azure AD audit logs
- Monitor service principal creations
- Track admin portal access patterns

## 5. Response Playbook

### Initial Detection
1. Identify source of enumeration activity
2. Review authentication logs
3. Check for new service principals

### Investigation
1. Analyze scope of enumeration
2. Review affected accounts
3. Check for suspicious application consents

### Containment
1. Block suspicious IPs
2. Revoke compromised credentials
3. Remove malicious applications

## 6. References
- MITRE: https://attack.mitre.org/techniques/T1087/004/
- Microsoft: https://docs.microsoft.com/security/cloud-accounts

---

# Threat Model: Forge Web Credentials (T1606) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries can forge various types of authentication credentials including:
- SAML tokens for federated authentication
- Service principal credentials
- Delegated authentication permissions
- Web session tokens

## 2. Attack Vectors

### 2.1 Forged SAML Token Attack
**Description**: Adversaries create fraudulent SAML tokens by compromising token signing certificates or modifying federation trust relationships.

**Audit Fields to Monitor**:
```json
{
  "Operation": "Set federation settings on domain",
  "UserAgent": "PowerShell Client", 
  "ObjectId": "/domains/contoso.com",
  "ModifiedProperties": [
    {
      "Name": "FederationTrustSettings",
      "OldValue": null,
      "NewValue": {
        "TokenSigningCertificate": "MIIDAj...",
        "IssuerUri": "http://malicious.com/adfs/services/trust"
      }
    }
  ]
}
```

### 2.2 Service Principal Credential Forgery
**Description**: Attackers add fraudulent credentials to existing service principals.

**Audit Fields to Monitor**:
```json
{
  "Operation": "Add service principal credentials",
  "UserId": "admin@contoso.com",
  "ObjectId": "a4aa47c6-c435-48ce-9a4f-4a6e14d6db51", 
  "Target": [
    {
      "Type": "ServicePrincipal",
      "ID": "8f937327-323d-4dca-926d-508c8aaf8c48"
    }
  ],
  "ResultStatus": "Success"
}
```

### 2.3 Delegated Permission Abuse
**Description**: Adversaries modify OAuth app permissions to forge access tokens.

**Audit Fields to Monitor**:
```json
{
  "Operation": "Add delegation entry",
  "UserId": "user@contoso.com",
  "ObjectId": "27af1299-4210-4789-99c1-b466ff983fd2",
  "Target": [
    {
      "Type": "Application",
      "ID": "8f937327-323d-4dca-926d-508c8aaf8c48"
    }
  ],
  "ModifiedProperties": [
    {
      "Name": "DelegatedPermissions",
      "NewValue": "Mail.Read Directory.ReadWrite.All"
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
// Detect rapid service principal credential additions
SELECT UserId, Count(*) as CredentialAdds
FROM AuditLogs 
WHERE Operation = "Add service principal credentials"
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING Count(*) > 5

// Monitor federation trust changes outside business hours
SELECT *
FROM AuditLogs
WHERE Operation = "Set federation settings on domain" 
AND TimeGenerated !between (datetime('09:00') .. datetime('17:00'))
```

### 3.2 Baseline Deviations
- Track normal patterns of service principal credential management
- Alert on anomalous numbers of permission changes
- Monitor typical federation configuration change frequency

## 4. Technical Controls

```json
{
  "ConditionalAccessPolicies": {
    "Name": "Block Legacy Authentication",
    "State": "Enabled",
    "Conditions": {
      "ClientAppTypes": ["Other Clients"],
      "Action": "Block"
    }
  },
  "AuditingSettings": {
    "UnifiedAuditLogIngestion": "Enabled",
    "RetentionDays": 90,
    "Operations": [
      "Add service principal credentials",
      "Set federation settings on domain",
      "Add delegation entry"
    ]
  }
}
```

## 5. Incident Response Playbook

1. Initial Detection
   - Review unified audit logs for suspicious credential/permission changes
   - Check federation configuration modifications
   - Identify affected service principals and applications

2. Investigation
   - Map timeline of credential/permission changes
   - Validate legitimate vs suspicious changes
   - Review authentication patterns post-modification

3. Containment
   - Revoke suspicious service principal credentials
   - Reset federation trust settings if compromised
   - Block affected application IDs
   - Reset affected user passwords

## 6. References

- [MITRE T1606](https://attack.mitre.org/techniques/T1606/)
- [Microsoft - Detecting SolarWinds Forged SAML Tokens](https://www.microsoft.com/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/)
- [Microsoft - Securing Service Principals](https://docs.microsoft.com/azure/active-directory/develop/security-best-practices-for-app-registration)

Let me know if you would like me to expand on any section or add additional details.

---

# Threat Model: Multi-Factor Authentication Request Generation (T1621) in Microsoft 365 & Entra ID

## Overview
This technique involves adversaries attempting to bypass MFA by generating excessive authentication requests to fatigue users into accepting. In Microsoft 365 and Entra ID environments, this commonly manifests through authentication attempts generating Microsoft Authenticator push notifications or SMS codes.

## Attack Vectors

### 1. Authentication Request Flooding
**Description**: Adversaries make repeated authentication attempts with valid credentials to trigger MFA prompts.

**Example Scenario**:
- Attacker obtains valid username/password but lacks MFA access
- Scripts automated login attempts every few minutes
- Continues until user accepts prompt from fatigue

**Relevant Audit Fields**:
```json
{
  "CreationTime": "2024-01-20T15:22:43",
  "Id": "<GUID>",
  "Operation": "UserLoggedIn", 
  "OrganizationId": "<TenantID>",
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserKey": "user@domain.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "12.34.56.78",
  "ExtendedProperties": [
    {
      "Name": "UserAgent",
      "Value": "Python-Requests/2.25.1"
    },
    {
      "Name": "AuthenticationMethod", 
      "Value": "MFA_PUSH"
    }
  ]
}
```

### 2. Self-Service Password Reset (SSPR) Abuse 
**Description**: Adversaries abuse SSPR functionality to generate MFA challenges without valid credentials.

**Example Scenario**:
- Attacker identifies valid usernames through enumeration
- Initiates SSPR flows repeatedly
- Users receive MFA prompts for password resets

**Relevant Audit Fields**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Operation": "Reset user password.",
  "RecordType": 8,
  "ResultStatus": "Attempted",
  "TargetUserOrGroupName": "user@domain.com",
  "TargetUserOrGroupType": "User",
  "Workload": "AzureActiveDirectory",
  "ObjectId": "user@domain.com",
  "UserId": "unknown",
  "ClientIP": "98.76.54.32"
}
```

### 3. Token Manipulation for Repeated Auth
**Description**: Adversaries manipulate authentication tokens to force new MFA challenges.

**Example Scenario**:
- Attacker obtains valid session token
- Modifies token claims to force reauthentication
- Each attempt generates new MFA prompt

**Relevant Audit Fields**:
```json
{
  "CreationTime": "2024-01-20T17:08:33",
  "Operation": "Update user.", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "TargetUserOrGroupName": "user@domain.com",
  "ModifiedProperties": [
    {
      "Name": "StrongAuthenticationMethod",
      "NewValue": "["Option:undefined"]"
    }
  ],
  "ActorIpAddress": "45.67.89.12"
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect rapid authentication attempts
SELECT UserKey, ClientIP, COUNT(*) as attempt_count
FROM AuditLogs 
WHERE Operation = 'UserLoggedIn'
AND ResultStatus = 'Failed'
AND Timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY UserKey, ClientIP
HAVING attempt_count >= 10;

-- Track SSPR abuse
SELECT TargetUserOrGroupName, COUNT(*) as reset_attempts 
FROM AuditLogs
WHERE Operation = 'Reset user password.'
AND Timestamp > NOW() - INTERVAL 24 HOURS
GROUP BY TargetUserOrGroupName
HAVING reset_attempts >= 5;
```

### Baseline Deviations
- Monitor for >50% increase in failed auth attempts per user
- Alert on MFA prompts outside normal working hours
- Track geographic anomalies in auth request origins

## Mitigation Controls

### Administrative Controls
- Implement number matching for MFA prompts
- Enable timeout periods between MFA attempts
- Configure adaptive MFA policies based on risk

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "conditions": {
      "signInRisk": "high",
      "userRisk": "medium",
      "applications": {
        "includeApplications": ["all"]
      }
    },
    "grantControls": {
      "operator": "AND",
      "builtInControls": [
        "mfa",
        "compliantDevice",
        "domainJoinedDevice"
      ]
    }
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Monitor MFA configuration changes
- Track SSPR attempt patterns

## Incident Response

### Initial Detection
1. Identify affected users from audit logs
2. Determine authentication attempt patterns
3. Review geographic origins of requests

### Investigation Steps
1. Analyze successful vs failed auth attempts
2. Review user agent strings for automation indicators
3. Map IP addresses to known threat actors

### Containment Actions
1. Reset affected user credentials
2. Enable additional MFA requirements
3. Block suspicious IP ranges

## References
- [MITRE T1621](https://attack.mitre.org/techniques/T1621)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Entra ID Protection](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/)

---

# Threat Model: Chat Messages (T1552.008) in Microsoft 365 & Entra ID

## Overview
This technique involves adversaries collecting credentials shared through Microsoft Teams, Outlook, SharePoint, and other Microsoft 365 communication channels. Key focus areas include:
- Direct access to chat messages through Teams/Outlook clients
- Admin portal access to message content 
- Integration service account abuse

## Attack Vectors

### 1. Teams Message Access
**Description**: Adversaries with compromised admin accounts access Teams message history to extract credentials shared in chats

**Scenario**: Attacker uses Global Admin account to export Teams messages searching for password patterns

**Relevant Audit Operations**:
- MessagesExported
- MessageRead  
- ChatRetrieved
- MessageHostedContentsListed

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T15:30:00",
  "Id": "4a7c8f9e-1234-5678-90ab-cdef12345678",
  "Operation": "MessagesExported",
  "OrganizationId": "contoso.onmicrosoft.com", 
  "RecordType": 25,
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "MicrosoftTeams",
  "ObjectId": "19:meeting_NjNiODM3NDktYzQ3MC00@thread.v2",
  "UserId": "admin@contoso.com",
  "CorrelationId": "4a7c8f9e-1234-5678-90ab-cdef12345678",
  "TeamName": "Finance Team",
  "MessageCount": 5000,
  "ExportType": "MessageHistoryReport"
}
```

### 2. Communication Compliance Access 
**Description**: Adversaries abuse communication compliance policies to scan messages for credentials

**Scenario**: Attacker creates compliance policy with broad scope to collect messages containing password patterns

**Relevant Audit Operations**:
- SupervisionPolicyCreated
- SupervisionPolicyUpdated
- SupervisionRuleMatch

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T16:20:00", 
  "Id": "5b8d9f0a-2345-6789-01bc-defg23456789",
  "Operation": "SupervisionPolicyCreated",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 15,
  "UserKey": "admin@contoso.com",
  "Workload": "SecurityCompliance",
  "ObjectId": "/policies/supervision/Finance-Policy",
  "PolicyDetails": {
    "Name": "Finance Communications",
    "Conditions": "*password* OR *credentials*",
    "Scope": "All Users",
    "Direction": "Inbound and Outbound"
  }
}
```

### 3. Integration Service Account Abuse
**Description**: Adversaries leverage over-privileged service accounts used for Teams/Exchange integrations

**Scenario**: Attacker compromises application service principal with Teams message access

**Relevant Audit Operations**:
- Add service principal
- Add service principal credentials
- Set delegation entry

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T17:10:00",
  "Id": "6c9e0f1b-3456-7890-12cd-efgh34567890", 
  "Operation": "Add service principal credentials",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 8,
  "UserKey": "admin@contoso.com",
  "Workload": "AzureActiveDirectory",
  "ObjectId": "ServicePrincipal_1234567890",
  "Target": "[{\"Type\":\"ServicePrincipal\",\"ID\":\"1234567890\"}]",
  "NewValue": "[{\"CredentialType\":\"Password\",\"Description\":\"Teams Integration\"}]"
}
```

## Detection Strategies

### Behavioral Analytics
```sql
-- Detect unusual volume of message exports
SELECT UserKey, COUNT(*) as export_count
FROM TeamsAuditLog 
WHERE Operation = 'MessagesExported'
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING COUNT(*) > 100

-- Detect sensitive keyword searches in compliance policies
SELECT UserKey, PolicyDetails.Conditions
FROM ComplianceAuditLog
WHERE Operation IN ('SupervisionPolicyCreated','SupervisionPolicyUpdated')
AND PolicyDetails.Conditions LIKE '%password%'
```

### Baseline Deviations
- Monitor for spikes in message access operations vs baseline
- Track service principal credential additions compared to normal rate
- Alert on new compliance policies with broad scope

### Key Thresholds
- More than 1000 messages exported per hour
- More than 3 new service principal credentials in 24 hours
- Compliance policies affecting >25% of users

## Technical Controls
```json
{
  "controls": {
    "teams": {
      "messageDataRetention": 30,
      "exportEnabled": false,
      "sensitiveKeywordBlocking": true
    },
    "servicePrincipals": {
      "credentialLifetime": 90,
      "requiredApproval": true,
      "scopeRestrictions": ["Teams.Read.Basic"]
    },
    "compliance": {
      "policyApproval": true,
      "maxUserScope": 1000,
      "auditRetention": 180
    }
  }
}
```

## Administrative Controls
1. Implement just-in-time access for Teams admin roles
2. Require MFA for all service principal credential management
3. Regular review of compliance policy scope and conditions
4. Monitoring of service account permissions and usage

## Monitoring Controls
1. Enable unified audit logging for all M365 workloads
2. Configure alerts for suspicious message access patterns
3. Monitor service principal credential management
4. Track compliance policy changes and scope

## Incident Response
1. Initial triage:
   - Review audit logs for message access patterns
   - Check compliance policy modifications
   - Audit service principal permissions

2. Investigation:
   - Export relevant message history
   - Review affected user accounts
   - Analyze service principal activity
   
3. Containment:
   - Revoke compromised credentials
   - Disable suspicious compliance policies
   - Reset affected service accounts

## References
- MITRE ATT&CK: T1552.008
- Microsoft Teams Security Guide
- Microsoft Service Principal Security Best Practices
- Microsoft Communication Compliance Documentation

---

# Threat Model: Internal Spearphishing (T1534) in Microsoft 365 & Entra ID

## 1. Overview 

Internal spearphishing in M365 environments typically involves compromised legitimate accounts being used to send malicious content to other users within the organization. The trusted nature of internal senders makes these attacks particularly effective. Key aspects:

- Leverages compromised legitimate accounts
- Uses internal email, Teams, or SharePoint for delivery
- Often involves impersonation of executives or trusted roles
- May include malicious links, attachments, or requests
- Takes advantage of existing trust relationships

## 2. Attack Vectors

### Vector 1: Compromised Executive Email Account

**Description:**
Adversary compromises an executive's email account and sends urgent requests to finance/HR personnel.

**Scenario:**
- Attacker gains access to CFO's account
- Sends urgent wire transfer requests to finance team
- Uses actual internal email threads and formatting
- Creates email rules to hide responses

**Detection Fields:**
- Operation: "New-InboxRule", "Set-InboxRule", "UpdateInboxRules"
- ClientIP
- UserId/Actor
- RuleName
- RuleParameters
- TargetFolder

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T15:22:33",
  "Id": "18a7c443-8b6a-4927-a40c-123456789abc",
  "Operation": "New-InboxRule",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 1,
  "UserKey": "10032001@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "192.168.1.100",
  "UserId": "CFO@contoso.com",
  "RuleName": "External Processing",
  "RuleParameters": {
    "MoveToFolder": "Archive",
    "SubjectContains": ["wire", "transfer", "urgent"],
    "FromAddressContains": ["finance@contoso.com"]
  }
}
```

### Vector 2: Teams Phishing Campaign 

**Description:**
Adversary uses compromised account to distribute malicious links via Teams chats/channels.

**Detection Fields:**
- Operation: "MessageCreatedHasLink", "MessageSent"
- ChatThreadId
- MessageContent 
- LinkCount
- ExternalLinks

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Operation": "MessageCreatedHasLink",
  "OrganizationId": "contoso.onmicrosoft.com", 
  "RecordType": 15,
  "UserKey": "user123@contoso.com",
  "ChatThreadId": "19:meeting_123@thread.v2",
  "MessageContent": "Please review this urgent document",
  "LinkCount": 1,
  "ExternalLinks": ["https://malicious-site.com/document"],
  "Recipients": ["team_finance@contoso.com"]
}
```

### Vector 3: SharePoint Document Weaponization

**Description:** 
Adversary uploads malicious files to shared SharePoint sites using compromised account.

**Detection Fields:**
- Operation: "FileUploaded", "FileSyncUploadedFull"
- SiteUrl
- SourceFileName
- FileType
- UserAgent

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-20T17:33:12",
  "Operation": "FileUploaded",
  "SiteUrl": "/sites/finance",
  "SourceFileName": "Q4_Report.docx",
  "FileType": "docx",
  "UserAgent": "Mozilla/5.0...",
  "ClientIP": "192.168.1.100",
  "UserId": "analyst@contoso.com",
  "DocumentLibrary": "Shared Documents"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules

```sql
-- Detect suspicious inbox rules
SELECT UserId, ClientIP, COUNT(*) as rule_count
FROM EmailAuditLogs 
WHERE Operation IN ('New-InboxRule','Set-InboxRule')
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 3;

-- Detect mass Teams messages with links
SELECT UserId, COUNT(*) as message_count
FROM TeamsAuditLogs
WHERE Operation = 'MessageCreatedHasLink'
AND TimeGenerated > ago(30m)
GROUP BY UserId
HAVING COUNT(*) > 10;
```

### Baseline Deviations
- Monitor for users sending 200% above their normal email volume
- Track abnormal working hours for account activity
- Flag new external domains in link patterns

## 4. Technical Controls

```json
{
  "conditionalAccessPolicy": {
    "name": "Block Suspicious Inbox Rules",
    "conditions": {
      "applications": ["Office 365 Exchange Online"],
      "clientAppTypes": ["All"],
      "locations": ["All"],
      "platforms": ["All"]
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["mfa"]
    }
  }
}
```

## 5. Incident Response Playbook

1. Initial Triage
   - Identify compromised account(s)
   - Review audit logs for rule creation
   - Check email forwarding settings
   - Extract indicators from malicious content

2. Containment
   - Reset compromised account credentials
   - Remove suspicious inbox rules
   - Block identified malicious URLs
   - Disable external sharing if needed

3. Investigation  
   - Review authentication logs
   - Track lateral movement attempts
   - Identify targeted users/data
   - Document attack timeline

## 6. References

- MITRE: https://attack.mitre.org/techniques/T1534/
- Microsoft: https://docs.microsoft.com/security/...
- Related Techniques: T1566, T1078, T1114

Would you like me to expand on any section or provide additional details?

---

# Threat Model: Trusted Relationship (T1199) in Microsoft 365 & Entra ID

## 1. Overview 

In Microsoft 365 and Entra ID environments, trusted relationships primarily manifest through:
- Delegated admin permissions granted to Microsoft Partners/CSPs
- Third-party service principal access
- Guest accounts with elevated permissions
- Federated trust relationships between domains/tenants

## 2. Attack Vectors

### 2.1 Partner/CSP Account Compromise

**Description:**
Adversaries compromise a Microsoft Partner or CSP account that has delegated admin permissions to customer tenants.

**Attack Scenario:**
1. Attacker compromises partner admin credentials
2. Uses Partner Center or Admin APIs to identify customer tenants
3. Leverages delegated permissions to access customer environments
4. Establishes persistence by creating new admin accounts

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Add partner to company.",
    "Add delegation entry.",
    "Set delegation entry.",
    "Add member to role."
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T15:22:43",
  "Id": "8382d091-9cd3-4b1a-9e1f-23412c44a112",
  "Operation": "Add partner to company.",
  "OrganizationId": "b7f4bc5c-f87a-4a12-b1b9-112c44a11245",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "partner@contoso.com",
  "UserType": 2,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "Partner_Access_f87a112c44a11245",
  "UserId": "partner@contoso.com",
  "PartnerTenantId": "c4b12d56-9b1a-4512-b7b9-986532ac1123"
}
```

### 2.2 Service Principal Elevation

**Description:** 
Attackers manipulate service principal permissions to gain elevated access.

**Attack Scenario:**
1. Compromise existing service principal credentials
2. Add additional API permissions/roles
3. Create new credential secrets
4. Use elevated access to extract data/create backdoors

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Add service principal.",
    "Add service principal credentials.",
    "Add member to role.",
    "Set delegation entry."
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T16:14:22",
  "Id": "92846ac2-1245-4c23-b44a-986532ac1123", 
  "Operation": "Add service principal credentials.",
  "OrganizationId": "b7f4bc5c-f87a-4a12-b1b9-112c44a11245",
  "RecordType": 1,
  "ResultStatus": "Success", 
  "UserKey": "admin@contoso.com",
  "UserType": 1,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "ServicePrincipal_b44a986532ac1123",
  "KeyId": "8d4e6a12-9c56-4512-a44b-112c44a11245",
  "KeyType": "Password"
}
```

### 2.3 Cross-Tenant Trust Abuse

**Description:**
Adversaries exploit federated trust relationships between tenants.

**Attack Scenario:**
1. Compromise account in trusted tenant
2. Create/modify federation trust settings
3. Generate forged SAML tokens
4. Access resources in target tenant

**Relevant Audit Operations:**
```json
{
  "Operations": [
    "Set federation settings on domain.",
    "Update domain.",
    "Set domain authentication.",
    "Add domain to company."
  ]
}
```

**Example Audit Log:**
```json
{
  "CreationTime": "2024-01-15T17:33:11",
  "Id": "7251abc3-9e45-4d12-8856-112c44a11245",
  "Operation": "Set federation settings on domain.", 
  "OrganizationId": "b7f4bc5c-f87a-4a12-b1b9-112c44a11245",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com", 
  "UserType": 1,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "contoso.com",
  "DomainName": "contoso.com",
  "FederationBrandName": "Contoso Federated Login",
  "IssuerUri": "http://sts.contoso.com/adfs/services/trust"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect unusual partner access patterns
SELECT UserId, Operation, COUNT(*) as access_count
FROM AuditLogs 
WHERE Operation IN ('Add partner to company','Add delegation entry')
  AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING COUNT(*) > 10;

-- Monitor service principal credential changes
SELECT ObjectId, COUNT(*) as cred_changes
FROM AuditLogs
WHERE Operation = 'Add service principal credentials'
  AND TimeGenerated > ago(24h)
GROUP BY ObjectId
HAVING COUNT(*) > 3;

-- Track federation configuration changes
SELECT UserId, COUNT(*) as fed_changes
FROM AuditLogs
WHERE Operation LIKE '%federation%'
  AND TimeGenerated > ago(7d)
GROUP BY UserId
HAVING COUNT(*) > 2;
```

### 3.2 Baseline Deviation Monitoring

- Partner access activity outside business hours
- Service principal permission changes from non-admin accounts
- Federation changes without change management tickets
- Multiple partner relationship changes in short timeframe

### 3.3 Priority Alert Conditions 

- New partner delegation during off hours
- Service principal credential additions from unknown IPs
- Federation trust changes to untrusted domains
- Multiple failed partner access attempts

## 4. Mitigation Strategies

### 4.1 Administrative Controls

1. Partner/CSP Access:
- Implement approval workflow for partner relationship changes
- Regular review of partner access rights
- Enable MFA for all partner accounts

2. Service Principals:
- Restrict service principal creation to approved admins
- Implement credential rotation process
- Regular permissions review

3. Federation:
- Change control process for federation changes
- Restrict federation to approved domains
- Monitor federation configuration

### 4.2 Technical Controls

```json
{
  "ConditionalAccessPolicies": {
    "PartnerAccess": {
      "UserRiskLevels": ["high"],
      "SignInRiskLevels": ["medium", "high"],
      "ClientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
      "Conditions": {
        "RequireMFA": true,
        "AllowedLocations": ["US", "CA"],
        "BlockUntrustedDevices": true
      }
    }
  },
  "ServicePrincipalRestrictions": {
    "AllowedCreators": ["GlobalAdmin", "CloudAppAdmin"],
    "RequireApproval": true,
    "MaxCredentialLifetime": "90.00:00:00"
  }
}
```

### 4.3 Monitoring Controls

1. Real-time alerts:
- Partner access outside business hours
- Service principal credential changes
- Federation configuration modifications

2. Daily reviews:
- New partner relationships
- Service principal permission changes
- Federation trust modifications

3. Weekly reports:
- Partner access patterns
- Service principal usage
- Federation activity summary

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Identify affected accounts/principals
2. Document timeline of suspicious activity
3. Preserve audit logs
4. Notify security team and stakeholders

### 5.2 Investigation
1. Review partner access logs
2. Analyze service principal changes
3. Audit federation configurations
4. Identify scope of compromise

### 5.3 Containment
1. Revoke compromised credentials
2. Remove unauthorized permissions
3. Disable suspicious federation trusts
4. Block malicious partner access

## 6. References

- [MITRE T1199](https://attack.mitre.org/techniques/T1199/)
- [Microsoft Partner Security Requirements](https://learn.microsoft.com/en-us/partner-center/partner-security-requirements)
- [Microsoft Service Principal Security](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
- [Microsoft Federation Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/whatis-fed)

---

# Threat Model: Cloud Account (T1136.003) in Microsoft 365 & Entra ID

## Overview
Adversaries create new cloud accounts in Microsoft 365 and Entra ID to establish persistence and maintain access. This can include regular user accounts, service principals, and managed identities with varying levels of permissions.

## Attack Vectors

### 1. Service Principal Creation

**Description:**
Adversaries create new service principals with OAuth app registrations to maintain backdoor access.

**Attack Scenario:**
1. Attacker compromises Global Admin account
2. Creates new "integration" service principal
3. Assigns Directory.ReadWrite.All permissions
4. Adds credentials for persistent access

**Relevant Audit Operations:**
- Add service principal
- Add service principal credentials
- Add delegation entry

**Example Audit Log:**
```json
{
  "Operation": "Add service principal.",
  "ObjectId": "d429a9e8-8ea8-4e38-b4f5-8f9293ef2f1f",
  "ResultStatus": "Success", 
  "Actor": {
    "Id": "admin@contoso.com",
    "Type": "User"
  },
  "Target": {
    "Id": "integration-app-svc",
    "Type": "ServicePrincipal"
  },
  "AdditionalDetails": {
    "PermissionScopes": ["Directory.ReadWrite.All"],
    "AppId": "a12b3c45-e6f7-89gh-i0jk-lmnopqrstuvw"
  }
}
```

### 2. Guest Account Creation 

**Description:**
Adversaries create external guest accounts to maintain access while appearing legitimate.

**Attack Scenario:**
1. Compromises user with invite privileges
2. Creates guest account with plausible business email
3. Assigns minimal permissions to avoid detection
4. Uses account for persistent access

**Relevant Audit Operations:**
- Add user
- Add member to group
- Update user

**Example Audit Log:**
```json
{
  "Operation": "Add user.",
  "ObjectId": "9a48c28e-4e36-4524-8d9f-15a4137195cb",
  "ResultStatus": "Success",
  "Actor": {
    "Id": "manager@contoso.com",
    "Type": "User"
  },
  "Target": {
    "Id": "consultant@partner.com", 
    "Type": "User",
    "UserType": "Guest"
  },
  "AdditionalDetails": {
    "UserPrincipalName": "consultant_partner.com#EXT#@contoso.onmicrosoft.com",
    "Department": "Consulting",
    "AccountEnabled": true
  }
}
```

### 3. Managed Identity Assignment

**Description:**
Adversaries create managed identities for Azure resources with excessive permissions.

**Attack Scenario:**
1. Creates Azure function app
2. Assigns system-assigned managed identity
3. Grants elevated Azure/M365 permissions
4. Uses identity for backdoor access

**Relevant Audit Operations:**
- Add service principal
- Add member to role
- Set delegation entry

**Example Audit Log:**
```json
{
  "Operation": "Add member to role.",
  "ObjectId": "7d1467f2-9c4a-43e8-b0a9-4fc5c2b501e7",
  "ResultStatus": "Success",
  "Actor": {
    "Id": "admin@contoso.com",
    "Type": "User"  
  },
  "Target": {
    "Id": "func-app-mi",
    "Type": "ServicePrincipal",
    "ResourceType": "ManagedIdentity" 
  },
  "AdditionalDetails": {
    "RoleName": "Exchange Administrator",
    "Scope": "/"
  }
}
```

## Detection Strategies

### Behavioral Analytics Rules

1. Service Principal Creation Anomalies
```sql
SELECT Actor.Id, COUNT(*) as count
FROM AuditLogs 
WHERE Operation = "Add service principal."
AND TimeGenerated > ago(1h)
GROUP BY Actor.Id
HAVING count > 3
```

2. Guest Account Pattern Analysis
```sql
SELECT Target.UserPrincipalName, COUNT(*) as count  
FROM AuditLogs
WHERE Operation IN ("Add user.") 
AND Target.UserType = "Guest"
AND TimeGenerated > ago(24h)
GROUP BY Target.UserPrincipalName
HAVING count > usual(count, 50%) 
```

3. Role Assignment Velocity
```sql
SELECT Actor.Id, COUNT(DISTINCT Target.Id) as targets
FROM AuditLogs
WHERE Operation = "Add member to role."
AND TimeGenerated > ago(1h)
GROUP BY Actor.Id
HAVING targets > 5
```

### Baseline Deviation Monitoring

1. Monitor daily averages for:
- New service principal creation rate
- Guest account creation volume
- Admin role assignments
- Permission scope changes

2. Alert on deviations:
- >2x standard deviation from baseline
- Sudden spikes in activity
- Off-hours activity
- Unusual source locations

### Correlation Rules

1. Service Principal Chain:
```sql
CREATE ALERT 
WHERE (Operation = "Add service principal.")
AND THEN 
(Operation = "Add service principal credentials." 
 OR Operation = "Add delegation entry.")
WITHIN 1 hour
```

## Mitigation Strategies

### Administrative Controls
1. Enforce JIT/PAM for admin access
2. Require MFA for all account creation
3. Limit guest invite privileges
4. Regular access reviews

### Technical Controls
```json
{
  "ConditionalAccessPolicy": {
    "Name": "Block High-Risk Account Creation",
    "State": "enabled",
    "Conditions": {
      "UserRiskLevels": ["high"],
      "ClientAppTypes": ["all"],
      "Applications": {
        "Include": ["d1ddf0e4-d672-4dae-b554-9d5bdfd93547"] // Azure MGMT
      }
    },
    "GrantControls": {
      "Operator": "OR",
      "BuiltInControls": ["block"]
    }
  }
}
```

### Monitoring Controls
1. Enable unified audit logging
2. Monitor service principal activity
3. Track guest account lifecycle
4. Alert on privileged role changes

## Incident Response Playbook

### Initial Detection
1. Validate alert authenticity
2. Identify affected resources
3. Document initial findings
4. Establish timeline

### Investigation
1. Review audit logs for:
   - Account creation context
   - Associated permissions
   - Usage patterns
2. Identify linked resources
3. Map lateral movement

### Containment
1. Disable suspicious accounts
2. Revoke credentials
3. Remove excessive permissions
4. Block associated IPs

## References
- [MITRE ATT&CK T1136.003](https://attack.mitre.org/techniques/T1136/003/)
- [Microsoft Service Principals](https://docs.microsoft.com/azure/active-directory/develop/app-objects-and-service-principals)
- [Microsoft Managed Identities](https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview)

---

# Threat Model: Account Manipulation (T1098) in Microsoft 365 & Entra ID

## Overview
Account manipulation in Microsoft 365 and Entra ID involves adversaries modifying account settings, permissions, and credentials to maintain persistence and escalate privileges. Common techniques include modifying group memberships, adding additional credentials to service principals, and manipulating authentication methods.

## Attack Vectors

### 1. Service Principal Credential Addition
**Description**: Adversaries add additional credentials (passwords/certificates) to existing service principals to maintain access even if the original credentials are rotated.

**Attack Scenario**:
```text
1. Attacker compromises Global Admin account
2. Adds new credentials to high-privilege service principals
3. Uses new credentials for persistent access even after detection
```

**Relevant Audit Operations**:
- Add service principal credentials
- Update service principal
- Set service principal properties

**Example Audit Log**:
```json
{
  "Operation": "Add service principal credentials",
  "ObjectId": "d5e0e132-3345-4e78-9af9-4d91cc401cb4",
  "ResultStatus": "Success",
  "Actor": {
    "ID": "admin@contoso.com",
    "Type": "User"
  },
  "Target": {
    "ID": "salesforce-integration-app",
    "Type": "ServicePrincipal"
  },
  "ModifiedProperties": [{
    "Name": "KeyCredentials",
    "NewValue": "[{\"KeyId\":\"bc87b4a5-31c4-422c-b8c5-2304583c3776\"}]"
  }]
}
```

### 2. Privileged Group Manipulation
**Description**: Attackers add compromised accounts to highly privileged groups to maintain elevated access.

**Attack Scenario**:
```text
1. Attacker compromises user account
2. Adds account to Global Admin/Privileged Role Admin groups
3. Uses elevated privileges for further attacks
```

**Relevant Audit Operations**:
- Add member to group
- Add member to role
- Update group

**Example Audit Log**:
```json
{
  "Operation": "Add member to group",
  "ObjectId": "Global-Administrators",
  "ResultStatus": "Success",
  "Actor": {
    "ID": "attacker@contoso.com",
    "Type": "User"
  },
  "Target": {
    "ID": "compromised@contoso.com",
    "Type": "User"
  },
  "ModifiedProperties": [{
    "Name": "Group.DisplayName",
    "OldValue": "",
    "NewValue": "Global Administrators"
  }]
}
```

### 3. Authentication Method Manipulation
**Description**: Adversaries add additional authentication methods to compromised accounts to bypass MFA.

**Attack Scenario**:
```text
1. Attacker gains initial access to account
2. Registers new phone number for SMS MFA
3. Uses new MFA method to maintain access
```

**Relevant Audit Operations**:
- Update user
- Change authentication method
- Register security info

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect multiple credential additions to service principals
SELECT ServicePrincipalId, COUNT(*) as CredentialAdditions
FROM AuditLogs 
WHERE Operation = "Add service principal credentials"
AND TimeGenerated > ago(1h)
GROUP BY ServicePrincipalId
HAVING COUNT(*) > 3;

-- Detect privileged group additions outside business hours
SELECT TargetUserPrincipalName
FROM AuditLogs
WHERE Operation = "Add member to group"
AND TargetGroup IN ('Global Administrators', 'Privileged Role Administrators')
AND TimeGenerated NOT BETWEEN '0900' AND '1700';
```

### Baseline Deviation Monitoring
- Monitor for spikes in authentication method changes
- Track unusual patterns of group membership modifications
- Alert on service principal credential additions above historical baseline

### Technical Controls (JSON)
```json
{
  "conditionalAccessPolicies": {
    "servicePrincipalCredentials": {
      "maxCredentialsPerApp": 2,
      "requireApproval": true,
      "approverGroups": ["security-team@contoso.com"]
    },
    "groupMembership": {
      "privilegedGroupChanges": {
        "requireMFA": true,
        "requireJustification": true,
        "notifySecurityTeam": true
      }
    }
  }
}
```

## Incident Response Playbook

### Initial Detection
1. Review audit logs for suspicious operations
2. Identify affected accounts and resources
3. Document timeline of modifications

### Investigation
1. Map all changes made by suspected compromise
2. Review authentication patterns before/after changes
3. Identify source accounts and IP addresses
4. Correlate with other suspicious activities

### Containment
1. Revoke added credentials
2. Remove unauthorized group memberships 
3. Reset compromised account passwords
4. Enable additional monitoring

## References
- [MITRE T1098](https://attack.mitre.org/techniques/T1098/)
- [Microsoft Service Principal Security](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
- [Detecting Suspicious Azure AD Activity](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs)

---

# Threat Model: Exfiltration Over Alternative Protocol (T1048) in Microsoft 365 & Entra ID

## 1. Overview
In Microsoft 365 and Entra ID environments, adversaries commonly exfiltrate data using alternative protocols like email forwarding, SharePoint downloads, or Teams file sharing rather than their primary C2 channel. This allows them to blend in with normal business traffic while moving data out of the environment.

## 2. Attack Vectors

### 2.1 Email Forwarding Rules
**Description**: Adversaries create inbox rules to automatically forward emails to external addresses.

**Attack Scenario**:
1. Attacker compromises user account
2. Creates forwarding rule to external email
3. All incoming mail is automatically forwarded

**Detection Fields**:
```json
{
  "Operation": "New-InboxRule",
  "ObjectId": "[RuleIdentifier]", 
  "Parameters": {
    "ForwardTo": "external@domain.com",
    "DeleteMessage": "True"
  },
  "UserId": "[Actor]",
  "ClientIP": "[Source IP]"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "8382289c-b9d4-4a1a-a40c-c80437485324",
  "Operation": "New-InboxRule", 
  "OrganizationId": "abc123",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserId": "bob@victim.com",
  "Parameters": {
    "ForwardTo": ["attacker@evil.com"],
    "DeleteMessage": true,
    "Name": "Process Invoices"
  },
  "ClientIP": "192.168.1.100"
}
```

### 2.2 SharePoint Mass Download
**Description**: Adversaries download large volumes of files from SharePoint sites.

**Detection Fields**:
```json
{
  "Operation": "FileDownloaded",
  "SiteUrl": "[SharePoint URL]",
  "SourceFileName": "[File Name]",
  "UserId": "[Actor]",
  "ClientIP": "[Source IP]"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22", 
  "Operation": "FileDownloaded",
  "SiteUrl": "https://victim.sharepoint.com/sites/Finance",
  "SourceFileName": "Q4_Financials.xlsx",
  "UserId": "alice@victim.com",
  "ClientIP": "10.1.1.100",
  "ObjectId": "https://victim.sharepoint.com/sites/Finance/Shared Documents/Q4_Financials.xlsx",
  "CorrelationId": "15bec489-c467-4081-b5ce-47970e91c577"
}
```

### 2.3 Teams External File Sharing
**Description**: Adversaries share sensitive files with external users via Teams.

**Detection Fields**:
```json
{
  "Operation": "SharingInvitationCreated", 
  "ObjectId": "[File Path]",
  "UserId": "[Actor]",
  "TargetUserOrGroupName": "[External User]",
  "ClientIP": "[Source IP]"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T17:33:12",
  "Operation": "SharingInvitationCreated",
  "ObjectId": "/Finance/Strategic Plans/2024_Roadmap.pptx",
  "UserId": "carol@victim.com", 
  "TargetUserOrGroupName": "partner@external.com",
  "ClientIP": "172.16.5.100",
  "SharingType": "Direct",
  "EventSource": "SharePoint"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect mass file downloads
SELECT UserId, COUNT(*) as download_count
FROM AuditLogs 
WHERE Operation = 'FileDownloaded'
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 100;

-- Detect suspicious email forwarding
SELECT UserId, COUNT(*) as rule_count
FROM AuditLogs
WHERE Operation = 'New-InboxRule'
AND Parameters.ForwardTo LIKE '%@external%'
AND TimeGenerated > ago(24h)
GROUP BY UserId
HAVING COUNT(*) > 3;
```

### 3.2 Baseline Deviation Monitoring
- Monitor daily averages for:
  - File downloads per user
  - External sharing actions
  - New inbox rules created
- Alert on deviations >3 standard deviations

### 3.3 Technical Controls
```json
{
  "mailboxForwardingRules": {
    "enabled": false,
    "allowedDomains": ["trusted-partner.com"],
    "notificationRecipients": ["security@company.com"]
  },
  "sharingControls": {
    "maxFilesPerHour": 50,
    "externalSharingRequiresApproval": true
  }
}
```

## 4. Mitigation Strategies

### Administrative Controls
1. Configure DLP policies to detect sensitive data exfiltration
2. Implement conditional access policies restricting external access
3. Enable auditing for all workloads
4. Configure alerts for suspicious forwarding rules

### Technical Controls
1. Block automatic email forwarding to external domains
2. Restrict SharePoint external sharing capabilities
3. Enable Microsoft Defender for Cloud Apps policies
4. Implement data loss prevention rules

### Monitoring Controls
1. Enable alerts for mass downloads
2. Monitor external sharing trends
3. Track inbox rule creation
4. Implement UEBA monitoring

## 5. Response Playbook

### Initial Detection
1. Identify affected accounts/resources
2. Document exfiltration method used
3. Quantify data exposure

### Investigation
1. Review audit logs for initial access vector
2. Identify other compromised accounts
3. Document timeline of activity
4. Determine data staging locations

### Containment
1. Disable compromised accounts
2. Remove malicious inbox rules
3. Revoke shared file access
4. Block suspicious IPs

## 6. References

1. [MITRE T1048](https://attack.mitre.org/techniques/T1048/)
2. [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
3. [Microsoft 365 Defender](https://security.microsoft.com/)
4. [Azure Sentinel Detection Rules](https://github.com/Azure/Azure-Sentinel)

---

# Threat Model: Phishing (T1566) in Microsoft 365 & Entra ID

## 1. Overview
In Microsoft 365 and Entra ID environments, phishing attacks commonly target user credentials and OAuth permissions through:
- Credential harvesting via spoofed login pages
- OAuth consent phishing for malicious apps
- Business email compromise through account takeover
- Email-based malware delivery

## 2. Attack Vectors

### 2.1 OAuth Consent Phishing
**Description**: Adversaries create malicious OAuth apps requesting broad permissions and trick users into granting consent.

**Detection Fields**:
```json
{
  "Operation": "ConsentModificationRequest",
  "Application": {
    "Name": string,
    "Id": GUID,
    "RequestedPermissions": string[]
  },
  "Actor": {
    "UserId": string,
    "UserType": string
  },
  "Result": string
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "4a22bc3c-487a-4fc1-92bb-d98749612545",
  "Operation": "ConsentModificationRequest",
  "OrganizationId": "d124f588-18cc-4f0b-8f94-f86d80a6b623", 
  "RecordType": 8,
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "d124f588-18cc-4f0b-8f94-f86d80a6b623",
  "Application": {
    "Name": "Document Reader Pro",
    "Id": "a942b3c5-43a1-42c4-8594-f8ce52a12c7a",
    "RequestedPermissions": [
      "Mail.Read",
      "Mail.Send",
      "Files.ReadWrite.All"
    ]
  }
}
```

### 2.2 Business Email Compromise
**Description**: Adversaries compromise accounts and create email rules to hide their activity.

**Detection Fields**:
```json
{
  "Operation": "New-InboxRule",
  "Parameters": {
    "ForwardTo": string[],
    "DeleteMessage": boolean,
    "MoveToFolder": string
  },
  "ClientIP": string,
  "UserId": string
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22",
  "Operation": "New-InboxRule",
  "ClientIP": "198.51.100.12",
  "UserId": "victim@contoso.com",
  "Parameters": {
    "ForwardTo": ["attacker@evil.com"],
    "DeleteMessage": true,
    "MoveToFolder": "Deleted Items"
  },
  "ResultStatus": "Success"
}
```

### 2.3 Credential Theft Attack
**Description**: Adversaries attempt password spraying or credential stuffing attacks.

**Detection Fields**:
```json
{
  "Operation": "UserLoggedIn", 
  "LogonError": string,
  "UserAgent": string,
  "IPAddress": string,
  "Location": {
    "City": string,
    "Country": string
  }
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T10:15:44",
  "Operation": "UserLoggedIn",
  "UserId": "user@contoso.com",
  "LogonError": "InvalidPassword",
  "IPAddress": "203.0.113.42",
  "UserAgent": "Mozilla/5.0...",
  "Location": {
    "City": "Unknown",
    "Country": "RU"
  }
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- OAuth Suspicious Consent Grants
SELECT Application.Name, COUNT(*) as grant_count
FROM ConsentModificationRequest
WHERE TimeGenerated > ago(1h)
GROUP BY Application.Name
HAVING count(*) > 10;

-- Suspicious Inbox Rules
SELECT UserId, COUNT(*) as rule_count
FROM New-InboxRule
WHERE TimeGenerated > ago(24h)
  AND (Parameters.ForwardTo IS NOT NULL 
       OR Parameters.DeleteMessage = true)
GROUP BY UserId
HAVING count(*) > 3;

-- Failed Login Attempts
SELECT UserId, IPAddress, COUNT(*) as failure_count
FROM UserLoggedIn
WHERE TimeGenerated > ago(10m)
  AND LogonError = 'InvalidPassword'
GROUP BY UserId, IPAddress
HAVING count(*) > 5;
```

### 3.2 Baseline Deviations
- Monitor for abnormal OAuth consent patterns vs typical daily baseline
- Track inbox rule creation frequency per user
- Alert on login attempts from new countries/regions

## 4. Mitigation Strategies

### Administrative Controls
1. Configure OAuth app consent policies:
   - Restrict consent to verified publishers
   - Require admin approval for high-risk permissions
2. Enable MFA for all users
3. Block legacy authentication protocols

### Technical Controls
```json
{
  "ConditionalAccessPolicies": {
    "Name": "Block Legacy Authentication",
    "Conditions": {
      "ClientAppTypes": ["ExchangeActiveSync", "Other"],
      "Action": "Block"
    }
  },
  "AuthenticationStrengthPolicies": {
    "RequireMFA": true,
    "AllowedMFAMethods": ["Authenticator", "FIDO2"]
  }
}
```

### Monitoring Controls
1. Enable Unified Audit Logging
2. Configure alerts for:
   - Mass OAuth consent grants
   - Suspicious inbox rules
   - Authentication anomalies

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected users and applications
2. Review audit logs for OAuth consents and inbox rules
3. Check for suspicious login patterns

### Investigation
1. Review OAuth permissions granted to suspicious apps
2. Analyze email forwarding rules and delegates
3. Check for additional compromised accounts

### Containment
1. Revoke suspicious OAuth grants
2. Reset compromised credentials
3. Remove malicious inbox rules
4. Block known phishing domains

## 6. References
- [MITRE T1566](https://attack.mitre.org/techniques/T1566/)
- [Microsoft OAuth Phishing Guidance](https://docs.microsoft.com/security/oauth-phishing)
- [Microsoft BEC Protection](https://docs.microsoft.com/security/bec-protection)

---

# Threat Model: Brute Force (T1110) in Microsoft 365 & Entra ID

## 1. Overview

Brute force attacks in Microsoft 365 and Entra ID typically manifest as repeated authentication attempts against user accounts through various endpoints including:
- Azure Portal Authentication
- Exchange Online Authentication 
- SharePoint Online Authentication
- Microsoft Graph API Authentication

## 2. Attack Vectors

### 2.1 Password Spray Attacks

**Description**: Attackers try a small set of common passwords against many accounts to avoid account lockouts.

**Scenario**: Attacker attempts to authenticate as different users using common passwords like "Spring2024!" across hundreds of accounts.

**Relevant Audit Operations**:
- UserLoggedIn
- UserLoggedOff
- MailboxLogin

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "44c2-4853-92d4",
  "Operation": "UserLoggedIn", 
  "OrganizationId": "4a7c8f9e-9f87",
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserKey": "10032001A42SDF",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "192.168.1.100",
  "ObjectId": "john.smith@company.com",
  "UserId": "john.smith@company.com",
  "AzureActiveDirectoryEventType": 0,
  "ExtendedProperties": [
    {
      "Name": "LoginError",
      "Value": "InvalidPassword"
    }
  ]
}
```

### 2.2 Credential Stuffing 

**Description**: Attackers use leaked username/password pairs from other breaches.

**Scenario**: Attacker attempts to authenticate using previously exposed credentials.

**Relevant Audit Operations**:
- Add user.
- Change user password.
- Reset user password.

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-15T10:23:45",
  "Id": "5789-7854-985d",
  "Operation": "Change user password.",
  "OrganizationId": "4a7c8f9e-9f87",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "10032001A42SDF",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "victim@company.com",
  "UserId":"attacker@company.com",
  "ModifiedProperties": [
    {
      "Name": "PasswordChange",
      "NewValue": "[New Hash]",
      "OldValue": "[Old Hash]"
    }
  ]
}
```

### 2.3 Password Reset Abuse

**Description**: Attackers attempt to exploit self-service password reset functionality.

**Relevant Audit Operations**:
- Set force change user password.
- Reset user password.

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Password Spray Detection
SELECT UserPrincipalName, ClientIP, COUNT(*) as FailedAttempts
FROM AuditLogs 
WHERE Operation = 'UserLoggedIn'
AND ResultStatus = 'Failed'
AND Timestamp >= NOW() - INTERVAL 1 HOUR
GROUP BY UserPrincipalName, ClientIP
HAVING COUNT(*) > 10;

-- Credential Stuffing Detection
SELECT ClientIP, COUNT(DISTINCT UserPrincipalName) as UniqueUsers
FROM AuditLogs
WHERE Operation = 'UserLoggedIn' 
AND ResultStatus = 'Failed'
AND Timestamp >= NOW() - INTERVAL 30 MINUTES
GROUP BY ClientIP
HAVING COUNT(DISTINCT UserPrincipalName) > 20;
```

### 3.2 Baseline Deviation Monitoring

- Track normal authentication patterns per user
- Alert on deviations:
  - Login attempts outside normal hours
  - Login attempts from new locations
  - Abnormal frequency of password resets

### 3.3 Threshold Alerts

- More than 10 failed logins per user within 1 hour
- More than 5 password resets per hour across organization
- More than 20 unique users with failed logins from same IP

## 4. Technical Controls

```json
{
  "conditionalAccessPolicies": {
    "signInRiskPolicy": {
      "state": "enabled",
      "conditions": {
        "signInRiskLevels": ["high", "medium"],
        "applications": {"includeApplications": ["all"]}
      },
      "grantControls": {
        "operator": "OR",
        "builtInControls": ["mfa"]
      }
    },
    "locationPolicy": {
      "state": "enabled", 
      "conditions": {
        "locations": {"includeLocations": ["all"]},
        "applications": {"includeApplications": ["all"]}
      },
      "grantControls": {
        "operator": "AND",
        "builtInControls": ["compliantDevice", "mfa"]
      }
    }
  },
  "passwordPolicy": {
    "minimumLength": 12,
    "requireComplexity": true,
    "preventPasswordReuse": 24,
    "lockoutThreshold": 10,
    "lockoutDurationMinutes": 30
  }
}
```

## 5. Administrative Controls

1. Implement strong password policies
2. Enable MFA for all accounts
3. Block legacy authentication protocols
4. Implement smart lockout
5. Enable risk-based conditional access
6. Regular access reviews

## 6. Monitoring Controls

1. Configure audit logging for all critical operations
2. Enable Azure AD Identity Protection
3. Monitor authentication patterns
4. Review sign-in logs daily
5. Alert on suspicious activities

## 7. Incident Response

### Initial Detection
1. Review Azure AD sign-in logs
2. Identify affected accounts
3. Check IP addresses and locations
4. Review user agent strings

### Investigation
1. Timeline analysis of login attempts
2. Pattern analysis of targeted accounts
3. Correlation with other security events
4. Geolocation analysis of source IPs

### Containment
1. Reset affected passwords
2. Enable MFA
3. Block suspicious IPs
4. Increase monitoring

## References

1. MITRE ATT&CK T1110
2. Azure AD Sign-in Logs Schema
3. Microsoft Security Documentation
4. Azure Identity Protection Documentation

---

# Threat Model: Outlook Forms (T1137.003) in Microsoft 365 & Entra ID

## 1. Overview
Adversaries can abuse Microsoft Outlook forms to establish persistence by creating malicious forms that execute code when specific trigger emails are received. The forms are loaded when Outlook starts and remain persistent until removed.

## 2. Attack Vectors

### Vector 1: Custom Form Creation
**Description**: Attacker creates a malicious Outlook form with embedded code
**Attack Flow**:
1. Compromise user credentials 
2. Access Outlook forms designer
3. Create form with malicious VBA code
4. Save form to user's mailbox

**Relevant Audit Operations**:
```json
{
  "Operation": "New-InboxRule",
  "UserKey": "victim@company.com",
  "ClientIP": "10.1.1.1",
  "Parameters": {
    "RuleName": "Project Updates",
    "Template": "CustomForm123",
    "Enabled": true
  }
}
```

### Vector 2: Form Distribution via Sharing
**Description**: Attacker shares malicious form across mailboxes
**Attack Flow**:
1. Create malicious form in compromised mailbox
2. Use sharing features to deploy to other users
3. Form loads automatically for recipients

**Relevant Audit Operations**:
```json
{
  "Operation": "AddFolderPermissions",
  "UserKey": "attacker@company.com", 
  "TargetUserOrGroupName": "AllUsers",
  "FolderPath": "\\Forms",
  "AccessRights": "Reviewer"
}
```

### Vector 3: Form Persistence Through Rules
**Description**: Attacker creates rules to maintain form execution
**Attack Flow**: 
1. Deploy malicious form
2. Create inbox rule to process specific trigger emails
3. Rule ensures form loads and executes

**Relevant Audit Operations**:
```json
{
  "Operation": "Set-InboxRule",
  "UserKey": "victim@company.com",
  "Parameters": {
    "RuleId": "Rule123",
    "Conditions": {
      "FromAddress": "trigger@attacker.com",
      "UseCustomForm": true,
      "FormName": "MaliciousForm"  
    }
  }
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect unusual form creation patterns
SELECT UserKey, COUNT(*) as FormCount
FROM AuditLogs 
WHERE Operation IN ('New-InboxRule', 'Set-InboxRule')
AND Template IS NOT NULL
GROUP BY UserKey, DATE(Timestamp)
HAVING FormCount > 3; -- Baseline threshold

-- Monitor form sharing activity
SELECT UserKey, TargetUserOrGroupName
FROM AuditLogs
WHERE Operation = 'AddFolderPermissions' 
AND FolderPath LIKE '%Forms%'
AND AccessRights NOT IN ('Reviewer', 'None');
```

### Baseline Deviation Monitoring
- Track normal form usage patterns per user/dept
- Alert on:
  - Sudden increase in form creation
  - Mass form sharing events
  - Forms with embedded code
  - Forms targeting sensitive mailboxes

## 4. Mitigation Controls

### Technical Controls
```json
{
  "OutlookFormSettings": {
    "DisableCustomForms": true,
    "BlockUntrustedPublishers": true,
    "RequireApproval": true,
    "AllowedFormLocations": [
      "ApprovedTemplateLibrary"
    ]
  },
  "ExchangeTransportRules": {
    "BlockExecutableAttachments": true,
    "ScanEmbeddedCode": true
  }
}
```

### Administrative Controls
1. Restrict form publishing permissions
2. Implement form approval workflow
3. Regular form template audits
4. User training on form security

### Monitoring Controls
1. Enable advanced audit logging
2. Monitor form creation/modification events
3. Track form usage patterns
4. Alert on suspicious form behaviors

## 5. Incident Response

### Initial Response
1. Identify affected mailboxes
2. Disable suspect forms
3. Block trigger email addresses
4. Preserve evidence

### Investigation
1. Review form audit logs
2. Analyze form code/macros
3. Track form distribution
4. Identify compromise vector

### Containment
1. Remove malicious forms
2. Reset affected accounts
3. Block attacker infrastructure
4. Update security policies

## 6. References
- [MITRE T1137.003](https://attack.mitre.org/techniques/T1137/003/)
- [Microsoft Form Security](https://docs.microsoft.com/security)
- [Exchange Online Protection](https://docs.microsoft.com/exchange/security-and-compliance/)

---

# Threat Model: Valid Accounts (T1078) in Microsoft 365 & Entra ID

## 1. Overview
Valid accounts abuse in Microsoft 365 and Entra ID environments involves adversaries obtaining and misusing legitimate credentials to access resources while appearing as normal users. This technique is particularly dangerous in cloud environments due to the broad access available through the Microsoft 365 admin center, Exchange Online PowerShell, and Microsoft Graph API.

## 2. Attack Vectors

### 2.1 Account Enumeration & Password Spraying
**Description**: Adversaries enumerate valid accounts through directory harvesting and attempt password spraying against discovered accounts.

**Detection Fields**:
```json
{
  "Operation": "UserLoggedIn", 
  "UserId": "user@domain.com",
  "ClientIP": "1.2.3.4",
  "UserAgent": "string",
  "ResultStatus": "Success/Failure",
  "LogonError": "InvalidPassword",
  "ApplicationId": "guid"
}
```

**Example Attack Pattern**:
```json
{
  "CreationTime": "2024-01-20T10:00:00",
  "Operation": "UserLoggedIn",
  "UserId": "john.smith@company.com", 
  "ClientIP": "45.76.123.45",
  "ResultStatus": "Failed",
  "LogonError": "InvalidPassword",
  "ApplicationId": "1b730954-1685-4b74-9bfd-dac224a7b894"
}
// Multiple failures across different accounts with same password pattern
```

### 2.2 Privileged Account Takeover
**Description**: Adversaries compromise admin accounts through various means and use them for persistence and privilege escalation.

**Detection Fields**:
```json
{
  "Operation": "Add member to role",
  "ObjectId": "guid",
  "RoleName": "Global Administrator",
  "TargetUserOrGroupName": "string",
  "Actor": ["DisplayName", "ID"],
  "ActorIPAddress": "string"
}
```

**Example Attack Pattern**:
```json
{
  "CreationTime": "2024-01-20T15:30:00",
  "Operation": "Add member to role",
  "RoleName": "Global Administrator", 
  "TargetUserOrGroupName": "backdoor.admin",
  "Actor": "compromised.admin@company.com",
  "ActorIPAddress": "103.45.234.12"
}
```

### 2.3 Service Principal Abuse
**Description**: Adversaries create or manipulate service principals and applications to maintain persistent access.

**Detection Fields**:
```json
{
  "Operation": [
    "Add service principal",
    "Add service principal credentials",
    "Update service principal"
  ],
  "ServicePrincipalId": "guid",
  "ServicePrincipalName": "string",
  "ActorUPN": "string",
  "CredentialType": "string"
}
```

**Example Attack Pattern**:
```json
{
  "CreationTime": "2024-01-20T16:45:00",
  "Operation": "Add service principal credentials",
  "ServicePrincipalName": "Malicious-Integration-App",
  "ActorUPN": "admin@company.com",
  "CredentialType": "Password",
  "ValidityPeriod": "P2Y" // 2 year validity
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect password spraying
SELECT UserId, ClientIP, COUNT(*) as FailureCount
FROM AuditLogs 
WHERE Operation = 'UserLoggedIn'
AND ResultStatus = 'Failed'
AND LogonError = 'InvalidPassword'
GROUP BY UserId, ClientIP, bin(TimeGenerated, 1h)
HAVING COUNT(*) > 10;

-- Detect suspicious admin additions
SELECT * FROM AuditLogs
WHERE Operation = 'Add member to role'
AND RoleName IN ('Global Administrator', 'Privileged Role Administrator')
AND NOT ActorIPAddress IN (known_admin_ips);
```

### 3.2 Baseline Deviation Monitoring
- Track normal patterns of:
  - Login times and locations per user
  - Admin activity frequency and types
  - Service principal creation and credential updates
  - Role membership changes

### 3.3 Correlation Rules 
```sql
-- Correlate suspicious patterns
SELECT * FROM (
  SELECT UserId, 
    COUNT(DISTINCT Operation) as OperationCount,
    COUNT(DISTINCT ResourceId) as ResourceCount
  FROM AuditLogs
  WHERE TimeGenerated > ago(1h)
  GROUP BY UserId
) 
WHERE OperationCount > 50 OR ResourceCount > 100;
```

## 4. Mitigation Strategies

### 4.1 Administrative Controls
- Implement strict privileged access workstation (PAW) requirements
- Require break-glass procedures for emergency access
- Regular access reviews and cleanup of stale accounts

### 4.2 Technical Controls
```json
{
  "ConditionalAccess": {
    "SignInRiskPolicy": {
      "State": "enabled",
      "RiskLevels": ["high", "medium"],
      "Controls": ["mfa", "block"]
    },
    "LocationPolicy": {
      "TrustedLocations": ["corporate-offices"],
      "BlockedLocations": ["high-risk-countries"]
    }
  },
  "AuthenticationStrength": {
    "MinimumRequirement": "phishing-resistant",
    "AllowedMethods": [
      "fido2",
      "certificateBasedAuth"
    ]
  }
}
```

### 4.3 Monitoring Controls
- Real-time alerts on privileged role changes
- Continuous monitoring of service principal activities
- Automated response to suspicious patterns

## 5. Incident Response Playbook

### 5.1 Initial Detection
1. Validate alert authenticity
2. Gather related audit logs
3. Establish timeline of activity

### 5.2 Investigation
1. Review authentication patterns
2. Check for additional compromised accounts
3. Analyze service principal modifications
4. Document scope of access

### 5.3 Containment
1. Suspend compromised accounts
2. Revoke active sessions
3. Reset credentials
4. Remove malicious service principals
5. Document and preserve evidence

## 6. References

- MITRE ATT&CK: T1078
- Microsoft Security Documentation
  - [Protecting Against AD Attacks](https://docs.microsoft.com/security/...)
  - [Securing Privileged Access](https://docs.microsoft.com/security/...)
- Azure AD Attack & Defense Playbook

---

# Threat Model: Account Access Removal (T1531) in Microsoft 365 & Entra ID

## Overview
Adversaries may disrupt business operations by removing access to legitimate user accounts through deletion, deactivation, or credential manipulation in Microsoft 365 and Entra ID. This can be a precursor to ransomware attacks or used to impede incident response.

## Attack Vectors

### 1. Administrative Account Deletion
**Description**: Adversaries with Global Admin privileges delete user accounts to prevent access

**Attack Scenario**:
- Attacker compromises Global Admin account
- Bulk deletes user accounts via Microsoft Graph API or admin portal
- Users lose access to all Microsoft 365 services

**Detection Fields**:
```json
{
  "Operation": "Delete user.",
  "Target": "[UPN of deleted user]",
  "Actor": "[UPN of admin]",
  "ActorIpAddress": "IP",
  "Timestamp": "DateTime",
  "ResultStatus": "Success"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "27c2c434-8e2b-4d55-bb9b-3853a4011223", 
  "Operation": "Delete user.",
  "OrganizationId": "b7c52c70-f861-4551-b067-c3e3c54d62a4",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "victim@contoso.com",
  "UserId": "admin@contoso.com",
  "ClientIP": "192.168.1.100",
  "Scope": "user",
  "Target": ["victim@contoso.com"]
}
```

### 2. Password Reset Attack
**Description**: Adversaries reset passwords of target accounts to deny access

**Attack Scenario**:
- Attacker uses compromised admin account
- Mass resets user passwords via PowerShell
- Users cannot login until passwords are restored

**Detection Fields**:
```json
{
  "Operation": "Reset user password.",
  "Target": "[UPN of affected user]",
  "Actor": "[UPN of admin]",
  "ResultStatus": "Success"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:25:44",
  "Id": "44982a53-9d72-4e88-b292-55bb592c437e",
  "Operation": "Reset user password.",
  "OrganizationId": "b7c52c70-f861-4551-b067-c3e3c54d62a4", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "victim@contoso.com",
  "UserId": "admin@contoso.com",
  "ClientIP": "192.168.1.100",
  "Target": ["victim@contoso.com"]
}
```

### 3. License Removal
**Description**: Adversaries remove license assignments to disable service access

**Attack Scenario**:
- Attacker removes Microsoft 365 licenses
- Users lose access to email, SharePoint, Teams etc.
- Business operations disrupted

**Detection Fields**:
```json
{
  "Operation": "Change user license.",
  "Target": "[UPN]",
  "Actor": "[Admin UPN]",
  "LicenseRemoved": "[License SKU]"
}
```

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T10:30:12",
  "Id": "8273cc52-5f2a-4bcd-aa12-87459023bdff",
  "Operation": "Change user license.",
  "OrganizationId": "b7c52c70-f861-4551-b067-c3e3c54d62a4",
  "RecordType": 8,
  "ResultStatus": "Success", 
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "victim@contoso.com",
  "UserId": "admin@contoso.com",
  "ClientIP": "192.168.1.100",
  "Target": ["victim@contoso.com"],
  "ModifiedProperties": [
    {
      "Name": "License",
      "OldValue": "['Enterprise E3']",
      "NewValue": "[]"
    }
  ]
}
```

## Detection Strategies

### Behavioral Analytics Rules

1. Mass Account Operations Detection
```sql
SELECT Actor, Operation, COUNT(*) as count
FROM AuditLogs 
WHERE Operation IN ('Delete user.', 'Reset user password.', 'Change user license.')
AND TimeGenerated > ago(1h)
GROUP BY Actor, Operation
HAVING count > 10
```

2. Suspicious Admin Activity
```sql
SELECT Actor, Operation, Target, ClientIP
FROM AuditLogs
WHERE Actor NOT IN (knownAdmins)
AND Operation IN ('Delete user.', 'Reset user password.')
```

3. After Hours Account Modifications
```sql
SELECT * FROM AuditLogs
WHERE Operation IN ('Delete user.', 'Reset user password.', 'Change user license.')
AND TimeGenerated.hour NOT BETWEEN 9 AND 17
```

### Baseline Deviation Monitoring
- Track normal rates of account operations per admin
- Alert on deviations > 2 standard deviations
- Monitor geographic locations of admin activities
- Establish baseline for service hours account operations

## Mitigation Strategies

### Administrative Controls
1. Implement Privileged Identity Management (PIM)
2. Require MFA for all admin accounts
3. Regular access reviews for admin roles
4. Time-bound role assignments

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "adminMFA": {
      "users": ["Global Admins", "User Admins"],
      "conditions": {
        "requireMFA": true,
        "deviceCompliance": true,
        "locations": ["Trusted Networks"]
      }
    },
    "adminWorkHours": {
      "restrictAccess": "During Business Hours",
      "riskLevel": "High"
    }
  }
}
```

### Monitoring Controls
1. Real-time alerts for:
   - Bulk account operations
   - After hours admin activity
   - License removal events
2. Regular audit log review
3. Admin activity reports

## Incident Response Playbook

### Initial Detection
1. Validate alert authenticity
2. Identify affected accounts
3. Document timestamps and admin accounts involved

### Investigation
1. Review audit logs for related activity
2. Check for other compromised admin accounts
3. Analyze authentication patterns
4. Review recent security alerts

### Containment
1. Suspend suspected admin accounts
2. Restore deleted user accounts
3. Reset compromised credentials
4. Re-assign required licenses
5. Enable additional monitoring

## References
- [MITRE T1531](https://attack.mitre.org/techniques/T1531/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Entra ID Audit Logs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs)

---

# Threat Model: Credential Stuffing (T1110.004) in Microsoft 365 & Entra ID

## Overview
Credential stuffing in Microsoft 365 and Entra ID involves attackers using compromised credentials from external breaches to attempt authentication against cloud services. The attack exploits password reuse across personal and business accounts.

## Attack Vectors

### 1. Microsoft Online Authentication Portal
**Description:**
- Attackers use automated tools to attempt logins through login.microsoftonline.com
- Credentials sourced from public breach databases are tested systematically
- Focus on high-privilege accounts like Global Admins

**Detection Fields:**
```json
{
  "Operation": "UserLoggedIn",
  "ResultStatus": "Failed",
  "ClientIP": "string",
  "UserAgent": "string",
  "UserId": "string",
  "ApplicationId": "string",
  "ErrorCode": "number"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T15:42:19",
  "Id": "18a7c443-8819-4ba7-af26-24d42b3357f9",
  "Operation": "UserLoggedIn", 
  "OrganizationId": "bf8d32d3-1c13-4487-af02-80dba2236485",
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "198.51.100.1",
  "UserId": "robert.smith@company.com",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "ErrorCode": 50126
}
```

### 2. Exchange Online Remote PowerShell
**Description:**
- Attackers leverage PowerShell modules for programmatic authentication attempts
- Allows rapid testing of multiple credentials
- Can bypass some MFA requirements through legacy authentication

**Detection Fields:**
```json
{
  "Operation": "Add-MailboxPermission",
  "ClientIP": "string", 
  "ClientInfoString": "string",
  "UserId": "string",
  "ResultStatus": "string"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T15:45:33",
  "Id": "27b32d12-9918-4ba7-af26-24d42b3357f9",
  "Operation": "Add-MailboxPermission",
  "OrganizationId": "bf8d32d3-1c13-4487-af02-80dba2236485",
  "RecordType": 1,
  "ResultStatus": "Failed",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "198.51.100.2",
  "UserId": "admin@company.com",
  "ClientInfoString": "PSVersion=7.0.3;PSEdition=Core;Windows 10 Enterprise"
}
```

### 3. Azure AD Connect Sync Account
**Description:**  
- Targeting of AD Connect sync accounts which often have privileged access
- Attempts to compromise hybrid identity infrastructure
- Can lead to on-premises AD compromise

**Detection Fields:**
```json
{
  "Operation": "Set DirSyncEnabled flag.",
  "ObjectId": "string",
  "UserId": "string",
  "ClientIP": "string",
  "ResultStatus": "string"
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-20T15:48:12",
  "Id": "89c76554-1234-4ba7-af26-24d42b3357f9", 
  "Operation": "Set DirSyncEnabled flag.",
  "OrganizationId": "bf8d32d3-1c13-4487-af02-80dba2236485",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "Sync_ADConnect@company.com",
  "UserId": "attacker@company.com",
  "ClientIP": "198.51.100.3"
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect multiple failed logins from same IP across different accounts
SELECT ClientIP, COUNT(DISTINCT UserId) as distinct_users,
COUNT(*) as total_attempts
FROM UserLoggedIn 
WHERE ResultStatus = 'Failed'
AND TimeGenerated > ago(1h)
GROUP BY ClientIP
HAVING COUNT(DISTINCT UserId) > 10
AND COUNT(*) > 50;

-- Detect successful logins after multiple failures
SELECT UserId, ClientIP, TimeGenerated
FROM UserLoggedIn
WHERE ResultStatus = 'Success'
AND EXISTS (
    SELECT 1 FROM UserLoggedIn prev 
    WHERE prev.UserId = UserLoggedIn.UserId
    AND prev.ResultStatus = 'Failed'
    AND prev.TimeGenerated > ago(1h)
    GROUP BY prev.UserId
    HAVING COUNT(*) > 20
);
```

### Baseline Deviation Monitoring
- Track normal authentication patterns per user:
  - Typical login times
  - Common IP addresses/ranges
  - Normal user agents
  - Typical authentication methods
- Alert on deviations:
  - Login attempts outside business hours
  - Unknown IP addresses/geographies
  - Unusual user agents
  - Legacy authentication protocols

## Technical Controls
```json
{
  "conditionalAccess": {
    "signInFrequency": {
      "value": 4,
      "type": "hours",
      "isPersistent": false
    },
    "persistentBrowser": "never",
    "deviceFilter": {
      "mode": "include",
      "rule": "device.isCompliant -eq True"
    }
  },
  "passwordPolicy": {
    "minimumLength": 14,
    "requireUppercase": true,
    "requireLowercase": true,
    "requireNumbers": true,
    "requireSymbols": true,
    "preventPasswordReuse": 24
  },
  "mfaSettings": {
    "state": "enabled",
    "rememberDevice": false,
    "methodTypes": ["phoneAppNotification", "phoneAppOTP"]
  }
}
```

## Incident Response Playbook

### Initial Detection
1. Identify affected accounts
2. Review authentication logs for indicators
3. Enable increased logging
4. Block suspicious IPs
5. Force password resets

### Investigation
1. Review successful logins after failures
2. Analyze geographic patterns
3. Check for post-compromise activity
4. Review mail rules and delegates
5. Check Azure AD Connect sync status

### Containment
1. Enable MFA
2. Block legacy authentication
3. Implement conditional access policies
4. Reset compromised credentials
5. Review and revoke sessions

## References
- MITRE ATT&CK: T1110.004
- Microsoft Security Documentation:
  - Azure AD Sign-in Logs
  - Identity Protection
  - Conditional Access
  - Azure AD Connect security

---

# Threat Model: Multi-Factor Authentication (T1556.006) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries manipulating MFA settings in Microsoft 365 and Entra ID to maintain persistent access to compromised accounts. Key methods include:

- Modifying Conditional Access policies to exclude compromised accounts
- Adding adversary-controlled authentication methods to accounts  
- Disabling MFA requirements for specific users or groups
- Creating authentication policy bypass rules

## 2. Attack Vectors

### Vector 1: MFA Method Addition
Description: Adversaries add their own authentication method (phone number, authenticator app) to a compromised account.

Detection Fields:
```json
{
  "Operation": "Update user.", 
  "ObjectId": "[User ObjectID]",
  "ModifiedProperties": [
    {
      "Name": "StrongAuthenticationMethod",
      "NewValue": "[New Authentication Method]"
    }
  ],
  "Actor": "[Actor UPN]",
  "ActorIpAddress": "[IP Address]"
}
```

### Vector 2: Conditional Access Policy Modification  
Description: Adversaries modify Conditional Access policies to exclude targeted accounts from MFA.

Detection Fields:
```json
{
  "Operation": "Update policy.",
  "ObjectId": "[Policy ObjectID]",
  "ModifiedProperties": [
    {
      "Name": "PolicyExclusions",
      "OldValue": "[]",
      "NewValue": "[User/Group ObjectIDs]"
    }
  ],
  "Actor": "[Actor UPN]"
}
```

### Vector 3: Authentication Policy Deletion
Description: Adversaries delete or disable authentication policies requiring MFA.

Detection Fields:
```json
{
  "Operation": "Delete policy.",
  "ObjectId": "[Policy ObjectID]",
  "PolicyType": "AuthenticationPolicy",
  "Actor": "[Actor UPN]",
  "Timestamp": "[Timestamp]"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect rapid MFA method changes
SELECT Actor, COUNT(*) as changes
FROM AuditLogs 
WHERE Operation = "Update user."
  AND ModifiedProperties.Name = "StrongAuthenticationMethod" 
GROUP BY Actor, bin(Timestamp, 1h)
HAVING changes > 3

-- Detect off-hours policy modifications
SELECT * FROM AuditLogs
WHERE Operation IN ("Update policy.", "Delete policy.")
  AND hour(Timestamp) NOT BETWEEN 9 AND 17
```

### Baseline Monitoring
- Track normal rate of MFA method changes per user
- Monitor typical policy modification patterns
- Establish baseline for authentication policy updates

### Risk Indicators
- MFA changes from unusual locations/IPs
- Multiple policy modifications in short timeframe
- Pattern of excluding specific users from MFA policies
- Sequential disabling of security controls

## 4. Mitigation Controls

### Administrative
- Require approval workflow for policy changes
- Restrict authentication policy management to security team
- Document all approved MFA bypass scenarios
- Regular access reviews of policy exclusions

### Technical
```json
{
  "conditionalAccessPolicy": {
    "displayName": "Require MFA for Admin Accounts",
    "state": "enabled",
    "conditions": {
      "userRiskLevels": ["high"],
      "signInRiskLevels": ["high"],
      "users": {
        "roles": ["Global Administrator"]
      }
    },
    "grantControls": {
      "operator": "AND",
      "builtInControls": ["mfa"]
    }
  }
}
```

### Monitoring
- Enable audit logging for all authentication policy changes
- Alert on MFA method changes outside business hours
- Monitor for bulk policy exclusion modifications
- Track failed authentication attempts after MFA changes

## 5. Incident Response

### Initial Detection
1. Identify affected accounts and policies
2. Review authentication logs for suspicious patterns
3. Document timeline of policy modifications

### Investigation
1. Analyze source IP addresses and user agents
2. Review related policy changes in same timeframe
3. Check for other compromised admin accounts
4. Identify any successful authentications post-modification

### Containment
1. Revert unauthorized policy changes
2. Remove unauthorized authentication methods
3. Force password reset for affected accounts
4. Re-enable MFA requirements
5. Review and tighten policy management permissions

## 6. References
- MITRE ATT&CK: T1556.006
- Microsoft: Conditional Access Policies
- CISA: MFA Security Advisory
- Microsoft Security Blog: Detecting MFA Bypass Attempts

---

# Threat Model: Remote Email Collection (T1114.002) in Microsoft 365 & Entra ID

## Overview
Adversaries may attempt to collect email data from Microsoft 365/Exchange Online through compromised accounts, service principals, or mailbox delegation. This technique enables attackers to exfiltrate sensitive information and monitor communications.

## Attack Vectors

### 1. Mailbox Delegation Abuse
**Description**: Attackers add mailbox delegation permissions to access target mailboxes using Add-MailboxPermission.

**Scenario**:
- Attacker compromises admin account
- Adds FullAccess permissions to attacker-controlled account
- Uses permissions to collect emails via EWS/MAPI

**Detection Fields**:
- Operation: Add-MailboxPermission, Remove-MailboxPermission
- Parameters: Identity, User, AccessRights
- ResultStatus

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Operation": "Add-MailboxPermission",
  "Parameters": {
    "Identity": "sarah.jones@company.com",
    "User": "attacker@company.com", 
    "AccessRights": ["FullAccess"]
  },
  "ResultStatus": "Success",
  "ClientIP": "192.168.1.100",
  "UserId": "admin@company.com"
}
```

### 2. Service Principal Token Abuse
**Description**: Attackers create service principals with mail.read permissions to programmatically access mailboxes.

**Detection Fields**:
- Operation: Add service principal credentials
- AppId
- Permissions: ["Mail.Read", "Mail.ReadWrite"]
- ConsentType

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:14:22", 
  "Operation": "Add service principal credentials",
  "AppId": "a4d9e7f2-3b12-4c89-9e4f-12d34567890a",
  "Permissions": ["Mail.Read"],
  "ConsentType": "AllPrincipals",
  "ActorUPN": "admin@company.com",
  "TargetResources": [{
    "Type": "ServicePrincipal",
    "ID": "8a7b6c5d-4e3f-2a1b-9c8d-7e6f5d4c3b2a"
  }]
}
```

### 3. Inbox Rule Collection
**Description**: Attackers create inbox rules to forward or copy emails to attacker-controlled mailboxes.

**Detection Fields**:
- Operation: New-InboxRule, Set-InboxRule
- RuleParameters: ForwardTo, RedirectTo
- Enabled

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T17:05:11",
  "Operation": "New-InboxRule",
  "RuleParameters": {
    "Name": "External Forward",
    "ForwardTo": "attacker@external.com",
    "Enabled": true
  },
  "UserId": "victim@company.com",
  "ClientIP": "10.1.2.3"
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect suspicious mailbox delegation patterns
SELECT UserId, Operation, COUNT(*) as del_count
FROM AuditLogs 
WHERE Operation = 'Add-MailboxPermission'
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING del_count > 5;

-- Detect mass inbox rule creation
SELECT UserId, COUNT(*) as rule_count
FROM AuditLogs
WHERE Operation IN ('New-InboxRule', 'Set-InboxRule') 
AND TimeGenerated > ago(24h)
GROUP BY UserId
HAVING rule_count > 10;
```

### Baseline Deviation Monitoring
- Track normal patterns of:
  - Mailbox delegation changes per admin per day
  - Inbox rule creation frequency
  - Service principal mail access volumes
- Alert on deviations > 2 standard deviations

### Technical Controls (JSON)
```json
{
  "conditionalAccessPolicies": {
    "name": "Block Legacy Auth",
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
  },
  "mailFlowRules": {
    "name": "Block External Forwarding",
    "conditions": {
      "messageTypeMatches": "AutoForward",
      "recipientDomainIs": "not internal domains"
    },
    "actions": {
      "rejectMessage": true
    }
  }
}
```

## Mitigation Strategies

### Administrative Controls
1. Implement least privilege access
2. Regular review of mailbox delegations
3. Restrict service principal creation
4. Enable modern authentication only

### Technical Controls
1. Configure Conditional Access policies
2. Enable mailbox auditing
3. Block legacy authentication protocols
4. Implement DLP policies

### Monitoring Controls
1. Monitor mailbox delegation changes
2. Alert on suspicious inbox rules
3. Track service principal mail access
4. Review audit logs for mass email access

## References
- [MITRE T1114.002](https://attack.mitre.org/techniques/T1114/002/)
- [Microsoft Exchange Auditing](https://docs.microsoft.com/exchange/policy-and-compliance/mailbox-audit-logging/mailbox-audit-logging)
- [Microsoft Entra ID Monitoring](https://docs.microsoft.com/azure/active-directory/reports-monitoring/)

---

# Threat Model: Password Policy Discovery (T1201) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries can attempt to discover password policy settings through several methods:
- Direct access to Entra ID admin portals and PowerShell modules
- Enumeration of authentication policies and settings via Microsoft Graph API
- Analysis of failed authentication attempts to infer policy rules

## 2. Attack Vectors

### 2.1 Admin Portal Access
**Description**: Adversaries with admin access view password policies through the Azure Portal or Microsoft 365 Admin Center

**Audit Fields to Monitor**:
```json
{
  "Operation": "Set password policy.",
  "UserId": "<user>", 
  "ClientIP": "<ip>",
  "Application": "Azure Portal",
  "ResultStatus": "Success"
}
```

### 2.2 PowerShell Enumeration
**Description**: Use of PowerShell modules like MSOnline or Az to query password policies

**Example Audit Log**:
```json
{
  "Operation": "Set federation settings on domain.", 
  "UserId": "<user>",
  "Workload": "AzureActiveDirectory",
  "ModifiedProperties": [
    {
      "Name": "PasswordValidityPeriodInDays",
      "OldValue": "90",
      "NewValue": "60" 
    }
  ]
}
```

### 2.3 Authentication Probing
**Description**: Systematic failed login attempts to identify lockout thresholds

**Example Audit Log**:
```json
{
  "Operation": "UserLoginFailed",
  "UserPrincipalName": "<user>",
  "ErrorCode": "InvalidPassword", 
  "FailureCount": "3",
  "ClientIP": "<ip>"
}
```

## 3. Detection Strategy

### 3.1 Behavioral Analytics
```sql
// Alert on multiple password policy changes within short period
SELECT UserId, COUNT(*) as changes
FROM AuditLogs 
WHERE Operation IN ('Set password policy', 'Set federation settings') 
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 3
```

### 3.2 Baseline Deviations
- Monitor for spikes in failed authentication attempts from same source
- Track unusual admin portal access patterns
- Alert on password policy changes outside business hours

### 3.3 Technical Controls
```json
{
  "controls": {
    "conditional_access": {
      "block_legacy_auth": true,
      "require_mfa_for_admins": true
    },
    "monitoring": {
      "log_admin_activities": true,
      "alert_on_policy_changes": true
    }
  }
}
```

## 4. Mitigation Strategy

### Administrative Controls
1. Implement role-based access control (RBAC) for password policy management
2. Require MFA for all admin activities
3. Regular access reviews for admin accounts

### Technical Controls
1. Enable detailed audit logging for Azure AD
2. Configure alerts for password policy changes
3. Implement Conditional Access policies

### Monitoring Controls
1. Review admin activity logs daily
2. Monitor for suspicious authentication patterns
3. Track failed login attempt patterns

## 5. Incident Response

### Initial Detection
1. Review Azure AD Sign-in logs for suspicious patterns
2. Check admin portal access history
3. Analyze PowerShell usage logs

### Investigation Steps
1. Document all policy changes made
2. Identify accounts involved
3. Review authentication logs for probing attempts
4. Map timeline of activities

### Containment Actions
1. Reset affected admin credentials
2. Restore original password policies if altered
3. Block suspicious IP addresses
4. Enable stricter monitoring

## 6. References

- MITRE: https://attack.mitre.org/techniques/T1201/
- Microsoft Entra ID Audit Logs: https://docs.microsoft.com/azure/active-directory/reports-monitoring/
- Azure AD Password Policies: https://docs.microsoft.com/azure/active-directory/authentication/

---

# Threat Model: Event Triggered Execution (T1546) in Microsoft 365 & Entra ID

## Overview
Adversaries can abuse event-triggered mechanisms in Microsoft 365 and Entra ID to maintain persistence and elevate privileges by creating malicious automated workflows, scheduled tasks, and event subscriptions that execute when specific cloud events occur.

## Attack Vectors

### 1. Power Automate Flow Abuse
**Description**: Adversaries create malicious automated flows triggered by events like new emails, file uploads, or form submissions to exfiltrate data or maintain persistence.

**Attack Scenario**:
1. Attacker compromises admin account with Power Platform privileges
2. Creates flow triggered by email arrivals
3. Flow forwards emails matching criteria to external account
4. Flow remains dormant until triggered

**Relevant Audit Operations**:
```json
{
  "Operation": "CreateUpdateRequest",
  "CreationTime": "2024-01-15T15:23:41",
  "UserId": "bob.smith@company.com",
  "Workload": "PowerAutomate",
  "ObjectId": "flow_123456789",
  "FlowName": "Email Monitor", 
  "TriggerType": "When a new email arrives",
  "Actions": ["Send email", "HTTP request"],
  "ConnectionNames": ["Office 365 Outlook", "HTTP"]
}
```

### 2. Application Service Principal Event Subscription
**Description**: Attackers create malicious app registrations with service principals subscribed to tenant-wide events to intercept activities.

**Audit Fields**:
```json
{
  "Operation": "Add service principal.",
  "CreationTime": "2024-01-15T16:42:13",
  "UserId": "admin@company.com",
  "ObjectId": "sp_987654321",
  "ApplicationId": "app_123456789",
  "Permissions": ["Mail.Read", "Files.Read.All"],
  "SubscriptionIds": ["sub_123456789"],
  "EventTypes": ["message.created", "fileUploaded"]
}
```

### 3. Azure Function Timer Trigger
**Description**: Adversaries deploy Azure Functions with timer triggers to periodically execute malicious code with elevated permissions.

**Audit Fields**:
```json
{
  "Operation": "Create Remote Action Operation",
  "TimeCreated": "2024-01-15T17:15:22",
  "Identity": "john.doe@company.com",
  "ResourceId": "/subscriptions/123/functions/malicious-func",
  "TriggerType": "timerTrigger",
  "Schedule": "0 */5 * * * *",
  "FunctionApp": "company-funcs"
}
```

## Detection Strategies

### Behavioral Analytics
```sql
-- Detect suspicious Power Automate flows
SELECT UserId, COUNT(*) as flow_count
FROM FlowCreationAudit
WHERE TimeGenerated > ago(1h)
  AND (
    ConnectionNames CONTAINS 'HTTP' OR
    ConnectionNames CONTAINS 'Custom Connector'
  )
GROUP BY UserId
HAVING flow_count > 5;

-- Monitor service principal subscription changes
SELECT *
FROM AuditEvents
WHERE Operation IN ('Add service principal.', 'Set delegation entry.')
  AND EventData.Permissions CONTAINS 'Mail.Read'
  AND TimeGenerated > ago(24h);
```

### Baseline Monitoring
- Track normal patterns of:
  - Flow creation frequency per user/day
  - Service principal event subscription types
  - Azure Function deployment frequency
- Alert on deviations >25% from baseline

### Time-Based Analytics
- Correlation of flow creation with other suspicious activities within 30 minute window
- Detection of flows created outside business hours
- Monitoring of synchronized or periodic execution patterns

## Mitigation Strategies

### Administrative Controls
1. Restrict Power Automate flow creation to authorized users
2. Implement approval workflows for new service principal registrations
3. Limit Azure Function deployment permissions

### Technical Controls
```json
{
  "powerPlatform": {
    "allowedConnections": ["Office365", "SharePoint"],
    "blockedTriggers": ["HTTP", "Recurrence"],
    "approvalRequired": true
  },
  "servicePrincipals": {
    "restrictedPermissions": ["Mail.ReadWrite.All", "Files.ReadWrite.All"],
    "allowedSubscriptionTypes": ["presence", "chat"]
  }
}
```

### Monitoring Controls
1. Real-time alerts on suspicious flow creation
2. Daily review of new service principal subscriptions
3. Automated scanning of Azure Function code

## Incident Response Playbook

### Initial Detection
1. Identify trigger source (Flow/SP/Function)
2. Document creation time and creator
3. Review associated permissions and connections

### Investigation
1. Analyze trigger conditions and actions
2. Review audit logs for creation context
3. Identify any data accessed/exfiltrated
4. Map related component connections

### Containment
1. Disable suspicious automation
2. Revoke compromised credentials
3. Block external connections
4. Remove malicious subscriptions

## References
- MITRE ATT&CK: T1546
- Microsoft: Power Automate Security Best Practices
- Azure AD: Monitoring Service Principal Activity
- Microsoft Security Blog: Detecting Suspicious Automation

---

# Threat Model: Outlook Home Page (T1137.004) in Microsoft 365 & Entra ID

## 1. Overview

The Outlook Home Page technique abuses a legacy feature in Microsoft Outlook that allows custom HTML pages to be set as the default view for email folders. This presents a persistence risk in Microsoft 365 environments as attackers can inject malicious HTML/JavaScript that executes when folders are accessed.

## 2. Attack Vectors

### 2.1 Registry Modification Attack Vector

**Description**: Attacker modifies registry keys to set malicious HTML pages as folder home pages.

**Scenario**: 
```text
1. Attacker gains initial access to workstation
2. Modifies HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\{folder-guid}
3. Sets HomePageURL to malicious HTML/JS payload
```

**Detection Fields**:
```json
{
  "Operation": "Update",
  "ClientInfoString": "Client=OWA;",
  "ClientIP": "10.1.2.3",
  "UserId": "john.doe@company.com",
  "FolderPathModified": true,
  "WebViewSettings": {
    "Modified": true,
    "HomepageUrl": "https://malicious.com/payload.html"
  }
}
```

### 2.2 Exchange Web Services (EWS) Attack Vector

**Description**: Attacker uses EWS API to programmatically set folder home pages.

**Scenario**:
```text
1. Attacker obtains OAuth token or credentials
2. Uses EWS API to modify folder properties
3. Sets PR_HOME_PAGE property to malicious URL
```

**Detection Fields**:
```json
{
  "Operation": "Set-MailboxFolderPermission",
  "ClientAppId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
  "TargetUserOrGroupName": "john.doe@company.com",
  "TargetFolderPath": "\\Inbox",
  "Parameters": {
    "HomepageUrl": "http://evil.com/page.html",
    "AccessRights": "Owner" 
  }
}
```

### 2.3 Delegated Access Attack Vector

**Description**: Attacker abuses delegated mailbox access to configure home pages.

**Detection Fields**:
```json
{
  "Operation": "Add-MailboxPermission",
  "ClientIP": "10.1.2.3",
  "UserId": "attacker@company.com", 
  "TargetUserOrGroupName": "victim@company.com",
  "Parameters": {
    "AccessRights": ["FullAccess"],
    "AutoMapping": true
  }
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
// Detect suspicious homepage modifications
SELECT UserId, ClientIP, Operation, Count(*) as count
FROM MailboxAuditLog 
WHERE Operation IN ('Update', 'Set-MailboxFolderPermission')
  AND WebViewSettings.Modified = true
GROUP BY UserId, ClientIP, Operation
HAVING count > 5 // Threshold for suspicious activity
WITHIN 1 hour
```

### 3.2 Baseline Deviation Monitoring

```json
{
  "BaselineMetrics": {
    "DailyFolderModifications": 10,
    "UniqueModifiedFolders": 3,
    "HomepageUrlChanges": 1
  },
  "AlertThresholds": {
    "ModificationSpike": "200% increase",
    "UniqueFoldersLimit": 5,
    "HomepageChangesLimit": 2
  }
}
```

## 4. Mitigation Strategies

### Administrative Controls
1. Disable Outlook Home Page feature via Group Policy
2. Block external URLs in home page settings
3. Implement least-privilege access model

### Technical Controls
```json
{
  "GroupPolicy": {
    "DisableOutlookHomePage": true,
    "BlockExternalUrls": true,
    "AllowedHomePageDomains": [
      "*.company.com"
    ]
  },
  "ConditionalAccess": {
    "RequireMFA": true,
    "BlockLegacyAuth": true
  }
}
```

### Monitoring Controls
1. Enable mailbox audit logging
2. Monitor EWS and delegate access operations
3. Alert on homepage URL modifications

## 5. Incident Response Playbook

1. Initial Detection
   - Review mailbox audit logs
   - Identify affected mailboxes
   - Document modified folder settings

2. Investigation
   - Analyze homepage URLs and content
   - Review authentication logs
   - Track lateral movement attempts

3. Containment
   - Block malicious URLs
   - Remove compromised home pages
   - Reset affected credentials
   - Revoke suspicious delegated access

## 6. References

- [MITRE ATT&CK T1137.004](https://attack.mitre.org/techniques/T1137/004/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Exchange Online Auditing](https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mailbox-audit-logging/mailbox-audit-logging)

---

# Threat Model: Web Session Cookie (T1550.004) in Microsoft 365 & Entra ID

## Overview
In Microsoft 365 and Entra ID environments, adversaries may steal and reuse authenticated session cookies to bypass authentication controls, including MFA. This allows access to Microsoft 365 services like Exchange Online, SharePoint Online, and Teams.

## Attack Vectors

### 1. Exchange Online Cookie Theft and Reuse
**Description**: Adversary steals session cookies for Exchange Online/Outlook Web Access and reuses them to access victim mailboxes.

**Audit Fields**:
- Operation: "MailboxLogin" and "MailItemsAccessed"
- ClientInfoString: Browser/user agent details
- ClientIP: Source IP address
- UserId: Account accessing mailbox

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:22:31",
  "Id": "12345-67890",
  "Operation": "MailboxLogin",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": 2,
  "UserKey": "user@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "198.51.100.1",
  "UserId": "user@contoso.com",
  "ClientInfoString": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "SessionId": "123456789"
}
```

### 2. SharePoint Online Session Hijacking  
**Description**: Adversary captures SharePoint Online session cookies to access document libraries and sites.

**Audit Fields**:
- Operation: "FileAccessed", "FileDownloaded" 
- UserAgent: Browser details
- ClientIP: Source IP address
- UserId: Account accessing SharePoint

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:30:12", 
  "Operation": "FileAccessed",
  "Site": "https://contoso.sharepoint.com/sites/finance",
  "ItemType": "File",
  "ItemName": "Q4_Financials.xlsx",
  "UserId": "user@contoso.com",
  "ClientIP": "198.51.100.1",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "SourceFileName": "/sites/finance/Shared Documents/Q4_Financials.xlsx"
}
```

### 3. Teams Web Session Compromise
**Description**: Adversary obtains Teams web client cookies to access chats and meetings.

**Audit Fields**:
- Operation: "TeamsSessionStarted", "MessageRead"
- UserAgent: Browser identification
- ClientIP: Access source
- UserId: Account using Teams

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:15:44",
  "Operation": "TeamsSessionStarted", 
  "OrganizationId": "contoso.onmicrosoft.com",
  "UserId": "user@contoso.com",
  "ClientIP": "198.51.100.1",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "SessionId": "abcd1234-ef56-7890"
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect concurrent sessions from different IPs
SELECT UserId, ClientIP, COUNT(DISTINCT SessionId) as Sessions
FROM AuditLogs 
WHERE TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(DISTINCT SessionId) > 3;

-- Detect anomalous user agent changes
SELECT UserId, ClientInfoString, COUNT(*) as Count
FROM AuditLogs
WHERE TimeGenerated > ago(1h)
  AND Operation IN ('MailboxLogin','TeamsSessionStarted')
GROUP BY UserId, ClientInfoString
HAVING COUNT(*) > 1;
```

### Baseline Deviations
- Monitor for sessions from new IP ranges or geographies
- Track typical login times and flag off-hours access
- Identify unusual access patterns to resources

### Correlation Rules
```sql
-- Correlate failed MFA with successful cookie-based access
SELECT a.UserId, a.ClientIP, a.Operation 
FROM AuditLogs a
JOIN AuditLogs b ON a.UserId = b.UserId
WHERE a.TimeGenerated BETWEEN b.TimeGenerated AND dateadd(minute,5,b.TimeGenerated)
AND a.Operation = 'MailboxLogin'
AND b.Operation = 'MFADenied';
```

## Mitigation Controls

### Administrative Controls
1. Configure conditional access policies
2. Implement session timeout policies
3. Enable risk-based sign-in policies

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "signInRiskLevels": ["high", "medium"],
    "clientAppTypes": ["browser"],
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
1. Enable Unified Audit Logging
2. Configure alerts for suspicious sign-ins
3. Monitor for mass cookie theft indicators

## Incident Response Playbook

### Initial Detection
1. Review sign-in logs for suspicious patterns
2. Identify affected accounts and services
3. Document timeline of suspicious activity

### Investigation
1. Analyze IP addresses and user agents
2. Review accessed resources
3. Identify potential cookie theft vectors

### Containment
1. Force sign-out of all sessions
2. Reset affected user passwords
3. Review and update conditional access policies

## References
- [MITRE ATT&CK T1550.004](https://attack.mitre.org/techniques/T1550/004/)
- [Microsoft Securing Identity Documentation](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/)
- [Microsoft 365 Session Management](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-session-lifetime)

---

# Threat Model: Impersonation (T1656) in Microsoft 365 & Entra ID

## Overview
Impersonation in Microsoft 365 and Entra ID involves adversaries masquerading as trusted entities (executives, colleagues, vendors) to manipulate victims into performing unauthorized actions. Primary vectors include business email compromise (BEC), executive impersonation, and vendor fraud through email and Teams communications.

## Attack Vectors

### 1. Executive Email Impersonation 
**Description**: Adversaries create or compromise email accounts that appear similar to executive names to issue fraudulent payment requests or data access demands.

**Detection Fields**:
```json
{
  "Operation": "Add-MailboxPermission",
  "UserId": "<actor>",
  "ObjectId": "<target mailbox>",
  "Parameters": {
    "AccessRights": ["FullAccess", "SendAs"],
    "InheritanceType": "All"
  }
}

{
  "Operation": "New-InboxRule",
  "UserId": "<actor>",
  "Parameters": {
    "ForwardTo": "<external domain>",
    "DeleteMessage": "True" 
  }
}
```

**Example Pattern**:
1. Add delegate mailbox permissions
2. Create forwarding rules
3. Send messages using SendAs permissions
4. Delete evidence using inbox rules

### 2. Teams Display Name Spoofing
**Description**: Adversaries modify Teams display names to match executives/IT staff for social engineering.

**Detection Fields**:
```json
{
  "Operation": "TeamSettingChanged",
  "UserId": "<actor>",
  "ObjectId": "<team id>",
  "ModifiedProperties": [{
    "Name": "DisplayName",
    "OldValue": "<original>",
    "NewValue": "<executive name>"
  }]
}
```

### 3. Vendor Email Account Takeover
**Description**: Adversaries compromise vendor email accounts to redirect payments or gain access to shared resources.

**Detection Fields**:
```json
{
  "Operation": "Add domain to company",
  "UserId": "<actor>",
  "Parameters": {
    "DomainName": "<suspicious domain>",
    "DomainType": "Federated"
  }
}
```

## Detection Strategy

### Behavioral Analytics Rules
```sql
-- Detect rapid permission changes followed by SendAs activity
SELECT UserId, ObjectId, COUNT(*) as changes
FROM AuditLog 
WHERE Operation IN ('Add-MailboxPermission', 'SendAs')
AND TimeGenerated BETWEEN ago(1h) AND now()
GROUP BY UserId, ObjectId
HAVING COUNT(*) > 5;

-- Detect suspicious domain additions
SELECT * FROM AuditLog
WHERE Operation = 'Add domain to company'
AND Parameters.DomainName NOT IN (SELECT domain FROM approved_vendors);
```

### Baseline Monitoring
- Track normal patterns of:
  - Executive email sending behavior
  - Delegation permission changes
  - Domain federation changes
  - Teams display name modifications

### Correlation Rules
```json
{
  "Name": "Potential Executive Impersonation",
  "Conditions": [
    {
      "Operation": "Add-MailboxPermission",
      "TimeWindow": "1h",
      "Followed_by": {
        "Operation": "SendAs",
        "TimeWindow": "15m"
      }
    }
  ],
  "Threshold": 3,
  "Severity": "High"
}
```

## Mitigation Controls

### Administrative Controls
- Implement naming conventions for service accounts
- Require MFA for all external email access
- Enable modern authentication
- Configure conditional access policies

### Technical Controls
```json
{
  "mailbox_settings": {
    "disable_auto_forwarding": true,
    "require_mfa_for_delegation": true,
    "block_suspicious_domains": true
  },
  "teams_settings": {
    "restrict_display_name_changes": true,
    "prevent_external_access": true
  }
}
```

### Monitoring Controls
- Alert on suspicious delegation changes
- Monitor for abnormal email sending patterns
- Track domain additions and federation changes
- Review Teams display name modifications

## References
- MITRE: https://attack.mitre.org/techniques/T1656/
- Microsoft: https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection

Would you like me to expand on any of these sections or provide additional details about specific aspects of the threat model?

---

# Threat Model: Disable or Modify Cloud Logs (T1562.008) in Microsoft 365 & Entra ID

## Overview
Adversaries may attempt to disable or modify audit logging capabilities in Microsoft 365 and Entra ID to evade detection. Common objectives include:
- Disabling mailbox audit logging
- Modifying audit retention periods 
- Removing audit log subscriptions
- Disabling advanced audit features
- Downgrading licenses to reduce logging

## Attack Vectors

### 1. Mailbox Audit Bypass
**Description**: Adversaries with Exchange Administrator privileges can disable mailbox auditing for specific users using Set-MailboxAuditBypassAssociation to prevent logging of email access and operations.

**Audit Log Fields**:
```json
{
  "Operation": "Set-MailboxAuditBypassAssociation",
  "Parameters": {
    "Identity": "username@domain.com",
    "AuditBypassEnabled": "True"
  },
  "Actor": {
    "ID": "[UPN]",
    "Type": "User"
  },
  "ResultStatus": "Success"
}
```

**Detection Strategy**:
```sql
SELECT Actor, Parameters.Identity 
FROM AuditLogs
WHERE Operation = "Set-MailboxAuditBypassAssociation"
  AND Parameters.AuditBypassEnabled = "True"
  AND TimeGenerated > ago(1h)
```

### 2. License Downgrade
**Description**: Attackers may downgrade user licenses from E5 to E3 to disable advanced auditing features.

**Audit Log Fields**:
```json
{
  "Operation": "Change user license",
  "ObjectId": "username@domain.com", 
  "ModifiedProperties": [{
    "Name": "AccountSku",
    "OldValue": "Enterprise E5",
    "NewValue": "Enterprise E3"
  }],
  "Actor": {
    "ID": "[UPN]",
    "Type": "User"
  }
}
```

**Detection Rule**:
```sql
SELECT ModifiedProperties, Actor
FROM AuditLogs 
WHERE Operation = "Change user license"
  AND ModifiedProperties.Name = "AccountSku"
  AND ModifiedProperties.OldValue LIKE "%E5%"
  AND ModifiedProperties.NewValue LIKE "%E3%"
```

### 3. Audit Configuration Changes
**Description**: Adversaries may modify audit retention settings or disable audit subscriptions.

**Audit Log Fields**:
```json
{
  "Operation": "UpdatedDataAccessSetting",
  "ObjectId": "/auditSettings",
  "Parameters": {
    "RetentionDays": "30",
    "PreviousValue": "365"
  },
  "Actor": {
    "ID": "[UPN]",
    "Type": "User"
  }
}
```

## Detection Strategies

### Behavioral Analytics
- Monitor for multiple audit configuration changes in short time periods
- Track license downgrades across multiple users
- Alert on audit bypass being enabled for privileged accounts

### Baseline Deviations
- Establish baseline for normal audit configuration changes
- Monitor changes outside business hours
- Track frequency of license modifications

### Correlation Rules
```sql
// Detect multiple audit changes by same actor
SELECT Actor.ID, COUNT(*) as changes
FROM AuditLogs
WHERE Operation IN (
  "Set-MailboxAuditBypassAssociation",
  "UpdatedDataAccessSetting",
  "Change user license"
)
GROUP BY Actor.ID, bin(TimeGenerated, 1h)
HAVING changes > 3
```

## Technical Controls
```json
{
  "preventiveControls": {
    "privilegedAccessReview": true,
    "requireMFA": true,
    "restrictAuditAdmins": true
  },
  "detectiveControls": {
    "alertOnAuditChanges": true,
    "monitorLicenseDowngrades": true,
    "trackAuditBypass": true
  }
}
```

## Incident Response Playbook

### Initial Detection
1. Identify affected resources and scope of audit changes
2. Document timing and sequence of modifications
3. Preserve available audit logs before potential loss

### Investigation 
1. Review authentication logs for suspicious access
2. Check for additional suspicious admin activities
3. Analyze timing and pattern of changes

### Containment
1. Revoke compromised admin credentials
2. Re-enable audit logging configurations
3. Restore E5 licenses if downgraded
4. Document all remediation steps

## References
- MITRE ATT&CK: T1562.008
- Microsoft Security Documentation: Audit Log Management
- Microsoft 365 Defender Portal Documentation

This provides a practical framework for detecting and responding to audit logging manipulation in Microsoft 365 and Entra ID environments.

Let me know if you would like me to expand on any section or provide additional detection examples!

---

# Threat Model: Data from Information Repositories (T1213) in Microsoft 365 & Entra ID

## 1. Overview

This technique involves adversaries accessing and extracting sensitive data from Microsoft 365 information repositories including:
- SharePoint document libraries and sites
- Teams chat messages and files
- Exchange Online mailboxes
- OneDrive for Business 

Key risk factors:
- Over-privileged accounts 
- Excessive external sharing
- Unmonitored data access patterns
- Lack of sensitivity labeling

## 2. Attack Vectors

### Vector 1: SharePoint Document Mass Download
**Description**: Adversary uses authenticated access to systematically download sensitive documents from SharePoint libraries.

**Scenario**: Compromised user account bulk downloads financial documents, technical specifications, and customer data from SharePoint sites.

**Detection Fields**:
```json
{
  "Operation": "FileDownloaded",
  "ObjectId": "/sites/finance/documents/Q4-forecast.xlsx",
  "UserId": "bob.smith@company.com",
  "ClientIP": "192.168.1.100",
  "UserAgent": "Mozilla/5.0...",
  "SiteUrl": "https://company.sharepoint.com/sites/finance",
  "SourceFileName": "Q4-forecast.xlsx",
  "SourceRelativeUrl": "/documents"
}
```

### Vector 2: Teams Chat History Mining
**Description**: Adversary accesses Teams chat histories to gather sensitive information shared in messages.

**Scenario**: Attacker uses compromised admin account to export Teams chat logs containing credentials and internal data.

**Detection Fields**:
```json
{
  "Operation": "MessagesExported",
  "UserId": "admin@company.com", 
  "TeamName": "IT Project Team",
  "ChannelName": "General",
  "RecordType": 1,
  "ExportType": "MessagesAndFiles",
  "NumberOfMessages": 5000,
  "ExportStartTime": "2024-01-20T10:00:00Z"
}
```

### Vector 3: Exchange Mailbox Access 
**Description**: Adversary uses delegated or impersonation access to mine mailbox data.

**Scenario**: Attacker adds mailbox delegation to access executive emails containing strategic plans.

**Detection Fields**:
```json
{
  "Operation": "Add-MailboxPermission",
  "ObjectId": "ceo@company.com",
  "UserId": "attacker@company.com",
  "Parameters": {
    "AccessRights": "FullAccess",
    "InheritanceType": "All"
  },
  "ResultStatus": "Success"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect mass downloads from SharePoint
SELECT UserId, COUNT(*) as download_count
FROM AuditLogs 
WHERE Operation = 'FileDownloaded'
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 100;

-- Detect unusual mailbox delegation
SELECT ObjectId, COUNT(*) as delegation_count 
FROM AuditLogs
WHERE Operation = 'Add-MailboxPermission'
AND TimeGenerated > ago(24h)
GROUP BY ObjectId
HAVING COUNT(*) > 3;

-- Detect Teams chat exports
SELECT UserId, TeamName, NumberOfMessages
FROM AuditLogs
WHERE Operation = 'MessagesExported' 
AND NumberOfMessages > 1000;
```

### Baseline Deviations
- Monitor daily average file downloads per user
- Track typical delegation patterns
- Establish normal Teams chat export volumes
- Alert on significant deviations (>2 standard deviations)

## 4. Mitigation Controls

### Administrative Controls
- Implement least privilege access 
- Require business justification for bulk downloads
- Review delegated permissions regularly
- Enable sensitivity labels on documents

### Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "name": "Block Suspicious Downloads",
    "conditions": {
      "userRiskLevels": ["high"],
      "applications": ["SharePoint", "Teams"],
      "controls": ["blockDownload", "requireMFA"]
    }
  },
  "dlpPolicies": {
    "name": "Prevent Mass Downloads",
    "rules": {
      "threshold": 50,
      "timeWindow": "1h",
      "actions": ["block", "alert"]
    }
  }
}
```

### Monitoring Controls
- Enable auditing for all information repositories
- Monitor privileged account activity 
- Track external sharing events
- Alert on sensitive data access

## 5. Incident Response

### Initial Detection
1. Identify affected repositories and data
2. Determine scope of access/exfiltration
3. Correlate with other suspicious activity

### Investigation
1. Review audit logs for access patterns
2. Analyze downloaded content
3. Check delegation changes
4. Examine authentication events

### Containment
1. Revoke compromised credentials
2. Remove suspicious delegations
3. Block external sharing
4. Enable stricter DLP policies

## 6. References

- MITRE: https://attack.mitre.org/techniques/T1213/
- Microsoft: https://docs.microsoft.com/en-us/microsoft-365/security/
- SharePoint Auditing: https://docs.microsoft.com/en-us/sharepoint/audit-log-events

---

# Threat Model: Masquerade Account Name (T1036.010) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 and Entra ID environments, adversaries attempt to create accounts that mimic legitimate service accounts, administrative accounts, or existing user accounts. This technique is often used in conjunction with account creation and modification operations to establish persistent access while blending in with normal account naming patterns.

## 2. Attack Vectors

### 2.1 Service Principal Name Masquerading

Description: Adversaries create service principals with names that closely match legitimate Microsoft or third-party application names.

Audit Operations:
- Add service principal.
- Add service principal credentials.
- Add delegation entry.

Example Log:
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "8a12e2b1-5cd2-4f31-9ebc-dc42330951d2",
  "Operation": "Add service principal.",
  "OrganizationId": "d124a9e7-1234-5678-90ab-cdef12345678",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001A42C8B1F@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "s-1-5-21-1234567890-1234567890-1234567890-1234",
  "UserId": "admin@contoso.com",
  "AppId": "11111111-1111-1111-1111-111111111111",
  "ApplicationName": "microsoft.graph.authservice", // Suspicious masquerading name
  "ApplicationDisplayName": "Microsoft Graph Auth Service"
}
```

### 2.2 Administrative Account Masquerading 

Description: Adversaries create user accounts with names similar to IT administrative accounts.

Audit Operations:
- Add user.
- Update user.
- Add member to role.

Example Log:
```json
{
  "CreationTime": "2024-01-15T15:43:12",
  "Id": "9b23f3c2-6de3-4f42-0fcd-ed53441062d3", 
  "Operation": "Add user.",
  "OrganizationId": "d124a9e7-1234-5678-90ab-cdef12345678",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001A42C8B1F@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "u-1-5-21-1234567890-1234567890-1234567890-5678",
  "UserId": "admin@contoso.com",
  "TargetUserOrGroupName": "adm1n.support", // Suspicious masquerading name
  "TargetUserOrGroupType": "User"
}
```

### 2.3 User Account Name Cloning

Description: Adversaries create accounts that closely match existing user account names with slight variations.

Audit Operations:
- Add user.
- Update user.
- Add member to group.

Example Log:
```json
{
  "CreationTime": "2024-01-15T09:15:33",
  "Id": "7c34e5d2-8ef1-3g22-1abc-fg45672893e4",
  "Operation": "Add user.",
  "OrganizationId": "d124a9e7-1234-5678-90ab-cdef12345678", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001A42C8B1F@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "u-1-5-21-1234567890-1234567890-1234567890-9012",
  "UserId": "admin@contoso.com",
  "TargetUserOrGroupName": "john.srnith@contoso.com", // Suspicious masquerading name (smith vs srnith)
  "TargetUserOrGroupType": "User"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules

```sql
-- Detect similar service principal names
SELECT sp.DisplayName, COUNT(*) as count
FROM ServicePrincipals sp
WHERE sp.DisplayName LIKE '%microsoft%' 
  OR sp.DisplayName LIKE '%azure%'
  OR sp.DisplayName LIKE '%graph%'
GROUP BY sp.DisplayName
HAVING COUNT(*) > 1;

-- Detect similar admin account names
SELECT u.UserPrincipalName, COUNT(*) as count 
FROM Users u
WHERE u.UserPrincipalName LIKE '%admin%'
  OR u.UserPrincipalName LIKE '%support%'
GROUP BY u.UserPrincipalName
HAVING COUNT(*) > 1;

-- Detect similar user names with Levenshtein distance
SELECT u1.UserPrincipalName, u2.UserPrincipalName
FROM Users u1 
JOIN Users u2 ON u1.Id != u2.Id
WHERE LEVENSHTEIN_DISTANCE(u1.UserPrincipalName, u2.UserPrincipalName) <= 2;
```

### Baseline Deviation Monitoring

- Track normal patterns of account creation naming conventions
- Alert on deviations from established naming standards
- Monitor for accounts created with names similar to privileged accounts
- Track service principal naming patterns versus known Microsoft patterns

## 4. Mitigation Strategies

### Administrative Controls
- Implement strict account naming policies and standards
- Require approval workflow for service principal registration
- Enforce naming conventions through Azure Policy
- Regular review of similar account names

### Technical Controls
```json
{
  "accountNamingPolicy": {
    "prefixRequired": true,
    "allowedPrefixes": ["dep-", "proj-", "svc-"],
    "prohibitedPatterns": ["admin*", "*microsoft*", "*azure*"],
    "minimumLength": 8,
    "maximumLength": 64
  },
  "servicePrincipalControls": {
    "requireApproval": true,
    "allowedPatterns": ["^[a-z0-9-]+$"],
    "restrictedKeywords": ["microsoft", "azure", "graph", "admin"]
  }
}
```

### Monitoring Controls
- Real-time alerts for similar name creation
- Daily reports of account naming pattern analysis
- Automated comparison of new accounts against existing ones
- Periodic review of service principal naming patterns

## 5. Incident Response Playbook

### Initial Detection
1. Identify suspicious account creation events
2. Compare against known naming patterns
3. Check for temporal proximity to other suspicious activities
4. Review account creator's history and permissions

### Investigation
1. Document all similarly named accounts
2. Review permissions and group memberships
3. Check for associated credential changes
4. Analyze authentication patterns
5. Review audit logs for creation context

### Containment
1. Disable suspicious accounts
2. Remove added permissions and credentials
3. Block associated authentication tokens
4. Document and preserve evidence
5. Review similar accounts for indicators of compromise

## 6. References

- MITRE ATT&CK: https://attack.mitre.org/techniques/T1036/010
- Microsoft Documentation:
  - [Managing Service Principals](https://docs.microsoft.com/azure/active-directory/develop/app-objects-and-service-principals)
  - [Monitoring Identity Security](https://docs.microsoft.com/azure/active-directory/identity-protection/overview-identity-protection)
- [Microsoft Security Best Practices](https://docs.microsoft.com/security/compass/microsoft-security-compass-introduction)

This model is designed to be customized based on your organization's specific Microsoft 365 and Entra ID implementation and security requirements.

---

# Threat Model: Transfer Data to Cloud Account (T1537) in Microsoft 365 & Entra ID

## 1. Overview
In Microsoft 365 environments, adversaries may exfiltrate data by transferring it to adversary-controlled accounts within the same tenant or to external tenants through sharing mechanisms. This technique abuses legitimate cloud sharing features and APIs to avoid detection focused on external data transfers.

## 2. Attack Vectors

### 2.1 SharePoint/OneDrive Anonymous Sharing Links
**Description**: Adversaries create anonymous sharing links for sensitive documents, enabling access without authentication.

**Detection Fields**:
```json
{
  "Operation": "AnonymousLinkCreated",
  "ObjectId": "/sites/finance/documents/strategic-plan.docx",
  "UserType": "Regular",
  "UserId": "john.smith@company.com",
  "ClientIP": "192.168.1.100",
  "LinkType": "Anonymous", 
  "SiteUrl": "https://company.sharepoint.com/sites/finance",
  "SourceFileName": "strategic-plan.docx",
  "CreationTime": "2024-01-20T15:30:00"
}
```

### 2.2 Delegated Admin Relationships
**Description**: Adversaries establish delegated admin relationships to gain persistent access to tenant resources.

**Detection Fields**:
```json
{
  "Operation": "Add partner to company.",
  "ObjectId": "PartnerTenantId=12345678",
  "UserId": "admin@company.com",
  "ApplicationId": "Partner Portal App ID",
  "ResultStatus": "Success",
  "PartnerName": "Malicious IT Services",
  "DelegatedPrivileges": ["Exchange Admin", "SharePoint Admin"]
}
```

### 2.3 Cross-Tenant Collection Access
**Description**: Adversaries grant external tenant access to collections/sites containing sensitive data.

**Detection Fields**:
```json
{
  "Operation": "SharingInvitationCreated", 
  "ObjectId": "/sites/hr/salary-data",
  "TargetUserOrGroupType": "External",
  "TargetUserOrGroupName": "user@external-domain.com",
  "Permission": ["Full Control", "Edit"],
  "SiteUrl": "https://company.sharepoint.com/sites/hr",
  "ClientIP": "10.1.1.100"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules
```sql
-- Detect excessive anonymous link creation
SELECT UserId, COUNT(*) as LinkCount
FROM AuditLogs 
WHERE Operation = 'AnonymousLinkCreated'
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 10;

-- Monitor external sharing to new domains
SELECT TargetUserOrGroupName, COUNT(*) as ShareCount
FROM AuditLogs
WHERE Operation IN ('SharingInvitationCreated', 'SharingSet')
AND TargetUserOrGroupType = 'External'
AND TimeGenerated > ago(24h)
GROUP BY TargetUserOrGroupName
HAVING COUNT(*) > 5;
```

### 3.2 Baseline Deviations
- Track normal sharing patterns per department/site
- Alert on >50% increase in external sharing volume
- Monitor sharing outside business hours
- Track new external domains receiving shared content

## 4. Mitigation Controls

### Administrative Controls
- Disable anonymous link creation
- Require admin approval for external sharing
- Implement data loss prevention policies
- Enable alerts for sensitive data sharing

### Technical Controls
```json
{
  "sharingCapability": "ExternalUserSharingOnly",
  "conditionalAccessPolicies": {
    "locations": {
      "includeLocations": ["AllTrusted"],
      "excludeLocations": ["AllUntrusted"]
    },
    "applications": {
      "includeApplications": ["Office365"],
      "controls": ["blockDownloads"]
    }
  }
}
```

### Monitoring Controls
- Enable unified audit logging
- Configure DLP alerts for sensitive data types
- Monitor admin activities in SharePoint admin center
- Track external sharing reports

## 5. Investigation Playbook

### Initial Response
1. Identify affected content and sharing patterns
2. Review audit logs for sharing activities
3. Document external domains/users involved
4. Assess data sensitivity and scope

### Containment 
1. Disable sharing links
2. Remove external access
3. Block suspect domains
4. Isolate compromised accounts

### Recovery
1. Revoke delegated permissions
2. Reset compromised credentials
3. Review and update sharing policies
4. Implement additional monitoring

## 6. References
- [Microsoft External Sharing Overview](https://docs.microsoft.com/en-us/microsoft-365/solutions/external-access-policies)
- [SharePoint Online Security](https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-and-onedrive)
- [MITRE T1537](https://attack.mitre.org/techniques/T1537/)
- [Microsoft 365 Defender](https://docs.microsoft.com/en-us/microsoft-365/security/defender/microsoft-365-defender)

---

# Threat Model: Create Account (T1136) in Microsoft 365 & Entra ID

## 1. Overview

Adversaries create accounts in Microsoft 365 and Entra ID environments to maintain persistent access without relying on malware. This can include:
- Creating new user accounts
- Registering service principals/applications 
- Creating additional credentials for existing accounts
- Adding delegated administrators

## 2. Attack Vectors

### 2.1 New User Account Creation

**Description:**
Adversaries with Global Admin or User Admin privileges create new user accounts to maintain access.

**Audit Log Detection Fields:**
```json
{
  "Operation": "Add user.",
  "ObjectId": "[UserPrincipalName]",
  "UserId": "[Admin UPN]",
  "ResultStatus": "Success",
  "Workload": "AzureActiveDirectory",
  "Parameters": [
    {
      "Name": "UserType",
      "Value": "Member" 
    },
    {
      "Name": "UserPrincipalName",
      "Value": "john.smith@contoso.com"
    }
  ]
}
```

### 2.2 Application Registration 

**Description:**
Attackers register new applications to create service principals with API permissions.

**Audit Log Detection Fields:**
```json
{
  "Operation": "Add service principal.",
  "ObjectId": "[AppId]",
  "UserId": "[Admin UPN]", 
  "ApplicationId": "[AppId]",
  "Parameters": [
    {
      "Name": "AppDisplayName",
      "Value": "Data Sync App"
    },
    {
      "Name": "ServicePrincipalType", 
      "Value": "Application"
    }
  ]
}
```

### 2.3 Delegated Admin Addition

**Description:**
Adversaries add partner/delegated admin accounts to maintain privileged access.

**Audit Log Detection Fields:**
```json
{
  "Operation": "Add partner to company.",
  "ObjectId": "[TenantId]",
  "UserId": "[Admin UPN]",
  "Parameters": [
    {
      "Name": "PartnerTenantId",
      "Value": "12345678-1234-1234-1234-123456789012"
    },
    {
      "Name": "Role",
      "Value": "GlobalAdministrator"
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect unusual account creation patterns
SELECT UserId, Operation, COUNT(*) as create_count
FROM AuditLogs 
WHERE Operation IN ('Add user.', 'Add service principal.')
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING COUNT(*) > 3;

-- Alert on off-hours account creation
SELECT * FROM AuditLogs
WHERE Operation = 'Add user.'
AND TimeGenerated.Hour NOT BETWEEN 9 AND 17;
```

### 3.2 Baseline Deviation Monitoring

- Establish baseline for:
  - Average number of accounts created per day
  - Typical account creation times
  - Common account creator locations
  - Normal application registration patterns

- Alert on deviations:
  - >25% increase in daily account creation
  - Account creation from new locations
  - Bulk application registrations

## 4. Mitigation Controls

### 4.1 Technical Controls
```json
{
  "conditionalAccessPolicies": {
    "userAccountCreation": {
      "requireMFA": true,
      "allowedLocations": ["Corporate Network"],
      "allowedRoles": ["Global Administrator", "User Administrator"]
    },
    "applicationRegistration": {
      "enabled": false,
      "exceptRoles": ["Application Administrator"]
    }
  },
  "auditingSettings": {
    "retentionDays": 90,
    "enableDetailedLogs": true
  }
}
```

### 4.2 Administrative Controls
- Implement JIT/PAM for admin access
- Review admin roles monthly
- Require business justification for new accounts
- Monitor partner/delegated admin relationships

### 4.3 Monitoring Controls
- Enable unified audit logging
- Configure alerts for:
  - New admin accounts
  - Service principal creation
  - Partner relationship changes
  - Multiple failed account creations

## 5. Incident Response

### 5.1 Initial Investigation
1. Gather account creation audit logs
2. Review creator's authentication logs
3. Check account properties and group membership
4. Analyze application permissions if service principal

### 5.2 Containment
1. Disable suspect accounts
2. Revoke access tokens
3. Remove delegated permissions
4. Reset admin credentials if compromised

### 5.3 Remediation
1. Delete unauthorized accounts
2. Review conditional access policies
3. Implement additional monitoring
4. Update account provisioning processes

## 6. References

- [MITRE ATT&CK T1136](https://attack.mitre.org/techniques/T1136/)
- [Microsoft Account Creation Security](https://docs.microsoft.com/security/account-creation)
- [Entra ID Monitoring Guide](https://docs.microsoft.com/azure/active-directory/monitoring)
- [Application Registration Security](https://docs.microsoft.com/azure/active-directory/develop/security-best-practices)

---

# Threat Model: Cloud Service Discovery (T1526) in Microsoft 365 & Entra ID

## Overview
Adversaries may attempt to enumerate Microsoft 365 and Entra ID services and configurations after gaining initial access to gather intelligence for further attacks. Key discovery targets include service principals, application registrations, authentication settings, and tenant configurations.

## Attack Vectors

### 1. Service Principal Enumeration
**Description**: Adversaries query service principal and application registrations to map available services and permissions.

**Scenario**: An attacker with compromised credentials uses PowerShell to enumerate all service principals and application registrations.

**Detection Fields**:
- Operation: "Add service principal", "Add service principal credentials"
- Actor: User/Service Principal performing enumeration
- Target: Service Principal IDs being accessed
- ResultStatus: Success/Failure

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T15:30:22",
  "Id": "abc123", 
  "Operation": "Add service principal",
  "OrganizationId": "contoso.onmicrosoft.com",
  "RecordType": "AzureActiveDirectory",
  "ResultStatus": "Success",
  "LogonType": "AzureServicePrincipal",
  "UserType": "Regular",
  "Actor": {
    "ID": "user@contoso.com",
    "Type": "User"
  },
  "Target": {
    "ID": "serviceprincipal123",
    "Type": "ServicePrincipal"
  }
}
```

### 2. Management API Discovery
**Description**: Adversaries use Microsoft Graph API or Azure Resource Manager API to discover available services and resources.

**Detection Fields**:
- Operation: SearchQueryPerformed, ProjectAccessed, ProjectListAccessed 
- ActorIPAddress: Source IP
- UserAgent: API client information
- QueryParameters: API query details

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T16:45:13",
  "Id": "def456",
  "Operation": "SearchQueryPerformed", 
  "RecordType": "SharePoint",
  "UserType": "Regular",
  "ActorIpAddress": "192.168.1.100",
  "UserAgent": "Microsoft Graph PowerShell SDK",
  "QueryParameters": "/v1.0/applications?$select=id,displayName,appRoles",
  "ResultCount": 250
}
```

### 3. Federation Settings Discovery
**Description**: Adversaries enumerate federation settings and domain trusts to identify authentication paths.

**Detection Fields**:
- Operation: "Set federation settings on domain", "Verify domain"
- ModifiedProperties: Changed federation settings
- DomainName: Target domain
- ResultStatus: Success/Failure

**Example Log**:
```json
{
  "CreationTime": "2024-01-20T17:15:44",
  "Id": "ghi789",
  "Operation": "Set federation settings on domain",
  "RecordType": "AzureActiveDirectory",
  "DomainName": "contoso.com",
  "ModifiedProperties": [
    {
      "Name": "FederationSettings",
      "OldValue": null,
      "NewValue": "WsFed:https://sts.contoso.com"
    }
  ]
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect rapid service principal enumeration
SELECT Actor.ID, COUNT(*) as query_count
FROM AuditLogs
WHERE Operation IN ('Add service principal', 'Add service principal credentials')
AND TimeGenerated > ago(1h)
GROUP BY Actor.ID
HAVING COUNT(*) > 50

-- Alert on federation setting changes from new IP addresses
SELECT ActorIpAddress, Operation
FROM AuditLogs 
WHERE Operation = 'Set federation settings on domain'
AND ActorIpAddress NOT IN (SELECT IPAddress FROM known_admin_ips)
```

### Baseline Deviations
- Monitor for >25% increase in API queries per hour compared to baseline
- Alert on first-time federation configuration changes from users/IPs
- Track service principal enumeration velocity against historical patterns

### Technical Controls
```json
{
  "conditionalAccessPolicy": {
    "name": "Block High-Risk API Access",
    "conditions": {
      "applications": {
        "includeApplications": ["Microsoft Graph API"]
      },
      "users": {
        "allUsers": true
      },
      "riskLevels": ["high"]
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }
}
```

### Administrative Controls
1. Implement least-privilege access model
2. Enable detailed API auditing
3. Require MFA for all administrative operations
4. Regularly review service principal permissions

### Monitoring Controls
1. Configure alerts for:
   - Bulk service principal queries (>50/hour)
   - Federation setting changes
   - First-time Graph API usage
   - Anomalous discovery patterns

## Incident Response Steps

1. Initial Detection
   - Review audit logs for enumeration patterns
   - Identify affected services and accounts
   - Document source IPs and actors

2. Investigation
   - Map unauthorized service discovery activities
   - Review authentication logs for related compromise
   - Analyze API usage patterns

3. Containment
   - Block suspicious IPs/users
   - Revoke compromised credentials
   - Enable additional monitoring

## References
- [Microsoft Graph Security API](https://docs.microsoft.com/graph/security-concept-overview)
- [Azure AD Audit Log Schema](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities)
- [MITRE T1526](https://attack.mitre.org/techniques/T1526/)

---

# Threat Model: Cloud Service Dashboard (T1538) in Microsoft 365 & Entra ID

## 1. Overview

Adversaries may use the Microsoft 365 Admin Center, Azure Portal, SharePoint Admin Center, and other administrative dashboards to gather information about the environment after compromising admin credentials. This provides a GUI-based method to enumerate services, configurations, and resources without generating API calls.

## 2. Attack Vectors

### 2.1 Microsoft 365 Admin Center Access
**Description**: Adversaries with compromised Global Admin or other admin roles access the M365 Admin Center to enumerate users, groups, licenses, and service configurations.

**Detection Fields**:
```json
{
  "Operation": "UserLoggedIn",
  "UserType": "Admin",
  "ApplicationId": "a0c73c16-a7e3-4564-9a95-2bdf47383716", // M365 Admin Portal
  "ActorIpAddress": "<ip>",
  "UserId": "<upn>",
  "DeviceProperties": {
    "TrustType": "Unmanaged",
    "DeviceID": null
  }
}
```

**Example Attack Pattern**:
- Initial admin credential compromise
- Login to admin.microsoft.com from unmanaged device
- Browse users, groups, billing, and service settings pages
- Download user lists and configuration reports

### 2.2 SharePoint Admin Center Enumeration
**Description**: Adversaries access SharePoint admin portal to map site collections, external sharing settings, and data access policies.

**Detection Fields**:
```json
{
  "Operation": "ViewRole", // Admin portal role view
  "Workload": "SharePoint",
  "ObjectId": "/", // Root level access
  "UserId": "<upn>",
  "ClientIP": "<ip>",
  "UserAgent": "<browser>",
  "SiteUrl": "https://<tenant>-admin.sharepoint.com"
}
```

### 2.3 Teams Admin Center Access 
**Description**: Adversaries enumerate Teams configurations, policies, and user settings through the Teams Admin Center.

**Detection Fields**:
```json
{
  "Operation": "TeamsTenantSettingChanged",
  "ObjectId": "Organization",
  "UserId": "<upn>", 
  "ApplicationDisplayName": "Microsoft Teams Admin Portal",
  "AdditionalDetails": [
    {
      "key": "Setting",
      "value": "ExternalAccess" 
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
-- Detect admin portal access from new locations
SELECT UserId, ClientIP, COUNT(*) as access_count
FROM AuditLogs 
WHERE Operation = 'UserLoggedIn'
AND ApplicationId = 'a0c73c16-a7e3-4564-9a95-2bdf47383716'
GROUP BY UserId, ClientIP
HAVING COUNT(*) = 1

-- Alert on multiple admin portals accessed in short time
SELECT UserId, COUNT(DISTINCT ApplicationId) as portal_count
FROM AuditLogs
WHERE TimeGenerated > ago(1h)
AND Operation = 'UserLoggedIn' 
AND UserType = 'Admin'
GROUP BY UserId
HAVING COUNT(DISTINCT ApplicationId) > 3
```

### 3.2 Baseline Deviations
- Monitor typical admin portal access patterns per user
- Alert on deviations in:
  - Number of pages/resources accessed
  - Time spent in admin portals
  - Sequence of portal access
  - Volume of config changes

### 3.3 Risk Scoring
```json
{
  "risk_factors": {
    "new_ip_address": 40,
    "unmanaged_device": 30,
    "outside_business_hours": 20,
    "multiple_portals": 25,
    "config_changes": 35
  },
  "threshold": 75
}
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement just-in-time access for admin roles
- Require Privileged Identity Management (PIM)
- Enforce conditional access policies for admin portals
- Regular access reviews for admin roles

### Technical Controls
```json
{
  "conditional_access": {
    "admin_portals": {
      "require_mfa": true,
      "block_unmanaged": true,
      "allowed_locations": ["corporate_networks"],
      "session_controls": {
        "sign_in_frequency": "1_hour",
        "persistent_browser": false
      }
    }
  }
}
```

### Monitoring Controls
- Enable Unified Audit Logging
- Configure alerts for suspicious admin activities
- Monitor PIM activation patterns
- Track admin portal usage metrics

## 5. Response Playbook

### Initial Detection
1. Validate admin portal access alerts
2. Verify user identity and role assignments
3. Check authentication context (device, location, MFA)

### Investigation
1. Review audit logs for accessed resources
2. Map timeline of admin portal activities
3. Identify any configuration changes made
4. Correlate with other suspicious activities

### Containment
1. Revoke suspicious admin sessions
2. Reset compromised credentials
3. Review and revert unauthorized changes
4. Enable stricter monitoring controls

## 6. References

- [MITRE T1538](https://attack.mitre.org/techniques/T1538/)
- [Microsoft Security Documentation](https://docs.microsoft.com/security/)
- [Azure AD Audit Logs Schema](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities)

---

# Threat Model: Additional Email Delegate Permissions (T1098.002) in Microsoft 365 & Entra ID

## 1. Overview

Adversaries can add delegate permissions to maintain persistent access to compromised mailboxes in Microsoft 365. This technique abuses legitimate Exchange Online functionality like:
- Full Access mailbox permissions 
- Folder-level permissions
- Calendar delegation
- Send As/Send on Behalf rights

## 2. Attack Vectors

### 2.1 Full Mailbox Delegation

**Description:**
Adversary adds Full Access permissions to a compromised mailbox using Exchange PowerShell or Admin portal.

**Attack Scenario:**
1. Attacker compromises admin account
2. Uses Add-MailboxPermission to grant full access to attacker-controlled account
3. Maintains persistent access even if original compromise is detected

**Detection Fields:**
```json
{
  "Operation": "Add-MailboxPermission",
  "ObjectId": "[Mailbox GUID]",
  "Parameters": {
    "AccessRights": ["FullAccess"],
    "User": "[Delegate Account]",
    "InheritanceType": "All"
  }
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-15T10:22:31",
  "Id": "8382d091-c2c3-4de8-b226-0a6d063559a4",
  "Operation": "Add-MailboxPermission", 
  "OrganizationId": "b36a5e0e-e6f2-48e3-9d61-5c627d915276",
  "RecordType": "ExchangeAdmin",
  "ResultStatus": "Success",
  "UserKey": "admin@contoso.com",
  "ObjectId": "d6e82687-b729-4d8e-8a41-d92577c0e762",
  "Parameters": {
    "AccessRights": ["FullAccess"],
    "User": "attacker@contoso.com",
    "Identity": "victim@contoso.com",
    "InheritanceType": "All"
  }
}
```

### 2.2 Folder Level Permissions

**Description:** 
Attacker modifies permissions on specific mailbox folders to maintain targeted access.

**Attack Scenario:**
1. Compromises user account
2. Adds permissions to sensitive folders like Inbox
3. Uses secondary account to access folder contents

**Detection Fields:**
```json
{
  "Operation": "AddFolderPermissions",
  "ObjectId": "[Folder Path]",
  "Parameters": {
    "FolderName": "Inbox",
    "User": "[Delegate]",
    "AccessRights": ["ReadItems", "CreateItems"]
  }
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-15T11:45:12", 
  "Id": "72a622f1-4e8b-4f1c-9de4-982d7c93d284",
  "Operation": "AddFolderPermissions",
  "RecordType": "ExchangeAdmin",
  "UserKey": "user@contoso.com",
  "ObjectId": "/inbox",
  "Parameters": {
    "FolderName": "Inbox",
    "User": "attacker@contoso.com",
    "AccessRights": ["ReadItems", "CreateItems"],
    "SharingPermissionFlags": "Delegate"
  }
}
```

### 2.3 Calendar Delegation 

**Description:**
Adversary adds calendar permissions as a stepping stone to further access.

**Attack Scenario:**
1. Adds calendar delegate access
2. Uses visibility into schedule for social engineering
3. Escalates to additional permissions

**Detection Fields:**
```json
{
  "Operation": "UpdateCalendarDelegation",
  "ObjectId": "[Calendar ID]", 
  "Parameters": {
    "User": "[Delegate]",
    "AccessRights": ["Editor"]
  }
}
```

**Example Log:**
```json
{
  "CreationTime": "2024-01-15T14:33:09",
  "Id": "92bf1a2c-4e21-482b-91d4-2f01a9e77d3c", 
  "Operation": "UpdateCalendarDelegation",
  "RecordType": "ExchangeItemAccess",
  "UserKey": "user@contoso.com",
  "ObjectId": "Calendar",
  "Parameters": {
    "User": "attacker@contoso.com",
    "AccessRights": ["Editor"],
    "SharingPermissionFlags": "Delegate"
  }
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics

```sql
-- Detect multiple mailbox delegation changes in short period
SELECT UserKey, COUNT(*) as changes
FROM ExchangeAuditLogs 
WHERE Operation IN ('Add-MailboxPermission','UpdateCalendarDelegation','AddFolderPermissions')
AND TimeGenerated > ago(1h)
GROUP BY UserKey
HAVING COUNT(*) > 5
```

### 3.2 Baseline Deviation

- Monitor for unusual delegation patterns outside business hours
- Alert on delegation to accounts with no previous relationship
- Track historical baseline of delegation activity per user/department

### 3.3 Critical Combinations

```sql
-- Detect delegation followed by suspicious access
SELECT a.UserKey, a.Operation, b.Operation
FROM ExchangeAuditLogs a
JOIN ExchangeAuditLogs b 
  ON a.ObjectId = b.ObjectId
WHERE a.Operation = 'Add-MailboxPermission'
AND b.Operation IN ('MailItemsAccessed','Send')
AND b.TimeGenerated BETWEEN a.TimeGenerated AND dateadd(hour,1,a.TimeGenerated)
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement approval workflow for mailbox delegation changes
- Regular review of delegation permissions
- Restrict delegation to authorized business hours

### Technical Controls
```json
{
  "mailboxDelegation": {
    "requireApproval": true,
    "allowedDelegateTypes": ["calendar", "inbox"],
    "restrictedRecipients": ["external"],
    "auditingEnabled": true,
    "maxDelegatesPerMailbox": 3
  }
}
```

### Monitoring Controls
- Real-time alerts on critical mailbox permission changes
- Weekly reports of delegation activity
- Integration with SIEM for correlation

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected mailboxes
2. Document all delegation changes
3. Establish timeline of events

### Investigation
1. Review authentication logs for delegate accounts
2. Check for suspicious inbox rules or forwards
3. Search for data exfiltration evidence

### Containment
1. Remove unauthorized delegations
2. Reset compromised account credentials
3. Block suspicious delegate accounts
4. Enable MFA if not already enabled

## 6. References

- [MITRE T1098.002](https://attack.mitre.org/techniques/T1098/002/)
- [Microsoft Exchange Auditing](https://docs.microsoft.com/exchange/policy-and-compliance/mailbox-audit-logging/mailbox-audit-logging)
- [Exchange Online PowerShell](https://docs.microsoft.com/powershell/exchange/exchange-online-powershell)

---

# Threat Model: Serverless Execution (T1648) in Microsoft 365 & Entra ID

## 1. Overview

In Microsoft 365 environments, adversaries can abuse serverless execution capabilities primarily through:
- Power Automate flows
- Azure Functions 
- Logic Apps
- SharePoint workflows
- Microsoft Teams webhooks

## 2. Attack Vectors

### Vector 1: Malicious Power Automate Flows

**Description:**
Adversaries create Power Automate flows that automatically exfiltrate data or grant permissions when triggered by events.

**Attack Scenario:**
1. Attacker compromises user account with Power Automate access
2. Creates flow triggered by email arrival events
3. Flow automatically forwards emails to external address
4. Flow runs with compromised user's permissions

**Detection Fields:**
```json
{
  "CreationTime": "2024-01-20T15:30:22",
  "Id": "<GUID>",
  "Operation": "Add delegation entry.",
  "RecordType": "AzureActiveDirectory",
  "ServicePrincipalId": "PowerAutomateServicePrincipal",
  "ServicePrincipalName": "Microsoft Power Automate",
  "TargetResources": [
    {
      "Type": "ServicePrincipal",
      "ID": "<GUID>", 
      "Permissions": ["Mail.Read", "Mail.Send"]
    }
  ],
  "ActorUserId": "attacker@victim.com"
}
```

### Vector 2: Malicious Azure Functions

**Description:** 
Adversaries deploy Azure Functions that execute malicious code when triggered by Microsoft 365 events.

**Attack Scenario:**
1. Attacker creates Azure Function with HTTP trigger
2. Configures Teams webhook to call function
3. Function executes malicious code with system privileges
4. Triggered by normal Teams activity

**Detection Fields:**
```json
{
  "CreationTime": "2024-01-20T16:45:33",
  "Operation": "Add service principal.",
  "RecordType": "AzureActiveDirectory", 
  "ServicePrincipalProperties": {
    "AppId": "<GUID>",
    "DisplayName": "Suspicious-Function-App",
    "ServicePrincipalType": "Application"
  },
  "ActorUserId": "attacker@victim.com"
}
```

### Vector 3: SharePoint Workflow Abuse

**Description:**
Adversaries create SharePoint workflows that execute malicious actions when documents are modified.

**Attack Scenario:**
1. Attacker creates SharePoint workflow
2. Configures to trigger on document changes
3. Workflow grants excessive permissions
4. Executes with site collection privileges

**Detection Fields:**
```json
{
  "CreationTime": "2024-01-21T09:15:44",
  "Operation": "FlowCreated", 
  "Workload": "SharePoint",
  "ObjectId": "/sites/target/workflows/suspicious",
  "UserId": "attacker@victim.com",
  "ClientIP": "12.34.56.78",
  "EventSource": "SharePoint",
  "ItemType": "Workflow"
}
```

## 3. Detection Strategies

### Behavioral Analytics Rules

```sql
-- Detect suspicious Power Automate permissions
SELECT UserId, Operation, ServicePrincipalId, COUNT(*) as freq
FROM AuditLogs 
WHERE Operation = "Add delegation entry"
AND ServicePrincipalName LIKE '%Power Automate%'
GROUP BY UserId
HAVING freq > 5 -- Threshold for suspicious number of permission grants
IN TIMESPAN(1h);

-- Detect unusual Azure Function creation patterns
SELECT ActorUserId, Operation, COUNT(*) as count
FROM AuditLogs
WHERE Operation IN ('Add service principal')
AND ServicePrincipalProperties.ServicePrincipalType = 'Application' 
GROUP BY ActorUserId
HAVING count > 3 -- Threshold for suspicious number of function apps
IN TIMESPAN(24h);
```

### Baseline Deviation Monitoring
- Monitor normal rates of serverless resource creation
- Alert on deviations >2 standard deviations from baseline
- Track typical permission patterns granted to functions/flows
- Alert on unusual permission combinations

## 4. Mitigation Strategies

### Administrative Controls
1. Implement strict RBAC for serverless resource creation
2. Require approval for new Power Automate flows
3. Limit service principal creation rights
4. Enable advanced threat protection for serverless services

### Technical Controls
```json
{
  "powerAutomatePolicy": {
    "allowedTriggers": ["scheduled"],
    "blockedActions": ["Mail.Send", "Grant-Permission"],
    "requireApproval": true,
    "dataExfilLimit": "1MB"
  },
  "azureFunctionPolicy": {
    "allowedRuntimes": ["dotnet"],
    "networkRestrictions": true,
    "requiredTags": ["BusinessUnit", "Owner"]
  }
}
```

### Monitoring Controls
1. Enable verbose logging for serverless executions
2. Monitor permission changes to service principals
3. Track data flows to external endpoints
4. Alert on unusual execution patterns

## 5. IR Playbook

### Initial Detection
1. Review audit logs for suspicious serverless resource creation
2. Identify affected user accounts and permissions
3. Map resource relationships and triggers
4. Document execution patterns and data flows

### Investigation
1. Analyze serverless resource configurations
2. Review execution history and triggers
3. Map data exfiltration paths
4. Identify compromised accounts

### Containment
1. Disable suspicious flows/functions
2. Revoke excess permissions
3. Block external endpoints
4. Reset compromised credentials

## 6. References

- [MITRE T1648](https://attack.mitre.org/techniques/T1648/)
- [Microsoft Power Automate Security](https://docs.microsoft.com/power-automate/security)
- [Azure Functions Security](https://docs.microsoft.com/azure/azure-functions/security-concepts)
- [SharePoint Workflow Security](https://docs.microsoft.com/sharepoint/workflow-security)

---

# Threat Model: Office Test (T1137.002) in Microsoft 365 & Entra ID

## 1. Overview
The Office Test technique involves adversaries abusing Microsoft Office's registry-based test functionality to establish persistence by loading malicious DLLs when Office applications start. In Microsoft 365 and Entra ID environments, this attack typically manifests through:

- Remote document template modifications
- Add-in installations via Microsoft 365 admin portals
- Custom DLL deployments through managed app policies

## 2. Attack Vectors

### 2.1 Office Template Manipulation
**Description**: Adversaries modify Office templates to include malicious code that loads when Office applications start.

**Detection Fields**:
```json
{
  "Operation": "Set-SPOSite",
  "ObjectId": "/sites/templates",
  "ModifiedProperties": [
    "CustomScriptEnabled",
    "AllowCustomTemplate"
  ],
  "UserId": "user@domain.com",
  "ClientIP": "10.1.1.1"
}
```

### 2.2 Add-in Deployment
**Description**: Attackers deploy malicious Office add-ins through admin portals.

**Detection Fields**:
```json
{
  "Operation": "Add service principal.",
  "ServicePrincipalName": "suspicious.add-in",
  "AppId": "9b1b1234-1234-1234-1234-123456789abc",
  "Permissions": ["Sites.ReadWrite.All", "Files.ReadWrite.All"],
  "InitiatingUser": "admin@domain.com",
  "TimeGenerated": "2024-01-20T10:15:00Z"
}
```

### 2.3 Custom DLL Distribution
**Description**: Malicious DLLs are distributed through managed app policies.

**Detection Fields**:
```json
{
  "Operation": "Update group.",
  "ObjectId": "SecurityGroup123",
  "ModifiedProperties": [
    {
      "Name": "AllowedFileTypes",
      "NewValue": "*.dll"
    }
  ],
  "ClientApplication": "Microsoft365 Admin Portal"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics
```sql
SELECT UserId, Operation, COUNT(*) as freq
FROM AuditLogs
WHERE Operation IN ('Add service principal.', 'Set-SPOSite')
  AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING freq > 3
```

### 3.2 Baseline Deviation
- Monitor template modification frequency vs historical baseline
- Track unusual admin portal access patterns
- Alert on abnormal DLL deployment activities

### 3.3 Technical Controls
```json
{
  "preventions": {
    "blockCustomDLLs": true,
    "enforceSignedAddIns": true,
    "restrictTemplateModification": true
  },
  "monitoring": {
    "templateChangeAlerts": true,
    "addInDeploymentAuditing": true,
    "dllLoadingLogs": true
  }
}
```

## 4. Incident Response

### Initial Detection
1. Identify source of template/add-in modification
2. Review admin portal access logs
3. Check for unauthorized DLL deployments

### Investigation
1. Analyze modified templates for malicious code
2. Review add-in permissions and configurations
3. Track lateral movement attempts

### Containment
1. Disable suspect add-ins
2. Block custom template usage
3. Reset affected user credentials

## 5. Mitigation Strategies

### Administrative Controls
- Enforce template change approval process
- Implement strict add-in deployment policies
- Regular security reviews of custom Office components

### Technical Controls
```json
{
  "officeSecurity": {
    "disableCustomTemplates": true,
    "blockUntrustedAddIns": true,
    "enforceApplicationGuard": true
  },
  "auditingConfig": {
    "enableDetailedLogging": true,
    "retentionDays": 90,
    "alertThresholds": {
      "templateChanges": 3,
      "addInDeployments": 2,
      "dllLoading": 1
    }
  }
}
```

### Monitoring Controls
- Real-time alerts for template modifications
- Add-in deployment monitoring
- DLL loading activity tracking

## 6. References
- MITRE ATT&CK: T1137.002
- Microsoft Security Documentation: Office Add-in Security
- Microsoft 365 Defender Portal: Advanced Hunting Schemas

---

# Threat Model: Application Access Token (T1550.001) in Microsoft 365 & Entra ID

## 1. Overview

Application access tokens in Microsoft 365 and Entra ID are primarily used with OAuth 2.0 for delegated and application permissions. Adversaries can abuse tokens through:

- OAuth consent phishing to obtain delegated permissions
- Service principal credential theft
- Token theft via compromised applications
- Forging tokens using stolen signing keys

## 2. Attack Vectors

### 2.1 OAuth Consent Phishing

**Description:**
Adversaries create malicious OAuth applications and trick users into granting permissions through phishing.

**Audit Operations:**
- Add service principal.
- Add delegation entry.
- Add service principal credentials.

**Example Log:**
```json
{
  "CreationTime": "2023-12-10T15:22:31",
  "Id": "8721fb2c-657f-4c4d-b5dd-12345678",
  "Operation": "Add service principal.",
  "OrganizationId": "4a7c9677-c974-4e4d-8f5a-12345678",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001C36C2E16",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "5c5a434c-0f1b-4657-b7e2-12345678",
  "UserId": "attacker@phishing.com",
  "AppId": "a2f7d745-98c8-4372-9876-12345678",
  "AppDisplayName": "Calendar Sync Tool",
  "Permissions": ["Mail.Read", "Mail.Send", "Files.ReadWrite.All"]
}
```

### 2.2 Service Principal Credential Theft 

**Description:**
Adversaries steal credentials configured for service principals to obtain tokens.

**Audit Operations:**
- Add service principal credentials.
- Update service principal.
- Remove service principal credentials.

**Example Log:**
```json
{
  "CreationTime": "2023-12-10T18:14:22", 
  "Id": "891de2f4-957d-4c2d-b5ef-12345678",
  "Operation": "Add service principal credentials.",
  "OrganizationId": "4a7c9677-c974-4e4d-8f5a-12345678", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "1002000C36A2B16",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "7d9a424c-1f3b-4897-b7e2-12345678",
  "UserId": "admin@victim.com",
  "KeyId": "9de734c2-8f54-42de-9876-12345678",
  "KeyType": "Password",
  "DisplayName": "ServicePrincipal-Backend"
}
```

### 2.3 Application Access Token Theft

**Description:** 
Adversaries compromise legitimate applications to steal tokens from token storage or in-transit.

**Audit Operations:**
- UsageLocation changed
- UserLoggedIn events from new locations
- Add delegation entry.

**Example Log:**
```json
{
  "CreationTime": "2023-12-10T22:45:11",
  "Id": "44fb892c-123f-4c4d-b5dd-12345678",
  "Operation": "UserLoggedIn", 
  "OrganizationId": "4a7c9677-c974-4e4d-8f5a-12345678",
  "RecordType": 15,
  "ResultStatus": "Success", 
  "UserKey": "10032001abcd1234",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "192.168.1.100",
  "UserId": "victim@company.com",
  "AppId": "de4871c2-4254-4e21-9876-12345678",
  "AppDisplayName": "Microsoft Office",
  "UserAgent": "Mozilla/5.0...",
  "Location": "Tokyo, Japan"
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect unusual delegation grants
SELECT UserId, Operation, COUNT(*) as count
FROM AuditLogs 
WHERE Operation = "Add delegation entry."
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING count > 10;

-- Detect service principal credential additions outside business hours
SELECT *
FROM AuditLogs
WHERE Operation = "Add service principal credentials."
AND TimeGenerated.hour() NOT BETWEEN 9 AND 17
AND TimeGenerated > ago(24h);

-- Detect token usage from new locations
SELECT UserId, ClientIP, Location, COUNT(*) as count
FROM SignInLogs
WHERE TimeGenerated > ago(24h)
GROUP BY UserId, ClientIP, Location
HAVING count = 1;
```

### 3.2 Baseline Deviation Monitoring

- Monitor for spikes in:
  - New service principal registrations (>3 per hour)
  - Delegation permission grants (>5 per user per day)
  - Token redemption from new IP addresses (>2 new IPs per user per day)
  - Application consent grants (>3 per user per day)

## 4. Mitigation Strategies

### 4.1 Administrative Controls

- Enable security defaults in Entra ID
- Implement Conditional Access policies
- Restrict service principal creation permissions
- Enable admin consent workflow
- Configure application allowlisting

### 4.2 Technical Controls

```json
{
  "conditionalAccessPolicy": {
    "name": "Block Suspicious Token Usage",
    "conditions": {
      "applications": {
        "includeApplications": ["All"]
      },
      "locations": {
        "includeLocations": ["All"]
      },
      "riskLevels": ["high", "medium"]
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }
}
```

### 4.3 Monitoring Controls

- Enable audit logging for all Azure AD activities
- Configure alerts for suspicious token-related activities
- Monitor service principal credential changes
- Track OAuth permission grants

## 5. Incident Response Playbook

1. Initial Detection:
   - Review OAuth consent grants
   - Check service principal credential changes
   - Analyze token usage patterns

2. Investigation:
   - Identify affected users/applications
   - Review application permissions
   - Check IP addresses and locations
   - Examine audit logs for lateral movement

3. Containment:
   - Revoke suspicious tokens
   - Disable compromised service principals
   - Block malicious applications
   - Reset affected credentials

## 6. References

1. MITRE ATT&CK: T1550.001
2. Microsoft: OAuth 2.0 authorization framework
3. Microsoft: Managing service principals
4. Microsoft: Investigating OAuth apps

---

# Threat Model: Cloud Accounts (T1078.004) in Microsoft 365 & Entra ID

## 1. Overview

Cloud account abuse in Microsoft 365 and Entra ID environments typically involves adversaries leveraging compromised or newly created accounts to maintain persistence and escalate privileges. Key risks include:

- Compromised admin accounts granting broad tenant access
- Service principals with overly permissive API access
- Federation trust abuse allowing hybrid identity attacks
- Long-term persistence via additional credentials/tokens

## 2. Attack Vectors 

### 2.1 Service Principal Credential Abuse

**Description**: Adversaries add credentials to existing service principals to maintain persistent API access.

**Audit Operations**:
- "Add service principal credentials."
- "Set delegation entry."
- "Add delegation entry."

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T15:22:43",
  "Id": "8721a24b-bc32-4f56-b76d-c2f89c34a02a", 
  "Operation": "Add service principal credentials.",
  "OrganizationId": "8bdef46c-2b17-4bc9-a023-9343f71c1e80",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001a341d307",
  "UserType": 0,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "63b1ad72-9d90-4932-b22f-49f8b044d121",
  "UserId": "admin@contoso.com",
  "AadAppId": "d526dbe9-0d39-4e74-9929-22f91983fe3c",
  "KeyIdentifier": "c9236b4f-0e9b-4ec7-9021-82b048ce1626",
  "KeyType": "Password",
  "KeyUsage": "Verify",
  "DisplayName": "ContosoServiceApp"
}
```

### 2.2 Admin Role Assignment

**Description**: Attackers elevate privileges by adding compromised accounts to privileged admin roles.

**Audit Operations**:
- "Add member to role."
- "Added role"
- "Add group."

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T18:14:22",
  "Id": "5582a24b-bc32-4f56-b76d-c2f89c34a543",
  "Operation": "Add member to role.",
  "OrganizationId": "8bdef46c-2b17-4bc9-a023-9343f71c1e80", 
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001a341d307",
  "UserType": 0,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "9837ad72-9d90-4932-b22f-49f8b044d876",
  "UserId": "attacker@contoso.com",
  "Target": "Global Administrator",
  "TargetId": "62e90394-69f5-4237-9190-012177145e10",
  "ModifiedProperties": [
    {
      "Name": "Role.DisplayName",
      "NewValue": "Global Administrator",
      "OldValue": ""
    }
  ]
}
```

### 2.3 Federation Trust Modification 

**Description**: Adversaries modify federation settings to enable authentication bypass.

**Audit Operations**:
- "Set federation settings on domain."
- "Set domain authentication."
- "Update domain."

**Example Log**:
```json
{
  "CreationTime": "2024-01-15T20:33:11",
  "Id": "9182a24b-bc32-4f56-b76d-c2f89c34a987",
  "Operation": "Set federation settings on domain.",
  "OrganizationId": "8bdef46c-2b17-4bc9-a023-9343f71c1e80",
  "RecordType": 8, 
  "ResultStatus": "Success",
  "UserKey": "10032001a341d307",
  "UserType": 0,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "contoso.com",
  "UserId": "admin@contoso.com",
  "DomainName": "contoso.com",
  "FederationBrandName": "Contoso IDP",
  "IssuerUri": "http://malicious.com/adfs/services/trust",
  "ModifiedProperties": [
    {
      "Name": "IssuerUri",
      "NewValue": "http://malicious.com/adfs/services/trust",
      "OldValue": "http://adfs.contoso.com/adfs/services/trust"
    }
  ]
}
```

## 3. Detection Strategies

### 3.1 Behavioral Analytics Rules

```sql
-- Detect unusual service principal credential additions
SELECT UserId, Count(*) as credential_adds
FROM AuditLogs 
WHERE Operation = "Add service principal credentials."
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING Count(*) > 3;

-- Alert on off-hours admin role assignments
SELECT * FROM AuditLogs
WHERE Operation = "Add member to role."
AND TargetResources.displayName CONTAINS "Admin"
AND TimeGenerated NOT BETWEEN '0800' AND '1800';
```

### 3.2 Baseline Deviation Monitoring

- Track normal patterns of service principal credential management
- Monitor typical admin role assignment frequency and timing
- Baseline federation configuration changes (rare in most environments)

### 3.3 Critical Alert Conditions

- Any modification to federation trust settings
- Service principal credential additions outside business hours
- Multiple admin role assignments in short timeframe
- New credential types not matching historical patterns

## 4. Mitigation Strategies

### 4.1 Administrative Controls

- Implement strict role-based access control (RBAC)
- Require MFA for all admin accounts 
- Regular access reviews for privileged roles
- Documented change control for federation settings

### 4.2 Technical Controls

```json
{
  "ConditionalAccessPolicies": {
    "AdminMFA": {
      "Users": ["All"],
      "Applications": ["All"],
      "Conditions": {
        "UserRisk": ["High"],
        "SignInRisk": ["High"],
        "Locations": ["All"] 
      },
      "GrantControls": {
        "Operator": "AND",
        "Controls": ["MFA", "CompliantDevice"]
      }
    }
  },
  "ServicePrincipalRestrictions": {
    "CredentialLifetime": "90d",
    "AllowedKeyTypes": ["Certificate"],
    "RequireApproval": true
  }
}
```

### 4.3 Monitoring Controls

- Real-time alerts for federation changes
- Daily admin role assignment reports
- Service principal credential inventory monitoring
- Automated admin account access reviews

## 5. Incident Response Playbook

1. Initial Detection
   - Identify affected accounts/principals
   - Document timeline of suspicious activity
   - Preserve audit logs

2. Investigation
   - Review authentication patterns
   - Check for additional compromised credentials
   - Analyze role changes and permission grants
   - Examine federation configuration history

3. Containment
   - Revoke suspicious credentials
   - Remove unauthorized role assignments
   - Reset affected admin accounts
   - Restore federation settings if compromised

## 6. References

- MITRE ATT&CK: T1078.004
- Microsoft Security Documentation:
  - [Securing privileged access](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/)
  - [Service principal security](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
  - [Federation security practices](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-fed-security-considerations)

---

# Threat Model: Modify Authentication Process (T1556) in Microsoft 365 & Entra ID

## Overview
In Microsoft 365 and Entra ID environments, adversaries may modify authentication mechanisms to bypass security controls and maintain persistent access. Key modification targets include:
- Federation settings and trusted domains
- Service principal authentication configurations
- Conditional Access policies
- MFA settings and enrollment policies

## Attack Vectors

### 1. Federation Trust Modification
**Description**: Adversaries modify federation trust settings to enable authentication bypass or credential theft.

**Attack Scenario**:
- Attacker compromises Global Admin account
- Adds new federation trust to adversary-controlled domain
- Enables Pass-Through Authentication to capture credentials
- Uses captured credentials to authenticate as any user

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Set federation settings on domain.",
    "Add domain to company.",
    "Set domain authentication."
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T15:30:22",
  "Id": "4a2f1f4c-e910-4f6c-8b85-96f00d37ea23",
  "Operation": "Set federation settings on domain",
  "OrganizationId": "4aa29ace-8acc-4e63-8c9d-2f7e9f981c24", 
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "domain.com",
  "UserId": "admin@contoso.com",
  "ClientIP": "192.168.1.100",
  "Parameters": [
    {
      "Name": "DomainName",
      "Value": "domain.com"
    },
    {
      "Name": "IssuerUri", 
      "Value": "http://malicious-idp.com"
    }
  ]
}
```

### 2. Service Principal Credential Manipulation
**Description**: Adversaries add credentials to existing service principals to maintain access.

**Attack Scenario**:
- Attacker compromises account with Application Administrator rights
- Adds new credentials to high-privilege service principal
- Uses service principal credentials to authenticate and access resources

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "Add service principal credentials.",
    "Update service principal.",
    "Add delegation entry."
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T16:45:33",
  "Id": "8b1a8f45-d48c-42aa-9c44-8f7e9b4e1234",
  "Operation": "Add service principal credentials",
  "OrganizationId": "4aa29ace-8acc-4e63-8c9d-2f7e9f981c24",
  "RecordType": 1,
  "ResultStatus": "Success", 
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "8f881f47-9f44-4ec4-b3aa-127f0f9c0033",
  "UserId": "admin@contoso.com",
  "ClientIP": "192.168.1.100",
  "Parameters": [
    {
      "Name": "ServicePrincipalId",
      "Value": "8f881f47-9f44-4ec4-b3aa-127f0f9c0033"
    },
    {
      "Name": "KeyType",
      "Value": "Password"
    }
  ]
}
```

### 3. Conditional Access Policy Tampering
**Description**: Adversaries modify conditional access policies to bypass security controls.

**Attack Scenario**: 
- Attacker gains access to Security Administrator role
- Disables MFA requirements for specific users/groups
- Creates policy exclusions for compromised accounts

**Relevant Audit Operations**:
```json
{
  "Operations": [
    "UpdatedPrivacySetting",
    "URbacAuthorizationStatusChanged",
    "DirectoryServicesAccountConfigurationUpdated"
  ]
}
```

**Example Audit Log**:
```json
{
  "CreationTime": "2024-01-20T17:15:12",
  "Id": "9c2e3f5d-b7aa-4522-95cc-1234567890ab",
  "Operation": "DirectoryServicesAccountConfigurationUpdated",
  "OrganizationId": "4aa29ace-8acc-4e63-8c9d-2f7e9f981c24",
  "RecordType": 1,
  "ResultStatus": "Success",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ObjectId": "Policy_123456",
  "UserId": "admin@contoso.com",
  "ClientIP": "192.168.1.100",
  "Parameters": [
    {
      "Name": "PolicyId",
      "Value": "Policy_123456"
    },
    {
      "Name": "ExcludedUsers",
      "Value": "[user1@contoso.com,user2@contoso.com]"
    }
  ]
}
```

## Detection Strategies

### Behavioral Analytics Rules
```sql
-- Detect unusual federation trust changes
SELECT UserId, ClientIP, COUNT(*) as changes
FROM AuditLogs 
WHERE Operation = "Set federation settings on domain"
AND TimeGenerated > ago(1h)
GROUP BY UserId, ClientIP
HAVING COUNT(*) > 2;

-- Monitor service principal credential additions
SELECT ServicePrincipalId, COUNT(*) as new_creds
FROM AuditLogs
WHERE Operation = "Add service principal credentials"
AND TimeGenerated > ago(24h)
GROUP BY ServicePrincipalId
HAVING COUNT(*) > 3;

-- Track conditional access policy modifications
SELECT UserId, Operation, COUNT(*) as policy_changes
FROM AuditLogs
WHERE Operation IN (
  "UpdatedPrivacySetting",
  "URbacAuthorizationStatusChanged"
)
AND TimeGenerated > ago(1h)
GROUP BY UserId, Operation
HAVING COUNT(*) > 5;
```

### Baseline Deviation Monitoring
- Monitor for changes to federation settings outside business hours
- Alert on service principal credential additions above historical baseline
- Track unusual patterns in conditional access policy modifications

## Mitigation Strategies

### Administrative Controls
1. Implement Role-Based Access Control (RBAC) for federation settings
2. Require multi-party approval for service principal credential changes 
3. Enable change tracking for conditional access policies

### Technical Controls
```json
{
  "ConditionalAccessPolicies": {
    "RequireMFA": true,
    "BlockLegacyAuthentication": true,
    "RestrictNonCompliantDevices": true
  },
  "SecurityDefaults": {
    "Enabled": true,
    "RequireMFAForAdmins": true
  },
  "FederationSettings": {
    "AllowedDomains": ["trusted-partner.com"],
    "BlockUntrustedFederation": true
  }
}
```

### Monitoring Controls
1. Enable unified audit logging
2. Configure alerts for critical authentication changes
3. Implement automated response playbooks

## Incident Response Playbook

### Initial Detection
1. Identify scope of authentication changes
2. Document modified settings and policies
3. Establish timeline of modifications

### Investigation
1. Review audit logs for associated activities
2. Identify compromised accounts/access paths
3. Determine blast radius of authentication changes

### Containment
1. Revert unauthorized authentication changes
2. Block compromised credentials/certificates
3. Reset affected service principal credentials

## References
- [MITRE T1556](https://attack.mitre.org/techniques/T1556/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/security/)
- [Azure AD Authentication Logs Schema](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities)

---

# Threat Model: Messaging Applications (T1213.005) in Microsoft 365 & Entra ID

## 1. Overview
Adversaries extract sensitive data and intelligence from Teams chats, channels, and other Microsoft 365 messaging platforms to obtain credentials, internal information, and details about ongoing IR efforts.

## 2. Attack Vectors

### 2.1 Teams Message History Exfiltration
**Description**: Adversaries access Teams chat history to extract sensitive information like credentials and internal discussions.

**Attack Scenario**: An attacker compromises an account and uses Teams APIs or web UI to scrape historical messages.

**Key Audit Operations**:
- MessagesExported
- MessageRead 
- MessagesListed
- ChatRetrieved

**Example Log**:
```json
{
  "CreationTime": "2024-02-15T15:30:22",
  "Id": "a7e89c33-de21-4c98-b69d-c159c4f8f45f",
  "Operation": "MessagesExported",
  "OrganizationId": "beb23354-f55c-41ed-893e-e5c7b3bb0eec",
  "RecordType": 25,
  "UserKey": "admin@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "MicrosoftTeams",
  "ObjectId": "19:meeting_MjExNGQ2ZTYtNTQ5Yy00NzY5LWFjZGItNTYzYTQ4OWM5Nzc2@thread.v2",
  "UserId": "admin@contoso.com",
  "CorrelationId": "a7cc89f3-a862-443e-9f5f-d2cbf5b23121",
  "EventSource": "SharePoint",
  "ItemType": "ChatMessage",
  "ExportType": "MessageHistory"
}
```

### 2.2 Teams Meeting Transcript Access
**Description**: Adversaries access meeting transcripts to gather intelligence about organizational activities.

**Attack Scenario**: Attacker downloads transcripts of sensitive meetings to gather information about security measures.

**Key Audit Operations**:
- TranscriptsExported
- RecordingExported
- MeetingParticipantDetail

**Example Log**:
```json
{
  "CreationTime": "2024-02-15T18:22:15",
  "Id": "b8f91c22-ae31-5c87-a79e-d249c5b8f32e", 
  "Operation": "TranscriptsExported",
  "OrganizationId": "beb23354-f55c-41ed-893e-e5c7b3bb0eec",
  "RecordType": 25,
  "UserKey": "attacker@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "MicrosoftTeams",
  "ObjectId": "19:meeting_NzY5YS00NzY5LWFjZGItNTYzYTQ4OWM5Nz@thread.v2",
  "UserId": "attacker@contoso.com",
  "EventSource": "SharePoint",
  "ItemType": "Meeting",
  "DataType": "Transcript"
}
```

### 2.3 Channel Message Monitoring
**Description**: Adversaries monitor Teams channels in real-time to gather intelligence about IR activities.

**Attack Scenario**: Attacker monitors security team channels to track incident response progress.

**Key Audit Operations**:
- MessageRead
- MessageHostedContentRead
- ChannelAdded

**Example Log**:
```json
{
  "CreationTime": "2024-02-15T19:45:33",
  "Id": "c9d92d44-bf42-6d98-b89f-e360d6c9f43f",
  "Operation": "MessageRead",
  "OrganizationId": "beb23354-f55c-41ed-893e-e5c7b3bb0eec", 
  "RecordType": 25,
  "UserKey": "suspect@contoso.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "MicrosoftTeams",
  "ObjectId": "19:channel_security_incident_response@thread.v2",
  "UserId": "suspect@contoso.com",
  "ChannelName": "Security Incident Response",
  "TeamName": "Security Team"
}
```

## 3. Detection Strategies

### Behavioral Analytics
```sql
-- Detect mass message access
SELECT UserId, COUNT(*) as message_reads
FROM TeamsAuditLog 
WHERE Operation IN ('MessageRead','MessagesListed')
AND TimeGenerated > ago(1h)
GROUP BY UserId
HAVING COUNT(*) > 1000

-- Detect unusual transcript downloads
SELECT UserId, COUNT(*) as transcript_exports
FROM TeamsAuditLog
WHERE Operation = 'TranscriptsExported'
AND TimeGenerated > ago(24h)
GROUP BY UserId
HAVING COUNT(*) > 5
```

### Baseline Deviations
- Track normal message access patterns per user/day
- Alert on 2x standard deviation increase
- Monitor after-hours message access volume
- Track unusual access to sensitive channels

### Correlation Rules
```sql
// Detect potential reconnaissance
let suspicious = TeamsAuditLog
| where TimeGenerated > ago(1h)
| where Operation in ('MessageRead','ChatRetrieved')
| summarize 
    message_count=count(),
    channels=dcount(ChannelName)
by UserId
| where message_count > 500 and channels > 10;

// Correlate with other suspicious activity
suspicious | join (
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == "50126" // MFA denied
) on UserId
```

## 4. Mitigation Strategies

### Administrative Controls
- Implement Teams retention policies
- Enable message supervision
- Configure sensitivity labels
- Restrict transcript downloads
- Enable audit logging

### Technical Controls
```json
{
  "teamsPolicy": {
    "allowTranscriptDownloads": false,
    "requireSensitivityLabels": true,
    "maxMessageHistoryDays": 180,
    "supervisionEnabled": true,
    "externalAccess": {
      "allowedDomains": ["partner.com"],
      "blockFileDownloads": true
    }
  }
}
```

### Monitoring Controls
- Monitor Teams admin activity
- Track policy changes
- Alert on mass message exports
- Monitor sensitive channel access
- Track transcript downloads

## 5. Incident Response Playbook

### Initial Detection
1. Identify affected accounts
2. Document accessed messages/channels
3. Determine data exposure scope
4. Note any exported content

### Investigation
1. Review authentication logs
2. Check for unusual access patterns
3. Analyze exported content
4. Review channel membership changes
5. Document timeline of events

### Containment
1. Suspend compromised accounts
2. Revoke active sessions
3. Reset affected credentials
4. Remove unauthorized channel access
5. Block suspicious IPs

## 6. References
- MITRE ATT&CK: T1213.005
- Microsoft Teams Audit Log Schema
- Microsoft Security Documentation
- Microsoft Teams Security Guide

---

