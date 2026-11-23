---
title: AWS Successful Console Login Without MFA
summary: |-
  Detects successful AWS console logins that were performed without Multi-Factor Authentication (MFA).
  This alert can be used to identify potential unauthorized access attempts, as logging in without MFA can indicate compromised credentials or misconfigured security settings.
sigma_id: 77caf516-34e5-4df9-b4db-20744fea0a60
status: experimental
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0001
  - TA0003
  - TA0004
  - TA0005
techniques:
  - T1078.004
author: Thuya@Hacktilizer, Ivan Saakov
date: '2025-10-18'
modified: '2025-10-21'
falsepositives:
  - Unlikely
references:
  - https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/iam-user-without-mfa/
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_success_without_mfa.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS Successful Console Login Without MFA
id: 77caf516-34e5-4df9-b4db-20744fea0a60
status: experimental
description: |
    Detects successful AWS console logins that were performed without Multi-Factor Authentication (MFA).
    This alert can be used to identify potential unauthorized access attempts, as logging in without MFA can indicate compromised credentials or misconfigured security settings.
references:
    - https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/iam-user-without-mfa/
    - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
author: Thuya@Hacktilizer, Ivan Saakov
date: 2025-10-18
modified: 2025-10-21
tags:
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: 'ConsoleLogin'
        additionalEventData.MFAUsed: 'NO'
        responseElements.ConsoleLogin: 'Success'
    condition: selection
falsepositives:
    - Unlikely
level: medium
```
