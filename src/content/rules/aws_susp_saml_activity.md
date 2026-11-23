---
title: AWS Suspicious SAML Activity
summary: Identifies when suspicious SAML activity has occurred in AWS. An adversary could gain backdoor access via SAML.
sigma_id: f43f5d2f-3f2a-4cc8-b1af-81fde7dbaf0e
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0001
  - TA0008
  - TA0003
  - TA0004
techniques:
  - T1078
  - T1548
  - T1550
  - T1550.001
author: Austin Songer
date: '2021-09-22'
modified: '2022-12-18'
falsepositives:
  - Automated processes that uses Terraform may lead to false positives.
  - SAML Provider could be updated by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
  - SAML Provider being updated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_susp_saml_activity.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS Suspicious SAML Activity
id: f43f5d2f-3f2a-4cc8-b1af-81fde7dbaf0e
status: test
description: Identifies when suspicious SAML activity has occurred in AWS. An adversary could gain backdoor access via SAML.
references:
    - https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html
    - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
author: Austin Songer
date: 2021-09-22
modified: 2022-12-18
tags:
    - attack.initial-access
    - attack.lateral-movement
    - attack.persistence
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1078
    - attack.t1548
    - attack.t1550
    - attack.t1550.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_sts:
        eventSource: 'sts.amazonaws.com'
        eventName: 'AssumeRoleWithSAML'
    selection_iam:
        eventSource: 'iam.amazonaws.com'
        eventName: 'UpdateSAMLProvider'
    condition: 1 of selection_*
falsepositives:
    - Automated processes that uses Terraform may lead to false positives.
    - SAML Provider could be updated by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - SAML Provider being updated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium
```
