---
title: AWS SAML Provider Deletion Activity
summary: >-
  Detects the deletion of an AWS SAML provider, potentially indicating malicious intent to disrupt administrative or security team access.

  An attacker can remove the SAML provider for the information security team or a team of system administrators, to make it difficult for them to work and investigate at the time of the attack and
  after it.
sigma_id: ccd6a6c8-bb4e-4a91-9d2a-07e632819374
status: experimental
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0005
  - TA0004
  - TA0001
  - TA0003
  - TA0040
techniques:
  - T1078.004
  - T1531
author: Ivan Saakov
date: '2024-12-19'
falsepositives:
  - Automated processes using tools like Terraform may trigger this alert.
  - Legitimate administrative actions by authorized system administrators could cause this alert. Verify the user identity, user agent, and hostname to ensure they are expected.
  - Deletions by unfamiliar users should be investigated. If the behavior is known and expected, it can be exempted from the rule.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteSAMLProvider.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_delete_saml_provider.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS SAML Provider Deletion Activity
id: ccd6a6c8-bb4e-4a91-9d2a-07e632819374
status: experimental
description: |
    Detects the deletion of an AWS SAML provider, potentially indicating malicious intent to disrupt administrative or security team access.
    An attacker can remove the SAML provider for the information security team or a team of system administrators, to make it difficult for them to work and investigate at the time of the attack and after it.
references:
    - https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteSAMLProvider.html
author: Ivan Saakov
date: 2024-12-19
tags:
    - attack.stealth
    - attack.t1078.004
    - attack.privilege-escalation
    - attack.initial-access
    - attack.persistence
    - attack.t1531
    - attack.impact
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'iam.amazonaws.com'
        eventName: 'DeleteSAMLProvider'
        status: 'success'
    condition: selection
falsepositives:
    - Automated processes using tools like Terraform may trigger this alert.
    - Legitimate administrative actions by authorized system administrators could cause this alert. Verify the user identity, user agent, and hostname to ensure they are expected.
    - Deletions by unfamiliar users should be investigated. If the behavior is known and expected, it can be exempted from the rule.
level: medium
```
