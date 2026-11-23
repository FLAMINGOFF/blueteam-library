---
title: AWS STS AssumeRole Misuse
summary: Identifies the suspicious use of AssumeRole. Attackers could move laterally and escalate privileges.
sigma_id: 905d389b-b853-46d0-9d3d-dea0d3a3cd49
status: test
level: low
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0008
  - TA0004
techniques:
  - T1548
  - T1550
  - T1550.001
author: Austin Songer @austinsonger
date: '2021-07-24'
modified: '2022-10-09'
falsepositives:
  - AssumeRole may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
  - AssumeRole from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
  - Automated processes that uses Terraform may lead to false positives.
references:
  - https://github.com/elastic/detection-rules/pull/1214
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_sts_assumerole_misuse.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS STS AssumeRole Misuse
id: 905d389b-b853-46d0-9d3d-dea0d3a3cd49
status: test
description: Identifies the suspicious use of AssumeRole. Attackers could move laterally and escalate privileges.
references:
    - https://github.com/elastic/detection-rules/pull/1214
    - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
author: Austin Songer @austinsonger
date: 2021-07-24
modified: 2022-10-09
tags:
    - attack.lateral-movement
    - attack.privilege-escalation
    - attack.t1548
    - attack.t1550
    - attack.t1550.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        userIdentity.type: AssumedRole
        userIdentity.sessionContext.sessionIssuer.type: Role
    condition: selection
falsepositives:
    - AssumeRole may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - AssumeRole from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
    - Automated processes that uses Terraform may lead to false positives.
level: low
```
