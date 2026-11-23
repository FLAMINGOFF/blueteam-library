---
title: AWS STS GetSessionToken Misuse
summary: Identifies the suspicious use of GetSessionToken. Tokens could be created and used by attackers to move laterally and escalate privileges.
sigma_id: b45ab1d2-712f-4f01-a751-df3826969807
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
  - >-
    GetSessionToken may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. GetSessionToken from
    unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
references:
  - https://github.com/elastic/detection-rules/pull/1213
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_sts_getsessiontoken_misuse.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS STS GetSessionToken Misuse
id: b45ab1d2-712f-4f01-a751-df3826969807
status: test
description: Identifies the suspicious use of GetSessionToken. Tokens could be created and used by attackers to move laterally and escalate privileges.
references:
    - https://github.com/elastic/detection-rules/pull/1213
    - https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html
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
        eventSource: sts.amazonaws.com
        eventName: GetSessionToken
        userIdentity.type: IAMUser
    condition: selection
falsepositives:
    - GetSessionToken may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. GetSessionToken from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: low
```
