---
title: AWS SecurityHub Findings Evasion
summary: Detects the modification of the findings on SecurityHub.
sigma_id: a607e1fe-74bf-4440-a3ec-b059b9103157
status: stable
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0112
techniques:
  - T1685
author: Sittikorn S
date: '2021-06-28'
falsepositives:
  - System or Network administrator behaviors
  - DEV, UAT, SAT environment. You should apply this rule with PROD environment only.
references:
  - https://docs.aws.amazon.com/cli/latest/reference/securityhub/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_securityhub_finding_evasion.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS SecurityHub Findings Evasion
id: a607e1fe-74bf-4440-a3ec-b059b9103157
status: stable
description: Detects the modification of the findings on SecurityHub.
references:
    - https://docs.aws.amazon.com/cli/latest/reference/securityhub/
author: Sittikorn S
date: 2021-06-28
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: securityhub.amazonaws.com
        eventName:
            - 'BatchUpdateFindings'
            - 'DeleteInsight'
            - 'UpdateFindings'
            - 'UpdateInsight'
    condition: selection
falsepositives:
    - System or Network administrator behaviors
    - DEV, UAT, SAT environment. You should apply this rule with PROD environment only.
level: high
```
