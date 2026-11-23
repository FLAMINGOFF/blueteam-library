---
title: AWS EnableRegion Command Monitoring
summary: >-
  Detects the use of the EnableRegion command in AWS CloudTrail logs.

  While AWS has 30+ regions, some of them are enabled by default, others must be explicitly enabled in each account separately.

  There may be situations where security monitoring does not cover some new AWS regions.

  Monitoring the EnableRegion command is important for identifying potential persistence mechanisms employed by adversaries, as enabling additional regions can facilitate continued access and
  operations within an AWS environment.
sigma_id: a5ffb6ea-c784-4e01-b30a-deb6e58ca2ab
status: experimental
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0003
techniques: []
author: Ivan Saakov, Sergey Zelenskiy
date: '2025-10-19'
falsepositives:
  - Legitimate use of the EnableRegion command by authorized administrators.
references:
  - https://docs.aws.amazon.com/accounts/latest/reference/API_EnableRegion.html
  - https://awscli.amazonaws.com/v2/documentation/api/2.14.0/reference/account/enable-region.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_region_enabled.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS EnableRegion Command Monitoring
id: a5ffb6ea-c784-4e01-b30a-deb6e58ca2ab
status: experimental
description: |
    Detects the use of the EnableRegion command in AWS CloudTrail logs.
    While AWS has 30+ regions, some of them are enabled by default, others must be explicitly enabled in each account separately.
    There may be situations where security monitoring does not cover some new AWS regions.
    Monitoring the EnableRegion command is important for identifying potential persistence mechanisms employed by adversaries, as enabling additional regions can facilitate continued access and operations within an AWS environment.
references:
    - https://docs.aws.amazon.com/accounts/latest/reference/API_EnableRegion.html
    - https://awscli.amazonaws.com/v2/documentation/api/2.14.0/reference/account/enable-region.html
author: Ivan Saakov, Sergey Zelenskiy
date: 2025-10-19
tags:
    - attack.persistence
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: 'EnableRegion'
        eventSource: 'account.amazonaws.com'
    condition: selection
falsepositives:
    - Legitimate use of the EnableRegion command by authorized administrators.
level: medium
```
