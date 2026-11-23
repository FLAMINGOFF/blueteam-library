---
title: AWS Root Credentials
summary: Detects AWS root account usage
sigma_id: 8ad1600d-e9dc-4251-b0ee-a65268f29add
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0004
  - TA0001
  - TA0003
techniques:
  - T1078.004
author: vitaliy0x1
date: '2020-01-21'
modified: '2022-10-09'
falsepositives:
  - AWS Tasks That Require AWS Account Root User Credentials https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_root_account_usage.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS Root Credentials
id: 8ad1600d-e9dc-4251-b0ee-a65268f29add
status: test
description: Detects AWS root account usage
references:
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
author: vitaliy0x1
date: 2020-01-21
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.initial-access
    - attack.persistence
    - attack.stealth
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_usertype:
        userIdentity.type: Root
    selection_eventtype:
        eventType: AwsServiceEvent
    condition: selection_usertype and not selection_eventtype
falsepositives:
    - AWS Tasks That Require AWS Account Root User Credentials https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html
level: medium
```
