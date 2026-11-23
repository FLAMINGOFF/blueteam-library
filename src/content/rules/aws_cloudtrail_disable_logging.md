---
title: AWS CloudTrail Important Change
summary: Detects disabling, deleting and updating of a Trail
sigma_id: 4db60cc0-36fb-42b7-9b58-a5b53019fb74
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0112
techniques:
  - T1685.002
author: vitaliy0x1
date: '2020-01-21'
modified: '2022-10-09'
falsepositives:
  - Valid change in a Trail
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_disable_logging.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
title_zh: AWS CloudTrail 审计日志被停用或删除
summary_zh: 检测停用、删除或更新 CloudTrail 跟踪（Trail）的操作。
featured: true
---

```yaml
title: AWS CloudTrail Important Change
id: 4db60cc0-36fb-42b7-9b58-a5b53019fb74
status: test
description: Detects disabling, deleting and updating of a Trail
references:
    - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html
author: vitaliy0x1
date: 2020-01-21
modified: 2022-10-09
tags:
    - attack.defense-impairment
    - attack.t1685.002
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: cloudtrail.amazonaws.com
        eventName:
            - StopLogging
            - UpdateTrail
            - DeleteTrail
    condition: selection_source
falsepositives:
    - Valid change in a Trail
level: medium
```
