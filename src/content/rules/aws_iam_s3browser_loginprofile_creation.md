---
title: AWS IAM S3Browser LoginProfile Creation
summary: Detects S3 Browser utility performing reconnaissance looking for existing IAM Users without a LoginProfile defined then (when found) creating a LoginProfile.
sigma_id: db014773-b1d3-46bd-ba26-133337c0ffee
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0002
  - TA0003
  - TA0001
  - TA0004
  - TA0005
techniques:
  - T1059.009
  - T1078.004
author: daniel.bohannon@permiso.io (@danielhbohannon)
date: '2023-05-17'
falsepositives:
  - Valid usage of S3 Browser for IAM LoginProfile listing and/or creation
references:
  - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_iam_s3browser_loginprofile_creation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS IAM S3Browser LoginProfile Creation
id: db014773-b1d3-46bd-ba26-133337c0ffee
status: test
description: Detects S3 Browser utility performing reconnaissance looking for existing IAM Users without a LoginProfile defined then (when found) creating a LoginProfile.
references:
    - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
author: daniel.bohannon@permiso.io (@danielhbohannon)
date: 2023-05-17
tags:
    - attack.execution
    - attack.persistence
    - attack.initial-access
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1059.009
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'iam.amazonaws.com'
        eventName:
            - 'GetLoginProfile'
            - 'CreateLoginProfile'
        userAgent|contains: 'S3 Browser'
    condition: selection
falsepositives:
    - Valid usage of S3 Browser for IAM LoginProfile listing and/or creation
level: high
```
