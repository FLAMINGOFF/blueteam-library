---
title: AWS IAM S3Browser User or AccessKey Creation
summary: Detects S3 Browser utility creating IAM User or AccessKey.
sigma_id: db014773-d9d9-4792-91e5-133337c0ffee
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0004
  - TA0002
  - TA0003
  - TA0001
techniques:
  - T1059.009
  - T1078.004
author: daniel.bohannon@permiso.io (@danielhbohannon)
date: '2023-05-17'
falsepositives:
  - Valid usage of S3 Browser for IAM User and/or AccessKey creation
references:
  - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_iam_s3browser_user_or_accesskey_creation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS IAM S3Browser User or AccessKey Creation
id: db014773-d9d9-4792-91e5-133337c0ffee
status: test
description: Detects S3 Browser utility creating IAM User or AccessKey.
references:
    - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
author: daniel.bohannon@permiso.io (@danielhbohannon)
date: 2023-05-17
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.initial-access
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
            - 'CreateUser'
            - 'CreateAccessKey'
        userAgent|contains: 'S3 Browser'
    condition: selection
falsepositives:
    - Valid usage of S3 Browser for IAM User and/or AccessKey creation
level: high
```
