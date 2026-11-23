---
title: AWS IAM S3Browser Templated S3 Bucket Policy Creation
summary: Detects S3 browser utility creating Inline IAM policy containing default S3 bucket name placeholder value of "<YOUR-BUCKET-NAME>".
sigma_id: db014773-7375-4f4e-b83b-133337c0ffee
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0002
  - TA0005
  - TA0003
  - TA0001
  - TA0004
techniques:
  - T1059.009
  - T1078.004
author: daniel.bohannon@permiso.io (@danielhbohannon)
date: '2023-05-17'
falsepositives:
  - Valid usage of S3 browser with accidental creation of default Inline IAM policy without changing default S3 bucket name placeholder value
references:
  - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_iam_s3browser_templated_s3_bucket_policy_creation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS IAM S3Browser Templated S3 Bucket Policy Creation
id: db014773-7375-4f4e-b83b-133337c0ffee
status: test
description: Detects S3 browser utility creating Inline IAM policy containing default S3 bucket name placeholder value of "<YOUR-BUCKET-NAME>".
references:
    - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
author: daniel.bohannon@permiso.io (@danielhbohannon)
date: 2023-05-17
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.009
    - attack.persistence
    - attack.initial-access
    - attack.privilege-escalation
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: iam.amazonaws.com
        eventName: PutUserPolicy
        userAgent|contains: 'S3 Browser'
        requestParameters|contains|all:
            - '"arn:aws:s3:::<YOUR-BUCKET-NAME>/*"'
            - '"s3:GetObject"'
            - '"Allow"'
    condition: selection
falsepositives:
    - Valid usage of S3 browser with accidental creation of default Inline IAM policy without changing default S3 bucket name placeholder value
level: high
```
