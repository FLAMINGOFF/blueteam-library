---
title: AWS S3 Bucket Versioning Disable
summary: Detects when S3 bucket versioning is disabled. Threat actors use this technique during AWS ransomware incidents prior to deleting S3 objects.
sigma_id: a136ac98-b2bc-4189-a14d-f0d0388e57a7
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0040
techniques:
  - T1490
author: Sean Johnstone | Unit 42
date: '2023-10-28'
falsepositives:
  - AWS administrator legitimately disabling bucket versioning
references:
  - https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_disable_bucket_versioning.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS S3 Bucket Versioning Disable
id: a136ac98-b2bc-4189-a14d-f0d0388e57a7
status: test
description: Detects when S3 bucket versioning is disabled. Threat actors use this technique during AWS ransomware incidents prior to deleting S3 objects.
references:
    - https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82
author: Sean Johnstone | Unit 42
date: 2023-10-28
tags:
    - attack.impact
    - attack.t1490
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: s3.amazonaws.com
        eventName: PutBucketVersioning
        requestParameters|contains: 'Suspended'
    condition: selection
falsepositives:
    - AWS administrator legitimately disabling bucket versioning
level: medium
```
