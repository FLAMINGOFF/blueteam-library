---
title: AWS S3 Data Management Tampering
summary: Detects when a user tampers with S3 data management in Amazon Web Services.
sigma_id: 78b3756a-7804-4ef7-8555-7b9024a02e2d
status: test
level: low
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0010
techniques:
  - T1537
author: Austin Songer @austinsonger
date: '2021-07-24'
modified: '2022-10-09'
falsepositives:
  - >-
    A S3 configuration change may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. S3
    configuration change from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
references:
  - https://github.com/elastic/detection-rules/pull/1145/files
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/setting-repl-config-perm-overview.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_s3_data_management_tampering.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS S3 Data Management Tampering
id: 78b3756a-7804-4ef7-8555-7b9024a02e2d
status: test
description: Detects when a user tampers with S3 data management in Amazon Web Services.
references:
    - https://github.com/elastic/detection-rules/pull/1145/files
    - https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html
    - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html
    - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html
    - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html
    - https://docs.aws.amazon.com/AmazonS3/latest/userguide/setting-repl-config-perm-overview.html
    - https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html
author: Austin Songer @austinsonger
date: 2021-07-24
modified: 2022-10-09
tags:
    - attack.exfiltration
    - attack.t1537
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: s3.amazonaws.com
        eventName:
            - PutBucketLogging
            - PutBucketWebsite
            - PutEncryptionConfiguration
            - PutLifecycleConfiguration
            - PutReplicationConfiguration
            - ReplicateObject
            - RestoreObject
    condition: selection
falsepositives:
    - A S3 configuration change may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. S3 configuration change from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: low
```
