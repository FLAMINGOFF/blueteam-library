---
title: AWS Bucket Deleted
summary: |-
  Detects the deletion of S3 buckets in AWS CloudTrail logs.
  Monitoring the deletion of S3 buckets is critical for security and data integrity, as it may indicate potential data loss or unauthorized access attempts.
sigma_id: 39c9f26d-6e3b-4dbb-9c7a-4154b0281112
status: experimental
level: medium
platform: aws
logsource: aws / cloudtrail
tactics: []
techniques: []
author: Ivan Saakov, Nasreddine Bencherchali
date: '2025-10-19'
falsepositives:
  - During maintenance operations or testing, authorized administrators may delete S3 buckets as part of routine data management or cleanup activities.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3api/delete-bucket.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_bucket_deleted.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS Bucket Deleted
id: 39c9f26d-6e3b-4dbb-9c7a-4154b0281112
status: experimental
description: |
    Detects the deletion of S3 buckets in AWS CloudTrail logs.
    Monitoring the deletion of S3 buckets is critical for security and data integrity, as it may indicate potential data loss or unauthorized access attempts.
references:
    - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
    - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3api/delete-bucket.html
author: Ivan Saakov, Nasreddine Bencherchali
date: 2025-10-19
tags:
    - attack.stealth
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_event_name:
        eventName: 'DeleteBucket'
    selection_status_success:
        errorCode: 'Success'
    selection_status_null:
        errorCode: null
    condition: selection_event_name and 1 of selection_status_*
falsepositives:
    - During maintenance operations or testing, authorized administrators may delete S3 buckets as part of routine data management or cleanup activities.
level: medium
```
