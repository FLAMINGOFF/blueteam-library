---
title: S3 Bucket Or Object ACL Grants Public Access
summary: |-
  Detects a successful PutBucketAcl or PutObjectAcl call that grants access to everyone (AllUsers) or to any AWS account (AuthenticatedUsers), either through a canned ACL or an explicit grant.
  Making a bucket or object public is a common way data ends up exposed, by mistake or on purpose.
sigma_id: 798eff28-d4b3-4d4e-8580-40a0ebaa8d53
status: experimental
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0009
techniques:
  - T1530
author: FLAMINGOFF
date: '2026-11-27'
falsepositives:
  - Buckets intentionally used for public static content (prefer bucket policies with Block Public Access exceptions, and list them here)
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-understanding-s3-entries.html
source:
  name: Blue Team Library
  url: https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/rules/btl_aws_s3_acl_grants_public_access.md
  license: Original
format: Sigma
original: true
title_zh: S3 存储桶或对象 ACL 授予公开访问
summary_zh: 检测成功的 PutBucketAcl 或 PutObjectAcl 调用把访问权授予所有人（AllUsers）或任意 AWS 账户（AuthenticatedUsers），无论是用预设 ACL 还是显式授权。把存储桶或对象设为公开，是数据被意外或故意暴露的常见原因。
notes_zh: 开启了 S3 Block Public Access 的账户里，这类调用会失败并带 errorCode，本规则已排除失败的调用。失败的尝试本身也值得留意，可另建一条低级别规则。
notes_en: In accounts with S3 Block Public Access these calls fail with an errorCode, which this rule excludes. The failed attempts are still worth a separate low-severity rule.
samples:
  - name:
      zh: 预设 ACL public-read
      en: Canned ACL public-read
    expect: true
    event:
      eventSource: s3.amazonaws.com
      eventName: PutBucketAcl
      awsRegion: ap-southeast-2
      sourceIPAddress: 203.0.113.25
      userIdentity:
        type: IAMUser
        arn: arn:aws:iam::111122223333:user/deploy
      requestParameters:
        bucketName: corp-exports
        x-amz-acl:
          - public-read
        acl: ''
  - name:
      zh: 显式授权给 AllUsers
      en: Explicit grant to AllUsers
    expect: true
    event:
      eventSource: s3.amazonaws.com
      eventName: PutObjectAcl
      userIdentity:
        type: AssumedRole
        arn: arn:aws:sts::111122223333:assumed-role/dev/alice
      requestParameters:
        bucketName: corp-exports
        key: customers.csv
        AccessControlPolicy:
          AccessControlList:
            Grant:
              - Grantee:
                  ID: 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be
                Permission: FULL_CONTROL
              - Grantee:
                  URI: http://acs.amazonaws.com/groups/global/AllUsers
                Permission: READ
  - name:
      zh: 被 Block Public Access 拦下（失败）
      en: Blocked by Block Public Access (failed)
    expect: false
    event:
      eventSource: s3.amazonaws.com
      eventName: PutBucketAcl
      errorCode: AccessDenied
      requestParameters:
        bucketName: corp-exports
        x-amz-acl:
          - public-read
  - name:
      zh: 设为 private
      en: Set to private
    expect: false
    event:
      eventSource: s3.amazonaws.com
      eventName: PutBucketAcl
      requestParameters:
        bucketName: corp-exports
        x-amz-acl:
          - private
---

```yaml
title: S3 Bucket Or Object ACL Grants Public Access
id: 798eff28-d4b3-4d4e-8580-40a0ebaa8d53
status: experimental
description: |
  Detects a successful PutBucketAcl or PutObjectAcl call that grants access to everyone (AllUsers) or to any AWS account (AuthenticatedUsers), either through a canned ACL or an explicit grant.
  Making a bucket or object public is a common way data ends up exposed, by mistake or on purpose.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-understanding-s3-entries.html
author: FLAMINGOFF
date: 2026-11-27
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_event:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'PutBucketAcl'
      - 'PutObjectAcl'
  selection_public:
    - requestParameters.x-amz-acl:
        - 'public-read'
        - 'public-read-write'
        - 'authenticated-read'
    - requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI|endswith:
        - '/groups/global/AllUsers'
        - '/groups/global/AuthenticatedUsers'
  filter_main_failed:
    errorCode|exists: true
  condition: all of selection_* and not filter_main_failed
falsepositives:
  - Buckets intentionally used for public static content (prefer bucket policies with Block Public Access exceptions, and list them here)
level: high
```
