---
title: AWS EFS Fileshare Modified or Deleted
summary: |-
  Detects when a EFS Fileshare is modified or deleted.
  You can't delete a file system that is in use.
  If the file system has any mount targets, the adversary must first delete them, so deletion of a mount will occur before deletion of a fileshare.
sigma_id: 25cb1ba1-8a19-4a23-a198-d252664c8cef
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0040
techniques: []
author: Austin Songer @austinsonger
date: '2021-08-15'
modified: '2022-10-09'
falsepositives:
  - Unknown
references:
  - https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_efs_fileshare_modified_or_deleted.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS EFS Fileshare Modified or Deleted
id: 25cb1ba1-8a19-4a23-a198-d252664c8cef
status: test
description: |
  Detects when a EFS Fileshare is modified or deleted.
  You can't delete a file system that is in use.
  If the file system has any mount targets, the adversary must first delete them, so deletion of a mount will occur before deletion of a fileshare.
references:
    - https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.html
author: Austin Songer @austinsonger
date: 2021-08-15
modified: 2022-10-09
tags:
    - attack.impact
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: elasticfilesystem.amazonaws.com
        eventName: DeleteFileSystem
    condition: selection
falsepositives:
    - Unknown
level: medium
```
