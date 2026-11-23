---
title: AWS EFS Fileshare Mount Modified or Deleted
summary: >-
  Detects when a EFS Fileshare Mount is modified or deleted. An adversary breaking any file system using the mount target that is being deleted, which might disrupt instances or applications using
  those mounts.
sigma_id: 6a7ba45c-63d8-473e-9736-2eaabff79964
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0040
techniques:
  - T1485
author: Austin Songer @austinsonger
date: '2021-08-15'
modified: '2022-10-09'
falsepositives:
  - Unknown
references:
  - https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_efs_fileshare_mount_modified_or_deleted.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS EFS Fileshare Mount Modified or Deleted
id: 6a7ba45c-63d8-473e-9736-2eaabff79964
status: test
description: Detects when a EFS Fileshare Mount is modified or deleted. An adversary breaking any file system using the mount target that is being deleted, which might disrupt instances or applications using those mounts.
references:
    - https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.html
author: Austin Songer @austinsonger
date: 2021-08-15
modified: 2022-10-09
tags:
    - attack.impact
    - attack.t1485
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: elasticfilesystem.amazonaws.com
        eventName: DeleteMountTarget
    condition: selection
falsepositives:
    - Unknown
level: medium
```
