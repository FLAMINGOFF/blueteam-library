---
title: AWS EKS Cluster Created or Deleted
summary: Identifies when an EKS cluster is created or deleted.
sigma_id: 33d50d03-20ec-4b74-a74e-1e65a38af1c0
status: test
level: low
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0040
techniques:
  - T1485
author: Austin Songer
date: '2021-08-16'
modified: '2022-10-09'
falsepositives:
  - EKS Cluster being created or deleted may be performed by a system administrator.
  - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
  - EKS Cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
references:
  - https://any-api.com/amazonaws_com/eks/docs/API_Description
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_eks_cluster_created_or_deleted.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS EKS Cluster Created or Deleted
id: 33d50d03-20ec-4b74-a74e-1e65a38af1c0
status: test
description: Identifies when an EKS cluster is created or deleted.
references:
    - https://any-api.com/amazonaws_com/eks/docs/API_Description
author: Austin Songer
date: 2021-08-16
modified: 2022-10-09
tags:
    - attack.impact
    - attack.t1485
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: eks.amazonaws.com
        eventName:
            - CreateCluster
            - DeleteCluster
    condition: selection
falsepositives:
    - EKS Cluster being created or deleted may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - EKS Cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: low
```
