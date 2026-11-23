---
title: Modification or Deletion of an AWS RDS Cluster
summary: Detects modifications to an RDS cluster or its deletion, which may indicate potential data exfiltration attempts, unauthorized access, or exposure of sensitive information.
sigma_id: 457cc9ac-d8e6-4d1d-8c0e-251d0f11a74c
status: experimental
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0010
techniques:
  - T1020
author: Ivan Saakov
date: '2024-12-06'
falsepositives:
  - Verify if the modification or deletion was performed by an authorized administrator.
  - Confirm if the modification or deletion was part of a planned change or maintenance activity.
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBCluster.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBCluster.html
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-rds-privesc#rds-modifydbinstance
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_rds_dbcluster_actions.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Modification or Deletion of an AWS RDS Cluster
id: 457cc9ac-d8e6-4d1d-8c0e-251d0f11a74c
status: experimental
description: Detects modifications to an RDS cluster or its deletion, which may indicate potential data exfiltration attempts, unauthorized access, or exposure of sensitive information.
references:
    - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBCluster.html
    - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBCluster.html
    - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-rds-privesc#rds-modifydbinstance
author: Ivan Saakov
date: 2024-12-06
tags:
    - attack.exfiltration
    - attack.t1020
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: rds.amazonaws.com
        eventName:
            - ModifyDBCluster
            - DeleteDBCluster
    condition: selection
falsepositives:
    - Verify if the modification or deletion was performed by an authorized administrator.
    - Confirm if the modification or deletion was part of a planned change or maintenance activity.
level: high
```
