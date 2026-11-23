---
title: Restore Public AWS RDS Instance
summary: Detects the recovery of a new public database instance from a snapshot. It may be a part of data exfiltration.
sigma_id: c3f265c7-ff03-4056-8ab2-d486227b4599
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0010
techniques:
  - T1020
author: faloker
date: '2020-02-12'
modified: '2022-10-09'
falsepositives:
  - Unknown
references:
  - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/rds__explore_snapshots/main.py
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_rds_public_db_restore.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Restore Public AWS RDS Instance
id: c3f265c7-ff03-4056-8ab2-d486227b4599
status: test
description: Detects the recovery of a new public database instance from a snapshot. It may be a part of data exfiltration.
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/rds__explore_snapshots/main.py
author: faloker
date: 2020-02-12
modified: 2022-10-09
tags:
    - attack.exfiltration
    - attack.t1020
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: rds.amazonaws.com
        responseElements.publiclyAccessible: 'true'
        eventName: RestoreDBInstanceFromDBSnapshot
    condition: selection_source
falsepositives:
    - Unknown
level: high
```
