---
title: AWS RDS Master Password Change
summary: Detects the change of database master password. It may be a part of data exfiltration.
sigma_id: 8a63cdd4-6207-414a-85bc-7e032bd3c1a2
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0010
techniques:
  - T1020
author: faloker
date: '2020-02-12'
modified: '2022-10-05'
falsepositives:
  - Benign changes to a db instance
references:
  - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/rds__explore_snapshots/main.py
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_rds_change_master_password.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS RDS Master Password Change
id: 8a63cdd4-6207-414a-85bc-7e032bd3c1a2
status: test
description: Detects the change of database master password. It may be a part of data exfiltration.
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/rds__explore_snapshots/main.py
author: faloker
date: 2020-02-12
modified: 2022-10-05
tags:
    - attack.exfiltration
    - attack.t1020
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: rds.amazonaws.com
        responseElements.pendingModifiedValues.masterUserPassword|contains: '*'
        eventName: ModifyDBInstance
    condition: selection_source
falsepositives:
    - Benign changes to a db instance
level: medium
```
