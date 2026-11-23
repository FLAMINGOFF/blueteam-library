---
title: AWS GuardDuty Important Change
summary: Detects updates of the GuardDuty list of trusted IPs, perhaps to disable security alerts against malicious IPs.
sigma_id: 6e61ee20-ce00-4f8d-8aee-bedd8216f7e3
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics: []
techniques:
  - T1685
author: faloker
date: '2020-02-11'
modified: '2022-10-09'
falsepositives:
  - Valid change in the GuardDuty (e.g. to ignore internal scanners)
references:
  - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/guardduty__whitelist_ip/main.py#L9
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_guardduty_disruption.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS GuardDuty Important Change
id: 6e61ee20-ce00-4f8d-8aee-bedd8216f7e3
status: test
description: Detects updates of the GuardDuty list of trusted IPs, perhaps to disable security alerts against malicious IPs.
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/guardduty__whitelist_ip/main.py#L9
author: faloker
date: 2020-02-11
modified: 2022-10-09
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: guardduty.amazonaws.com
        eventName: CreateIPSet
    condition: selection_source
falsepositives:
    - Valid change in the GuardDuty (e.g. to ignore internal scanners)
level: high
```
