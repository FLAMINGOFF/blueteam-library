---
title: Potential Malicious Usage of CloudTrail System Manager
summary: Detect when System Manager successfully executes commands against an instance.
sigma_id: 38e7f511-3f74-41d4-836e-f57dfa18eead
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0004
  - TA0001
techniques:
  - T1566
  - T1566.002
author: jamesc-grafana
date: '2024-07-11'
modified: '2025-12-08'
falsepositives:
  - There are legitimate uses of SSM to send commands to EC2 instances
  - Legitimate users may have to use SSM to perform actions against machines in the Cloud to update or maintain them
references:
  - https://github.com/elastic/detection-rules/blob/v8.6.0/rules/integrations/aws/initial_access_via_system_manager.toml
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_ssm_malicious_usage.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Malicious Usage of CloudTrail System Manager
id: 38e7f511-3f74-41d4-836e-f57dfa18eead
status: test
description: |
    Detect when System Manager successfully executes commands against an instance.
references:
    - https://github.com/elastic/detection-rules/blob/v8.6.0/rules/integrations/aws/initial_access_via_system_manager.toml
author: jamesc-grafana
date: 2024-07-11
modified: 2025-12-08
tags:
    - attack.privilege-escalation
    - attack.initial-access
    - attack.t1566
    - attack.t1566.002
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_event:
        eventName: 'SendCommand'
        eventSource: 'ssm.amazonaws.com'
    selection_status_success:
        errorCode: 'Success'
    selection_status_null:
        errorCode: null
    condition: selection_event and 1 of selection_status_*
falsepositives:
    - There are legitimate uses of SSM to send commands to EC2 instances
    - Legitimate users may have to use SSM to perform actions against machines in the Cloud to update or maintain them
level: high
```
