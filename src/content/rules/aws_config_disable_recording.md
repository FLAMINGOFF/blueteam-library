---
title: AWS Config Disabling Channel/Recorder
summary: Detects AWS Config Service disabling
sigma_id: 07330162-dba1-4746-8121-a9647d49d297
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics: []
techniques:
  - T1685.002
author: vitaliy0x1
date: '2020-01-21'
modified: '2022-10-09'
falsepositives:
  - Valid change in AWS Config Service
references:
  - https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-log-files-for-aws-config.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_config_disable_recording.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS Config Disabling Channel/Recorder
id: 07330162-dba1-4746-8121-a9647d49d297
status: test
description: Detects AWS Config Service disabling
references:
    - https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-log-files-for-aws-config.html
author: vitaliy0x1
date: 2020-01-21
modified: 2022-10-09
tags:
    - attack.defense-impairment
    - attack.t1685.002
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'config.amazonaws.com'
        eventName:
            - 'DeleteDeliveryChannel'
            - 'StopConfigurationRecorder'
    condition: selection
falsepositives:
    - Valid change in AWS Config Service
level: high
```
