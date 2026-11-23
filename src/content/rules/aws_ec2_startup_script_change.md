---
title: AWS EC2 Startup Shell Script Change
summary: Detects changes to the EC2 instance startup script. The shell script will be executed as root/SYSTEM every time the specific instances are booted up.
sigma_id: 1ab3c5ed-5baf-417b-bb6b-78ca33f6c3df
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0002
techniques:
  - T1059.001
  - T1059.003
  - T1059.004
author: faloker
date: '2020-02-12'
modified: '2022-06-07'
falsepositives:
  - Valid changes to the startup script
references:
  - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/ec2__startup_shell_script/main.py#L9
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_ec2_startup_script_change.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS EC2 Startup Shell Script Change
id: 1ab3c5ed-5baf-417b-bb6b-78ca33f6c3df
status: test
description: Detects changes to the EC2 instance startup script. The shell script will be executed as root/SYSTEM every time the specific instances are booted up.
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/ec2__startup_shell_script/main.py#L9
author: faloker
date: 2020-02-12
modified: 2022-06-07
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1059.003
    - attack.t1059.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: ec2.amazonaws.com
        requestParameters.attribute: 'userData'
        eventName: ModifyInstanceAttribute
    condition: selection_source
falsepositives:
    - Valid changes to the startup script
level: high
```
