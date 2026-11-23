---
title: AWS IAM Backdoor Users Keys
summary: |-
  Detects AWS API key creation for a user by another user.
  Backdoored users can be used to obtain persistence in the AWS environment.
  Also with this alert, you can detect a flow of AWS keys in your org.
sigma_id: 0a5177f4-6ca9-44c2-aacf-d3f3d8b6e4d2
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0003
  - TA0004
techniques:
  - T1098
author: faloker
date: '2020-02-12'
modified: '2026-08-14'
falsepositives:
  - Adding user keys to their own accounts (the filter cannot cover all possible variants of user naming)
  - AWS API keys legitimate exchange workflows
references:
  - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/iam__backdoor_users_keys/main.py
  - https://github.com/SigmaHQ/sigma/issues/6223
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_iam_backdoor_users_keys.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS IAM Backdoor Users Keys
id: 0a5177f4-6ca9-44c2-aacf-d3f3d8b6e4d2
status: test
description: |
  Detects AWS API key creation for a user by another user.
  Backdoored users can be used to obtain persistence in the AWS environment.
  Also with this alert, you can detect a flow of AWS keys in your org.
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/iam__backdoor_users_keys/main.py
    - https://github.com/SigmaHQ/sigma/issues/6223
author: faloker
date: 2020-02-12
modified: 2026-08-14
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1098
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: iam.amazonaws.com
        eventName: CreateAccessKey
    filter_main_same_user:
        userIdentity.arn|fieldref|contains: responseElements.accessKey.userName
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Adding user keys to their own accounts (the filter cannot cover all possible variants of user naming)
    - AWS API keys legitimate exchange workflows
level: medium
```
