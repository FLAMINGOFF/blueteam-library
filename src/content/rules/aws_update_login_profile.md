---
title: AWS User Login Profile Was Modified
summary: |-
  Detects activity when someone is changing passwords on behalf of other users.
  An attacker with the "iam:UpdateLoginProfile" permission on other users can change the password used to login to the AWS console on any user that already has a login profile setup.
sigma_id: 055fb148-60f8-462d-ad16-26926ce050f1
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0003
  - TA0004
techniques:
  - T1098
author: toffeebr33k
date: '2021-08-09'
modified: '2024-04-26'
falsepositives:
  - Legitimate user account administration
references:
  - https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_update_login_profile.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS User Login Profile Was Modified
id: 055fb148-60f8-462d-ad16-26926ce050f1
status: test
description: |
    Detects activity when someone is changing passwords on behalf of other users.
    An attacker with the "iam:UpdateLoginProfile" permission on other users can change the password used to login to the AWS console on any user that already has a login profile setup.
references:
    - https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation
author: toffeebr33k
date: 2021-08-09
modified: 2024-04-26
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1098
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'iam.amazonaws.com'
        eventName: 'UpdateLoginProfile'
    filter_main_user_identity:
        userIdentity.arn|fieldref: requestParameters.userName
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate user account administration
level: high
```
