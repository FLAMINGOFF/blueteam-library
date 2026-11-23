---
title: AWS EC2 Disable EBS Encryption
summary: |-
  Identifies disabling of default Amazon Elastic Block Store (EBS) encryption in the current region.
  Disabling default encryption does not change the encryption status of your existing volumes.
sigma_id: 16124c2d-e40b-4fcc-8f2c-5ab7870a2223
status: stable
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0040
techniques:
  - T1486
  - T1565
author: Sittikorn S
date: '2021-06-29'
modified: '2021-08-20'
falsepositives:
  - System Administrator Activities
  - DEV, UAT, SAT environment. You should apply this rule with PROD account only.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_ec2_disable_encryption.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS EC2 Disable EBS Encryption
id: 16124c2d-e40b-4fcc-8f2c-5ab7870a2223
status: stable
description: |
  Identifies disabling of default Amazon Elastic Block Store (EBS) encryption in the current region.
  Disabling default encryption does not change the encryption status of your existing volumes.
references:
    - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html
author: Sittikorn S
date: 2021-06-29
modified: 2021-08-20
tags:
    - attack.impact
    - attack.t1486
    - attack.t1565
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: ec2.amazonaws.com
        eventName: DisableEbsEncryptionByDefault
    condition: selection
falsepositives:
    - System Administrator Activities
    - DEV, UAT, SAT environment. You should apply this rule with PROD account only.
level: medium
```
