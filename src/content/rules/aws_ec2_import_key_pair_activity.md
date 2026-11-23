---
title: AWS Key Pair Import Activity
summary: >-
  Detects the import of SSH key pairs into AWS EC2, which may indicate an attacker attempting to gain unauthorized access to instances. This activity could lead to initial access, persistence, or
  privilege escalation, potentially compromising sensitive data and operations.
sigma_id: 92f84194-8d9a-4ee0-8699-c30bfac59780
status: experimental
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0001
  - TA0005
  - TA0003
  - TA0004
techniques:
  - T1078
author: Ivan Saakov
date: '2024-12-19'
falsepositives:
  - Legitimate administrative actions by authorized users importing keys for valid purposes.
  - Automated processes for infrastructure setup may trigger this alert.
  - Verify the user identity, user agent, and source IP address to ensure they are expected.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ImportKeyPair.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_ec2_import_key_pair_activity.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS Key Pair Import Activity
id: 92f84194-8d9a-4ee0-8699-c30bfac59780
status: experimental
description: |
    Detects the import of SSH key pairs into AWS EC2, which may indicate an attacker attempting to gain unauthorized access to instances. This activity could lead to initial access, persistence, or privilege escalation, potentially compromising sensitive data and operations.
references:
    - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ImportKeyPair.html
author: Ivan Saakov
date: 2024-12-19
tags:
    - attack.initial-access
    - attack.stealth
    - attack.t1078
    - attack.persistence
    - attack.privilege-escalation
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'ec2.amazonaws.com'
        eventName: 'ImportKeyPair'
    condition: selection
falsepositives:
    - Legitimate administrative actions by authorized users importing keys for valid purposes.
    - Automated processes for infrastructure setup may trigger this alert.
    - Verify the user identity, user agent, and source IP address to ensure they are expected.
level: medium
```
