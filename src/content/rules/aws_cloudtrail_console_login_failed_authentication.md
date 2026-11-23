---
title: AWS ConsoleLogin Failed Authentication
summary: >-
  Detects failed AWS console login attempts due to authentication failures. Monitoring these events is crucial for identifying potential brute-force attacks or unauthorized access attempts to AWS
  accounts.
sigma_id: 6393e346-1977-46ef-8987-ad414a145fad
status: experimental
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0006
techniques:
  - T1110
author: Ivan Saakov, Nasreddine Bencherchali
date: '2025-10-19'
falsepositives:
  - Legitimate failed login attempts by authorized users. Investigate the source of repeated failed login attempts.
references:
  - https://naikordian.github.io/blog/posts/brute-force-aws-console/
  - https://web.archive.org/web/20251215031703/https://help.fortinet.com/fsiem/Public_Resource_Access/7_2_1/rules/PH_RULE_AWS_Management_Console_Brute_Force_of_Root_User_Identity.htm
  - https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/aws_login_failure/aws_cloudtrail_events.json
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_failed_authentication.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS ConsoleLogin Failed Authentication
id: 6393e346-1977-46ef-8987-ad414a145fad
status: experimental
description: |
    Detects failed AWS console login attempts due to authentication failures. Monitoring these events is crucial for identifying potential brute-force attacks or unauthorized access attempts to AWS accounts.
references:
    - https://naikordian.github.io/blog/posts/brute-force-aws-console/
    - https://web.archive.org/web/20251215031703/https://help.fortinet.com/fsiem/Public_Resource_Access/7_2_1/rules/PH_RULE_AWS_Management_Console_Brute_Force_of_Root_User_Identity.htm
    - https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/aws_login_failure/aws_cloudtrail_events.json
author: Ivan Saakov, Nasreddine Bencherchali
date: 2025-10-19
tags:
    - attack.credential-access
    - attack.t1110
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: 'ConsoleLogin'
        errorMessage: 'Failed authentication'
    condition: selection
falsepositives:
    - Legitimate failed login attempts by authorized users. Investigate the source of repeated failed login attempts.
level: medium
```
