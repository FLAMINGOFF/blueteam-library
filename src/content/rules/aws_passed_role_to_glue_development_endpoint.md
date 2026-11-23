---
title: AWS Glue Development Endpoint Activity
summary: Detects possible suspicious glue development endpoint activity.
sigma_id: 4990c2e3-f4b8-45e3-bc3c-30b14ff0ed26
status: test
level: low
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0004
techniques: []
author: Austin Songer @austinsonger
date: '2021-10-03'
modified: '2022-12-18'
falsepositives:
  - Glue Development Endpoint Activity may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
  - If known behavior is causing false positives, it can be exempted from the rule.
references:
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
  - https://docs.aws.amazon.com/glue/latest/webapi/API_CreateDevEndpoint.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_passed_role_to_glue_development_endpoint.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS Glue Development Endpoint Activity
id: 4990c2e3-f4b8-45e3-bc3c-30b14ff0ed26
status: test
description: Detects possible suspicious glue development endpoint activity.
references:
    - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
    - https://docs.aws.amazon.com/glue/latest/webapi/API_CreateDevEndpoint.html
author: Austin Songer @austinsonger
date: 2021-10-03
modified: 2022-12-18
tags:
    - attack.privilege-escalation
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'glue.amazonaws.com'
        eventName:
            - 'CreateDevEndpoint'
            - 'DeleteDevEndpoint'
            - 'UpdateDevEndpoint'
    condition: selection
falsepositives:
    - Glue Development Endpoint Activity may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - If known behavior is causing false positives, it can be exempted from the rule.
level: low
```
