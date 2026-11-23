---
title: AWS New Lambda Layer Attached
summary: |-
  Detects when a user attached a Lambda layer to an existing Lambda function.
  A malicious Lambda layer could execute arbitrary code in the context of the function's IAM role.
  This would give an adversary access to resources that the function has access to.
sigma_id: 97fbabf8-8e1b-47a2-b7d5-a418d2b95e3d
status: test
level: low
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0004
techniques: []
author: Austin Songer
date: '2021-09-23'
modified: '2025-03-17'
falsepositives:
  - Lambda Layer being attached may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
  - Lambda Layer being attached from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
references:
  - https://docs.aws.amazon.com/lambda/latest/dg/API_UpdateFunctionConfiguration.html
  - https://github.com/clearvector/lambda-spy
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_new_lambda_layer_attached.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS New Lambda Layer Attached
id: 97fbabf8-8e1b-47a2-b7d5-a418d2b95e3d
status: test
description: |
  Detects when a user attached a Lambda layer to an existing Lambda function.
  A malicious Lambda layer could execute arbitrary code in the context of the function's IAM role.
  This would give an adversary access to resources that the function has access to.
references:
    - https://docs.aws.amazon.com/lambda/latest/dg/API_UpdateFunctionConfiguration.html
    - https://github.com/clearvector/lambda-spy
author: Austin Songer
date: 2021-09-23
modified: 2025-03-17
tags:
    - attack.privilege-escalation
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: lambda.amazonaws.com
        eventName|startswith: 'UpdateFunctionConfiguration'
        requestParameters.layers|contains: '*'
    condition: selection
falsepositives:
    - Lambda Layer being attached may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Lambda Layer being attached from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: low
```
