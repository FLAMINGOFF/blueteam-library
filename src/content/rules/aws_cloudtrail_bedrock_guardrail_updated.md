---
title: AWS Bedrock Guardrail Updated
summary: |-
  Detects updates to an Amazon Bedrock guardrail, which may indicate attempts to weaken
  model safety controls and allow unsafe or unauthorized model responses.
sigma_id: 1c722651-254a-4b04-a9f4-99b62a2d0a1f
status: experimental
level: medium
platform: aws
logsource: aws / cloudtrail
tactics: []
techniques:
  - T1685
author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
date: '2026-07-10'
falsepositives:
  - Legitimate guardrail updates by authorized identities.
references:
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_UpdateGuardrail.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_bedrock_guardrail_updated.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS Bedrock Guardrail Updated
id: 1c722651-254a-4b04-a9f4-99b62a2d0a1f
status: experimental
description: |
    Detects updates to an Amazon Bedrock guardrail, which may indicate attempts to weaken
    model safety controls and allow unsafe or unauthorized model responses.
references:
    - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_UpdateGuardrail.html
author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
date: 2026-07-10
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: 'UpdateGuardrail'
        eventSource: 'bedrock.amazonaws.com'
    condition: selection
falsepositives:
    - Legitimate guardrail updates by authorized identities.
level: medium
```
