---
title: AWS Bedrock Guardrail Deleted
summary: |-
  Detects deletion of an Amazon Bedrock guardrail, which may indicate attempts to remove
  model safety controls and allow unsafe or unauthorized model responses.
sigma_id: 59b70e4d-dd17-44a9-b740-acf07ae3eb6a
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
  - Legitimate guardrail deletion by authorized identities.
references:
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_DeleteGuardrail.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_bedrock_guardrail_deleted.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS Bedrock Guardrail Deleted
id: 59b70e4d-dd17-44a9-b740-acf07ae3eb6a
status: experimental
description: |
    Detects deletion of an Amazon Bedrock guardrail, which may indicate attempts to remove
    model safety controls and allow unsafe or unauthorized model responses.
references:
    - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_DeleteGuardrail.html
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
        eventName: 'DeleteGuardrail'
        eventSource: 'bedrock.amazonaws.com'
    condition: selection
falsepositives:
    - Legitimate guardrail deletion by authorized identities.
level: medium
```
