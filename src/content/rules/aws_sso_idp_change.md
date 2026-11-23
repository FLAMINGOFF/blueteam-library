---
title: AWS Identity Center Identity Provider Change
summary: |-
  Detects a change in the AWS Identity Center (FKA AWS SSO) identity provider.
  A change in identity provider allows an attacker to establish persistent access or escalate privileges via user impersonation.
sigma_id: d3adb3ef-b7e7-4003-9092-1924c797db35
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0003
  - TA0006
  - TA0112
techniques:
  - T1556
author: Michael McIntyre @wtfender
date: '2023-09-27'
falsepositives:
  - Authorized changes to the AWS account's identity provider
references:
  - https://docs.aws.amazon.com/singlesignon/latest/userguide/app-enablement.html
  - https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html
  - https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamidentitycentersuccessortoawssinglesign-on.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_sso_idp_change.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS Identity Center Identity Provider Change
id: d3adb3ef-b7e7-4003-9092-1924c797db35
status: test
description: |
    Detects a change in the AWS Identity Center (FKA AWS SSO) identity provider.
    A change in identity provider allows an attacker to establish persistent access or escalate privileges via user impersonation.
references:
    - https://docs.aws.amazon.com/singlesignon/latest/userguide/app-enablement.html
    - https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html
    - https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamidentitycentersuccessortoawssinglesign-on.html
author: Michael McIntyre @wtfender
date: 2023-09-27
tags:
    - attack.persistence
    - attack.credential-access
    - attack.defense-impairment
    - attack.t1556
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource:
            - 'sso-directory.amazonaws.com'
            - 'sso.amazonaws.com'
        eventName:
            - 'AssociateDirectory'
            - 'DisableExternalIdPConfigurationForDirectory'
            - 'DisassociateDirectory'
            - 'EnableExternalIdPConfigurationForDirectory'
    condition: selection
falsepositives:
    - Authorized changes to the AWS account's identity provider
level: high
```
