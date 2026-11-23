---
title: AWS ElastiCache Security Group Created
summary: Detects when an ElastiCache security group has been created.
sigma_id: 4ae68615-866f-4304-b24b-ba048dfa5ca7
status: test
level: low
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0003
techniques:
  - T1136
  - T1136.003
author: Austin Songer @austinsonger
date: '2021-07-24'
modified: '2022-10-09'
falsepositives:
  - >-
    A ElastiCache security group may be created by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    Security group creations from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
references:
  - https://github.com/elastic/detection-rules/blob/598f3d7e0a63221c0703ad9a0ea7e22e7bc5961e/rules/integrations/aws/persistence_elasticache_security_group_creation.toml
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_elasticache_security_group_created.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS ElastiCache Security Group Created
id: 4ae68615-866f-4304-b24b-ba048dfa5ca7
status: test
description: Detects when an ElastiCache security group has been created.
references:
    - https://github.com/elastic/detection-rules/blob/598f3d7e0a63221c0703ad9a0ea7e22e7bc5961e/rules/integrations/aws/persistence_elasticache_security_group_creation.toml
author: Austin Songer @austinsonger
date: 2021-07-24
modified: 2022-10-09
tags:
    - attack.persistence
    - attack.t1136
    - attack.t1136.003
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: elasticache.amazonaws.com
        eventName: 'CreateCacheSecurityGroup'
    condition: selection
falsepositives:
    - A ElastiCache security group may be created by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Security group creations from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.


level: low
```
