---
title: New Network Route Added
summary: Detects the addition of a new network route to a route table in AWS.
sigma_id: c803b2ce-c4a2-4836-beae-b112010390b1
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0112
techniques:
  - T1686.001
author: jamesc-grafana
date: '2024-07-11'
falsepositives:
  - New VPC Creation requiring setup of a new route table
  - New subnets added requiring routing setup
references:
  - https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_route_added.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: New Network Route Added
id: c803b2ce-c4a2-4836-beae-b112010390b1
status: test
description: |
    Detects the addition of a new network route to a route table in AWS.
references:
    - https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/
author: jamesc-grafana
date: 2024-07-11
tags:
    - attack.defense-impairment
    - attack.t1686.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'ec2.amazonaws.com'
        eventName: 'CreateRoute'
    condition: selection
falsepositives:
    - New VPC Creation requiring setup of a new route table
    - New subnets added requiring routing setup
level: medium
```
