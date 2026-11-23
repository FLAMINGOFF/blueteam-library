---
title: LoadBalancer Security Group Modification
summary: >-
  Detects changes to the security groups associated with an Elastic Load Balancer (ELB) or Application Load Balancer (ALB).

  This can indicate that a misconfiguration allowing more traffic into the system than required, or could indicate that an attacker is attempting to enable new connections into a VPC or subnet
  controlled by the account.
sigma_id: 7a4409fc-f8ca-45f6-8006-127d779eaad9
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0001
techniques:
  - T1190
author: jamesc-grafana
date: '2024-07-11'
falsepositives:
  - Repurposing of an ELB or ALB to serve a different or additional application
  - Changes to security groups to allow for new services to be deployed
references:
  - https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_security_group_change_loadbalancer.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: LoadBalancer Security Group Modification
id: 7a4409fc-f8ca-45f6-8006-127d779eaad9
status: test
description: |
    Detects changes to the security groups associated with an Elastic Load Balancer (ELB) or Application Load Balancer (ALB).
    This can indicate that a misconfiguration allowing more traffic into the system than required, or could indicate that an attacker is attempting to enable new connections into a VPC or subnet controlled by the account.
references:
    - https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/
author: jamesc-grafana
date: 2024-07-11
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'elasticloadbalancing.amazonaws.com'
        eventName:
            - 'ApplySecurityGroupsToLoadBalancer'
            - 'SetSecurityGroups'
    condition: selection
falsepositives:
    - Repurposing of an ELB or ALB to serve a different or additional application
    - Changes to security groups to allow for new services to be deployed
level: medium
```
