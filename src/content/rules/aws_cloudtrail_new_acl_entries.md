---
title: New Network ACL Entry Added
summary: Detects that network ACL entries have been added to a route table which could indicate that new attack vectors have been opened up in the AWS account.
sigma_id: e1f7febb-7b94-4234-b5c6-00fb8500f5dd
status: test
level: low
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0112
techniques:
  - T1686.001
author: jamesc-grafana
date: '2024-07-11'
falsepositives:
  - Legitimate use of ACLs to enable customer and staff access from the public internet into a public VPC
references:
  - https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_acl_entries.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: New Network ACL Entry Added
id: e1f7febb-7b94-4234-b5c6-00fb8500f5dd
status: test
description: |
    Detects that network ACL entries have been added to a route table which could indicate that new attack vectors have been opened up in the AWS account.
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
        eventName: 'CreateNetworkAclEntry'
    condition: selection
falsepositives:
    - Legitimate use of ACLs to enable customer and staff access from the public internet into a public VPC
level: low
```
