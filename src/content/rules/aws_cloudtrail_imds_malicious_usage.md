---
title: Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure
summary: |-
  Detects when an instance identity has taken an action that isn't inside SSM.
  This can indicate that a compromised EC2 instance is being used as a pivot point.
sigma_id: 352a918a-34d8-4882-8470-44830c507aa3
status: test
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0004
  - TA0001
  - TA0003
techniques:
  - T1078
  - T1078.002
author: jamesc-grafana
date: '2024-07-11'
falsepositives:
  - A team has configured an EC2 instance to use instance profiles that grant the option for the EC2 instance to talk to other AWS Services
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-identity-roles.html
  - https://ermetic.com/blog/aws/aws-ec2-imds-what-you-need-to-know/
  - https://www.packetmischief.ca/2023/07/31/amazon-ec2-credential-exfiltration-how-it-happens-and-how-to-mitigate-it/#lifting-credentials-from-imds-this-is-why-we-cant-have-nice-things
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_imds_malicious_usage.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure
id: 352a918a-34d8-4882-8470-44830c507aa3
status: test
description: |
    Detects when an instance identity has taken an action that isn't inside SSM.
    This can indicate that a compromised EC2 instance is being used as a pivot point.
references:
    - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-identity-roles.html
    - https://ermetic.com/blog/aws/aws-ec2-imds-what-you-need-to-know/
    - https://www.packetmischief.ca/2023/07/31/amazon-ec2-credential-exfiltration-how-it-happens-and-how-to-mitigate-it/#lifting-credentials-from-imds-this-is-why-we-cant-have-nice-things
author: jamesc-grafana
date: 2024-07-11
tags:
    - attack.privilege-escalation
    - attack.initial-access
    - attack.persistence
    - attack.stealth
    - attack.t1078
    - attack.t1078.002
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        userIdentity.arn|re: '.+:assumed-role/aws:.+'
    filter_main_generic:
        - eventSource: 'ssm.amazonaws.com'
        - eventName: 'RegisterManagedInstance'
        - sourceIPAddress: 'AWS Internal'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - A team has configured an EC2 instance to use instance profiles that grant the option for the EC2 instance to talk to other AWS Services
level: high
```
