---
title: AWS STS GetCallerIdentity Enumeration Via TruffleHog
summary: |-
  Detects the use of TruffleHog for AWS credential validation by identifying GetCallerIdentity API calls where the userAgent indicates TruffleHog.
  Threat actors leverage TruffleHog to enumerate and validate exposed AWS keys.
  Successful exploitation allows threat actors to confirm the validity of compromised AWS credentials, facilitating further unauthorized access and actions within the AWS environment.
sigma_id: 9b1b8e9b-0a5d-4af1-9d2f-4c4b6e7c2c9d
status: experimental
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0007
techniques:
  - T1087.004
author: Adan Alvarez @adanalvarez
date: '2025-10-12'
falsepositives:
  - Legitimate internal security scanning or key validation that intentionally uses TruffleHog. Authorize and filter known scanner roles, IP ranges, or assumed roles as needed.
references:
  - https://www.rapid7.com/blog/post/tr-crimson-collective-a-new-threat-group-observed-operating-in-the-cloud/
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
  - https://github.com/trufflesecurity/trufflehog
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_sts_getcalleridentity_trufflehog.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS STS GetCallerIdentity Enumeration Via TruffleHog
id: 9b1b8e9b-0a5d-4af1-9d2f-4c4b6e7c2c9d
status: experimental
description: |
    Detects the use of TruffleHog for AWS credential validation by identifying GetCallerIdentity API calls where the userAgent indicates TruffleHog.
    Threat actors leverage TruffleHog to enumerate and validate exposed AWS keys.
    Successful exploitation allows threat actors to confirm the validity of compromised AWS credentials, facilitating further unauthorized access and actions within the AWS environment.
references:
    - https://www.rapid7.com/blog/post/tr-crimson-collective-a-new-threat-group-observed-operating-in-the-cloud/
    - https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
    - https://github.com/trufflesecurity/trufflehog
author: Adan Alvarez @adanalvarez
date: 2025-10-12
tags:
    - attack.discovery
    - attack.t1087.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'sts.amazonaws.com'
        eventName: 'GetCallerIdentity'
        userAgent|contains: 'TruffleHog'
    condition: selection
falsepositives:
    - Legitimate internal security scanning or key validation that intentionally uses TruffleHog. Authorize and filter known scanner roles, IP ranges, or assumed roles as needed.
level: medium
```
