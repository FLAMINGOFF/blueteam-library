---
title: SES Identity Has Been Deleted
summary: Detects an instance of an SES identity being deleted via the "DeleteIdentity" event. This may be an indicator of an adversary removing the account that carried out suspicious or malicious activities
sigma_id: 20f754db-d025-4a8f-9d74-e0037e999a9a
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0005
techniques:
  - T1070
author: Janantha Marasinghe
date: '2022-12-13'
modified: '2022-12-28'
falsepositives:
  - Unknown
references:
  - https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_delete_identity.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: SES Identity Has Been Deleted
id: 20f754db-d025-4a8f-9d74-e0037e999a9a
status: test
description: Detects an instance of an SES identity being deleted via the "DeleteIdentity" event. This may be an indicator of an adversary removing the account that carried out suspicious or malicious activities
references:
    - https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/
author: Janantha Marasinghe
date: 2022-12-13
modified: 2022-12-28
tags:
    - attack.stealth
    - attack.t1070
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'ses.amazonaws.com'
        eventName: 'DeleteIdentity'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
