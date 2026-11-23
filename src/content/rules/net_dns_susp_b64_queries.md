---
title: Suspicious DNS Query with B64 Encoded String
summary: Detects suspicious DNS queries using base64 encoding
sigma_id: 4153a907-2451-4e4f-a578-c52bb6881432
status: test
level: medium
platform: other
logsource: dns
tactics:
  - TA0010
  - TA0011
techniques:
  - T1048.003
  - T1071.004
author: Florian Roth (Nextron Systems)
date: '2018-05-10'
modified: '2022-10-09'
falsepositives:
  - Unknown
references:
  - https://github.com/krmaxwell/dns-exfiltration
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/network/dns/net_dns_susp_b64_queries.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious DNS Query with B64 Encoded String
id: 4153a907-2451-4e4f-a578-c52bb6881432
status: test
description: Detects suspicious DNS queries using base64 encoding
references:
    - https://github.com/krmaxwell/dns-exfiltration
author: Florian Roth (Nextron Systems)
date: 2018-05-10
modified: 2022-10-09
tags:
    - attack.exfiltration
    - attack.t1048.003
    - attack.command-and-control
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection:
        query|contains: '==.'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
