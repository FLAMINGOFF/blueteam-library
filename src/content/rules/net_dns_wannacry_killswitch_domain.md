---
title: Wannacry Killswitch Domain
summary: Detects wannacry killswitch domain dns queries
sigma_id: 3eaf6218-3bed-4d8a-8707-274096f12a18
status: test
level: high
platform: other
logsource: dns
tactics:
  - TA0011
techniques:
  - T1071.001
author: Mike Wade
date: '2020-09-16'
modified: '2022-03-24'
falsepositives:
  - Analyst testing
references:
  - https://www.mandiant.com/resources/blog/wannacry-ransomware-campaign
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/network/dns/net_dns_wannacry_killswitch_domain.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Wannacry Killswitch Domain
id: 3eaf6218-3bed-4d8a-8707-274096f12a18
status: test
description: Detects wannacry killswitch domain dns queries
references:
    - https://www.mandiant.com/resources/blog/wannacry-ransomware-campaign
author: Mike Wade
date: 2020-09-16
modified: 2022-03-24
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: dns
detection:
    selection:
        query:
            - 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.testing'
            - 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.test'
            - 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com'
            - 'ayylmaotjhsstasdfasdfasdfasdfasdfasdfasdf.com'
            - 'iuqssfsodp9ifjaposdfjhgosurijfaewrwergwea.com'
    condition: selection
falsepositives:
    - Analyst testing
level: high
```
