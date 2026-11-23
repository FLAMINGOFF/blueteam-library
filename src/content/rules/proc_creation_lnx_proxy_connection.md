---
title: Connection Proxy
summary: Detects setting proxy configuration
sigma_id: 72f4ab3f-787d-495d-a55d-68c2ff46cf4c
status: test
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0011
techniques:
  - T1090
author: Ömer Günal
date: '2020-06-17'
modified: '2022-10-05'
falsepositives:
  - Legitimate administration activities
references: []
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_proxy_connection.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Connection Proxy
id: 72f4ab3f-787d-495d-a55d-68c2ff46cf4c
status: test
description: Detects setting proxy configuration
author: Ömer Günal
date: 2020-06-17
modified: 2022-10-05
tags:
    - attack.command-and-control
    - attack.t1090
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'http_proxy='
            - 'https_proxy='
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
```
