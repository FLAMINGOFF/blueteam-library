---
title: System Information Discovery
summary: Detects system information discovery commands
sigma_id: 42df45e7-e6e9-43b5-8f26-bec5b39cc239
status: stable
level: informational
platform: linux
logsource: linux / process_creation
tactics:
  - TA0007
techniques:
  - T1082
author: Ömer Günal, oscd.community
date: '2020-10-08'
modified: '2021-09-14'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_system_info_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: System Information Discovery
id: 42df45e7-e6e9-43b5-8f26-bec5b39cc239
status: stable
description: Detects system information discovery commands
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md
author: Ömer Günal, oscd.community
date: 2020-10-08
modified: 2021-09-14
tags:
    - attack.discovery
    - attack.t1082
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/uname'
            - '/hostname'
            - '/uptime'
            - '/lspci'
            - '/dmidecode'
            - '/lscpu'
            - '/lsmod'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: informational
```
