---
title: Suspicious Download and Execute Pattern via Curl/Wget
summary: |-
  Detects suspicious use of command-line tools such as curl or wget to download remote
  content - particularly scripts - into temporary directories (e.g., /dev/shm, /tmp), followed by
  immediate execution, indicating potential malicious activity. This pattern is commonly used
  by malicious scripts, stagers, or downloaders in fileless or multi-stage Linux attacks.
sigma_id: a2d9e2f3-0f43-4c7a-bcd9-9acfc0d723aa
status: experimental
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059.004
  - T1203
author: Aayush Gupta
date: '2025-06-17'
falsepositives:
  - System update scripts using temporary files
  - Installer scripts or automated provisioning tools
references:
  - https://gtfobins.github.io/gtfobins/wget/
  - https://gtfobins.github.io/gtfobins/curl/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_curl_wget_exec_tmp.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Download and Execute Pattern via Curl/Wget
id: a2d9e2f3-0f43-4c7a-bcd9-9acfc0d723aa
status: experimental
description: |
    Detects suspicious use of command-line tools such as curl or wget to download remote
    content - particularly scripts - into temporary directories (e.g., /dev/shm, /tmp), followed by
    immediate execution, indicating potential malicious activity. This pattern is commonly used
    by malicious scripts, stagers, or downloaders in fileless or multi-stage Linux attacks.
references:
    - https://gtfobins.github.io/gtfobins/wget/
    - https://gtfobins.github.io/gtfobins/curl/
author: Aayush Gupta
date: 2025-06-17
tags:
    - attack.execution
    - attack.t1059.004
    - attack.t1203
logsource:
    category: process_creation
    product: linux
detection:
    selection_downloader:
        CommandLine|contains:
            - '/curl'
            - '/wget'
    selection_tmp:
        CommandLine|contains:
            - '/tmp/'
            - '/dev/shm/'
    selection_executor:
        CommandLine|contains: 'sh -c'
    condition: all of selection_*
falsepositives:
    - System update scripts using temporary files
    - Installer scripts or automated provisioning tools
level: high
```
