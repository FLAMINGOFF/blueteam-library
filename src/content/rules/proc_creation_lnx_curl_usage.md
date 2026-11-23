---
title: Curl Usage on Linux
summary: Detects a curl process start on linux, which indicates a file download from a remote location or a simple web request to a remote server
sigma_id: ea34fb97-e2c4-4afb-810f-785e4459b194
status: test
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0011
techniques:
  - T1105
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-15'
falsepositives:
  - Scripts created by developers and admins
  - Administrative activity
references:
  - https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_curl_usage.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Curl Usage on Linux
id: ea34fb97-e2c4-4afb-810f-785e4459b194
status: test
description: Detects a curl process start on linux, which indicates a file download from a remote location or a simple web request to a remote server
references:
    - https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/curl'
    condition: selection
falsepositives:
    - Scripts created by developers and admins
    - Administrative activity
level: low
```
