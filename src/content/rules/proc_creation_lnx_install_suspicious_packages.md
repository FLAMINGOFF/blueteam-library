---
title: Suspicious Package Installed - Linux
summary: Detects installation of suspicious packages using system installation utilities
sigma_id: 700fb7e8-2981-401c-8430-be58e189e741
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics: []
techniques:
  - T1553.004
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-01-03'
modified: '2026-01-01'
falsepositives:
  - Legitimate administration activities
references:
  - https://gist.githubusercontent.com/MichaelKoczwara/12faba9c061c12b5814b711166de8c2f/raw/e2068486692897b620c25fde1ea258c8218fe3d3/history.txt
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_install_suspicious_packages.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Package Installed - Linux
id: 700fb7e8-2981-401c-8430-be58e189e741
status: test
description: Detects installation of suspicious packages using system installation utilities
references:
    - https://gist.githubusercontent.com/MichaelKoczwara/12faba9c061c12b5814b711166de8c2f/raw/e2068486692897b620c25fde1ea258c8218fe3d3/history.txt
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-03
modified: 2026-01-01
tags:
    - attack.defense-impairment
    - attack.t1553.004
logsource:
    product: linux
    category: process_creation
detection:
    selection_tool_apt:
        Image|endswith:
            - '/apt'
            - '/apt-get'
        CommandLine|contains: 'install'
    selection_tool_yum:
        Image|endswith: '/yum'
        CommandLine|contains:
            - 'localinstall'
            - 'install'
    selection_tool_rpm:
        Image|endswith: '/rpm'
        CommandLine|contains: '-i'
    selection_tool_dpkg:
        Image|endswith: '/dpkg'
        CommandLine|contains:
            - '--install'
            - '-i'
    selection_keyword:
        CommandLine|contains:
            # Add more suspicious packages
            - 'nmap'
            - ' nc'
            - 'netcat'
            - 'wireshark'
            - 'tshark'
            - 'openconnect'
            - 'proxychains'
            - 'socat'
    condition: 1 of selection_tool_* and selection_keyword
falsepositives:
    - Legitimate administration activities
level: medium
```
