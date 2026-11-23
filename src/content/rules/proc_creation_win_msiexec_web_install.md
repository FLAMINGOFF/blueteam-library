---
title: MsiExec Web Install
summary: Detects suspicious msiexec process starts with web addresses as parameter
sigma_id: f7b5f842-a6af-4da5-9e95-e32478f3cd2f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
  - TA0011
techniques:
  - T1218.007
  - T1105
author: Florian Roth (Nextron Systems)
date: '2018-02-09'
modified: '2022-01-07'
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
references:
  - https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_msiexec_web_install.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: MsiExec Web Install
id: f7b5f842-a6af-4da5-9e95-e32478f3cd2f
related:
    - id: 8150732a-0c9d-4a99-82b9-9efb9b90c40c
      type: similar
status: test
description: Detects suspicious msiexec process starts with web addresses as parameter
references:
    - https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/
author: Florian Roth (Nextron Systems)
date: 2018-02-09
modified: 2022-01-07
tags:
    - attack.stealth
    - attack.t1218.007
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' msiexec'
            - '://'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_msiexec_web_install/info.yml
```
