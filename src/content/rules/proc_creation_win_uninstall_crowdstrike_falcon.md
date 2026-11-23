---
title: Uninstall Crowdstrike Falcon Sensor
summary: Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon
sigma_id: f0f7be61-9cf5-43be-9836-99d6ef448a18
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: frack113
date: '2021-07-12'
modified: '2023-03-09'
falsepositives:
  - Administrator might leverage the same command line for debugging or other purposes. However this action must be always investigated
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_uninstall_crowdstrike_falcon.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uninstall Crowdstrike Falcon Sensor
id: f0f7be61-9cf5-43be-9836-99d6ef448a18
status: test
description: Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
author: frack113
date: 2021-07-12
modified: 2023-03-09
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\WindowsSensor.exe'
            - ' /uninstall'
            - ' /quiet'
    condition: selection
falsepositives:
    - Administrator might leverage the same command line for debugging or other purposes. However this action must be always investigated
level: high
```
