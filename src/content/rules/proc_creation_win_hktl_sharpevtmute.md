---
title: HackTool - SharpEvtMute Execution
summary: Detects the use of SharpEvtHook, a tool that tampers with the Windows event logs
sigma_id: bedfc8ad-d1c7-4e37-a20e-e2b0dbee759c
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685.001
author: Florian Roth (Nextron Systems)
date: '2022-09-07'
modified: '2023-02-14'
falsepositives:
  - Unknown
references:
  - https://github.com/bats3c/EvtMute
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_sharpevtmute.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SharpEvtMute Execution
id: bedfc8ad-d1c7-4e37-a20e-e2b0dbee759c
related:
    - id: 49329257-089d-46e6-af37-4afce4290685 # DLL load
      type: similar
status: test
description: Detects the use of SharpEvtHook, a tool that tampers with the Windows event logs
references:
    - https://github.com/bats3c/EvtMute
author: Florian Roth (Nextron Systems)
date: 2022-09-07
modified: 2023-02-14
tags:
    - attack.defense-impairment
    - attack.t1685.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        - Image|endswith: '\SharpEvtMute.exe'
        - Description: 'SharpEvtMute'
        - CommandLine|contains:
              - '--Filter "rule '
              - '--Encoded --Filter \"'
    condition: selection
falsepositives:
    - Unknown
level: high
```
