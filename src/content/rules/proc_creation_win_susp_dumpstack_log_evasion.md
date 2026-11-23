---
title: DumpStack.log Defender Evasion
summary: Detects the use of the filename DumpStack.log to evade Microsoft Defender
sigma_id: 4f647cfa-b598-4e12-ad69-c68dd16caef8
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics: []
techniques: []
author: Florian Roth (Nextron Systems)
date: '2022-01-06'
modified: '2022-06-17'
falsepositives:
  - Unknown
references:
  - https://twitter.com/mrd0x/status/1479094189048713219
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_dumpstack_log_evasion.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: DumpStack.log Defender Evasion
id: 4f647cfa-b598-4e12-ad69-c68dd16caef8
status: test
description: Detects the use of the filename DumpStack.log to evade Microsoft Defender
references:
    - https://twitter.com/mrd0x/status/1479094189048713219
author: Florian Roth (Nextron Systems)
date: 2022-01-06
modified: 2022-06-17
tags:
    - attack.defense-impairment
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\DumpStack.log'
    selection_download:
        CommandLine|contains: ' -o DumpStack.log'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: critical
```
