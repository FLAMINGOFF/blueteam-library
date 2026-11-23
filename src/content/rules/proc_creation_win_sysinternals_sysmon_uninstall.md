---
title: Uninstall Sysinternals Sysmon
summary: Detects the removal of Sysmon, which could be a potential attempt at defense evasion
sigma_id: 6a5f68d1-c4b5-46b9-94ee-5324892ea939
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685
author: frack113
date: '2022-01-12'
modified: '2026-06-29'
falsepositives:
  - Legitimate administrators might use this command to remove Sysmon for debugging purposes
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md#atomic-test-11---uninstall-sysmon
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_sysmon_uninstall.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uninstall Sysinternals Sysmon
id: 6a5f68d1-c4b5-46b9-94ee-5324892ea939
status: test
description: Detects the removal of Sysmon, which could be a potential attempt at defense evasion
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md#atomic-test-11---uninstall-sysmon
author: frack113
date: 2022-01-12
modified: 2026-06-29
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_pe:
        - Image|endswith:
              - \Sysmon64.exe
              - \Sysmon64a.exe
              - \Sysmon.exe
        - Description: 'System activity monitor'
    selection_cli:
        CommandLine|contains|windash: '-u'
    condition: all of selection_*
falsepositives:
    - Legitimate administrators might use this command to remove Sysmon for debugging purposes
level: high
```
