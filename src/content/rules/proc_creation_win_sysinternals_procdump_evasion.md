---
title: Potential SysInternals ProcDump Evasion
summary: Detects uses of the SysInternals ProcDump utility in which ProcDump or its output get renamed, or a dump file is moved or copied to a different name
sigma_id: 79b06761-465f-4f88-9ef2-150e24d3d737
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
  - TA0006
techniques:
  - T1036
  - T1003.001
author: Florian Roth (Nextron Systems)
date: '2022-01-11'
modified: '2023-05-09'
falsepositives:
  - False positives are expected in cases in which ProcDump just gets copied to a different directory without any renaming
references:
  - https://twitter.com/mrd0x/status/1480785527901204481
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_procdump_evasion.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential SysInternals ProcDump Evasion
id: 79b06761-465f-4f88-9ef2-150e24d3d737
status: test
description: Detects uses of the SysInternals ProcDump utility in which ProcDump or its output get renamed, or a dump file is moved or copied to a different name
references:
    - https://twitter.com/mrd0x/status/1480785527901204481
author: Florian Roth (Nextron Systems)
date: 2022-01-11
modified: 2023-05-09
tags:
    - attack.stealth
    - attack.t1036
    - attack.t1003.001
    - attack.credential-access
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains:
            - 'copy procdump'
            - 'move procdump'
    selection_2:
        CommandLine|contains|all:
            - 'copy '
            - '.dmp '
        CommandLine|contains:
            - '2.dmp'
            - 'lsass'
            - 'out.dmp'
    selection_3:
        CommandLine|contains:
            - 'copy lsass.exe_'  # procdump default pattern e.g. lsass.exe_220111_085234.dmp
            - 'move lsass.exe_'  # procdump default pattern e.g. lsass.exe_220111_085234.dmp
    condition: 1 of selection_*
falsepositives:
    - False positives are expected in cases in which ProcDump just gets copied to a different directory without any renaming
level: high
```
