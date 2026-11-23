---
title: Suspicious Usage of For Loop with Recursive Directory Search in CMD
summary: |-
  Detects suspicious usage of the cmd.exe 'for /f' loop combined with the 'tokens=' parameter and a recursive directory listing.
  This pattern may indicate an attempt to discover and execute system binaries dynamically, for example powershell, a technique sometimes used by attackers to evade detection.
  This behavior has been observed in various malicious lnk files.
sigma_id: 2782fbd8-b662-4eb5-9962-5bfbfb671e7b
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.003
  - T1027.010
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: '2025-11-12'
falsepositives:
  - Unknown
references:
  - https://www.virustotal.com/gui/file/29837d0d3202758063185828c8f8d9e0b7b42b365c8941cc926d2d7c7bae2fb3
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_cmd_for_loop_execution_with_recursive_directory_search.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Usage of For Loop with Recursive Directory Search in CMD
id: 2782fbd8-b662-4eb5-9962-5bfbfb671e7b
status: experimental
description: |
    Detects suspicious usage of the cmd.exe 'for /f' loop combined with the 'tokens=' parameter and a recursive directory listing.
    This pattern may indicate an attempt to discover and execute system binaries dynamically, for example powershell, a technique sometimes used by attackers to evade detection.
    This behavior has been observed in various malicious lnk files.
references:
    - https://www.virustotal.com/gui/file/29837d0d3202758063185828c8f8d9e0b7b42b365c8941cc926d2d7c7bae2fb3
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2025-11-12
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.003
    - attack.t1027.010
logsource:
    category: process_creation
    product: windows
detection:
    selection_tokens:
        CommandLine|contains|all:
            - 'for /f'
            - 'tokens='
            - 'in ('
            - 'dir'
    selection_tokens_parent:
        ParentCommandLine|contains|all:
            - 'for /f'
            - 'tokens='
            - 'in ('
            - 'dir'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium
```
