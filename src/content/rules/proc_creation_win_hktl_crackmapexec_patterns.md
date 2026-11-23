---
title: HackTool - CrackMapExec Process Patterns
summary: Detects suspicious process patterns found in logs when CrackMapExec is used
sigma_id: f26307d8-14cd-47e3-a26b-4b4769f24af6
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.001
author: Florian Roth (Nextron Systems)
date: '2022-03-12'
modified: '2023-02-13'
falsepositives:
  - Unknown
references:
  - https://web.archive.org/web/20220625230734/https://mpgn.gitbook.io/crackmapexec/smb-protocol/obtaining-credentials/dump-lsass
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_patterns.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - CrackMapExec Process Patterns
id: f26307d8-14cd-47e3-a26b-4b4769f24af6
status: test
description: Detects suspicious process patterns found in logs when CrackMapExec is used
references:
    - https://web.archive.org/web/20220625230734/https://mpgn.gitbook.io/crackmapexec/smb-protocol/obtaining-credentials/dump-lsass
author: Florian Roth (Nextron Systems)
date: 2022-03-12
modified: 2023-02-13
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_lsass_dump1:
        CommandLine|contains|all:
            - 'tasklist /fi '
            - 'Imagename eq lsass.exe'
        CommandLine|contains:
            - 'cmd.exe /c '
            - 'cmd.exe /r '
            - 'cmd.exe /k '
            - 'cmd /c '
            - 'cmd /r '
            - 'cmd /k '
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    selection_lsass_dump2:
        CommandLine|contains|all:
            - 'do rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump'
            - '\Windows\Temp\'
            - ' full'
            - '%%B'
    selection_procdump:
        CommandLine|contains|all:
            - 'tasklist /v /fo csv'
            - 'findstr /i "lsass"'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
```
