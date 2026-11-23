---
title: Remote File Download Via Findstr.EXE
summary: >-
  Detects execution of "findstr" with specific flags and a remote share path. This specific set of CLI flags would allow "findstr" to download the content of the file located on the remote share as
  described in the LOLBAS entry.
sigma_id: 587254ee-a24b-4335-b3cd-065c0f1f4baa
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
  - TA0011
  - TA0005
techniques:
  - T1218
  - T1564.004
  - T1552.001
  - T1105
author: Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)
date: '2020-10-05'
modified: '2024-03-05'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Findstr/
  - https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/
  - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_findstr_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote File Download Via Findstr.EXE
id: 587254ee-a24b-4335-b3cd-065c0f1f4baa
related:
    - id: bf6c39fc-e203-45b9-9538-05397c1b4f3f
      type: obsolete
status: test
description: |
    Detects execution of "findstr" with specific flags and a remote share path. This specific set of CLI flags would allow "findstr" to download the content of the file located on the remote share as described in the LOLBAS entry.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Findstr/
    - https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
author: Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)
date: 2020-10-05
modified: 2024-03-05
tags:
    - attack.credential-access
    - attack.command-and-control
    - attack.stealth
    - attack.t1218
    - attack.t1564.004
    - attack.t1552.001
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_findstr:
        - CommandLine|contains: findstr
        - Image|endswith: 'findstr.exe'
        - OriginalFileName: 'FINDSTR.EXE'
    selection_cli_download_1:
        CommandLine|contains|windash: ' -v '
    selection_cli_download_2:
        CommandLine|contains|windash: ' -l '
    selection_cli_download_3:
        CommandLine|contains: '\\\\'
    condition: selection_findstr and all of selection_cli_download_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_findstr_download/info.yml
```
