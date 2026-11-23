---
title: Uncommon Child Processes Of SndVol.exe
summary: Detects potentially uncommon child processes of SndVol.exe (the Windows volume mixer)
sigma_id: ba42babc-0666-4393-a4f7-ceaf5a69191e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: X__Junior (Nextron Systems)
date: '2023-06-09'
falsepositives:
  - Unknown
references:
  - https://twitter.com/Max_Mal_/status/1661322732456353792
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sndvol_susp_child_processes.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon Child Processes Of SndVol.exe
id: ba42babc-0666-4393-a4f7-ceaf5a69191e
status: test
description: Detects potentially uncommon child processes of SndVol.exe (the Windows volume mixer)
references:
    - https://twitter.com/Max_Mal_/status/1661322732456353792
author: X__Junior (Nextron Systems)
date: 2023-06-09
tags:
    - attack.execution
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\SndVol.exe'
    filter_main_rundll32:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: ' shell32.dll,Control_RunDLL '
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
