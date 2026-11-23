---
title: HackTool - Koadic Execution
summary: Detects command line parameters used by Koadic hack tool
sigma_id: 5cddf373-ef00-4112-ad72-960ac29bac34
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.003
  - T1059.005
  - T1059.007
author: wagga, Jonhnathan Ribeiro, oscd.community
date: '2020-01-12'
modified: '2023-02-11'
falsepositives:
  - Unknown
references:
  - https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/
  - https://github.com/offsecginger/koadic/blob/457f9a3ff394c989cdb4c599ab90eb34fb2c762c/data/stager/js/stdlib.js
  - https://blog.f-secure.com/hunting-for-koadic-a-com-based-rootkit/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_koadic.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Koadic Execution
id: 5cddf373-ef00-4112-ad72-960ac29bac34
status: test
description: Detects command line parameters used by Koadic hack tool
references:
    - https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/
    - https://github.com/offsecginger/koadic/blob/457f9a3ff394c989cdb4c599ab90eb34fb2c762c/data/stager/js/stdlib.js
    - https://blog.f-secure.com/hunting-for-koadic-a-com-based-rootkit/
author: wagga, Jonhnathan Ribeiro, oscd.community
date: 2020-01-12
modified: 2023-02-11
tags:
    - attack.execution
    - attack.t1059.003
    - attack.t1059.005
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_cli:
        CommandLine|contains|all:
            - '/q'
            - '/c'
            - 'chcp'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
