---
title: Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE
summary: Detects the usage of "reg.exe" to add Defender folder exclusions. Qbot has been seen using this technique to add exclusions for folders within AppData and ProgramData.
sigma_id: 48917adc-a28e-4f5d-b729-11e75da8941f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685
author: frack113
date: '2022-02-13'
modified: '2023-02-04'
falsepositives:
  - Legitimate use
references:
  - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
  - https://redcanary.com/threat-detection-report/threats/qbot/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_defender_exclusion.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE
id: 48917adc-a28e-4f5d-b729-11e75da8941f
status: test
description: Detects the usage of "reg.exe" to add Defender folder exclusions. Qbot has been seen using this technique to add exclusions for folders within AppData and ProgramData.
references:
    - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
    - https://redcanary.com/threat-detection-report/threats/qbot/
author: frack113
date: 2022-02-13
modified: 2023-02-04
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains:
            - 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
            - 'SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Paths'
        CommandLine|contains|all:
            - 'ADD '
            - '/t '
            - 'REG_DWORD '
            - '/v '
            - '/d '
            - '0'
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
