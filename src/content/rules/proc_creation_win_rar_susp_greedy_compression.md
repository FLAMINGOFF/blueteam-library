---
title: Suspicious Greedy Compression Using Rar.EXE
summary: Detects RAR usage that creates an archive from a suspicious folder, either a system folder or one of the folders often used by attackers for staging purposes
sigma_id: afe52666-401e-4a02-b4ff-5d128990b8cb
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: X__Junior (Nextron Systems), Florian Roth (Nextron Systems)
date: '2022-12-15'
modified: '2024-01-02'
falsepositives:
  - Unknown
references:
  - https://decoded.avast.io/martinchlumecky/png-steganography
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rar_susp_greedy_compression.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Greedy Compression Using Rar.EXE
id: afe52666-401e-4a02-b4ff-5d128990b8cb
status: test
description: Detects RAR usage that creates an archive from a suspicious folder, either a system folder or one of the folders often used by attackers for staging purposes
references:
    - https://decoded.avast.io/martinchlumecky/png-steganography
author: X__Junior (Nextron Systems), Florian Roth (Nextron Systems)
date: 2022-12-15
modified: 2024-01-02
tags:
    - attack.execution
    - attack.t1059
logsource:
    product: windows
    category: process_creation
detection:
    # Example : rar.exe a -m5 -r -y -ta20210204000000 -hp1qazxcde32ws -v2560k Asia1Dpt-PC-c.rar c:\\*.doc c:\\*.docx c:\\*.xls c:\\*.xlsx c:\\*.pdf c:\\*.ppt c:\\*.pptx c:\\*.jpg c:\\*.txt >nul
    selection_opt_1:
        - Image|endswith: '\rar.exe'
        - Description: 'Command line RAR'
    selection_opt_2:
        CommandLine|contains:
            - '.exe a '
            - ' a -m'
    selection_cli_flags:
        CommandLine|contains|all:
            - ' -hp' # password
            - ' -r ' # recursive
    selection_cli_folders:
        CommandLine|contains:
            - ' ?:\\\*.'
            - ' ?:\\\\\*.'
            - ' ?:\$Recycle.bin\'
            - ' ?:\PerfLogs\'
            - ' ?:\Temp'
            - ' ?:\Users\Public\'
            - ' ?:\Windows\'
            - ' %public%'
    condition: 1 of selection_opt_* and all of selection_cli_*
falsepositives:
    - Unknown
level: high
```
