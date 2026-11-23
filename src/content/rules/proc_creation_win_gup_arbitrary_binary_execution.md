---
title: Arbitrary Binary Execution Using GUP Utility
summary: Detects execution of the Notepad++ updater (gup) to launch other commands or executables
sigma_id: d65aee4d-2292-4cea-b832-83accd6cfa43
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-10'
modified: '2023-03-02'
falsepositives:
  - Other parent binaries using GUP not currently identified
references:
  - https://twitter.com/nas_bench/status/1535322445439180803
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_gup_arbitrary_binary_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Arbitrary Binary Execution Using GUP Utility
id: d65aee4d-2292-4cea-b832-83accd6cfa43
status: test
description: Detects execution of the Notepad++ updater (gup) to launch other commands or executables
references:
    - https://twitter.com/nas_bench/status/1535322445439180803
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-10
modified: 2023-03-02
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\gup.exe'
        Image|endswith: '\explorer.exe'
    filter:
        Image|endswith: '\explorer.exe'
        CommandLine|contains: '\Notepad++\notepad++.exe'
    filter_parent:
        ParentImage|contains: '\Notepad++\updater\'
    filter_null:
        CommandLine: null
    condition: selection and not 1 of filter*
falsepositives:
    - Other parent binaries using GUP not currently identified
level: medium
```
