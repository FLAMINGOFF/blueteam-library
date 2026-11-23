---
title: Suspicious XOR Encoded PowerShell Command
summary: Detects presence of a potentially xor encoded powershell command
sigma_id: bb780e0c-16cf-4383-8383-1e5471db6cf9
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1059.001
  - T1140
  - T1027
author: Sami Ruohonen, Harish Segar, Tim Shelton, Teymur Kheirkhabarov, Vasiliy Burov, oscd.community, Nasreddine Bencherchali
date: '2018-09-05'
modified: '2023-01-30'
falsepositives:
  - Unknown
references:
  - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=65
  - https://redcanary.com/blog/yellow-cockatoo/
  - https://zero2auto.com/2020/05/19/netwalker-re/
  - https://web.archive.org/web/20230304082026/https://mez0.cc/posts/cobaltstrike-powershell-exec/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_xor_commandline.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious XOR Encoded PowerShell Command
id: bb780e0c-16cf-4383-8383-1e5471db6cf9
related:
    - id: 5b572dcf-254b-425c-a8c5-d9af6bea35a6
      type: obsolete
status: test
description: Detects presence of a potentially xor encoded powershell command
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=65
    - https://redcanary.com/blog/yellow-cockatoo/
    - https://zero2auto.com/2020/05/19/netwalker-re/
    - https://web.archive.org/web/20230304082026/https://mez0.cc/posts/cobaltstrike-powershell-exec/
author: Sami Ruohonen, Harish Segar, Tim Shelton, Teymur Kheirkhabarov, Vasiliy Burov, oscd.community, Nasreddine Bencherchali
date: 2018-09-05
modified: 2023-01-30
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.001
    - attack.t1140
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
        - Description: 'Windows PowerShell'
        - Product: 'PowerShell Core 6'
    selection_cli_xor:
        CommandLine|contains: 'bxor'
    selection_cli_other:
        CommandLine|contains:
            - 'ForEach'
            - 'for('
            - 'for '
            - '-join '
            - "-join'"
            - '-join"'
            - '-join`'
            - '::Join'
            - '[char]'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
