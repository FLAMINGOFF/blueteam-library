---
title: C# IL Code Compilation Via Ilasm.EXE
summary: Detects the use of "Ilasm.EXE" in order to compile C# intermediate (IL) code to EXE or DLL.
sigma_id: 850d55f9-6eeb-4492-ad69-a72338f65ba4
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1127
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: '2022-05-07'
modified: '2022-05-16'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Ilasm/
  - https://www.echotrail.io/insights/search/ilasm.exe
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ilasm_il_code_compilation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: C# IL Code Compilation Via Ilasm.EXE
id: 850d55f9-6eeb-4492-ad69-a72338f65ba4
status: test
description: Detects the use of "Ilasm.EXE" in order to compile C# intermediate (IL) code to EXE or DLL.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Ilasm/
    - https://www.echotrail.io/insights/search/ilasm.exe
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2022-05-07
modified: 2022-05-16
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\ilasm.exe'
        - OriginalFileName: 'ilasm.exe'
    selection_cli:
        CommandLine|contains:
            - ' /dll'
            - ' /exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
