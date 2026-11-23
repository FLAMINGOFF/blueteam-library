---
title: PowerShell Download Pattern
summary: Detects a Powershell process that contains download commands in its command line string
sigma_id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
date: '2019-01-16'
modified: '2025-10-20'
falsepositives:
  - Unknown
references:
  - https://blog.redteam.pl/2020/06/black-kingdom-ransomware.html
  - https://lab52.io/blog/winter-vivern-all-summer/
  - https://hatching.io/blog/powershell-analysis/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_download_patterns.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PowerShell Download Pattern
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
related:
    - id: e6c54d94-498c-4562-a37c-b469d8e9a275
      type: derived
    - id: 8f70ac5f-1f6f-4f8e-b454-db19561216c5
      type: obsolete
status: test
description: Detects a Powershell process that contains download commands in its command line string
references:
    - https://blog.redteam.pl/2020/06/black-kingdom-ransomware.html
    - https://lab52.io/blog/winter-vivern-all-summer/
    - https://hatching.io/blog/powershell-analysis/
author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
date: 2019-01-16
modified: 2025-10-20
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\powershell_ise.exe'
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell_ISE.EXE'
              - 'PowerShell.EXE'
              - 'pwsh.dll'
    selection_cli:
        CommandLine|contains|all:
            - 'new-object'
            - 'net.webclient).'
            - 'download'
        CommandLine|contains:
            - 'string('
            - 'file('
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_powershell_download_patterns/info.yml
```
