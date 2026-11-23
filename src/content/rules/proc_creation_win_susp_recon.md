---
title: Recon Information for Export with Command Prompt
summary: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
sigma_id: aa2efee7-34dd-446e-8a37-40790a66efd7
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1119
author: frack113
date: '2021-07-30'
modified: '2022-09-13'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_recon.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Recon Information for Export with Command Prompt
id: aa2efee7-34dd-446e-8a37-40790a66efd7
related:
    - id: 8e0bb260-d4b2-4fff-bb8d-3f82118e6892
      type: similar
status: test
description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md
author: frack113
date: 2021-07-30
modified: 2022-09-13
tags:
    - attack.collection
    - attack.t1119
logsource:
    product: windows
    category: process_creation
detection:
    selection_image:
        - Image|endswith:
              - '\tree.com'
              - '\WMIC.exe'
              - '\doskey.exe'
              - '\sc.exe'
        - OriginalFileName:
              - 'wmic.exe'
              - 'DOSKEY.EXE'
              - 'sc.exe'
    selection_redirect:
        ParentCommandLine|contains:
            - ' > %TEMP%\'
            - ' > %TMP%\'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_susp_recon/info.yml
```
