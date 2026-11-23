---
title: Execution Of Non-Existing File
summary: |-
  Detects process creation events where the Image field lacks an absolute path,
  which occurs when the backing file no longer exists on disk at the time of
  logging - commonly caused by Process Ghosting or other unorthodox process creation techniques.
sigma_id: 71158e3f-df67-472b-930e-7d287acaa3e1
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1055
author: Max Altgelt (Nextron Systems)
date: '2021-12-09'
modified: '2026-07-05'
falsepositives:
  - Unknown
references:
  - https://pentestlaboratories.com/2021/12/08/process-ghosting/
  - https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_image_missing.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Execution Of Non-Existing File
id: 71158e3f-df67-472b-930e-7d287acaa3e1
status: test
description: |
    Detects process creation events where the Image field lacks an absolute path,
    which occurs when the backing file no longer exists on disk at the time of
    logging - commonly caused by Process Ghosting or other unorthodox process creation techniques.
references:
    - https://pentestlaboratories.com/2021/12/08/process-ghosting/
    - https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack
author: Max Altgelt (Nextron Systems)
date: 2021-12-09
modified: 2026-07-05
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    filter_main_image_absolute_path:
        Image|contains: '\'
    filter_optional_null:
        Image: null
    filter_optional_empty:
        Image:
            - '-'
            - ''
    filter_optional_4688:
        - Image:
              - 'MemCompression'
              - 'Registry'
              - 'System'
              - 'vmmem'
              - 'vmmemWSL'
        - CommandLine:
              - 'MemCompression'
              - 'Registry'
              - 'vmmem'
              - 'vmmemWSL'
    condition: not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: high
```
