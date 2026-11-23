---
title: RunMRU Registry Key Deletion
summary: |-
  Detects deletion of the RunMRU registry key, which stores the history of commands executed via the Run dialog.
  In the clickfix techniques, the phishing lures instruct users to open a run dialog through (Win + R) and execute malicious commands.
  Adversaries may delete this key to cover their tracks after executing commands.
sigma_id: c11aecef-9c37-45a6-9c07-bc0782f963fd
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1070.003
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-09-25'
falsepositives:
  - Unknown
references:
  - https://www.zscaler.com/blogs/security-research/coldriver-updates-arsenal-baitswitch-and-simplefix
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_delete_runmru.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: RunMRU Registry Key Deletion
id: c11aecef-9c37-45a6-9c07-bc0782f963fd
related:
    - id: 3a9b8c1e-5b2e-4f7a-9d1c-2a7f3b6e1c55
      type: similar
status: experimental
description: |
    Detects deletion of the RunMRU registry key, which stores the history of commands executed via the Run dialog.
    In the clickfix techniques, the phishing lures instruct users to open a run dialog through (Win + R) and execute malicious commands.
    Adversaries may delete this key to cover their tracks after executing commands.
references:
    - https://www.zscaler.com/blogs/security-research/coldriver-updates-arsenal-baitswitch-and-simplefix
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-09-25
tags:
    - attack.stealth
    - attack.t1070.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' del'
            - '\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
