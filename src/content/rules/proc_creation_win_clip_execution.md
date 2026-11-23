---
title: Data Copied To Clipboard Via Clip.EXE
summary: Detects the execution of clip.exe in order to copy data to the clipboard. Adversaries may collect data stored in the clipboard from users copying information within or between applications.
sigma_id: ddeff553-5233-4ae9-bbab-d64d2bd634be
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1115
author: frack113
date: '2021-07-27'
modified: '2023-02-21'
falsepositives:
  - Unknown
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/clip
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1115/T1115.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_clip_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Data Copied To Clipboard Via Clip.EXE
id: ddeff553-5233-4ae9-bbab-d64d2bd634be
status: test
description: Detects the execution of clip.exe in order to copy data to the clipboard. Adversaries may collect data stored in the clipboard from users copying information within or between applications.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/clip
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1115/T1115.md
author: frack113
date: 2021-07-27
modified: 2023-02-21
tags:
    - attack.collection
    - attack.t1115
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\clip.exe'
        - OriginalFileName: clip.exe
    condition: selection
falsepositives:
    - Unknown
level: low
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_clip_execution/info.yml
simulation:
    - type: atomic-red-team
      name: Utilize Clipboard to store or execute commands from
      technique: T1115
      atomic_guid: 0cd14633-58d4-4422-9ede-daa2c9474ae7
```
