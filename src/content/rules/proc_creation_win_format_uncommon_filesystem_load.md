---
title: Uncommon FileSystem Load Attempt By Format.com
summary: Detects the execution of format.com with an uncommon filesystem selection that could indicate a defense evasion activity in which "format.com" is used to load malicious DLL files or other programs.
sigma_id: 9fb6b26e-7f9e-4517-a48b-8cac4a1b6c60
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques: []
author: Florian Roth (Nextron Systems)
date: '2022-01-04'
modified: '2024-05-13'
falsepositives:
  - Unknown
references:
  - https://twitter.com/0gtweet/status/1477925112561209344
  - https://web.archive.org/web/20220103143620/https://twitter.com/wdormann/status/1478011052130459653
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_format_uncommon_filesystem_load.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon FileSystem Load Attempt By Format.com
id: 9fb6b26e-7f9e-4517-a48b-8cac4a1b6c60
status: test
description: |
    Detects the execution of format.com with an uncommon filesystem selection that could indicate a defense evasion activity in which "format.com" is used to load malicious DLL files or other programs.
references:
    - https://twitter.com/0gtweet/status/1477925112561209344
    - https://web.archive.org/web/20220103143620/https://twitter.com/wdormann/status/1478011052130459653
author: Florian Roth (Nextron Systems)
date: 2022-01-04
modified: 2024-05-13
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\format.com'
        CommandLine|contains: '/fs:'
    filter_main_known_fs:
        CommandLine|contains:
            - '/fs:exFAT'
            - '/fs:FAT'
            - '/fs:NTFS'
            - '/fs:ReFS'
            - '/fs:UDF'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
