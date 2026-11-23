---
title: Potential Command Line Path Traversal Evasion Attempt
summary: Detects potential evasion or obfuscation attempts using bogus path traversal via the commandline
sigma_id: 1327381e-6ab0-4f38-b583-4c1b8346a56b
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1036
author: Christian Burkard (Nextron Systems)
date: '2021-10-26'
modified: '2023-03-29'
falsepositives:
  - Google Drive
  - Citrix
references:
  - https://web.archive.org/web/20211012220242/https://twitter.com/Hexacorn/status/1448037865435320323
  - https://twitter.com/Gal_B1t/status/1062971006078345217
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_commandline_path_traversal_evasion.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Command Line Path Traversal Evasion Attempt
id: 1327381e-6ab0-4f38-b583-4c1b8346a56b
status: test
description: Detects potential evasion or obfuscation attempts using bogus path traversal via the commandline
references:
    - https://web.archive.org/web/20211012220242/https://twitter.com/Hexacorn/status/1448037865435320323
    - https://twitter.com/Gal_B1t/status/1062971006078345217
author: Christian Burkard (Nextron Systems)
date: 2021-10-26
modified: 2023-03-29
tags:
    - attack.stealth
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|contains: '\Windows\'
        CommandLine|contains:
            - '\..\Windows\'
            - '\..\System32\'
            - '\..\..\'
    selection_2:
        CommandLine|contains: '.exe\..\'
    filter_optional_google_drive:
        CommandLine|contains: '\Google\Drive\googledrivesync.exe\..\'
    filter_optional_citrix:
        CommandLine|contains: '\Citrix\Virtual Smart Card\Citrix.Authentication.VirtualSmartcard.Launcher.exe\..\'
    condition: 1 of selection_* and not 1 of filter_optional_*
falsepositives:
    - Google Drive
    - Citrix
level: medium
```
