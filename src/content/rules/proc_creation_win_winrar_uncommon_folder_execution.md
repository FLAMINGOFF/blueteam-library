---
title: WinRAR Execution in Non-Standard Folder
summary: Detects a suspicious WinRAR execution in a folder which is not the default installation folder
sigma_id: 4ede543c-e098-43d9-a28f-dd784a13132f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1560.001
author: Florian Roth (Nextron Systems), Tigzy
date: '2021-11-17'
modified: '2025-07-16'
falsepositives:
  - Legitimate use of WinRAR in a folder of a software that bundles WinRAR
references:
  - https://twitter.com/cyb3rops/status/1460978167628406785
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_winrar_uncommon_folder_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: WinRAR Execution in Non-Standard Folder
id: 4ede543c-e098-43d9-a28f-dd784a13132f
status: test
description: Detects a suspicious WinRAR execution in a folder which is not the default installation folder
references:
    - https://twitter.com/cyb3rops/status/1460978167628406785
author: Florian Roth (Nextron Systems), Tigzy
date: 2021-11-17
modified: 2025-07-16
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\rar.exe'
              - '\winrar.exe'
        - Description:
              - 'Command line RAR'
              - 'WinRAR'
    filter_main_unrar:
        # Note: we filter unrar as it has the same description as the other utilities, and we're only interested in compression
        Image|endswith: '\UnRAR.exe'
    filter_main_path:
        Image|contains:
            - ':\Program Files (x86)\WinRAR\'
            - ':\Program Files\WinRAR\'
    filter_optional_temp:
        # Note: in some occasion installers were seen dropping "rar" in TEMP
        Image|contains: ':\Windows\Temp\'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate use of WinRAR in a folder of a software that bundles WinRAR
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_winrar_uncommon_folder_execution/info.yml
```
