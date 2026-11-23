---
title: Arbitrary File Download Via ConfigSecurityPolicy.EXE
summary: |-
  Detects the execution of "ConfigSecurityPolicy.EXE", a binary part of Windows Defender used to manage settings in Windows Defender.
  Users can configure different pilot collections for each of the co-management workloads.
  It can be abused by attackers in order to upload or download files.
sigma_id: 1f0f6176-6482-4027-b151-00071af39d7e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0010
techniques:
  - T1567
author: frack113
date: '2021-11-26'
modified: '2022-05-16'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/ConfigSecurityPolicy/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_configsecuritypolicy_download_file.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Arbitrary File Download Via ConfigSecurityPolicy.EXE
id: 1f0f6176-6482-4027-b151-00071af39d7e
status: test
description: |
    Detects the execution of "ConfigSecurityPolicy.EXE", a binary part of Windows Defender used to manage settings in Windows Defender.
    Users can configure different pilot collections for each of the co-management workloads.
    It can be abused by attackers in order to upload or download files.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/ConfigSecurityPolicy/
author: frack113
date: 2021-11-26
modified: 2022-05-16
tags:
    - attack.exfiltration
    - attack.t1567
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - CommandLine|contains: ConfigSecurityPolicy.exe
        - Image|endswith: '\ConfigSecurityPolicy.exe'
        - OriginalFileName: 'ConfigSecurityPolicy.exe'
    selection_url:
        CommandLine|contains:
            - 'ftp://'
            - 'http://'
            - 'https://'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
