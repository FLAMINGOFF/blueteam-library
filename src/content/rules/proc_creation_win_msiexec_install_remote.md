---
title: Suspicious Msiexec Quiet Install From Remote Location
summary: Detects usage of Msiexec.exe to install packages hosted remotely quietly
sigma_id: 8150732a-0c9d-4a99-82b9-9efb9b90c40c
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218.007
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-10-28'
modified: '2025-10-07'
falsepositives:
  - Unknown
references:
  - https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_msiexec_install_remote.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Msiexec Quiet Install From Remote Location
id: 8150732a-0c9d-4a99-82b9-9efb9b90c40c
related:
    - id: f7b5f842-a6af-4da5-9e95-e32478f3cd2f
      type: similar
status: test
description: Detects usage of Msiexec.exe to install packages hosted remotely quietly
references:
    - https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-28
modified: 2025-10-07
tags:
    - attack.stealth
    - attack.t1218.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\msiexec.exe'
        - OriginalFileName: 'msiexec.exe'
    selection_cli:
        # Note that there is no space before and after the arguments because it's possible to write a commandline as such
        # Example: msiexec -q/i [MSI Package]
        CommandLine|contains|windash:
            - '-i'
            - '-package'
            - '-a'
            - '-j'
    selection_quiet:
        CommandLine|contains|windash: '-q'
    selection_remote:
        CommandLine|contains:
            - 'http'
            - '\\\\'
    filter_optional_openoffice:
        CommandLine|contains|all:
            - '\AppData\Local\Temp\OpenOffice'
            - 'Installation Files\openoffice'
    condition: all of selection_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
```
