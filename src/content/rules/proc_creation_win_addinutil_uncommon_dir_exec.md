---
title: AddinUtil.EXE Execution From Uncommon Directory
summary: Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) from a non-standard directory.
sigma_id: 6120ac2a-a34b-42c0-a9bd-1fb9f459f348
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
author: Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
date: '2023-09-18'
modified: '2025-02-24'
falsepositives:
  - Unknown
references:
  - https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_addinutil_uncommon_dir_exec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AddinUtil.EXE Execution From Uncommon Directory
id: 6120ac2a-a34b-42c0-a9bd-1fb9f459f348
status: test
description: Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) from a non-standard directory.
references:
    - https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html
author: Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
date: 2023-09-18
modified: 2025-02-24
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\addinutil.exe'
        - OriginalFileName: 'AddInUtil.exe'
    filter_main_legit_location:
        Image|contains:
            - ':\Windows\Microsoft.NET\Framework\'
            - ':\Windows\Microsoft.NET\Framework64\'
            - ':\Windows\Microsoft.NET\FrameworkArm\'
            - ':\Windows\Microsoft.NET\FrameworkArm64\'
            - ':\Windows\WinSxS\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
